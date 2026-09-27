package api

import (
	"sync"
	"time"
)

const (
	// pairingMaxFailures wrong codes from one source close pairing redeem to that source
	// for pairingLockout. Three guesses against a six-digit PIN in a 90-second window is
	// noise; three thousand is the attack this exists to stop.
	pairingMaxFailures = 3
	pairingLockout     = 15 * time.Minute
	// pairingMaxSources caps the table like auditBudgetMaxSources: past it, unseen
	// sources share one bucket rather than each drawing fresh attempts.
	pairingMaxSources = 1024
	pairingOverflow   = "overflow"
)

// pairingLimiter counts wrong pairing codes per network source. Keyed on sourceKey, the
// peer address, for the reason audit_budget.go gives: a header the caller writes is no
// key at all. ponytail: behind a reverse proxy every caller shares one bucket, so three
// wrong codes from anyone close redeem for everyone for the lockout; the upgrade path is
// a trusted-proxy setting that lets sourceKey read X-Forwarded-For.
type pairingLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	sources     map[string]*pairingSource
	maxFailures int
	lockout     time.Duration
}

type pairingSource struct {
	failures int
	until    time.Time // failures reset, and a lockout ends, once this passes
}

func newPairingLimiter() *pairingLimiter {
	return newLimiter(pairingMaxFailures, pairingLockout)
}

func newLimiter(maxFailures int, lockout time.Duration) *pairingLimiter {
	return &pairingLimiter{now: time.Now, sources: map[string]*pairingSource{}, maxFailures: maxFailures, lockout: lockout}
}

func (l *pairingLimiter) key(src string) string {
	if _, ok := l.sources[src]; !ok && len(l.sources) >= pairingMaxSources {
		return pairingOverflow
	}
	return src
}

// allow reports whether src may attempt a redeem now.
func (l *pairingLimiter) allow(src string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.sources[l.key(src)]
	if !ok || !l.now().Before(p.until) {
		return true
	}
	return p.failures < l.maxFailures
}

// fail records a wrong code. The third within the window starts the lockout.
func (l *pairingLimiter) fail(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	k := l.key(src)
	p, ok := l.sources[k]
	if !ok || !now.Before(p.until) {
		p = &pairingSource{}
		l.sources[k] = p
	}
	p.failures++
	p.until = now.Add(l.lockout)
}

// reset clears a source after a redeem succeeded: the code was the user's own.
func (l *pairingLimiter) reset(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sources, src)
}

// sweep drops sources whose window has passed. Run with the periodic audit flush.
func (l *pairingLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, p := range l.sources {
		if !now.Before(p.until) {
			delete(l.sources, k)
		}
	}
}
