package sso

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/oidcverify"
)

// Identity is what a KySignOn login proved, kept on every session it produced so a
// back-channel logout can find the sessions it names. Device sessions inherit the
// identity of the browser session that paired them.
type Identity struct {
	Issuer    string
	ClientID  string
	Subject   string
	SessionID string    // OIDC sid; empty when the issuer did not send one
	IssuedAt  time.Time // ID token iat
}

// Revocable reports whether a logout token could ever name this identity. A session
// minted without one would outlive every logout, so minting refuses it.
func (id Identity) Revocable() bool {
	return id.Issuer != "" && id.ClientID != "" && id.Subject != ""
}

// LogoutEvent is one accepted logout token, retained through ReplayUntil so a repeat
// delivery is refused and a login that races it is fenced.
type LogoutEvent struct {
	Issuer      string    `json:"issuer"`
	ClientID    string    `json:"clientId"`
	JWTID       string    `json:"jti"`
	Subject     string    `json:"subject,omitempty"`
	SessionID   string    `json:"sessionId,omitempty"`
	IssuedAt    time.Time `json:"issuedAt"`
	RetainUntil time.Time `json:"retainUntil"`
}

// Matches reports whether a session with this identity is one the event logs out:
// the named session, or every session of the subject issued before the logout.
// An unknown session ID never widens into a subject-wide logout.
func (e LogoutEvent) Matches(id Identity) bool {
	if id.Subject == "" || id.Issuer != e.Issuer || id.ClientID != e.ClientID {
		return false
	}
	if e.SessionID != "" {
		return id.SessionID == e.SessionID && (e.Subject == "" || id.Subject == e.Subject)
	}
	return id.Subject == e.Subject && !id.IssuedAt.After(e.IssuedAt)
}

var (
	ErrLogoutReplayed = errors.New("sso: logout token already applied")
	ErrLogoutCapacity = errors.New("sso: logout receipt capacity reached")
)

const logoutCapacity = 4096

// LogoutLog is the durable record of accepted logout tokens. It is written through to
// disk on every admission so a restart cannot forget a delivery and accept it twice.
// It is not part of the sealed backup: every event expires within minutes and a restored
// process holds no sessions for it to fence.
type LogoutLog struct {
	mu     sync.Mutex
	path   string
	events map[string]LogoutEvent
}

func NewLogoutLog(dir string) (*LogoutLog, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l := &LogoutLog{path: filepath.Join(dir, "sso-logout.json"), events: map[string]LogoutEvent{}}
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var list []LogoutEvent
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for _, e := range list {
		l.events[e.key()] = e
	}
	return l, nil
}

func (e LogoutEvent) key() string { return e.Issuer + "\x00" + e.ClientID + "\x00" + e.JWTID }

// Admit records a verified logout token for clientID. A token seen before returns
// ErrLogoutReplayed; nothing is recorded unless the write reaches disk.
func (l *LogoutLog) Admit(c oidcverify.LogoutClaims, clientID string, now time.Time) (LogoutEvent, error) {
	e := LogoutEvent{Issuer: c.Issuer, ClientID: clientID, JWTID: c.JWTID, Subject: c.Subject, SessionID: c.SessionID, IssuedAt: c.IssuedAt, RetainUntil: c.ReplayUntil}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, old := range l.events {
		if now.After(old.RetainUntil) {
			delete(l.events, k)
		}
	}
	if _, seen := l.events[e.key()]; seen {
		return LogoutEvent{}, ErrLogoutReplayed
	}
	if len(l.events) >= logoutCapacity {
		return LogoutEvent{}, ErrLogoutCapacity
	}
	l.events[e.key()] = e
	if err := l.saveLocked(); err != nil {
		delete(l.events, e.key())
		return LogoutEvent{}, err
	}
	return e, nil
}

// Fenced reports whether a retained logout already covers this identity, so a login
// whose token predates the logout cannot mint a session after it.
func (l *LogoutLog) Fenced(id Identity, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.events {
		if !now.After(e.RetainUntil) && e.Matches(id) {
			return true
		}
	}
	return false
}

func (l *LogoutLog) saveLocked() error {
	list := make([]LogoutEvent, 0, len(l.events))
	for _, e := range l.events {
		list = append(list, e)
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}
