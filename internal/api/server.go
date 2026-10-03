package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busnes-app/ky-primitives/health"
	"github.com/Busnes-app/ky-primitives/logging"
	"github.com/Busnes-app/ky-primitives/oidcverify"
	"github.com/Busnes-app/kyvault-server/internal/audit"
	"github.com/Busnes-app/kyvault-server/internal/backup"
	"github.com/Busnes-app/kyvault-server/internal/devices"
	"github.com/Busnes-app/kyvault-server/internal/reporting"
	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/sso"
	kysync "github.com/Busnes-app/kyvault-server/internal/sync"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

type Session struct {
	// ID names the session in the inventory; it is random and unrelated to the token.
	ID              string
	UserID          string
	IP              string
	IssuedAt        time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	CSRFToken       string
	SSO             sso.Identity
	// DeviceID is set only for device-token sessions minted by pairing redemption;
	// browser sessions leave it empty.
	DeviceID string
}

type Server struct {
	reporting     *reporting.Store
	users         *users.Store
	vault         *vault.Store
	devices       *devices.Store
	audit         *audit.Store
	ssoStore      *sso.Store
	logouts       *sso.LogoutLog
	backupState   *backup.StateStore
	backupService *backup.Service
	recovery      backup.RecoveryClient
	pairingSecret string
	scimToken     string
	dataDir       string
	pairings      *pairingLimiter
	lookupLimit   *pairingLimiter

	// shared is shared-vault membership; sharedSettings is CONFIG_DIR/shared.json.
	shared         *shared.Store
	sharedSettings *sharedSettings
	// sharedResolved runs after sharedMember reads the record; tests race writes through it.
	sharedResolved func()
	// rotateVerifying and rotateCommitted run inside a rotation's Verify and AfterCommit
	// steps, under shared.mu; tests race key replacements and writes through them.
	rotateVerifying, rotateCommitted func()

	// trustedProxies are the peers whose X-Forwarded-For sourceKey may believe.
	trustedProxies []netip.Prefix
	// sessionsDirty is set when sessions.json could not be written; see saveSessionsLocked.
	sessionsDirty bool // guarded by sessMu
	// logoutPending holds jtis whose session write failed, so the sender's retry is
	// answered 200 once the write lands instead of 400 as a replay.
	logoutPending map[string]struct{} // guarded by sessMu

	// auditFailures counts audit writes that did not reach the log. Sticky: the
	// missing record never comes back, so only a restart — after someone has
	// looked — clears it. Only the admin audit route reports this counter.
	auditFailures atomic.Int64

	// rejects bounds the audit writes an unauthenticated caller can cause, and
	// flushStop/flushDone run the periodic flush that keeps the folded ones from
	// being lost. See audit_budget.go.
	rejects   *auditBudget
	flushStop chan struct{}
	flushDone chan struct{}
	closeOnce sync.Once

	sessMu       sync.RWMutex
	sessions     map[string]Session // token -> Session
	oidcMu       sync.Mutex
	oidcPending  map[string]oidcAttempt
	oidcHTTP     *http.Client
	oidcVerifier *oidcverify.Verifier
	// oidcDiscoveredAt bounds how often a failing logout token may re-run discovery.
	oidcDiscoveredAt time.Time
	syncMu           sync.Mutex
	syncReceipts     map[string]syncReceipt
}

// Config holds initialization paths and secrets for Server.
type Config struct {
	DataDir       string
	ConfigDir     string
	PairingSecret string
	SCIMToken     string
	RetentionDays int
	Backup        backup.Config
	AppVersion    string
	// TrustedProxies lists reverse proxies (KYVAULT_TRUSTED_PROXIES) whose
	// X-Forwarded-For names the client for per-source limits. Empty trusts nobody.
	TrustedProxies []netip.Prefix
}

// NewServer constructs the KyVault Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "./config"
	}
	token, err := kysync.LoadSCIMToken(cfg.ConfigDir, cfg.SCIMToken)
	if err != nil {
		return nil, err
	}
	cfg.SCIMToken = token
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 90
	}
	if cfg.AppVersion == "" {
		cfg.AppVersion = "dev"
	}

	uStore, err := users.NewStore(cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init users store: %w", err)
	}

	vStore, err := vault.NewStore(cfg.DataDir+"/vaults", cfg.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("init vault store: %w", err)
	}

	shStore, err := shared.NewStore(cfg.DataDir+"/shared", cfg.RetentionDays, func(id, dst string) error {
		return vStore.MoveOut(shared.StoreKey(id), dst)
	})
	if err != nil {
		return nil, fmt.Errorf("init shared store: %w", err)
	}

	reportStore, err := reporting.New(cfg.DataDir + "/reporting")
	if err != nil {
		return nil, fmt.Errorf("init reporting store: %w", err)
	}

	dStore, err := devices.NewStore(cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init devices store: %w", err)
	}

	aStore, err := audit.NewStore(cfg.DataDir+"/audit", cfg.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("init audit store: %w", err)
	}

	ssoSt := sso.NewStore(cfg.ConfigDir)
	logouts, err := sso.NewLogoutLog(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("init logout log: %w", err)
	}
	backupState := backup.NewStateStore(cfg.ConfigDir)
	recovery := backup.NewClient(cfg.Backup.AllowPrivate)
	collector := backup.Collector{
		Vault: vStore, Audit: aStore, Users: uStore, Devices: dStore, SSO: ssoSt, Shared: shStore,
		State: backupState, PairingSecret: cfg.PairingSecret, SCIMToken: cfg.SCIMToken, RetentionDays: cfg.RetentionDays,
		AppVersion: cfg.AppVersion, DataDir: cfg.DataDir, SharedSettingsPath: filepath.Join(cfg.ConfigDir, "shared.json"),
	}

	s := &Server{
		reporting:      reportStore,
		users:          uStore,
		vault:          vStore,
		devices:        dStore,
		audit:          aStore,
		ssoStore:       ssoSt,
		logouts:        logouts,
		backupState:    backupState,
		recovery:       recovery,
		pairingSecret:  cfg.PairingSecret,
		scimToken:      cfg.SCIMToken,
		dataDir:        cfg.DataDir,
		pairings:       newPairingLimiter(),
		lookupLimit:    newLimiter(lookupMaxMisses, lookupLockout),
		shared:         shStore,
		sharedSettings: newSharedSettings(cfg.ConfigDir),
		trustedProxies: cfg.TrustedProxies,
		sessions:       make(map[string]Session),
		logoutPending:  make(map[string]struct{}),
		oidcPending:    make(map[string]oidcAttempt), oidcHTTP: sso.NewHTTPClient(), syncReceipts: make(map[string]syncReceipt),
		rejects:   newAuditBudget(auditBudgetWindow, auditBudgetBurst),
		flushStop: make(chan struct{}),
		flushDone: make(chan struct{}),
	}
	if err := s.loadSessions(); err != nil {
		return nil, fmt.Errorf("load sessions: %w", err)
	}
	s.pruneShared()
	s.backupService = &backup.Service{State: backupState, Collector: collector, Client: recovery, Config: cfg.Backup}
	go s.flushSuppressed()

	return s, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/", s.scimRoutes())
	lg, err := logging.New(logging.Config{App: "kyvault"})
	if err != nil {
		panic(err) // Static application name is valid.
	}
	// Public health describes process availability only. Audit failure is admin-only.
	h := health.Handler("kyvault", lg)
	mux.Handle("GET /healthz", h)
	mux.Handle("GET /api/health", h)

	// Public auth. KySignOn is the only way in: there is no local login, no login
	// parameters to fetch, no recovery-as-site-access and no first-run setup. Paper
	// recovery still works, client-side, against the vault key envelope.
	mux.HandleFunc("GET /api/auth/sso-config", s.handleSSOConfig)
	mux.HandleFunc("GET /api/auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/oidc/login", s.handleSSOLogin)
	mux.HandleFunc("GET /auth/sso/login", s.handleSSOLogin)
	mux.HandleFunc("GET /api/auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleSSOCallback)
	mux.HandleFunc("GET /auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("POST /api/auth/oidc/backchannel-logout", s.handleBackchannelLogout) // issuer-facing

	// Self & Session. Changing the master password is a client-side re-wrap of the vault
	// key envelope against PUT /api/vault/envelopes; the server has no password to change.
	// Unlinking SSO is gone too — it would only be a way to lock yourself out for good.
	mux.HandleFunc("GET /api/auth/me", s.withAuth(s.handleMe))
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("GET /api/auth/sessions", s.withAuth(s.handleSessionsList))
	mux.HandleFunc("DELETE /api/auth/sessions/{id}", s.withAuth(s.handleSessionEnd))

	mux.HandleFunc("GET /api/reporting/config", s.withAuth(s.reportBrowser(s.handleReportConfig)))
	mux.HandleFunc("PUT /api/reporting/report", s.withAuth(s.reportBrowser(s.handleReportPut)))
	mux.HandleFunc("DELETE /api/reporting/report", s.withAuth(s.reportBrowser(s.handleReportDelete)))
	mux.HandleFunc("PUT /api/admin/reporting/config", s.withFreshAdmin(s.reportBrowser(s.handleReportConfigure)))
	mux.HandleFunc("GET /api/admin/reporting", s.withAdmin(s.reportBrowser(s.handleReportList)))

	// Vault Operations
	mux.HandleFunc("GET /api/vault/metadata", s.withAuth(s.handleVaultMetadata))
	mux.HandleFunc("GET /api/vault/kdbx", s.withAuth(s.handleVaultDownload))
	mux.HandleFunc("POST /api/vault/upload", s.withAuth(s.handleVaultUpload))
	mux.HandleFunc("PUT /api/vault/envelopes", s.withAuth(s.handleVaultEnvelopes))
	mux.HandleFunc("PUT /api/vault/user-key", s.withAuth(s.handleUserKeyPut))
	mux.HandleFunc("GET /api/users/lookup", s.withAuth(s.handleUserLookup))
	mux.HandleFunc("GET /api/users/{id}/key", s.withAuth(s.handleUserKeyGet))
	mux.HandleFunc("GET /api/vault/history", s.withAuth(s.handleVaultHistory))
	mux.HandleFunc("GET /api/vault/history/{id}", s.withAuth(s.handleVaultHistoryDownload))
	mux.HandleFunc("POST /api/vault/history/{id}/restore", s.withAuth(s.handleVaultHistoryRestore))
	mux.HandleFunc("GET /api/vault/conflicts", s.withAuth(s.handleVaultConflicts))
	mux.HandleFunc("GET /api/vault/conflicts/{id}", s.withAuth(s.handleVaultConflictDownload))
	mux.HandleFunc("DELETE /api/vault/conflicts/{id}", s.withAuth(s.handleVaultConflictDiscard))

	// Devices & Extension Pairing
	mux.HandleFunc("POST /api/devices/pairing/start", s.withAuth(s.handlePairingStart))
	mux.HandleFunc("POST /api/devices/pairing/redeem", s.handlePairingRedeem) // device-facing
	mux.HandleFunc("GET /api/devices", s.withAuth(s.handleDevicesList))
	mux.HandleFunc("DELETE /api/devices/{id}", s.withAuth(s.handleDeviceRevoke))
	mux.HandleFunc("PATCH /api/devices/{id}", s.withAuth(s.handleDeviceRename))

	// Directory Sync Webhook
	mux.Handle("POST /api/sync/webhook", s.signedSyncHandler())

	// Admin Operations
	// Shared vaults: lifecycle and membership. Every {id} route resolves the caller's row first.
	mux.HandleFunc("POST /api/shared", s.withAuth(s.handleSharedCreate))
	mux.HandleFunc("GET /api/shared", s.withAuth(s.handleSharedList))
	mux.HandleFunc("GET /api/shared/{id}", s.withAuth(s.handleSharedGet))
	mux.HandleFunc("PATCH /api/shared/{id}", s.withAuth(s.handleSharedRename))
	mux.HandleFunc("DELETE /api/shared/{id}", s.withAuth(s.handleSharedDelete))
	mux.HandleFunc("POST /api/shared/{id}/members", s.withAuth(s.handleSharedInvite))
	mux.HandleFunc("PUT /api/shared/{id}/members/{userId}", s.withAuth(s.handleSharedMemberUpdate))
	mux.HandleFunc("DELETE /api/shared/{id}/members/{userId}", s.withAuth(s.handleSharedMemberRemove))
	mux.HandleFunc("POST /api/shared/{id}/accept", s.withAuth(s.handleSharedAccept))
	mux.HandleFunc("POST /api/shared/{id}/decline", s.withAuth(s.handleSharedDecline))
	mux.HandleFunc("POST /api/shared/{id}/rotate", s.withAuth(s.handleSharedRotate))
	mux.HandleFunc("GET /api/shared/{id}/metadata", s.withAuth(s.withSharedRead(s.vaultMetadata)))
	mux.HandleFunc("GET /api/shared/{id}/kdbx", s.withAuth(s.withSharedRead(s.vaultDownload)))
	mux.HandleFunc("POST /api/shared/{id}/upload", s.withAuth(s.withSharedWrite(s.vaultUpload)))
	mux.HandleFunc("GET /api/shared/{id}/history", s.withAuth(s.withSharedRead(s.vaultHistory)))
	mux.HandleFunc("GET /api/shared/{id}/history/{hid}", s.withAuth(s.withSharedRead(s.vaultHistoryDownload)))
	mux.HandleFunc("POST /api/shared/{id}/history/{hid}/restore", s.withAuth(s.withSharedWrite(s.vaultHistoryRestore)))
	mux.HandleFunc("GET /api/shared/{id}/conflicts", s.withAuth(s.withSharedRead(s.vaultConflicts)))
	mux.HandleFunc("GET /api/shared/{id}/conflicts/{cid}", s.withAuth(s.withSharedRead(s.vaultConflictDownload)))
	mux.HandleFunc("DELETE /api/shared/{id}/conflicts/{cid}", s.withAuth(s.withSharedWrite(s.vaultConflictDiscard)))

	mux.HandleFunc("GET /api/admin/provisioning", s.withAdmin(s.handleProvisioningStatus))
	mux.HandleFunc("GET /api/admin/users", s.withAdmin(s.handleAdminUsersList))
	mux.HandleFunc("PUT /api/admin/users/{id}/role", s.withAdmin(s.handleAdminUserRole))
	mux.HandleFunc("POST /api/admin/users/{id}/deactivate", s.withAdmin(s.handleAdminUserDeactivate))
	mux.HandleFunc("POST /api/admin/users/{id}/reactivate", s.withAdmin(s.handleAdminUserReactivate))
	mux.HandleFunc("GET /api/admin/sso", s.withAdmin(s.handleAdminSSOGet))
	mux.HandleFunc("PUT /api/admin/sso", s.withAdmin(s.handleAdminSSOPut))
	mux.HandleFunc("GET /api/audit", s.withAdmin(s.handleAuditList))
	mux.HandleFunc("GET /api/audit/verify", s.withAdmin(s.handleAuditVerify))
	mux.HandleFunc("POST /api/backup/drill", s.withAdmin(s.handleBackupDrill))
	mux.HandleFunc("POST /api/backup/export-capsule", s.withFreshAdmin(s.handleExportCapsule))
	mux.HandleFunc("POST /api/backup/pair-remote", s.withFreshAdmin(s.handlePairRemoteRecovery))
	mux.HandleFunc("POST /api/backup/deposit", s.withFreshAdmin(s.handleDepositBackup))
	mux.HandleFunc("POST /api/backup/pin-key", s.withFreshAdmin(s.handlePinRecoveryKey))
	mux.HandleFunc("DELETE /api/backup/pairing", s.withFreshAdmin(s.handleUnpairRecovery))
	mux.HandleFunc("PUT /api/backup/schedule", s.withFreshAdmin(s.handleBackupSchedule))
	mux.HandleFunc("GET /api/backup/status", s.withAdmin(s.handleBackupStatus))
	mux.HandleFunc("GET /api/admin/shared", s.withAdmin(s.handleAdminSharedList))
	mux.HandleFunc("DELETE /api/admin/shared/{id}", s.withFreshAdmin(s.handleAdminSharedDelete))
	mux.HandleFunc("DELETE /api/admin/shared/{id}/members/{userId}", s.withFreshAdmin(s.handleAdminSharedMemberRemove))
	mux.HandleFunc("GET /api/admin/shared/settings", s.withAdmin(s.handleAdminSharedSettingsGet))
	mux.HandleFunc("PUT /api/admin/shared/settings", s.withFreshAdmin(s.handleAdminSharedSettingsPut))

	return SecurityHeaders(mux)
}

// record writes an audit entry and makes a failed write impossible to miss.
//
// It does not fail the request. Every call site records an operation the server has
// already carried out, so a 500 would not undo it — it would ask the client to retry
// something that already happened, and the retry would be just as unrecorded. Several
// call sites record a rejection — sync.rejected, device.pairing_failed — where a 500
// would turn "you are not authorised" into "the server is broken" and tell an attacker
// the log is down.
//
// What a lost record does change is what the operator and the auditor are told. The
// failure goes to stderr with its cause and the running count, and GET /api/audit/verify
// — which is admin-only, and the one place someone asks whether the trail is sound —
// carries the count, because VerifyIntegrity cannot see a record that never reached the
// log. GET /api/health does not carry it: it takes no credential, and a caller filling
// the disk must not be able to watch the filling work.
// TestFailedAuditWriteIsReportedOnlyToAnAdmin pins all three.
//
// Rejections recorded before any credential is checked go through
// recordAnonymousRejection instead, which bounds what they cost.
func (s *Server) record(r *http.Request, action, userID, deviceID, ip, details string) {
	s.recordCtx(r.Context(), action, userID, deviceID, ip, details)
}

// recordCtx is record for a call site that has no request — the periodic flush.
func (s *Server) recordCtx(ctx context.Context, action, userID, deviceID, ip, details string) {
	if _, err := s.audit.Log(ctx, action, userID, deviceID, ip, details); err != nil {
		n := s.auditFailures.Add(1)
		// details is left out on purpose: it carries operation content, and both the
		// audit records and these logs are content-blind.
		log.Printf("AUDIT WRITE FAILED (%d since start) action=%s user=%s device=%s ip=%s: %v",
			n, action, userID, deviceID, ip, err)
	}
}

// writeJSON formats and sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// clientIP extracts the client's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// errLoginFenced means a logout for this identity arrived while the login was in flight.
var errLoginFenced = errors.New("login superseded by a KySignOn logout")

// startSession issues session token & CSRF token cookies. authenticatedAt is the
// issuer's auth_time, the moment the person actually authenticated, not now.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID string, id sso.Identity, authenticatedAt time.Time) error {
	tokBytes := make([]byte, 24)
	if _, err := rand.Read(tokBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokBytes)

	csrfBytes := make([]byte, 24)
	if _, err := rand.Read(csrfBytes); err != nil {
		return err
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	now := time.Now().UTC()
	// Fence check and insert share the lock with applySSOLogout, so a logout cannot
	// slip between them and leave a session it should have ended.
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if u, err := s.users.Get(userID); err != nil || !u.Active {
		return fmt.Errorf("account is inactive")
	}
	if !id.Revocable() {
		return errors.New("session needs a revocable identity")
	}
	if s.logouts.Fenced(id, now) {
		return errLoginFenced
	}
	s.pruneSessionsLocked(now)
	s.sessions[sessionKey(token)] = Session{
		ID:              randomHex(16),
		UserID:          userID,
		IP:              clientIP(r),
		IssuedAt:        now,
		AuthenticatedAt: authenticatedAt,
		ExpiresAt:       now.Add(24 * time.Hour),
		CSRFToken:       csrfToken,
		SSO:             id,
	}
	// A mint that is not durable is a session lost on restart, not a security gap;
	// the flush retries and the login stands.
	_ = s.saveSessionsLocked()

	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "kypass_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	return nil
}

func isRequestSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func requestHost(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.Host
}

// currentUser extracts the user from the session cookie or Bearer token.
// currentSession resolves the request's unexpired session from the cookie or bearer token.
func (s *Server) currentSession(r *http.Request) (Session, bool) {
	token := ""
	if cookie, err := r.Cookie("kypass_session"); err == nil && cookie.Value != "" {
		token = cookie.Value
	} else if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}
	if token == "" {
		return Session{}, false
	}

	s.sessMu.RLock()
	sess, ok := s.sessions[sessionKey(token)]
	s.sessMu.RUnlock()

	if !ok || time.Now().UTC().After(sess.ExpiresAt) {
		return Session{}, false
	}
	return sess, true
}

func (s *Server) currentUser(r *http.Request) (users.User, bool) {
	sess, ok := s.currentSession(r)
	if !ok {
		return users.User{}, false
	}

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		return users.User{}, false
	}

	return u, true
}

// validCSRF protects cookie-authenticated state changes. Bearer callers are not
// vulnerable to ambient-cookie CSRF and do not need the browser token.
func (s *Server) validCSRF(r *http.Request) bool {
	sessionCookie, err := r.Cookie("kypass_session")
	if err != nil || sessionCookie.Value == "" {
		return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil || csrfCookie.Value == "" {
		return false
	}
	s.sessMu.RLock()
	session, ok := s.sessions[sessionKey(sessionCookie.Value)]
	s.sessMu.RUnlock()
	header := r.Header.Get("X-CSRF-Token")
	return ok && subtle.ConstantTimeCompare([]byte(header), []byte(csrfCookie.Value)) == 1 &&
		subtle.ConstantTimeCompare([]byte(header), []byte(session.CSRFToken)) == 1
}

// withAuth enforces authenticated session.
func (s *Server) withAuth(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, u)
	}
}

// freshSessionWindow is how recently an admin must have signed in to move or expose backup
// material. KyVault has no password of its own to re-prompt for, so a stale admin is sent
// back through KySignOn instead.
const freshSessionWindow = 10 * time.Minute

// sessionIsFresh holds when the session's KySignOn sign-in is within freshSessionWindow.
func sessionIsFresh(sess Session) bool {
	return !sess.AuthenticatedAt.IsZero() && time.Since(sess.AuthenticatedAt) <= freshSessionWindow
}

// requireFresh answers 403 unless sess is fresh.
func (s *Server) requireFresh(w http.ResponseWriter, sess Session) bool {
	if !sessionIsFresh(sess) {
		http.Error(w, "re-authenticate to continue: sign in again through KySignOn", http.StatusForbidden)
		return false
	}
	return true
}

// withFreshAdmin is withAdmin plus requireFresh, for destructive admin routes.
func (s *Server) withFreshAdmin(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return s.withAdmin(func(w http.ResponseWriter, r *http.Request, u users.User) {
		sess, _ := s.currentSession(r)
		if !s.requireFresh(w, sess) {
			return
		}
		next(w, r, u)
	})
}

// withAdmin enforces admin role.
func (s *Server) withAdmin(next func(http.ResponseWriter, *http.Request, users.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if u.Role != users.RoleAdmin {
			http.Error(w, "forbidden: admin privileges required", http.StatusForbidden)
			return
		}
		next(w, r, u)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
