package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/sso"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithUsers(t, "")
}

// newTestServerWithUsers seeds config/users.json before the server opens it, which is the
// only way to produce an account the current code cannot create — a legacy record with no
// KySignOn identity. Pass "" for a fresh install.
func newTestServerWithUsers(t *testing.T, usersJSON string) *Server {
	t.Helper()
	dir := t.TempDir()
	if usersJSON != "" {
		if err := os.MkdirAll(dir+"/config", 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(dir+"/config/users.json", []byte(usersJSON), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	srv, _ := newServerIn(t, dir)
	return srv
}

// newServerIn builds a server rooted at dir and hands back its data directory, which
// the tests that have to break the audit log need in order to find it.
func newServerIn(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	srv, err := NewServer(Config{
		DataDir:       dir + "/data",
		ConfigDir:     dir + "/config",
		PairingSecret: "test-pairing-secret-123",
		RetentionDays: 90,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	// Stops the background audit flush before t.TempDir removes what it writes to.
	t.Cleanup(srv.Close)
	return srv, dir + "/data"
}

// signedInUser provisions an account the way KySignOn would and returns it with a session
// cookie. Sessions are only ever issued after an SSO login now, so tests start here.
func signedInUser(t *testing.T, srv *Server, username string, role users.Role) (users.User, *http.Cookie) {
	t.Helper()
	u, err := srv.users.CreateSSOUser(username, role, "sub-"+username, username, username+"@example.com")
	if err != nil {
		t.Fatalf("CreateSSOUser(%q): %v", username, err)
	}

	rec := httptest.NewRecorder()
	id := sso.Identity{Issuer: "https://kysignon.test", ClientID: "kyvault-app", Subject: u.SSOSub, SessionID: "sid-" + username, IssuedAt: time.Now().UTC()}
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), u.ID, id, time.Now().UTC()); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" {
			return u, c
		}
	}
	t.Fatal("no session cookie was issued")
	return users.User{}, nil
}

func TestAuthenticatedSessionAndMe(t *testing.T) {
	// There is no login endpoint to drive; a session comes from the SSO callback, which
	// TestSSOCallbackStillMatchesOnSub covers end to end. This checks that a session,
	// once held, authenticates.
	srv := newTestServer(t)
	u, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/me status = %d", rec.Code)
	}

	var meResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&meResp)
	if meResp["authenticated"] != true {
		t.Errorf("expected authenticated=true in /api/auth/me: %+v", meResp)
	}
	if user, ok := meResp["user"].(map[string]any); !ok || user["id"] != u.ID {
		t.Errorf("unexpected user in /api/auth/me: %+v", meResp)
	}

	// Without the cookie the same route must refuse.
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/auth/me = %d, want 401", rec.Code)
	}
}

func TestVaultOperationsAndConflicts(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	_, sessCookie := signedInUser(t, srv, "bob", users.RoleUser)
	var rec *httptest.ResponseRecorder

	// 1. Initial vault upload
	v1Payload, _ := json.Marshal(VaultUploadRequest{
		ExpectedVersion:  0,
		KdbxBase64:       base64.StdEncoding.EncodeToString([]byte("ENCRYPTED-KDBX-V1")),
		PasswordEnvelope: "pw-env-v1",
		RecoveryEnvelope: "rec-env-v1",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(v1Payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/vault/upload v1 status = %d", rec.Code)
	}

	// 2. Download vault
	req = httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vault/kdbx status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "ENCRYPTED-KDBX-V1" {
		t.Errorf("download mismatch: %s", string(body))
	}
	if rec.Header().Get("ETag") != "\"1\"" {
		t.Errorf("expected ETag \"1\", got: %s", rec.Header().Get("ETag"))
	}

	// 3. Stale upload conflict (expectedVersion = 0 instead of 1)
	vStalePayload, _ := json.Marshal(VaultUploadRequest{
		ExpectedVersion: 0,
		KdbxBase64:      base64.StdEncoding.EncodeToString([]byte("ENCRYPTED-KDBX-STALE")),
	})
	req = httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(vStalePayload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected conflict status 409, got %d", rec.Code)
	}

	// 4. List conflicts
	req = httptest.NewRequest(http.MethodGet, "/api/vault/conflicts", nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/vault/conflicts status = %d", rec.Code)
	}
}

// pairDeviceForTest performs the pairing start and redeem calls a browser session would
// drive and returns the new device's ID and its bearer session token.
func pairDeviceForTest(t *testing.T, handler http.Handler, cookie *http.Cookie) (deviceID, token string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/start", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/pairing/start status = %d", rec.Code)
	}

	var pairInit map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&pairInit)
	pin := pairInit["pin"].(string)

	redeemBody, _ := json.Marshal(PairingRedeemRequest{
		CodeOrPIN:      pin,
		DeviceName:     "Carol's iPhone",
		Platform:       "ios",
		DeviceEnvelope: "ios-wrapped-key-123",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", bytes.NewReader(redeemBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/devices/pairing/redeem status = %d", rec.Code)
	}

	var redeemResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&redeemResp)
	deviceID, _ = redeemResp["deviceId"].(string)
	token, _ = redeemResp["sessionToken"].(string)
	if deviceID == "" || token == "" {
		t.Fatalf("unexpected redeem response: %+v", redeemResp)
	}
	return deviceID, token
}

func TestDevicePairingFlow(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	_, sessCookie := signedInUser(t, srv, "carol", users.RoleUser)
	pairDeviceForTest(t, handler, sessCookie)

	// User lists devices
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.AddCookie(sessCookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/devices status = %d", rec.Code)
	}
}

func TestDeviceRevokeEndsSession(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, sessCookie := signedInUser(t, srv, "erin", users.RoleUser)
	deviceID, token := pairDeviceForTest(t, handler, sessCookie)

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var listed []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&listed)
	if len(listed) != 1 || listed[0]["current"] != true {
		t.Fatalf("device session should see itself as current: %+v", listed)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/devices/"+deviceID, nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/vault/metadata", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device token still works: %d", rec.Code)
	}
}

func TestDeviceRename(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, owner := signedInUser(t, srv, "fay", users.RoleUser)
	_, other := signedInUser(t, srv, "gus", users.RoleUser)
	deviceID, _ := pairDeviceForTest(t, handler, owner)
	for _, tc := range []struct {
		cookie *http.Cookie
		body   string
		want   int
	}{
		{owner, `{"name":"  Kitchen tablet "}`, http.StatusOK},
		{owner, `{"name":""}`, http.StatusBadRequest},
		{owner, `{"name":"bad\u0007name"}`, http.StatusBadRequest},
		{owner, `{"name":"` + strings.Repeat("x", 65) + `"}`, http.StatusBadRequest},
		{other, `{"name":"mine now"}`, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodPatch, "/api/devices/"+deviceID, strings.NewReader(tc.body))
		req.AddCookie(tc.cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("PATCH %s with %s = %d, want %d", tc.cookie.Value[:4], tc.body, rec.Code, tc.want)
		}
	}
	dev, _ := srv.devices.Get(deviceID)
	if dev.Name != "Kitchen tablet" {
		t.Fatalf("name = %q", dev.Name)
	}
}

// TestStartSessionRefusesGoneDevice pins that a session cannot be minted for a device
// that no longer exists, e.g. one revoked between RedeemPairing and startSessionWithToken.
// Without this check the minted session's DeviceID would name nothing a later revoke
// could find, leaving a bearer token no revoke could ever end.
func TestStartSessionRefusesGoneDevice(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.CreateSSOUser("hank", users.RoleUser, "sub-hank", "hank", "hank@example.com")
	if err != nil {
		t.Fatal(err)
	}
	id := sso.Identity{Issuer: "https://kysignon.test", ClientID: "kyvault-app", Subject: u.SSOSub, SessionID: "sid-hank", IssuedAt: time.Now().UTC()}

	if _, err := srv.startSessionWithToken(u.ID, "device-that-does-not-exist", "", id); err == nil {
		t.Fatal("expected an error minting a session for a nonexistent device")
	}
}

func TestSSOCallbackAutoProvisions(t *testing.T) {
	srv := newTestServer(t)
	idp := mockIdP(t, map[string]any{"sub": "kysignon-sub-999", "email": "dave@urlxl.com", "preferred_username": "dave", "role": "admin"})
	srv.oidcHTTP = idp.Client()
	if err := srv.ssoStore.Save(sso.SSOSettings{Enabled: true, IssuerURL: idp.URL, ClientID: "kyvault-app", AutoProvision: true}); err != nil {
		t.Fatal(err)
	}
	rec := driveSSOCallback(t, srv)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	// Verify Dave was auto-provisioned
	dave, err := srv.users.GetBySSOSub("kysignon-sub-999")
	if err != nil || dave.Username != "dave" || dave.Role != users.RoleAdmin {
		t.Errorf("dave auto-provision mismatch: %+v, err: %v", dave, err)
	}

}

func TestAuditLogIntegrity(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()

	_, sessCookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	req.AddCookie(sessCookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/audit/verify status = %d", rec.Code)
	}

	var verifyResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&verifyResp)
	if verifyResp["valid"] != true {
		t.Errorf("expected valid audit chain: %+v", verifyResp)
	}
}

// A client that hangs up after the handler has already acted must not take its audit
// record with it. r.Context() dies the instant the connection does and handlers log
// last, so honouring that cancellation meant an aborted request left no trace at all,
// with the same HTTP status and a chain that still verified clean.
func TestAbortedRequestStillRecordsTheAudit(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil).WithContext(ctx)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/logout status = %d, want 200", rec.Code)
	}

	entries, err := srv.audit.List(0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	logged := false
	for _, e := range entries {
		if e.Action == "auth.logout" {
			logged = true
		}
	}
	if !logged {
		t.Fatalf("the aborted request logged out but left no audit record: %+v", entries)
	}
	if ok, err := srv.audit.VerifyIntegrity(); !ok || err != nil {
		t.Fatalf("audit chain does not verify: ok=%v, err=%v", ok, err)
	}
}

// A failed audit write must not vanish. This is a password vault: an instance that
// keeps accepting privileged operations while recording none of them is the state an
// attacker wants it in, and until now every call site discarded the error, so nothing
// said a word until a later restart refused to boot.
//
// The request still succeeds. The operation it is recording has already happened, so a
// 500 would not undo it — it would ask the client to retry something the server has
// already done, and the retry would be just as unrecorded. What changes is that the
// failure is reported: on stderr, in the health body, and to an admin asking whether
// the trail is sound.
//
// Health stays 200 in both states. A sticky counter wired to 503 is a credential vault
// that takes itself out of service for one transient write failure and stays there
// until a human restarts it; both status codes are asserted here so that trade is a
// decision rather than an accident.
//
// The audit log path is made a directory rather than the directory made read-only,
// because root writes into a read-only directory whatever its mode says. O_WRONLY on a
// directory is EISDIR for every uid, so this test has no skip.
func TestFailedAuditWriteIsReportedOnlyToAnAdmin(t *testing.T) {
	srv, dataDir := newServerIn(t, t.TempDir())
	_, cookie := signedInUser(t, srv, "dana", users.RoleAdmin)
	handler := srv.Routes()

	health := func() (int, string) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		var body struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("health body %q: %v", rec.Body.String(), err)
		}
		return rec.Code, body.Status
	}
	if code, status := health(); code != http.StatusOK || status != "ok" {
		t.Fatalf(`GET /api/health = %d %q with a working audit log, want 200 "ok"`, code, status)
	}

	// A log the append cannot open, which a full or broken volume also produces. The
	// store is already constructed, so this is a write-time failure, not a boot one.
	logPath := filepath.Join(dataDir, "audit", "audit.jsonl")
	if err := os.RemoveAll(logPath); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.Mkdir(logPath, 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/logout = %d; the logout happened, so the client must not be told to retry it", rec.Code)
	}
	if !strings.Contains(logs.String(), "AUDIT WRITE FAILED") || !strings.Contains(logs.String(), "auth.logout") {
		t.Fatalf("a failed audit write left no line an operator could see: %q", logs.String())
	}
	// 200 still — a full audit volume must not become a credential lockout — and the
	// body must not have moved, because an anonymous caller reading a change here is
	// reading confirmation that the disk they are filling is full.
	if code, status := health(); code != http.StatusOK || status != "ok" {
		t.Fatalf(`GET /api/health = %d %q after an audit write failed, want an unchanged 200 "ok"`, code, status)
	}

	// And the admin asking whether the trail is sound is told, which VerifyIntegrity
	// alone cannot say: it only ever sees the records that were written.
	_, adminCookie := signedInUser(t, srv, "auditor", users.RoleAdmin)
	vreq := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	vreq.AddCookie(adminCookie)
	vrec := httptest.NewRecorder()
	handler.ServeHTTP(vrec, vreq)
	var verify struct {
		WriteFailures int64 `json:"writeFailures"`
	}
	if err := json.Unmarshal(vrec.Body.Bytes(), &verify); err != nil {
		t.Fatalf("verify body %q: %v", vrec.Body.String(), err)
	}
	if verify.WriteFailures == 0 {
		t.Fatalf("GET /api/audit/verify reported no lost records after a failed write: %s", vrec.Body.String())
	}
}

func TestAdminCannotDeactivateSelfOrLastAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, cookie := signedInUser(t, srv, "root", users.RoleAdmin)
	post := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post("/api/admin/users/" + admin.ID + "/deactivate"); code != http.StatusBadRequest {
		t.Fatalf("self deactivate = %d, want 400", code)
	}
	other, err := srv.users.CreateSSOUser("second", users.RoleAdmin, "sub-second", "second", "s@x")
	if err != nil {
		t.Fatal(err)
	}
	if code := post("/api/admin/users/" + other.ID + "/deactivate"); code != http.StatusOK {
		t.Fatalf("deactivate other admin = %d, want 200", code)
	}
	// Reactivate other and deactivate root through the store, sign in third as admin, then
	// deactivate other through the store too. Third is now the last active admin, so
	// demoting itself via the role endpoint must get 409.
	if err := srv.users.Reactivate(other.ID); err != nil {
		t.Fatal(err)
	}
	if err := srv.users.Deactivate(admin.ID); err != nil {
		t.Fatal(err)
	}
	_, otherCookie := signedInUser(t, srv, "third", users.RoleAdmin)
	if err := srv.users.Deactivate(other.ID); err != nil {
		t.Fatal(err)
	}
	third, _ := srv.users.GetByUsername("third")
	req := httptest.NewRequest(http.MethodPut, "/api/admin/users/"+third.ID+"/role", strings.NewReader(`{"role":"user"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(otherCookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("demote last admin = %d, want 409", rec.Code)
	}
}

func TestAuditListBefore(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	other, err := srv.users.CreateSSOUser("other", users.RoleUser, "sub-other", "other", "other@example.com")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	get := func(q string) []map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/audit?"+q, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v %s", err, rec.Body)
		}
		return out
	}
	putRole := func(role string) {
		req := httptest.NewRequest(http.MethodPut, "/api/admin/users/"+other.ID+"/role", strings.NewReader(`{"role":"`+role+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT role %q status = %d: %s", role, rec.Code, rec.Body)
		}
	}
	// Two audited actions, so paging has something to page across.
	putRole("admin")
	putRole("user")

	all := get("limit=100")
	if len(all) < 2 {
		t.Fatalf("need at least two audit rows, got %d", len(all))
	}
	last := int64(all[0]["index"].(float64))
	older := get(fmt.Sprintf("limit=1&before=%d", last))
	if len(older) != 1 || int64(older[0]["index"].(float64)) >= last {
		t.Fatalf("before did not page: %v", older)
	}
	if bad := get("limit=1&before=x"); len(bad) == 0 {
		t.Fatalf("an invalid before must be ignored, not fail")
	}
}
