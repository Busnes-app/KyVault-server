package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

// A restart must not end browser sessions or device pairings, and the file that carries
// them across it must not contain anything a request could present.
func TestSessionsSurviveRestartAsHashes(t *testing.T) {
	dir := t.TempDir()
	srv, dataDir := newServerIn(t, dir)
	_, cookie := signedInUser(t, srv, "hana", users.RoleUser)
	_, token := pairDeviceForTest(t, srv.Routes(), cookie)

	raw, err := os.ReadFile(dataDir + "/sessions.json")
	if err != nil {
		t.Fatalf("sessions.json: %v", err)
	}
	for _, secret := range []string{cookie.Value, token} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("sessions.json holds a raw token")
		}
	}
	if !strings.Contains(string(raw), sessionKey(token)) {
		t.Fatalf("sessions.json does not hold the token hash")
	}
	srv.Close()

	again, _ := newServerIn(t, dir)
	for name, req := range map[string]*http.Request{
		"cookie": withCookie(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), cookie),
		"bearer": withBearer(httptest.NewRequest(http.MethodGet, "/api/vault/metadata", nil), token),
	} {
		rec := httptest.NewRecorder()
		again.Routes().ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s session did not survive the restart", name)
		}
	}
}

func TestExpiredSessionsArePrunedAndNotLoaded(t *testing.T) {
	dir := t.TempDir()
	srv, _ := newServerIn(t, dir)
	_, stale := signedInUser(t, srv, "ivo", users.RoleUser)
	srv.sessMu.Lock()
	sess := srv.sessions[sessionKey(stale.Value)]
	sess.ExpiresAt = time.Now().Add(-time.Second)
	srv.sessions[sessionKey(stale.Value)] = sess
	srv.saveSessionsLocked()
	srv.sessMu.Unlock()

	// The periodic flush prunes in place.
	srv.flushOnce()
	srv.sessMu.RLock()
	_, present := srv.sessions[sessionKey(stale.Value)]
	srv.sessMu.RUnlock()
	if present {
		t.Fatal("expired session survived the flush")
	}

	// And a restart never loads one, even if a flush did not run first.
	srv.sessMu.Lock()
	srv.sessions[sessionKey(stale.Value)] = sess
	srv.saveSessionsLocked()
	srv.sessMu.Unlock()
	srv.Close()
	again, _ := newServerIn(t, dir)
	if len(again.sessions) != 0 {
		t.Fatalf("expired session loaded: %d sessions", len(again.sessions))
	}
}

func TestSessionInventoryListsOwnAndEndsOthers(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, mine := signedInUser(t, srv, "jo", users.RoleUser)
	_, theirs := signedInUser(t, srv, "kim", users.RoleUser)
	deviceID, token := pairDeviceForTest(t, handler, mine)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil), mine))
	var list []sessionView
	_ = json.NewDecoder(rec.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("inventory = %+v, want the browser and the device session", list)
	}
	var current, device sessionView
	for _, v := range list {
		if v.Current {
			current = v
		}
		if v.Kind == "device" {
			device = v
		}
	}
	if current.ID == "" || current.Kind != "browser" || device.DeviceID != deviceID || device.DeviceName == "" || device.Current {
		t.Fatalf("inventory rows wrong: %+v", list)
	}
	if strings.Contains(rec.Body.String(), sessionKey(token)) || strings.Contains(rec.Body.String(), token) {
		t.Fatal("inventory leaks a token or its hash")
	}

	// Ending the current session is refused; logout is the way.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/"+current.ID, nil), mine))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ending own session = %d, want 400", rec.Code)
	}
	// Another user cannot end it.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/"+device.ID, nil), theirs))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user end = %d, want 404", rec.Code)
	}
	// The owner ends the device session, which revokes the device too.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/"+device.ID, nil), mine))
	if rec.Code != http.StatusOK {
		t.Fatalf("end device session = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, withBearer(httptest.NewRequest(http.MethodGet, "/api/vault/metadata", nil), token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("device token still works after its session was ended: %d", rec.Code)
	}
	if _, err := srv.devices.Get(deviceID); err == nil {
		t.Fatal("device record survived ending its session")
	}
}

func TestPairingRedeemLocksASourceAfterThreeWrongCodes(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, cookie := signedInUser(t, srv, "lee", users.RoleUser)

	redeem := func(addr, code string) int {
		body := `{"codeOrPin":"` + code + `","deviceName":"x","platform":"test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem", strings.NewReader(body))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < pairingMaxFailures; i++ {
		if code := redeem("10.0.0.1:1", "000000"); code != http.StatusBadRequest {
			t.Fatalf("wrong code %d = %d, want 400", i+1, code)
		}
	}
	// The fourth from the same source is refused before the store is consulted, even
	// with a code that would be right.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodPost, "/api/devices/pairing/start", nil), cookie))
	var start map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&start)
	pin, _ := start["pin"].(string)
	if code := redeem("10.0.0.1:2", pin); code != http.StatusTooManyRequests {
		t.Fatalf("locked source = %d, want 429", code)
	}
	// Another source is unaffected and the pairing is still redeemable.
	if code := redeem("10.0.0.2:1", pin); code != http.StatusOK {
		t.Fatalf("other source = %d, want 200", code)
	}
	// The lockout ends with the window.
	srv.pairings.now = func() time.Time { return time.Now().Add(pairingLockout + time.Second) }
	if code := redeem("10.0.0.1:3", "000000"); code != http.StatusBadRequest {
		t.Fatalf("after the window = %d, want 400", code)
	}
}

func withCookie(r *http.Request, c *http.Cookie) *http.Request {
	r.AddCookie(c)
	return r
}

func withBearer(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
