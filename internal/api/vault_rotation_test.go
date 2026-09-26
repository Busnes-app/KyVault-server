package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

// Key rotation writes the new KDBX and both envelopes in one raw upload. A stale version
// must change nothing; a current one must replace the vault and both envelopes together.
func TestRotationUploadWritesVaultAndBothEnvelopesTogether(t *testing.T) {
	srv := newTestServer(t)
	user, cookie := signedInUser(t, srv, "rotator", users.RoleUser)
	if _, err := srv.vault.SaveVault(user.ID, 0, []byte("old vault"), "old-pw", "old-rec", "web"); err != nil {
		t.Fatal(err)
	}
	handler := srv.Routes()
	upload := func(ifMatch string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader([]byte("new vault")))
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("If-Match", ifMatch)
		request.Header.Set("X-Password-Envelope", "new-pw")
		request.Header.Set("X-Recovery-Envelope", "new-rec")
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	stored := func() (string, string, string, int64) {
		meta, err := srv.vault.GetMetadata(user.ID)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/api/vault/kdbx", nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Body.String(), meta.PasswordEnvelope, meta.RecoveryEnvelope, meta.Version
	}

	if code := upload(`"0"`); code != http.StatusConflict {
		t.Fatalf("stale rotation upload = %d, want 409", code)
	}
	if kdbx, pw, rec, v := stored(); kdbx != "old vault" || pw != "old-pw" || rec != "old-rec" || v != 1 {
		t.Fatalf("stale upload changed state: %q %q %q v%d", kdbx, pw, rec, v)
	}
	if code := upload(`"1"`); code != http.StatusOK {
		t.Fatalf("rotation upload = %d, want 200", code)
	}
	if kdbx, pw, rec, v := stored(); kdbx != "new vault" || pw != "new-pw" || rec != "new-rec" || v != 2 {
		t.Fatalf("rotation upload stored %q %q %q v%d", kdbx, pw, rec, v)
	}
}

// The rotation upload records the version it wrote as the key epoch. Older snapshots are
// flagged and refused for rollback without anyone decrypting them; a password change,
// which only rewraps the same key, does not move the epoch.
func TestRotationWatermarkFlagsAndRefusesOlderSnapshots(t *testing.T) {
	srv := newTestServer(t)
	user, cookie := signedInUser(t, srv, "epoch", users.RoleUser)
	for i, body := range []string{"v1", "v2"} {
		if _, err := srv.vault.SaveVault(user.ID, int64(i), []byte(body), "pw", "rec", "web"); err != nil {
			t.Fatal(err)
		}
	}
	handler := srv.Routes()
	send := func(req *http.Request) *httptest.ResponseRecorder {
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	upload := func(ifMatch string, rotated bool, pw, recEnv string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader([]byte("rotated "+ifMatch)))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("If-Match", ifMatch)
		if pw != "" {
			req.Header.Set("X-Password-Envelope", pw)
		}
		if recEnv != "" {
			req.Header.Set("X-Recovery-Envelope", recEnv)
		}
		if rotated {
			req.Header.Set("X-Vault-Key-Rotated", "1")
		}
		return send(req).Code
	}
	// The flag without both envelopes is not a rotation.
	if code := upload(`"2"`, true, "new-pw", ""); code != http.StatusBadRequest {
		t.Fatalf("rotation without recovery envelope = %d, want 400", code)
	}
	if code := upload(`"2"`, true, "new-pw", "new-rec"); code != http.StatusOK {
		t.Fatalf("rotation upload = %d", code)
	}
	meta, _ := srv.vault.GetMetadata(user.ID)
	if meta.Version != 3 || meta.KeyEpochSince != 3 {
		t.Fatalf("after rotation: v%d epoch %d, want 3 and 3", meta.Version, meta.KeyEpochSince)
	}
	if code := upload(`"3"`, false, "", ""); code != http.StatusOK {
		t.Fatalf("ordinary save = %d", code)
	}
	// Password change: rewraps the same key through the envelopes route.
	put := httptest.NewRequest(http.MethodPut, "/api/vault/envelopes", bytes.NewReader([]byte(`{"passwordEnvelope":"rewrapped"}`)))
	put.Header.Set("Content-Type", "application/json")
	if rec := send(put); rec.Code != http.StatusOK {
		t.Fatalf("envelope PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := srv.vault.GetMetadata(user.ID); meta.KeyEpochSince != 3 {
		t.Fatalf("password change moved the epoch to %d", meta.KeyEpochSince)
	}

	list := send(httptest.NewRequest(http.MethodGet, "/api/vault/history", nil))
	var history []struct {
		ID       string `json:"id"`
		Version  int64  `json:"version"`
		StaleKey bool   `json:"staleKey"`
	}
	if err := json.NewDecoder(list.Body).Decode(&history); err != nil {
		t.Fatal(err)
	}
	var staleID, freshID string
	for _, h := range history {
		if h.StaleKey != (h.Version < 3) {
			t.Fatalf("snapshot v%d staleKey=%v", h.Version, h.StaleKey)
		}
		if h.Version == 2 {
			staleID = h.ID
		}
		if h.Version == 3 {
			freshID = h.ID
		}
	}
	if staleID == "" || freshID == "" {
		t.Fatalf("history = %+v", history)
	}

	before, _ := srv.vault.GetMetadata(user.ID)
	beforeHistory, _ := srv.vault.ListHistory(user.ID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, csrfRequest(t, srv, cookie, http.MethodPost, "/api/vault/history/"+staleID+"/restore", `{}`))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("stale restore = %d %q: %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Fatalf("stale restore body = %s", rec.Body.String())
	}
	after, _ := srv.vault.GetMetadata(user.ID)
	afterHistory, _ := srv.vault.ListHistory(user.ID)
	if after.Version != before.Version || after.Checksum != before.Checksum || len(afterHistory) != len(beforeHistory) {
		t.Fatalf("stale restore changed state: %+v -> %+v", before, after)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, csrfRequest(t, srv, cookie, http.MethodPost, "/api/vault/history/"+freshID+"/restore", `{}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("post-rotation restore = %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := srv.vault.GetMetadata(user.ID); meta.KeyEpochSince != 3 {
		t.Fatalf("rollback moved the epoch to %d", meta.KeyEpochSince)
	}
}
