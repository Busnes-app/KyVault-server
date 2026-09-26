package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
