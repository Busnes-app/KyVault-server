package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

func TestHistoryRestoreRefusesPathShapedIDs(t *testing.T) {
	srv, dataDir := newServerIn(t, t.TempDir())
	owner, cookie := signedInUser(t, srv, "hana", users.RoleUser)
	victim, _ := signedInUser(t, srv, "ivo", users.RoleUser)
	for i, body := range [][]byte{[]byte("kdbx-v1"), []byte("kdbx-v2")} {
		if _, err := srv.vault.SaveVault(owner.ID, int64(i), body, "", "", "web"); err != nil {
			t.Fatal(err)
		}
	}
	victimBytes := []byte("victim ciphertext")
	if _, err := srv.vault.SaveVault(victim.ID, 0, victimBytes, "", "", "web"); err != nil {
		t.Fatal(err)
	}
	victimVault := filepath.Join(dataDir, "vaults", victim.ID, "vault.kdbx")
	if _, err := os.Stat(victimVault); err != nil {
		t.Fatalf("victim vault not where the test expects: %v", err)
	}
	// A symlink planted in the history directory must not lead out of it.
	if err := os.Symlink(victimVault, filepath.Join(dataDir, "vaults", owner.ID, "history", "planted.kdbx")); err != nil {
		t.Fatal(err)
	}

	bad := []string{
		"missing",
		"../vault",
		"../../" + victim.ID + "/vault",
		filepath.Join(dataDir, "vaults", victim.ID, "vault"),
		"a/b",
		`a\b`,
		"\x00",
		"planted",
	}
	for _, id := range bad {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, http.MethodPost, "/api/vault/history/"+url.PathEscape(id)+"/restore", `{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("restore %q = %d, want 404", id, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), victimBytes) {
			t.Errorf("restore %q leaked victim bytes", id)
		}
	}

	// Refused restores touched nothing: same version, same bytes, no new snapshot.
	meta, err := srv.vault.GetMetadata(owner.ID)
	if err != nil || meta.Version != 2 {
		t.Fatalf("metadata after refused restores = %+v %v", meta, err)
	}
	rc, _, err := srv.vault.OpenVault(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := io.ReadAll(rc)
	rc.Close()
	if string(current) != "kdbx-v2" {
		t.Fatalf("owner vault bytes changed to %q", current)
	}
	if after, _ := srv.vault.ListHistory(owner.ID); len(after) != 2 { // the real snapshot plus the planted symlink
		t.Fatalf("history changed: %+v", after)
	}
}
