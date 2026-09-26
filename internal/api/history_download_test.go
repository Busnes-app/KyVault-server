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

func TestHistoryDownloadOwnerOnlyAndSafeIDs(t *testing.T) {
	srv, dataDir := newServerIn(t, t.TempDir())
	owner, cookie := signedInUser(t, srv, "hana", users.RoleUser)
	victim, other := signedInUser(t, srv, "ivo", users.RoleUser)
	first := []byte("kdbx-v1")
	for i, body := range [][]byte{first, []byte("kdbx-v2")} {
		if _, err := srv.vault.SaveVault(owner.ID, int64(i), body, "", "", "web"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.vault.SaveVault(victim.ID, 0, []byte("victim ciphertext"), "", "", "web"); err != nil {
		t.Fatal(err)
	}
	history, err := srv.vault.ListHistory(owner.ID)
	if err != nil || len(history) != 1 {
		t.Fatalf("history = %+v %v", history, err)
	}
	id := history[0].ID

	get := func(c *http.Cookie, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/vault/history/"+url.PathEscape(id), nil)
		if c != nil {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := get(cookie, id); rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), first) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("owner download = %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if rec := get(other, id); rec.Code != http.StatusNotFound {
		t.Fatalf("other user = %d", rec.Code)
	}
	if rec := get(nil, id); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", rec.Code)
	}

	// A symlink planted in the history directory must not lead out of it.
	if err := os.Symlink(filepath.Join(dataDir, "vaults", victim.ID, "vault.kdbx"), filepath.Join(dataDir, "vaults", owner.ID, "history", "planted.kdbx")); err != nil {
		t.Fatal(err)
	}
	bad := []string{"missing", "../vault", "../../" + victim.ID + "/vault", "a/b", `a\b`, "\x00", "planted"}
	for _, b := range bad {
		if rec := get(cookie, b); rec.Code != http.StatusNotFound {
			t.Errorf("download %q = %d, want 404", b, rec.Code)
		}
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, csrfRequest(t, srv, cookie, http.MethodPost, "/api/vault/history/"+url.PathEscape(b)+"/restore", `{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("restore %q = %d, want 404", b, rec.Code)
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
		t.Fatalf("vault bytes changed to %q", current)
	}
	if after, _ := srv.vault.ListHistory(owner.ID); len(after) != 2 { // the snapshot plus the planted symlink
		t.Fatalf("history changed: %+v", after)
	}

	downloads := 0
	audit, _ := srv.audit.List(200)
	for _, e := range audit {
		if e.Action == "vault.snapshot_downloaded" {
			downloads++
			if e.Details != "downloaded snapshot "+id {
				t.Fatalf("audit details = %q", e.Details)
			}
		}
	}
	if downloads != 1 {
		t.Fatalf("snapshot download audits = %d, want 1", downloads)
	}
}
