package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSPAHandlerNeverListsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets", "fonts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>app"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "fonts", "a.woff2"), []byte("font"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := SPAHandler(dir)

	for _, path := range []string{"/", "/assets/", "/assets/fonts/", "/vault", "/assets/fonts"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app") {
			t.Errorf("%s: code %d body %q, want index.html", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "a.woff2") {
			t.Errorf("%s: directory listing leaked", path)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/fonts/a.woff2", nil))
	if rec.Body.String() != "font" {
		t.Errorf("real file not served: %q", rec.Body.String())
	}
}

func TestManifestContentType(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>app"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.webmanifest"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := SPAHandler(dir)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/manifest.webmanifest", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/manifest+json") {
		t.Errorf("Content-Type %q, want application/manifest+json prefix", ct)
	}
}
