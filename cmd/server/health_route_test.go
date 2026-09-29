package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/api"
)

func TestProductionMuxServesBothPublicHealthAliases(t *testing.T) {
	dir := t.TempDir()
	srv, err := api.NewServer(api.Config{DataDir: dir + "/data", ConfigDir: dir + "/config"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	mountAPIRoutes(mux, srv.Routes())
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // Models the SPA/development fallback.
	})

	read := func(path string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 5 || body["schema"] != "ky.health/1" || body["service"] != "kyvault" || body["status"] != "ok" {
			t.Fatalf("GET %s: %s", path, w.Body.String())
		}
		if checks, ok := body["checks"].([]any); !ok || len(checks) != 0 {
			t.Fatalf("GET %s checks = %v", path, body["checks"])
		}
		return body
	}
	first := read("/healthz")
	time.Sleep(1100 * time.Millisecond)
	if second := read("/api/health"); !reflect.DeepEqual(first, second) {
		t.Fatalf("production aliases use different evaluations: %v vs %v", first, second)
	}
	for _, path := range []string{"/api/auth/me", "/auth/sso/login", "/scim/v2/Users"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusTeapot {
			t.Fatalf("GET %s reached SPA fallback", path)
		}
	}
	fallback := httptest.NewRecorder()
	mux.ServeHTTP(fallback, httptest.NewRequest(http.MethodGet, "/unrelated", nil))
	if fallback.Code != http.StatusTeapot {
		t.Fatalf("unrelated path = %d, want fallback", fallback.Code)
	}
}
