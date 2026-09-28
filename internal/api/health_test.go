package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestPublicHealthRoutesShareCachedProcessStatus(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	read := func(path string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s cache control = %q", path, w.Header().Get("Cache-Control"))
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		want := []string{"schema", "service", "status", "time", "checks"}
		for _, key := range want {
			if _, ok := body[key]; !ok {
				t.Fatalf("GET %s missing %s: %s", path, key, w.Body.String())
			}
		}
		if len(body) != len(want) || body["schema"] != "ky.health/1" || body["service"] != "kyvault" || body["status"] != "ok" {
			t.Fatalf("GET %s unexpected body: %s", path, w.Body.String())
		}
		if checks, ok := body["checks"].([]any); !ok || len(checks) != 0 {
			t.Fatalf("GET %s checks = %v", path, body["checks"])
		}
		return body
	}
	first := read("/healthz")
	time.Sleep(1100 * time.Millisecond)
	second := read("/api/health")
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("aliases differ within cache window: /healthz=%v /api/health=%v", first, second)
	}
}
