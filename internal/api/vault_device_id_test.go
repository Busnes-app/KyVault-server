package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

// The device recorded for a save is the one the session proves. A header or JSON
// field naming another device, or a path, is ignored.
func TestUploadDeviceIDComesFromTheSession(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	user, cookie := signedInUser(t, srv, "saver", users.RoleUser)
	deviceID, token := pairDeviceForTest(t, handler, cookie)

	// Browser session, JSON body claiming a device: recorded as the web client.
	body, _ := json.Marshal(map[string]any{
		"expectedVersion": 0, "kdbxBase64": base64.StdEncoding.EncodeToString([]byte("v1")),
		"passwordEnvelope": "pw", "recoveryEnvelope": "rec", "deviceId": "chrome-ext",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("browser upload = %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := srv.vault.GetMetadata(user.ID); meta.UpdatedByDevice != "" {
		t.Fatalf("browser save recorded device %q, want none", meta.UpdatedByDevice)
	}

	// Device session forging a path-shaped id on a stale upload: the conflict is named
	// after the real device and the audit row carries it.
	req = httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader([]byte("stale")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-Match", `"0"`)
	req.Header.Set("X-Device-ID", "../../../../escaped")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale device upload = %d: %s", rec.Code, rec.Body.String())
	}
	var conf struct {
		ConflictID string `json:"conflictId"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&conf)
	if !strings.Contains(conf.ConflictID, deviceID) || strings.Contains(conf.ConflictID, "..") {
		t.Fatalf("conflict id %q should name device %s and carry no path", conf.ConflictID, deviceID)
	}
	entries, _ := srv.audit.List(50)
	found := false
	for _, e := range entries {
		if e.Action == "vault.conflict_rejected" {
			found = true
			if e.DeviceID != deviceID {
				t.Fatalf("audit device %q, want %s", e.DeviceID, deviceID)
			}
		}
	}
	if !found {
		t.Fatal("no vault.conflict_rejected audit row")
	}

	// A current device upload records that device.
	req = httptest.NewRequest(http.MethodPost, "/api/vault/upload", bytes.NewReader([]byte("v2")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("If-Match", `"1"`)
	req.Header.Set("X-Device-ID", "someone-else")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device upload = %d: %s", rec.Code, rec.Body.String())
	}
	if meta, _ := srv.vault.GetMetadata(user.ID); meta.UpdatedByDevice != deviceID {
		t.Fatalf("device save recorded %q, want %s", meta.UpdatedByDevice, deviceID)
	}
}
