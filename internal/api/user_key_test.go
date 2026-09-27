package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

func userKeyBody(t *testing.T, pk byte) []byte {
	t.Helper()
	pub := bytes.Repeat([]byte{pk}, userkey.PublicKeyBytes)
	rec := userkey.Record{Alg: userkey.AlgXWing, PublicKey: base64.StdEncoding.EncodeToString(pub),
		WrappedSeed: base64.StdEncoding.EncodeToString(make([]byte, userkey.WrappedSeedBytes)), CreatedAt: time.Now().UTC()}
	b, _ := json.Marshal(rec)
	return b
}

func putUserKey(handler http.Handler, cookie *http.Cookie, ifMatch string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/vault/user-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", ifMatch)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func putUserKeyCreateOnly(handler http.Handler, cookie *http.Cookie, ifMatch string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/vault/user-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", ifMatch)
	req.Header.Set("If-None-Match", "*")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestUserKeyPublishReplaceAndRead(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	alice, aliceCookie := signedInUser(t, srv, "alice", users.RoleUser)
	_, bobCookie := signedInUser(t, srv, "bob", users.RoleUser)
	if _, err := srv.vault.SaveVault(alice.ID, 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}

	if rec := putUserKey(handler, nil, `"1"`, userKeyBody(t, 1)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous PUT = %d", rec.Code)
	}
	if rec := putUserKey(handler, aliceCookie, `"0"`, userKeyBody(t, 1)); rec.Code != http.StatusConflict {
		t.Fatalf("stale If-Match = %d", rec.Code)
	}
	if rec := putUserKey(handler, aliceCookie, `"1"`, []byte(`{"alg":"xwing","publicKey":"AAAA","wrappedSeed":"AAAA","createdAt":"2026-09-27T00:00:00Z"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad shape = %d", rec.Code)
	}
	rec := putUserKey(handler, aliceCookie, `"1"`, userKeyBody(t, 1))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"fingerprint"`) {
		t.Fatalf("publish = %d %s", rec.Code, rec.Body.String())
	}
	// A second tab racing the first publish with If-None-Match: * must not overwrite it.
	if rec := putUserKeyCreateOnly(handler, aliceCookie, `"1"`, userKeyBody(t, 2)); rec.Code != http.StatusConflict {
		t.Fatalf("create-only against an existing key = %d", rec.Code)
	}
	req0 := httptest.NewRequest(http.MethodGet, "/api/users/"+alice.ID+"/key", nil)
	req0.AddCookie(bobCookie)
	out0 := httptest.NewRecorder()
	handler.ServeHTTP(out0, req0)
	var pub0 userkey.Public
	_ = json.Unmarshal(out0.Body.Bytes(), &pub0)
	if pub0.Fingerprint != userkey.Fingerprint(bytes.Repeat([]byte{1}, userkey.PublicKeyBytes)) || len(pub0.Previous) != 0 {
		t.Fatalf("create-only conflict changed the record: %+v", pub0)
	}
	// second PUT with a different key appends previous
	if rec := putUserKey(handler, aliceCookie, `"1"`, userKeyBody(t, 2)); rec.Code != http.StatusOK {
		t.Fatalf("replace = %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users/"+alice.ID+"/key", nil)
	req.AddCookie(bobCookie)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("bob reads alice's key = %d", out.Code)
	}
	if strings.Contains(out.Body.String(), "wrappedSeed") {
		t.Fatal("public key response leaks wrappedSeed")
	}
	var pub userkey.Public
	_ = json.Unmarshal(out.Body.Bytes(), &pub)
	if pub.UserID != alice.ID || len(pub.Previous) != 1 || pub.Fingerprint != userkey.Fingerprint(bytes.Repeat([]byte{2}, userkey.PublicKeyBytes)) {
		t.Fatalf("public: %+v", pub)
	}

	// GET key 404 when none
	req = httptest.NewRequest(http.MethodGet, "/api/users/no-such-user/key", nil)
	req.AddCookie(bobCookie)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("unknown user = %d", out.Code)
	}

	entries, _ := srv.audit.List(50)
	var published, replaced bool
	for _, e := range entries {
		published = published || e.Action == "user_key.published"
		replaced = replaced || e.Action == "user_key.replaced"
		if strings.Contains(e.Details, "wrappedSeed") || strings.Contains(e.Details, "AAAA") {
			t.Fatalf("audit detail carries key material: %q", e.Details)
		}
	}
	if !published || !replaced {
		t.Fatalf("audit rows: published=%v replaced=%v", published, replaced)
	}
}

func TestUserKeyReadableWithDeviceToken(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	alice, cookie := signedInUser(t, srv, "alice", users.RoleUser)
	if _, err := srv.vault.SaveVault(alice.ID, 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	if rec := putUserKey(handler, cookie, `"1"`, userKeyBody(t, 1)); rec.Code != http.StatusOK {
		t.Fatalf("publish = %d", rec.Code)
	}
	_, token := pairDeviceForTest(t, handler, cookie)
	req := httptest.NewRequest(http.MethodGet, "/api/users/"+alice.ID+"/key", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("device token read = %d", out.Code)
	}
}
