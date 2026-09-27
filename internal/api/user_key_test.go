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

	"github.com/Busnes-app/kyvault-server/internal/sso"
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

	// A device token must not be able to publish or replace the key.
	putReq := httptest.NewRequest(http.MethodPut, "/api/vault/user-key", bytes.NewReader(userKeyBody(t, 2)))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("If-Match", `"1"`)
	putReq.Header.Set("Authorization", "Bearer "+token)
	putOut := httptest.NewRecorder()
	handler.ServeHTTP(putOut, putReq)
	if putOut.Code != http.StatusForbidden {
		t.Fatalf("device token PUT = %d", putOut.Code)
	}

	checkReq := httptest.NewRequest(http.MethodGet, "/api/users/"+alice.ID+"/key", nil)
	checkReq.AddCookie(cookie)
	checkOut := httptest.NewRecorder()
	handler.ServeHTTP(checkOut, checkReq)
	var pub userkey.Public
	_ = json.Unmarshal(checkOut.Body.Bytes(), &pub)
	if pub.Fingerprint != userkey.Fingerprint(bytes.Repeat([]byte{1}, userkey.PublicKeyBytes)) || len(pub.Previous) != 0 {
		t.Fatalf("device PUT changed the record: %+v", pub)
	}
}

// staleSession signs the user in with an auth_time older than freshSessionWindow.
func staleSession(t *testing.T, srv *Server, u users.User) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	id := sso.Identity{Issuer: "https://kysignon.test", ClientID: "kyvault-app", Subject: u.SSOSub, SessionID: "sid-stale-" + u.Username, IssuedAt: time.Now().UTC().Add(-time.Hour)}
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), u.ID, id, time.Now().UTC().Add(-freshSessionWindow-time.Minute)); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypass_session" {
			return c
		}
	}
	t.Fatal("no session cookie was issued")
	return nil
}

// The master password proof lives in the browser, so a stolen session must not be able
// to replace the published identity on its own: replace needs a recent KySignOn sign-in.
// First publish is create-only and stays open to any session.
func TestUserKeyReplaceNeedsFreshSession(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	alice, fresh := signedInUser(t, srv, "alice", users.RoleUser)
	if _, err := srv.vault.SaveVault(alice.ID, 0, []byte("v"), "pw", "rec", ""); err != nil {
		t.Fatal(err)
	}
	stale := staleSession(t, srv, alice)

	// First publish from a stale session is allowed (create-only).
	req := httptest.NewRequest(http.MethodPut, "/api/vault/user-key", bytes.NewReader(userKeyBody(t, 1)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"1"`)
	req.Header.Set("If-None-Match", "*")
	req.AddCookie(stale)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stale first publish = %d %s", rec.Code, rec.Body.String())
	}
	before, _ := srv.vault.GetMetadata(alice.ID)

	if rec := putUserKey(handler, stale, `"1"`, userKeyBody(t, 2)); rec.Code != http.StatusForbidden || !strings.HasPrefix(rec.Body.String(), "re-authenticate") {
		t.Fatalf("stale replace = %d %s", rec.Code, rec.Body.String())
	}
	after, _ := srv.vault.GetMetadata(alice.ID)
	if after.UserKey.PublicKey != before.UserKey.PublicKey || after.UserKey.WrappedSeed != before.UserKey.WrappedSeed || len(after.UserKey.Previous) != 0 {
		t.Fatal("stale replace changed the record")
	}

	if rec := putUserKey(handler, fresh, `"1"`, userKeyBody(t, 2)); rec.Code != http.StatusOK {
		t.Fatalf("fresh replace = %d %s", rec.Code, rec.Body.String())
	}
}
