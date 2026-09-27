package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
)

func lookup(h http.Handler, c *http.Cookie, bearer, name string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/users/lookup?username="+name, nil)
	if c != nil {
		req.AddCookie(c)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUserLookup(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	_, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, _ := signedInUser(t, srv, "bob", users.RoleUser)
	bobFP := publishKey(t, srv, bob, 2)
	carol, _ := signedInUser(t, srv, "carol", users.RoleUser) // no key
	_ = carol

	rec := lookup(h, aliceC, "", "bob")
	if rec.Code != http.StatusOK {
		t.Fatalf("bob = %d %s", rec.Code, rec.Body.String())
	}
	var got struct{ UserID, Username, Fingerprint string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UserID != bob.ID || got.Username != "bob" || got.Fingerprint != bobFP {
		t.Fatalf("got %+v", got)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("publicKey")) || bytes.Contains(rec.Body.Bytes(), []byte("wrappedSeed")) {
		t.Fatal("lookup must return only id, username and fingerprint")
	}
	for _, name := range []string{"carol", "nobody", ""} {
		if rec := lookup(h, aliceC, "", name); rec.Code != http.StatusNotFound {
			t.Fatalf("%q = %d", name, rec.Code)
		}
	}
	if rec := lookup(h, nil, "", "bob"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", rec.Code)
	}
	// Inactive users look like unknown ones.
	if err := srv.users.Deactivate(bob.ID); err != nil {
		t.Fatal(err)
	}
	if rec := lookup(h, aliceC, "", "bob"); rec.Code != http.StatusNotFound {
		t.Fatalf("inactive bob = %d", rec.Code)
	}
	entries, err := srv.audit.List(50)
	if err != nil {
		t.Fatal(err)
	}
	found, limited := 0, 0
	for _, e := range entries {
		switch e.Action {
		case "user.lookup":
			found++
		case "user.lookup_limited":
			limited++
		}
	}
	if found < 5 || limited != 0 {
		t.Fatalf("audit lookup=%d limited=%d", found, limited)
	}
}

func TestUserLookupDeviceTokenAndLimit(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	_, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, _ := signedInUser(t, srv, "bob", users.RoleUser)
	publishKey(t, srv, bob, 2)
	_, token := pairDeviceForTest(t, h, aliceC)
	if rec := lookup(h, nil, token, "bob"); rec.Code != http.StatusOK {
		t.Fatalf("device = %d %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 20; i++ {
		if rec := lookup(h, aliceC, "", "nobody"); rec.Code != http.StatusNotFound {
			t.Fatalf("miss %d = %d", i, rec.Code)
		}
	}
	if rec := lookup(h, aliceC, "", "bob"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after 20 misses = %d", rec.Code)
	}
	entries, err := srv.audit.List(50)
	if err != nil {
		t.Fatal(err)
	}
	limited := 0
	for _, e := range entries {
		if e.Action == "user.lookup_limited" {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("limited rows = %d", limited)
	}
	_ = userkey.PublicKeyBytes
}
