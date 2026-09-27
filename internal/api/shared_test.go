package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

var t0 = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

// sealedKeyFor is a well-formed sealed key whose bytes are all b, so each member's copy
// is distinguishable in a response body.
func sealedKeyFor(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, shared.SealedKeyBytes))
}

// publishKey gives u a user key with public key bytes all = pk and returns its fingerprint.
func publishKey(t *testing.T, srv *Server, u users.User, pk byte) string {
	t.Helper()
	meta, err := srv.vault.GetMetadata(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version == 0 {
		if meta, err = srv.vault.SaveVault(u.ID, 0, []byte("v"), "pw", "rec", ""); err != nil {
			t.Fatal(err)
		}
	}
	rec := userkey.Record{Alg: userkey.AlgXWing, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{pk}, userkey.PublicKeyBytes)),
		WrappedSeed: base64.StdEncoding.EncodeToString(make([]byte, userkey.WrappedSeedBytes)), CreatedAt: t0}
	if _, err := srv.vault.SaveUserKey(u.ID, meta.Version, rec, false); err != nil {
		t.Fatal(err)
	}
	fp, err := rec.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// do sends a request as a browser would: a cookie session also carries its CSRF token.
func do(t *testing.T, srv *Server, method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		browserAuth(srv, req, cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// browserAuth adds a cookie session and its CSRF token to req.
func browserAuth(srv *Server, req *http.Request, cookie *http.Cookie) {
	req.AddCookie(cookie)
	srv.sessMu.RLock()
	token := srv.sessions[sessionKey(cookie.Value)].CSRFToken
	srv.sessMu.RUnlock()
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
}

func createShared(t *testing.T, srv *Server, cookie *http.Cookie, name, sealedKey, fp string) string {
	t.Helper()
	rec := do(t, srv, http.MethodPost, "/api/shared", cookie, map[string]any{"name": name, "sealedKey": sealedKey, "keyFingerprint": fp})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !shared.ValidID(out.ID) {
		t.Fatalf("create body %s: %v", rec.Body.String(), err)
	}
	return out.ID
}

func invite(t *testing.T, srv *Server, cookie *http.Cookie, id, userID, role, sealedKey, fp string) {
	t.Helper()
	rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", cookie, map[string]any{"userId": userID, "role": role, "sealedKey": sealedKey, "keyFingerprint": fp})
	if rec.Code != http.StatusOK {
		t.Fatalf("invite %s = %d %s", userID, rec.Code, rec.Body.String())
	}
}

func expectCode(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s = %d, want %d: %s", what, rec.Code, want, rec.Body.String())
	}
}

// assertNoForeignKeys fails if body carries any sealed key in foreign.
func assertNoForeignKeys(t *testing.T, what, body string, foreign ...string) {
	t.Helper()
	for _, k := range foreign {
		if strings.Contains(body, k) {
			t.Fatalf("%s leaks another member's sealed key: %s", what, body)
		}
	}
}

func assertAudited(t *testing.T, srv *Server, actions ...string) {
	t.Helper()
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, a := range actions {
		want[a] = false
	}
	for _, e := range entries {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
		for b := 0; b < 256; b++ {
			if strings.Contains(e.Details, sealedKeyFor(byte(b))[:40]) {
				t.Fatalf("audit detail carries a sealed key: %s %s", e.Action, e.Details)
			}
		}
	}
	for a, seen := range want {
		if !seen {
			t.Fatalf("missing audit %s", a)
		}
	}
}

func TestSharedCreateInviteAcceptAndVisibility(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	_, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	aliceKey, bobKey := sealedKeyFor(0xA1), sealedKeyFor(0xB2)

	// No published key → 404 on create; fingerprint mismatch → 400.
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared", carolC, map[string]any{"name": "x", "sealedKey": aliceKey, "keyFingerprint": "nope"}), http.StatusNotFound, "create without key")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared", aliceC, map[string]any{"name": "x", "sealedKey": aliceKey, "keyFingerprint": bobFP}), http.StatusBadRequest, "create fp mismatch")
	id := createShared(t, srv, aliceC, "Finance", aliceKey, aliceFP)

	// Path-shaped or unknown vault ids are 404.
	for _, p := range []string{"/api/shared/shared%2F..%2F" + alice.ID, "/api/shared/u-1", "/api/shared/sv_zzzzzzzzzzzzzzzzzzzzzz"} {
		expectCode(t, do(t, srv, http.MethodGet, p, aliceC, nil), http.StatusNotFound, "GET "+p)
	}
	// A non-member sees 404 everywhere, indistinguishable from an unknown id.
	for _, m := range []struct{ method, path string }{
		{"GET", "/api/shared/" + id}, {"PATCH", "/api/shared/" + id}, {"DELETE", "/api/shared/" + id},
		{"POST", "/api/shared/" + id + "/members"}, {"PUT", "/api/shared/" + id + "/members/" + alice.ID},
		{"DELETE", "/api/shared/" + id + "/members/" + alice.ID}, {"POST", "/api/shared/" + id + "/accept"},
		{"POST", "/api/shared/" + id + "/decline"},
	} {
		expectCode(t, do(t, srv, m.method, m.path, carolC, map[string]any{"name": "y"}), http.StatusNotFound, "non-member "+m.method+" "+m.path)
	}

	// Invite bob: wrong fp → 400, bad role → 400, right → 200, twice → 409.
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": bobKey, "keyFingerprint": aliceFP}), http.StatusBadRequest, "invite fp mismatch")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "admin", "sealedKey": bobKey, "keyFingerprint": bobFP}), http.StatusBadRequest, "invite bad role")
	invite(t, srv, aliceC, id, bob.ID, "editor", bobKey, bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": bob.ID, "role": "reader", "sealedKey": bobKey, "keyFingerprint": bobFP}), http.StatusConflict, "double invite")

	// Bob's list shows the invitation with alice's fingerprint and only his own key; the vault stays closed.
	rec := do(t, srv, http.MethodGet, "/api/shared", bobC, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"invited"`) || !strings.Contains(rec.Body.String(), aliceFP) || !strings.Contains(rec.Body.String(), bobKey) {
		t.Fatalf("bob list = %d %s", rec.Code, rec.Body.String())
	}
	assertNoForeignKeys(t, "bob list", rec.Body.String(), aliceKey)
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil), http.StatusNotFound, "invited GET vault")

	rec = do(t, srv, http.MethodGet, "/api/shared", aliceC, nil)
	assertNoForeignKeys(t, "alice list", rec.Body.String(), bobKey)
	rec = do(t, srv, http.MethodGet, "/api/shared/"+id, aliceC, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sealedKey") {
		t.Fatalf("owner GET = %d %s", rec.Code, rec.Body.String())
	}
	assertNoForeignKeys(t, "owner GET", rec.Body.String(), aliceKey, bobKey)

	// Only an invited row accepts.
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", aliceC, nil), http.StatusConflict, "owner accept")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	rec = do(t, srv, http.MethodGet, "/api/shared", bobC, nil)
	if !strings.Contains(rec.Body.String(), `"state":"active"`) || strings.Count(rec.Body.String(), "sealedKey") != 1 {
		t.Fatalf("bob list after accept: %s", rec.Body.String())
	}
	assertNoForeignKeys(t, "bob list after accept", rec.Body.String(), aliceKey)
	rec = do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil)
	expectCode(t, rec, http.StatusOK, "bob GET")
	assertNoForeignKeys(t, "bob GET", rec.Body.String(), aliceKey, bobKey)

	// Rename: editors cannot, owners can, validation applies.
	expectCode(t, do(t, srv, http.MethodPatch, "/api/shared/"+id, bobC, map[string]any{"name": "Ops"}), http.StatusForbidden, "editor rename")
	expectCode(t, do(t, srv, http.MethodPatch, "/api/shared/"+id, aliceC, map[string]any{"name": ""}), http.StatusBadRequest, "empty rename")
	expectCode(t, do(t, srv, http.MethodPatch, "/api/shared/"+id, aliceC, map[string]any{"name": "Ops"}), http.StatusOK, "rename")

	// Last-owner rule via the API, then leave.
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+alice.ID, aliceC, map[string]any{"role": "reader"}), http.StatusConflict, "demote last owner")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+alice.ID, aliceC, nil), http.StatusConflict, "last owner leaves")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+bob.ID, bobC, nil), http.StatusOK, "bob leaves")
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil), http.StatusNotFound, "after leave")

	// Owner delete needs a fresh session; then the vault is gone for everyone.
	stale := staleSession(t, srv, alice)
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id, stale, nil), http.StatusForbidden, "stale delete")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id, aliceC, nil), http.StatusOK, "delete")
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, aliceC, nil), http.StatusNotFound, "after delete")

	assertAudited(t, srv, "shared.created", "shared.member_invited", "shared.member_accepted", "shared.renamed", "shared.member_left", "shared.deleted")
}

func TestSharedMemberUpdateRemoveAndDecline(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	dave, _ := signedInUser(t, srv, "dave", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	carolFP := publishKey(t, srv, carol, 3)
	publishKey(t, srv, dave, 4)
	aliceKey := sealedKeyFor(0xA1)
	id := createShared(t, srv, aliceC, "Finance", aliceKey, aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "reader", sealedKeyFor(0xB2), bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")

	member := func(uid string) shared.Member {
		t.Helper()
		v, err := srv.shared.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		return v.Members[uid]
	}

	// A path user with no row is 404, before any key or user lookup.
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+dave.ID, aliceC, map[string]any{"role": "reader"}), http.StatusNotFound, "PUT non-member target")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+dave.ID, aliceC, nil), http.StatusNotFound, "DELETE non-member target")

	// Validation happens before any write.
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, bobC, map[string]any{"role": "owner"}), http.StatusForbidden, "reader changes role")
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"role": "boss"}), http.StatusBadRequest, "bad role")
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"sealedKey": sealedKeyFor(0xB3)}), http.StatusBadRequest, "sealedKey without fp")
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"sealedKey": "short", "keyFingerprint": bobFP}), http.StatusBadRequest, "bad sealedKey")
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"role": "editor", "sealedKey": sealedKeyFor(0xB3), "keyFingerprint": aliceFP}), http.StatusBadRequest, "reseal fp mismatch")
	if m := member(bob.ID); m.Role != shared.RoleReader || m.SealedKey != sealedKeyFor(0xB2) {
		t.Fatalf("refused update changed bob: %+v", m)
	}
	// Role is applied first: a last-owner refusal leaves the seal untouched.
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+alice.ID, aliceC, map[string]any{"role": "reader", "sealedKey": sealedKeyFor(0xA9), "keyFingerprint": aliceFP}), http.StatusConflict, "demote last owner with reseal")
	if m := member(alice.ID); m.Role != shared.RoleOwner || m.SealedKey != aliceKey {
		t.Fatalf("refused demote resealed alice: %+v", m)
	}

	// Bob replaces his user key; alice re-seals to it and promotes him in one call.
	bobFP2 := publishKey(t, srv, bob, 5)
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"sealedKey": sealedKeyFor(0xB3), "keyFingerprint": bobFP}), http.StatusBadRequest, "reseal to retired key")
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"role": "editor", "sealedKey": sealedKeyFor(0xB3), "keyFingerprint": bobFP2}), http.StatusOK, "reseal and promote")
	if m := member(bob.ID); m.Role != shared.RoleEditor || m.SealedKey != sealedKeyFor(0xB3) || m.KeyFingerprint != bobFP2 || m.SealedBy != alice.ID {
		t.Fatalf("bob after update: %+v", m)
	}

	// Invited carol deletes her own row: that is a decline, not a leave. Before that, an
	// invited row cannot probe who else is a member.
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), carolFP)
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+dave.ID, carolC, map[string]any{"role": "reader"}), http.StatusForbidden, "invited PUT probe")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+dave.ID, carolC, nil), http.StatusForbidden, "invited DELETE probe")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+bob.ID, carolC, nil), http.StatusForbidden, "invited removes bob")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+carol.ID, carolC, nil), http.StatusOK, "carol declines by delete")
	// Decline route, and an owner removing an editor.
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), carolFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/decline", carolC, nil), http.StatusOK, "carol declines")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/decline", bobC, nil), http.StatusConflict, "active member declines")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+alice.ID, bobC, nil), http.StatusForbidden, "editor removes owner")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+bob.ID, aliceC, nil), http.StatusOK, "owner removes bob")
	if v, err := srv.shared.Get(id); err != nil || len(v.Members) != 1 {
		t.Fatalf("members after removals: %+v %v", v.Members, err)
	}

	assertAudited(t, srv, "shared.member_declined", "shared.member_role_changed", "shared.member_resealed", "shared.member_removed")
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	declined := 0
	for _, e := range entries {
		switch e.Action {
		case "shared.member_left":
			t.Fatalf("an invited self-removal was audited as a leave: %s", e.Details)
		case "shared.member_declined":
			declined++
		}
	}
	if declined != 2 {
		t.Fatalf("shared.member_declined rows = %d, want 2 (self-DELETE and /decline)", declined)
	}
}

func TestSharedAdminAndSettings(t *testing.T) {
	srv := newTestServer(t)
	admin, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	dave, _ := signedInUser(t, srv, "dave", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	carolFP := publishKey(t, srv, carol, 3)
	daveFP := publishKey(t, srv, dave, 4)
	aliceKey, bobKey := sealedKeyFor(0xA1), sealedKeyFor(0xB2)
	id := createShared(t, srv, aliceC, "Finance", aliceKey, aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", bobKey, bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), carolFP)

	// Admin sees it with no sealed keys, is not a member, cannot read it through member routes.
	rec := do(t, srv, http.MethodGet, "/api/admin/shared", adminC, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), id) || strings.Contains(rec.Body.String(), "sealedKey") {
		t.Fatalf("admin list = %d %s", rec.Code, rec.Body.String())
	}
	assertNoForeignKeys(t, "admin list", rec.Body.String(), aliceKey, bobKey, sealedKeyFor(0xC3))
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, adminC, nil), http.StatusNotFound, "admin member GET")
	expectCode(t, do(t, srv, http.MethodGet, "/api/admin/shared", aliceC, nil), http.StatusForbidden, "user admin list")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id, aliceC, nil), http.StatusForbidden, "user admin delete")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+bob.ID, aliceC, nil), http.StatusForbidden, "user admin member remove")
	expectCode(t, do(t, srv, http.MethodPut, "/api/admin/shared/settings", aliceC, map[string]any{"createRestrictedToAdmins": true}), http.StatusForbidden, "user settings put")
	expectCode(t, do(t, srv, http.MethodGet, "/api/admin/shared/settings", aliceC, nil), http.StatusForbidden, "user settings get")

	// Settings: a stale admin cannot change them; a fresh one restricts creation to admins.
	stale := staleSession(t, srv, admin)
	expectCode(t, do(t, srv, http.MethodPut, "/api/admin/shared/settings", stale, map[string]any{"createRestrictedToAdmins": true}), http.StatusForbidden, "stale settings put")
	expectCode(t, do(t, srv, http.MethodPut, "/api/admin/shared/settings", adminC, map[string]any{"createRestrictedToAdmins": true}), http.StatusOK, "settings put")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared", aliceC, map[string]any{"name": "x", "sealedKey": aliceKey, "keyFingerprint": aliceFP}), http.StatusForbidden, "restricted create")
	adminFP := publishKey(t, srv, admin, 9)
	createShared(t, srv, adminC, "Admin vault", sealedKeyFor(0xD4), adminFP)
	rec = do(t, srv, http.MethodGet, "/api/admin/shared/settings", adminC, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"createRestrictedToAdmins":true`) {
		t.Fatalf("settings get = %d %s", rec.Code, rec.Body.String())
	}

	// Admin member removal needs a fresh session; a fresh admin may remove the last owner.
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+alice.ID, stale, nil), http.StatusForbidden, "stale admin remove")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+dave.ID, adminC, nil), http.StatusNotFound, "admin remove non-member")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+alice.ID, adminC, nil), http.StatusOK, "admin remove owner")
	rec = do(t, srv, http.MethodGet, "/api/admin/shared", adminC, nil)
	if !strings.Contains(rec.Body.String(), `"ownerless":true`) {
		t.Fatalf("ownerless flag missing: %s", rec.Body.String())
	}

	// Ownerless: existing members keep reading, nobody joins, members cannot delete.
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil), http.StatusOK, "editor reads ownerless")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", bobC, map[string]any{"userId": dave.ID, "role": "reader", "sealedKey": sealedKeyFor(0xE5), "keyFingerprint": daveFP}), http.StatusForbidden, "editor invites into ownerless")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", carolC, nil), http.StatusConflict, "accept into ownerless")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id, bobC, nil), http.StatusForbidden, "editor deletes ownerless")

	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id, stale, nil), http.StatusForbidden, "stale admin delete")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/sv_zzzzzzzzzzzzzzzzzzzzzz", adminC, nil), http.StatusNotFound, "admin delete unknown")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id, adminC, nil), http.StatusOK, "admin delete")
	if _, err := srv.shared.Get(id); err == nil {
		t.Fatal("vault still exists after admin delete")
	}

	assertAudited(t, srv, "admin.shared_member_removed", "admin.shared_settings_updated", "admin.shared_deleted")
}

// Delete moves the vault data into the deleted area; a late save to the old key cannot
// bring it back into the live store.
func TestSharedDeleteMovesVaultData(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	if _, err := srv.vault.SaveVault(shared.StoreKey(id), 0, []byte("kdbx"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id, aliceC, nil), http.StatusOK, "delete")
	if got, err := os.ReadFile(filepath.Join(srv.dataDir, "shared", "deleted", id, "vault", "vault.kdbx")); err != nil || string(got) != "kdbx" {
		t.Fatalf("deleted area kdbx = %q, %v", got, err)
	}
	meta, err := srv.vault.GetMetadata(shared.StoreKey(id))
	if err != nil || meta.Version != 0 {
		t.Fatalf("live metadata after delete = %+v, %v", meta, err)
	}
	liveDir := filepath.Join(srv.dataDir, "vaults", "shared", id)
	for _, version := range []int64{1, 0} {
		if _, err := srv.vault.SaveVault(shared.StoreKey(id), version, []byte("late"), "", "", ""); !errors.Is(err, vault.ErrRetired) {
			t.Fatalf("late save at version %d = %v", version, err)
		}
		if _, err := os.Stat(liveDir); !os.IsNotExist(err) {
			t.Fatalf("late save at version %d recreated %s: %v", version, liveDir, err)
		}
	}
}

// Accept and decline are body-less POSTs a sibling origin could forge: a cookie session
// needs the CSRF token on every state-changing shared route; a device bearer does not.
func TestSharedRoutesRequireCSRF(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	admin, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "reader", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	publishKey(t, srv, admin, 3)

	noCSRF := func(method, path string, cookie *http.Cookie) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, m := range []struct {
		method, path string
		cookie       *http.Cookie
	}{
		{"POST", "/api/shared", aliceC}, {"PATCH", "/api/shared/" + id, aliceC}, {"DELETE", "/api/shared/" + id, aliceC},
		{"POST", "/api/shared/" + id + "/members", aliceC}, {"PUT", "/api/shared/" + id + "/members/" + bob.ID, aliceC},
		{"DELETE", "/api/shared/" + id + "/members/" + bob.ID, aliceC}, {"POST", "/api/shared/" + id + "/accept", bobC},
		{"POST", "/api/shared/" + id + "/decline", bobC}, {"DELETE", "/api/admin/shared/" + id, adminC},
		{"DELETE", "/api/admin/shared/" + id + "/members/" + bob.ID, adminC}, {"PUT", "/api/admin/shared/settings", adminC},
	} {
		if got := noCSRF(m.method, m.path, m.cookie); got != http.StatusForbidden {
			t.Fatalf("%s %s without CSRF = %d, want 403", m.method, m.path, got)
		}
	}
	if v, err := srv.shared.Get(id); err != nil || v.Members[bob.ID].State != shared.StateInvited || v.Name != "Finance" {
		t.Fatalf("a request without CSRF changed the vault: %+v %v", v, err)
	}

	// A device bearer token needs no CSRF header.
	_, token := pairDeviceForTest(t, h, bobC)
	req := httptest.NewRequest(http.MethodPost, "/api/shared/"+id+"/accept", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	expectCode(t, rec, http.StatusOK, "bearer accept")
}

// Authority is re-checked at the write: an owner removed or demoted after the handler
// resolved their row is refused and nothing changes.
func TestSharedOwnerRemovedMidRequestIsRefused(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	dave, _ := signedInUser(t, srv, "dave", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "owner", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	daveFP := publishKey(t, srv, dave, 4)

	race := func(fn func() error) {
		srv.sharedResolved = func() {
			srv.sharedResolved = nil
			if err := fn(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Demoted between resolve and write: 403.
	race(func() error { return srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleEditor) })
	expectCode(t, do(t, srv, http.MethodPatch, "/api/shared/"+id, bobC, map[string]any{"name": "Bob's"}), http.StatusForbidden, "demoted rename")
	if err := srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleOwner); err != nil {
		t.Fatal(err)
	}
	race(func() error { return srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleEditor) })
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id, bobC, nil), http.StatusForbidden, "demoted delete")
	if err := srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleOwner); err != nil {
		t.Fatal(err)
	}
	// Removed between resolve and write: 404, and he cannot re-add anyone, himself included.
	race(func() error { return srv.shared.Remove(id, alice.ID, bob.ID) })
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", bobC, map[string]any{"userId": dave.ID, "role": "owner", "sealedKey": sealedKeyFor(0xE5), "keyFingerprint": daveFP}), http.StatusNotFound, "removed invite")

	v, err := srv.shared.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, in := v.Members[bob.ID]; in || len(v.Members) != 1 || v.Name != "Finance" {
		t.Fatalf("refused writes changed the vault: %+v", v)
	}
}

// rawReq sends a raw body. cookie != nil authenticates as a browser (with CSRF unless
// noCSRF); otherwise bearer, if set, authenticates as a device.
func rawReq(srv *Server, method, path string, cookie *http.Cookie, bearer string, noCSRF bool, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	switch {
	case cookie != nil && noCSRF:
		req.AddCookie(cookie)
	case cookie != nil:
		browserAuth(srv, req, cookie)
	case bearer != "":
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func uploadShared(srv *Server, cookie *http.Cookie, id, ifMatch, body string, extra map[string]string) *httptest.ResponseRecorder {
	headers := map[string]string{"If-Match": ifMatch}
	for k, v := range extra {
		headers[k] = v
	}
	return rawReq(srv, http.MethodPost, "/api/shared/"+id+"/upload", cookie, "", false, body, headers)
}

func sharedMeta(t *testing.T, srv *Server, id string) vault.Metadata {
	t.Helper()
	meta, err := srv.vault.GetMetadata(shared.StoreKey(id))
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func decodeIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids
}

// dataRoutes lists every shared data route with a path-shaped placeholder id.
func dataRoutes(id string) []struct{ method, path string } {
	return []struct{ method, path string }{
		{"GET", "/api/shared/" + id + "/metadata"}, {"GET", "/api/shared/" + id + "/kdbx"},
		{"POST", "/api/shared/" + id + "/upload"}, {"GET", "/api/shared/" + id + "/history"},
		{"GET", "/api/shared/" + id + "/history/h1"}, {"POST", "/api/shared/" + id + "/history/h1/restore"},
		{"GET", "/api/shared/" + id + "/conflicts"}, {"GET", "/api/shared/" + id + "/conflicts/c1"},
		{"DELETE", "/api/shared/" + id + "/conflicts/c1"},
	}
}

func TestSharedDataRoutesAndRoles(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	erin, erinC := signedInUser(t, srv, "erin", users.RoleUser)
	_, daveC := signedInUser(t, srv, "dave", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), publishKey(t, srv, carol, 3))
	invite(t, srv, aliceC, id, erin.ID, "reader", sealedKeyFor(0xE5), publishKey(t, srv, erin, 5))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", carolC, nil), http.StatusOK, "carol accept")

	// Envelope headers and JSON envelope fields are ignored; the rotation header is refused.
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "kdbx-v1", map[string]string{"X-Password-Envelope": "pw-env", "X-Recovery-Envelope": "rec-env"}), http.StatusOK, "owner upload")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "kdbx-rot", map[string]string{"X-Vault-Key-Rotated": "1", "X-Password-Envelope": "p", "X-Recovery-Envelope": "r"}), http.StatusBadRequest, "rotation header")
	if meta := sharedMeta(t, srv, id); meta.Version != 1 {
		t.Fatalf("rotation attempt changed the vault: %+v", meta)
	}
	jsonBody, err := json.Marshal(VaultUploadRequest{ExpectedVersion: 1, KdbxBase64: base64.StdEncoding.EncodeToString([]byte("kdbx-v2")), PasswordEnvelope: "pw-env", RecoveryEnvelope: "rec-env"})
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, uploadShared(srv, bobC, id, "", string(jsonBody), map[string]string{"Content-Type": "application/json"}), http.StatusOK, "editor JSON upload")
	if meta := sharedMeta(t, srv, id); meta.Version != 2 || meta.PasswordEnvelope != "" || meta.RecoveryEnvelope != "" || len(meta.DeviceEnvelopes) != 0 {
		t.Fatalf("shared metadata carries envelopes: %+v", meta)
	}

	// Reader: reads, cannot write. Writes need CSRF on a cookie session.
	expectCode(t, uploadShared(srv, carolC, id, `"2"`, "kdbx-v3", nil), http.StatusForbidden, "reader upload")
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/upload", bobC, "", true, "kdbx-v3", map[string]string{"If-Match": `"2"`}), http.StatusForbidden, "editor upload without CSRF")
	if meta := sharedMeta(t, srv, id); meta.Version != 2 {
		t.Fatalf("a refused upload saved: %+v", meta)
	}
	for _, p := range []string{"/metadata", "/kdbx", "/history", "/conflicts"} {
		expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id+p, carolC, nil), http.StatusOK, "reader GET "+p)
	}
	rec := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", carolC, nil)
	if rec.Body.String() != "kdbx-v2" || rec.Header().Get("Content-Disposition") != `attachment; filename="Finance.kdbx"` {
		t.Fatalf("download body/disposition: %q %q", rec.Body.String(), rec.Header().Get("Content-Disposition"))
	}

	// Non-member: 404 on every data route. Invited: 403 on every one, only the list entry.
	for _, m := range dataRoutes(id) {
		expectCode(t, rawReq(srv, m.method, m.path, daveC, "", false, "x", map[string]string{"If-Match": `"2"`}), http.StatusNotFound, "non-member "+m.method+" "+m.path)
		rec := rawReq(srv, m.method, m.path, erinC, "", false, "x", map[string]string{"If-Match": `"2"`})
		if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != "forbidden" {
			t.Fatalf("invited %s %s = %d %q", m.method, m.path, rec.Code, rec.Body.String())
		}
	}
	if rec := do(t, srv, http.MethodGet, "/api/shared", erinC, nil); !strings.Contains(rec.Body.String(), id) || !strings.Contains(rec.Body.String(), `"state":"invited"`) {
		t.Fatalf("invited list: %s", rec.Body.String())
	}

	// Conflict: preserved on a stale If-Match; reader downloads but cannot discard.
	expectCode(t, uploadShared(srv, bobC, id, `"1"`, "kdbx-stale", nil), http.StatusConflict, "stale upload")
	conflicts := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/conflicts", bobC, nil))
	if len(conflicts) != 1 {
		t.Fatalf("conflicts: %v", conflicts)
	}
	cpath := "/api/shared/" + id + "/conflicts/" + conflicts[0]
	if rec := do(t, srv, http.MethodGet, cpath, carolC, nil); rec.Code != http.StatusOK || rec.Body.String() != "kdbx-stale" {
		t.Fatalf("reader conflict download = %d %q", rec.Code, rec.Body.String())
	}
	expectCode(t, do(t, srv, http.MethodDelete, cpath, carolC, nil), http.StatusForbidden, "reader discard")
	expectCode(t, rawReq(srv, http.MethodDelete, cpath, bobC, "", true, "", nil), http.StatusForbidden, "editor discard without CSRF")
	expectCode(t, do(t, srv, http.MethodDelete, cpath, bobC, nil), http.StatusOK, "editor discard")

	// Snapshot: reader downloads; restore is a write and leaves envelopes and membership alone.
	hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", bobC, nil))
	if len(hist) == 0 {
		t.Fatal("no history")
	}
	hpath := "/api/shared/" + id + "/history/" + hist[0]
	if rec := do(t, srv, http.MethodGet, hpath, carolC, nil); rec.Code != http.StatusOK || rec.Body.String() != "kdbx-v1" {
		t.Fatalf("reader snapshot download = %d %q", rec.Code, rec.Body.String())
	}
	expectCode(t, do(t, srv, http.MethodPost, hpath+"/restore", carolC, nil), http.StatusForbidden, "reader restore")
	expectCode(t, rawReq(srv, http.MethodPost, hpath+"/restore", bobC, "", true, "", nil), http.StatusForbidden, "editor restore without CSRF")
	before, err := srv.shared.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, do(t, srv, http.MethodPost, hpath+"/restore", bobC, nil), http.StatusOK, "editor restore")
	meta := sharedMeta(t, srv, id)
	if meta.Version != 3 || meta.PasswordEnvelope != "" || meta.RecoveryEnvelope != "" || meta.UserKey != nil {
		t.Fatalf("restore polluted metadata: %+v", meta)
	}
	if after, err := srv.shared.Get(id); err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("restore touched the membership record (err %v)", err)
	}

	// An editor's device token reads and writes; the save records the session's device.
	deviceID, token := pairDeviceForTest(t, srv.Routes(), bobC)
	expectCode(t, rawReq(srv, http.MethodGet, "/api/shared/"+id+"/metadata", nil, token, false, "", nil), http.StatusOK, "device read")
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/upload", nil, token, false, "kdbx-dev", map[string]string{"If-Match": `"` + strconv.FormatInt(meta.Version, 10) + `"`}), http.StatusOK, "device upload")
	if meta := sharedMeta(t, srv, id); meta.UpdatedByDevice != deviceID {
		t.Fatalf("shared save device = %q, want %q", meta.UpdatedByDevice, deviceID)
	}

	assertAudited(t, srv, "shared.saved", "shared.downloaded", "shared.snapshot_downloaded", "shared.conflict_downloaded", "shared.rolled_back", "shared.conflict_discarded", "shared.conflict_rejected")
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "shared.") && !strings.Contains(e.Details, id) {
			t.Fatalf("audit %s lacks the vault id: %q", e.Action, e.Details)
		}
	}
}

func TestSharedDownloadFilenameIsSanitised(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	id := createShared(t, srv, aliceC, `Fin"an;ce`, sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "kdbx", nil), http.StatusOK, "upload")
	rec := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil)
	expectCode(t, rec, http.StatusOK, "download")
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="Fin-an-ce.kdbx"` {
		t.Fatalf("Content-Disposition = %q", got)
	}
}

func memberState(t *testing.T, srv *Server, id, userID string) shared.Member {
	t.Helper()
	v, err := srv.shared.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return v.Members[userID]
}

func TestSharedHooksStaleAndSuspended(t *testing.T) {
	srv := newTestServer(t)
	_, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	dave, _ := signedInUser(t, srv, "dave", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	invite(t, srv, aliceC, id, dave.ID, "reader", sealedKeyFor(0xD4), publishKey(t, srv, dave, 4))
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "v1", nil), http.StatusOK, "owner upload")

	// Bob replaces his user key through the route: his row goes stale, alice's does not.
	bobMeta, err := srv.vault.GetMetadata(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, putUserKey(srv.Routes(), bobC, `"`+strconv.FormatInt(bobMeta.Version, 10)+`"`, userKeyBody(t, 9)), http.StatusOK, "replace bob's key")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateStale {
		t.Fatalf("bob after key replace: %s/%s", m.State, m.SuspendedFrom)
	}
	if m := memberState(t, srv, id, alice.ID); m.State != shared.StateActive {
		t.Fatalf("alice after bob's key replace: %s/%s", m.State, m.SuspendedFrom)
	}
	// Stale reads, cannot write.
	for _, p := range []string{"/metadata", "/kdbx", "/history", "/conflicts"} {
		expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id+p, bobC, nil), http.StatusOK, "stale GET "+p)
	}
	expectCode(t, uploadShared(srv, bobC, id, `"1"`, "v2", nil), http.StatusForbidden, "stale upload")
	newBobFP := userkey.Fingerprint(bytes.Repeat([]byte{9}, userkey.PublicKeyBytes))
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC, map[string]any{"sealedKey": sealedKeyFor(0xB3), "keyFingerprint": newBobFP}), http.StatusOK, "reseal")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateActive {
		t.Fatalf("bob after reseal: %s/%s", m.State, m.SuspendedFrom)
	}

	// Suspended (the store state, account still able to sign in) reads and writes nothing.
	if _, err := srv.shared.SetSuspended(bob.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, m := range dataRoutes(id) {
		expectCode(t, rawReq(srv, m.method, m.path, bobC, "", false, "x", map[string]string{"If-Match": `"1"`}), http.StatusForbidden, "suspended "+m.method+" "+m.path)
	}
	if _, err := srv.shared.SetSuspended(bob.ID, false); err != nil {
		t.Fatal(err)
	}

	// Admin deactivation suspends every row, remembering the prior state; reactivation restores it.
	for _, u := range []users.User{bob, dave} {
		expectCode(t, do(t, srv, http.MethodPost, "/api/admin/users/"+u.ID+"/deactivate", adminC, nil), http.StatusOK, "deactivate "+u.Username)
	}
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateSuspended || m.SuspendedFrom != shared.StateActive {
		t.Fatalf("bob suspended: %s/%s", m.State, m.SuspendedFrom)
	}
	if m := memberState(t, srv, id, dave.ID); m.State != shared.StateSuspended || m.SuspendedFrom != shared.StateInvited {
		t.Fatalf("dave suspended: %s/%s", m.State, m.SuspendedFrom)
	}
	rec := do(t, srv, http.MethodGet, "/api/admin/shared", adminC, nil)
	if !strings.Contains(rec.Body.String(), `"state":"suspended"`) {
		t.Fatalf("admin list after deactivation: %s", rec.Body.String())
	}
	for _, u := range []users.User{bob, dave} {
		expectCode(t, do(t, srv, http.MethodPost, "/api/admin/users/"+u.ID+"/reactivate", adminC, nil), http.StatusOK, "reactivate "+u.Username)
	}
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateActive {
		t.Fatalf("bob restored: %s/%s", m.State, m.SuspendedFrom)
	}
	if m := memberState(t, srv, id, dave.ID); m.State != shared.StateInvited {
		t.Fatalf("dave restored: %s/%s", m.State, m.SuspendedFrom)
	}
	assertAudited(t, srv, "shared.member_stale", "shared.member_suspended", "shared.member_restored")
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "shared.member_s") || e.Action == "shared.member_restored" {
			if !strings.Contains(e.Details, id) {
				t.Fatalf("hook audit %s lacks the vault id: %q", e.Action, e.Details)
			}
		}
	}
}

// SCIM and the signed webhook suspend and restore memberships when they change the flag.
func TestSharedHooksFollowDirectory(t *testing.T) {
	srv, client := scimTestClient(t)
	ctx := context.Background()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")

	bobSCIM := func(active bool) scim.User {
		return scim.User{Schemas: []string{scim.UserSchema}, ExternalID: bob.SSOSub, UserName: "bob", Active: active}
	}
	sync := func(event string, active bool) error {
		rec := doSync(t, srv, signedSyncRequest(srv.pairingSecret, event, scimUserResource(bob.SSOSub, "bob", "bob@example.com", "user", active)))
		if rec.Code != http.StatusOK {
			return fmt.Errorf("%s = %d %s", event, rec.Code, rec.Body.String())
		}
		return nil
	}
	steps := []struct {
		what string
		want shared.State
		act  func() error
	}{
		{"SCIM PATCH inactive", shared.StateSuspended, func() error {
			_, err := client.PatchUser(ctx, bob.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
			return err
		}},
		{"SCIM PATCH active", shared.StateActive, func() error {
			_, err := client.PatchUser(ctx, bob.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: true})
			return err
		}},
		{"SCIM PUT inactive", shared.StateSuspended, func() error { _, err := client.ReplaceUser(ctx, bob.ID, bobSCIM(false)); return err }},
		{"SCIM PUT active", shared.StateActive, func() error { _, err := client.ReplaceUser(ctx, bob.ID, bobSCIM(true)); return err }},
		{"SCIM DELETE", shared.StateSuspended, func() error { return client.DeleteUser(ctx, bob.ID) }},
		{"SCIM POST restore", shared.StateActive, func() error { _, err := client.CreateUser(ctx, bobSCIM(true)); return err }},
		{"sync user.updated inactive", shared.StateSuspended, func() error { return sync("user.updated", false) }},
		{"sync user.updated active", shared.StateActive, func() error { return sync("user.updated", true) }},
		{"sync user.deleted", shared.StateSuspended, func() error { return sync("user.deleted", false) }},
		{"sync user.created restore", shared.StateActive, func() error { return sync("user.created", true) }},
	}
	for _, s := range steps {
		if err := s.act(); err != nil {
			t.Fatalf("%s: %v", s.what, err)
		}
		if m := memberState(t, srv, id, bob.ID); m.State != s.want {
			t.Fatalf("%s: bob = %s/%s, want %s", s.what, m.State, m.SuspendedFrom, s.want)
		}
	}
	if got, err := srv.users.Get(bob.ID); err != nil || !got.Active {
		t.Fatalf("bob after the directory round trip: %+v %v", got, err)
	}
}

// A hook that cannot write the membership record does not fail the account change; it
// leaves a shared.hook_failed row naming the user.
func TestSharedHookFailureIsAudited(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory this test relies on")
	}
	srv := newTestServer(t)
	_, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, _ := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "reader", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	dir := filepath.Join(srv.dataDir, "shared")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	expectCode(t, do(t, srv, http.MethodPost, "/api/admin/users/"+bob.ID+"/deactivate", adminC, nil), http.StatusOK, "deactivate")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateInvited {
		t.Fatalf("read-only store changed bob: %s", m.State)
	}
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "shared.hook_failed" && strings.Contains(e.Details, bob.ID) {
			return
		}
	}
	t.Fatal("no shared.hook_failed audit row")
}
