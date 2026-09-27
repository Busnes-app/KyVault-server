package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/userkey"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

var t0 = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

// epoch1 is the key epoch of a shared vault that has never been rotated; every write
// must prove the epoch its ciphertext was sealed under.
var epoch1 = map[string]string{sharedEpochHeader: "1"}

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
func do(t *testing.T, srv *Server, method, path string, cookie *http.Cookie, body any, extra ...map[string]string) *httptest.ResponseRecorder {
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
	for _, h := range extra {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
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
	race(func() error { return srv.shared.Remove(id, alice.ID, bob.ID, time.Now()) })
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

// uploadShared posts to a shared vault. epoch is the key epoch the ciphertext claims to be
// encrypted under; a negative epoch sends no epoch header at all.
func uploadShared(srv *Server, cookie *http.Cookie, id, ifMatch, body string, epoch int, extra map[string]string) *httptest.ResponseRecorder {
	headers := map[string]string{"If-Match": ifMatch}
	if epoch >= 0 {
		headers[sharedEpochHeader] = strconv.Itoa(epoch)
	}
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
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "kdbx-v1", 1, map[string]string{"X-Password-Envelope": "pw-env", "X-Recovery-Envelope": "rec-env"}), http.StatusOK, "owner upload")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "kdbx-rot", 1, map[string]string{"X-Vault-Key-Rotated": "1", "X-Password-Envelope": "p", "X-Recovery-Envelope": "r"}), http.StatusBadRequest, "rotation header")
	if meta := sharedMeta(t, srv, id); meta.Version != 1 {
		t.Fatalf("rotation attempt changed the vault: %+v", meta)
	}
	jsonBody, err := json.Marshal(VaultUploadRequest{ExpectedVersion: 1, KdbxBase64: base64.StdEncoding.EncodeToString([]byte("kdbx-v2")), PasswordEnvelope: "pw-env", RecoveryEnvelope: "rec-env"})
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, uploadShared(srv, bobC, id, "", string(jsonBody), 1, map[string]string{"Content-Type": "application/json"}), http.StatusOK, "editor JSON upload")
	if meta := sharedMeta(t, srv, id); meta.Version != 2 || meta.PasswordEnvelope != "" || meta.RecoveryEnvelope != "" || len(meta.DeviceEnvelopes) != 0 {
		t.Fatalf("shared metadata carries envelopes: %+v", meta)
	}

	// Reader: reads, cannot write. Writes need CSRF on a cookie session.
	expectCode(t, uploadShared(srv, carolC, id, `"2"`, "kdbx-v3", 1, nil), http.StatusForbidden, "reader upload")
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
	expectCode(t, uploadShared(srv, bobC, id, `"1"`, "kdbx-stale", 1, nil), http.StatusConflict, "stale upload")
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
	expectCode(t, do(t, srv, http.MethodDelete, cpath, bobC, nil, epoch1), http.StatusOK, "editor discard")

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
	expectCode(t, do(t, srv, http.MethodPost, hpath+"/restore", bobC, nil, epoch1), http.StatusOK, "editor restore")
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
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/upload", nil, token, false, "kdbx-dev", map[string]string{"If-Match": `"` + strconv.FormatInt(meta.Version, 10) + `"`, sharedEpochHeader: "1"}), http.StatusOK, "device upload")
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
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "kdbx", 1, nil), http.StatusOK, "upload")
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
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "v1", 1, nil), http.StatusOK, "owner upload")

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
	expectCode(t, uploadShared(srv, bobC, id, `"1"`, "v2", 1, nil), http.StatusForbidden, "stale upload")
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

// A row that goes stale before it was ever accepted is not a member who once had access:
// it must read nothing, same as a plain invitation, though it still shows in the
// invitee's own list and can still be declined.
func TestSharedUnacceptedStaleMemberReadsNothing(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	bobFP := publishKey(t, srv, bob, 2)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), bobFP)

	// Bob replaces his user key before ever accepting: stale with no AcceptedAt.
	bobMeta, err := srv.vault.GetMetadata(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, putUserKey(srv.Routes(), bobC, `"`+strconv.FormatInt(bobMeta.Version, 10)+`"`, userKeyBody(t, 9)), http.StatusOK, "replace bob's key")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateStale || m.AcceptedAt != nil {
		t.Fatalf("bob after key replace: %s accepted=%v", m.State, m.AcceptedAt)
	}

	for _, r := range dataRoutes(id) {
		rec := rawReq(srv, r.method, r.path, bobC, "", false, "x", map[string]string{"If-Match": `"0"`})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("unaccepted stale %s %s = %d %q", r.method, r.path, rec.Code, rec.Body.String())
		}
	}
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil), http.StatusNotFound, "unaccepted stale member GET")

	if rec := do(t, srv, http.MethodGet, "/api/shared", bobC, nil); !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("bob's own list: %s", rec.Body.String())
	}

	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/decline", bobC, nil), http.StatusOK, "decline unaccepted stale")
	v, err := srv.shared.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Members[bob.ID]; ok {
		t.Fatal("bob's row still exists after decline")
	}
	assertAudited(t, srv, "shared.member_declined")
}

// An unaccepted stale row must not gain access just because the vault has no owner: the
// ownerless carve-out is for members who already had a foothold, not a route around
// acceptance.
func TestSharedUnacceptedStaleCannotReadOwnerlessVault(t *testing.T) {
	srv := newTestServer(t)
	_, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	bobFP := publishKey(t, srv, bob, 2)
	invite(t, srv, aliceC, id, bob.ID, "reader", sealedKeyFor(0xB2), bobFP)

	bobMeta, err := srv.vault.GetMetadata(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, putUserKey(srv.Routes(), bobC, `"`+strconv.FormatInt(bobMeta.Version, 10)+`"`, userKeyBody(t, 9)), http.StatusOK, "replace bob's key")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateStale || m.AcceptedAt != nil {
		t.Fatalf("bob after key replace: %s accepted=%v", m.State, m.AcceptedAt)
	}

	expectCode(t, do(t, srv, http.MethodDelete, "/api/admin/shared/"+id+"/members/"+alice.ID, adminC, nil), http.StatusOK, "admin remove sole owner")

	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id, bobC, nil), http.StatusNotFound, "unaccepted stale member GET ownerless")
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/metadata", bobC, nil), http.StatusForbidden, "unaccepted stale member metadata ownerless")
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

// A sole owner who replaces their user key goes stale and would leave the vault with no
// one able to re-seal it; they re-seal their own row from a fresh session and own it again.
func TestSharedSoleOwnerSelfReseal(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, _ := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	carolFP := publishKey(t, srv, carol, 3)

	meta, err := srv.vault.GetMetadata(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, putUserKey(srv.Routes(), aliceC, `"`+strconv.FormatInt(meta.Version, 10)+`"`, userKeyBody(t, 9)), http.StatusOK, "replace alice's key")
	if m := memberState(t, srv, id, alice.ID); m.State != shared.StateStale {
		t.Fatalf("alice after key replace: %s", m.State)
	}
	newFP := userkey.Fingerprint(bytes.Repeat([]byte{9}, userkey.PublicKeyBytes))
	path := "/api/shared/" + id + "/members/" + alice.ID
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC, map[string]any{"userId": carol.ID, "role": "reader", "sealedKey": sealedKeyFor(0xC3), "keyFingerprint": carolFP}), http.StatusForbidden, "stale owner invites")
	// Nobody else can re-seal her: bob is not an owner.
	expectCode(t, do(t, srv, http.MethodPut, path, bobC, map[string]any{"sealedKey": sealedKeyFor(0xA2), "keyFingerprint": newFP}), http.StatusForbidden, "editor reseals the owner")
	expectCode(t, do(t, srv, http.MethodPut, path, aliceC, map[string]any{"role": "owner", "sealedKey": sealedKeyFor(0xA2), "keyFingerprint": newFP}), http.StatusBadRequest, "self-reseal with a role")
	expectCode(t, do(t, srv, http.MethodPut, path, aliceC, map[string]any{"sealedKey": sealedKeyFor(0xA2), "keyFingerprint": aliceFP}), http.StatusBadRequest, "self-reseal to the retired key")
	expectCode(t, do(t, srv, http.MethodPut, path, staleSession(t, srv, alice), map[string]any{"sealedKey": sealedKeyFor(0xA2), "keyFingerprint": newFP}), http.StatusForbidden, "self-reseal from a stale session")
	if m := memberState(t, srv, id, alice.ID); m.State != shared.StateStale {
		t.Fatalf("refused self-reseals changed alice: %s", m.State)
	}
	expectCode(t, do(t, srv, http.MethodPut, path, aliceC, map[string]any{"sealedKey": sealedKeyFor(0xA2), "keyFingerprint": newFP}), http.StatusOK, "self-reseal")
	m := memberState(t, srv, id, alice.ID)
	if m.State != shared.StateActive || m.KeyFingerprint != newFP || m.SealedByFingerprint != newFP || m.SealedKey != sealedKeyFor(0xA2) {
		t.Fatalf("alice after self-reseal: %+v", m)
	}
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), carolFP)
	assertAudited(t, srv, "shared.member_stale", "shared.member_resealed")
}

// sealedByFingerprint is what the sealer's key was when they sealed, not what it is now.
func TestSharedSealedByFingerprintIsSealTime(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	publishKey(t, srv, alice, 7) // alice's current key changes after she sealed bob's copy
	var rows []struct {
		MyKey struct {
			SealedByFingerprint string `json:"sealedByFingerprint"`
		} `json:"myKey"`
		InvitedBy struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"invitedBy"`
	}
	rec := do(t, srv, http.MethodGet, "/api/shared", bobC, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list %s: %v", rec.Body.String(), err)
	}
	if rows[0].MyKey.SealedByFingerprint != aliceFP || rows[0].InvitedBy.Fingerprint != aliceFP {
		t.Fatalf("sealer fingerprint = %+v, want %s", rows[0], aliceFP)
	}
}

// Write authority is re-checked under the membership lock at the write: an editor removed
// or demoted after the route's early check is refused and the vault does not move.
func TestSharedWriterRemovedMidRequestIsRefused(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	bobFP := publishKey(t, srv, bob, 2)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "v1", 1, nil), http.StatusOK, "upload v1")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "v2", 1, nil), http.StatusOK, "upload v2")
	hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", bobC, nil))
	if len(hist) == 0 {
		t.Fatal("no history")
	}
	restore := "/api/shared/" + id + "/history/" + hist[0] + "/restore"
	race := func(fn func() error) {
		srv.sharedResolved = func() {
			srv.sharedResolved = nil
			if err := fn(); err != nil {
				t.Fatal(err)
			}
		}
	}
	rejoin := func() {
		if err := srv.shared.Invite(id, bob.ID, shared.RoleEditor, sealedKeyFor(0xB2), bobFP, alice.ID, "", t0); err != nil {
			t.Fatal(err)
		}
		if err := srv.shared.Accept(id, bob.ID, t0); err != nil {
			t.Fatal(err)
		}
	}
	demote := func() error { return srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleReader) }
	remove := func() error { return srv.shared.Remove(id, alice.ID, bob.ID, time.Now()) }

	race(demote)
	expectCode(t, uploadShared(srv, bobC, id, `"2"`, "v3", 1, nil), http.StatusForbidden, "demoted upload")
	if err := srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleEditor); err != nil {
		t.Fatal(err)
	}
	race(demote)
	expectCode(t, do(t, srv, http.MethodPost, restore, bobC, nil, epoch1), http.StatusForbidden, "demoted restore")
	if err := srv.shared.SetRole(id, alice.ID, bob.ID, shared.RoleEditor); err != nil {
		t.Fatal(err)
	}
	race(remove)
	expectCode(t, uploadShared(srv, bobC, id, `"2"`, "v3", 1, nil), http.StatusNotFound, "removed upload")
	rejoin()
	race(remove)
	expectCode(t, do(t, srv, http.MethodPost, restore, bobC, nil, epoch1), http.StatusNotFound, "removed restore")
	if meta := sharedMeta(t, srv, id); meta.Version != 2 {
		t.Fatalf("a refused write moved the vault to v%d", meta.Version)
	}
	rec := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil)
	if rec.Body.String() != "v2" {
		t.Fatalf("vault body = %q", rec.Body.String())
	}
}

// A corrupt record neither leaks its ids nor blocks anyone else.
func TestSharedCorruptRecordIsContained(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bad := createShared(t, srv, aliceC, "Broken", sealedKeyFor(0xA1), aliceFP)
	invite(t, srv, aliceC, bad, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	carolFP := publishKey(t, srv, carol, 3)
	good := createShared(t, srv, carolC, "Fine", sealedKeyFor(0xC3), carolFP)

	path := filepath.Join(srv.dataDir, "shared", bad+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(string(data), `"role": "editor"`, `"role": "janitor"`, 1)
	if corrupt == string(data) {
		t.Fatal("corruption did not match the record")
	}
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, srv, http.MethodGet, "/api/shared", carolC, nil)
	expectCode(t, rec, http.StatusOK, "unrelated list")
	for _, leak := range []string{bad, alice.ID, bob.ID} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("unrelated list leaks %s: %s", leak, rec.Body.String())
		}
	}
	if ids := decodeIDs(t, rec); len(ids) != 1 || ids[0] != good {
		t.Fatalf("carol's list = %v", ids)
	}
	rec = do(t, srv, http.MethodGet, "/api/shared/"+bad, aliceC, nil)
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "internal error\n" {
		t.Fatalf("member GET corrupt = %d %q", rec.Code, rec.Body.String())
	}
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared", bobC, nil), http.StatusOK, "member list")
	createShared(t, srv, bobC, "Bob's", sealedKeyFor(0xB3), publishKey(t, srv, bob, 2))
}

// The active-flag hook runs on every directory write but audits only what it changed.
func TestSharedHookIsQuietWhenNothingChanges(t *testing.T) {
	srv, client := scimTestClient(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), publishKey(t, srv, alice, 1))
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), publishKey(t, srv, bob, 2))
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	count := func() int {
		entries, err := srv.audit.List(500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Action, "shared.member_s") || e.Action == "shared.member_restored" || e.Action == "shared.hook_failed" {
				n++
			}
		}
		return n
	}
	before := count()
	if _, err := client.ReplaceUser(context.Background(), bob.ID, scim.User{Schemas: []string{scim.UserSchema}, ExternalID: bob.SSOSub, UserName: "bob", Active: true}); err != nil {
		t.Fatal(err)
	}
	if after := count(); after != before {
		t.Fatalf("active→active SCIM PUT wrote %d hook audit rows", after-before)
	}
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateActive {
		t.Fatalf("bob = %s", m.State)
	}
}

// Every shared write proves which key epoch its ciphertext was sealed under: a member
// re-sealed by a rotation whose tab still holds the retired key would otherwise upload
// ciphertext nobody left in the vault can open.
func TestSharedWritesCarryTheKeyEpoch(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "first upload")

	// A missing header is refused exactly like a stale one, and neither writes.
	rec := uploadShared(srv, aliceC, id, `"1"`, "two", -1, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "was rotated") {
		t.Fatalf("missing epoch = %d %s", rec.Code, rec.Body.String())
	}
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 0, nil), http.StatusConflict, "stale epoch")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 2, nil), http.StatusConflict, "future epoch")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", -1, map[string]string{sharedEpochHeader: "one"}), http.StatusConflict, "unparseable epoch")
	if meta := sharedMeta(t, srv, id); meta.Version != 1 {
		t.Fatalf("a refused write moved the vault to v%d", meta.Version)
	}
	if rec := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil); rec.Body.String() != "one" {
		t.Fatalf("vault body = %q", rec.Body.String())
	}

	// The history restore and the conflict discard carry it too.
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/history/nope/restore", aliceC, nil), http.StatusConflict, "restore without the epoch")
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/conflicts/nope", aliceC, nil), http.StatusConflict, "discard without the epoch")

	// Reads never carry it.
	expectCode(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/metadata", aliceC, nil), http.StatusOK, "metadata read")
}

// rotateBody builds the rotate route's multipart body: the re-encrypted vault first, then
// the keys JSON, which is the order the route reads them in.
func rotateBody(t *testing.T, kdbx string, epoch int, sealed []map[string]string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("kdbx", "vault.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(kdbx)); err != nil {
		t.Fatal(err)
	}
	keys, err := mw.CreateFormField("keys")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(keys).Encode(map[string]any{"epoch": epoch, "sealed": sealed}); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), mw.FormDataContentType()
}

// multipartBody writes the named parts in the order given, which is how the rotate route
// reads them.
func multipartBody(t *testing.T, parts ...[2]string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, part := range parts {
		w, err := mw.CreateFormField(part[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(part[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), mw.FormDataContentType()
}

// sealedFor is one entry of the keys part.
func sealedFor(userID, sealedKey, fingerprint string) map[string]string {
	return map[string]string{"userId": userID, "sealedKey": sealedKey, "keyFingerprint": fingerprint}
}

// rotate posts a prepared body to the rotate route as a browser would.
func rotate(srv *Server, cookie *http.Cookie, id, ifMatch, body, contentType string) *httptest.ResponseRecorder {
	return rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", cookie, "", false, body,
		map[string]string{"Content-Type": contentType, "If-Match": ifMatch})
}

// auditDetail is the newest audit detail recorded for action.
func auditDetail(t *testing.T, srv *Server, action string) string {
	t.Helper()
	entries, err := srv.audit.List(500)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == action {
			return e.Details
		}
	}
	t.Fatalf("no audit row for %s", action)
	return ""
}

func sharedRecord(t *testing.T, srv *Server, id string) shared.Vault {
	t.Helper()
	v, err := srv.shared.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A rotation re-keys the vault, its members' sealed copies and its ciphertext in one
// commit, and takes the history and conflicts the retired key still opens with it.
func TestSharedRotate(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	dave, daveC := signedInUser(t, srv, "dave", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	carolFP := publishKey(t, srv, carol, 3)
	daveFP := publishKey(t, srv, dave, 4)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), bobFP)
	invite(t, srv, aliceC, id, carol.ID, "reader", sealedKeyFor(0xC3), carolFP)
	invite(t, srv, aliceC, id, dave.ID, "reader", sealedKeyFor(0xD4), daveFP)
	for _, c := range []*http.Cookie{bobC, carolC, daveC} {
		expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", c, nil), http.StatusOK, "accept")
	}
	// Establish contents, a snapshot and a preserved conflict.
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 1, nil), http.StatusOK, "upload two")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "stale", 1, nil), http.StatusConflict, "preserved conflict")
	if hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil)); len(hist) == 0 {
		t.Fatal("fixture has no history")
	}
	if confs := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/conflicts", aliceC, nil)); len(confs) == 0 {
		t.Fatal("fixture has no preserved conflict")
	}

	// Carol leaves: her copy of the key still opens everything until the rotation.
	expectCode(t, do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+carol.ID, carolC, nil), http.StatusOK, "carol leaves")
	if p := sharedRecord(t, srv, id).RotationPending; p == nil || p.UserID != carol.ID || p.Reason != shared.ReasonLeft {
		t.Fatalf("departure did not flag a rotation: %+v", p)
	}
	// The pending flag reaches a member's list and the admin list.
	if got := do(t, srv, http.MethodGet, "/api/shared", aliceC, nil); !strings.Contains(got.Body.String(), `"rotationPending"`) {
		t.Fatalf("list does not carry the pending flag: %s", got.Body.String())
	}
	_, adminC := signedInUser(t, srv, "root", users.RoleAdmin)
	if got := do(t, srv, http.MethodGet, "/api/admin/shared", adminC, nil); !strings.Contains(got.Body.String(), `"rotationPending"`) {
		t.Fatalf("admin list does not carry the pending flag: %s", got.Body.String())
	}

	newKey := sealedKeyFor(9)
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{
		sealedFor(alice.ID, newKey, aliceFP),
		sealedFor(bob.ID, newKey, bobFP),
	})
	rec := rotate(srv, aliceC, id, `"2"`, body, ct)
	expectCode(t, rec, http.StatusOK, "rotate")
	var out struct {
		OK             bool           `json:"ok"`
		Metadata       vault.Metadata `json:"metadata"`
		KeyEpoch       int            `json:"keyEpoch"`
		LeftBehind     []string       `json:"leftBehind"`
		HistoryCleared bool           `json:"historyCleared"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("rotate body %s: %v", rec.Body.String(), err)
	}
	// Dave was not sealed for: he stays at the retired epoch, stale, with his old copy.
	if !out.OK || out.KeyEpoch != 2 || out.Metadata.Version != 3 || !out.HistoryCleared ||
		len(out.LeftBehind) != 1 || out.LeftBehind[0] != dave.ID {
		t.Fatalf("rotate response = %+v", out)
	}
	if want := fmt.Sprintf("%s: rotated to epoch 2, sealed to 2 members, 1 left behind", id); auditDetail(t, srv, "shared.key_rotated") != want {
		t.Fatalf("audit detail = %q, want %q", auditDetail(t, srv, "shared.key_rotated"), want)
	}

	// The history and the conflicts the retired key opens are gone; the contents are new.
	if hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil)); len(hist) != 0 {
		t.Fatalf("history survived the rotation: %v", hist)
	}
	if confs := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/conflicts", aliceC, nil)); len(confs) != 0 {
		t.Fatalf("conflicts survived the rotation: %v", confs)
	}
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil); got.Body.String() != "rekeyed" {
		t.Fatalf("vault body = %q", got.Body.String())
	}

	// The flag is cleared and bob holds the new key at the new epoch.
	v := sharedRecord(t, srv, id)
	if v.RotationPending != nil || v.KeyEpoch != 2 {
		t.Fatalf("record after rotate: %+v", v)
	}
	if m := v.Members[bob.ID]; m.SealedKey != newKey || m.KeyEpoch != 2 || m.State != shared.StateActive || m.SealedBy != alice.ID {
		t.Fatalf("bob after rotate: %+v", m)
	}
	if m := v.Members[dave.ID]; m.SealedKey != sealedKeyFor(0xD4) || m.KeyEpoch != 1 || m.State != shared.StateStale {
		t.Fatalf("dave after rotate: %+v", m)
	}
	list := do(t, srv, http.MethodGet, "/api/shared", bobC, nil)
	if !strings.Contains(list.Body.String(), newKey) {
		t.Fatalf("bob's list does not carry the new key: %s", list.Body.String())
	}

	// A write at the retired epoch is refused; at the new one it is accepted.
	expectCode(t, uploadShared(srv, bobC, id, `"3"`, "bob", 1, nil), http.StatusConflict, "write at the old epoch")
	expectCode(t, uploadShared(srv, bobC, id, `"3"`, "bob", 2, nil), http.StatusOK, "write at the new epoch")
	assertAudited(t, srv, "shared.key_rotated")
}

// Every refusal leaves the record, the ciphertext and the history exactly as they were.
func TestSharedRotateRefusals(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	dave, _ := signedInUser(t, srv, "dave", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(0xB2), bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 1, nil), http.StatusOK, "upload two")

	newKey := sealedKeyFor(9)
	good := []map[string]string{sealedFor(alice.ID, newKey, aliceFP), sealedFor(bob.ID, newKey, bobFP)}
	body, ct := rotateBody(t, "rekeyed", 1, good)

	// An editor cannot rotate; a non-member sees 404.
	expectCode(t, rotate(srv, bobC, id, `"2"`, body, ct), http.StatusForbidden, "editor rotate")
	_, malloryC := signedInUser(t, srv, "mallory", users.RoleUser)
	expectCode(t, rotate(srv, malloryC, id, `"2"`, body, ct), http.StatusNotFound, "stranger rotate")

	// No CSRF token, and a session that is not freshly signed in.
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", true, body,
		map[string]string{"Content-Type": ct, "If-Match": `"2"`}), http.StatusForbidden, "rotate without CSRF")
	expectCode(t, rotate(srv, staleSession(t, srv, alice), id, `"2"`, body, ct), http.StatusForbidden, "rotate from a stale session")
	// A paired device carries no authentication timestamp, so it can never rotate either.
	_, token := pairDeviceForTest(t, srv.Routes(), aliceC)
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", nil, token, false, body,
		map[string]string{"Content-Type": ct, "If-Match": `"2"`}), http.StatusForbidden, "rotate from a device token")

	// The epoch being rotated from, and the vault version, must both be current.
	stale, staleCT := rotateBody(t, "rekeyed", 0, good)
	expectCode(t, rotate(srv, aliceC, id, `"2"`, stale, staleCT), http.StatusConflict, "rotate from a retired epoch")
	expectCode(t, rotate(srv, aliceC, id, `"99"`, body, ct), http.StatusConflict, "rotate over a newer version")

	// A fingerprint that is not the member's current published one, a member with no
	// published key, a stranger's row, and a rotation that does not seal for the caller.
	wrongFP, wrongCT := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, newKey, aliceFP), sealedFor(bob.ID, newKey, aliceFP)})
	expectCode(t, rotate(srv, aliceC, id, `"2"`, wrongFP, wrongCT), http.StatusBadRequest, "rotate with a stale fingerprint")
	noKey, noKeyCT := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, newKey, aliceFP), sealedFor(dave.ID, newKey, aliceFP)})
	expectCode(t, rotate(srv, aliceC, id, `"2"`, noKey, noKeyCT), http.StatusBadRequest, "rotate sealing for a user with no key")
	notMine, notMineCT := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(bob.ID, newKey, bobFP)})
	expectCode(t, rotate(srv, aliceC, id, `"2"`, notMine, notMineCT), http.StatusBadRequest, "rotate that drops the caller")
	empty, emptyCT := rotateBody(t, "rekeyed", 1, nil)
	expectCode(t, rotate(srv, aliceC, id, `"2"`, empty, emptyCT), http.StatusBadRequest, "rotate sealing for nobody")

	// A truncated body, a missing part, a third part, parts in the wrong order, an empty
	// vault part and a body that is not multipart at all.
	expectCode(t, rotate(srv, aliceC, id, `"2"`, body[:len(body)/2], ct), http.StatusBadRequest, "truncated body")
	var one bytes.Buffer
	mw := multipart.NewWriter(&one)
	p, err := mw.CreateFormFile("kdbx", "v.kdbx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	expectCode(t, rotate(srv, aliceC, id, `"2"`, one.String(), mw.FormDataContentType()), http.StatusBadRequest, "missing keys part")
	keysJSON, err := json.Marshal(map[string]any{"epoch": 1, "sealed": good})
	if err != nil {
		t.Fatal(err)
	}
	third, thirdCT := multipartBody(t, [2]string{"kdbx", "rekeyed"}, [2]string{"keys", string(keysJSON)}, [2]string{"extra", "x"})
	expectCode(t, rotate(srv, aliceC, id, `"2"`, third, thirdCT), http.StatusBadRequest, "a third part")
	reversed, reversedCT := multipartBody(t, [2]string{"keys", string(keysJSON)}, [2]string{"kdbx", "rekeyed"})
	expectCode(t, rotate(srv, aliceC, id, `"2"`, reversed, reversedCT), http.StatusBadRequest, "parts in the wrong order")
	empt, emptCT := rotateBody(t, "", 1, good)
	expectCode(t, rotate(srv, aliceC, id, `"2"`, empt, emptCT), http.StatusBadRequest, "empty vault part")
	expectCode(t, rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body,
		map[string]string{"Content-Type": "application/json", "If-Match": `"2"`}), http.StatusBadRequest, "not multipart")

	// Not one of those refusals moved the vault, its key or its history.
	v := sharedRecord(t, srv, id)
	if v.KeyEpoch != 1 || v.Members[alice.ID].SealedKey != sealedKeyFor(0xA1) || v.Members[bob.ID].SealedKey != sealedKeyFor(0xB2) {
		t.Fatalf("a refused rotation changed the record: %+v", v)
	}
	if meta := sharedMeta(t, srv, id); meta.Version != 2 {
		t.Fatalf("a refused rotation moved the vault to v%d", meta.Version)
	}
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil); got.Body.String() != "two" {
		t.Fatalf("vault body = %q", got.Body.String())
	}
	if hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil)); len(hist) != 1 {
		t.Fatalf("history after refusals = %v", hist)
	}
	// A refused rotation never leaves its ciphertext behind as a conflict nobody can open.
	if confs := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/conflicts", aliceC, nil)); len(confs) != 0 {
		t.Fatalf("a refused rotation preserved a conflict: %v", confs)
	}
}

// Each part is bounded on its own: an oversized keys part is refused, never truncated
// into something that parses.
func TestSharedRotateRefusesOversizedParts(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, sealedKeyFor(9), aliceFP)})
	defer func(kdbx, keys int64) { rotateKdbxLimit, rotateKeysLimit = kdbx, keys }(rotateKdbxLimit, rotateKeysLimit)

	rotateKdbxLimit = 4 // the vault part alone is over the limit; the body is not
	rec := rotate(srv, aliceC, id, `"1"`, body, ct)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("oversized vault part = %d %s", rec.Code, rec.Body.String())
	}
	rotateKdbxLimit, rotateKeysLimit = 50<<20, 1<<10 // the keys part alone is over the limit
	rec = rotate(srv, aliceC, id, `"1"`, body, ct)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("oversized keys part = %d %s", rec.Code, rec.Body.String())
	}
	if meta := sharedMeta(t, srv, id); meta.Version != 1 {
		t.Fatalf("an oversized rotation moved the vault to v%d", meta.Version)
	}
	if v := sharedRecord(t, srv, id); v.KeyEpoch != 1 {
		t.Fatalf("an oversized rotation moved the epoch to %d", v.KeyEpoch)
	}
}

// Simultaneous rotations: the record's epoch admits exactly one.
func TestConcurrentRotationsLeaveOneEpoch(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	// Built once: t.Fatal off the test goroutine is a race.
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, sealedKeyFor(9), aliceFP)})

	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = rotate(srv, aliceC, id, `"1"`, body, ct).Code
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
		default:
			t.Fatalf("codes %v: a losing rotation must be 409", codes)
		}
	}
	if wins != 1 {
		t.Fatalf("codes %v: exactly one rotation must win", codes)
	}
	if v := sharedRecord(t, srv, id); v.KeyEpoch != 2 {
		t.Fatalf("epoch = %d", v.KeyEpoch)
	}
	if meta := sharedMeta(t, srv, id); meta.Version != 2 {
		t.Fatalf("version = %d", meta.Version)
	}
}

// A write that passed the gate at epoch N is refused if a rotation commits before it
// reaches the store: otherwise a restore could copy a pre-rotation snapshot over the
// live vault, under a key no remaining member holds.
func TestSharedWriteIsRefusedWhenARotationCommitsMidRequest(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 1, nil), http.StatusOK, "upload two")
	hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil))
	if len(hist) == 0 {
		t.Fatal("no history")
	}
	rotateNow := func() {
		srv.sharedResolved = func() {
			srv.sharedResolved = nil
			v, err := srv.shared.Rotate(id, alice.ID, sharedRecord(t, srv, id).KeyEpoch,
				[]shared.SealedFor{{UserID: alice.ID, SealedKey: sealedKeyFor(9), KeyFingerprint: aliceFP}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if v.KeyEpoch < 2 {
				t.Fatalf("racing rotation left epoch %d", v.KeyEpoch)
			}
		}
	}
	rotateNow()
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/history/"+hist[0]+"/restore", aliceC, nil, epoch1),
		http.StatusConflict, "restore after a rotation committed")
	rotateNow()
	expectCode(t, uploadShared(srv, aliceC, id, `"2"`, "three", 2, nil), http.StatusConflict, "upload after a rotation committed")
	if meta := sharedMeta(t, srv, id); meta.Version != 2 {
		t.Fatalf("a refused write moved the vault to v%d", meta.Version)
	}
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil); got.Body.String() != "two" {
		t.Fatalf("vault body = %q", got.Body.String())
	}
}

// The rotation write starts a new key epoch, so a snapshot taken under the retired key can
// never be rolled back onto the live vault — not even by an owner sending the current epoch
// header, because only the bytes are stale. The clear is made to fail here so those
// snapshots are still on disk, which is also how the owner learns to rotate again.
func TestSharedRotateLeavesRetiredSnapshotsUnrestorable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory this test relies on")
	}
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(0xA1), aliceFP)
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")
	expectCode(t, uploadShared(srv, aliceC, id, `"1"`, "two", 1, nil), http.StatusOK, "upload two")
	hist := decodeIDs(t, do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil))
	if len(hist) != 1 {
		t.Fatalf("history fixture = %v", hist)
	}

	// A history directory the server cannot write is the one thing that can survive a
	// rotation's clear.
	dir := filepath.Join(srv.dataDir, "vaults", "shared", id, "history")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, sealedKeyFor(9), aliceFP)})
	rec := rotate(srv, aliceC, id, `"2"`, body, ct)
	expectCode(t, rec, http.StatusOK, "rotate")
	if !strings.Contains(rec.Body.String(), `"historyCleared":false`) {
		t.Fatalf("a failed clear must be reported: %s", rec.Body.String())
	}
	assertAudited(t, srv, "shared.key_rotated", "shared.hook_failed")

	// The retired snapshot is still there, flagged, and refused at the current epoch.
	list := do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil)
	if !strings.Contains(list.Body.String(), `"staleKey":true`) {
		t.Fatalf("history after the rotation = %s", list.Body.String())
	}
	restore := do(t, srv, http.MethodPost, "/api/shared/"+id+"/history/"+hist[0]+"/restore", aliceC, nil,
		map[string]string{sharedEpochHeader: "2"})
	if restore.Code != http.StatusConflict || !strings.Contains(restore.Body.String(), "previous vault key") {
		t.Fatalf("restore of a retired snapshot = %d %s", restore.Code, restore.Body.String())
	}
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil); got.Body.String() != "rekeyed" {
		t.Fatalf("a refused rollback changed the vault: %q", got.Body.String())
	}
}

// A row a rotation left behind holds a copy of the retired key. Self-resealing with it
// would republish that stale copy as current; only an owner, who holds the new key, can
// bring the row back.
func TestSelfResealNeedsTheCurrentEpoch(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	invite(t, srv, aliceC, id, bob.ID, "editor", sealedKeyFor(1), bobFP)
	expectCode(t, do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil), http.StatusOK, "bob accept")
	expectCode(t, uploadShared(srv, aliceC, id, `"0"`, "one", 1, nil), http.StatusOK, "upload one")

	// Alice rotates without bob: he is left behind, stale at epoch 1.
	newKey := sealedKeyFor(9)
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{sealedFor(alice.ID, newKey, aliceFP)})
	expectCode(t, rotate(srv, aliceC, id, `"1"`, body, ct), http.StatusOK, "rotate")

	// Bob cannot self-reseal: he does not hold the epoch-2 key, so sealing his own row
	// would publish a copy of a key nobody can open.
	rec := do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, bobC,
		map[string]any{"sealedKey": sealedKeyFor(4), "keyFingerprint": bobFP})
	if rec.Code != http.StatusConflict {
		t.Fatalf("epoch-stale self-reseal = %d %s", rec.Code, rec.Body.String())
	}
	if m := memberState(t, srv, id, bob.ID); m.SealedKey != sealedKeyFor(1) || m.KeyEpoch != 1 {
		t.Fatalf("refused self-reseal changed bob: %+v", m)
	}
	// An owner can still re-seal him.
	expectCode(t, do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC,
		map[string]any{"sealedKey": newKey, "keyFingerprint": bobFP}), http.StatusOK, "owner reseal")
	if m := memberState(t, srv, id, bob.ID); m.State != shared.StateActive || m.KeyEpoch != 2 || m.SealedKey != newKey {
		t.Fatalf("bob after owner reseal: %+v", m)
	}

	// A rotated-and-recovered vault carries no pending flag.
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id, aliceC, nil); strings.Contains(got.Body.String(), `"rotationPending"`) {
		t.Fatalf("a rotated vault carries no flag: %s", got.Body.String())
	}
}
