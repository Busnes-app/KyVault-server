# Shared Vaults Web Client (3b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Members create, join, open, edit and manage shared vaults from the web app through a one-vault-at-a-time switcher; admins see and destroy them from the Admin tab; one new server route looks up a user by exact username.

**Architecture:** `App.tsx` gains a `selected` vault descriptor; the existing single `vault`/`vaultKey`/`saveQueue`/`meta` state describes whichever vault is selected, and the personal key is kept aside as `personalKey` for seed unwrap and pins. Every personal-vault API path becomes `basePath`-relative (`/api/vault` or `/api/shared/<id>`), so `VaultPage`, `HistoryModal`, `ConflictComparison` and `VaultSaveQueue` serve both. New pure modules (`sharedKey.ts`, `sharedVaults.ts`, `vaultSelection.ts`, `keyReplaceReseal.ts`) hold the logic and are unit-tested with injected API functions; the dialogs and the admin tab are thin React over them.

**Tech Stack:** React 18 + TypeScript (`frontend/`, tests `npm test` = tsx --test, gate `npm run build`), hpke-js via `lib/userKey.ts` (`seal`/`open`), kdbxweb via `lib/kdbx.ts`, Go 1.26 stdlib for the lookup route.

**Spec:** `docs/superpowers/specs/2026-09-27-shared-vaults-web-design.md`

## Global Constraints

- Repo root `KyVault-server/`. Frontend gate: `cd frontend && npm test && npm run build` (build = `tsc && vite build` + postbuild `scripts/check-bundle.mjs`). Backend gate: `gofmt -l . | grep -v node_modules` empty, `go vet ./...`, `go test -race ./...`.
- Shared key sealing: `seal(publicKey, "kyvault/shared-vault-key/1", key)` from `lib/userKey.ts`; key is 32 random bytes; blob is exactly 1168 bytes; `keyFingerprint` sent to the server is the fingerprint of the public key sealed to.
- Server contract (3a): `GET /api/shared` list entry `{id, name, role, state, keyEpoch, myKey: {sealedKey, keyFingerprint, keyEpoch, sealedBy, sealedByFingerprint}, invitedBy?: {userId, username, fingerprint}}`; `GET /api/shared/{id}` `{id, name, createdBy, createdAt, keyEpoch, members: [{userId, username, role, state, keyFingerprint, keyEpoch, addedAt, acceptedAt?}]}`; `POST /api/shared {name, sealedKey, keyFingerprint}` → 201 `{id}`; `POST /api/shared/{id}/members {userId, role, sealedKey, keyFingerprint}`; `PUT /api/shared/{id}/members/{userId} {role?, sealedKey?, keyFingerprint?}`; `DELETE …/members/{userId}`; `POST …/accept`, `POST …/decline`; `PATCH /api/shared/{id} {name}`; `DELETE /api/shared/{id}`; data routes `GET …/metadata`, `GET …/kdbx`, `POST …/upload`, `GET …/history`, `GET …/history/{hid}`, `POST …/history/{hid}/restore`, `GET …/conflicts`, `GET …/conflicts/{cid}`, `DELETE …/conflicts/{cid}`; admin `GET /api/admin/shared` (`ownerless` flag), `DELETE /api/admin/shared/{id}`, `DELETE /api/admin/shared/{id}/members/{userId}`, `GET/PUT /api/admin/shared/settings {createRestrictedToAdmins}`. Every mutation needs `X-CSRF-Token` (the `request` helper in `lib/api.ts` adds it). Fresh-session refusals have body starting `re-authenticate to continue`.
- Roles `owner|editor|reader`; states `invited|active|stale|suspended`. Readers open read-only. `invited` and own-`stale` rows are not openable.
- Routes: `#/vault[/entry]`, `#/shared/<id>[/entry]` (`^sv_[A-Za-z0-9_-]{22}$`), `#/admin/shared`.
- Locked drafts: id `${userId}:${scope}:${uuid}` and AAD `${userId}:${scope}` where scope is `personal` or the shared id.
- No native `confirm`/`prompt`/`alert` (`noNativeDialogs.test.ts`); every question goes through `useDialogs()`.
- Text: the trust line on the Accept dialog is exactly `KyVault trusts the server for who is in a vault, never for its contents.`
- New server route: `GET /api/users/lookup?username=<name>` (`withAuth`), 200 `{userId, username, fingerprint}` only for an active user with a published key; 404 otherwise; per-source limiter 20 misses / 15 min → 429; audit `user.lookup` (detail: queried name) and `user.lookup_limited`.
- Commit trailer: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

1. Switching vaults while an upload is in flight must not let the in-flight response bump the *new* queue's version or resurrect the old vault into state (Task 7 test `switching closes the old queue before opening the new one`; `VaultSaveQueue.discard()` aborts transport).
2. A shared vault the user was removed from while it is selected: the next save gets 404/403; the UI must switch back to personal with a notice instead of looping retries (Task 7 test `save 404 on a shared vault falls back to personal`).
3. A reload on `#/shared/<id>` before unlock must unlock the personal vault first and only then open the shared one; a shared id the user is not a member of falls back to `#/vault` with a notice (Task 7 test `route restore after unlock`).
4. Pins written while a shared vault is selected must land in the *personal* KDBX and upload immediately; a pin must never be written into the shared KDBX (Task 8 test `pin on invite writes the personal vault`).
5. Replace user key with an unopenable shared key must warn by vault name before replacing, and a self-reseal failure after the replace must keep the key in memory for Retry, never silently drop it (Task 9 tests).

---

### Task 1: `GET /api/users/lookup` (server)

**Files:**
- Create: `internal/api/user_lookup_handlers.go`
- Create: `internal/api/user_lookup_test.go`
- Modify: `internal/api/server.go` (route line next to `GET /api/users/{id}/key`; a `lookupLimit *pairingLimiter`-style field)
- Modify: `internal/api/pairing_limit.go` (parameterise the limiter: failures and lockout become fields set by the constructor)
- Modify: `AGENTS.md` (Authentication bullet: one sentence for the route)

**Interfaces:**
- Consumes: `users.Store.GetByUsername(username) (User, error)` (case-insensitive, trimmed), `vault.Store.GetMetadata(id)`, `meta.UserKey.Public(id)`, `s.sourceKey(r)`, `s.record(r, action, userID, deviceID, ip, details)`, `pairingLimiter` (`newPairingLimiter`, `allow`, `fail`, `reset`).
- Produces: route `GET /api/users/lookup?username=` → `{userId, username, fingerprint}`.

Ruling carried from the spec: `GetByUsername` is case-insensitive and that is the directory's own matching rule; the route uses it (the spec's "exact" means whole-string, not case-sensitive). `frontend` sends the name as typed.

- [ ] **Step 1: Parameterise the limiter**

In `pairing_limit.go` change the type so failures/lockout are per-instance:

```go
type pairingLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	sources     map[string]*pairingSource
	maxFailures int
	lockout     time.Duration
}

func newPairingLimiter() *pairingLimiter {
	return newLimiter(pairingMaxFailures, pairingLockout)
}

func newLimiter(maxFailures int, lockout time.Duration) *pairingLimiter {
	return &pairingLimiter{now: time.Now, sources: map[string]*pairingSource{}, maxFailures: maxFailures, lockout: lockout}
}
```

and replace every use of the constants `pairingMaxFailures`/`pairingLockout` inside the methods with `l.maxFailures`/`l.lockout`. Run `go test -race ./internal/api/ -run Pairing` and confirm the three pairing-limit tests still pass.

- [ ] **Step 2: Write the failing tests**

`internal/api/user_lookup_test.go`:

```go
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
	if _, err := srv.users.Deactivate(bob.ID); err != nil {
		t.Fatal(err)
	}
	if rec := lookup(h, aliceC, "", "bob"); rec.Code != http.StatusNotFound {
		t.Fatalf("inactive bob = %d", rec.Code)
	}
	found, limited := 0, 0
	for _, e := range srv.audit.List(50) {
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
	limited := 0
	for _, e := range srv.audit.List(50) {
		if e.Action == "user.lookup_limited" {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("limited rows = %d", limited)
	}
	_ = userkey.PublicKeyBytes
}
```

`publishKey`, `signedInUser`, `pairDeviceForTest` exist in `shared_test.go` / `api_test.go`. If `srv.users.Deactivate` has a different name, use the one `admin_handlers.go` calls.

- [ ] **Step 3: Run to confirm failure**

Run: `go test ./internal/api/ -run TestUserLookup`
Expected: 404 from the mux (route missing) → FAIL.

- [ ] **Step 4: Implement**

`internal/api/user_lookup_handlers.go`:

```go
package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

const (
	lookupMaxMisses = 20
	lookupLockout   = 15 * time.Minute
)

// GET /api/users/lookup?username=. Resolves a username to the id and fingerprint the
// invite flow needs. Unknown, inactive and key-less users all answer 404 so the route
// only confirms "an active user with that name has a key"; misses are rate limited per
// source like pairing codes.
func (s *Server) handleUserLookup(w http.ResponseWriter, r *http.Request, u users.User) {
	src := s.sourceKey(r)
	if !s.lookupLimit.allow(src) {
		s.record(r, "user.lookup_limited", u.ID, "", clientIP(r), "")
		http.Error(w, "too many lookups; try again later", http.StatusTooManyRequests)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("username"))
	s.record(r, "user.lookup", u.ID, "", clientIP(r), name)
	target, err := s.users.GetByUsername(name)
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	if err != nil || name == "" || !target.Active {
		s.lookupLimit.fail(src)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	meta, err := s.vault.GetMetadata(target.ID)
	if err != nil || meta.UserKey == nil {
		s.lookupLimit.fail(src)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pub, err := meta.UserKey.Public(target.ID)
	if err != nil {
		http.Error(w, "stored key is malformed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"userId": target.ID, "username": target.Username, "fingerprint": pub.Fingerprint})
}
```

Check the field name on the value `Public` returns (`internal/userkey/userkey.go`); use whatever holds the fingerprint. In `server.go`: add `lookupLimit *pairingLimiter` to `Server`, initialise `lookupLimit: newLimiter(lookupMaxMisses, lookupLockout)` where `pairingLimit` is initialised, and register `mux.HandleFunc("GET /api/users/lookup", s.withAuth(s.handleUserLookup))` **before** `GET /api/users/{id}/key` (Go 1.22 mux prefers the more specific literal pattern anyway, but keep them adjacent). If a periodic sweep calls `pairingLimit.sweep()`, call `lookupLimit.sweep()` beside it.

- [ ] **Step 5: Gate and commit**

Run: `gofmt -l internal; go vet ./... && go test -race ./internal/api/`
Expected: PASS. Add to root `AGENTS.md` Authentication (after the user-key sentence): "`GET /api/users/lookup?username=` (any session or device token) answers `{userId, username, fingerprint}` for an active user with a published key and 404 otherwise; misses are limited per source (20 in 15 minutes → 429, `user.lookup_limited`), every call is audited `user.lookup` with the name."

```bash
git add internal/api AGENTS.md
git commit -m "api: user lookup by username for shared-vault invites

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `lib/sharedKey.ts`

**Files:**
- Create: `frontend/src/lib/sharedKey.ts`
- Create: `frontend/src/lib/sharedKey.test.ts`

**Interfaces:**
- Consumes: `seal`, `open`, `b64`, `generateUserKey` from `lib/userKey.ts`.
- Produces:
  ```ts
  export const SHARED_KEY_INFO = "kyvault/shared-vault-key/1";
  export const SHARED_KEY_BYTES = 32;
  export const SEALED_KEY_BYTES = 1168;
  export function newSharedKey(): Uint8Array;                                   // 32 random bytes
  export async function sealSharedKey(publicKey: Uint8Array, key: Uint8Array): Promise<string>;   // base64 of 1168 bytes
  export async function openSharedKey(seed: Uint8Array, sealedKey: string): Promise<Uint8Array>; // 32 bytes or throws
  ```

- [ ] **Step 1: Write the failing test**

`frontend/src/lib/sharedKey.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, b64 } from "./userKey";
import { newSharedKey, sealSharedKey, openSharedKey, SEALED_KEY_BYTES, SHARED_KEY_BYTES } from "./sharedKey";

test("shared key seals to a public key and opens with its seed", async () => {
  const alice = await generateUserKey();
  const key = newSharedKey();
  assert.equal(key.length, SHARED_KEY_BYTES);
  const sealed = await sealSharedKey(alice.publicKey, key);
  assert.equal(b64.decode(sealed).length, SEALED_KEY_BYTES);
  const opened = await openSharedKey(alice.seed, sealed);
  assert.deepEqual([...opened], [...key]);
});

test("a different seed cannot open the key", async () => {
  const alice = await generateUserKey();
  const mallory = await generateUserKey();
  const sealed = await sealSharedKey(alice.publicKey, newSharedKey());
  await assert.rejects(openSharedKey(mallory.seed, sealed));
});

test("sealing refuses a key of the wrong length", async () => {
  const alice = await generateUserKey();
  await assert.rejects(sealSharedKey(alice.publicKey, new Uint8Array(16)), /32 bytes/);
});

test("two fresh keys differ", () => {
  assert.notDeepEqual([...newSharedKey()], [...newSharedKey()]);
});
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd frontend && npx tsx --test src/lib/sharedKey.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement**

```ts
import { seal, open, b64 } from "./userKey";

export const SHARED_KEY_INFO = "kyvault/shared-vault-key/1";
export const SHARED_KEY_BYTES = 32;
export const SEALED_KEY_BYTES = 1168;

export function newSharedKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SHARED_KEY_BYTES));
}

export async function sealSharedKey(publicKey: Uint8Array, key: Uint8Array): Promise<string> {
  if (key.length !== SHARED_KEY_BYTES) throw new Error(`shared vault key must be ${SHARED_KEY_BYTES} bytes`);
  const sealed = await seal(publicKey, SHARED_KEY_INFO, key);
  if (sealed.length !== SEALED_KEY_BYTES) throw new Error(`sealed key is ${sealed.length} bytes, expected ${SEALED_KEY_BYTES}`);
  return b64.encode(sealed);
}

export async function openSharedKey(seed: Uint8Array, sealedKey: string): Promise<Uint8Array> {
  const blob = b64.decode(sealedKey);
  if (blob.length !== SEALED_KEY_BYTES) throw new Error("sealed key has the wrong length");
  const key = await open(seed, SHARED_KEY_INFO, blob);
  if (key.length !== SHARED_KEY_BYTES) throw new Error("opened key has the wrong length");
  return key;
}
```

The HPKE interop with Go is already pinned by `hpke-xwing-vector.json`; only the info string differs here, so no second vector (ruling).

- [ ] **Step 4: Run, then commit**

Run: `cd frontend && npx tsx --test src/lib/sharedKey.test.ts` → PASS.

```bash
git add frontend/src/lib/sharedKey.ts frontend/src/lib/sharedKey.test.ts
git commit -m "frontend: shared vault key seal/open helpers

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `lib/sharedVaults.ts` API client and `useSharedVaults`

**Files:**
- Create: `frontend/src/lib/sharedVaults.ts`
- Create: `frontend/src/lib/sharedVaults.test.ts`

**Interfaces:**
- Consumes: `getJSON`, `postJSON`, `putJSON`, `patchJSON`, `deleteJSON`, `requestJSON`, `HttpError`, `toErrorMessage` from `lib/api.ts`.
- Produces:
  ```ts
  export type Role = "owner" | "editor" | "reader";
  export type MemberState = "invited" | "active" | "stale" | "suspended";
  export type MyKey = { sealedKey: string; keyFingerprint: string; keyEpoch: number; sealedBy: string; sealedByFingerprint: string };
  export type SharedVaultSummary = { id: string; name: string; role: Role; state: MemberState; keyEpoch: number; myKey: MyKey; invitedBy?: { userId: string; username: string; fingerprint: string } };
  export type Member = { userId: string; username: string; role: Role; state: MemberState; keyFingerprint: string; keyEpoch: number; addedAt: string; acceptedAt?: string };
  export type SharedVaultDetail = { id: string; name: string; createdBy: string; createdAt: string; keyEpoch: number; members: Member[] };
  export type LookupResult = { userId: string; username: string; fingerprint: string };
  export const SHARED_ID = /^sv_[A-Za-z0-9_-]{22}$/;
  export const sharedBase = (id: string) => `/api/shared/${encodeURIComponent(id)}`;
  export const sharedApi = {
    list: () => Promise<SharedVaultSummary[]>,
    get: (id) => Promise<SharedVaultDetail>,
    create: (name, sealedKey, keyFingerprint) => Promise<{ id: string }>,
    rename: (id, name) => Promise<void>,
    remove: (id) => Promise<void>,                  // DELETE /api/shared/{id}
    invite: (id, userId, role, sealedKey, keyFingerprint) => Promise<void>,
    updateMember: (id, userId, patch: { role?: Role; sealedKey?: string; keyFingerprint?: string }) => Promise<void>,
    removeMember: (id, userId) => Promise<void>,
    accept: (id) => Promise<void>,
    decline: (id) => Promise<void>,
    lookupUser: (username) => Promise<LookupResult | null>,   // null on 404
    metadata: (id) => Promise<{ version: number }>,
  };
  export type SharedApi = typeof sharedApi;
  export function canOpen(v: SharedVaultSummary): boolean;                 // only active rows open
  export function stateLabel(v: SharedVaultSummary): string | null;      // "Invitation" | "Key changed" | "Read-only" | null
  export function useSharedVaults(enabled: boolean, api?: SharedApi): { vaults: SharedVaultSummary[]; refresh: () => Promise<void>; error: string };
  ```

- [ ] **Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { canOpen, stateLabel, SHARED_ID, sharedBase, type SharedVaultSummary } from "./sharedVaults";

const row = (over: Partial<SharedVaultSummary>): SharedVaultSummary => ({
  id: "sv_abcdefghijklmnopqrstuv", name: "Finance", role: "editor", state: "active", keyEpoch: 1,
  myKey: { sealedKey: "", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" }, ...over,
});

test("only active rows open", () => {
  assert.equal(canOpen(row({})), true);
  assert.equal(canOpen(row({ state: "invited" })), false);
  assert.equal(canOpen(row({ state: "stale" })), false);
  assert.equal(canOpen(row({ state: "suspended" })), false);
});

test("state labels", () => {
  assert.equal(stateLabel(row({})), null);
  assert.equal(stateLabel(row({ role: "reader" })), "Read-only");
  assert.equal(stateLabel(row({ state: "invited" })), "Invitation");
  assert.equal(stateLabel(row({ state: "stale" })), "Key changed");
});

test("id pattern and base path", () => {
  assert.equal(SHARED_ID.test("sv_abcdefghijklmnopqrstuv"), true);
  assert.equal(SHARED_ID.test("sv_../x"), false);
  assert.equal(SHARED_ID.test("u-1"), false);
  assert.equal(sharedBase("sv_abcdefghijklmnopqrstuv"), "/api/shared/sv_abcdefghijklmnopqrstuv");
});
```

The `sharedApi` functions are one-line wrappers over `lib/api.ts`; `lookupUser` is the only one with logic (404 → null). The hook and the wrappers are exercised against the mock API in the Task 11 UI pass rather than by stubbing `fetch` here.

- [ ] **Step 2: Run to confirm failure** — `cd frontend && npx tsx --test src/lib/sharedVaults.test.ts` → module not found.

- [ ] **Step 3: Implement**

```ts
import { useCallback, useEffect, useState } from "react";
import { getJSON, postJSON, putJSON, patchJSON, deleteJSON, HttpError, toErrorMessage } from "./api";

export type Role = "owner" | "editor" | "reader";
export type MemberState = "invited" | "active" | "stale" | "suspended";
export type MyKey = { sealedKey: string; keyFingerprint: string; keyEpoch: number; sealedBy: string; sealedByFingerprint: string };
export type SharedVaultSummary = { id: string; name: string; role: Role; state: MemberState; keyEpoch: number; myKey: MyKey; invitedBy?: { userId: string; username: string; fingerprint: string } };
export type Member = { userId: string; username: string; role: Role; state: MemberState; keyFingerprint: string; keyEpoch: number; addedAt: string; acceptedAt?: string };
export type SharedVaultDetail = { id: string; name: string; createdBy: string; createdAt: string; keyEpoch: number; members: Member[] };
export type LookupResult = { userId: string; username: string; fingerprint: string };

export const SHARED_ID = /^sv_[A-Za-z0-9_-]{22}$/;
export const sharedBase = (id: string) => `/api/shared/${encodeURIComponent(id)}`;

export const sharedApi = {
  list: () => getJSON<SharedVaultSummary[]>("/api/shared"),
  get: (id: string) => getJSON<SharedVaultDetail>(sharedBase(id)),
  create: (name: string, sealedKey: string, keyFingerprint: string) => postJSON<{ id: string }>("/api/shared", { name, sealedKey, keyFingerprint }),
  rename: async (id: string, name: string) => { await patchJSON(sharedBase(id), { name }); },
  remove: async (id: string) => { await deleteJSON(sharedBase(id)); },
  invite: async (id: string, userId: string, role: Role, sealedKey: string, keyFingerprint: string) => { await postJSON(`${sharedBase(id)}/members`, { userId, role, sealedKey, keyFingerprint }); },
  updateMember: async (id: string, userId: string, patch: { role?: Role; sealedKey?: string; keyFingerprint?: string }) => { await putJSON(`${sharedBase(id)}/members/${encodeURIComponent(userId)}`, patch); },
  removeMember: async (id: string, userId: string) => { await deleteJSON(`${sharedBase(id)}/members/${encodeURIComponent(userId)}`); },
  accept: async (id: string) => { await postJSON(`${sharedBase(id)}/accept`, {}); },
  decline: async (id: string) => { await postJSON(`${sharedBase(id)}/decline`, {}); },
  lookupUser: async (username: string): Promise<LookupResult | null> => {
    try {
      return await getJSON<LookupResult>(`/api/users/lookup?username=${encodeURIComponent(username)}`);
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) return null;
      throw err;
    }
  },
  metadata: (id: string) => getJSON<{ version: number }>(`${sharedBase(id)}/metadata`),
};
export type SharedApi = typeof sharedApi;

export const canOpen = (v: SharedVaultSummary) => v.state === "active";

export function stateLabel(v: SharedVaultSummary): string | null {
  if (v.state === "invited") return "Invitation";
  if (v.state === "stale") return "Key changed";
  if (v.role === "reader") return "Read-only";
  return null;
}

const REFRESH_MS = 60_000;

// Loads the caller's shared vaults after unlock and keeps them fresh while the tab is visible.
export function useSharedVaults(enabled: boolean, api: SharedApi = sharedApi) {
  const [vaults, setVaults] = useState<SharedVaultSummary[]>([]);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    if (!enabled) return;
    try {
      setVaults(await api.list());
      setError("");
    } catch (err) {
      setError(toErrorMessage(err, "Could not load shared vaults."));
    }
  }, [enabled, api]);
  useEffect(() => {
    if (!enabled) { setVaults([]); setError(""); return; }
    void refresh();
    const tick = () => { if (document.visibilityState === "visible") void refresh(); };
    const timer = setInterval(tick, REFRESH_MS);
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", tick); };
  }, [enabled, refresh]);
  return { vaults, refresh, error };
}
```

- [ ] **Step 4: Run, then commit**

`cd frontend && npx tsx --test src/lib/sharedVaults.test.ts` → PASS.

```bash
git add frontend/src/lib/sharedVaults.ts frontend/src/lib/sharedVaults.test.ts
git commit -m "frontend: shared vault API client and list hook

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Routes for shared vaults and the admin tab

**Files:**
- Modify: `frontend/src/lib/route.ts`
- Modify: `frontend/src/lib/route.test.ts` (append)

**Interfaces:**
- Produces:
  ```ts
  export type AdminTab = "sso" | "users" | "audit" | "backup" | "shared";
  export type Route = { tab: "vault" | "watchtower" | "security" | "admin"; admin?: AdminTab; entry?: string; shared?: string };
  // `shared` is set only with tab "vault": `#/shared/<id>[/entry]`.
  ```

- [ ] **Step 1: Write the failing tests** (append to `route.test.ts`, matching its existing style)

```ts
test("shared vault routes", () => {
  assert.deepEqual(parseRoute("#/shared/sv_abcdefghijklmnopqrstuv"), { tab: "vault", shared: "sv_abcdefghijklmnopqrstuv" });
  assert.deepEqual(parseRoute("#/shared/sv_abcdefghijklmnopqrstuv/e%201"), { tab: "vault", shared: "sv_abcdefghijklmnopqrstuv", entry: "e 1" });
  assert.deepEqual(parseRoute("#/shared/../x"), { tab: "vault" });
  assert.deepEqual(parseRoute("#/shared/u-1"), { tab: "vault" });
  assert.equal(formatRoute({ tab: "vault", shared: "sv_abcdefghijklmnopqrstuv" }), "#/shared/sv_abcdefghijklmnopqrstuv");
  assert.equal(formatRoute({ tab: "vault", shared: "sv_abcdefghijklmnopqrstuv", entry: "e 1" }), "#/shared/sv_abcdefghijklmnopqrstuv/e%201");
  assert.deepEqual(parseRoute("#/admin/shared"), { tab: "admin", admin: "shared" });
  assert.equal(formatRoute({ tab: "admin", admin: "shared" }), "#/admin/shared");
});
```

- [ ] **Step 2: Run to confirm failure** — `cd frontend && npx tsx --test src/lib/route.test.ts` → FAIL.

- [ ] **Step 3: Implement**

```ts
export type AdminTab = "sso" | "users" | "audit" | "backup" | "shared";
export type Route = { tab: "vault" | "watchtower" | "security" | "admin"; admin?: AdminTab; entry?: string; shared?: string };
const ADMIN_TABS: AdminTab[] = ["sso", "users", "audit", "backup", "shared"];
const SHARED_ID = /^sv_[A-Za-z0-9_-]{22}$/;

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "watchtower") return { tab: "watchtower" };
  if (parts[0] === "security") return { tab: "security" };
  if (parts[0] === "admin") return { tab: "admin", admin: ADMIN_TABS.includes(parts[1] as AdminTab) ? (parts[1] as AdminTab) : "sso" };
  if (parts[0] === "shared" && SHARED_ID.test(parts[1] ?? "")) {
    return parts[2] ? { tab: "vault", shared: parts[1], entry: decodeURIComponent(parts[2]) } : { tab: "vault", shared: parts[1] };
  }
  if (parts[0] === "vault" && parts[1]) return { tab: "vault", entry: decodeURIComponent(parts[1]) };
  return { tab: "vault" };
}

export function formatRoute(route: Route): string {
  if (route.tab === "watchtower") return "#/watchtower";
  if (route.tab === "security") return "#/security";
  if (route.tab === "admin") return `#/admin/${route.admin ?? "sso"}`;
  const base = route.shared ? `#/shared/${route.shared}` : "#/vault";
  return route.entry ? `${base}/${encodeURIComponent(route.entry)}` : base;
}
```

(`useRoute` unchanged.) Grep every `navigate({ tab: "vault"` and `route.entry` use in `App.tsx`, `VaultPage.tsx`, `WatchtowerPage.tsx`; each place that builds a vault route must carry `shared: route.shared` so navigating to an entry inside a shared vault does not drop back to the personal one. `VaultPage`'s route-follow effect compares `route.entry` only; leave it, Task 7 adds the shared guard.

- [ ] **Step 4: Run, typecheck, commit**

`cd frontend && npx tsx --test src/lib/route.test.ts && npx tsc --noEmit` → PASS.

```bash
git add frontend/src/lib/route.ts frontend/src/lib/route.test.ts frontend/src/App.tsx frontend/src/pages
git commit -m "frontend: #/shared/<id> and #/admin/shared routes

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Base-path-relative vault transport and scoped drafts

**Files:**
- Modify: `frontend/src/lib/vaultSave.ts` (`uploadVault` base path; `VaultSaveQueue` option)
- Modify: `frontend/src/lib/vaultSave.test.ts` (append)
- Modify: `frontend/src/components/HistoryModal.tsx`, `frontend/src/components/ConflictComparison.tsx` (new `basePath` prop, default `/api/vault`)
- Modify: `frontend/src/pages/VaultPage.tsx` (pass `basePath` through; new prop)
- Modify: `frontend/src/lib/lockedDraft.ts`, `frontend/src/lib/lockedDraft.test.ts` (scope)
- Modify: `frontend/src/lib/keyRotation.ts` only if it calls `uploadVault` positionally (keep its call compiling; personal base path).

**Interfaces:**
- Produces:
  ```ts
  export const PERSONAL_BASE = "/api/vault";
  export async function uploadVault(binary, version, passwordEnvelope?, recoveryEnvelope?, signal?, keyRotated = false, userKeyHeader?, basePath = PERSONAL_BASE): Promise<number>;
  export class VaultSaveQueue { constructor(vault, version, passwordEnvelope?, basePath = PERSONAL_BASE) }
  // lockedDraft.ts
  export type DraftScope = "personal" | `sv_${string}`;
  export const draftAccount = (userId: string, scope: DraftScope) => `${userId}:${scope}`;
  export const draftId = (userId: string, scope: DraftScope) => `${userId}:${scope}:${crypto.randomUUID()}`;
  // HistoryModal / ConflictComparison / VaultPage props gain `basePath?: string` (default PERSONAL_BASE)
  ```

- [ ] **Step 1: Write the failing tests**

Append to `vaultSave.test.ts` (look at how the existing tests stub `fetch`/`requestJSON`; follow the same pattern):

```ts
test("uploadVault and the overwrite re-read use the base path", async () => {
  const seen: string[] = [];
  const restore = stubFetch(async (url, init) => {   // use the file's existing fetch stub helper; if it has none, add one that swaps globalThis.fetch and returns a restore fn
    seen.push(`${init?.method ?? "GET"} ${url}`);
    if (String(url).endsWith("/metadata")) return jsonResponse({ version: 7 });
    return jsonResponse({ metadata: { version: 8 } });
  });
  try {
    const v = await uploadVault(new ArrayBuffer(4), 7, undefined, undefined, undefined, false, undefined, "/api/shared/sv_abcdefghijklmnopqrstuv");
    assert.equal(v, 8);
    assert.deepEqual(seen, ["POST /api/shared/sv_abcdefghijklmnopqrstuv/upload"]);
  } finally { restore(); }
});
```

Append to `lockedDraft.test.ts`:

```ts
test("draft account and id carry the vault scope", async () => {
  assert.equal(draftAccount("u-1", "personal"), "u-1:personal");
  assert.equal(draftAccount("u-1", "sv_abcdefghijklmnopqrstuv"), "u-1:sv_abcdefghijklmnopqrstuv");
  assert.match(draftId("u-1", "personal"), /^u-1:personal:[0-9a-f-]{36}$/);
  const key = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await sealDraft(new ArrayBuffer(8), { version: 1, dirty: true, entry: null }, key, draftAccount("u-1", "sv_abcdefghijklmnopqrstuv"));
  await assert.rejects(openDraft(sealed, key, draftAccount("u-1", "personal")));
});
```

- [ ] **Step 2: Run to confirm failure** — both files FAIL to compile.

- [ ] **Step 3: Implement**

`vaultSave.ts`:

```ts
export const PERSONAL_BASE = "/api/vault";

export async function uploadVault(binary: ArrayBuffer, version: number, passwordEnvelope?: string, recoveryEnvelope?: string, signal?: AbortSignal, keyRotated = false, userKeyHeader?: string, basePath = PERSONAL_BASE): Promise<number> {
  ...
  const data = await requestJSON<unknown>(`${basePath}/upload`, { method: "POST", headers, body: binary, signal });
```

`VaultSaveQueue`: `constructor(private vault: KeePassVault | null, version: number, private passwordEnvelope?: string, private basePath = PERSONAL_BASE)`; inside `save()` pass `this.basePath` as the last argument; the overwrite path reads `${this.basePath}/metadata`. The overwrite envelope guard (`passwordEnvelope` comparison) must be skipped when `basePath !== PERSONAL_BASE` (shared metadata has no envelope).

`HistoryModal.tsx` and `ConflictComparison.tsx`: add `basePath?: string` to `Props`, default `PERSONAL_BASE`, and replace each literal `/api/vault` with `${basePath}`. `VaultPage.tsx`: add `basePath?: string` to `Props`, default `PERSONAL_BASE`, and pass it to `<HistoryModal basePath={basePath} …>` and `<ConflictComparison basePath={basePath} …>` (the latter is rendered inside HistoryModal's recovery path; thread it through).

`lockedDraft.ts`:

```ts
export type DraftScope = "personal" | `sv_${string}`;
export const draftAccount = (userId: string, scope: DraftScope) => `${userId}:${scope}`;
export const draftId = (userId: string, scope: DraftScope) => `${userId}:${scope}:${crypto.randomUUID()}`;
```

`pruneDrafts(userId, keep, now)` scans the `${userId}:` prefix already, so scoped ids are covered. In `App.tsx` the auto-lock path currently builds `id = \`${u.id}:${crypto.randomUUID()}\`` and seals with account `u.id`; change it to `draftId(u.id, "personal")` and `draftAccount(u.id, "personal")` now (Task 7 passes the real scope). The unlock-time `openDraft` call uses the same account string. Existing drafts sealed with the bare `u.id` account will no longer open: `App.tsx` already deletes and reports an unreadable checkpoint, so one lost pre-upgrade draft is the accepted migration cost (note it in the commit message).

- [ ] **Step 4: Gate and commit**

`cd frontend && npm test && npx tsc --noEmit` → PASS.

```bash
git add frontend/src
git commit -m "frontend: vault transport takes a base path; locked drafts are scoped per vault

A checkpoint sealed before this change no longer opens and is deleted with the existing notice.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `lib/vaultSelection.ts` — pure selection and open logic

**Files:**
- Create: `frontend/src/lib/vaultSelection.ts`
- Create: `frontend/src/lib/vaultSelection.test.ts`

**Interfaces:**
- Consumes: `openSharedKey` (Task 2), `SharedVaultSummary`, `canOpen`, `sharedBase` (Task 3), `KeePassVault` (`open`, `createNew`, `exportBinary`), `uploadVault`, `VaultSaveQueue` (Task 5), `getBinary`/`getJSON` from `lib/api.ts`.
- Produces:
  ```ts
  export type Selected = { kind: "personal" } | { kind: "shared"; id: string };
  export const personal: Selected;
  export const selectionScope = (s: Selected): DraftScope;            // "personal" | id
  export const selectionBase = (s: Selected): string;                 // PERSONAL_BASE | sharedBase(id)
  export function sameSelection(a: Selected, b: Selected): boolean;
  export function resolveSelection(routeShared: string | undefined, vaults: SharedVaultSummary[]): { selected: Selected; notice: string | null };
  // routeShared undefined → personal; id in vaults and canOpen → shared; id in vaults but not openable → personal + notice naming the state; unknown id → personal + "You are not a member of that shared vault."
  export type OpenDeps = {
    openKey: (seed: Uint8Array, sealedKey: string) => Promise<Uint8Array>;
    fetchMetadata: (base: string) => Promise<{ version: number }>;
    fetchKdbx: (base: string, signal?: AbortSignal) => Promise<ArrayBuffer>;
    openVault: (bytes: ArrayBuffer, key: Uint8Array) => Promise<KeePassVault>;
    createVault: (key: Uint8Array, name: string) => Promise<KeePassVault>;
    upload: (binary: ArrayBuffer, version: number, base: string) => Promise<number>;
  };
  export const defaultOpenDeps: OpenDeps;
  export type OpenedShared = { vault: KeePassVault; key: Uint8Array; version: number; readOnly: boolean };
  export async function openShared(row: SharedVaultSummary, seed: Uint8Array, deps?: OpenDeps): Promise<OpenedShared>;
  // opens the sealed key (throws Error("key") wrapped message "Your copy of the key cannot be opened; ask an owner to re-seal it." when open fails),
  // reads metadata; version 0 → createVault + upload with If-Match 0 and use the returned version; else fetchKdbx + openVault. readOnly = row.role === "reader".
  ```

- [ ] **Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveSelection, openShared, selectionScope, selectionBase, personal, type OpenDeps } from "./vaultSelection";
import type { SharedVaultSummary } from "./sharedVaults";

const ID = "sv_abcdefghijklmnopqrstuv";
const row = (over: Partial<SharedVaultSummary> = {}): SharedVaultSummary => ({
  id: ID, name: "Finance", role: "editor", state: "active", keyEpoch: 1,
  myKey: { sealedKey: "AAAA", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" }, ...over,
});

test("resolveSelection", () => {
  assert.deepEqual(resolveSelection(undefined, [row()]), { selected: personal, notice: null });
  assert.deepEqual(resolveSelection(ID, [row()]), { selected: { kind: "shared", id: ID }, notice: null });
  assert.equal(resolveSelection(ID, [row({ state: "invited" })]).selected.kind, "personal");
  assert.match(resolveSelection(ID, [row({ state: "invited" })]).notice ?? "", /invitation/i);
  assert.match(resolveSelection("sv_zzzzzzzzzzzzzzzzzzzzzz", [row()]).notice ?? "", /not a member/i);
  assert.equal(selectionScope(personal), "personal");
  assert.equal(selectionScope({ kind: "shared", id: ID }), ID);
  assert.equal(selectionBase({ kind: "shared", id: ID }), `/api/shared/${ID}`);
});

const fakeVault = { name: "v" } as any;
const deps = (over: Partial<OpenDeps>): OpenDeps => ({
  openKey: async () => new Uint8Array(32),
  fetchMetadata: async () => ({ version: 3 }),
  fetchKdbx: async () => new ArrayBuffer(8),
  openVault: async () => fakeVault,
  createVault: async () => { throw new Error("should not create"); },
  upload: async () => { throw new Error("should not upload"); },
  ...over,
});

test("openShared opens an existing vault read-only for readers", async () => {
  const calls: string[] = [];
  const opened = await openShared(row({ role: "reader" }), new Uint8Array(32), deps({
    fetchKdbx: async (base) => { calls.push(base); return new ArrayBuffer(8); },
  }));
  assert.equal(opened.vault, fakeVault);
  assert.equal(opened.version, 3);
  assert.equal(opened.readOnly, true);
  assert.deepEqual(calls, [`/api/shared/${ID}`]);
});

test("openShared creates and uploads an empty vault at version 0", async () => {
  let uploaded: [number, string] | null = null;
  const opened = await openShared(row(), new Uint8Array(32), deps({
    fetchMetadata: async () => ({ version: 0 }),
    createVault: async () => ({ ...fakeVault, exportBinary: async () => new ArrayBuffer(4) }),
    upload: async (_b, version, base) => { uploaded = [version, base]; return 1; },
  }));
  assert.deepEqual(uploaded, [0, `/api/shared/${ID}`]);
  assert.equal(opened.version, 1);
  assert.equal(opened.readOnly, false);
});

test("openShared reports an unopenable key", async () => {
  await assert.rejects(openShared(row(), new Uint8Array(32), deps({ openKey: async () => { throw new Error("bad"); } })), /ask an owner to re-seal/);
});
```

- [ ] **Step 2: Run to confirm failure** — module not found.

- [ ] **Step 3: Implement**

```ts
import { KeePassVault } from "./kdbx";
import { getBinary, getJSON } from "./api";
import { openSharedKey } from "./sharedKey";
import { canOpen, sharedBase, type SharedVaultSummary } from "./sharedVaults";
import { PERSONAL_BASE, uploadVault } from "./vaultSave";
import type { DraftScope } from "./lockedDraft";

export type Selected = { kind: "personal" } | { kind: "shared"; id: string };
export const personal: Selected = { kind: "personal" };
export const selectionScope = (s: Selected): DraftScope => (s.kind === "personal" ? "personal" : (s.id as DraftScope));
export const selectionBase = (s: Selected) => (s.kind === "personal" ? PERSONAL_BASE : sharedBase(s.id));
export const sameSelection = (a: Selected, b: Selected) => a.kind === b.kind && (a.kind === "personal" || a.id === (b as { id: string }).id);

export function resolveSelection(routeShared: string | undefined, vaults: SharedVaultSummary[]): { selected: Selected; notice: string | null } {
  if (!routeShared) return { selected: personal, notice: null };
  const row = vaults.find((v) => v.id === routeShared);
  if (!row) return { selected: personal, notice: "You are not a member of that shared vault." };
  if (!canOpen(row)) {
    const why = row.state === "invited" ? "You have not accepted the invitation to" : "Your key for";
    return { selected: personal, notice: `${why} “${row.name}” ${row.state === "invited" ? "yet." : "needs to be re-sealed by an owner."}` };
  }
  return { selected: { kind: "shared", id: row.id }, notice: null };
}

export type OpenDeps = {
  openKey: (seed: Uint8Array, sealedKey: string) => Promise<Uint8Array>;
  fetchMetadata: (base: string) => Promise<{ version: number }>;
  fetchKdbx: (base: string, signal?: AbortSignal) => Promise<ArrayBuffer>;
  openVault: (bytes: ArrayBuffer, key: Uint8Array) => Promise<KeePassVault>;
  createVault: (key: Uint8Array, name: string) => Promise<KeePassVault>;
  upload: (binary: ArrayBuffer, version: number, base: string) => Promise<number>;
};

export const defaultOpenDeps: OpenDeps = {
  openKey: openSharedKey,
  fetchMetadata: (base) => getJSON<{ version: number }>(`${base}/metadata`),
  fetchKdbx: (base, signal) => getBinary(`${base}/kdbx`, signal ?? new AbortController().signal),
  openVault: (bytes, key) => KeePassVault.open(bytes, key),
  createVault: (key, name) => KeePassVault.createNew(key, name),
  upload: (binary, version, base) => uploadVault(binary, version, undefined, undefined, undefined, false, undefined, base),
};

export type OpenedShared = { vault: KeePassVault; key: Uint8Array; version: number; readOnly: boolean };

export async function openShared(row: SharedVaultSummary, seed: Uint8Array, deps: OpenDeps = defaultOpenDeps): Promise<OpenedShared> {
  let key: Uint8Array;
  try {
    key = await deps.openKey(seed, row.myKey.sealedKey);
  } catch {
    throw new Error("Your copy of the key cannot be opened; ask an owner to re-seal it.");
  }
  const base = sharedBase(row.id);
  const meta = await deps.fetchMetadata(base);
  const readOnly = row.role === "reader";
  if (!meta.version) {
    const vault = await deps.createVault(key, row.name);
    const version = await deps.upload(await vault.exportBinary(), 0, base);
    return { vault, key, version, readOnly };
  }
  const vault = await deps.openVault(await deps.fetchKdbx(base), key);
  return { vault, key, version: meta.version, readOnly };
}
```

- [ ] **Step 4: Run, commit**

`cd frontend && npx tsx --test src/lib/vaultSelection.test.ts` → PASS.

```bash
git add frontend/src/lib/vaultSelection.ts frontend/src/lib/vaultSelection.test.ts
git commit -m "frontend: vault selection and shared open logic

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: App integration — switcher, selected state, read-only editing

**Files:**
- Create: `frontend/src/components/VaultSwitcher.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/pages/VaultPage.tsx` (`readOnly` prop; `basePath` pass-through from Task 5; switcher slot)
- Modify: `frontend/src/pages/SecuritySettings.tsx` (hide personal-only cards while a shared vault is selected: `personalOnly` prop)
- Create: `frontend/src/lib/appSelection.test.ts` (reducer-level tests of the switch sequence with injected deps)
- Create: `frontend/src/lib/appSelection.ts` (the switch sequence as a pure async function so it is testable)

**Interfaces:**
- Consumes: Tasks 3–6.
- Produces:
  ```ts
  // lib/appSelection.ts
  export type SwitchDeps = {
    confirmDiscard: () => Promise<boolean>;
    closeQueue: () => void;                                   // saveQueue.discard() + setSaveQueue(null)
    openShared: (row: SharedVaultSummary) => Promise<OpenedShared>;
    openPersonal: () => Promise<{ vault: KeePassVault; key: Uint8Array; version: number; passwordEnvelope?: string }>;   // returns the retained personal vault + key
    apply: (next: { selected: Selected; vault: KeePassVault; key: Uint8Array; queue: VaultSaveQueue; readOnly: boolean }) => void;
    notify: (text: string) => void;
    generation: () => number;
  };
  export async function switchTo(target: Selected, row: SharedVaultSummary | undefined, deps: SwitchDeps): Promise<boolean>;
  export function lostAccess(selected: Selected, state: SaveState): boolean;
  // true when selected.kind === "shared" and state.kind === "error" and state.status is 403 or 404 (add `status?: number` to the error SaveState in vaultSave.ts, set from HttpError.status). App then refreshes the list and switches to personal with the notice.
  // 1 confirmDiscard (false → return false); 2 gen = generation(); 3 closeQueue; 4 open (shared → openShared(row); personal → openPersonal);
  // 5 if generation() !== gen → return false (a lock happened; do not apply); 6 build VaultSaveQueue(vault, version, passwordEnvelope, selectionBase(target)); 7 apply; on error: notify(message) and re-open personal via openPersonal + apply (never leave the app with no vault).
  // components/VaultSwitcher.tsx
  type Props = { selected: Selected; vaults: SharedVaultSummary[]; onSelect: (s: Selected) => void; onCreate: () => void; onAccept: (row) => void; onDecline: (row) => void; onMembers: () => void; canCreate: boolean; busy: boolean };
  // VaultPage: readOnly?: boolean; basePath?: string; header?: ReactNode  (the switcher renders in the header slot)
  ```

- [ ] **Step 1: Write the failing tests** (`appSelection.test.ts`)

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { switchTo, lostAccess, type SwitchDeps } from "./appSelection";
import { personal } from "./vaultSelection";

const ID = "sv_abcdefghijklmnopqrstuv";
const row: any = { id: ID, name: "Finance", role: "editor", state: "active", keyEpoch: 1, myKey: { sealedKey: "AAAA", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" } };
const vaultA: any = { name: "personal" }; const vaultB: any = { name: "shared" };

function deps(over: Partial<SwitchDeps> = {}) {
  const log: string[] = [];
  let gen = 1;
  const d: SwitchDeps = {
    confirmDiscard: async () => true,
    closeQueue: () => { log.push("close"); },
    openShared: async () => { log.push("openShared"); return { vault: vaultB, key: new Uint8Array(32), version: 3, readOnly: false }; },
    openPersonal: async () => { log.push("openPersonal"); return { vault: vaultA, key: new Uint8Array(32), version: 9 }; },
    apply: (next) => { log.push(`apply:${next.selected.kind}:${next.vault.name}:${next.queue.getSnapshot().version}`); },
    notify: (t) => { log.push(`notify:${t}`); },
    generation: () => gen,
    ...over,
  };
  return { d, log, bump: () => { gen++; } };
}

test("switching closes the old queue before opening the new one", async () => {
  const { d, log } = deps();
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), true);
  assert.deepEqual(log, ["close", "openShared", `apply:shared:shared:3`]);
});

test("declining the discard confirm aborts before anything closes", async () => {
  const { d, log } = deps({ confirmDiscard: async () => false });
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), false);
  assert.deepEqual(log, []);
});

test("a lock during the open is not applied", async () => {
  const h = deps();
  h.d.openShared = async () => { h.bump(); return { vault: vaultB, key: new Uint8Array(32), version: 3, readOnly: false }; };
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, h.d), false);
  assert.ok(!h.log.some((l) => l.startsWith("apply")));
});

test("save 404 on a shared vault falls back to personal", () => {
  const sel = { kind: "shared", id: ID } as const;
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 404 } as any), true);
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 403 } as any), true);
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 409 } as any), false);
  assert.equal(lostAccess(personal, { kind: "error", version: 3, message: "x", status: 404 } as any), false);
});

test("an open failure notifies and falls back to the personal vault", async () => {
  const { d, log } = deps({ openShared: async () => { throw new Error("Your copy of the key cannot be opened; ask an owner to re-seal it."); } });
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), false);
  assert.deepEqual(log, ["close", "notify:Your copy of the key cannot be opened; ask an owner to re-seal it.", "openPersonal", "apply:personal:personal:9"]);
});
```

- [ ] **Step 2: Run to confirm failure** — module not found.

- [ ] **Step 3: Implement `appSelection.ts`**

```ts
import { VaultSaveQueue, type SaveState } from "./vaultSave";
import { selectionBase, type Selected, type OpenedShared } from "./vaultSelection";
import type { SharedVaultSummary } from "./sharedVaults";
import type { KeePassVault } from "./kdbx";

export type SwitchDeps = {
  confirmDiscard: () => Promise<boolean>;
  closeQueue: () => void;
  openShared: (row: SharedVaultSummary) => Promise<OpenedShared>;
  openPersonal: () => Promise<{ vault: KeePassVault; key: Uint8Array; version: number; passwordEnvelope?: string }>;
  apply: (next: { selected: Selected; vault: KeePassVault; key: Uint8Array; queue: VaultSaveQueue; readOnly: boolean }) => void;
  notify: (text: string) => void;
  generation: () => number;
};

export const lostAccess = (selected: Selected, state: SaveState): boolean =>
  selected.kind === "shared" && state.kind === "error" && (state.status === 403 || state.status === 404);

export async function switchTo(target: Selected, row: SharedVaultSummary | undefined, deps: SwitchDeps): Promise<boolean> {
  if (!(await deps.confirmDiscard())) return false;
  const gen = deps.generation();
  deps.closeQueue();
  try {
    if (target.kind === "shared") {
      if (!row) throw new Error("That shared vault is no longer available.");
      const o = await deps.openShared(row);
      if (deps.generation() !== gen) return false;
      deps.apply({ selected: target, vault: o.vault, key: o.key, queue: new VaultSaveQueue(o.vault, o.version, undefined, selectionBase(target)), readOnly: o.readOnly });
      return true;
    }
    const p = await deps.openPersonal();
    if (deps.generation() !== gen) return false;
    deps.apply({ selected: target, vault: p.vault, key: p.key, queue: new VaultSaveQueue(p.vault, p.version, p.passwordEnvelope), readOnly: false });
    return true;
  } catch (err) {
    deps.notify(err instanceof Error ? err.message : String(err));
    if (deps.generation() !== gen) return false;
    const p = await deps.openPersonal();
    if (deps.generation() !== gen) return false;
    deps.apply({ selected: { kind: "personal" }, vault: p.vault, key: p.key, queue: new VaultSaveQueue(p.vault, p.version, p.passwordEnvelope), readOnly: false });
    return false;
  }
}
```

- [ ] **Step 4: Run** `npx tsx --test src/lib/appSelection.test.ts` → PASS.

- [ ] **Step 5: `App.tsx` integration**

Add state next to the existing vault state:

```ts
const [selected, setSelected] = useState<Selected>(personal);
const [readOnly, setReadOnly] = useState(false);
const personalRef = useRef<{ vault: KeePassVault; key: Uint8Array; version: number; passwordEnvelope?: string } | null>(null);
const sharedKeyRef = useRef<Uint8Array | null>(null);
const shared = useSharedVaults(!!vault && !!user);
```

- Where `initVault` sets `setVault(...)`, `setVaultKey(key)`, `setSaveQueue(new VaultSaveQueue(...))` for the personal vault (both the create branch and the unlock branch), also set `personalRef.current = { vault, key, version, passwordEnvelope }`, `setSelected(personal)`, `setReadOnly(false)`.
- `closeVault()`: additionally `sharedKeyRef.current?.fill(0); sharedKeyRef.current = null; personalRef.current = null; setSelected(personal); setReadOnly(false);`.
- `personalKey` for seed/pins: `const personalKey = personalRef.current?.key ?? vaultKey;` and pass `personalRef.current?.vault ?? vault` as `pinVault` to the dialogs in Task 8. The `pinQueue`: when a pin is written while `selected.kind === "shared"`, call `personalRef.current.vault` `setCustomData` then run `uploadVault(await personalRef.current.vault.exportBinary(), personalRef.current.version, undefined, undefined, undefined, false, undefined, PERSONAL_BASE)` through a small `savePersonalPins()` helper that updates `personalRef.current.version` from the response; a 409 here means the personal vault changed elsewhere: notify "Your personal vault changed on the server; the pin was not saved. Switch to My vault and try again." (no retry loop). When `selected.kind === "personal"` a pin write just calls `saveQueue.changed()` as today.
- `switchVault(target)`: builds `SwitchDeps` from the above: `confirmDiscard: confirmDiscardVault`, `closeQueue: () => { saveQueue?.discard(); setSaveQueue(null); }`, `openShared: (row) => openShared(row, seed)` where `seed` comes from `userKey.kind === "ready" ? userKey.seed : throw new Error("Your user key is not available; reload and unlock again.")`, `openPersonal: async () => personalRef.current!` (the personal vault is retained; no refetch), `apply: (n) => { sharedKeyRef.current?.fill(0); sharedKeyRef.current = n.selected.kind === "shared" ? n.key : null; setSelected(n.selected); setVault(n.vault); setVaultKey(n.key); setSaveQueue(n.queue); setReadOnly(n.readOnly); draft.current = null; setInitialDraft(null); setHasDraft(false); navigate({ tab: "vault", shared: n.selected.kind === "shared" ? n.selected.id : undefined }); }`, `notify: (t) => setLockNotice(t)`, `generation: () => unlockGeneration.current`. Note the personal queue: when switching *away* from personal, `closeQueue` discards the personal queue; `openPersonal` returns `personalRef.current` whose `version` must be current, so keep `personalRef.current.version` updated from `saveState.version` whenever `selected.kind === "personal"` (a `useEffect` on `[saveState.version, selected]`).
- Route restore: after `initVault` succeeds and `shared.vaults` has loaded (effect on `[vault, shared.vaults, route.shared]`, guarded by a `restored` ref per unlock generation), call `resolveSelection(route.shared, shared.vaults)`; if it yields a shared selection different from `selected`, `switchVault` to it; if it yields a notice, `setLockNotice(notice)` and `navigate({ tab: "vault" })`.
- Route follow: when the user navigates to `#/shared/<other>` or `#/vault` while unlocked (effect on `route.shared`), run the same resolve + switch. While `selected.kind === "shared"`, every `navigate({ tab: "vault", entry })` in `App.tsx`/`VaultPage`/`WatchtowerPage` must include `shared: selected.id` (Task 4 made `Route` carry it; pass `route.shared` through).
- Save failure on a shared vault: an effect on `[saveState, selected]` calls `lostAccess(selected, saveState)` (add `status?: number` to the error `SaveState` in `vaultSave.ts`, set from `HttpError.status`); when true, call `shared.refresh()` and `switchVault(personal)` with notice "You no longer have write access to “<name>”; switched to My vault."
- Auto-lock draft: `draftId(u.id, selectionScope(selected))` and `draftAccount(u.id, selectionScope(selected))`; on unlock, drafts are only restored for the personal scope (a shared draft is restored when that vault is next selected: on `apply` for a shared selection, look up the pointer for that scope and run the same restore path; keep it simple: read `draftPointer(sessionStorage, \`${u.id}:${scope}\`)`, so store the pointer under `kyvault.draft:${userId}:${scope}` for shared scopes and leave the personal key unchanged).
- Security page: pass `personalOnly={selected.kind === "personal"}`; in `SecuritySettings`, when `personalOnly` is false render a single card "Switch to My vault to change the master password, paper code, device key or rotate the vault key." instead of those cards; the "Your key" card and "Known keys" (Task 8) always render.
- Watchtower: unchanged; it reads `vault`.

`VaultPage.tsx`: add `readOnly?: boolean` and `header?: ReactNode`. Render `header` above the folder pane. When `readOnly`: do not render the New entry button (line ~701), Apply/Cancel edit controls (edit mode never starts: guard `startEdit`/double-click handlers), Delete/Restore entry buttons, folder create/rename/move/delete buttons, Import KeePass/CSV buttons, and pass `readOnly` to `<EntryAttachments readOnly={readOnly || recycled}>`; History modal gets `allowRollback={!readOnly && …}`. Export CSV/KDBX, search, copy, reveal, TOTP stay.

`VaultSwitcher.tsx`:

```tsx
export function VaultSwitcher({ selected, vaults, onSelect, onCreate, onAccept, onDecline, onMembers, canCreate, busy }: Props) {
  const invitations = vaults.filter((v) => v.state === "invited");
  const value = selected.kind === "personal" ? "personal" : selected.id;
  return (
    <div className="vault-switcher" style={{ display: "flex", gap: "0.5rem", alignItems: "center", padding: "0.5rem 0.75rem", borderBottom: "1px solid var(--line)" }}>
      <label className="sr-only" htmlFor="vault-switcher">Vault</label>
      <select id="vault-switcher" className="input" value={value} disabled={busy}
        onChange={(e) => onSelect(e.target.value === "personal" ? { kind: "personal" } : { kind: "shared", id: e.target.value })}>
        <option value="personal">My vault</option>
        {vaults.filter((v) => v.state !== "invited").map((v) => (
          <option key={v.id} value={v.id} disabled={!canOpen(v)}>{v.name}{stateLabel(v) ? ` — ${stateLabel(v)}` : ""}</option>
        ))}
      </select>
      {selected.kind === "shared" ? <button type="button" className="btn btn-quiet btn-sm" onClick={onMembers}>Members</button> : null}
      <button type="button" className="btn btn-quiet btn-sm" onClick={onCreate} disabled={!canCreate || busy} title={canCreate ? undefined : "Your user key is not ready yet."}>New shared vault…</button>
      {invitations.map((v) => (
        <span key={v.id} className="badge badge-cyan" style={{ display: "inline-flex", gap: "0.25rem", alignItems: "center" }}>
          Invitation: {v.name}
          <button type="button" className="btn btn-quiet btn-sm" onClick={() => onAccept(v)}>Accept</button>
          <button type="button" className="btn btn-quiet btn-sm" onClick={() => onDecline(v)}>Decline</button>
        </span>
      ))}
    </div>
  );
}
```

Wire it as `<VaultPage header={<VaultSwitcher …/>} readOnly={readOnly} basePath={selectionBase(selected)} …/>`. `onCreate`/`onAccept`/`onDecline`/`onMembers` open the Task 8 dialogs (stub them as no-ops in this task so it compiles; Task 8 fills them).

- [ ] **Step 6: Gate and commit**

`cd frontend && npm test && npm run build` → PASS (the build runs `check-bundle`; nothing here adds an eager chunk).

```bash
git add frontend/src
git commit -m "frontend: vault switcher; one selected vault at a time; read-only editing for readers

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Create, Accept, Members and Invite dialogs; Known keys

**Files:**
- Create: `frontend/src/lib/sharedFlows.ts` (pure flow functions with injected API: `createSharedVault`, `inviteMember`, `acceptInvitation`, `resealMember`)
- Create: `frontend/src/lib/sharedFlows.test.ts`
- Create: `frontend/src/components/AcceptInvitationDialog.tsx`
- Create: `frontend/src/components/SharedMembersDialog.tsx` (list, role select, Re-seal, Remove, Leave, Rename, Delete, and the Invite form)
- Create: `frontend/src/components/KnownKeys.tsx` (Security card: list pins with Re-pin / Forget)
- Modify: `frontend/src/App.tsx` (wire the switcher callbacks; create uses `dialogs.prompt`)
- Modify: `frontend/src/pages/SecuritySettings.tsx` (render `<KnownKeys>`)

**Interfaces:**
- Consumes: `sharedApi`/`SharedApi`, `SharedVaultSummary`, `Member` (Task 3); `newSharedKey`, `sealSharedKey`, `openSharedKey` (Task 2); `lookupKey`, `pinKey`, `readPin`, `Lookup`, `fetchPublishedKey` (`lib/keyPins.ts`); `fingerprint` (`lib/userKey.ts`); `useDialogs`; `Dialog`.
- Produces:
  ```ts
  // lib/sharedFlows.ts
  export type PinStatus = { state: "pinned" | "unknown" | "changed"; fingerprint: string; publicKey: Uint8Array };
  export type FlowDeps = {
    api: SharedApi;
    pinVault: KeePassVault;                            // the personal vault (pins live here)
    onPinChanged: () => void;                          // App's savePersonalPins / saveQueue.changed
    lookupKey: (vault: KeePassVault, userId: string) => Promise<Lookup>;   // default keyPins.lookupKey
    pinKey: (vault: KeePassVault, userId: string, publicKey: Uint8Array, onChanged: () => void) => Promise<unknown>;
    me: { id: string; publicKey: Uint8Array; seed: Uint8Array; fingerprint: string };
  };
  export async function createSharedVault(name: string, deps: FlowDeps): Promise<{ id: string; key: Uint8Array }>;
  //   key = newSharedKey(); sealed = sealSharedKey(me.publicKey, key); api.create(name, sealed, me.fingerprint)
  export async function resolveInvitee(username: string, deps: FlowDeps): Promise<{ user: LookupResult; pin: PinStatus } | null>;
  //   api.lookupUser → null; lookupKey(pinVault, userId) → state; published null → throws Error("That user has no published key.")
  export async function inviteMember(vaultId: string, invitee: { user: LookupResult; pin: PinStatus }, role: Role, sharedKey: Uint8Array, deps: FlowDeps): Promise<void>;
  //   pin.state === "changed" → throws Error("This user's key changed since you pinned it. Re-pin it from Security → Known keys first.")
  //   pin.state === "unknown" → pinKey first; then sealSharedKey(pin.publicKey, sharedKey) and api.invite(vaultId, userId, role, sealed, pin.fingerprint)
  export async function resealMember(vaultId: string, userId: string, sharedKey: Uint8Array, deps: FlowDeps): Promise<void>;
  //   same lookup/pin rules as invite, then api.updateMember(vaultId, userId, { sealedKey, keyFingerprint })
  export async function inviterStatus(row: SharedVaultSummary, deps: FlowDeps): Promise<PinStatus>;
  //   for the Accept dialog: lookupKey(pinVault, row.invitedBy.userId); compares to row.invitedBy.fingerprint; published null → state "unknown" with the server-reported fingerprint and an empty publicKey (cannot pin)
  export async function acceptInvitation(row: SharedVaultSummary, status: PinStatus, deps: FlowDeps): Promise<void>;
  //   if status.state !== "pinned" and publicKey.length > 0 → pinKey (re-pin on "changed" only after the dialog's second confirm, which the dialog enforces before calling); api.accept(row.id)
  ```

- [ ] **Step 1: Write the failing tests** (`sharedFlows.test.ts`) with an in-memory `SharedApi` fake and a fake `pinVault` implementing `getCustomData`/`setCustomData` over a Map:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, fingerprint } from "./userKey";
import { openSharedKey } from "./sharedKey";
import { createSharedVault, resolveInvitee, inviteMember, acceptInvitation, inviterStatus, type FlowDeps } from "./sharedFlows";
import { lookupKey, pinKey, readPin, type PublishedKey } from "./keyPins";

function fakeVault() {
  const m = new Map<string, string>();
  return { getCustomData: (k: string) => m.get(k), setCustomData: (k: string, v: string | undefined) => { if (v === undefined) m.delete(k); else m.set(k, v); }, customDataKeys: (p: string) => [...m.keys()].filter((k) => k.startsWith(p)) } as any;
}

async function setup() {
  const alice = await generateUserKey(); const bob = await generateUserKey();
  const published: Record<string, PublishedKey> = {
    "u-bob": { userId: "u-bob", publicKey: bob.publicKey, fingerprint: await fingerprint(bob.publicKey), createdAt: "", previous: [] },
    "u-alice": { userId: "u-alice", publicKey: alice.publicKey, fingerprint: await fingerprint(alice.publicKey), createdAt: "", previous: [] },
  };
  const calls: any[] = [];
  const api: any = {
    create: async (name: string, sealedKey: string, fp: string) => { calls.push(["create", name, fp]); return { id: "sv_abcdefghijklmnopqrstuv" }; },
    invite: async (...a: any[]) => { calls.push(["invite", ...a]); },
    updateMember: async (...a: any[]) => { calls.push(["update", ...a]); },
    accept: async (id: string) => { calls.push(["accept", id]); },
    lookupUser: async (name: string) => (name === "bob" ? { userId: "u-bob", username: "bob", fingerprint: published["u-bob"].fingerprint } : null),
  };
  const pinVault = fakeVault();
  let pinSaves = 0;
  const deps: FlowDeps = {
    api, pinVault, onPinChanged: () => { pinSaves++; },
    lookupKey: (v, id) => lookupKey(v, id, async (u) => published[u] ?? null),
    pinKey,
    me: { id: "u-alice", publicKey: alice.publicKey, seed: alice.seed, fingerprint: published["u-alice"].fingerprint },
  };
  return { alice, bob, api, calls, deps, pinVault, published, pinSaves: () => pinSaves };
}

test("create seals the new key to myself", async () => {
  const s = await setup();
  const { id, key } = await createSharedVault("Finance", s.deps);
  assert.equal(id, "sv_abcdefghijklmnopqrstuv");
  assert.deepEqual(s.calls[0].slice(0, 3), ["create", "Finance", s.deps.me.fingerprint]);
});

test("invite pins an unknown user, seals to their key, and writes the personal vault", async () => {
  const s = await setup();
  const invitee = await resolveInvitee("bob", s.deps);
  assert.equal(invitee?.pin.state, "unknown");
  const key = crypto.getRandomValues(new Uint8Array(32));
  await inviteMember("sv_abcdefghijklmnopqrstuv", invitee!, "editor", key, s.deps);
  const [, vaultId, userId, role, sealed, fp] = s.calls.find((c) => c[0] === "invite")!;
  assert.equal(userId, "u-bob"); assert.equal(role, "editor"); assert.equal(fp, s.published["u-bob"].fingerprint);
  assert.deepEqual([...(await openSharedKey(s.bob.seed, sealed))], [...key]);
  assert.ok(readPin(s.pinVault, "u-bob"));
  assert.equal(s.pinSaves(), 1);
});

test("invite refuses a changed pin and an unknown username", async () => {
  const s = await setup();
  await pinKey(s.pinVault, "u-bob", s.alice.publicKey, () => {});   // wrong key pinned
  const invitee = await resolveInvitee("bob", s.deps);
  assert.equal(invitee?.pin.state, "changed");
  await assert.rejects(inviteMember("sv_x", invitee!, "reader", new Uint8Array(32), s.deps), /Re-pin/);
  assert.equal(await resolveInvitee("nobody", s.deps), null);
});

test("accept reports inviter pin status and pins on accept", async () => {
  const s = await setup();
  const row: any = { id: "sv_abcdefghijklmnopqrstuv", name: "Finance", role: "editor", state: "invited", keyEpoch: 1, myKey: {}, invitedBy: { userId: "u-bob", username: "bob", fingerprint: s.published["u-bob"].fingerprint } };
  const status = await inviterStatus(row, s.deps);
  assert.equal(status.state, "unknown");
  await acceptInvitation(row, status, s.deps);
  assert.ok(readPin(s.pinVault, "u-bob"));
  assert.deepEqual(s.calls.at(-1), ["accept", row.id]);
  assert.equal((await inviterStatus(row, s.deps)).state, "pinned");
});
```

- [ ] **Step 2: Run to confirm failure** — module not found.

- [ ] **Step 3: Implement `sharedFlows.ts`** exactly per the Interfaces block (each function is 5–15 lines; `inviterStatus` maps `Lookup` → `PinStatus` and, when `published` is null, returns `{ state: "unknown", fingerprint: row.invitedBy.fingerprint, publicKey: new Uint8Array() }`). Run the tests → PASS.

- [ ] **Step 4: Dialogs**

`AcceptInvitationDialog.tsx` props `{ row: SharedVaultSummary; deps: FlowDeps; onDone: (accepted: boolean) => void }`. On mount call `inviterStatus`. Body:

```tsx
<Dialog title={`Join “${row.name}”?`} onClose={() => onDone(false)}>
  <p>Invited by <strong>{row.invitedBy?.username}</strong> as <strong>{row.role}</strong>.</p>
  <p>Their key fingerprint:</p>
  <code className="font-mono" aria-label="Inviter key fingerprint">{status.fingerprint}</code>
  {status.state === "pinned" ? <p className="ok">Matches the key you pinned.</p> : null}
  {status.state === "unknown" ? <p role="alert" className="warn">Not verified. Verify with {row.invitedBy?.username} before you rely on this vault.</p> : null}
  {status.state === "changed" ? <p role="alert" className="danger">Their key changed since you pinned it. Verify with {row.invitedBy?.username} before you rely on this vault.</p> : null}
  <p className="muted">KyVault trusts the server for who is in a vault, never for its contents.</p>
  <div className="dialog-actions">
    <button className="btn btn-secondary" onClick={decline}>Decline</button>
    <button className="btn btn-primary" disabled={busy || !status} onClick={accept}>Accept</button>
  </div>
</Dialog>
```

`accept`: if `status.state === "changed"`, first `dialogs.confirm({ title: "Re-pin this key?", message: "You are about to trust a new key for this user. Only do this after verifying the fingerprint with them.", danger: true, confirmLabel: "Re-pin and accept" })`; then `acceptInvitation`, `onDone(true)`. `decline`: `api.decline(row.id)`, `onDone(false)`. Errors show inline via `toErrorMessage`.

`SharedMembersDialog.tsx` props `{ vaultId: string; myId: string; myRole: Role; sharedKey: Uint8Array | null; deps: FlowDeps; onChanged: () => void; onLeftOrDeleted: () => void; onClose: () => void }`. Loads `api.get(vaultId)`; renders the members table (username, role select for owners with last-owner 409 shown inline, state badge, key fingerprint with pin status from `deps.lookupKey`, "sealed by"), per row: Re-seal (owner, `state === "stale"`, needs `sharedKey`), Remove (owner, not self, confirm), Leave (self, confirm "You will lose access to this vault until an owner invites you again."); header: Rename (owner; `dialogs.prompt`), Delete (owner; confirm; on 403 starting `re-authenticate` show the `<a href="/api/auth/oidc/login?reauth=true">Sign in again</a>` line like `AdminBackup.tsx:139-142`); Invite form (owner): username input → "Look up" → shows fingerprint + pin status + role select → Invite (disabled on `changed`, with the Re-pin message). Every action awaits the API, then `onChanged()` (App refreshes `shared` list) and reloads the detail; Leave/Delete call `onLeftOrDeleted()` (App switches to personal).

`KnownKeys.tsx` props `{ vault: KeePassVault; onChanged: () => void }`: lists `vault.customDataKeys("kyvault.pin.")` → for each, `readPin` → row with user id, fingerprint, pinned date, Forget (removes the custom data, `onChanged`) and Re-pin (fetches `fetchPublishedKey(userId)`, shows both fingerprints, confirm, `pinKey`). Rendered in `SecuritySettings` below "Your key" with `vault={pinVault}` and `onChanged={savePins}`.

`App.tsx`: implement the switcher callbacks: `onCreate` → `dialogs.prompt({ title: "New shared vault", label: "Name", validate: (v) => (v.trim().length >= 1 && v.trim().length <= 64 && !/[\p{Cc}\p{Cf}]/u.test(v) ? null : "1 to 64 characters, no control characters") })` → `createSharedVault(name, flowDeps)` → `shared.refresh()` → `switchVault({ kind: "shared", id })`; `onAccept` → mount `<AcceptInvitationDialog>`; `onDecline` → confirm then `sharedApi.decline`; `onMembers` → mount `<SharedMembersDialog sharedKey={sharedKeyRef.current} …>`. `flowDeps` is built once per unlock from `sharedApi`, `personalRef.current.vault`, `savePersonalPins`, `lookupKey`, `pinKey`, and `userKey` (`kind === "ready"`). Every dialog must be closed by `closeVault` (add their `setShow…(false)` to it), matching the rule that a lock cancels every pending question.

- [ ] **Step 5: Gate and commit**

`cd frontend && npm test && npm run build` → PASS.

```bash
git add frontend/src
git commit -m "frontend: create, invite, accept and manage shared vaults; known keys card

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Replace user key re-seals shared vaults

**Files:**
- Create: `frontend/src/lib/keyReplaceReseal.ts`
- Create: `frontend/src/lib/keyReplaceReseal.test.ts`
- Modify: `frontend/src/pages/SecuritySettings.tsx` (`replaceUserKey` uses the plan; new props `sharedVaults: SharedVaultSummary[]`, `onSharedChanged: () => void`, `sharedApi?: SharedApi`)
- Modify: `frontend/src/App.tsx` (pass `shared.vaults` and refresh after replace)

**Interfaces:**
- Produces:
  ```ts
  export type HeldKey = { id: string; name: string; key: Uint8Array };
  export type ReplacePlan = { held: HeldKey[]; unopenable: { id: string; name: string; soleOwner: boolean }[] };
  export async function planReplace(vaults: SharedVaultSummary[], seed: Uint8Array, openKey?: typeof openSharedKey, getDetail?: (id: string) => Promise<SharedVaultDetail>): Promise<ReplacePlan>;
  //   for each row with state "active" (any role): try openKey → held; catch → unopenable, soleOwner = role === "owner" && detail.members has no other active owner
  export function replaceWarning(plan: ReplacePlan): string | null;
  //   null when nothing is unopenable; otherwise names each vault, and for soleOwner ones adds "its contents will be lost".
  export async function resealHeld(held: HeldKey[], me: { id: string; publicKey: Uint8Array; fingerprint: string }, api: SharedApi, seal?: typeof sealSharedKey): Promise<{ failed: { id: string; name: string; error: string }[] }>;
  //   for each: api.updateMember(id, me.id, { sealedKey: await seal(me.publicKey, key), keyFingerprint: me.fingerprint }); collects failures, never throws.
  ```

- [ ] **Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { planReplace, replaceWarning, resealHeld } from "./keyReplaceReseal";
import { generateUserKey, fingerprint } from "./userKey";
import { sealSharedKey, openSharedKey, newSharedKey } from "./sharedKey";

const row = (id: string, name: string, role: any, sealedKey: string, state = "active"): any => ({ id, name, role, state, keyEpoch: 1, myKey: { sealedKey, keyFingerprint: "", keyEpoch: 1, sealedBy: "", sealedByFingerprint: "" } });

test("planReplace holds openable keys and names the rest", async () => {
  const me = await generateUserKey(); const other = await generateUserKey();
  const k1 = newSharedKey();
  const vaults = [
    row("sv_aaaaaaaaaaaaaaaaaaaaaa", "Finance", "owner", await sealSharedKey(me.publicKey, k1)),
    row("sv_bbbbbbbbbbbbbbbbbbbbbb", "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey())),
    row("sv_cccccccccccccccccccccc", "Invited", "editor", "AAAA", "invited"),
  ];
  const detail = async (id: string) => ({ id, name: "", createdBy: "", createdAt: "", keyEpoch: 1, members: id.startsWith("sv_b") ? [{ userId: "me", role: "owner", state: "active" }] : [] } as any);
  const plan = await planReplace(vaults, me.seed, openSharedKey, detail);
  assert.deepEqual(plan.held.map((h) => h.id), ["sv_aaaaaaaaaaaaaaaaaaaaaa"]);
  assert.deepEqual([...plan.held[0].key], [...k1]);
  assert.deepEqual(plan.unopenable, [{ id: "sv_bbbbbbbbbbbbbbbbbbbbbb", name: "Ops", soleOwner: true }]);
  assert.match(replaceWarning(plan) ?? "", /Ops.*contents will be lost/s);
  assert.equal(replaceWarning({ held: [], unopenable: [] }), null);
});

test("resealHeld reseals to the new key and collects failures", async () => {
  const me = await generateUserKey();
  const held = [{ id: "sv_aaaaaaaaaaaaaaaaaaaaaa", name: "Finance", key: newSharedKey() }, { id: "sv_bbbbbbbbbbbbbbbbbbbbbb", name: "Ops", key: newSharedKey() }];
  const calls: any[] = [];
  const api: any = { updateMember: async (id: string, userId: string, patch: any) => { calls.push([id, userId, patch]); if (id.startsWith("sv_b")) throw new Error("boom"); } };
  const fp = await fingerprint(me.publicKey);
  const { failed } = await resealHeld(held, { id: "me", publicKey: me.publicKey, fingerprint: fp }, api);
  assert.deepEqual(failed.map((f) => f.id), ["sv_bbbbbbbbbbbbbbbbbbbbbb"]);
  assert.equal(calls[0][2].keyFingerprint, fp);
  assert.deepEqual([...(await openSharedKey(me.seed, calls[0][2].sealedKey))], [...held[0].key]);
});
```

- [ ] **Step 2: Run to confirm failure** — module not found.

- [ ] **Step 3: Implement** per the Interfaces block (≈50 lines). Then in `SecuritySettings.replaceUserKey`:

```ts
const plan = userKey.kind === "ready" ? await planReplace(sharedVaults, userKey.seed) : { held: [], unopenable: [] };
const warning = replaceWarning(plan);
const confirmed = await dialogs.confirm({ title: "Replace your key?", message: [BASE_MESSAGE, warning].filter(Boolean).join("\n\n"), confirmLabel: "Replace key", danger: true });
if (!confirmed) return;
... existing PUT ...
onUserKeyReplaced(nextState, generation);
const { failed } = await resealHeld(plan.held, { id: user.id, publicKey: made.publicKey, fingerprint: await fingerprint(made.publicKey) }, sharedApi);
setResealFailures(failed.length ? { failed, held: plan.held, me: … } : null);   // renders a list with a Retry button that calls resealHeld again for the failed subset
onSharedChanged();   // App: shared.refresh()
```

Held keys stay in component state until success or until `closeVault` (component unmounts on lock).

- [ ] **Step 4: Gate and commit**

`cd frontend && npm test && npm run build` → PASS.

```bash
git add frontend/src
git commit -m "frontend: replacing the user key re-seals held shared vault keys

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Admin → Shared vaults

**Files:**
- Create: `frontend/src/components/AdminShared.tsx`
- Modify: `frontend/src/pages/AdminPanel.tsx` (tab button + body branch for `activeTab === "shared"`)
- Modify: `frontend/src/lib/sharedVaults.ts` (append `adminSharedApi`)

**Interfaces:**
- Produces:
  ```ts
  export type AdminSharedVault = { id: string; name: string; createdBy: string; createdAt: string; keyEpoch: number; ownerless: boolean; members: { userId: string; username: string; role: Role; state: MemberState }[] };
  export const adminSharedApi = {
    list: () => getJSON<AdminSharedVault[]>("/api/admin/shared"),
    remove: async (id) => { await deleteJSON(`/api/admin/shared/${encodeURIComponent(id)}`); },
    removeMember: async (id, userId) => { await deleteJSON(`/api/admin/shared/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}`); },
    settings: () => getJSON<{ createRestrictedToAdmins: boolean }>("/api/admin/shared/settings"),
    saveSettings: async (s) => { await putJSON("/api/admin/shared/settings", s); },
  };
  ```

- [ ] **Step 1: Implement** `AdminShared.tsx` following the `usersList.map` row style in `AdminPanel.tsx:396-434`: a settings card with the checkbox "Only admins may create shared vaults" (saves on change; 403 `re-authenticate` → error card with the Sign in again link, copied from `AdminBackup.tsx:139-142`); a table of vaults (name, created by, created, member count, `ownerless` badge in the same style as `Disabled`); expand → members with role and state badges and a Remove button (confirm: "Remove <username> from “<name>”? They lose access now; their copy of the key is only invalidated by a key rotation."); Delete vault button (confirm: "Delete “<name>”? Members lose access. The server keeps it for the retention window; recovery is a host operation."). After each action reload the list. Add the tab button `<Users2 size={16}/> Shared vaults` and the body branch. No fingerprints, no keys.

- [ ] **Step 2: Gate and commit**

`cd frontend && npm test && npm run build` → PASS.

```bash
git add frontend/src
git commit -m "frontend: admin shared vaults tab

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: Mock API, UI verification, docs, full gate

**Files:**
- Modify: `frontend/mock/api.ts` (shared, lookup and admin shared routes over an in-memory store)
- Modify: `UI-VERIFICATION.md`, `docs/` screenshots (`docs/shared-*.png`)
- Modify: `AGENTS.md` (Child DOX Index bullets for the new libs/components; capability 10 gains "Web client: switcher…"; `internal/shared/AGENTS.md` unchanged)
- Modify: `docs/superpowers/specs/2026-09-27-shared-vaults-web-design.md` only if execution changed a contract (record it)

- [ ] **Step 1: Mock routes**

In the if-chain add an in-memory `sharedStore: { vaults: Map<string, {name, members, bytes, version, ...}>, settings }` seeded with one vault where `u-1` is owner and one pending invitation from `dana`, plus `GET /api/users/lookup` (`dana` → `{userId:"u-2", username:"dana", fingerprint:"AAAA BBBB CCCC DDDD EEEE"}`), `GET /api/users/u-2/key` returning a real generated X-Wing public key (generate once at mock start with `@hpke/hybridkem-x-wing` so `sealSharedKey` works), all `/api/shared*` routes with the 3a semantics the UI depends on (404 non-member, 403 reader write, 409 last owner), and the admin routes. Sealed keys: the mock's seeded vault must hold a `myKey.sealedKey` sealed to the mock user's key: simplest is to let `POST /api/shared` from the UI create it during the manual pass, and seed only the invitation (whose `sealedKey` can be any 1168 bytes because the UI never opens an invitation's key).

- [ ] **Step 2: UI pass**

`cd frontend && npm run dev:mock`; with the Playwright MCP capture: switcher with an invitation badge; Accept dialog in the three pin states (drive by pre-seeding a pin in the mock vault's custom data through the UI Known keys card, then changing the mock fingerprint); Members dialog with Invite form; a reader's read-only vault; Admin → Shared vaults. Save to `docs/shared-switcher.png`, `docs/shared-accept.png`, `docs/shared-members.png`, `docs/shared-admin.png`. Record what was checked and what could not be captured in `UI-VERIFICATION.md`.

- [ ] **Step 3: Docs**

Root `AGENTS.md` Child DOX Index, one bullet:
"`frontend/src/lib/sharedVaults.ts`, `sharedKey.ts`, `vaultSelection.ts`, `appSelection.ts`, `sharedFlows.ts`, `keyReplaceReseal.ts`, `components/VaultSwitcher.tsx`, `AcceptInvitationDialog.tsx`, `SharedMembersDialog.tsx`, `KnownKeys.tsx`, `AdminShared.tsx`: one vault is open at a time; `selected` in `App.tsx` names it and the personal vault is retained in `personalRef` for seed and pins. Shared keys are 32 random bytes sealed with `seal(pk, "kyvault/shared-vault-key/1", key)`; the blob is 1168 bytes. Switching runs `switchTo` (confirm discard → close queue → open → generation check → apply; failure falls back to personal). Transport is `basePath`-relative (`/api/vault` or `/api/shared/<id>`) in `vaultSave.ts`, `HistoryModal`, `ConflictComparison`; drafts are scoped `${userId}:${scope}`. Invite looks up by exact username (`GET /api/users/lookup`), pins on first use, refuses a changed pin until re-pinned in Security → Known keys; Accept shows the inviter's fingerprint with pin status and the line 'KyVault trusts the server for who is in a vault, never for its contents.' Readers open read-only (`VaultPage readOnly`). Replace user key opens every held shared key first, warns by name for unopenable ones (sole owner: contents lost), and self-reseals each after the replace with Retry for failures. Admin → Shared vaults lists, deletes and removes members; no key material. Not built: 3c rotation, 3d clients."

- [ ] **Step 4: Full gate**

`gofmt -l . | grep -v node_modules` (empty); `go vet ./...`; `go test -race ./...`; `cd frontend && npm test && npm run build && npm audit --audit-level=high`; `cd extension && npm test && npm run build && npm run lint` (untouched, must still pass).

- [ ] **Step 5: Commit**

```bash
git add frontend/mock/api.ts UI-VERIFICATION.md docs AGENTS.md
git commit -m "docs: shared vaults web client contract, mock routes and UI verification

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
