# Shared Vault Leaving and Key Rotation (3c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A removed member's copy of a shared vault key stops opening anything the vault saves afterwards: departures flag a pending rotation, an owner re-keys the vault and re-seals it to everyone who remains, and the ciphertext the retired key could open is deleted.

**Architecture:** `internal/shared` gains a `rotationPending` flag set by every departure and a `Rotate` transition that bumps the vault's key epoch, re-seals the named members and marks the rest stale. `internal/vault` gains `ClearHistory`. One new route, `POST /api/shared/{id}/rotate`, parses a two-part multipart body as a stream and commits the ciphertext, the sealed keys, the epoch and the history deletion together. Every shared write carries `X-Shared-Key-Epoch` so a tab holding a retired key cannot save. On the client a pure `lib/sharedRotation.ts` decides whom to seal to and performs the rotation with the same lost-response check the Replace-key flow uses.

**Tech Stack:** Go 1.26 stdlib (`mime/multipart` via `r.MultipartReader`, `net/http`, `encoding/json`), existing `internal/shared`, `internal/vault`, `internal/api`; React 18 + TypeScript in `frontend/` (tests `npm test` = tsx --test, gate `npm run build`), hpke-js through `lib/userKey.ts`, kdbxweb through `lib/kdbx.ts`.

**Spec:** `docs/superpowers/specs/2026-09-27-shared-vault-rotation-design.md`

**Interfaces digest (read-only reference, exact current signatures):** `.superpowers/3c-digest.md`

## Global Constraints

- Repo root `KyVault-server/`. Go gate: `gofmt -l . | grep -v node_modules` empty, `go vet ./...`, `go test -race ./...`. Frontend gate: `cd frontend && npm test && npm run build`.
- `rotationPending` JSON: `{"since": "<RFC3339>", "userId": "<id>", "reason": "removed|left|declined"}`, omitted when absent. Set by removal, leaving and declining; never by `SetRole` or `SetSuspended`; cleared by `Rotate`.
- A member removing their own `invited` row is `declined`; any other self-removal is `left`; anyone removing someone else is `removed`.
- `Rotate(id, actorID, sealed []SealedFor, now)`: actor must be an active owner; every `SealedFor` names a current member, carries a base64 sealed key of exactly `SealedKeyBytes` (1168) and a `KeyFingerprint` equal to that member's current published fingerprint; vault `KeyEpoch` → N+1; named members take the new key, epoch N+1, the actor as `SealedBy`/`SealedByFingerprint`, keeping role and `invited`/`active` state; unnamed members stay at epoch N and become `stale` (a `suspended` row keeps `suspended` with `suspendedFrom` `stale`); `RotationPending` cleared. An ownerless vault is refused.
- Route `POST /api/shared/{id}/rotate`: `withAuth`, active owners only, `validCSRF`, `requireFresh`, `multipart/form-data` with exactly two parts in order — `kdbx` (the re-encrypted vault, streamed) and `keys` (JSON `{"epoch": N, "sealed": [{userId, sealedKey, keyFingerprint}]}`, ≤ 1 MiB). `epoch` is the epoch being rotated **from**. Whole body capped at `50<<20 + 1<<20`. `If-Match` carries the vault data version.
- `X-Shared-Key-Epoch: N` is required on shared upload, history restore and conflict discard; `withSharedWrite` refuses a missing or mismatched value with 409 and the body `the shared vault key was rotated; reload the vault`.
- Audit `shared.key_rotated`, detail `<vaultId>: rotated to epoch N, sealed to X members, Y left behind`. No sealed key in any audit detail (`assertAudited` enforces it).
- Copy, verbatim where quoted: the rotate confirmation says the vault's version history and preserved conflicts are deleted; removal and leave confirmations say a removed member's copy of the key still opens anything saved before a rotation.
- Commit trailer: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. A rotation whose multipart body is truncated mid-`kdbx` must leave the membership record, the ciphertext and the history exactly as they were (Task 3, in `TestSharedRotateRefusals`: the truncated-body case and the final "changed nothing" assertions).
2. Two owners rotating the same vault at the same moment must not both succeed: the second must see the epoch move and be refused (Task 1, the stale-epoch case at the end of `TestRotate`; Task 3 `TestConcurrentRotationsLeaveOneEpoch`).
3. A member re-sealed by a rotation whose tab still holds the retired key must be refused on save, not silently write old-key ciphertext (Task 2 `TestSharedWritesCarryTheKeyEpoch`).
4. A rotation that names a member who was removed between the client's read and the write must fail the whole rotation rather than writing a key for a stranger (Task 1, the non-member case in `TestRotateRefusals`).
5. A rotation whose response is lost must not leave the vault re-keyed while the only browser holding the new key discards it (Task 6 `a lost response is adopted when the published key is ours`).

---

### Task 1: `rotationPending` and `shared.Store.Rotate`

**Files:**
- Modify: `internal/shared/shared.go`
- Modify: `internal/shared/shared_test.go` (append)

**Interfaces:**
- Consumes: the existing `Vault`, `Member`, `update`, `authorize`, `freshState`, `ValidSealedKey`, `ErrForbidden`, `ErrNotMember`, `ErrShape`, `ErrState`, `ErrNotFound` (see `.superpowers/3c-digest.md` §1).
- Produces:
  ```go
  type RotationReason string
  const (
      ReasonRemoved  RotationReason = "removed"
      ReasonLeft     RotationReason = "left"
      ReasonDeclined RotationReason = "declined"
  )
  type Pending struct {
      Since  time.Time      `json:"since"`
      UserID string         `json:"userId"`
      Reason RotationReason `json:"reason"`
  }
  // on Vault:
  //   RotationPending *Pending `json:"rotationPending,omitempty"`
  type SealedFor struct {
      UserID         string `json:"userId"`
      SealedKey      string `json:"sealedKey"`
      KeyFingerprint string `json:"keyFingerprint"`
  }
  func (s *Store) Rotate(id, actorID string, epoch int, sealed []SealedFor, now time.Time) (Vault, error)
  var ErrEpoch = errors.New("the shared vault key was rotated")
  ```
  `Remove(id, actorID, userID string, now time.Time) error` gains the `now` parameter so it can stamp the flag. Every caller in `internal/api` is updated in Task 2.

- [ ] **Step 1: Write the failing tests**

Append to `internal/shared/shared_test.go`:

```go
func sealedForAll(t *testing.T, v Vault) []SealedFor {
	t.Helper()
	out := []SealedFor{}
	for id, m := range v.Members {
		out = append(out, SealedFor{UserID: id, SealedKey: sealed(), KeyFingerprint: m.KeyFingerprint})
	}
	return out
}

func TestDepartureFlagsARotation(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(1), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-3", RoleReader, sealed(), fp(2), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	// An owner removing an accepted member.
	if err := s.Remove(v.ID, "u-1", "u-2", t0); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, v.ID)
	if got.RotationPending == nil || got.RotationPending.UserID != "u-2" || got.RotationPending.Reason != ReasonRemoved {
		t.Fatalf("after removal: %+v", got.RotationPending)
	}
	// A role change does not flag.
	if _, err := s.Rotate(v.ID, "u-1", got.KeyEpoch, sealedForAll(t, got), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(v.ID, "u-1", "u-3", RoleEditor); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, s, v.ID).RotationPending != nil {
		t.Fatal("a role change must not flag a rotation")
	}
	// An invited member removing their own row is a decline.
	if err := s.Remove(v.ID, "u-3", "u-3", t0); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, s, v.ID); got.RotationPending == nil || got.RotationPending.Reason != ReasonDeclined {
		t.Fatalf("invited self-removal: %+v", got.RotationPending)
	}
}

func TestLeavingFlagsALeft(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(1), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(v.ID, "u-2", "u-2", t0); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, v.ID)
	if got.RotationPending == nil || got.RotationPending.Reason != ReasonLeft || got.RotationPending.UserID != "u-2" {
		t.Fatalf("leaving: %+v", got.RotationPending)
	}
	// Deactivation is not a departure.
	if _, err := s.SetSuspended("u-1", true); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, s, v.ID); got.RotationPending.Reason != ReasonLeft {
		t.Fatal("suspension must not overwrite or set the flag")
	}
}

func TestRotate(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		id   string
		role Role
		f    string
	}{{"u-2", RoleEditor, fp(1)}, {"u-3", RoleReader, fp(2)}, {"u-4", RoleEditor, fp(3)}} {
		if err := s.Invite(v.ID, m.id, m.role, sealed(), m.f, "u-1", fp(0), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-3", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(v.ID, "u-1", "u-3", t0); err != nil {
		t.Fatal(err)
	}
	before := mustGet(t, s, v.ID)
	// u-4 is left behind: not named.
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, SealedKeyBytes))
	sealed := []SealedFor{
		{UserID: "u-1", SealedKey: newKey, KeyFingerprint: fp(0)},
		{UserID: "u-2", SealedKey: newKey, KeyFingerprint: fp(1)},
	}
	if _, err := s.Rotate(v.ID, "u-1", before.KeyEpoch, sealed, t0); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, v.ID)
	if got.KeyEpoch != before.KeyEpoch+1 {
		t.Fatalf("epoch %d", got.KeyEpoch)
	}
	if got.RotationPending != nil {
		t.Fatal("rotation must clear the flag")
	}
	for _, id := range []string{"u-1", "u-2"} {
		m := got.Members[id]
		if m.SealedKey != newKey || m.KeyEpoch != got.KeyEpoch || m.State != StateActive || m.SealedBy != "u-1" {
			t.Fatalf("%s: %+v", id, m)
		}
	}
	if m := got.Members["u-2"]; m.Role != RoleEditor {
		t.Fatalf("rotation must keep roles: %+v", m)
	}
	if m := got.Members["u-4"]; m.State != StateStale || m.KeyEpoch != before.KeyEpoch {
		t.Fatalf("u-4 should be left behind stale at the old epoch: %+v", m)
	}
	// A second rotation at the same epoch is refused (Review Focus 2).
	if _, err := s.Rotate(v.ID, "u-1", before.KeyEpoch, sealed, t0); !errors.Is(err, ErrEpoch) {
		t.Fatalf("stale epoch = %v", err)
	}
}

func TestRotateKeepsInvitedAndSuspendedStates(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(1), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-3", RoleReader, sealed(), fp(2), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-3", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended("u-3", true); err != nil {
		t.Fatal(err)
	}
	cur := mustGet(t, s, v.ID)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, SealedKeyBytes))
	_, err = s.Rotate(v.ID, "u-1", cur.KeyEpoch, []SealedFor{
		{UserID: "u-1", SealedKey: key, KeyFingerprint: fp(0)},
		{UserID: "u-2", SealedKey: key, KeyFingerprint: fp(1)},
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, v.ID)
	if m := got.Members["u-2"]; m.State != StateInvited || m.SealedKey != key {
		t.Fatalf("an invited member is re-sealed and stays invited: %+v", m)
	}
	if m := got.Members["u-3"]; m.State != StateSuspended || m.SuspendedFrom != StateStale {
		t.Fatalf("a suspended member left behind: %+v", m)
	}
}

func TestRotateRefusals(t *testing.T) {
	s := newStore(t)
	v, err := s.Create("Finance", "u-1", sealed(), fp(0), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Invite(v.ID, "u-2", RoleEditor, sealed(), fp(1), "u-1", fp(0), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(v.ID, "u-2", t0); err != nil {
		t.Fatal(err)
	}
	cur := mustGet(t, s, v.ID)
	ok := []SealedFor{{UserID: "u-1", SealedKey: sealed(), KeyFingerprint: fp(0)}}
	// Not an owner, and not a member at all.
	if _, err := s.Rotate(v.ID, "u-2", cur.KeyEpoch, ok, t0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("editor = %v", err)
	}
	if _, err := s.Rotate(v.ID, "u-9", cur.KeyEpoch, ok, t0); !errors.Is(err, ErrNotMember) {
		t.Fatalf("stranger = %v", err)
	}
	// Sealing for a non-member aborts everything (Review Focus 4).
	bad := append([]SealedFor{}, ok...)
	bad = append(bad, SealedFor{UserID: "u-9", SealedKey: sealed(), KeyFingerprint: fp(9)})
	if _, err := s.Rotate(v.ID, "u-1", cur.KeyEpoch, bad, t0); !errors.Is(err, ErrShape) {
		t.Fatalf("non-member = %v", err)
	}
	// A fingerprint that is not the member's current one.
	wrongFP := []SealedFor{{UserID: "u-1", SealedKey: sealed(), KeyFingerprint: fp(5)}}
	if _, err := s.Rotate(v.ID, "u-1", cur.KeyEpoch, wrongFP, t0); !errors.Is(err, ErrShape) {
		t.Fatalf("wrong fingerprint = %v", err)
	}
	// A malformed sealed key.
	short := []SealedFor{{UserID: "u-1", SealedKey: "AAAA", KeyFingerprint: fp(0)}}
	if _, err := s.Rotate(v.ID, "u-1", cur.KeyEpoch, short, t0); !errors.Is(err, ErrShape) {
		t.Fatalf("short key = %v", err)
	}
	// Every refusal above left the record untouched.
	if after := mustGet(t, s, v.ID); after.KeyEpoch != cur.KeyEpoch || after.Members["u-1"].SealedKey != cur.Members["u-1"].SealedKey {
		t.Fatal("a refused rotation must change nothing")
	}
	// An ownerless vault cannot rotate.
	if err := s.Remove(v.ID, "", "u-1", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(v.ID, "u-2", mustGet(t, s, v.ID).KeyEpoch, ok, t0); err == nil {
		t.Fatal("an ownerless vault must not rotate")
	}
}
```

`mustGet`, `newStore`, `sealed()`, `fp(n)` and `t0` already exist in this file; `bytes` and `encoding/base64` are already imported.

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/shared/ -run 'TestDeparture|TestLeaving|TestRotate'`
Expected: compile failure (`Rotate`, `RotationPending`, `ReasonRemoved` undefined; `Remove` takes 3 arguments).

- [ ] **Step 3: Implement**

In `internal/shared/shared.go` add the types from the Interfaces block, add `RotationPending *Pending` to `Vault`, and add `ErrEpoch`. Validate `RotationPending` in `loadLocked` beside the existing enum checks: a non-nil flag must carry one of the three reasons and a non-empty `UserID`, else `ErrCorrupt`.

`Remove` gains `now time.Time` and, after the existing removal succeeds, stamps the flag:

```go
reason := ReasonRemoved
if actorID == userID {
	reason = ReasonLeft
	if was == StateInvited {
		reason = ReasonDeclined
	}
}
v.RotationPending = &Pending{Since: now.UTC(), UserID: userID, Reason: reason}
```

where `was` is the removed member's state captured before deletion. An admin removal (`actorID == ""`) is `ReasonRemoved`, because `"" != userID`.

`Rotate`:

```go
// Rotate re-keys a shared vault: it takes one sealed copy of the new key per member the
// caller could seal for, bumps the epoch, and leaves everyone else at the old epoch as
// stale. It is the only thing that stops a removed member's copy of the key from opening
// what the vault saves next, so it clears the pending flag a departure set.
func (s *Store) Rotate(id, actorID string, epoch int, sealed []SealedFor, now time.Time) (Vault, error) {
	var out Vault
	err := s.update(id, actorID, func(v *Vault) error {
		if v.KeyEpoch != epoch {
			return fmt.Errorf("%w: at epoch %d", ErrEpoch, v.KeyEpoch)
		}
		for _, sf := range sealed {
			m, ok := v.Members[sf.UserID]
			if !ok {
				return fmt.Errorf("%w: %s is not a member", ErrShape, sf.UserID)
			}
			if err := ValidSealedKey(sf.SealedKey); err != nil {
				return err
			}
			if sf.KeyFingerprint == "" || sf.KeyFingerprint != m.KeyFingerprint {
				return fmt.Errorf("%w: keyFingerprint does not match %s's current key", ErrShape, sf.UserID)
			}
		}
		actorFP := ""
		if a, ok := v.Members[actorID]; ok {
			actorFP = a.KeyFingerprint
		}
		next := v.KeyEpoch + 1
		named := map[string]bool{}
		for _, sf := range sealed {
			m := v.Members[sf.UserID]
			m.SealedKey, m.KeyFingerprint = sf.SealedKey, sf.KeyFingerprint
			m.SealedBy, m.SealedByFingerprint = actorID, actorFP
			m.KeyEpoch = next
			v.Members[sf.UserID] = m
			named[sf.UserID] = true
		}
		for id, m := range v.Members {
			if named[id] {
				continue
			}
			if m.State == StateSuspended {
				m.SuspendedFrom = StateStale
			} else {
				m.State = StateStale
			}
			v.Members[id] = m
		}
		v.KeyEpoch = next
		v.RotationPending = nil
		out = *v
		return nil
	})
	return out, err
}
```

`update` already runs `authorize(v, actorID)` under the lock, which refuses a non-owner with `ErrForbidden`, a stranger with `ErrNotMember`, and an ownerless vault (no active owner) — confirm that last one against `authorize` in the digest and, if an ownerless vault currently passes for a remaining active owner, add the explicit check `if activeOwners(*v) == 0 { return ErrState }` at the top of the closure.

- [ ] **Step 4: Run to confirm they pass**

Run: `go test -race ./internal/shared/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shared
git commit -m "shared: departures flag a pending rotation; Rotate re-keys the vault

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `ClearHistory` and the epoch gate on shared writes

**Files:**
- Modify: `internal/vault/vault.go`
- Modify: `internal/vault/vault_test.go` (append)
- Modify: `internal/api/shared_handlers.go` (`withSharedWrite`, and the `Remove` call sites gain `time.Now()`)
- Modify: `internal/api/vault_handlers.go` (drop the shared-rotation 400 now that a real route exists)
- Modify: `internal/api/shared_test.go` (append)

**Interfaces:**
- Consumes: `shared.Store.Remove(id, actorID, userID string, now time.Time) error` (Task 1); `sharedCtx`, `withSharedWrite`, `sharedErr` (digest §3).
- Produces:
  ```go
  // internal/vault
  // ClearHistory removes every snapshot and preserved conflict for key, leaving the current
  // vault and its metadata intact. A rotation calls it because the retired key is the only
  // thing that could open them.
  func (s *Store) ClearHistory(key string) error
  // internal/api
  const sharedEpochHeader = "X-Shared-Key-Epoch"
  func sharedEpoch(r *http.Request) (int, bool)   // parses the header; false when absent or unparseable
  ```

- [ ] **Step 1: Write the failing store test**

Append to `internal/vault/vault_test.go`:

```go
func TestClearHistoryRemovesSnapshotsAndConflicts(t *testing.T) {
	store, err := NewStore(t.TempDir(), 90)
	if err != nil {
		t.Fatal(err)
	}
	key := "shared/sv_abcdefghijklmnopqrstuv"
	meta, err := store.SaveVault(key, 0, []byte("one"), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveVault(key, meta.Version, []byte("two"), "", "", ""); err != nil {
		t.Fatal(err)
	}
	// A rejected upload leaves a conflict behind.
	if _, err := store.SaveVault(key, 1, []byte("stale"), "", "", ""); err == nil {
		t.Fatal("expected a conflict")
	}
	hist, err := store.ListHistory(key)
	if err != nil {
		t.Fatal(err)
	}
	confs, err := store.ListConflicts(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) == 0 || len(confs) == 0 {
		t.Fatalf("fixture: %d snapshots, %d conflicts", len(hist), len(confs))
	}
	if err := store.ClearHistory(key); err != nil {
		t.Fatal(err)
	}
	if hist, err = store.ListHistory(key); err != nil || len(hist) != 0 {
		t.Fatalf("history after clear: %d %v", len(hist), err)
	}
	if confs, err = store.ListConflicts(key); err != nil || len(confs) != 0 {
		t.Fatalf("conflicts after clear: %d %v", len(confs), err)
	}
	// The current vault is untouched.
	data, _, err := store.OpenVault(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "two" {
		t.Fatalf("current vault = %q", data)
	}
	// Idempotent, and a key that never existed is not an error.
	if err := store.ClearHistory(key); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearHistory("shared/sv_zzzzzzzzzzzzzzzzzzzzzz"); err != nil {
		t.Fatal(err)
	}
	// A retired key is refused, like every other writer.
	if err := store.MoveOut(key, filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearHistory(key); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired = %v", err)
	}
}
```

Check `OpenVault`'s real name and return shape in the digest (§2) and match it; if it returns `([]byte, Metadata, error)` adapt the assertion.

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/vault/ -run TestClearHistory`
Expected: FAIL, `store.ClearHistory undefined`.

- [ ] **Step 3: Implement `ClearHistory`**

```go
// ClearHistory removes every snapshot and preserved conflict for key, leaving the current
// vault and its metadata intact. A rotation calls it because after the rotation the retired
// key exists nowhere legitimate: those files are unreadable to every remaining member and
// readable only by whoever kept the old key, which is the member the rotation locked out.
func (s *Store) ClearHistory(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired[key] {
		return ErrRetired
	}
	for _, dir := range []string{s.historyDir(key), s.conflictsDir(key)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".kdbx") {
				continue
			}
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Write the failing epoch-gate test**

Append to `internal/api/shared_test.go`:

```go
func TestSharedWritesCarryTheKeyEpoch(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	// Version 0 → first upload establishes the vault.
	if rec := uploadShared(srv, aliceC, id, `"0"`, "one", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatalf("first upload = %d %s", rec.Code, rec.Body.String())
	}
	// A missing header is refused (Review Focus 3).
	rec := uploadShared(srv, aliceC, id, `"1"`, "two", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "was rotated") {
		t.Fatalf("missing epoch = %d %s", rec.Code, rec.Body.String())
	}
	// A previous epoch is refused.
	rec = uploadShared(srv, aliceC, id, `"1"`, "two", map[string]string{"X-Shared-Key-Epoch": "0"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale epoch = %d %s", rec.Code, rec.Body.String())
	}
	// Nothing was written by either refusal.
	got := do(t, srv, http.MethodGet, "/api/shared/"+id+"/metadata", aliceC, nil)
	if !strings.Contains(got.Body.String(), `"version":1`) {
		t.Fatalf("metadata = %s", got.Body.String())
	}
	// The conflict discard and the history restore carry it too.
	rec = do(t, srv, http.MethodDelete, "/api/shared/"+id+"/conflicts/nope", aliceC, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("discard without the epoch = %d", rec.Code)
	}
}
```

Read `uploadShared` in the digest (§7): it forwards `extra` headers, so passing `nil` sends none. If it currently forces a header, extend it rather than duplicating it.

- [ ] **Step 5: Run to confirm failure**

Run: `go test ./internal/api/ -run TestSharedWritesCarryTheKeyEpoch`
Expected: FAIL, the uploads succeed because no epoch is checked.

- [ ] **Step 6: Implement the gate**

In `internal/api/shared_handlers.go`:

```go
const sharedEpochHeader = "X-Shared-Key-Epoch"

// sharedEpoch reads the epoch a write claims to be encrypted under. It is required: a client
// that does not send it cannot prove it holds the current key, and a member re-sealed by a
// rotation whose tab still holds the retired key would otherwise write ciphertext nobody can
// open.
func sharedEpoch(r *http.Request) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(sharedEpochHeader)))
	if err != nil {
		return 0, false
	}
	return n, true
}
```

In `withSharedWrite`, after the role and state checks and before `sharedCSRF`:

```go
epoch, ok := sharedEpoch(r)
if !ok || epoch != c.vault.KeyEpoch {
	http.Error(w, "the shared vault key was rotated; reload the vault", http.StatusConflict)
	return
}
```

Update every `s.shared.Remove(...)` call in `internal/api` to pass `time.Now()`. In `internal/api/vault_handlers.go` delete the `t.shared && r.Header.Get("X-Vault-Key-Rotated") == "1"` 400 branch and, in its place, keep refusing the header on a shared target by ignoring it (`rotated = rotated && !t.shared`), so a shared upload can never take the personal rotation path even though shared rotation now exists on its own route.

- [ ] **Step 7: Gate and commit**

Run: `gofmt -l internal; go vet ./... && go test -race ./internal/vault/ ./internal/api/ ./internal/shared/`
Expected: PASS. Existing personal-vault tests unchanged; existing shared tests that upload now need the header — add it to the shared helper so the change is one line, not many.

```bash
git add internal/vault internal/api
git commit -m "vault: ClearHistory; api: shared writes prove their key epoch

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: the rotate route

**Files:**
- Create: `internal/api/shared_rotate.go`
- Modify: `internal/api/server.go` (one route line)
- Modify: `internal/api/shared_test.go` (append)

**Interfaces:**
- Consumes: `shared.Store.Rotate` and `shared.SealedFor` (Task 1); `vault.Store.ClearHistory` (Task 2); `sharedMember`, `sharedCSRF`, `requireFresh`, `sharedErr`, `sharedEpoch` (digest §3); `ifMatchVersion` (digest §5).
- Produces:
  ```go
  func (s *Server) handleSharedRotate(w http.ResponseWriter, r *http.Request, u users.User)
  // route: mux.HandleFunc("POST /api/shared/{id}/rotate", s.withAuth(s.handleSharedRotate))
  // request: multipart/form-data, parts in order: "kdbx" (bytes), "keys" (JSON)
  // response: 200 {"ok":true,"metadata":<vault.Metadata>,"keyEpoch":N+1,"leftBehind":["u-4"]}
  ```

- [ ] **Step 1: Write the failing tests**

Append to `internal/api/shared_test.go`:

```go
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

func TestSharedRotate(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	carol, carolC := signedInUser(t, srv, "carol", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	carolFP := publishKey(t, srv, carol, 3)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	invite := func(u users.User, fp, role string) {
		if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC,
			map[string]any{"userId": u.ID, "role": role, "sealedKey": sealedKeyFor(1), "keyFingerprint": fp}); rec.Code != http.StatusOK {
			t.Fatalf("invite %s = %d %s", u.Username, rec.Code, rec.Body.String())
		}
	}
	invite(bob, bobFP, "editor")
	invite(carol, carolFP, "reader")
	for _, c := range []*http.Cookie{bobC, carolC} {
		if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", c, nil); rec.Code != http.StatusOK {
			t.Fatalf("accept = %d %s", rec.Code, rec.Body.String())
		}
	}
	// Establish contents, a snapshot and a conflict.
	if rec := uploadShared(srv, aliceC, id, `"0"`, "one", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body.String())
	}
	if rec := uploadShared(srv, aliceC, id, `"1"`, "two", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := uploadShared(srv, aliceC, id, `"1"`, "stale", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusConflict {
		t.Fatalf("expected a preserved conflict, got %d", rec.Code)
	}
	if hist := do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil); !strings.Contains(hist.Body.String(), "_v1") {
		t.Fatalf("fixture history = %s", hist.Body.String())
	}
	// Carol leaves; the vault is flagged.
	if rec := do(t, srv, http.MethodDelete, "/api/shared/"+id+"/members/"+carol.ID, carolC, nil); rec.Code != http.StatusOK {
		t.Fatalf("leave = %d %s", rec.Code, rec.Body.String())
	}
	if got := do(t, srv, http.MethodGet, "/api/shared", aliceC, nil); !strings.Contains(got.Body.String(), `"rotationPending"`) {
		t.Fatalf("list should carry the flag: %s", got.Body.String())
	}
	// Rotate, sealing to alice and bob only.
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, shared.SealedKeyBytes))
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{
		{"userId": alice.ID, "sealedKey": newKey, "keyFingerprint": aliceFP},
		{"userId": bob.ID, "sealedKey": newKey, "keyFingerprint": bobFP},
	})
	rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body,
		map[string]string{"Content-Type": ct, "If-Match": `"2"`})
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"keyEpoch":2`) {
		t.Fatalf("response = %s", rec.Body.String())
	}
	// History and conflicts are gone; the contents are the new ciphertext.
	if hist := do(t, srv, http.MethodGet, "/api/shared/"+id+"/history", aliceC, nil); strings.Contains(hist.Body.String(), "_v1") {
		t.Fatalf("history survived: %s", hist.Body.String())
	}
	if confs := do(t, srv, http.MethodGet, "/api/shared/"+id+"/conflicts", aliceC, nil); strings.Contains(confs.Body.String(), "exp1") {
		t.Fatalf("conflicts survived: %s", confs.Body.String())
	}
	// The flag is cleared and bob's sealed key is the new one.
	list := do(t, srv, http.MethodGet, "/api/shared", bobC, nil)
	if strings.Contains(list.Body.String(), `"rotationPending"`) || !strings.Contains(list.Body.String(), newKey) {
		t.Fatalf("bob's list = %s", list.Body.String())
	}
	// A write at the old epoch is now refused; at the new one it is accepted.
	if rec := uploadShared(srv, bobC, id, `"3"`, "bob", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusConflict {
		t.Fatalf("old epoch = %d", rec.Code)
	}
	if rec := uploadShared(srv, bobC, id, `"3"`, "bob", map[string]string{"X-Shared-Key-Epoch": "2"}); rec.Code != http.StatusOK {
		t.Fatalf("new epoch = %d %s", rec.Code, rec.Body.String())
	}
	assertAudited(t, srv, "shared.key_rotated")
}

func TestSharedRotateRefusals(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Routes()
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC,
		map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": sealedKeyFor(1), "keyFingerprint": bobFP}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := uploadShared(srv, aliceC, id, `"0"`, "one", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, shared.SealedKeyBytes))
	good := []map[string]string{{"userId": alice.ID, "sealedKey": newKey, "keyFingerprint": aliceFP}}
	body, ct := rotateBody(t, "rekeyed", 1, good)
	hdr := func(extra map[string]string) map[string]string {
		m := map[string]string{"Content-Type": ct, "If-Match": `"1"`}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// An editor cannot rotate.
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", bobC, "", false, body, hdr(nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("editor = %d %s", rec.Code, rec.Body.String())
	}
	// A non-member sees 404.
	_, malloryC := signedInUser(t, srv, "mallory", users.RoleUser)
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", malloryC, "", false, body, hdr(nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("stranger = %d", rec.Code)
	}
	// No CSRF token.
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", true, body, hdr(nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("no csrf = %d", rec.Code)
	}
	// A stale session.
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", staleSession(t, srv, alice), "", false, body, hdr(nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("stale session = %d", rec.Code)
	}
	// The wrong epoch, and the wrong version.
	stale, ct2 := rotateBody(t, "rekeyed", 0, good)
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, stale,
		map[string]string{"Content-Type": ct2, "If-Match": `"1"`}); rec.Code != http.StatusConflict {
		t.Fatalf("wrong epoch = %d %s", rec.Code, rec.Body.String())
	}
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body, hdr(map[string]string{"If-Match": `"99"`})); rec.Code != http.StatusConflict {
		t.Fatalf("wrong version = %d", rec.Code)
	}
	// A truncated body changes nothing (Review Focus 1).
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body[:len(body)/2], hdr(nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("truncated = %d %s", rec.Code, rec.Body.String())
	}
	// A missing part.
	var one bytes.Buffer
	mw := multipart.NewWriter(&one)
	p, _ := mw.CreateFormFile("kdbx", "v.kdbx")
	_, _ = p.Write([]byte("x"))
	_ = mw.Close()
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, one.String(),
		map[string]string{"Content-Type": mw.FormDataContentType(), "If-Match": `"1"`}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing keys part = %d", rec.Code)
	}
	// Every refusal left the vault at epoch 1 with its original contents and no lost history.
	got := do(t, srv, http.MethodGet, "/api/shared", aliceC, nil)
	if !strings.Contains(got.Body.String(), `"keyEpoch":1`) {
		t.Fatalf("epoch moved: %s", got.Body.String())
	}
	kdbx := do(t, srv, http.MethodGet, "/api/shared/"+id+"/kdbx", aliceC, nil)
	if kdbx.Body.String() != "one" {
		t.Fatalf("contents changed: %q", kdbx.Body.String())
	}
}
```

Add `mime/multipart` and `encoding/json` to the test imports if absent, and import `internal/shared` for `SealedKeyBytes`.

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/api/ -run TestSharedRotate`
Expected: FAIL, 404 from the mux (no route).

- [ ] **Step 3: Implement**

`internal/api/shared_rotate.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Busnes-app/kyvault-server/internal/shared"
	"github.com/Busnes-app/kyvault-server/internal/users"
	"github.com/Busnes-app/kyvault-server/internal/vault"
)

// rotateKeysLimit bounds the JSON part: 100 members at ~1.6 KiB of base64 each, with room
// for the field names.
const rotateKeysLimit = 1 << 20

type rotateKeys struct {
	Epoch  int                `json:"epoch"`
	Sealed []shared.SealedFor `json:"sealed"`
}

// POST /api/shared/{id}/rotate. The re-encrypted vault and one sealed copy of the new key
// per remaining member commit together: split them and the vault's contents would be under a
// key its members do not hold. Active owners only, and a fresh sign-in, because this is the
// action that locks a removed member out and it destroys the vault's history.
func (s *Server) handleSharedRotate(w http.ResponseWriter, r *http.Request, u users.User) {
	c, ok := s.sharedMember(w, r, u)
	if !ok {
		return
	}
	if !c.activeOwner() {
		http.Error(w, "only an active owner can rotate the key", http.StatusForbidden)
		return
	}
	if !s.sharedCSRF(w, r) || !s.requireFresh(w, c.session) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20+rotateKeysLimit)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "rotate needs a multipart/form-data body", http.StatusBadRequest)
		return
	}
	var kdbx []byte
	var keys rotateKeys
	for _, want := range []string{"kdbx", "keys"} {
		part, err := mr.NextPart()
		if err != nil {
			http.Error(w, fmt.Sprintf("missing the %q part", want), http.StatusBadRequest)
			return
		}
		if part.FormName() != want {
			http.Error(w, fmt.Sprintf("expected the %q part, got %q", want, part.FormName()), http.StatusBadRequest)
			return
		}
		switch want {
		case "kdbx":
			if kdbx, err = io.ReadAll(part); err != nil {
				http.Error(w, "failed to read the vault part", http.StatusBadRequest)
				return
			}
		case "keys":
			if err := json.NewDecoder(io.LimitReader(part, rotateKeysLimit)).Decode(&keys); err != nil {
				http.Error(w, "invalid keys part: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		_ = part.Close()
	}
	if len(kdbx) == 0 {
		http.Error(w, "empty vault payload", http.StatusBadRequest)
		return
	}
	if len(keys.Sealed) == 0 {
		http.Error(w, "a rotation must seal the new key to at least the caller", http.StatusBadRequest)
		return
	}
	id := c.vault.ID
	var meta vault.Metadata
	var next shared.Vault
	// One critical section, lock order shared.mu then vault.mu, the same as Delete: the
	// membership write is last so a failed vault write leaves the old sealed keys in place.
	err = s.shared.WithWriter(id, u.ID, func() error {
		var writeErr error
		meta, writeErr = s.vault.SaveVault(shared.StoreKey(id), ifMatchVersion(r), kdbx, "", "", c.session.DeviceID)
		if writeErr != nil {
			return writeErr
		}
		if writeErr = s.vault.ClearHistory(shared.StoreKey(id)); writeErr != nil {
			return writeErr
		}
		next, writeErr = s.shared.Rotate(id, u.ID, keys.Epoch, keys.Sealed, time.Now())
		return writeErr
	})
	switch {
	case errors.Is(err, shared.ErrEpoch):
		http.Error(w, "the shared vault key was rotated; reload the vault", http.StatusConflict)
		return
	case errors.Is(err, shared.ErrShape):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		var confErr *vault.ConflictError
		if errors.As(err, &confErr) {
			writeJSON(w, http.StatusConflict, confErr)
			return
		}
		if sharedRefused(w, err) {
			return
		}
		sharedErr(w, err)
		return
	}
	left := []string{}
	for uid, m := range next.Members {
		if m.KeyEpoch != next.KeyEpoch {
			left = append(left, uid)
		}
	}
	s.record(r, "shared.key_rotated", u.ID, c.session.DeviceID, clientIP(r),
		fmt.Sprintf("%s: rotated to epoch %d, sealed to %d members, %d left behind", id, next.KeyEpoch, len(keys.Sealed), len(left)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metadata": meta, "keyEpoch": next.KeyEpoch, "leftBehind": left})
}
```

Two things to verify against the digest and fix if they differ: `sharedCtx` may expose the owner check as a method or a helper (`activeOwner()`), and `WithWriter`'s closure may not be the right vehicle if it re-checks write permission in a way an owner-only action does not need — if so, take `shared.mu` through whatever the package exposes for a locked multi-step write, keeping the `shared.mu` → `vault.mu` order. `ErrEpoch` must be checked before the generic branches because `Rotate` returns it wrapped.

The ordering above deliberately writes the ciphertext first and the membership record last: a crash between them leaves new contents with old sealed keys, which every member notices immediately as an unopenable vault and an owner fixes by rotating again. The reverse order would hand out keys for contents that do not exist.

- [ ] **Step 4: Register the route**

In `internal/api/server.go`, beside the other shared routes:

```go
mux.HandleFunc("POST /api/shared/{id}/rotate", s.withAuth(s.handleSharedRotate))
```

- [ ] **Step 5: Run to confirm they pass**

Run: `go test -race ./internal/api/ -run TestSharedRotate`
Expected: PASS.

- [ ] **Step 6: Add the concurrency test**

```go
func TestConcurrentRotationsLeaveOneEpoch(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	if rec := uploadShared(srv, aliceC, id, `"0"`, "one", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, shared.SealedKeyBytes))
	sealed := []map[string]string{{"userId": alice.ID, "sealedKey": newKey, "keyFingerprint": aliceFP}}
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, ct := rotateBody(t, "rekeyed", 1, sealed)
			codes[i] = rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body,
				map[string]string{"Content-Type": ct, "If-Match": `"1"`}).Code
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		if c == http.StatusOK {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("codes %v: exactly one rotation must win", codes)
	}
	if got := do(t, srv, http.MethodGet, "/api/shared", aliceC, nil); !strings.Contains(got.Body.String(), `"keyEpoch":2`) {
		t.Fatalf("epoch = %s", got.Body.String())
	}
}
```

Run: `go test -race ./internal/api/ -run TestConcurrentRotations` → PASS. `rotateBody` calls `t.Fatal` on error; if `-race` complains about `t.Fatal` off the test goroutine, build the body once before the loop and reuse the string.

- [ ] **Step 7: Gate and commit**

Run: `gofmt -l internal; go vet ./... && go test -race ./...`

```bash
git add internal/api
git commit -m "api: POST /api/shared/{id}/rotate re-keys a shared vault in one commit

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: the flag and the epoch on the wire

**Files:**
- Modify: `internal/api/shared_handlers.go` (`handleSharedList`, `handleSharedGet`, `handleAdminSharedList` row structs)
- Modify: `internal/api/shared_handlers.go` (self-reseal gains the epoch condition)
- Modify: `internal/api/shared_test.go` (append)
- Modify: `internal/shared/AGENTS.md`

**Interfaces:**
- Produces: `rotationPending` on the three list/detail payloads:
  ```json
  "rotationPending": {"since": "…", "userId": "u-2", "reason": "left"}
  ```
  omitted when absent. `GET /api/shared` and `GET /api/shared/{id}` expose it to members; `GET /api/admin/shared` exposes it to admins.

- [ ] **Step 1: Write the failing test**

```go
func TestSelfResealNeedsTheCurrentEpoch(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceC := signedInUser(t, srv, "alice", users.RoleUser)
	bob, bobC := signedInUser(t, srv, "bob", users.RoleUser)
	aliceFP := publishKey(t, srv, alice, 1)
	bobFP := publishKey(t, srv, bob, 2)
	id := createShared(t, srv, aliceC, "Finance", sealedKeyFor(1), aliceFP)
	if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/members", aliceC,
		map[string]any{"userId": bob.ID, "role": "editor", "sealedKey": sealedKeyFor(1), "keyFingerprint": bobFP}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := do(t, srv, http.MethodPost, "/api/shared/"+id+"/accept", bobC, nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := uploadShared(srv, aliceC, id, `"0"`, "one", map[string]string{"X-Shared-Key-Epoch": "1"}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	// Alice rotates without bob: he is left behind, stale at epoch 1.
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, shared.SealedKeyBytes))
	body, ct := rotateBody(t, "rekeyed", 1, []map[string]string{{"userId": alice.ID, "sealedKey": newKey, "keyFingerprint": aliceFP}})
	if rec := rawReq(srv, http.MethodPost, "/api/shared/"+id+"/rotate", aliceC, "", false, body,
		map[string]string{"Content-Type": ct, "If-Match": `"1"`}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	// Bob cannot self-reseal: he does not hold the epoch-2 key, so sealing his own row would
	// publish a copy of a key nobody can open.
	rec := do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, bobC,
		map[string]any{"sealedKey": sealedKeyFor(4), "keyFingerprint": bobFP})
	if rec.Code != http.StatusConflict {
		t.Fatalf("epoch-stale self-reseal = %d %s", rec.Code, rec.Body.String())
	}
	// An owner can still re-seal him.
	if rec := do(t, srv, http.MethodPut, "/api/shared/"+id+"/members/"+bob.ID, aliceC,
		map[string]any{"sealedKey": newKey, "keyFingerprint": bobFP}); rec.Code != http.StatusOK {
		t.Fatalf("owner reseal = %d %s", rec.Code, rec.Body.String())
	}
	// The flag reaches the list and the admin list.
	if got := do(t, srv, http.MethodGet, "/api/shared/"+id, aliceC, nil); strings.Contains(got.Body.String(), `"rotationPending"`) {
		t.Fatal("a rotated vault carries no flag")
	}
}
```

Also append, to whichever existing test covers a removal, an assertion that `GET /api/admin/shared` shows `rotationPending` for a flagged vault.

- [ ] **Step 2: Run to confirm failure**

Run: `go test ./internal/api/ -run TestSelfResealNeedsTheCurrentEpoch`
Expected: FAIL, bob's self-reseal is accepted.

- [ ] **Step 3: Implement**

Add `RotationPending *shared.Pending \`json:"rotationPending,omitempty"\`` to the three row structs and fill it from `v.RotationPending`.

In the self-reseal branch of `handleSharedMemberUpdate`, before applying the re-seal:

```go
if selfReseal && c.me.KeyEpoch != c.vault.KeyEpoch {
	http.Error(w, "the shared vault key was rotated; ask an owner to re-seal your copy", http.StatusConflict)
	return
}
```

- [ ] **Step 4: Run, then DOX**

Run: `go test -race ./internal/api/` → PASS.

Update `internal/shared/AGENTS.md`: the `rotationPending` field and the three reasons, that `SetRole`/`SetSuspended` never set it, `Rotate`'s contract (epoch check, re-seal, leave behind, suspended handling, clears the flag, ownerless refused), and the lock order note for the rotate route.

- [ ] **Step 5: Commit**

```bash
git add internal/api internal/shared
git commit -m "api: expose rotationPending; an epoch-stale row cannot self-reseal

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: client transport — the epoch on every shared write

**Files:**
- Modify: `frontend/src/lib/vaultSave.ts` (`uploadVault`, `VaultSaveQueue`)
- Modify: `frontend/src/lib/vaultSave.test.ts` (append)
- Modify: `frontend/src/lib/sharedVaults.ts` (`rotate` on `sharedApi`, `rotationPending` on the types)
- Modify: `frontend/src/lib/vaultSelection.ts` (`openShared` returns the epoch)
- Modify: `frontend/src/components/HistoryModal.tsx` (restore and discard send the header)
- Modify: `frontend/src/App.tsx` (thread the epoch into the queue)

**Interfaces:**
- Produces:
  ```ts
  // vaultSave.ts
  export async function uploadVault(binary: ArrayBuffer, version: number, passwordEnvelope?: string,
    recoveryEnvelope?: string, signal?: AbortSignal, keyRotated = false, userKeyHeader?: string,
    basePath = PERSONAL_BASE, keyEpoch?: number): Promise<number>;
  export class VaultSaveQueue {
    constructor(vault: KeePassVault | null, version: number, passwordEnvelope?: string,
                basePath = PERSONAL_BASE, keyEpoch?: number)
    setKeyEpoch(epoch: number): void   // a rotation moves the queue to the new epoch
  }
  // sharedVaults.ts
  export type Pending = { since: string; userId: string; reason: "removed" | "left" | "declined" };
  // SharedVaultSummary and SharedVaultDetail gain: rotationPending?: Pending
  // AdminSharedVault gains: rotationPending?: Pending
  export type RotateResult = { keyEpoch: number; leftBehind: string[]; metadata: { version: number } };
  // sharedApi gains:
  //   rotate: (id: string, kdbx: ArrayBuffer, epoch: number, version: number,
  //            sealed: { userId: string; sealedKey: string; keyFingerprint: string }[]) => Promise<RotateResult>
  // vaultSelection.ts: OpenedShared gains keyEpoch: number
  ```
  `keyEpoch` is only sent when `basePath !== PERSONAL_BASE`; a personal write never carries it.

- [ ] **Step 1: Write the failing tests**

Append to `frontend/src/lib/vaultSave.test.ts`, following the file's existing `t.mock.method(globalThis, "fetch", …)` stubbing:

```ts
test("a shared upload carries the key epoch and a personal one does not", async (t) => {
  const seen: { url: string; epoch: string | null }[] = [];
  t.mock.method(globalThis, "fetch", async (url: any, init: any) => {
    seen.push({ url: String(url), epoch: new Headers(init?.headers).get("X-Shared-Key-Epoch") });
    return new Response(JSON.stringify({ metadata: { version: 4 } }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await uploadVault(new ArrayBuffer(4), 3, undefined, undefined, undefined, false, undefined, "/api/shared/sv_abcdefghijklmnopqrstuv", 2);
  await uploadVault(new ArrayBuffer(4), 3);
  assert.equal(seen[0].epoch, "2");
  assert.equal(seen[1].epoch, null);
});

test("the queue sends the epoch it was built with, and the one a rotation moved it to", async (t) => {
  const epochs: (string | null)[] = [];
  t.mock.method(globalThis, "fetch", async (_url: any, init: any) => {
    epochs.push(new Headers(init?.headers).get("X-Shared-Key-Epoch"));
    return new Response(JSON.stringify({ metadata: { version: 9 } }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  const queue = new VaultSaveQueue(fakeVault(), 8, undefined, "/api/shared/sv_abcdefghijklmnopqrstuv", 1);
  await queue.save();
  queue.setKeyEpoch(2);
  await queue.save();
  assert.deepEqual(epochs, ["1", "2"]);
});
```

`fakeVault()` is the existing helper in that file; reuse whatever it is actually called.

- [ ] **Step 2: Run to confirm failure**

Run: `cd frontend && npx tsx --test src/lib/vaultSave.test.ts`
Expected: FAIL, no header is sent.

- [ ] **Step 3: Implement the transport**

`uploadVault` gains the trailing `keyEpoch?: number` and, when `basePath !== PERSONAL_BASE && keyEpoch !== undefined`, sets `headers["X-Shared-Key-Epoch"] = String(keyEpoch)`. `VaultSaveQueue` takes it as a fifth constructor argument, stores it, passes it on every `save()`, and exposes `setKeyEpoch`.

`sharedApi.rotate` builds the multipart body with `FormData` so the browser streams it:

```ts
rotate: async (id, kdbx, epoch, version, sealed): Promise<RotateResult> => {
  const form = new FormData();
  form.append("kdbx", new Blob([kdbx], { type: "application/octet-stream" }), "vault.kdbx");
  form.append("keys", JSON.stringify({ epoch, sealed }));
  return requestJSON<RotateResult>(`${sharedBase(id)}/rotate`, {
    method: "POST",
    headers: { "If-Match": `"${version}"` },   // no Content-Type: the browser sets the boundary
    body: form,
  });
},
```

The parts must be appended in this order, since the server reads them positionally. Do not set `Content-Type` by hand.

`openShared` returns `keyEpoch: row.keyEpoch` in `OpenedShared`; `App.tsx`'s `apply` passes it into the new `VaultSaveQueue`. `HistoryModal` takes a `keyEpoch?: number` prop alongside its `basePath` and sends the header on the restore POST and the conflict DELETE.

- [ ] **Step 4: Run, typecheck, commit**

Run: `cd frontend && npm test && npx tsc --noEmit` → PASS.

```bash
git add frontend/src
git commit -m "frontend: shared writes carry the key epoch; sharedApi.rotate

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `lib/sharedRotation.ts`

**Files:**
- Create: `frontend/src/lib/sharedRotation.ts`
- Create: `frontend/src/lib/sharedRotation.test.ts`

**Interfaces:**
- Consumes: `newSharedKey`, `sealSharedKey`, `openSharedKey` (`lib/sharedKey.ts`); `Member`, `SharedApi`, `RotateResult` (`lib/sharedVaults.ts`); `PinStatus`, `FlowDeps` (`lib/sharedFlows.ts`); `KeePassVault` (`lib/kdbx.ts`).
- Produces:
  ```ts
  export type KeyView = { key: PinStatus } | { problem: string };   // same shape SharedMembersDialog loads
  export type Seal = { userId: string; publicKey: Uint8Array; pin: PinStatus };
  export type LeftBehind = { userId: string; username: string; reason: string };
  export type RotationPlan = { seal: Seal[]; leftBehind: LeftBehind[] };
  export function planRotation(members: Member[], views: Record<string, KeyView>, me: { id: string; publicKey: Uint8Array; fingerprint: string }): RotationPlan;
  export type RotateDeps = {
    api: Pick<SharedApi, "rotate" | "list">;
    pinUnknown: (userId: string, publicKey: Uint8Array) => Promise<void>;
    reEncrypt: (key: Uint8Array) => Promise<ArrayBuffer>;   // exports the open vault under a new key
    seal?: typeof sealSharedKey;
    openKey?: typeof openSharedKey;
    seed: Uint8Array;
  };
  export type RotationOutcome = { key: Uint8Array; keyEpoch: number; leftBehind: LeftBehind[] };
  export async function rotateSharedVault(id: string, epoch: number, version: number,
    plan: RotationPlan, deps: RotateDeps): Promise<RotationOutcome>;
  export async function rotationLanded(id: string, expected: Uint8Array, deps: RotateDeps): Promise<{ keyEpoch: number } | null>;
  ```

`planRotation` seals to me unconditionally (my own key, no pin involved), seals to every member whose view is `{ key }` with state `pinned` or `unknown`, and leaves behind every member whose view is `{ key }` with state `changed` (reason `their key changed since you pinned it`) or `{ problem }` (reason = the problem text). `suspended` members are sealed to like anyone else if their view is usable: they cannot sign in, but re-sealing keeps their row current so a reactivation does not need an owner.

- [ ] **Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, fingerprint } from "./userKey";
import { newSharedKey, sealSharedKey, openSharedKey } from "./sharedKey";
import { planRotation, rotateSharedVault, rotationLanded, type KeyView, type RotateDeps } from "./sharedRotation";

const member = (userId: string, over: any = {}): any => ({
  userId, username: userId, role: "editor", state: "active", keyFingerprint: "FP",
  keyEpoch: 1, addedAt: "2026-09-27T00:00:00Z", ...over,
});
const view = (state: "pinned" | "unknown" | "changed", publicKey: Uint8Array): KeyView =>
  ({ key: { state, fingerprint: "FP", publicKey } as any });

test("planRotation seals to me, to matching and unpinned members, and names the rest", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const carol = await generateUserKey();
  const dave = await generateUserKey();
  const members = [member("me"), member("bob"), member("carol"), member("dave"), member("erin")];
  const views: Record<string, KeyView> = {
    bob: view("pinned", bob.publicKey),
    carol: view("unknown", carol.publicKey),
    dave: view("changed", dave.publicKey),
    erin: { problem: "Could not check this key" },
  };
  const plan = planRotation(members, views, { id: "me", publicKey: me.publicKey, fingerprint: await fingerprint(me.publicKey) });
  assert.deepEqual(plan.seal.map((s) => s.userId).sort(), ["bob", "carol", "me"]);
  assert.deepEqual(plan.leftBehind.map((l) => l.userId).sort(), ["dave", "erin"]);
  assert.match(plan.leftBehind.find((l) => l.userId === "dave")!.reason, /changed/i);
  assert.equal(plan.leftBehind.find((l) => l.userId === "erin")!.reason, "Could not check this key");
});

test("rotateSharedVault seals a fresh key to everyone in the plan and pins the unknown ones", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const pinned: string[] = [];
  let sent: any = null;
  const plan = planRotation([member("me"), member("bob")], { bob: view("unknown", bob.publicKey) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  const deps: RotateDeps = {
    api: {
      rotate: async (_id, _kdbx, epoch, version, sealed) => { sent = { epoch, version, sealed }; return { keyEpoch: 2, leftBehind: [], metadata: { version: 4 } }; },
      list: async () => [],
    },
    pinUnknown: async (userId) => { pinned.push(userId); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  };
  const out = await rotateSharedVault("sv_abcdefghijklmnopqrstuv", 1, 3, plan, deps);
  assert.equal(out.keyEpoch, 2);
  assert.deepEqual(pinned, ["bob"]);
  assert.deepEqual(sent.sealed.map((s: any) => s.userId).sort(), ["bob", "me"]);
  assert.equal(sent.epoch, 1);
  assert.equal(sent.version, 3);
  // Both sealed copies open to the same fresh key.
  const mine = await openSharedKey(me.seed, sent.sealed.find((s: any) => s.userId === "me").sealedKey);
  const his = await openSharedKey(bob.seed, sent.sealed.find((s: any) => s.userId === "bob").sealedKey);
  assert.deepEqual([...mine], [...his]);
  assert.deepEqual([...out.key], [...mine]);
});

test("a lost response is adopted when the published key is ours", async () => {
  const me = await generateUserKey();
  const key = newSharedKey();
  const sealedForMe = await sealSharedKey(me.publicKey, key);
  const deps: RotateDeps = {
    api: {
      rotate: async () => { throw new Error("network"); },
      list: async () => [{ id: "sv_abcdefghijklmnopqrstuv", keyEpoch: 2, myKey: { sealedKey: sealedForMe } } as any],
    },
    pinUnknown: async () => {},
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  };
  const landed = await rotationLanded("sv_abcdefghijklmnopqrstuv", key, deps);
  assert.deepEqual(landed, { keyEpoch: 2 });
  // A different key means it did not land.
  assert.equal(await rotationLanded("sv_abcdefghijklmnopqrstuv", newSharedKey(), deps), null);
  // A vault that is no longer in the list means it did not land.
  assert.equal(await rotationLanded("sv_zzzzzzzzzzzzzzzzzzzzzz", key, deps), null);
});
```

- [ ] **Step 2: Run to confirm failure** — `cd frontend && npx tsx --test src/lib/sharedRotation.test.ts` → module not found.

- [ ] **Step 3: Implement**

```ts
import { newSharedKey, sealSharedKey, openSharedKey } from "./sharedKey";
import type { Member, SharedApi, RotateResult } from "./sharedVaults";
import type { PinStatus } from "./sharedFlows";

export type KeyView = { key: PinStatus } | { problem: string };
export type Seal = { userId: string; publicKey: Uint8Array; pin: PinStatus };
export type LeftBehind = { userId: string; username: string; reason: string };
export type RotationPlan = { seal: Seal[]; leftBehind: LeftBehind[] };

const CHANGED = "their key changed since you pinned it";

// planRotation decides who gets a copy of the next key. A member whose published key no
// longer matches the owner's pin is left behind rather than blocking the rotation: this is
// the action that locks out someone who was removed, and an unrelated trust question must
// not hold it up. They stay stale until an owner verifies the new key and re-seals them.
export function planRotation(members: Member[], views: Record<string, KeyView>,
                             me: { id: string; publicKey: Uint8Array; fingerprint: string }): RotationPlan {
  const seal: Seal[] = [{ userId: me.id, publicKey: me.publicKey, pin: { state: "pinned", fingerprint: me.fingerprint, publicKey: me.publicKey } as PinStatus }];
  const leftBehind: LeftBehind[] = [];
  for (const m of members) {
    if (m.userId === me.id) continue;
    const v = views[m.userId];
    if (!v || "problem" in v) {
      leftBehind.push({ userId: m.userId, username: m.username, reason: v ? v.problem : "Could not check this key" });
      continue;
    }
    if (v.key.state === "changed") {
      leftBehind.push({ userId: m.userId, username: m.username, reason: CHANGED });
      continue;
    }
    seal.push({ userId: m.userId, publicKey: v.key.publicKey, pin: v.key });
  }
  return { seal, leftBehind };
}

export type RotateDeps = {
  api: Pick<SharedApi, "rotate" | "list">;
  pinUnknown: (userId: string, publicKey: Uint8Array) => Promise<void>;
  reEncrypt: (key: Uint8Array) => Promise<ArrayBuffer>;
  seal?: typeof sealSharedKey;
  openKey?: typeof openSharedKey;
  seed: Uint8Array;
};
export type RotationOutcome = { key: Uint8Array; keyEpoch: number; leftBehind: LeftBehind[] };

export async function rotateSharedVault(id: string, epoch: number, version: number,
                                        plan: RotationPlan, deps: RotateDeps): Promise<RotationOutcome> {
  const seal = deps.seal ?? sealSharedKey;
  const key = newSharedKey();
  const sealed: { userId: string; sealedKey: string; keyFingerprint: string }[] = [];
  for (const s of plan.seal) {
    if (s.pin.state === "unknown") await deps.pinUnknown(s.userId, s.publicKey);
    sealed.push({ userId: s.userId, sealedKey: await seal(s.publicKey, key), keyFingerprint: s.pin.fingerprint });
  }
  const kdbx = await deps.reEncrypt(key);
  let res: RotateResult;
  try {
    res = await deps.api.rotate(id, kdbx, epoch, version, sealed);
  } catch (err) {
    // A rotation whose response was lost still re-keyed the vault, and this tab holds the
    // only copy of the new key. Discarding it would leave every member locked out of a vault
    // only another rotation could recover, so a rejection is checked against the server.
    const landed = await rotationLanded(id, key, deps);
    if (!landed) throw err;
    res = { keyEpoch: landed.keyEpoch, leftBehind: plan.leftBehind.map((l) => l.userId), metadata: { version: 0 } };
  }
  return { key, keyEpoch: res.keyEpoch, leftBehind: plan.leftBehind };
}

export async function rotationLanded(id: string, expected: Uint8Array, deps: RotateDeps): Promise<{ keyEpoch: number } | null> {
  const open = deps.openKey ?? openSharedKey;
  try {
    const row = (await deps.api.list()).find((v) => v.id === id);
    if (!row) return null;
    const mine = await open(deps.seed, row.myKey.sealedKey);
    const same = mine.length === expected.length && mine.every((b, i) => b === expected[i]);
    return same ? { keyEpoch: row.keyEpoch } : null;
  } catch {
    return null;
  }
}
```

- [ ] **Step 4: Run, then commit**

Run: `cd frontend && npx tsx --test src/lib/sharedRotation.test.ts` → PASS.

```bash
git add frontend/src/lib/sharedRotation.ts frontend/src/lib/sharedRotation.test.ts
git commit -m "frontend: plan and perform a shared vault key rotation

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: the rotation in the UI

**Files:**
- Modify: `frontend/src/components/SharedMembersDialog.tsx` (the banner, the Rotate button, the result, the three copy fixes, Leave for a stale member)
- Modify: `frontend/src/components/VaultSwitcher.tsx` (the "Needs rotation" badge)
- Modify: `frontend/src/components/AdminShared.tsx` (show the flag)
- Modify: `frontend/src/App.tsx` (the rotate handler, the epoch 409 re-open)
- Modify: `frontend/src/lib/appSelection.ts` (`rotatedElsewhere`)
- Modify: `frontend/src/lib/appSelection.test.ts` (append)
- Modify: `frontend/src/lib/sharedFlows.ts` (self-reseal refuses an epoch-stale row client-side too)

**Interfaces:**
- Produces:
  ```ts
  // appSelection.ts
  export const rotatedElsewhere = (selected: Selected, state: SaveState): boolean =>
    selected.kind === "shared" && state.kind === "error" && state.status === 409 &&
    /was rotated/.test(state.message);
  ```
  A 409 that names a rotation re-opens the vault; every other 409 stays the existing conflict flow.

- [ ] **Step 1: Write the failing test**

Append to `frontend/src/lib/appSelection.test.ts`:

```ts
test("a rotation 409 re-opens the vault, an ordinary conflict does not", () => {
  const shared = { kind: "shared", id: "sv_abcdefghijklmnopqrstuv" } as const;
  const err = (message: string, status?: number) => ({ kind: "error", version: 3, message, status } as any);
  assert.equal(rotatedElsewhere(shared, err("the shared vault key was rotated; reload the vault", 409)), true);
  assert.equal(rotatedElsewhere(shared, err("conflict", 409)), false);
  assert.equal(rotatedElsewhere(shared, err("the shared vault key was rotated", 403)), false);
  assert.equal(rotatedElsewhere(personal, err("the shared vault key was rotated; reload the vault", 409)), false);
});
```

- [ ] **Step 2: Run to confirm failure** — import error.

- [ ] **Step 3: Implement the UI**

`SharedMembersDialog`: when `vault.rotationPending` and the caller is an active owner, render a banner above the member list:

> `<username> <left|was removed|declined the invitation> on <date>. Their copy of the key still opens anything this vault saved before a rotation. Rotating re-keys the vault for everyone who remains.`

with a `Rotate key` button. The button is also present without the flag (an owner may rotate whenever), labelled `Rotate key`. Clicking it confirms:

> `Rotate the key for “<name>”? Everyone who remains gets a new copy. This vault's version history and preserved conflicts are deleted: after the rotation nobody holds the key that opens them.`

then runs `planRotation` over the member views the dialog already loaded, calls `rotateSharedVault`, and on success reports `Rotated. <n> members have the new key.` plus, when `leftBehind` is non-empty, a list of names with their reason and the sentence `Verify their key and re-seal them from this dialog.` Failures render through `ErrorLine`, so the fresh-session 403 keeps its Sign in again link.

Rotation is refused with a title-attribute explanation unless: the caller is an active owner, `userKey.kind === "ready"`, the vault is the open selection, and there are no unsaved edits. It runs inside `queue.exclusive`, and `reEncrypt` is `(key) => vault.exportBinaryWith(key)` — check `lib/kdbx.ts` for the real way to re-credential an open database and export under a new key; if no such method exists, add `KeePassVault.exportUnder(key: Uint8Array): Promise<ArrayBuffer>` that sets the credentials, exports, and restores the previous credentials on failure, with a test in `kdbx.test.ts` proving the export opens under the new key and not the old.

On success `App.tsx` swaps the in-memory shared key (`sharedKeyRef`), calls `queue.setKeyEpoch(next)`, refreshes the list, and zeroes the old key.

`VaultSwitcher`: an owner sees `— Needs rotation` appended to a flagged vault's option label, alongside the existing `stateLabel`.

`AdminShared`: a `Rotation pending` badge in the same style as `Ownerless`, with the departing username and date in the row's detail line.

`App.tsx`: an effect on `[saveState, selected]` calling `rotatedElsewhere` re-opens the shared vault through the existing switch path instead of surfacing an error.

`sharedFlows.resealMember`: when the target is the caller and the row's `keyEpoch` is not the vault's, refuse before any request with `Your copy of this vault's key is from an older rotation. An owner has to re-seal it.`

The three carry-forward copy fixes, all in `SharedMembersDialog`: the pre-flight guard must not tell a member with `{problem: "No published key"}` that the key "has not been checked yet"; the own-row mismatch tooltip must not say "Re-pin it from Security → Known keys"; and Leave must render for a `stale` row.

- [ ] **Step 4: Gate and commit**

Run: `cd frontend && npm test && npm run build` → PASS.

```bash
git add frontend/src
git commit -m "frontend: rotate a shared vault key from the members dialog

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: mock, screenshots, docs, full gate

**Files:**
- Modify: `frontend/mock/api.ts` (the rotate route, `rotationPending`, the epoch check)
- Modify: `UI-VERIFICATION.md`, `docs/shared-members.png` (re-capture), new `docs/shared-rotate.png`
- Modify: `AGENTS.md` (the shared bullets), `docs/RESTORE.md` (one line)

- [ ] **Step 1: Mock**

The mock's shared store gains `keyEpoch` and `rotationPending`, sets the flag on member removal, leave and decline, refuses a write whose `X-Shared-Key-Epoch` is absent or stale with the same 409 body, and serves `POST /api/shared/{id}/rotate` by parsing the multipart body (Node's `busboy` is not a dependency — parse it with `request.formData()` if the dev server's Node version supports it on a raw `IncomingMessage`, otherwise read the boundary and split by hand; keep it under 40 lines) and applying the same transitions as the store. Seed a vault whose flag is already set so the banner can be photographed without performing a removal first.

- [ ] **Step 2: UI pass**

`cd frontend && npm run dev:mock`, then with the Playwright MCP tools capture: the Members dialog showing the rotation banner and the Rotate key button (`docs/shared-rotate.png`), and a re-capture of `docs/shared-members.png` now that the own-row label reads "Your key". Record both in `UI-VERIFICATION.md`, together with anything the mock cannot reach.

- [ ] **Step 3: Docs**

Root `AGENTS.md`: extend the shared bullets with the pending flag and its three reasons, the epoch header on every shared write, the rotate route and its multipart shape, that a rotation deletes the vault's history and conflicts, that an epoch-stale row cannot self-reseal, and that the client adopts a rotation whose response was lost. Remove the "Not built (3c/3d)" clause's 3c half. `docs/RESTORE.md`: a rotated vault's capsule carries no pre-rotation history.

- [ ] **Step 4: Full gate**

Run, in this order (the Go gate before any `npm ci` in `extension/`):

```
gofmt -l . | grep -v node_modules
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go build -o /tmp/kyvault-server ./cmd/server
cd frontend && npm test && npm run build && npm audit --audit-level=high
cd ../extension && npm test && npm run build && npm run lint
```

Paste the real output tail of each into the report. Fix only what this branch caused.

- [ ] **Step 5: Commit**

```bash
git add frontend/mock AGENTS.md UI-VERIFICATION.md docs
git commit -m "docs: shared vault rotation contract, mock route and UI verification

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```
