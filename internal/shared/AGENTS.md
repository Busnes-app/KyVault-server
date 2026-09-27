# Shared vault membership

## Purpose

Owns who may open a shared vault, in what role and state, and each member's copy of the
vault key sealed to their user key. Vault bytes live in `internal/vault` under
`StoreKey(id)` (`shared/<id>`). Nothing here can open a sealed key.

## Ownership

- `shared.go`: record shape and validation, store, lifecycle, write gate (`WithWriter`),
  key rotation (`Rotate`, `RotationPending`), hooks' store side (`SetSuspended`,
  `MarkStale`), deleted area and its reconcile, backup `Snapshot`.
- `shared_test.go`: every transition and invariant.
- HTTP gates, audit and hook call sites belong to `internal/api` (root `AGENTS.md`).

## Local Contracts

- Record: `data/shared/<id>.json` (`sv_` + 22 base64url chars), atomic tmp+rename, one
  mutex for the whole store. Unparseable JSON, an id mismatch, unknown roles or states, or
  a `suspendedFrom` that is set on a non-suspended row or not `invited|active|stale` on a
  suspended one fail the load with `ErrCorrupt` (`ErrShape` is caller input only). `Get`
  returns it; every bulk path (`List`, `ListFor`, the owned cap, both hooks) logs and skips
  the record so one bad file blocks no one else. The API answers it as a bare 500.
- Roles `owner|editor|reader`; states `invited|active|stale|suspended`. Name 1 to 64 runes,
  no control (`Cc`) or format (`Cf`, e.g. bidi overrides) characters.
- `sealedKey` is exactly 1168 bytes of standard base64 (HPKE enc + key + tag),
  shape-checked only. `keyFingerprint` records which user key it was sealed to; the caller
  checks it against the current published key. `sealedByFingerprint` is the sealer's
  fingerprint at seal time (`Create`, `Invite`, `Reseal` take it), shown as-is, never
  recomputed.
- Owner-only methods (`Rename`, `SetRole`, `Remove`, `Delete` take `actorID`; `Invite` and
  `Reseal` take it as `sealedBy`) re-check the actor inside the locked update: `""` is an admin, anyone else must hold an
  active owner row (`ErrForbidden`, `ErrNotMember`). `Remove` of one's own row skips that
  check (leave, decline) but not the last-owner rule; only an admin removes the last owner.
  `Reseal` with `sealedBy == userID` on a `stale` row skips it too, so a sole owner who
  replaced their user key can recover the vault.
- Every `Remove` (removal, leave, decline) stamps `rotationPending`
  (`since`, `userId`, `reason` of `removed|left|declined`; a self-removal of an `invited`
  row is `declined`, an admin removal is `removed`), because the departed row's copy of the
  vault key still opens the vault. A non-empty flag whose reason or `userId` is invalid
  fails the load with `ErrCorrupt`. Nothing else sets or clears it: a role change, a
  suspension and a `MarkStale` leave it alone.
- `Rotate(id, actorID, epoch, []SealedFor, writeVault)` is the only thing that retires that
  copy. Under one hold of the lock it authorizes the actor, refuses an ownerless vault
  (`ErrState`) and a stale `epoch` (`ErrEpoch`), validates every `SealedFor` (a current
  member, `ValidSealedKey`, a non-empty `keyFingerprint`), refuses a rotation that does not
  seal for the actor's own row or would leave no active owner (`ErrShape`, `ErrLastOwner`),
  then calls `writeVault` and returns its error untouched, and only then re-seals, bumps
  `keyEpoch`, marks every unnamed member `stale` at the old epoch and clears the flag. Any
  refusal writes nothing. A named row lands on `freshState` like a `Reseal`, so a stale or
  left-behind member who is re-sealed comes back. An admin actor (`""`) can never rotate:
  the actor must be one of the named members and `""` is never a member id.
- `Rotate` does **not** compare the supplied `keyFingerprint` to the row's: `MarkStale`
  leaves the retired fingerprint on the row, so a member who replaced their user key is
  re-sealed to a fingerprint the row has never held. It overwrites the row's value, exactly
  as `Reseal` does; checking it against the member's current published key is the route's
  job, since only the route can read published keys.
- Rotation commit order: the re-encrypted ciphertext is written inside `writeVault`, before
  the record commits. A crash between them leaves the live vault under the new key while
  the record still carries the old epoch and old sealed keys — the pre-rotation snapshot is
  still in history, so a member rolls back with the key they hold and the rotation is run
  again. Nothing may delete history inside `writeVault`. The closure runs under `shared.mu`
  and must never re-enter this store (`Get`, `WithWriter`, any method): it self-deadlocks.
- `WithWriter(id, userID, fn)` runs `fn` (the vault write) under `shared.mu` only while the
  row is an active owner or editor (`ErrNotMember`, `ErrForbidden`), so a removal or
  demotion cannot land between the route's check and the write.
- Invariants: `SetRole`, non-admin `Remove` and `Rotate` keep one active owner (`ErrLastOwner`);
  `MaxMembers` 100 at `Invite`; `MaxOwnedVaults` 20 at `Create` only; every row carries a
  sealed key. `Accept` requires `invited` and refuses an ownerless vault (`ErrState`).
- `SetSuspended` mirrors the account: suspending keeps the prior state in `suspendedFrom`;
  restoring returns to it, or to `freshState` (active if `AcceptedAt`, else invited) when
  none is recorded. Every transition but `Accept` (only an `invited` row, which is never
  suspended) and `SetSuspended` itself goes through `landOn(m, state)`: a suspended row
  keeps `suspended` and records the target in `suspendedFrom` instead.
  `MarkStale` flags active and invited rows sealed to another fingerprint; a suspended row
  gets `suspendedFrom: stale`. `Reseal` lands a row on `freshState`. Both hooks return the
  ids they touched even on error.
- `NewStore` takes a `VaultMover` (the API passes `vault.Store.MoveOut`; `nil` for the
  offline backup, where `Delete` fails). `Delete` writes `deleted/<id>/record.json` with
  `deletedAt`, removes the live record, then moves the vault directory; lock order is
  `shared.mu` then `vault.mu`, never the reverse. `NewStore` reconciles: every deleted
  record with no live record gets its vault directory moved (a no-op once moved), which
  finishes a Delete a crash interrupted. `PruneDeleted` removes entries older than the
  retention window (`RETENTION_DAYS`, default 90); the API runs it at start and on every
  audit flush.
- `Snapshot` returns every regular file under the store (records and deleted area) for the
  capsule and refuses symlinks.

## Verification

- `go test -race ./internal/shared/`
