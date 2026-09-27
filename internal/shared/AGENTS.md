# Shared vault membership

## Purpose

Owns who may open a shared vault, in what role and state, and each member's copy of the
vault key sealed to their user key. Vault bytes live in `internal/vault` under
`StoreKey(id)` (`shared/<id>`). Nothing here can open a sealed key.

## Ownership

- `shared.go`: record shape and validation, store, lifecycle, write gate (`WithWriter`),
  hooks' store side (`SetSuspended`, `MarkStale`), deleted area and its reconcile, backup
  `Snapshot`.
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
- `WithWriter(id, userID, fn)` runs `fn` (the vault write) under `shared.mu` only while the
  row is an active owner or editor (`ErrNotMember`, `ErrForbidden`), so a removal or
  demotion cannot land between the route's check and the write.
- Invariants: `SetRole` and non-admin `Remove` keep one active owner (`ErrLastOwner`);
  `MaxMembers` 100 at `Invite`; `MaxOwnedVaults` 20 at `Create` only; every row carries a
  sealed key. `Accept` requires `invited` and refuses an ownerless vault (`ErrState`).
- `SetSuspended` mirrors the account: suspending keeps the prior state in `suspendedFrom`;
  restoring returns to it, or to `freshState` (active if `AcceptedAt`, else invited) when
  none is recorded. `MarkStale` flags active and invited rows sealed to another
  fingerprint; a suspended row gets `suspendedFrom: stale`. `Reseal` returns a stale row to
  `freshState`; on a suspended row it sets `suspendedFrom` to `freshState`. Both hooks
  return the ids they touched even on error.
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
