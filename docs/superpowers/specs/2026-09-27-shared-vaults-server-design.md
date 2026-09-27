# Shared vaults, server and membership (3a) — design

Sub-project 3a of the reporting effort (order: 2 Watchtower ✓, 1 user keys ✓, 3a server
and membership, 3b web client, 3c leaving and key rotation, 3d extension and KyAuth,
4 admin encrypted report). This spec is server-only: storage, membership, API, hooks,
audit, backup. No UI.

## Goal

A shared vault is a second KDBX with its own random 32-byte key, owned by a group of
users. The server stores the KDBX and, per member, the vault key sealed with HPKE to that
member's user key (sub-project 1). The server enforces who may read and write; it never
holds the vault key and cannot read the contents. An admin can see and destroy a shared
vault but never read it.

## Decisions

- Roles `owner | editor | reader`; several owners allowed; at least one active owner always.
- Any active user may create a shared vault; an admin toggle restricts creation to admins.
- Joining is invite-then-accept: the owner seals the key at invite time, the invitee sees
  the owner's fingerprint and accepts or declines.
- The server sees the vault name, members, roles and states in plaintext; contents and
  keys are sealed.
- Admins see all shared vaults, may remove members and delete vaults (fresh session,
  audited), never gain a key.
- Storage reuses `internal/vault.Store` keyed by `shared/<vaultId>`, so history, conflicts,
  rollback, retention and the key-epoch logic are unchanged.

## Storage

### Vault data

`vault.Store` entries keyed `shared/<vaultId>` (`data/vaults/shared/<vaultId>/…`). The
`shared/` prefix cannot collide with a user ID. `Metadata.PasswordEnvelope`,
`RecoveryEnvelope`, `DeviceEnvelopes` and `UserKey` stay empty for shared vaults.

### Membership record

`internal/shared` package. One JSON file per vault, `data/shared/<vaultId>.json`, written
atomically (tmp + rename) under a per-store mutex.

```json
{
  "id": "sv_<22 base64url chars>", "name": "Finance team",
  "createdBy": "u-1", "createdAt": "2026-09-27T…", "keyEpoch": 1,
  "members": {
    "u-1": { "role": "owner",  "state": "active",  "sealedKey": "<base64>", "sealedBy": "u-1",
             "keyFingerprint": "A1B2 C3D4 E5F6 0718 293A", "keyEpoch": 1,
             "addedAt": "…", "acceptedAt": "…" },
    "u-2": { "role": "editor", "state": "invited", "sealedKey": "<base64>", "sealedBy": "u-1",
             "keyFingerprint": "…", "keyEpoch": 1, "addedAt": "…" }
  }
}
```

- `sealedKey`: HPKE single-shot output (`enc || ct`, 1120 + 32 + 16 = 1168 bytes) of the
  32-byte vault key sealed to the member's user public key with
  `info = "kyvault/shared-vault-key/1"`. Shape-checked (base64, 1168 bytes), never opened.
- `keyFingerprint`: fingerprint of the member's user key the blob was sealed to. Must equal
  the member's current published fingerprint at write time (400 otherwise).
- `keyEpoch` (vault): increments on shared-key rotation (3c). In 3a it is 1 forever. A
  member row with an older epoch is `stale`.
- States: `invited` (sealed, not yet accepted), `active`, `stale` (the member's user key
  changed since sealing, or the vault epoch moved; needs an owner re-seal), `suspended`
  (member's account inactive; restored on reactivation to the prior state).
- Name: 1–64 characters, no control runes (same rule as device names).
- Caps (constants): 100 members per vault, 20 vaults owned per user.

### Invariants (enforced in `internal/shared`)

- At least one `active` owner: the last one cannot be removed, demoted, leave, or be
  suspended by *this package* (deactivation of the last owner still suspends the row; the
  vault becomes ownerless, see Admin).
- Owner-only store methods take an `actorID` re-checked inside the locked update (`""` is
  an admin; removing one's own row skips the owner check). `Remove` has no
  `allowLastOwner` flag: only the admin actor may remove the last owner.
- A member row exists only with a `sealedKey` and `keyFingerprint`.
- Roles and states are closed enums; unknown values are rejected on read and write.

### Admin setting

`CONFIG_DIR/shared.json`: `{ "createRestrictedToAdmins": false }`. Read on each create.
`GET/PUT /api/admin/shared/settings` (`withFreshAdmin` for PUT).

### Deleted vaults

Delete moves `data/vaults/shared/<vaultId>/` and `data/shared/<vaultId>.json` to
`data/shared/deleted/<vaultId>/` with a `deletedAt` stamp. The retention pass removes
entries older than the store's retention window (default 90 days). Nothing serves a
deleted vault; recovery is a server-host operation (documented in `docs/RESTORE.md`).

## API

All routes `withAuth` (session or device token) unless noted. Handlers resolve the caller's
member row first; a non-member (or unknown vault) is 404 on every route, so existence is
not leaked. Bodies are JSON, ≤ 64 KiB.

### Vault lifecycle

- `POST /api/shared` `{name, sealedKey, keyFingerprint}` → 201 `{id}`. Caller becomes the
  active owner with the given self-sealed key. 403 when `createRestrictedToAdmins` and the
  caller is not admin; 409 at the owned-vault cap; 404 if the caller has no published user
  key; 400 on fingerprint mismatch. The KDBX follows through `POST /api/shared/{id}/upload`
  at version 0 (`If-Match: "0"`).
- `GET /api/shared` → `[{id, name, role, state, keyEpoch, myKey: {sealedKey, keyFingerprint,
  keyEpoch, sealedBy, sealedByFingerprint}, invitedBy?: {userId, username, fingerprint}}]`
  for every vault the caller has a row in, including `invited`. Only the caller's own
  sealed key is ever returned.
- `GET /api/shared/{id}` → `{id, name, createdBy, createdAt, keyEpoch, members: [{userId,
  username, role, state, keyFingerprint, keyEpoch, addedAt, acceptedAt?}]}`. Members only;
  an `invited` row gets 404 and sees only its `GET /api/shared` entry. No sealed keys.
- `PATCH /api/shared/{id}` `{name}`: active owners.
- `DELETE /api/shared/{id}`: active owners, fresh session (`freshSessionWindow`).

### Membership

- `POST /api/shared/{id}/members` `{userId, role, sealedKey, keyFingerprint}`: active
  owners. 409 already a member; 404 target has no published key or is inactive; 400 role
  invalid or fingerprint ≠ target's current fingerprint; 409 member cap. Row is `invited`.
- `PUT /api/shared/{id}/members/{userId}` `{role?, sealedKey?, keyFingerprint?}`: active
  owners. Role change (last-owner rule); re-seal (`stale` → `active`, or `invited` stays
  `invited`) with the fingerprint check; `sealedKey` and `keyFingerprint` come together.
- `DELETE /api/shared/{id}/members/{userId}`: active owners remove anyone; any member
  removes themselves (leave). Last-owner rule. 3a deletes the row only; 3c adds the
  rotation that must follow a removal.
- `POST /api/shared/{id}/accept`, `POST /api/shared/{id}/decline`: the `invited` member
  only. Accept → `active` + `acceptedAt`; decline → row deleted.

### Vault data

`GET /api/shared/{id}/metadata`, `GET …/kdbx`, `POST …/upload`, `GET …/history`,
`GET …/history/{hid}`, `POST …/history/{hid}/restore`, `GET …/conflicts`,
`GET …/conflicts/{cid}`, `DELETE …/conflicts/{cid}`. The existing personal handlers are
refactored to take a store key and an acting user (for audit and the conflict device ID);
the personal routes call them with the user's ID, the shared routes with `shared/<id>`.

- Read routes: `active` and `stale` members. `invited` may read nothing under
  `/api/shared/{id}/…` (only `GET /api/shared` shows the invitation). `suspended` is moot
  because an inactive account cannot authenticate; the check exists for the record.
- Write routes (`upload`, `restore`, conflict `DELETE`): `active` owners and editors only.
  Readers, `stale`, `invited`, `suspended` → 403.
- `X-Vault-Key-Rotated` on a shared upload → 400 in 3a.
- Envelope headers and JSON envelope fields are ignored on shared uploads.
- The upload response, audit row and conflict filename record the session's `DeviceID`
  exactly as personal saves do.

### Admin

- `GET /api/admin/shared` (`withAdmin`): every vault: id, name, createdBy, createdAt,
  keyEpoch, members (userId, username, role, state). No sealed keys.
- `DELETE /api/admin/shared/{id}` (`withFreshAdmin`): delete, same as owner delete.
- `DELETE /api/admin/shared/{id}/members/{userId}` (`withFreshAdmin`): remove any member,
  last owner included. An ownerless vault: no one can be added, existing active editors and
  readers keep working, only an admin can delete it. `GET /api/admin/shared` flags
  `ownerless: true`.
- `GET/PUT /api/admin/shared/settings` as above.

### Hooks

- Account deactivation (admin route, SCIM, sync webhook) → every membership of that user
  becomes `suspended` (previous state kept in `suspendedFrom`); reactivation restores it.
- User key replacement (`user_key.replaced`) → every membership whose `keyFingerprint`
  differs from the new fingerprint becomes `stale`.
- Both hooks run inside the handlers that perform the change, after the users write
  succeeds, and are best-effort with an audit row on failure (`shared.hook_failed`).

### Audit

Detail = vault id (+ target user id / role where relevant), never a sealed key:
`shared.created`, `shared.renamed`, `shared.deleted`, `shared.member_invited`,
`shared.member_accepted`, `shared.member_declined`, `shared.member_role_changed`,
`shared.member_resealed`, `shared.member_removed`, `shared.member_left`,
`shared.member_stale`, `shared.member_suspended`, `shared.member_restored`,
`shared.saved`, `shared.conflict_rejected`, `shared.downloaded`, `shared.rolled_back`,
`shared.snapshot_downloaded`, `shared.conflict_downloaded`, `shared.conflict_discarded`,
`admin.shared_deleted`, `admin.shared_member_removed`, `admin.shared_settings_updated`,
`shared.hook_failed`.

## Backup and restore

`data/shared/` (membership records and the deleted area) joins the capsule collection
roots. Shared KDBX data is already under `data/vaults/`. The drill walk and
`docs/RESTORE.md` name the new directory. The `shared.json` config file joins the config
collection.

## Security properties

- No shared vault key ever exists server-side: only HPKE blobs sealed to members' user
  keys, and the server has no user private key.
- Authorisation (roles, states, ownership, caps) is server-enforced; confidentiality is
  client-enforced by sealing. An admin can destroy but not read.
- Non-membership is indistinguishable from non-existence (404).
- Fingerprint binding at invite/re-seal time: the server refuses a blob sealed to a key
  that is not the target's current key, so the owner's pin is what the seal is bound to.
- No outbound traffic; CSP unchanged.

## Testing

- `internal/shared` unit tests: every lifecycle transition; last-owner rule on remove,
  demote, leave; caps; suspend/restore; stale on key change; name validation; enum
  rejection; delete → deleted area → retention prune; atomic write survives a crash
  between tmp and rename (tmp left behind is ignored on load).
- `internal/api/shared_test.go` over real routes: 404 for non-members on every route;
  reader 403 on writes and 200 on reads; `invited` sees only the list entry; `stale` and
  `suspended` cannot write; other members' sealed keys never appear in any body (assert
  on the raw response); fingerprint mismatch 400; `X-Vault-Key-Rotated` 400;
  `createRestrictedToAdmins` 403 and admin bypass; owner delete needs a fresh session;
  admin routes need admin + fresh session; ownerless vault deletable, not joinable; the
  deactivation and key-replacement hooks; every action's audit row present and free of
  sealed keys; device token can read and (as editor) write a shared vault.
- Refactor gate: every existing personal-vault test stays green unchanged.
- Backup: a capsule built after creating a shared vault contains its record and KDBX;
  restore reproduces both.

## Docs

- `internal/shared/AGENTS.md`: record format, states, invariants, hooks, caps.
- Root `AGENTS.md`: routes, store-key convention, admin setting, Child DOX Index entry.
- `docs/RESTORE.md`: `data/shared/` and the deleted area.

## Out of scope

Any UI (3b); shared key rotation and removed-member cleanup (3c); extension and KyAuth
(3d); request-to-join; per-vault quotas beyond the two caps.
