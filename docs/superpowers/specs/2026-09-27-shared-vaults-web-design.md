# Shared vaults, web client (3b) — design

Sub-project 3b of the reporting effort (2 Watchtower ✓, 1 user keys ✓, 3a server ✓ PR #77,
3b web client, 3c leaving and key rotation, 3d extension and KyAuth, 4 admin encrypted
report). This spec covers the React client for the 3a API plus one small server route.
Server contract: `docs/superpowers/specs/2026-09-27-shared-vaults-server-design.md` and
`internal/shared/AGENTS.md`.

## Goal

A member can create a shared vault, invite others, accept an invitation, and open, edit and
manage a shared vault from the web app, with the same editor, history, conflicts and
Watchtower the personal vault has. An admin can see and destroy shared vaults from the
Admin tab. No key ever leaves the browser unsealed.

## Decisions

- **One vault open at a time** (vault switcher). Personal or one shared vault; switching
  swaps KDBX, key and save queue. No merged tree, no cross-vault search.
- **Trust on accept is TOFU with one click.** The dialog shows the inviter's fingerprint
  with pin status; unpinned or changed fingerprints warn, Accept pins and proceeds. HPKE
  runs in base mode (X-Wing is a KEM), so the sealed blob proves it was sealed *to* the
  invitee, not *by* the inviter. The UI says so: "KyVault trusts the server for who is in a
  vault, never for its contents." Per-user signing keys are out of scope.
- **Invite by exact username** through a new `GET /api/users/lookup` route; no directory
  listing for non-admins.
- **Admin UI included**: Admin → Shared vaults.
- A shared vault is reachable only after the personal vault is unlocked in this tab: the
  user key seed is wrapped under the personal vault key. Lock locks everything.

## Client state

`App.tsx` adds `selected: { kind: "personal" } | { kind: "shared"; id: string }`. The
existing `vault`, `vaultKey`, `saveQueue`, `meta`, draft and checkpoint state describe the
selected vault. While a shared vault is selected the personal vault key is kept as
`personalKey` (seed unwrap, pins) and the personal `KeePassVault` stays in memory for pin
reads/writes; its save queue is closed while not selected and pin writes on it enqueue a
personal save when it is next selected or, simpler, pin writes are applied to the personal
vault and uploaded through a short-lived personal queue immediately. Decision: pins are
written and uploaded immediately through a dedicated `pinQueue` on the personal vault so a
pin never waits on a switch.

`lib/sharedVaults.ts`: API client for `/api/shared*` (list, get, create, rename, delete,
invite, updateMember, removeMember, accept, decline, kdbx, upload, metadata) and the
`SharedVaultSummary`/`Member` types mirroring the 3a JSON. `useSharedVaults()` loads
`GET /api/shared` after unlock, refreshes after every membership action and every 60 s
while the tab is visible, and exposes `{ vaults, refresh, error }`.

`lib/sharedKey.ts`: `sealSharedKey(publicKey, key)` / `openSharedKey(seed, blob)` with
`info = "kyvault/shared-vault-key/1"`, 32-byte key, 1168-byte blob (shape-checked before
send), plus `newSharedKey()`.

### Switching

The switcher is a select above the folder pane on the Vault tab: "My vault" then each
shared vault with a badge: `invited` (Accept / Decline), `stale` ("Key changed"), `reader`
("read-only"), `suspended` never shows (the account cannot sign in). Choosing one:

1. `canDiscardVault` confirm if edits are unsaved (same dialog as lock).
2. Close the current save queue.
3. Shared: `openSharedKey(seed, myKey.sealedKey)`; a failure shows "Your copy of the key
   cannot be opened; ask an owner to re-seal" and leaves the personal vault selected.
   `GET /api/shared/{id}/metadata` and `/kdbx`; open with the hex-key credential like the
   personal vault (`KeePassVault.open`); a version-0 vault (create upload failed earlier)
   is created empty and uploaded with `If-Match: "0"` on open.
4. New `VaultSaveQueue` with `uploadVault` pointed at `POST /api/shared/{id}/upload`
   (`X-CSRF-Token` already sent by the shared request helper; no envelope headers).
5. `readOnly` prop on `VaultPage` for readers: hides New, Apply, Delete, Move, Import,
   folder create/rename/delete, attachments add/remove, history restore; Copy, reveal,
   TOTP, search and export stay.

Routes: `#/vault[/entry]`, `#/shared/<id>[/entry]`, `#/admin/shared`. `parseRoute` accepts
`shared` ids matching `^sv_[A-Za-z0-9_-]{22}$`; unknown falls back to `#/vault`. Reload
restores the selection after unlock; a shared id the user is not a member of falls back to
personal with a notice.

Lock, auto-lock, logout, Forget: as today, plus zero the shared key and reset selection.
Locked drafts: key and AAD gain the vault scope (`personal` or `sv_…`) so a checkpoint from
one vault cannot restore into another; `lockedDraft.ts` `draftKey(userId, scope, id)`.
Device-key unlock, paper code, master password change and vault key rotation remain
personal-only and are hidden while a shared vault is selected. Watchtower, history,
conflicts and rollback operate on the selected vault unchanged; Watchtower's HIBP
auto-check preference stays per account.

## Create

"New shared vault…" in the switcher → name prompt (1–64 chars, validated client-side with
the device-name rule) → `newSharedKey()` → `sealSharedKey(ownPublicKey, key)` →
`POST /api/shared {name, sealedKey, keyFingerprint: ownFingerprint}` → build an empty KDBX
under the key (same as the version-0 personal create) → `POST /api/shared/{id}/upload` with
`If-Match: "0"` → refresh list → select it. If the upload fails the vault stays listed at
version 0 and the next open performs the empty upload. 403 (restricted to admins), 409
(owned cap) and 404 (no published key: user key state not `ready`) show the server text.
Create is disabled while `userKey.kind !== "ready"`.

## Invite and re-seal

Members dialog → Invite: username field → `GET /api/users/lookup?username=` → 404 shows
"No active user with a published key has that name" → otherwise `lookupKey(personalVault,
userId)`:

- `pinned-match`: fingerprint shown green.
- `unpinned`: fingerprint shown with "Not verified. Compare it with <name> out of band."
  Invite pins it (TOFU, existing wording).
- `pin-mismatch`: fingerprint shown red, Invite disabled: "This user's key changed since you
  pinned it. Re-pin it from Security → Known keys first." (Security gains a small "Known
  keys" list with Re-pin / Forget; it reads the `kyvault.pin.*` custom data.)

Role select owner/editor/reader (default reader). Seal with the looked-up public key, post
`{userId, role, sealedKey, keyFingerprint}`; 409 already a member / cap and 400
fingerprint mismatch (key changed between lookup and post) show inline; the mismatch case
re-runs the lookup. Re-seal on a stale row is the same path with `PUT …/members/{userId}`
and no role.

## Accept and decline

Invitations render in the switcher and as a banner on the Vault tab ("1 invitation"). The
Accept dialog shows: vault name, "Invited by <username>", the inviter's fingerprint with
pin status (match / not pinned / **changed**), the role offered, and the fixed trust line.
Not pinned: amber, "Verify with <name> before you rely on this vault." Changed: red, same
text plus "Their key changed since you pinned it." Accept pins (or re-pins after an
explicit second confirm on changed) and calls `/accept`; Decline calls `/decline`.
Accepting does not open the vault.

## Members dialog

Header button "Members" on a shared vault. List: username, role, state badge, key
fingerprint with pin status, sealed by. Owner controls: Invite, role select per row
(`PUT …/members/{userId} {role}`; last-owner 409 inline), Re-seal on stale rows, Remove
(confirm), Rename, Delete (confirm; fresh-session 403 → "Sign in again" link, reused from
the backup UI). Own row: Leave (confirm naming the loss; last-owner 409 inline). Readers
and editors see the list read-only plus Leave. Every action refreshes the list and, when
the selected vault was deleted or left, switches back to personal.

## Stale rows and key replacement

Own row stale: the switcher shows "Key changed, ask an owner to re-seal" and the vault
cannot be opened (the sealed copy is for a key this browser no longer has). Another
member stale: owners see Re-seal.

Security → Replace user key gains a pre-step: list the user's active shared memberships,
open each `myKey.sealedKey` with the current seed and hold the keys in memory. The confirm
dialog names any vault whose key could not be opened and warns: "You will lose access to
<name> until an owner re-seals it; if you are its only owner, its contents are lost." After
the replace succeeds, self-reseal each held key with `PUT /api/shared/{id}/members/{self}
{sealedKey, keyFingerprint: newFingerprint}` (fresh session already established for the
replace). Failures list the vaults with Retry that resends only those; the keys stay in
memory until success or lock.

## Admin → Shared vaults

`#/admin/shared`: table from `GET /api/admin/shared`: name, created by, created, members,
`ownerless` badge; expand row → members with username, role, state. Actions: Delete vault,
Remove member (confirm each; fresh-session 403 → "Sign in again"). Toggle "Only admins may
create shared vaults" (`GET/PUT /api/admin/shared/settings`). No fingerprints, no keys.

## Server addition

`GET /api/users/lookup?username=<exact>` — `withAuth` (session or device token). Exact,
case-sensitive match on `Username`; 200 `{userId, username, fingerprint}` only for an
active user with a published user key; 404 otherwise (inactive, unknown, no key all look
the same). Per-source limit shared with pairing (`pairing_limit.go` source key): after 20
misses in 15 minutes → 429, audited `user.lookup_limited`; each call audited `user.lookup`
with the queried name. The route reveals only "an active user with that exact name has a
key", which the invite flow needs; the admin directory stays admin-only.

## Mock API

`frontend/mock/api.ts` gains the shared routes, the lookup route and the admin shared
routes with an in-memory store so `npm run dev:mock` drives every dialog.

## Testing

- `sharedKey.test.ts`: seal/open round trip; blob length 1168; wrong seed fails; a Go-sealed
  vector opens (extend `internal/userkey` vector tooling with the shared-key info string).
- `sharedVaults.test.ts`: API client shapes, error mapping (403/404/409 text), 60 s refresh
  gating on visibility.
- `vaultSelection.test.ts`: selection reducer (switch, lock resets, deleted/left vault
  falls back, invited/stale not openable, reader → readOnly).
- `route.test.ts`: `#/shared/<id>` parse/format, invalid id falls back.
- `lockedDraft.test.ts`: scope in key and AAD; a shared draft does not restore into personal.
- `keyReplaceReseal.test.ts`: opens held keys, replaces, reseals each, partial failure →
  retry set, unopenable key named in the warning.
- Server: `user_lookup_test.go` (exact match, inactive 404, no key 404, device token ok,
  limit 429, audit rows).
- UI verification: screenshots via `dev:mock` of switcher, Accept dialog (three pin states),
  Members dialog, Admin tab; recorded in `UI-VERIFICATION.md`.

## Security properties

- The shared vault key exists only in browser memory while that vault is selected; it is
  never written to IndexedDB, drafts store ciphertext only, and lock zeroes it.
- Sealing always targets a key the owner has pinned or is pinning now; a changed pin blocks
  sealing until a deliberate re-pin.
- The client sends `X-CSRF-Token` on every shared mutation (3a requires it).
- Admin pages show no key material.

## Out of scope

Shared key rotation and removed-member cleanup (3c); extension and KyAuth (3d);
cross-vault search or merged views; per-user signing keys; request-to-join; notifications.
