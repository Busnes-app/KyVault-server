# Shared vaults, leaving and key rotation (3c) — design

Sub-project 3c of the reporting effort (2 Watchtower ✓, 1 user keys ✓, 3a server ✓ PR #77,
3b web client ✓ PR #78, 3c leaving and key rotation, 3d extension and KyAuth, 4 admin
encrypted report). Server and web client together. Prior contracts:
`docs/superpowers/specs/2026-09-27-shared-vaults-server-design.md`,
`docs/superpowers/specs/2026-09-27-shared-vaults-web-design.md`, `internal/shared/AGENTS.md`.

## Goal

A removed member's copy of the shared vault key stops opening anything the vault saves from
then on. Removal alone cannot do that: the key was sealed to them and may be cached in their
browser's memory or in a copy of the KDBX they exported. Rotation re-keys the vault, re-seals
it to everyone who remains, and destroys the ciphertext the old key could open.

## What rotation does and does not promise

Rotation protects future contents only. A member who read an entry keeps what they read, and
a KDBX they downloaded before the removal stays readable with their old key forever. Every
piece of UI copy in this sub-project says so rather than implying a removal is a revocation.

## Decisions

- **Removal flags, an owner rotates.** Removing an active member, leaving, and declining an
  invitation each set `rotationPending`; all three held a sealed copy of the key. An owner
  completes the rotation. An admin removal sets the flag and nothing else, because an admin
  holds no key.
- **An unverifiable member is left behind, not a blocker.** A member whose published key no
  longer matches the rotating owner's pin is skipped and named afterwards; the rotation still
  happens. Sealing to an unverified key is refused everywhere, and blocking a security action
  on an unrelated trust question is the wrong strictness.
- **Pre-rotation ciphertext is deleted.** After a rotation the old key exists nowhere
  legitimate, so the vault's snapshots and preserved conflicts are unreadable to every
  remaining member and readable only by someone who kept the retired key — precisely the
  member who was removed. The rotation deletes them. Personal-vault rotation is unchanged.
- **One multipart POST.** The re-encrypted KDBX and every sealed key commit together. A
  50 MiB vault stays 50 MiB on the wire and is read as a stream.

## Server

### Record

`internal/shared` `Vault` gains:

```json
"rotationPending": { "since": "2026-09-27T…", "userId": "u-2", "reason": "removed" }
```

`reason` is `removed | left | declined`. Absent when no rotation is owed. `Vault.KeyEpoch`
and `Member.KeyEpoch` stop being constant 1.

### Transitions

- `Remove` (owner removing someone else, an admin removing anyone, a member leaving) and
  `Decline` set `RotationPending` with the matching reason and the departing user's id. A
  member removing their own **invited** row is `declined`; any other self-removal is `left`.
- `SetRole` and `SetSuspended` never set it. Neither is a departure.
- `Rotate` clears it.
- The flag is advisory: nothing is refused while it is set.

### `Rotate`

```go
type SealedFor struct { UserID, SealedKey, KeyFingerprint string }
func (s *Store) Rotate(id, actorID string, sealed []SealedFor, now time.Time) (Vault, error)
```

Under the store lock: the actor must be an active owner (`ErrForbidden` otherwise, `ErrNotMember`
with no row); every `SealedFor` must name a current member and carry a well-formed 1168-byte
sealed key whose `KeyFingerprint` equals that member's current published fingerprint (`ErrShape`
otherwise, and the whole call fails); `KeyEpoch` becomes N+1; each named member's row takes the
new sealed key, `SealedBy`/`SealedByFingerprint` of the actor, `KeyEpoch` N+1, and keeps its
role and its `invited`/`active` state; every member not named stays at epoch N and becomes
`stale` (a `suspended` row keeps `suspended` with `suspendedFrom` `stale`); `RotationPending`
is cleared. An ownerless vault cannot rotate.

### Route

`POST /api/shared/{id}/rotate`, `withAuth`, active owners only, `validCSRF`, `requireFresh`.
`multipart/form-data` with exactly two parts: `kdbx` (the re-encrypted vault, read as a stream)
and `keys` (JSON `{"epoch": N, "sealed": [{userId, sealedKey, keyFingerprint}]}`, ≤ 1 MiB).
`epoch` is the epoch the client is rotating **from**, i.e. what it believes is current.
`MaxBytesReader` caps the whole request body at 50 MiB plus a 1 MiB allowance for the keys
part and the multipart framing, so an oversized vault is still refused before any mutation.
`If-Match` carries the vault data version.

The handler holds `shared.mu` for the whole operation through `WithWriter`'s lock order
(`shared.mu` then `vault.mu`) and: refuses `epoch != v.KeyEpoch` with 409; writes the KDBX
through the vault store with the `If-Match` version, 409 on mismatch; deletes the vault's
snapshots and conflicts; commits the membership record. A failure at any step leaves the
record, the ciphertext and the history as they were. Audit `shared.key_rotated` with the vault
id, the new epoch and the count of members sealed and left behind, never a sealed key.

### Epoch on ordinary writes

Shared uploads, history restores and conflict discards send `X-Shared-Key-Epoch: N`.
`withSharedWrite` refuses `N != v.KeyEpoch` with 409 and the body `the shared vault key was
rotated; reload the vault`. Without it, a member re-sealed during a rotation whose tab still
holds the old key would write old-key ciphertext under the new epoch and strand everyone.
A missing header is refused the same way, so an un-updated client cannot write blind.

## Client

### Surfaces

- Switcher: a "Needs rotation" badge on a flagged vault, owners only.
- Members dialog: an owners-only banner naming who left, when, and that their copy of the key
  opens anything saved before a rotation, with the Rotate key button. Also present whenever
  the flag is set, not only right after a removal.
- Removal and leave confirmations state what removal does not do.
- The rotate confirmation states that the vault's version history and preserved conflicts are
  deleted, because after the rotation nobody holds the key that opens them.
- Admin → Shared vaults shows the flag. An admin cannot rotate.
- After a rotation: the members left behind, by name, with the reason.

### Flow

`lib/sharedRotation.ts`, dependencies injected, no React:

```ts
export type RotationPlan = { seal: { userId: string; publicKey: Uint8Array; pin: PinStatus }[];
                             leftBehind: { userId: string; username: string; reason: string }[] };
export function planRotation(members: Member[], views: Record<string, KeyView>, myId: string): RotationPlan;
export async function rotateSharedVault(id: string, plan: RotationPlan, deps: RotateDeps): Promise<RotationResult>;
export async function rotationLanded(id: string, expected: Uint8Array, deps: RotateDeps): Promise<boolean>;
```

`planRotation` seals to the owner and to every member whose pin matches or is unpinned, and
leaves behind every member whose key changed since the owner pinned it or whose published key
could not be read. Unpinned members are pinned in the same action, as invite does.

`rotateSharedVault` generates a 32-byte key, re-encrypts the open KDBX under it, seals it per
the plan, and sends the multipart POST with the current epoch and version.

Rotation requires an active owner, `userKey.kind === "ready"`, the vault open, and no unsaved
edits; it runs inside `VaultSaveQueue.exclusive`. On success the tab swaps key and queue and
refreshes. On rejection `rotationLanded` re-reads the vault and opens the caller's newly
published sealed key with their seed: if it is the key this click generated, the rotation
landed and only the response was lost, so the tab adopts it; otherwise nothing happened and
the old key stays current. Without that check a dropped response re-keys the vault while the
only browser holding the new key discards it.

### Epoch handling

`useSharedVaults` already carries `keyEpoch`; the save queue sends it on every shared write. A
409 naming the epoch re-opens the vault rather than showing an error, because a re-sealed
member's fresh key is already in the list. A member left behind is `stale` instead, which the
existing treatment covers: no open, and an owner must re-seal them.

### Carry-forward from 3b, landing here

- Self-reseal additionally requires `m.KeyEpoch == v.KeyEpoch`, so a member left behind by a
  rotation cannot re-seal themselves to a key they do not hold (server and client).
- A stale member can reach Leave.
- The three Members-dialog copy fixes: the no-key pre-flight message, the own-row re-pin
  tooltip, and distinguishing an unavailable lazy chunk from a mismatched key when an open
  fails.
- `docs/shared-members.png` is re-captured.

## Security properties

- After a rotation, the vault's ciphertext, its history and its conflicts are all under the
  new key; the retired key opens nothing the server still serves.
- No member receives a key sealed against a pin the owner has not verified.
- The epoch header makes it impossible to write ciphertext under a retired key.
- The rotation is one commit: the ciphertext and the sealed keys never disagree.
- No sealed key, seed or vault key appears in an audit row, a log or a dialog body.

## Testing

- `internal/shared`: each trigger sets the flag with the right reason; role change and
  deactivation do not; rotate bumps the epoch, re-seals the named members, marks the rest
  stale, preserves roles and invited state, clears the flag, and is refused to a non-owner, a
  non-member and an ownerless vault; a malformed or fingerprint-mismatched sealed key aborts
  the whole call.
- `internal/api`: the multipart route end to end, an oversized `kdbx` part, a `keys` part over
  1 MiB, a missing part, the epoch 409 and version 409, the fresh-session and CSRF gates, the
  audit row's contents, history and conflicts gone afterwards, and that a failure at the vault
  write leaves the membership record untouched.
- `internal/vault`: a new `ClearHistory(key)` that removes a key's snapshots and preserved
  conflicts under the store lock, leaving the current vault and metadata intact.
- Frontend: `planRotation` over every pin verdict; the lost-response adoption; the epoch on
  writes and the re-open on an epoch 409; `sharedFlows` self-reseal refusing an epoch-stale row.
- Mock API gains the rotate route and the flag so the banner, the confirmation and the
  left-behind summary can be captured; `UI-VERIFICATION.md` records them.

## Out of scope

Rotating on a schedule or automatically; rotating the personal vault's history policy;
re-encrypting a removed member's own exports (impossible); the extension and KyAuth (3d);
the admin encrypted report (4).
