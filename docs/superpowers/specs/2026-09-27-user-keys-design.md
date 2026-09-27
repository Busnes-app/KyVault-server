# User key pairs — design

Sub-project 1 of 4 in the reporting effort (order: 2 Watchtower ✓, 1 user keys, 3 shared
vaults, 4 admin encrypted report). This spec covers only the key pair, its storage, its
lifecycle and pinning. Nothing in it shares a vault or sends a report.

## Goal

Every user has a public-key pair so that (a) a shared vault's key can later be wrapped to
each member and (b) a user can later encrypt a report to an admin. The private half is as
secret as the vault: only an unlocked browser holds it. The server stores and serves public
keys but is not trusted to vouch for them; users pin keys in their own vault.

## Decisions

- Algorithm: HPKE (RFC 9180) with the X-Wing KEM (ML-KEM-768 + X25519, draft-ietf-hpke-pq),
  HKDF-SHA256, AES-256-GCM — the suite `ky-primitives/capsule` already uses through Go
  `crypto/hpke.MLKEM768X25519`. Chosen over X25519-only because sealed keys and reports
  are stored for years (harvest-now-decrypt-later).
- JS implementation: `@hpke/core` 1.9.0 + `@hpke/hybridkem-x-wing` 0.7.0 (MIT, pinned,
  lazy-loaded). Verified 2026-09-27: a fixed seed yields the same 1216-byte public key in
  Go and JS (also matches `@noble/post-quantum`'s `ml_kem768_x25519`), Go-sealed opens in
  JS and JS-sealed opens in Go. The private key must be loaded with
  `kem.importKey("raw", seed, false)`; `deriveKeyPair(ikm)` applies HPKE's labeled
  derivation and yields a different key.
- Trust: trust-on-first-use. One key per user, pinned directly by fingerprint. No signing
  key, no admin attestation (may be layered on later).
- Pins live in the user's own KDBX (custom data), not per browser.
- Only the browser implements this now; the extension and KyAuth get the format.

## Key material

- Seed: 32 random bytes from `crypto.getRandomValues`. Public key: 1216 bytes derived from
  the seed. Encapsulation: 1120 bytes.
- Fingerprint: SHA-256 over the public key bytes, first 20 hex characters, upper case,
  grouped in fours (`A1B2 C3D4 E5F6 0718 293A`). Shown wherever humans compare keys.

## Server record

New optional field on `vaults/<userID>/metadata.json` (`vault.Metadata`), opaque to the
server beyond shape checks:

```json
"userKey": {
  "alg": "xwing",
  "publicKey": "<base64, 1216 bytes>",
  "wrappedSeed": "<base64: 12-byte IV || AES-256-GCM(seed)>",
  "createdAt": "2026-09-27T01:00:00Z",
  "previous": [{ "publicKey": "<base64>", "replacedAt": "..." }]
}
```

- `wrappedSeed` is AES-256-GCM keyed on the raw vault key (same pattern as
  `lockedDraft.ts`), AAD = UTF-8 `kyvault-user-key:<userId>`, so a blob cannot be moved
  between accounts.
- Shape checks on write: `alg == "xwing"`, `publicKey` decodes to 1216 bytes,
  `wrappedSeed` decodes to 12 + 32 + 16 = 60 bytes. Anything else is 400.
- `previous` is appended by a replace; capped at 5 entries, oldest dropped.

## Sealing (library surface for sub-projects 3 and 4)

`frontend/src/lib/userKey.ts`:

```ts
generateUserKey(): Promise<{ seed: Uint8Array; publicKey: Uint8Array }>
publicKeyFromSeed(seed): Promise<Uint8Array>
fingerprint(publicKey): Promise<string>
wrapSeed(seed, vaultKey, userId): Promise<Uint8Array>      // IV || ciphertext
unwrapSeed(wrapped, vaultKey, userId): Promise<Uint8Array>
seal(publicKey, info: string, plaintext): Promise<Uint8Array>   // HPKE single-shot: enc || ct
open(seed, info: string, sealed): Promise<Uint8Array>
```

`info` names the purpose and is part of the key schedule, e.g. `kyvault/shared-vault-key/1`,
`kyvault/report/1`; a blob sealed for one purpose does not open as another. Output is
byte-compatible with Go `hpke.Seal(pk, HKDFSHA256(), AES256GCM(), info, pt)`.

## Lifecycle

- **Generation.** On unlock, if the server record has no `userKey`, the browser generates
  one and publishes it in the background (no prompt). A failed publish retries on the next
  unlock. Generation runs after the vault is usable, never blocks unlock.
- **Unlock.** After the vault key is unwrapped, fetch the record, unwrap the seed, derive
  the public key, compare with the published one. Mismatch: the key is not used and the
  Security page shows "Your published key does not match your private key" with a Replace
  action; nothing else changes.
- **In memory.** The seed sits next to the vault key in `App.tsx` state and is cleared on
  lock. The device-key cache never stores it; a passwordless unlock re-unwraps it from the
  record.
- **Vault key rotation.** `keyRotation.ts` re-wraps the seed under the new vault key and
  sends it in the same `POST /api/vault/upload` (`X-Vault-Key-Rotated: 1`) as the new
  envelopes, as JSON field `userKey` (full record). `RotateVault` writes it atomically and
  refuses (400) a rotation that omits `userKey` while one exists. Public key and fingerprint
  do not change; no one re-pins.
- **Paper recovery** unwraps the vault key, which unwraps the seed. Nothing is added to the
  paper code.
- **Replace** (Security → Your key → Replace my key): requires the master password
  (`verifyMasterPassword`, as other Security actions). Generates a new pair, publishes it
  with the old public key appended to `previous`. Everyone who pinned the user will see
  "changed" on next lookup.

## API

- `PUT /api/vault/user-key` (session auth, CSRF): body is the record without `previous`;
  `If-Match: "<vault version>"` required, 409 on mismatch, writes under the vault store
  lock and bumps nothing else (version unchanged, like envelopes). If a record exists and
  the public key differs, the old one is appended to `previous`. Audit
  `user_key.published` (first) or `user_key.replaced`, detail = fingerprint.
- `GET /api/vault/user-key` (owner): full record including `wrappedSeed`.
- `GET /api/users/{id}/key` (any signed-in user): `{userId, alg, publicKey, fingerprint,
  createdAt, previous:[{publicKey, replacedAt}]}`; 404 if none. Never `wrappedSeed`.
  Fingerprint is computed server-side with the same definition (tested equal).
- Device-pairing tokens reach `GET /api/vault/user-key` and `GET /api/users/{id}/key`
  (a paired client needs them to open shared vaults later) but not the PUT.

## Pins

`frontend/src/lib/keyPins.ts`, stored as KDBX meta custom data:

- Key `kyvault.pin.<userId>`, value JSON `{ "fingerprint", "publicKey", "pinnedAt" }`.
- `lookupKey(vault, userId)` → `{ state: "unknown" | "pinned" | "changed", published, pin? }`.
  `changed` carries both fingerprints. Network fetch of the published key only.
- `pinKey(vault, userId, publicKey)` writes the pin and queues an ordinary vault save.
- Callers decide policy. This sub-project ships no pinning UI.

## UI

- Security → **Your key**: fingerprint (grouped), created date, Copy, "Replace my key".
  Mismatch warning per Lifecycle.
- Admin → User Directory: a Fingerprint column from `GET /api/users/{id}/key`, blank when
  none. Read-only.

## Backup

The record is in `metadata.json`, already collected into the capsule; restore brings it
back. No `internal/backup` change.

## Security properties

- The seed leaves the browser only wrapped under the vault key.
- Public keys are served to signed-in users and deliberately not trusted from the server;
  pins in the user's own vault carry trust.
- Replace requires the master password; a hijacked session cannot swap the published key.
- AAD binds the wrapped seed to the account.
- No new outbound traffic; CSP unchanged. `@hpke/*` and `mlkem` are lazy chunks.

## Testing

- `userKey.test.ts`: generate/wrap/unwrap/derive; wrong vault key and wrong userId fail;
  seal/open round trip; wrong seed fails; different `info` fails; fingerprint pinned to a
  vector; interop fixture (below) opens.
- Interop fixture `frontend/src/lib/testdata/hpke-xwing-vector.json`: `{seed, publicKey,
  info, goSealed, plaintext}` produced by a Go program in `internal/userkey/gen_vector_test.go`
  (run with `-update`) using `crypto/hpke.MLKEM768X25519`. JS asserts derived public key
  equals `publicKey` and `open(seed, info, goSealed) == plaintext`; a Go test asserts the
  same file's `jsSealed` (written by the JS test with `UPDATE_VECTOR=1`) opens. Both sides
  check the other's bytes, like the Argon2id vector.
- `keyPins.test.ts`: unknown/pinned/changed; pins survive encrypted save and reopen.
- `keyRotation.test.ts`: the rotation upload carries the re-wrapped seed; it opens under
  the new vault key.
- Go `internal/api/user_key_test.go`: PUT with If-Match, 409 stale, shape 400s,
  `previous` append and cap, GET by another user omits `wrappedSeed`, anonymous 401,
  RotateVault refuses missing `userKey`, audit rows. `users_test.go` adds `userKey`,
  `wrappedSeed` to the never-in-users.json list.
- `scripts/check-bundle.mjs`: add a marker string from `@hpke/hybridkem-x-wing`.

## Docs

`AGENTS.md`: Child DOX Index bullet for `lib/userKey.ts`, `lib/keyPins.ts`,
`internal/api/user_key_handlers.go`: record format, AAD, rotation coupling, fingerprint,
pin storage, the raw-seed import gotcha, and a cross-product note (KyAuth and the extension
must pass the same interop vector). Routes added to the Authentication section.

## Out of scope

Sharing UI, report encryption, extension and KyAuth implementation, admin attestation,
pin export, any change to the paper code.
