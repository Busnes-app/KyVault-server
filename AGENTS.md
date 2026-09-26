# KyVault Server

KyVault Server is a zero-knowledge KeePass v4 management and synchronization server with web interface, mobile clients, and browser plugins.

## Core Capabilities & Architecture

1. **Zero-Knowledge KeePass v4 Vault Storage**: Server stores encrypted KDBX v4 vaults and wrapped key envelopes. The server never receives raw master passwords, plaintext vault keys, or unencrypted credential data.
2. **Key Custody & Envelopes**: Vault master key (256-bit) is wrapped client-side into password-wrapped, paper-recovery-wrapped, and device-wrapped envelopes using PBKDF2/Argon2 + AES-GCM. Changing passwords re-wraps the envelope without re-encrypting the full KDBX.
   KyAuth may upload its local KDBX and password envelope when the server vault is empty; the web client opens both raw-key and KyAuth hex-key KDBX credentials.
3. **Atomic Sync & Conflict Preservation**: Optimistic concurrency via ETag / version check (`If-Match: "{version}"`). Conflicting uploads are rejected and preserved in `conflicts/` for client deconfliction.
4. **Bounded Version History & Rollback**: Keep up to 100 snapshots per user spread across a default 90-day age window, with one-click rollback. Saves and rollbacks prune synchronously under the store lock. After age expiry, preserve the oldest/newest snapshots and thin the closest-spaced interior snapshots so a burst of writes cannot erase the pre-session recovery window.
5. **KySignOn SSO & Directory Replication**: KySignOn is the sole authenticator and sole directory (`/api/auth/oidc/login`, `/api/sync/webhook`). There is no local login, no local account creation and no server-side user credential. See "Replication" and "Authentication" below.
6. **Native Device Pairing**: 90-second PIN and QR code protocol (`/api/devices/pairing/*`) for mobile apps and browser extensions. Device sessions carry `DeviceID`; revoking a device deletes its sessions. `GET /api/devices` marks the caller's own device `current`; `PATCH /api/devices/{id}` renames (1 to 64 characters, no control runes). `api_test.go` covers revoke ending the session and rename validation.
7. **Tamper-Evident Audit Logging**: Cryptographic hash-chained audit trail (`/api/audit/*`). `GET /api/audit` pages with `before=<index>` (newest first).
8. **Web Interface**: React + TypeScript frontend using Space Grotesk, IBM Plex Mono, and Busnes light/dark themes with a browser-local System/Light/Dark selector. The Go server sets a strict CSP (script-src 'self' 'wasm-unsafe-eval', frame-ancestors 'none'), nosniff, no-referrer and HSTS on every response and serves no CORS headers; native and extension clients use Bearer tokens from non-browser or host-permitted contexts. Production builds ship no source maps. Installable as a PWA through `frontend/public/manifest.webmanifest` (icons from `logo.png` and a 512px export of `KyVault.png`; no service worker, so nothing works offline). `pwa.test.ts` validates the manifest and the `index.html` references; `static.go` serves `.webmanifest` as `application/manifest+json`.
9. **Blind KyRecovery Deposits**: `internal/backup` snapshots encrypted vault and operational state, uses `ky-primitives/recoveryclient` to seal `kycap/3` capsules to the pinned suite recovery public key, and writes local copies and deposits them without giving KyRecovery or this server the recovery private key.

## Authentication

KySignOn is the only way in. The user record holds **no** authentication material —
no password hash, no salt, no client-derived verifier, no recovery hash. A test in
`internal/users/users_test.go` asserts those JSON keys never reappear; if you find
yourself adding one, the design has been misread.

- Pending OIDC attempts are bounded at 1024; at capacity, evict the earliest expiry
  and admit new logins. Evicted attempts must restart. Issuer configuration is normalized
  by removing trailing slashes before both discovery and token verification; discovered
  and signed issuer values must still match exactly.
- Accounts are matched on the OIDC `sub` alone, which is the KySignOn user ID
  (`kysignon-server/internal/oauth/oauth.go:310,326`). Never match on username: doing
  so hands any KySignOn identity the local account that shares its name, and its vault.
- OIDC login attempts keep settings, PKCE verifier and nonce server-side for five minutes.
  The cookie is an opaque single-use state. Discovery/token transport is HTTPS with no
  redirects; `oidcverify.VerifyWithNonce` verifies issuer/client/signature/nonce before
  claims can create/link accounts or sessions. Userinfo is not an authentication fallback.
- Every session remembers what KySignOn proved: issuer, client, `sub`, `sid` and the ID
  token `iat` (`sso.Identity` on `api.Session`). Device sessions inherit the identity of
  the browser session that started the pairing; a pairing whose browser session has been
  logged out cannot be redeemed. `AuthenticatedAt` is the token's `auth_time`, falling
  back to `iat`, never the moment the callback ran; a value later than `iat` plus a minute
  is refused. `GET /api/auth/oidc/login?reauth=true` adds `max_age` equal to
  `freshSessionWindow` so a session bounced by `withFreshAdmin` can come back fresh; the
  gate still reads only the returned `auth_time`. The backup UI's "Sign in again" uses it. When discovery advertises
  `backchannel_logout_session_supported`, an ID token without `sid` is refused.
- `POST /api/auth/oidc/backchannel-logout` receives KySignOn's OIDC Back-Channel Logout
  tokens (`oidcverify.VerifyLogout`, form-encoded, 64 KiB, no cookie or CSRF, the query
  string is never read). A `sid` token ends that session and the devices it paired; a
  `sub`-only token ends every session of the subject issued at or before the token. It
  ends authentication only: vault ciphertext, envelopes and device registrations stay.
  Accepted `jti`s are written through to `DATA_DIR/sso-logout.json` and retained through
  the token's replay bound, so a repeat is 400 after a restart too, and a login whose
  token predates a retained logout is refused with 403 (`auth.sso_login_fenced`).
  Admission and revocation share the session lock with session minting, so a login
  cannot slip between them. That file is not in the sealed capsule: events expire in
  minutes and a restored process holds no sessions. Rejections are audited within the
  source's budget as `auth.logout_rejected`; success is `auth.sso_logout` with the `jti`.
- The master password is not a credential. It unwraps the vault key envelope in the
  browser and is never transmitted. Changing it is a client-side re-wrap against
  `PUT /api/vault/envelopes`. Changing it, generating a paper code and showing the
  offline vault key each require the current master password or paper code, verified in
  the browser against the stored envelope (`verifyMasterPassword`).
- A version-0 vault shows a create dialog with a confirm field (`lib/unlockMode.ts`); the unlock dialog auto-opens only on the vault tab.
- Paper recovery unlocks the vault, not the site. The unlock dialog tries the password envelope and then the recovery envelope with whatever was typed (`unwrapVaultKeyFromEnvelopes`).
- Key rotation (`keyRotation.ts`, Security → Rotate Vault Key) proves the current password, generates a new vault key, re-encrypts the KDBX and sends it with both new envelopes in one `POST /api/vault/upload` with `If-Match`, so `SaveVault` writes vault and envelopes under one lock; `PUT /api/vault/envelopes` is never used for rotation. It runs inside the save queue's serializer (`VaultSaveQueue.exclusive`) and is refused while edits are unsaved. A server error restores the old key in memory; a lost response is adopted only if the stored envelopes are ours at exactly the expected version + 1; otherwise (unreadable, or ours with a later save on top) the tab locks. On success the tab swaps key and queue, re-caches the device key, shows the new paper code with type-it-back, and revokes every device best effort (404 counts as done, failures offer Retry revoking). Snapshots and conflicts older than a rotation are encrypted with a retired key. `keyRotation.test.ts` proves old key refused, new key and both envelopes open, one upload, rollback on failure and the reconcile; `vault_rotation_test.go` pins that a stale upload changes nothing and a current one replaces vault and both envelopes.
- Local admin actions cannot deactivate the caller (400) or leave zero active admins (409, users.ErrLastAdmin); directory-driven deactivation via SCIM or the webhook is not guarded, the directory is authoritative.
- Admin → User Directory changes roles through `PUT /api/admin/users/{id}/role`; the caller's row is disabled and the last-admin 409 is shown inline.
- Admin → Backup: pinning a recovery key asks for confirmation first; the server still refuses a second, different key.
- User-facing callback failures (identity not linked, account deactivated, login fenced by a logout) redirect to `/?sso_error=<code>`; the login page explains the code. Token and configuration failures keep their status codes.
- A 401 from any API call except the session probe and logout raises `kyvault:unauthorized`; the app locks the vault and shows the login page with a notice.
- Destructive backup actions require a recent KySignOn-authenticated session. Device-pairing
  tokens carry no authentication timestamp and cannot refresh that gate. Capsule export is
  POST-only and requires the session-bound CSRF token because it snapshots the whole service.
- SSO settings come from `KYVAULT_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`
  (optional `_REDIRECT_URI`, `_AUTO_PROVISION`) and take precedence over
  `config/sso.json`. `PUT /api/admin/sso` answers 409 while they are set. Without an
  identity provider, or with an active account that has no `ssoSub`, the server
  refuses to start. `GET /api/admin/sso` never returns the client secret, only
  `clientSecretSet`; a PUT with a blank secret keeps the stored one, and `enabled:false`,
  a non-https issuer or an empty `clientId` is refused with 400.

## Replication

KySignOn's sync engine dictates the wire format; KyVault is the receiver and has no
say in it. `POST /api/sync/webhook` receives:

- a **bare SCIM 2.0 User resource** as the body — not an envelope with an `event` key
- the event in the **`X-KySignOn-Event-Type`** header: `user.created`, `user.updated`,
  `user.deleted`
- **`X-KySignOn-Signature`**: `syncauth` v1 HMAC binding the RFC3339 timestamp,
  event type, event ID and body digest. Use the shared Sign/Middleware, not a local encoder.
- `X-KySignOn-Event-ID` is stable across retries; no bearer secret is sent or accepted.
  A verified completed retransmission gets 200 without another mutation; failed handlers
  may retry. ID reuse with different content/type is rejected. Completion receipts are
  bounded and in memory for the signature window; restart durability needs persistent receipts.

This was previously mismatched: KyVault expected `{"event","user"}` and an
`X-Sync-Signature` over the body only, so every event fell out of the switch and
returned 200 having done nothing, while the bearer token made KySignOn record it as
delivered. **Both sides looked healthy and no account was ever provisioned.** Any change
here needs a round-trip test against a real KySignOn payload, not a unit test against our
own encoder — the bug was that our encoder and theirs disagreed.

Status codes matter to the sender (`kysignon-server/internal/sync/sync.go`, `deliver()`):
it treats 2xx as success, plus 404 on `user.deleted` and 409 on `user.created`. A 404 on
`user.updated` is a delivery *failure* it will retry, so an update naming an unknown
subject provisions the account when auto-provisioning is on and otherwise returns 200.

For signed replication, configure suite type `kyvault` with callback
`/api/sync/webhook`. Deploy the signed KySignOn sender with this receiver;
legacy unsigned or timestamp-dot-body webhook requests are rejected.

Standard Users-only SCIM uses `/scim/v2` and the shared `ky-primitives/scim` v0.6.0
wire types. It is disabled unless `KYVAULT_SCIM_TOKEN` is set (32–512 characters).
That dedicated bearer token grants directory access only; session, pairing and OIDC
secrets are not SCIM credentials. The deployment token overrides a restored `CONFIG_DIR/scim.token`. Collect the effective
token inside sealed capsules; it grants directory access but never user sessions. To disable
SCIM after restore, remove that file and unset the environment token.

`POST /Users` requires `externalId` equal to the KySignOn OIDC subject and returns the
server-owned local `id`. Lookup supports equality on `externalId` or `userName`, with
bounded pagination. PUT preserves the subject; PATCH supports add/replace of userName,
active, emails and roles, plus removal of emails/roles. Store one email and role per user;
reject additional values rather than discard them. Validate every operation before
one atomic directory update. Groups, bulk and arbitrary filters/attribute paths are outside
this interface. `/ServiceProviderConfig` advertises supported operations.

DELETE marks the account `scimDeleted` and inactive while retaining its vault. Only inactive
tombstones are hidden from SCIM GET/list; a local admin's reactivation must remain visible.
Creating the same externalId or an explicit signed `user.created` recovers the retained account.
Signed `user.updated` acknowledges but never restores inactive tombstones, recording
`sync.update_ignored_deleted`; explicit signed recreation records `sync.user_restored`.
SCIM authentication/disabled-route failures use `recordAnonymousRejection` with action
`scim.rejected`, a fixed non-secret detail and the existing source audit budget.
Successful SCIM writes distinguish `scim.user_created`, `scim.user_restored` and
`scim.user_updated`; details record role/active state or transitions, never credentials.
Deactivation invalidates existing sessions and outstanding pairing codes. The standard
client must use its bearer token and returned server IDs; the old signed generic sender's
empty DELETE payload is not accepted by this interface. `Admin → User Directory` shows
configuration and the base URL, never the token. `internal/api/scim_handlers_test.go` drives
the real shared client over TLS and checks convergence with the captured KySignOn payload.

A `user.deleted` deactivates the account and **never** deletes the vault. The vault is
the user's, not the directory's.

## Verification

- Backend: `gofmt -l .` (must be empty), `go vet ./...`, `go test -race ./...`
- Frontend: `npm test && npm run build` in `frontend/` (`build` is `tsc && vite build`, so it is the typecheck gate)
- UI without KySignOn: `npm run dev:mock` in `frontend/` serves the app with an in-process mock of the API (`frontend/mock/api.ts`, dev only, never built) for manual and screenshot checks.
- Daemon build: `go build -o ./kyvault-server ./cmd/server`
- Docker build: `docker build -t kyvault-server:latest .`
- Dependency vulns: `govulncheck ./...` and `npm audit --audit-level=high` in `frontend/`

All of the above run in CI on every push to `master` and every pull request, split
across six jobs in `.github/workflows/ci.yml`: `backend`, `frontend`, `docker`,
`security`, `publish`, `promote`. Keep the workflow and this list in sync when either changes.
`publish` and `promote` run only on a green push to `master`. `publish` pushes the exact
image the `docker` job handed over as an artifact (no rebuild) to
`ghcr.io/busnes-app/kyvault-server:<commit sha>`, attests it and verifies the attestation pinned to this workflow on `master`.
`promote` then moves `:latest` to that digest, only at the tip of `master`, and asserts the
tag resolves to the attested digest. `docker-compose.yml` names the published image and never
builds; source installs add `docker-compose.build.yml` to the `COMPOSE_FILE` chain in `.env`
(overlay tags `kyvault-server:local`) so every compose command, `docs/RESTORE.md` included,
uses the local build.

`.github/dependabot.yml` opens weekly grouped dependency PRs for Go modules, npm,
the Dockerfile base images, and the actions themselves. `kdbxweb` and
`argon2-browser` are grouped separately from the rest of npm: a bump to either
touches vault encryption, so it needs a vault round-trip review, not a rubber stamp.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
- Keep Child DOX Index entries current and delete stale rules.

## User Preferences

- Web themes default to the Busnes.app cream/light and charcoal/dark palettes with orange accents, following the OS until a browser-local choice is saved. Preserve existing named themes and saved choices.

- Best-effort 90-second keyword refresh policy (foreground cadence; background catch-up on resume).
- DOX hierarchy scope is app-only.

## Shared browser UI

- `frontend/src/ky-ui/` is generated from Busnes-app/ky-ui, pinned by `VERSION` file hashes. Change shared colors, navigation states and storage helpers upstream, then run its consumer sync with an explicit worktree map; do not hand-edit vendored files.
- Products own layout, routes, saved choice keys and named palettes. Busnes aliases consume shared tokens; mark primary navigation with `ky-nav-item` while preserving current-page semantics.
- Verify vendored files with `node frontend/src/ky-ui/check-vendor.mjs` from this document's directory. Builds/CI run that check. Rendered evidence and capture limitations are recorded in the repository-root `UI-VERIFICATION.md`.

## Child DOX Index

- `frontend/src/lib/kdbx.ts` and `frontend/src/pages/VaultPage.tsx`: selected live
  folders support child creation and rename through ordinary autosave. All Items/Recycle
  Bin create at the live root. Rename updates only the native group name/times, retaining
  UUID, children, entries and history; no-op names create no save revision. Reject blank
  names/control characters and unknown parents before mutation. The shared createGroup
  helper also constructs imported/recycled trees in tests; UI parents come from live groups.
  Rename rejects the metadata recycle bin and descendants. Group views include full paths
  and depth; sidebar indentation is capped at six levels while full paths remain available.
  Entry/CSV selectors use paths. `folders.test.ts` checks encrypted rename/reopen,
  nested paths, unchanged contents/history/binaries, no-ops, invalid targets and recycle guards.
  CSV prevalidates all prospective folder names before mutation so an invalid later row cannot
  leave earlier rows imported without a save revision; the same test file covers that boundary.
  A new entry is a draft in the editor until Apply Edits creates it; Cancel leaves no entry and
  no save revision. Selecting a folder clears an entry that is not in it.
  A typed but unapplied new entry is not checkpointed on auto-lock and does not trigger the
  unload warning; the discard confirm still asks.
  Folders can be moved (never into themselves, their descendants or the bin) and deleted;
  deletion recycles the whole subtree when recycling is enabled and is permanent otherwise,
  after a confirm. `folders.test.ts` covers both.

- `frontend/src/components/EntryAttachments.tsx` and `frontend/src/lib/kdbx.ts`:
  entries support adding one file at a time (10 MiB maximum), downloading decrypted
  copies and removing attachments. Reject duplicate names rather than overwrite.
  Add/remove checkpoint native entry history and use ordinary autosave. Recycled entries
  permit download only; controls are unavailable while editing fields. Stage binary hashing
  outside the live database and check cancellation before mutation; lock, navigation,
  entry/vault changes and entering edit mode cancel pending reads. Exports use native
  binary cleanup, preserving references from live/recycled entries and retained history.
  `attachments.test.ts` checks encrypted download/removal/restore, shared and protected
  binaries, invalid/cancelled additions and cleanup with disabled history.
  Reject additions before mutation above a 40 MiB vault-wide attachment budget, reserving
  10 MiB below the server upload limit for other contents. Count unique referenced hashes
  across live/recycled entries and history, plus per-reference base64 cost for inline binaries
  and their pending checkpoint. Check after hashing so concurrent additions cannot bypass it.
  Ordinary removal retains history; explicit removal of saved copies deletes that filename
  from every history version. Clear attachment history removes only historical binaries,
  keeping current files and password history. Both use autosave; export cleanup reclaims
  unreferenced bytes. Tests reproduce budget overflow without mutation and recover an
  imported >50 MiB vault with history enabled; shared copies in other entries survive.
- `internal/api/vault_handlers.go`: read upload bodies with MaxBytesReader before any
  mutation. Raw and JSON requests above 50 MiB receive 413; exactly 50 MiB is accepted.
  LimitReader previously saved a truncated raw vault and returned 200. The streaming
  regression in `vault_upload_limit_test.go` proves oversized uploads preserve the current
  bytes/version and that a boundary-sized upload round-trips intact.

- `frontend/src/components/EntryHistoryModal.tsx` and `frontend/src/lib/kdbx.ts`: Entry
  History reads native KeePass history in the unlocked browser. Changed Apply Edits
  checkpoints the previous complete entry; no-op edits add no history or save revision.
  Restore checkpoints the current entry, copies the selected native version, retains UUID
  and current folder, and queues ordinary autosave. Preserve protected fields, binaries,
  tags, auto-type, expiry and custom data (kdbxweb copyFrom omits customData/qualityCheck).
  History masks passwords, TOTP and all protected fields; changing version or reopening
  resets reveal. The native dialog closes on lock and tab navigation. History is unavailable
  during entry editing; recycled entries allow viewing only. Refresh reuse detection and
  editor fields after restoration. Honor historyMaxItems (default 10, negative unlimited);
  a zero item/byte limit disables new checkpoints and restore while retaining readable
  imported history. Positive byte-budget pruning awaits native historyMaxSize support.
  `entryHistory.test.ts` covers encrypted restore/undo, unchanged edits, complete native
  data, count limits, disabled history, and invalid/recycled targets.

- `frontend/src/components/ConflictComparison.tsx` and `lib/conflictComparison.ts`:
  Version History → Preserved Conflicts downloads an owner-scoped encrypted conflict and
  opens it locally with the unlocked key. Compare live entries by UUID across title,
  username, password, URL, notes and TOTP; other fields/history/attachments are not compared.
  Recover as copy imports the complete native entry into the top-level live folder with a
  fresh UUID and title suffix, preserving title protection, unknown fields, binaries and history. Remap imported
  icon collisions so existing icons cannot change. Never overwrite an existing entry or delete
  the conflict automatically. Use ordinary version-checked autosave; rollback and conflict discard
  stay disabled while recovery edits are unsaved. Close/lock cancels transport and ignores late decryption.
  `conflictComparison.test.ts` checks comparison identity, protected fields and full encrypted
  import preservation. Shared `getEntries()` reads every protected standard field as text.
- `GET /api/vault/conflicts/{id}` returns ciphertext only to the owning authenticated user,
  with no-store caching and a download audit event identifying the validated conflict ID. `Store.OpenConflict` validates a flat
  filename and uses `os.OpenInRoot` to prevent escaping symlinks. Discard shares filename
  validation. API/store tests cover anonymous/cross-user access, traversal, symlinks and
  read-only retrieval. Recoveries do not bypass If-Match or server conflict preservation.
  History rollback ids are validated like conflict ids (shared `openFileID`) before any path
  use; a path-shaped or symlinked id is 404 and changes nothing (`history_restore_id_test.go`).

- `frontend/src/lib/kdbx.ts` recycle helpers identify the bin and descendants by metadata
  UUID. `VaultPage` excludes them from All Items and folder selectors and offers a read-only
  Recycle Bin with Restore to vault (the top-level live group). Restore preserves entry UUID
  and contents and uses ordinary autosave. Delete respects explicitly disabled recycling in
  imported vaults and confirms permanent removal from the current vault; existing snapshots
  and backups remain. Otherwise deletion keeps the entry in the bin. Repeated deletion of a
  recycled entry is a no-op. No purge action in the recycle view.
  `recycleBin.test.ts` verifies encrypted reopening, restoration and disabled-bin retention policy and successive deletions.

- `frontend/src/lib/passwordReuse.ts`: browser-only exact nonempty password comparison
  across `getLiveEntries()`, excluding the metadata recycle bin and descendants. Returns
  UUID/count pairs, never persists or transmits the report. `VaultPage` refreshes after
  applied edits, creation, deletion and import; the reuse filter spans all live folders
  and still respects text search. Empty passwords are ignored; whitespace and case are
  significant. `passwordReuse.test.ts` covers edits, deletion and encrypted reopening.

- `frontend/src/lib/autoLock.ts` and `App.tsx`: per-tab vault idle locking defaults to five
  minutes; Security offers 1/5/15/30/60 minutes saved per browser. Check both wall and
  monotonic elapsed time before accepting activity, including focus/visibility resume.
  Lock invalidates pending unlocks and discards the save queue. A session-storage lock
  marker prevents refreshing the locked tab from using its trusted key. Mirror activity and
  lock markers in localStorage so a new tab after closure/browser restart also expires the
  cached key; missing or invalid activity requires a password. Automatic lock
  also removes that cached device key. Other already-unlocked tabs keep their own timers.
- `frontend/src/lib/lockedDraft.ts`: automatic lock checkpoints applied unsaved vault changes
  and unapplied entry fields, AES-GCM encrypted with the vault key and account-bound AAD.
  A separate IndexedDB database preserves the existing key-store version for older clients.
  Each lock allocates a fresh checkpoint ID so duplicated tabs cannot overwrite each other.
  Ordinary unlock does not open recovery storage unless this account has a checkpoint reference.
  Copies belong to a tab/account, survive refresh, and are consumed after successful
  decryption on unlock. Restore uses the original server version and requires explicit retry
  for unsaved changes, preserving conflict protection. Recovery read failures open the server
  copy with a notice and retain the unread reference; cleanup failures also surface a notice.
  Cache-key write failure does not block password unlock. Storage failure retains encrypted
  memory recovery and an unload warning; encryption failure locks anyway and reports the loss.
  Manual lock/logout still ask before discarding unsaved edits. Forget removes this tab's copy.
  Drafts record `sealedAt`; after each unlock `pruneDrafts` scans this account's key prefix
  and deletes drafts older than 7 days, stamps legacy drafts without a timestamp so they age
  out, and never touches the current tab's pointer. `planDraftCleanup` is the tested decision;
  the IndexedDB walk is exercised in the browser pass. No offline login/unlock.
  An unreadable checkpoint (corrupt or undecryptable) is deleted and reported rather than
  blocking unlock (`App.tsx`).

- `frontend/src/lib/vaultSave.ts`: owns one automatic save queue per unlocked vault.
  Applied edits, entry/folder creation, deletion, and CSV import enqueue saves after 1.5 seconds
  of idle time. Explicit retry flushes immediately. Serialize
  KDBX exports and uploads; each success acknowledges only its starting edit revision and
  advances the version for the next upload. Failures remain unsaved. A network failure
  retries once when the browser reports online. A 409 is flagged as a conflict: Retry does
  nothing, Overwrite server copy re-reads the server version and uploads over it (the
  server copy stays in history), refused when the stored password envelope differs from the one
  the queue was unlocked against (key rotated elsewhere; an old-key upload would strand the vault), Reload server copy discards local edits. Uploads use the
  shared CSRF request helper. `App.tsx` retains
  the queue and mounted editor across tabs, warns before unloading unsaved work, and guards
  rollback. Lock/logout/forget always allow the user to confirm discarding unsaved or in-flight
  edits; saving cannot refuse those actions. `canDiscardVault` takes an async confirmer (the
  `useDialogs()` confirm dialog, never a native `confirm()`) so every caller awaits it.
  Closing/replacing the queue cancels its timer,
  aborts transport and prevents later revisions uploading. An already accepted request cannot
  be undone. Logout clears the visible vault before network I/O; forgetting starts key removal
  independently of logout. Draft fields require Apply Edits; automatic locking preserves them in the encrypted local checkpoint.
  `vaultSave.test.ts` checks encrypted round trips, debounce, cancellation, failures, and retry.

- `frontend/src/lib/download.ts`: every browser download goes through `downloadBlob`, which
  appends the anchor and revokes the object URL a second later so Firefox and Safari do not
  cancel it.

- `frontend/src/styles/styles.css`: `.settings-page` provides the bounded scroll area for
  Admin and Security within the fixed-height app shell; keep long backup forms reachable.

- `frontend/src/components/Dialog.tsx` and `DialogHost.tsx`: every modal uses `Dialog`
  (native `<dialog>`, Escape closes, backdrop click never closes, focus returns to the
  opener). Questions go through `useDialogs().confirm/prompt/notify/choose`, sequenced by
  `lib/dialogQueue.ts` so a second question waits for the first. Native `confirm`, `prompt`
  and `alert` are banned in `frontend/src`, including `window.confirm`. `noNativeDialogs.test.ts` fails the suite if one comes back.
  Autofocus inside a `Dialog` uses `data-autofocus`, not the React `autoFocus` prop: React
  never emits an `autofocus` DOM attribute, so `Dialog`'s `[autofocus]` lookup was dead code.
  Locking the vault cancels every pending question (`cancelAll`) so a handler that captured
  the vault key cannot be resumed from a locked screen. `choose` renders a select.

- `internal/backup/AGENTS.md`: owns the recoveryclient settings/sealer adapter, file-store
  collection, product restore validation, and backup integration. Vault validation is ciphertext/checksum-only;
  only drills and restores may hold private recovery material.

- `frontend/src/lib/storage.ts` and `frontend/src/lib/deviceKey.ts`: manages the IndexedDB
  `keys` store on trusted devices for 1-click unlock. The vault key is sealed (AES-GCM)
  under a non-extractable per-browser CryptoKey held in the same store; legacy plain-hex
  records are deleted on sight, and the next password unlock writes a sealed record.
  Forget This Device clears it. The pairing modal polls `GET /api/devices` every 3 seconds
  while open and visible and closes when the device count grows.
- `frontend/src/lib/vaultCrypto.ts`: the vault key envelope — **the only place a
  human-chosen secret is stretched**. Everything else is keyed on a 256-bit random vault
  key, where the KDF is near-irrelevant; here it is the whole defence, and the envelope is
  stored server-side, so anyone holding a backup can attack the master password offline
  forever. Argon2id, m=64 MiB, t=3, p=1 (OWASP), AES-GCM over the vault key.

  The envelope is self-describing so parameters can be raised later without a format break:

  ```json
  {"kdf":"argon2id","salt":"…","iv":"…","ciphertext":"…",
   "memoryKiB":65536,"iterations":3,"parallelism":1}
  ```

  **`memoryKiB` is KiB.** The field is named for its unit on purpose — mixing it up runs
  Argon2 on a thousandth of the intended memory while every round-trip still succeeds and
  the recorded parameters still read correctly. `deriveEnvelopeKey` is exported and pinned
  to a known vector in `vaultCrypto.test.ts` for exactly that reason; the parameter
  assertions alone cannot catch it, because they only check what was written.

  **This is a cross-product format.** KyAuth reads *and writes* envelopes
  (`KyVaultEnvelopeCrypto.kt`), and today it writes PBKDF2-HMAC-SHA256 at 600k
  iterations. An envelope with no `kdf` field is PBKDF2 by definition, and
  `unwrapVaultKey` still reads that shape so a vault uploaded by an un-updated KyAuth
  remains openable. Remove the PBKDF2 path only once KyAuth writes Argon2id.

  Shared vector for whoever implements the Kotlin side — Argon2id, m=65536 KiB, t=3, p=1,
  32-byte output, password `correct horse battery staple`, salt = 16 bytes of `0x03`:

  ```
  73eb74162616418d643f08dc0856539ea61400cb268f85ce8df01d8257795b8d
  ```

  Both implementations must produce that. Unit tests per repo only prove each side is
  self-consistent; agreeing on a vector is what proves they interoperate — the same lesson
  the silently-mismatched replication format taught. The client refuses master passwords under 12 characters (lib/masterPassword.ts) on create and change; the server never sees one so it cannot enforce this.
  The Security page shows the paper code and vault key with Copy (cleared after 30 seconds when allowed), Print (print-only region), auto-hide (`lib/secretDisplay.ts`) and a type-it-back confirmation for the paper code.

- `frontend/src/lib/kdbx.ts`: client-side KDBX v4 vault, written to be byte-compatible with
  KyAuth so either client opens the other's file and so a downloaded vault opens in KeePassXC.
  Entries carry native tags (favourite is the tag `favorite`), expiry
  (`times.expires/expiryTime`) and custom fields (native `fields`, `ProtectedValue` when
  protected); `entryMeta.ts` owns parsing, expiry windows, sorting and search, which never
  reads protected custom values. `entryMeta.test.ts` proves the encrypted round trip.
  Two properties carry that, and both are load-bearing:
  - **The credential is the vault key as hexadecimal text**, never the raw bytes. That is what
    KyAuth uses (`KdbxPasswordVault.kt`: `Credentials.from(EncryptedValue.fromString(
    bytesToHex(vaultKey)))`), and it is the only form a human can type into KeePassXC. A
    binary-keyed vault has no offline recovery path at all — the file opens with nothing a
    person can enter.
    Legacy web vaults still require binary-key reads: `open` tries hexadecimal first and
    falls back only on `InvalidKey`. A legacy load uses hexadecimal credentials for the next
    explicit save/export, without uploading or changing the original snapshot on unlock.
    Keep the legacy open/export regression test alongside the new-vault checks.
  - **Argon2d with kotpass's `Ver4x.create()` parameters**: m=32 MiB, t=8, p=2, set explicitly
    because kdbxweb's Argon2 defaults are far weaker (1 MiB, t=2, p=1).

  The Argon2 engine is hash-wasm, not argon2-browser: argon2-browser resolves its WASM by URL
  and dies outside a browser, which left every Argon2 path untestable under `node --test`.

  **Do not "convert" the memory argument in `deriveArgon2Key`.** kdbxweb passes KiB and
  hash-wasm expects KiB. Dividing by 1024 runs Argon2 on 32 KiB instead of 32 MiB — a
  thousandfold weakening that still encrypts, decrypts and round-trips, with the header still
  advertising 32 MiB because the header is written independently of what the KDF consumed. The
  pinned-key test in `kdbx.test.ts` is the only thing that catches it; keep it.

  ponytail: kdbxweb's `setVersion` takes only a major version, so we write KDBX 4.0 while
  kotpass writes 4.1. Both libraries read both. Upgrade path is kdbxweb minor-version support.
  Also untested: opening a genuine kotpass-written file. The KyAuth fixture in `kdbx.test.ts`
  is built with kdbxweb, so it proves our credential handling, not cross-library compatibility.
  `openForeign` opens a file written by another client with a plain password; `importFrom`
  copies its live tree into an existing same-named top-level folder (reused across repeat
  imports) or a new one named after the source root, keeps UUIDs that are free, recurses
  into a same-UUID live group instead of skipping it (so entries added there after an
  earlier import are picked up), and skips existing entries. Imported groups keep only
  their name and UUID, not the source's own metadata. `kdbxImport.test.ts` covers skip,
  recurse and carry. CSV export (`csvExport.ts`) omits custom fields and attachments.
- `frontend/src/lib/csvImport.ts`: zero-knowledge RFC 4180 CSV parser and multi-format importer supporting
  Google Chrome, 1Password, Bitwarden, LastPass, DashPass (Dashlane), and generic CSV formats. Provider
  folder values are split on `/` and `\` into nested KeePass groups, reusing existing groups by path;
  all parsing and vault mutation happen client-side. Covered by `csvImport.test.ts`.
  Exact duplicate detection compares title, username, password, URL, notes and TOTP across
  live vault folders and selected CSV rows. `KeePassVault.getLiveEntries()` excludes the
  metadata-designated recycle bin and its descendants; recycled entries remain browsable
  through `getEntries()`. Delete-then-reimport is tested across encrypted export/reopen.
  Skip duplicates is on by default, with explicit
  opt-out. Preview and apply share the same comparison; apply rechecks current vault contents.
  Skipped-only imports create no folders or save revisions. Changed field values are retained
  as separate entries; comparison performs no fuzzy matching, merging, or normalization.
  CSV parsing preserves password whitespace, including passwords consisting entirely of spaces.
  Bitwarden unencrypted JSON exports import logins with folder and TOTP (`bitwardenImport.ts`); generic CSV supports explicit column mapping (`applyMapping`); `csvExport.ts` writes a KeePassXC-compatible CSV (plus Tags, Expires, Last Modified) behind a plaintext warning.

- `frontend/src/lib/totp.ts`: RFC 6238 TOTP in the browser. otpauth URIs may set secret,
  digits (6 to 10), period and algorithm (SHA1, SHA256, SHA512; anything else falls back
  to SHA-1). `totp.test.ts` pins the RFC 6238 Appendix B vectors for all three algorithms.

- `frontend/src/lib/format.ts`: `formatInterval` (Off, minutes, Hourly, hours, Daily, days) and `formatWhen` (never renders Invalid Date). `format.test.ts` covers both.

- `frontend/src/lib/clipboard.ts`: every copy goes through `copyText`; passwords, TOTP codes and generated passwords are cleared after 30 seconds if the clipboard still holds them (or, where reading is refused, if nothing newer was copied through the helper). The timed clear is best effort: browsers may refuse clipboard access from a timer, and the UI says so. `clipboard.test.ts` covers both.

- `frontend/src/lib/route.ts`: hash routes `#/vault[/entryUuid]`, `#/security`, `#/admin/{sso|users|audit|backup}` drive the top tabs, admin tabs and the selected entry; unknown routes fall back to the vault; a non-admin on an admin route is redirected. `route.test.ts` covers parsing and formatting.
  `App.tsx` remembers the last vault route (`lastVault` ref) so the Vault nav button restores the selected entry instead of deselecting it. `VaultPage`'s route-follow effect syncs the mobile pane (`list` when the hash drops the entry, `detail` when it names one) and treats a recycled entry's uuid as unknown, correcting the hash back to `#/vault` rather than reopening it.

- `frontend/src/lib/useMediaQuery.ts` and `VaultPage` panes: under 900px the vault is one pane at a time (folders, list, detail) with Folders and Back controls; under 600px nav labels collapse to icons with aria-labels. Desktop keeps the three-column grid.

- `frontend/src/lib/generatePassword.ts`: uniform rejection sampling, one guaranteed character per selected class, length 8 to 128, optional look-alike exclusion, settings persisted under `kyvault.generator`. `generatePassword.test.ts` pins class coverage and the error cases.

- `frontend/src/lib/passphrase.ts` and `effWordlist.ts`: passphrases draw uniformly from the bundled EFF long list (7776 words, generated module, never fetched); `passphraseEntropyBits` and `passwordEntropyBits` are log2 of the search space and the meter says "about". `passphrase.test.ts` pins the list size, charset and a zero-randomness phrase.

- `frontend/src/lib/health.ts` and `components/HealthReport.tsx`: the report is computed from live entries in memory (weak heuristic, reuse, expiry) and names entries by uuid and title only. The HIBP check is opt-in per click behind a confirm that states what leaves the browser; it sends the 5-character SHA-1 prefix with `Add-Padding` and no credentials, keeps results in memory, and is the only allowed non-self `connect-src` in `internal/api/headers.go`. `health.test.ts` pins the heuristic, the parser and the request shape.
