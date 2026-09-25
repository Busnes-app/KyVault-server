# KyVault Fix-Everything Roadmap

> **For agentic workers:** This is the master roadmap from the 2026-09-25 site audit. Each phase
> gets its own bite-sized plan in this directory when it starts. Phase 1 is written:
> `2026-09-25-phase1-security.md`. Do not start Phase N+1 until Phase N is merged to `master`
> and CI is green.

**Goal:** Close every finding from the 2026-09-25 audit, security first, then ship Chrome and
Firefox extensions that pair with the server like any other device.

**Order:** 1 Security → 2 Functional bugs → 3 Annoyances → 4 Missing features → 5 Browser extension.
Security first because each later phase adds UI surface; a CSP and a sane CORS policy must be in
place before the extension and the new modal component land.

**Execution:** one PR per phase, branched from `master`, using the `pull-request` skill. Every PR
passes the AGENTS.md Verification list. Every phase ends with a DOX pass on `AGENTS.md`.

**Corrections to the audit made while planning:**
- "Pin public key silently replaces the pinned key" is wrong at the server: `handlePinRecoveryKey`
  returns 409 on a different key (`backup_handlers.go:223`). Only a UI confirm is missing (Phase 3).
- Plain-hex device key in IndexedDB: wrapping it with a non-extractable `CryptoKey` raises the bar
  for a profile-copy attacker but not for XSS. The real XSS defence is the CSP in Phase 1 Task 1.
  Both ship.

---

## Phase 1: Security (plan: `2026-09-25-phase1-security.md`)

| # | Finding | Fix | Test |
|---|---|---|---|
| 1 | Wildcard CORS, no CSP/frame/referrer/HSTS headers, source maps shipped, directory listings | Delete `corsMiddleware`; add `securityHeaders` on the root mux; `sourcemap:false`; directory → SPA index | Go test asserts headers on `/api/health` and `/`; no ACAO header |
| 2 | JSON upload stores base64 text as vault bytes | `base64.StdEncoding.DecodeString`, 400 on bad input | Round-trip test in `vault_upload_limit_test.go` |
| 3 | `GET /api/admin/sso` leaks client secret; PUT accepts `enabled:false` and blanks; UI form usable when load failed | GET returns `clientSecretSet`; PUT keeps secret when blank, refuses `enabled:false`, validates https issuer + clientId; UI loads with `allSettled` and gates the form | Go tests for GET shape and PUT rules |
| 4 | Admin can deactivate self or last admin, or demote last admin | `ErrLastAdmin` in `users.Store.Deactivate/SetRole`; self-deactivate 400 in handler | Store test + handler test |
| 5 | Device key cached as plain hex | Wrap with non-extractable AES-GCM `CryptoKey` in the same IndexedDB store; fix the "secure storage vault" copy | Node test with `fake-indexeddb`? No: keep to a WebCrypto round-trip test of `wrapForDevice/unwrapForDevice` |
| 6 | `javascript:` entry URLs rendered into `href`; CSRF cookie regex unanchored | `safeHref()` allowlist http/https; anchored cookie regex | `safeHref.test.ts` |
| 7 | No master-password minimum on create/change | `checkMasterPassword()` min 12 chars, `autocomplete="new-password"` | `masterPassword.test.ts` |
| 8 | Change password / reveal key without proving the current password | Unwrap the current password envelope client-side before either action | Manual browser check + unit test of the helper |

## Phase 2: Functional bugs

- TOTP honours `algorithm=SHA256|SHA512` and `digits`/`period` (`totp.ts`); test vectors from RFC 6238 Appendix B for all three algorithms.
- `EntryAttachments`: reset `removeFromHistory` in the per-entry effect.
- CSV import: call `onChanged()` in a `finally` when any mutation happened; surface partial failure in the modal, not `alert`.
- `vaultSave.ts`: on 409, fetch `/api/vault/metadata` and store the new version so Retry is meaningful; on network errors retry once on `window` `online`.
- Login page: distinguish "KyVault backend unreachable" (fetch threw or 5xx) from "SSO not configured" (200 with `enabled:false`); add a Retry button; read `?error=` and `?error_description=` set by the OIDC callback and show them.
- `api.ts`: on 401 from any authenticated call, dispatch a `kyvault:unauthorized` event; `App.tsx` listens, clears state and shows the login page with "Your session ended."
- `AdminPanel`: `auditValid` is `boolean | "loading" | "error"`; only `false` shows the red badge; show `writeFailures` from `/api/audit/verify`.
- `AdminBackup`: drill failure renders red; `keyHealthy` checked before `paired`; refresh does not overwrite dirty form fields; empty interval field is a validation error, not "off"; drill button gated like Back up now.
- Pairing modal: QR dark-on-light using theme tokens; countdown from server `expiresAt`; error state offers Generate again; clear the unused `secret` state.
- Clipboard: `await navigator.clipboard.writeText` and show failure; clear the clipboard 30 s after copying a password or TOTP (only if clipboard still holds it).
- Object URL downloads: append anchor, click, revoke in `setTimeout(..., 1000)`; one shared `downloadBlob()` in `lib/download.ts` used by `App.tsx`, `EntryAttachments`, `AdminBackup`.
- `index.html`: `favicon.ico` + `favicon.png` + `apple-touch-icon`; delete duplicate `app-icon.png` if identical to `logo.png`.
- `lockedDraft.ts`: zero the decrypted buffer in `openDraft`; fix the header comment.
- `storage.ts`: resolve on `transaction.oncomplete`, add `onblocked`.
- `HistoryModal`/`SecuritySettings`/`AdminPanel`: clear stale error/message before each action; correct "Loading snapshots…" on the conflicts tab; format `lastSeenAt` safely.
- Vite dev proxy: add `/scim`.

## Phase 3: Annoyances

- Responsive vault: below 900px the three panes become a stack with a folder drawer and a list→detail push; below 600px the nav collapses. Screenshots at 1280/900/390 in the PR.
- Routing: hash router (`#/vault`, `#/security`, `#/admin/users`, `#/vault/<entryUuid>`) so refresh and back work; no new dependency (`useSyncExternalStore` on `hashchange`).
- One `Dialog` component (`<dialog>` + `showModal`, Escape, focus return, labelled close) replaces every `div.modal-overlay`; one `useConfirm()` hook replaces `confirm()`/`prompt()`/`alert()` everywhere. Backdrop click never discards typed state.
- First-run: when `meta.version === 0`, show "Create your master password" with confirm field, strength meter, the 12-char rule, and an offer to generate the paper code immediately.
- New entry opens the editor without saving; Cancel on a never-applied entry removes it.
- Selecting a folder clears the selected entry when it is not in the folder; "All Items" becomes a `<button>`.
- Paper code and vault key: Copy, Print, Hide-after-60s, and "type it back" before dismissing the paper code.
- Success messages survive modal close (lift to the page); disabled Rollback/Discard get a reason tooltip.
- Generator: persist settings in `localStorage`; guarantee one char per selected class; refuse zero classes; length 8–128 with number input; "Use password" confirms overwrite.
- Admin: pin-key confirm dialog stating write-once and showing the key ID after; audit pagination (`?before=`); verify runs only on the Audit tab; "daily"/"hourly" labels; copy buttons for SCIM URL; role change dropdown (uses Phase 1 guard).
- Login page: theme switcher moves to the page corner, labelled.
- Unlock modal: `autocomplete="current-password"`, backdrop click does not close while unlocking.

## Phase 4: Missing features

- Folders: delete (moves contents to Recycle Bin) and move (drag or "Move to…" select).
- Entries: sort (title/modified), tags, favourites, expiry date with badge, custom fields (kdbxweb `fields`), icon picker. Search covers tags and custom fields.
- Import KDBX (merge by UUID with kdbxweb `merge`) and Bitwarden JSON; column mapping for Generic CSV; export CSV (with a plaintext warning).
- Generator: passphrase mode from the EFF long wordlist (bundled), entropy meter, look-alike exclusion.
- Health report: weak (zxcvbn-ts or length/class heuristics), reused, expired, and HIBP k-anonymity range check (opt-in, hashed prefix only).
- Vault key rotation: new key, re-encrypt KDBX, re-wrap password + recovery envelopes, drop device envelopes, revoke devices; single confirmed flow.
- Devices: "this device" marker, rename, revoke all others; pairing modal polls `/api/devices` and closes on success.
- Snapshot preview: open a snapshot read-only with the current key and diff entry counts before rollback; conflict comparison in both directions and recover into the original folder when it exists.
- PWA: `manifest.webmanifest`, `theme-color`, icons; no service worker (offline unlock is out of scope by AGENTS.md).
- Locked-draft inventory: enumerate `IndexedDB` drafts for this account on unlock and delete any older than 7 days.

## Phase 5: Browser extension (Chrome + Firefox, Manifest V3)

**Location:** `extension/` in this repo, Vite + TypeScript, importing `../frontend/src/lib/{kdbx,vaultCrypto,totp,passwordReuse}` directly so the crypto stays one implementation. Separate `package.json`; CI job `extension` runs `npm test && npm run build` and `web-ext lint`.

**Pairing:** options page takes server URL + PIN → `POST /api/devices/pairing/redeem` with `{codeOrPin, deviceName, platform:"extension"}` → stores `sessionToken` (Bearer) in `chrome.storage.local`. Host permission for the entered origin is requested at that moment via `permissions.request` from `optional_host_permissions: ["https://*/*"]`, which is what Firefox MV3 requires. HTTPS only.

**Unlock:** `GET /api/vault/metadata` + `GET /api/vault/kdbx` with Bearer; user types the master password in the popup; `unwrapVaultKey` → `KeePassVault.open`. The vault key lives only in `chrome.storage.session` (memory, cleared on browser exit) with the same 1/5/15/30/60-minute idle lock as the web app. The extension CSP needs `'wasm-unsafe-eval'` for hash-wasm.

**Popup:** entries matching the active tab's registrable domain first, then search; copy username/password/TOTP with the 30 s clipboard clear; "Fill" injects via `scripting.executeScript` into the focused frame and sets `input[type=password]` and the nearest username field, dispatching `input` events. No autofill without a click.

**Write path (5b):** "Save login" from the popup creates an entry and uploads with `If-Match`; 409 shows "vault changed elsewhere, unlock again to refresh".

**Server:** none required. 401 from any call → "This device was revoked, pair again." The device shows up in Security → Devices with platform "extension".

**Firefox specifics:** `browser_specific_settings.gecko.id`, `background.scripts` alongside `service_worker`, `web-ext run` for manual testing. Store submission steps are documented but not automated.
