# KyVault Browser Extension

## Purpose

Chrome and Firefox MV3 extension that pairs with KyVault as a device, unlocks
the vault with the master password in the browser, lists entries for the
current site, and fills or copies credentials on click.

## Ownership

Owns `extension/` only. `frontend/src/lib` stays owned by `frontend/`; this
directory imports from it read-only through `../frontend/src/lib`.

## Local Contracts

- No runtime dependencies. `extension/package.json` carries devDependencies
  only; crypto (`kdbxweb`, `hash-wasm`) resolves through `../frontend/src/lib`
  into `frontend/node_modules`, so `npm ci` runs in `frontend/` before
  `extension/`.
- The vault key lives only in the background worker's memory and
  `chrome.storage.session`. Never in `storage.local`, a content script, or a
  message to a page. `storage.local` holds only server origin, session token,
  device id, device name and settings such as auto-lock minutes.
- HTTPS only to the paired server origin, `redirect: "error"`,
  `credentials: "omit"`. No telemetry, no analytics, no remote code.
- Fill and save act only on a click in the popup. No content script is
  registered in the manifest; `content/fill.js` is injected by
  `scripting.executeScript` at click time.
- Two manifests, one source: `src/manifest.ts` exports `chromeManifest()` and
  `firefoxManifest()`; `scripts/pack.mjs` writes each into
  `dist/chrome/manifest.json` and `dist/firefox/manifest.json`. Edit the
  source, never a generated manifest.
- `optional_host_permissions: ["https://*/*"]`, no `host_permissions`.
  Pairing requests exactly the entered server's origin at redeem time.

## Work Guidance

- Copy: full sentences, no em-dashes, never the word "successfully". Errors
  say what to do next.
- Tests run under `node --test` through `tsx`; every task lands one.

## Verification

`npm test && npm run build && npm run lint` in `extension/` (`build` runs
`tsc` first, so it is the typecheck gate too; `lint` is `web-ext lint
--source-dir dist/firefox` and must report 0 errors). No browser automation
in CI; loading `dist/chrome` unpacked and `npm run run:firefox` are manual
checks.

## Child DOX Index

- `src/manifest.ts` and `src/manifest.test.ts`: the manifest source and its
  MV3 permission/CSP/background-shape test (Task 1).
- `src/lib/serverUrl.ts`, `src/lib/pairing.ts`, `src/lib/settings.ts`,
  `src/messages.ts`, `src/options/main.ts`, `src/background.ts` (Task 2):
  pairing from the options page. `parseServerOrigin` accepts only a bare
  `https:` origin (no user/password, path dropped). The options page runs
  `parseServerOrigin` then `ext.permissions.request` then the redeem fetch
  all inside the Pair button's click handler, with no `await` before the
  permission request other than parsing the typed address. Chrome and
  Firefox refuse `permissions.request` outside a user gesture, and a gesture
  does not survive a hop through `runtime.sendMessage`. On success the
  options page writes `serverOrigin`, `sessionToken`, `deviceId`,
  `deviceName` to `storage.local` itself (the only place those four keys are
  written) and sends `{type: "paired"}` so the background worker clears
  `storage.session`. Unpair sends `{type: "unpair"}`: the background worker
  makes a best-effort `DELETE /api/devices/{id}` with the bearer token, then
  clears the four pairing keys (keeping the `autoLockMinutes` preference),
  clears `storage.session`, and releases the granted host permission. The
  device stays listed in Security, then Devices, until revoked there. The
  options page says so. `{type: "status"}` reports `paired`/`unlocked`/
  `serverOrigin`/`deviceName` from `storage.local`; the options page's own
  paired-or-not render decision asks the background worker for this instead
  of reading `sessionToken` into page memory for a truthiness check.
  `pair()` rejects a device name outside 1 to 64 code points or containing a
  control character, matching the server's rename rule; the input also gets
  `maxlength="64"`. `serverUrl.test.ts` and
  `pairing.test.ts` are the plan's pinned tests; `pairing.ts`'s `PairIO` is
  the seam that lets them run without a browser.
- `src/lib/session.ts`, `src/lib/lock.ts`, `src/lib/vaultState.ts`,
  `src/background.ts`, `src/popup/` (Task 3): unlock and idle lock.
  State model:
  - Worker memory: the open `KeePassVault`, its version and checksum. The
    unwrapped key bytes exist only for one `KeePassVault.open` call and are
    zeroed after it. The password is used once for
    `unwrapVaultKeyFromEnvelopes` and dropped; it is never stored or logged.
  - `storage.session` (default access level, trusted contexts only): `keyHex`
    and `lockAt`. Cleared on lock and by the browser on exit.
  - `storage.local`: only the allowlist above; `autoLockMinutes` is the idle
    window. `session.test.ts` fails if any file but `lib/settings.ts` calls
    `storage.local.`, if `keyHex` appears outside `vaultState.ts`, or if
    anything calls `setAccessLevel`.
  Unlock: metadata, envelope unwrap, `GET /api/vault/kdbx`, `KeePassVault.open`
  with the hex credential; the version comes from the kdbx response's
  `X-Vault-Version`. `InvalidKey` after a good unwrap means the key was
  rotated elsewhere: lock and say so. Only an AES-GCM `OperationError` means a
  wrong password; a malformed or unknown-kdf envelope gets its own sentence
  pointing at the web app. Lock rules: `lockAt = now + minutes`,
  armed as alarm `lock`; every message runs `status()` first, which locks when
  `isLocked` says so by the clock (a missed alarm cannot extend the window, and
  a deadline further ahead than the window plus a minute means the clock went
  backwards, so it locks). `ensure` (the popup's open, later `entries`) extends
  the deadline and, after worker eviction, reopens from `keyHex` without the
  password. `lock()` bumps a generation so an unlock in flight cannot commit
  after it. 401 rule: `serverFetch` calls `forgetSession` (drops
  `sessionToken` and `deviceId`, keeps `serverOrigin` and `deviceName`),
  the state locks, and the popup shows the revoked sentence with an options
  link. Every request goes through `serverFetch`: bearer header,
  `credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`, a 120 s
  timeout that also covers the body (`readBody` maps it to a sentence), and the stored origin re-checked as bare `https:`. The background
  answers only its own extension pages (`sender.url` under
  `runtime.getURL("")`). The popup imports `frontend/src/ky-ui/tokens.css`
  for the Busnes themes. `vaultState.test.ts` holds the one real crypto round
  trip (Argon2id envelope, Argon2d KDBX) plus the state machine on fakes.
- `src/lib/domain.ts`, `src/lib/rank.ts`, `src/lib/vaultState.ts` (`listEntries`,
  `secret`), `src/background.ts`, `src/popup/main.ts` (Task 4): the popup list, site
  ranking, search and copy.
  - `registrableDomain`/`sameSite` are a suffix heuristic (last two labels, or three
    under a listed second-level suffix such as `co.uk`), not the Public Suffix List.
    `ponytail:` a site under an unlisted multi-label suffix (`example.github.io`) ranks
    its neighbours as matches; upgrade path is vendoring the PSL's ICANN section as a
    generated module like `effWordlist.ts` when a report shows it matters.
  - `rankEntries` without a query keeps only exact-host and same-registrable-domain
    entries (tier 0/1), site tier first, each tier sorted by title. With a query it
    searches every entry (`entryMatches`, so tags and custom field names match too) and
    still sorts site matches first. `EntryView` never carries the password or TOTP seed.
  - The popup only ever holds `EntryView`s and one secret at a time. `entries` message
    reads the active tab's host through `activeTab` (no `tabs` permission) and calls
    `vaultState.listEntries`, which also extends the idle deadline. `copy` message
    generates one field (`generateTOTP` for TOTP) on demand; the popup, not the
    background, writes the clipboard, since clipboard access needs a document.
  - Copy clear: the popup's `copyText(..., {clearAfterMs})` timer dies with the popup,
    so it also sends `{type: "copied", digest}` (a SHA-256 of the value, never the value
    itself) and the background arms alarm `clipboard` for 30 seconds. On Chrome the
    alarm opens `offscreen.html`, which blind-writes a space over the clipboard via
    `execCommand("copy")` and closes; Firefox has no offscreen API, so there the clear
    only happens while the popup stays open. The toast says which is true for the
    running browser (checked via `typeof ext.offscreen`, since @types/chrome always
    types the namespace but only Chrome populates it at runtime).
  - `domain.test.ts` and `rank.test.ts` are the plan's pinned tests.
- `src/lib/fillTargets.ts`, `src/lib/fillTab.ts`, `src/content/fill.ts`,
  `vite.content.config.ts`, `src/background.ts` (`fill`), `src/popup/main.ts` (Task 5):
  fill on click.
  - The popup's Fill button sends `{type: "fill", uuid}`; it is disabled, with the reason
    as its title, when the entry's host is not the tab's site. The background enforces it
    regardless: `fillTab` refuses non-`http(s):` tabs, entries without a URL, entries whose
    host is not `sameSite` with the tab, and an `https:` entry on an `http:` page or frame.
  - Probe then fill: `content/fill.js` is injected with `files` into all frames. It reads
    field metadata only (never values), runs `chooseTargets`, and returns
    `{origin, count, targets}` as the IIFE's completion value (the `outro` in
    `vite.content.config.ts`; `treeshake: false` and `minify: false` keep `probe` by name).
    The credentials then go to one frame only, top frame first, whose origin passes the
    same checks, as `executeScript({func: fillFrame, args, frameIds})`. No message,
    storage or `window` property carries them.
  - `fillFrame` must reference nothing outside itself (it is serialized) and must not
    declare inner named functions (bundler name helpers do not exist in the frame). It
    refuses if the frame's origin, input count or target types changed since the probe,
    sets values through `HTMLInputElement.prototype`'s setter, fires bubbling `input` and
    `change`, never submits, and clears its credential locals.
  - `fillTargets.test.ts` (the plan's pinned tests), `fillTab.test.ts` (host and frame
    rules on fakes; `fillFrame` run from its source text in a `vm` fake DOM), and
    `src/content/fill.test.ts` (builds the content script with the real config, asserts no
    `import`/`export`, runs it as a classic script in a `vm` context, checks the returned
    probe and that no global was added).
  - `ponytail:` inputs inside shadow roots are not found; upgrade path is walking open
    shadow roots in `probe` and `fillFrame` alike.
