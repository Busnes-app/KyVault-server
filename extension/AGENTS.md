# KyVault Browser Extension

## Purpose

Chrome and Firefox MV3 extension that pairs with KyVault as a device, unlocks
the vault with the master password in the browser, lists entries for the
current site, fills or copies credentials on click, and saves a new login
typed into the popup.

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
  MV3 permission/CSP/background-shape test (Task 1). Chrome's background
  carries `service_worker` only; Firefox's carries `scripts` only (Firefox
  ignores `service_worker` and warns `BACKGROUND_SERVICE_WORKER_IGNORED` if
  it is present, and has run `background.scripts` regardless of that key
  since Firefox 121). Firefox has no Offscreen API; `scripts/pack.mjs` drops
  `offscreen.js`/`offscreen.html` from `dist/firefox`. `web-ext lint --source-dir dist/firefox` is 0 errors, 2
  warnings (`KEY_FIREFOX_*_UNSUPPORTED_BY_MIN_VERSION`, explained in the
  README); raising `strict_min_version` to silence them would drop Firefox
  128 through 139 support for a manifest field with no runtime effect, so it
  stays at 128 and the warnings are documented instead.
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
  makes a best-effort `DELETE /api/devices/{id}` through `serverFetch` (a 401
  there is ignored), then clears the four pairing keys (keeping the
  `autoLockMinutes` preference), clears `storage.session`, and releases the
  granted host permission. The DELETE removes the device from Security, then
  Devices, when the server can be reached; the options page says so. The paired
  view also carries the "Lock the vault after" select; it sends
  `{type: "setAutoLock"}` and the worker saves it, then gives an unlocked vault
  a fresh deadline under the new window (`rearm`), since `status()` reads a
  deadline beyond the window as a backwards clock and would lock. `{type: "status"}`
  reports `paired`/`unlocked`/`serverOrigin`/`deviceName`/`autoLockMinutes`
  from `storage.local`; the options page's own
  paired-or-not render decision asks the background worker for this instead
  of reading `sessionToken` into page memory for a truthiness check.
  `pair()` rejects a device name outside 1 to 64 code points or containing a
  control character, matching the server's rename rule; the input also gets
  `maxlength="64"`. `serverUrl.test.ts` and
  `pairing.test.ts` are the plan's pinned tests; `pairing.ts`'s `PairIO` is
  the seam that lets them run without a browser. The options page builds it
  with `browserPairIO`, which calls `fetch` unbound: a bare `fetch` stored on
  an object throws "Illegal invocation" in the browser.
- `src/lib/session.ts`, `src/lib/lock.ts`, `src/lib/vaultState.ts`,
  `src/background.ts`, `src/popup/` (Task 3): unlock and idle lock.
  State model:
  - Worker memory: the open `KeePassVault`, its version and checksum. The
    unwrapped key bytes exist only for one `KeePassVault.open` call and are
    zeroed after it. Also `lastServerContact`, the time of the last answered
    request or revocation check attempt. The password is used once for
    `unwrapVaultKeyFromEnvelopes` and dropped; it is never stored or logged.
  - `storage.session` (default access level, trusted contexts only): `keyHex`,
    `lockAt`, `envelope` (the password envelope the key was unwrapped from, for
    the save path's rotation check) and `lastServerContact`, written with `lockAt` and after each confirmed save. Cleared on lock and by the browser on exit.
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
  link. List, copy and fill work from memory, so an unlocked `status` or
  `entries` message first runs `checkDevice`: when the last server contact is
  more than 60 seconds old it sends one `GET /api/vault/metadata` (5 s
  timeout). A 401 takes the revoked path; an unreachable server is ignored and
  retried a minute later. `unlock` waits for a save in flight before it locks,
  so its download includes that save; the alarm lock stays immediate.
  Every server request, unpair's DELETE included, goes through `serverFetch`;
  the one exception is the pairing redeem in `pairing.ts`, which has no token
  yet and sets the same options itself. `serverFetch` sets the bearer header,
  `credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`, a 120 s (unpair 15 s)
  timeout that also covers the body (`readBody` maps it to a sentence), and the stored origin re-checked as bare `https:`. The background
  answers only its own extension pages (`sender.url` under
  `runtime.getURL("")`). The popup imports `frontend/src/ky-ui/tokens.css`
  for the Busnes themes. `vaultState.test.ts` holds the one real crypto round
  trip (Argon2id envelope, Argon2d KDBX) plus the state machine on fakes.
- `src/lib/domain.ts`, `src/lib/rank.ts`, `src/lib/vaultState.ts` (`listEntries`,
  `secret`), `src/background.ts`, `src/popup/main.ts` (Task 4): the popup list, site
  ranking, search and copy.
  - `registrableDomain`/`sameSite` are a suffix heuristic (last two labels, or three
    under a listed second-level suffix such as `co.uk`), not the Public Suffix List, and
    they only order the list. `ponytail:` a site under an unlisted multi-label suffix
    (`example.github.io`) ranks its neighbours as matches; upgrade path is vendoring the
    PSL's ICANN and PRIVATE sections as a generated module like `effWordlist.ts`.
  - `mayFill(entryHost, pageHost)` is the only fill authorization: exact host equality,
    nothing else. No suffix guessing and no subdomain inheritance, so tenants under a
    shared suffix (`victim.github.io` and `evil.github.io`) and tenant sites under a
    service's own domain (`evil.neocities.org` for a `neocities.org` login) never receive
    another host's credentials (`domain.test.ts`, `fillTab.test.ts`). `ponytail:` per-entry
    extra hosts are the upgrade path for multi-host services.
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
    so it also sends `{type: "copied"}` and the background arms alarm `clipboard` for
    30 seconds. On Chrome the alarm runs `lib/clipboardClear.ts`: open `offscreen.html`
    (or reuse one left open), send it `{type: "offscreenClear"}`, which blind-writes a
    space over the clipboard via `execCommand("copy")` and replies, then close it from
    the background even if the clear failed (a close error is swallowed). An offscreen
    document has only `chrome.runtime`, so it cannot close itself. The second browser
    pass confirmed the worker-to-offscreen message and that the document is closed
    after each clear. `clipboardClear.test.ts` checks that
    consecutive copies each clear. Firefox has no offscreen API, so there the clear
    only happens while the popup stays open. The toast says which is true for the
    running browser (checked via `typeof ext.offscreen`, since @types/chrome always
    types the namespace but only Chrome populates it at runtime).
  - `domain.test.ts` and `rank.test.ts` are the plan's pinned tests.
- `src/lib/fillTargets.ts`, `src/lib/fillTab.ts`, `src/content/fill.ts`,
  `vite.content.config.ts`, `src/background.ts` (`fill`), `src/popup/main.ts` (Task 5):
  fill on click.
  - The popup's Fill button sends `{type: "fill", uuid}`; it is disabled, with the reason
    as its title, when `mayFill` refuses the tab host. The background enforces it
    regardless: `fillTab` refuses non-`http(s):` tabs, entries without a URL, tabs and
    frames that `mayFill` refuses, and an `https:` entry on an `http:` page or frame.
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
    rules on fakes; `fillFrame` run from its source text in the `vm` fake DOM of
    `fillFrame.fixture.ts`), and `src/content/fill.test.ts` (builds the content script with
    the real config, asserts no `import`/`export`, runs it as a classic script in a `vm`
    context, checks the returned probe and that no global was added; also builds the
    background bundle and runs the minified `fillFrame` text through the same fixture).
  - `ponytail:` inputs inside shadow roots are not found; upgrade path is walking open
    shadow roots in `probe` and `fillFrame` alike.
- `src/lib/save.ts`, `src/lib/vaultState.ts` (`saveLogin`), `src/background.ts`
  (`saveLogin`), `src/popup/main.ts` (Task 6): save login, the extension's only write.
  - The popup form (title and address prefilled from the active http(s) tab, username,
    password with Generate from `generatePassword.ts` defaults) sends the typed values
    once and clears only on success. Any other error keeps the typed values, says the
    save could not be confirmed (a lost answer may hide a stored entry) and refreshes
    the list quietly: a failed refresh never replaces the view. Page
    fields are never read. `saveLogin` refuses a blank title, an
    empty password, or an address that is not `http(s):`.
  - Order: `ensure`, then `GET /api/vault/metadata` and compare its `passwordEnvelope`
    with the session's `envelope`; a mismatch locks with the rotation sentence before
    anything is created or uploaded. Then one `createEntry` in `getLiveGroups()[0]`,
    `exportBinary`, raw `POST /api/vault/upload` with `If-Match: "<version>"` and
    `X-Device-ID`. Success sets the in-memory version to the returned
    `metadata.version`, which must be a safe integer above the sent one.
  - 409 locks and throws `LockedError` ("The vault changed elsewhere. Unlock again to
    refresh, then add the login again."); the server keeps the rejected bytes under
    `conflicts/`. Never retry with the newer version. 401 is the revoked path. Any other
    failure drops the in-memory vault (not `deleteEntry`, which would recycle it) so the
    next request re-downloads it from `keyHex`. `createEntry` mutates the shared
    in-memory vault before the upload, so a concurrent `entries` may list the new
    login until the upload settles.
  - Saves are serialised behind one promise per worker. `LockedError` takes a message,
    and the popup's locked form shows it.
  - `save.test.ts`: the plan's upload tests, a real KDBX round trip (headers, bytes
    reopened with the key, entry in the root group), serialised versions, 409 lock,
    no phantom after a 500, envelope mismatch refusing before upload, and input checks.
