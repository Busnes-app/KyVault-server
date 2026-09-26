# Phase 5: Browser Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Chrome and Firefox extension (Manifest V3) that pairs with KyVault like any other device, unlocks the vault with the master password in the browser, lists entries for the current site, copies and fills credentials on click, generates TOTP codes, and (5b) saves a new login through the version-checked upload path.

**Architecture:** `extension/` is a second Vite + TypeScript project that imports `../frontend/src/lib/{kdbx,vaultCrypto,totp,passwordReuse,entryMeta,clipboard,autoLock}` directly, so there is one crypto implementation. The background worker is the single owner of the network session and the open vault; the popup and options page are thin views that talk to it over `runtime.sendMessage`. The vault key lives only in `chrome.storage.session`. The server needs no change: the extension is a bearer device (`currentSession` in `internal/api/server.go` reads `Authorization: Bearer`, and `validCSRF` exempts bearer callers).

**Tech Stack:** Vite 8, TypeScript 7, `tsx --test`, kdbxweb 2.x and hash-wasm 4.x resolved from `frontend/node_modules`, `web-ext` for lint and manual runs, `@types/chrome` for typings.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md`, "Phase 5: Browser extension". Facts checked against the worktree while planning:

- `POST /api/devices/pairing/redeem` (`internal/api/device_handlers.go`, `PairingRedeemRequest`) takes `{codeOrPin, deviceName, platform, deviceEnvelope?}`, needs no session, and answers `{ok, deviceId, sessionToken, user: {id}}`. `platform` is stored verbatim and shown in Security → Devices. The 90-day bearer session carries `DeviceID`; revoking the device deletes it (Phase 4b), so a revoked extension gets 401 on its next call.
- `GET /api/vault/metadata` returns `vault.Metadata` (`version`, `checksum`, `sizeBytes`, `updatedAt`, `passwordEnvelope`, `recoveryEnvelope`, device envelopes). There is no `keyRotated` flag; a rotated key shows up as `KeePassVault.open` failing with `InvalidKey` (`isWrongVaultKey` in `kdbx.ts`), and `unwrapVaultKey` on the new envelope fixes it.
- `GET /api/vault/kdbx` answers 404 "vault does not exist yet" at version 0 and otherwise sets `ETag: "<version>"`, `X-Vault-Version` and `X-Vault-Checksum`. The extension takes its version from that response, not from the earlier metadata call, so the two cannot disagree.
- `POST /api/vault/upload` with a raw body reads `If-Match: "<version>"` and `X-Device-ID`; 409 carries `{currentVersion, expectedVersion, conflictId}` and the server keeps the rejected bytes under `conflicts/`.
- The server sends no CORS headers (`internal/api/headers.go`). Extension contexts fetch cross-origin when the origin is a granted host permission, which is why pairing requests it.
- `kdbx.ts`, `vaultCrypto.ts`, `totp.ts`, `passwordReuse.ts`, `entryMeta.ts`, `clipboard.ts` and the pure exports of `autoLock.ts` (`AUTO_LOCK_MINUTES`, `parseAutoLockMinutes`, `IdleDeadline`) touch no `window`, `document` or `localStorage` at import time. `api.ts` (cookies, `window` events), `storage.ts` (IndexedDB) and `keyRotation.ts` are not imported.

**Decision: master password on every unlock, no device envelope.** The roadmap's popup-takes-the-password design is the one to build. A device-wrapped envelope (`deviceEnvelope` on redeem, as KyAuth uses) would need a device secret in `chrome.storage.local`, which sits on disk beside the wrapped key; for a profile-copy attacker that pair is the vault key, and the extension has no CSP-backed page isolation story equal to the web app's. Typing the password costs one Argon2id derivation (64 MiB, about a second) per unlock and leaves nothing on disk. Revocation is then complete: the server deletes the session and the extension holds no key material. `ponytail:` a device envelope is the upgrade path if unlock friction is measured to matter; it would reuse `wrapVaultKey` with a random device secret and land through the existing `deviceEnvelope` field.

## Global Constraints

- Branch `feat/phase5-extension` stacked on `feat/phase4b-features` (PR #64); rebase onto `master` once #62 and #64 merge. One PR. Commit after every task.
- No runtime dependencies beyond what `frontend/` already has (kdbxweb, hash-wasm). `extension/package.json` has only devDependencies; the crypto modules resolve through `../frontend/src/lib` to `frontend/node_modules`, so `npm ci` runs in `frontend/` before `extension/`.
- No telemetry, no analytics, no remote code. The extension never sends the master password, the vault key, or any plaintext field anywhere. The only network peer is the paired server origin, over HTTPS, with `redirect: "error"` and `credentials: "omit"`.
- The vault key exists in `chrome.storage.session` (default access level, trusted contexts only) and in the background worker's memory. Never in `storage.local`, never in a content script, never in a message to a page.
- Fill and Save act only on a click in the popup. No autofill on page load, no content script registered in the manifest; `content/fill.js` is injected by `scripting.executeScript` at click time.
- Copy rules: full sentences, no em-dashes, never the word "successfully". Errors say what to do next.
- Tests under `node --test` through `tsx`; every task lands one. No browser automation in CI; the browser pass is the controller's job with a written checklist.
- DOX: create `extension/AGENTS.md` (Task 1) and add an `extension/` line to the root Child DOX Index. Each later task updates `extension/AGENTS.md`. Root AGENTS.md Verification lists the `extension` CI job.

## Review Focus

1. Key material: `grep -rn "storage.local" extension/src` shows only `serverOrigin`, `sessionToken`, `deviceId`, `deviceName`, `autoLockMinutes`. Pinned: Task 3 `session.test.ts` and the manual check in Task 8.
2. Host permission scope: the manifest has `optional_host_permissions: ["https://*/*"]` and no `host_permissions`; pairing requests exactly `origin + "/*"` for the entered server. Pinned: Task 1 `manifest.test.ts`, Task 2 `pairing.test.ts`.
3. Fill never crosses domains: the injected script fills only when `location.hostname` is the entry's registrable domain or a subdomain of it, and only after the user clicked Fill. Pinned: Task 5 `fillTargets.test.ts` and the frame filter in `content/fill.ts`.
4. Save uses `If-Match` with the version from the download response and treats 409 as "lock and re-unlock", never as "retry with the new version". Pinned: Task 6 `save.test.ts`.
5. 401 means revoked: the session token is deleted and the popup says so. No retry loop against a revoked token. Pinned: Task 3 `session.test.ts`.

---

### Task 1: Scaffold, manifests, CI job

**Files:**
- Create: `extension/package.json`, `extension/tsconfig.json`, `extension/vite.config.ts`, `extension/vite.content.config.ts`, `extension/scripts/pack.mjs`, `extension/src/manifest.ts`, `extension/src/manifest.test.ts`, `extension/src/ext.ts`, `extension/popup.html`, `extension/options.html`, `extension/offscreen.html`, `extension/src/popup/main.ts` (placeholder), `extension/src/options/main.ts` (placeholder), `extension/src/background.ts` (placeholder), `extension/src/content/fill.ts` (placeholder), `extension/src/offscreen.ts` (placeholder), `extension/public/icons/{16,32,48,128}.png`, `extension/README.md`, `extension/AGENTS.md`, `extension/.gitignore`
- Modify: `.github/workflows/ci.yml` (`extension` job, `security` job audit step), `.github/dependabot.yml`, `AGENTS.md`

**Layout:** `vite build` writes pages, background and shared chunks to `build/`; `vite build -c vite.content.config.ts` writes `build/content/fill.js` as a single IIFE (content scripts cannot import chunks); `scripts/pack.mjs` copies `build/` to `dist/chrome/` and `dist/firefox/` and writes each browser's `manifest.json`. `web-ext lint` and `web-ext run` point at `dist/firefox`; Chrome loads `dist/chrome` unpacked.

**Icons:** `magick KyVault.png -resize 128x128 extension/public/icons/128.png` and the same for 48, 32, 16, from the tracked 1024px master at the repo root. Never label a file with a size it is not.

**Interfaces:**

`extension/src/ext.ts`, the one browser shim:

```ts
// Firefox exposes promise-returning APIs on both namespaces; Chrome only on chrome.
export const ext: typeof chrome = (globalThis as { browser?: typeof chrome }).browser ?? chrome;
```

`extension/src/manifest.ts`:

```ts
import { version } from "../package.json";

const shared = {
  manifest_version: 3,
  name: "KyVault",
  version,
  description: "Fill logins from your KyVault vault. Zero knowledge: the server never sees your passwords.",
  icons: { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" },
  action: { default_popup: "popup.html", default_title: "KyVault" },
  options_ui: { page: "options.html", open_in_tab: true },
  permissions: ["storage", "alarms", "activeTab", "scripting"],
  optional_host_permissions: ["https://*/*"],
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'" },
} as const;

export function chromeManifest() {
  return { ...shared, permissions: [...shared.permissions, "offscreen"], background: { service_worker: "background.js", type: "module" }, minimum_chrome_version: "120" };
}

export function firefoxManifest() {
  return {
    ...shared,
    background: { scripts: ["background.js"], service_worker: "background.js", type: "module" },
    browser_specific_settings: { gecko: { id: "kyvault@busnes.app", strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } } },
  };
}
```

`package.json` scripts: `"build": "tsc && vite build && vite build -c vite.content.config.ts && node scripts/pack.mjs"`, `"test": "tsx --test \"src/**/*.test.ts\""`, `"lint": "web-ext lint --source-dir dist/firefox"`, `"run:firefox": "web-ext run --source-dir dist/firefox"`, `"watch": "vite build --watch"`. devDependencies: `vite`, `typescript`, `tsx`, `@types/chrome`, `@types/node`, `web-ext`, at the versions `frontend/package.json` pins where they overlap. `"type": "module"`.

`tsconfig.json`: copy `frontend/tsconfig.json`, drop `jsx`, add `"types": ["chrome", "node"]`, `"resolveJsonModule": true`, `"include": ["src", "scripts", "../frontend/src/lib"]`. No `rootDir`, so the sibling import compiles.

`vite.config.ts`: `build.outDir: "build"`, `emptyOutDir: true`, `sourcemap: false`, `rollupOptions.input: { popup: "popup.html", options: "options.html", offscreen: "offscreen.html", background: "src/background.ts" }`, `output: { entryFileNames: "[name].js", chunkFileNames: "chunks/[name]-[hash].js", assetFileNames: "assets/[name]-[hash][extname]" }`, `resolve.dedupe: ["kdbxweb", "hash-wasm"]`. `vite.content.config.ts`: `build.lib: { entry: "src/content/fill.ts", formats: ["iife"], name: "kyvaultFill", fileName: () => "content/fill.js" }`, `outDir: "build"`, `emptyOutDir: false`.

`scripts/pack.mjs`: `rm -rf dist`, `cp -r build dist/chrome`, `cp -r build dist/firefox`, then `writeFile(dist/<b>/manifest.json, JSON.stringify(manifest, null, 2))` for each, importing the two functions from `../src/manifest.ts` through `tsx` (`node --import tsx scripts/pack.mjs`, or make the script `pack.ts` run with `tsx`). Delete `build/manifest.json` if Vite copied one from `public/`; `public/` holds only `icons/`.

- [ ] **Step 1: Write the failing test**

```ts
// extension/src/manifest.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { chromeManifest, firefoxManifest } from "./manifest";

for (const [name, manifest] of [["chrome", chromeManifest()], ["firefox", firefoxManifest()]] as const) {
  test(`${name} manifest is MV3 with the minimum permission set`, () => {
    assert.equal(manifest.manifest_version, 3);
    assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
    assert.deepEqual(manifest.optional_host_permissions, ["https://*/*"]);
    assert.equal("host_permissions" in manifest, false);
    const perms = [...manifest.permissions].sort();
    const expected = name === "chrome" ? ["activeTab", "alarms", "offscreen", "scripting", "storage"] : ["activeTab", "alarms", "scripting", "storage"];
    assert.deepEqual(perms, expected);
    assert.equal("content_scripts" in manifest, false);
    assert.match(manifest.content_security_policy.extension_pages, /'wasm-unsafe-eval'/);
    assert.doesNotMatch(manifest.content_security_policy.extension_pages, /'unsafe-eval'|'unsafe-inline'|http/);
    assert.equal(manifest.background.service_worker, "background.js");
    assert.equal(manifest.background.type, "module");
    assert.equal(JSON.parse(JSON.stringify(manifest)).name, "KyVault");
  });
}

test("chrome has no background.scripts; firefox has scripts and a gecko id", () => {
  assert.equal("scripts" in chromeManifest().background, false);
  const ff = firefoxManifest();
  assert.deepEqual(ff.background.scripts, ["background.js"]);
  assert.equal(ff.browser_specific_settings.gecko.id, "kyvault@busnes.app");
  assert.deepEqual(ff.browser_specific_settings.gecko.data_collection_permissions, { required: ["none"] });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd extension && npm ci && npx tsx --test src/manifest.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement**

Write the files listed above. Placeholders export nothing and log nothing. `popup.html`, `options.html` and `offscreen.html` are minimal documents with `<script type="module" src="/src/popup/main.ts">` (and the matching two); no inline scripts, no inline styles (the CSP forbids neither, but keeping them external keeps the pages one shape). Add `extension/.gitignore` with `node_modules`, `build`, `dist`, `web-ext-artifacts`.

`extension/README.md`: how to build, load unpacked in Chrome, `npm run run:firefox`, and a "Store submission" section: Chrome Web Store (zip `dist/chrome`, developer dashboard listing, privacy tab: no user data collected, permission justifications for `storage`, `alarms`, `activeTab`, `scripting`, `offscreen`, optional host access "to reach the KyVault server you pair with"), AMO (zip `dist/firefox`, upload source zip with `npm ci` and `npm run build` instructions because the bundle is minified, `data_collection_permissions` declared as none). Not automated.

`.github/workflows/ci.yml`, after `frontend`:

```yaml
  extension:
    name: Extension (Chrome + Firefox)
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: extension
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: |
            frontend/package-lock.json
            extension/package-lock.json
      # The crypto modules are imported from ../frontend/src/lib and resolve their
      # dependencies from frontend/node_modules, so both installs are needed.
      - run: npm ci
        working-directory: frontend
      - run: npm ci
      - name: npm test
        run: npm test
      # `build` is `tsc && vite build ...`, so this is the typecheck gate too.
      - name: npm run build
        run: npm run build
      - name: web-ext lint
        run: npm run lint
```

`security` job: add `npm audit --audit-level=high` in `extension/` after the frontend audit (needs its own `npm ci`). `publish.needs` gains `extension`. `dependabot.yml`: an `npm` entry for `/extension` with the `dev` group only (everything there is dev).

`extension/AGENTS.md` (Purpose, Ownership, Local Contracts, Work Guidance, Verification): purpose as above; owns `extension/` only; contracts: imports from `../frontend/src/lib` are read-only from here (change them in `frontend/`), no runtime dependencies, key material rules, HTTPS only, click-only fill, two manifests from one source; verification: `npm test && npm run build && npm run lint`. Root `AGENTS.md`: Child DOX Index line `- \`extension/\` — Chrome and Firefox MV3 extension; pairs as a device, unlocks with the master password in the browser, fills on click. See \`extension/AGENTS.md\`.` and the Verification list gains `extension` (`npm test && npm run build && npm run lint` in `extension/`), seven jobs named.

- [ ] **Step 4: Verify and commit**

Run: `cd frontend && npm ci && cd ../extension && npm ci && npm test && npm run build && npm run lint`. `web-ext lint` must report 0 errors; warnings about `service_worker` on Firefox are expected and named in the README. Load `dist/chrome` unpacked and confirm the popup opens with its placeholder.

```bash
git add extension .github/workflows/ci.yml .github/dependabot.yml AGENTS.md
git commit -m "extension scaffold: MV3 manifests for Chrome and Firefox, CI job"
```

---

### Task 2: Pairing from the options page

**Files:**
- Create: `extension/src/lib/serverUrl.ts`, `extension/src/lib/serverUrl.test.ts`, `extension/src/lib/pairing.ts`, `extension/src/lib/pairing.test.ts`, `extension/src/lib/settings.ts`, `extension/src/messages.ts`
- Modify: `extension/src/options/main.ts`, `extension/options.html`, `extension/src/background.ts`, `extension/AGENTS.md`

**Interfaces:**
- `settings.ts`: `type Settings = { serverOrigin?: string; sessionToken?: string; deviceId?: string; deviceName?: string; autoLockMinutes: AutoLockMinutes }`; `loadSettings()` / `saveSettings(patch)` over `ext.storage.local`, parsing `autoLockMinutes` with `parseAutoLockMinutes` from `../../frontend/src/lib/autoLock`. Nothing else is ever written to `storage.local`.
- `serverUrl.ts`: `parseServerOrigin(input: string): string` returns `new URL(input).origin` when the protocol is `https:`, there is no username or password, and the host is not empty; throws `Error("Enter the server address as https://host, no path.")` otherwise. A path is tolerated and dropped, since people paste the login page URL.
- `pairing.ts`: `pair(io, origin, codeOrPin, deviceName)`: `io.requestHost(origin + "/*")` (wraps `ext.permissions.request({ origins })`), then `io.fetch(origin + "/api/devices/pairing/redeem", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ codeOrPin, deviceName, platform: "extension" }), credentials: "omit", redirect: "error" })`. Refuses when permission is denied ("KyVault needs access to that server to pair."), maps 400 to the server's text (it is the pairing error: expired, wrong code), 401 to "The account is inactive or signed out.", other statuses to "The server answered <status>.". Returns `{ deviceId, sessionToken }` after checking both are non-empty strings; `platform` is the literal `"extension"`.
- `messages.ts`: the request union the popup and options page send and the response shapes. Task 2 adds `{ type: "paired" }` (background clears any vault state) and `{ type: "status" }` → `{ paired: boolean; unlocked: boolean; serverOrigin?: string; deviceName?: string; lockAt?: number }`.

- [ ] **Step 1: Write the failing tests**

```ts
// extension/src/lib/serverUrl.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseServerOrigin } from "./serverUrl";

test("accepts https origins and drops the path", () => {
  assert.equal(parseServerOrigin("https://vault.example.com/login?x=1"), "https://vault.example.com");
  assert.equal(parseServerOrigin(" https://vault.example.com:8443 "), "https://vault.example.com:8443");
});

test("refuses http, credentials in the URL, and junk", () => {
  for (const bad of ["http://vault.example.com", "https://user:pw@vault.example.com", "vault.example.com", "", "ftp://x", "https://"]) {
    assert.throws(() => parseServerOrigin(bad), /https:\/\/host/, bad);
  }
});
```

```ts
// extension/src/lib/pairing.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { pair } from "./pairing";

function io(opts: { grant: boolean; status: number; body: unknown }) {
  const calls: { origins?: string[]; url?: string; init?: RequestInit } = {};
  return {
    calls,
    requestHost: async (pattern: string) => { calls.origins = [pattern]; return opts.grant; },
    fetch: async (url: string, init: RequestInit) => {
      calls.url = url; calls.init = init;
      return new Response(typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body), { status: opts.status });
    },
  };
}

test("requests exactly the server origin and posts platform extension", async () => {
  const fake = io({ grant: true, status: 200, body: { ok: true, deviceId: "d1", sessionToken: "t1", user: { id: "u1" } } });
  const got = await pair(fake, "https://vault.example.com", "123456", "Work laptop");
  assert.deepEqual(got, { deviceId: "d1", sessionToken: "t1" });
  assert.deepEqual(fake.calls.origins, ["https://vault.example.com/*"]);
  assert.equal(fake.calls.url, "https://vault.example.com/api/devices/pairing/redeem");
  assert.deepEqual(JSON.parse(fake.calls.init!.body as string), { codeOrPin: "123456", deviceName: "Work laptop", platform: "extension" });
  assert.equal(fake.calls.init!.credentials, "omit");
  assert.equal(fake.calls.init!.redirect, "error");
});

test("denied permission, expired code and inactive account are distinct messages", async () => {
  await assert.rejects(pair(io({ grant: false, status: 200, body: {} }), "https://v.example", "1", "n"), /needs access/);
  await assert.rejects(pair(io({ grant: true, status: 400, body: "pairing code expired or invalid\n" }), "https://v.example", "1", "n"), /expired or invalid/);
  await assert.rejects(pair(io({ grant: true, status: 401, body: "x" }), "https://v.example", "1", "n"), /inactive or signed out/);
  await assert.rejects(pair(io({ grant: true, status: 200, body: { ok: true } }), "https://v.example", "1", "n"), /did not return a session/);
});
```

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`pairing.ts`:

```ts
export type PairIO = { requestHost: (pattern: string) => Promise<boolean>; fetch: typeof fetch };

export async function pair(io: PairIO, origin: string, codeOrPin: string, deviceName: string) {
  if (!await io.requestHost(origin + "/*")) throw new Error("KyVault needs access to that server to pair. Allow it and try again.");
  const res = await io.fetch(origin + "/api/devices/pairing/redeem", {
    method: "POST", headers: { "Content-Type": "application/json" }, credentials: "omit", redirect: "error", cache: "no-store",
    body: JSON.stringify({ codeOrPin: codeOrPin.trim(), deviceName: deviceName.trim(), platform: "extension" }),
  });
  if (res.status === 400) throw new Error((await res.text()).trim() || "The pairing code was not accepted.");
  if (res.status === 401) throw new Error("The account is inactive or signed out. Sign in to KyVault and start pairing again.");
  if (!res.ok) throw new Error(`The server answered ${res.status}. Check the address and try again.`);
  const body = (await res.json()) as { deviceId?: unknown; sessionToken?: unknown };
  if (typeof body.deviceId !== "string" || !body.deviceId || typeof body.sessionToken !== "string" || !body.sessionToken) throw new Error("The server did not return a session. Try pairing again.");
  return { deviceId: body.deviceId, sessionToken: body.sessionToken };
}
```

Options page (`options/main.ts`, plain DOM, no framework): fields Server address, Pairing code or PIN, Device name (default "Browser extension"), idle lock select over `AUTO_LOCK_MINUTES`, a Pair button, and a status line. On Pair: `parseServerOrigin`, `pair({ requestHost: (p) => ext.permissions.request({ origins: [p] }), fetch }, ...)`, then `saveSettings({ serverOrigin, sessionToken, deviceId, deviceName })` and `ext.runtime.sendMessage({ type: "paired" })`. The permission request must run inside the click handler (Firefox requires a user gesture), so no `await` before it other than parsing. Paired state shows "Paired with <origin> as <name>." and an Unpair button that clears the four keys, sends `{ type: "paired" }`, and calls `ext.permissions.remove({ origins })`; it does not call the server (the device stays listed in Security → Devices until revoked there; the status line says so). The page explains where the code comes from: "In KyVault, open Security, then Devices, then Pair a device."

Background: on `paired` drop any in-memory vault and clear `storage.session` (Task 3 fills this in).

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd extension && npm test && npm run build && npm run lint`. Browser: against a local server over an HTTPS proxy (or a hosted instance), start pairing in the web app, redeem from the options page, confirm the device appears in Security → Devices with platform `extension`, and that Chrome's permission prompt names only the server origin.

`extension/AGENTS.md` Local Contracts: pairing flow, what `storage.local` may hold, the unpair semantics.

```bash
git add extension
git commit -m "extension pairing: options page redeems a PIN and pins the server origin"
```

---

### Task 3: Unlock, key handling, idle lock

**Files:**
- Create: `extension/src/lib/session.ts`, `extension/src/lib/session.test.ts`, `extension/src/lib/lock.ts`, `extension/src/lib/lock.test.ts`, `extension/src/lib/vaultState.ts`
- Modify: `extension/src/background.ts`, `extension/src/messages.ts`, `extension/src/popup/main.ts`, `extension/popup.html`, `extension/AGENTS.md`

**Interfaces:**
- `session.ts`: `class RevokedError extends Error` (message "This device was revoked. Pair again from the KyVault options page."). `serverFetch(io, path, init)`: reads `serverOrigin` and `sessionToken` through `io.settings()`, throws `Error("Pair this extension with your KyVault server first.")` without them, fetches `origin + path` with `Authorization: Bearer <token>`, `credentials: "omit"`, `redirect: "error"`, `cache: "no-store"`; on 401 calls `io.forget()` (deletes `sessionToken` and `deviceId`, keeps `serverOrigin` and `deviceName` so re-pairing is one field) and throws `RevokedError`. Never logs the token.
- `lock.ts`: `lockDeadline(now: number, minutes: AutoLockMinutes): number` and `isLocked(lockAt: number | undefined, now: number): boolean`. Pure; the alarm and the stored deadline both derive from it.
- `vaultState.ts` (background only): module-level `let open: { vault: KeePassVault; version: number; checksum: string } | undefined`. `unlock(password)`: `GET /api/vault/metadata`; 404 or `version === 0` → `Error("Create your vault in the KyVault web app first.")`; `unwrapVaultKeyFromEnvelopes([meta.passwordEnvelope, meta.recoveryEnvelope], password)`; then `download()`. `download()`: `GET /api/vault/kdbx`, version from `X-Vault-Version`, checksum from `X-Vault-Checksum`, `KeePassVault.open(bytes, key)`; on `isWrongVaultKey(err)` clear the key and throw `Error("The vault key changed. Unlock with your master password again.")`. `ensure()`: returns `open` when present; else reads `keyHex` and `lockAt` from `storage.session`; if `isLocked` or no key → `LockedError`; else `download()` with the stored key (this is the path after the service worker was evicted; it costs one download and one Argon2d open, no password). `lock()`: `open = undefined`, `storage.session.clear()`, `alarms.clear("lock")`. `touch()`: `lockAt = lockDeadline(Date.now(), settings.autoLockMinutes)`, write it to `storage.session`, `alarms.create("lock", { when: lockAt })`.
- Background message handlers: `unlock` → `{ ok: true }` or `{ error }`; `lock`; `status` (adds `lockAt`); `entries` (Task 4). Every handler except `status` calls `touch()` on success, so popup activity extends the deadline the same way page activity does in the web app.
- Popup: if not paired → "Pair this extension with your KyVault server first." with a button that opens the options page. If locked → password field (`autocomplete="current-password"`), Unlock button, "Unlocking takes about a second." while the message is in flight. Errors from the background are shown verbatim; a `RevokedError` also shows the options link.

The password crosses one `runtime.sendMessage` from popup to background, inside the extension process, and the background drops it after `unwrapVaultKeyFromEnvelopes` returns. The key is stored as hex in `storage.session` because the API stores JSON; it is cleared on lock and on browser exit by the platform.

- [ ] **Step 1: Write the failing tests**

```ts
// extension/src/lib/session.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { RevokedError, serverFetch } from "./session";

function io(status: number) {
  const seen: { url?: string; init?: RequestInit; forgot: number } = { forgot: 0 };
  return {
    seen,
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", autoLockMinutes: 5 as const }),
    forget: async () => { seen.forgot++; },
    fetch: async (url: string, init: RequestInit) => { seen.url = url; seen.init = init; return new Response("{}", { status }); },
  };
}

test("bearer, no cookies, no redirects", async () => {
  const fake = io(200);
  await serverFetch(fake, "/api/vault/metadata", { method: "GET" });
  assert.equal(fake.seen.url, "https://v.example/api/vault/metadata");
  assert.equal(new Headers(fake.seen.init!.headers).get("Authorization"), "Bearer tok");
  assert.equal(fake.seen.init!.credentials, "omit");
  assert.equal(fake.seen.init!.redirect, "error");
  assert.equal(fake.seen.forgot, 0);
});

test("401 forgets the session and says the device was revoked", async () => {
  const fake = io(401);
  await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), RevokedError);
  assert.equal(fake.seen.forgot, 1);
});

test("unpaired is a clear instruction, not a fetch", async () => {
  const fake = { ...io(200), settings: async () => ({ autoLockMinutes: 5 as const }) };
  await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), /Pair this extension/);
  assert.equal(fake.seen.url, undefined);
});
```

```ts
// extension/src/lib/lock.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { isLocked, lockDeadline } from "./lock";

test("deadline is minutes from now and a missing or past deadline is locked", () => {
  const now = 1_800_000_000_000;
  assert.equal(lockDeadline(now, 5), now + 300_000);
  assert.equal(isLocked(undefined, now), true);
  assert.equal(isLocked(now + 1, now), false);
  assert.equal(isLocked(now, now), true);
  // a clock set backwards must not extend the session
  assert.equal(isLocked(now + 3_600_000, now - 86_400_000), true);
});
```

For the last case `isLocked` returns true when `lockAt - now` exceeds the largest allowed window (60 minutes plus a minute of slack), so a backwards clock jump locks instead of granting a day.

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`lock.ts`:

```ts
import type { AutoLockMinutes } from "../../../frontend/src/lib/autoLock";
const MAX_WINDOW_MS = 61 * 60_000;
export function lockDeadline(now: number, minutes: AutoLockMinutes): number { return now + minutes * 60_000; }
export function isLocked(lockAt: number | undefined, now: number): boolean {
  return lockAt === undefined || lockAt <= now || lockAt - now > MAX_WINDOW_MS;
}
```

`session.ts` as specified; `serverFetch` takes `io: { settings, forget, fetch }` so the background passes the real ones and tests pass fakes. `background.ts` registers `ext.runtime.onMessage.addListener((msg, _sender, respond) => { handle(msg).then(respond, (e) => respond({ error: e instanceof Error ? e.message : String(e) })); return true; })` and `ext.alarms.onAlarm.addListener((a) => { if (a.name === "lock") void lock(); })`. On `runtime.onStartup` call `lock()` as belt and braces (session storage is already empty after a browser restart). The alarm's minimum delay is 30 seconds on Chrome 120 and above, so the 1-minute option is honoured; `ensure()` also checks `isLocked` on every call for the case where the worker slept through the alarm.

Popup shell: `popup.html` with a header (icon, "KyVault", a Lock button when unlocked), a `<main>` the script fills, and `styles.css` using the Busnes tokens copied from `frontend/src/styles/styles.css` (`--ky-bg #f8f6f0` / `#182326`, orange accent) behind `prefers-color-scheme`. Width 360px.

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd extension && npm test && npm run build && npm run lint`. Browser: unlock, close the popup, wait past the chosen interval, reopen: locked. Set 1 minute, unlock, kill the service worker from `chrome://serviceworker-internals`, reopen the popup within the minute: still unlocked after a short download, no password. Revoke the device in the web app, reopen: the revoked message and the options link. Inspect `chrome.storage.local` in DevTools: no `keyHex`.

`extension/AGENTS.md`: the state model (memory, session storage, local storage, what each holds), the lock rules, the 401 rule.

```bash
git add extension
git commit -m "extension unlock: master password in the popup, key in session storage, alarm idle lock"
```

---

### Task 4: Popup list, domain ranking, search, copy, TOTP

**Files:**
- Create: `extension/src/lib/domain.ts`, `extension/src/lib/domain.test.ts`, `extension/src/lib/rank.ts`, `extension/src/lib/rank.test.ts`
- Modify: `extension/src/background.ts`, `extension/src/vaultState.ts`, `extension/src/messages.ts`, `extension/src/popup/main.ts`, `extension/popup.html`, `extension/AGENTS.md`

**Interfaces:**
- `domain.ts`: `registrableDomain(hostname: string): string`. Lowercases, strips a trailing dot; IPv4, IPv6 and single-label hosts return as is; if the last two labels are in `SECOND_LEVEL` (`co.uk org.uk gov.uk ac.uk me.uk co.jp ne.jp or.jp ac.jp com.au net.au org.au edu.au co.nz org.nz com.br net.br co.za org.za com.mx com.ar com.tr com.sg com.hk co.kr co.in co.id com.my com.ph`) take the last three labels, else the last two. `sameSite(a, b)` compares registrable domains. `ponytail:` this is a suffix heuristic, not the Public Suffix List; a site under an unlisted multi-label suffix (`example.github.io`) ranks its neighbours as matches. Upgrade path: vendor the PSL's ICANN section as a generated module like `effWordlist.ts` when a report shows it matters.
- `rank.ts`: `type EntryView = Pick<VaultEntry, "uuid" | "title" | "username" | "url"> & { hasPassword: boolean; hasTotp: boolean; reused: number }` (never the password or seed). `rankEntries(entries: EntryView[], tabHost: string | undefined, query: string): EntryView[]`: with an empty query, entries whose URL host is exactly `tabHost` first, then same registrable domain, then nothing else (the popup shows "No logins for this site" and a search box). With a query, `entryMatches` from `entryMeta.ts` over the full entry list, matches ranked the same way, the rest after, each group sorted by title with `localeCompare`. URL parsing failures (an entry URL like `ssh host`) count as no host.
- Background `entries` message → `{ tabHost, entries: EntryView[] }` where `tabHost` comes from `ext.tabs.query({ active: true, lastFocusedWindow: true })` (URL readable through `activeTab`) and `reused` from `findReusedPasswords(vault)`. `copy` message `{ uuid, field: "username" | "password" | "totp" }` → `{ value }` for that one entry, generated on demand with `generateTOTP(entry.totpSeed)`; the popup, not the background, writes the clipboard (clipboard access needs a document). `ponytail:` the copied value crosses one in-process message; the alternative (clipboard from an offscreen document owned by the background) is the same trust boundary with more code.
- Popup rows: title, username, three buttons (Copy user, Copy password, Copy TOTP when `hasTotp`), and Fill (Task 5). A "reused" badge when `reused > 1`. Search box filters through the `entries` message with `query` so the background does the matching and the popup never holds the full list.

**Clipboard clear:** the popup calls `copyText(value, { clearAfterMs: SECRET_CLIPBOARD_MS })` from `frontend/src/lib/clipboard.ts`, which clears only if nothing newer was copied through the helper (the popup has no `clipboardRead`, so `readText` throws and the generation check decides). The popup usually closes before 30 seconds, and its timer dies with it. So the popup also tells the background `{ type: "copied", digest }` with a SHA-256 of the value; the background sets alarm `clipboard` for 30 seconds. When it fires on Chrome, the background opens `offscreen.html` (`reasons: ["CLIPBOARD"]`, `justification: "Clear a copied password after 30 seconds"`), which writes a single space through a hidden `<textarea>` and `document.execCommand("copy")` (the async clipboard API needs a focused document, which an offscreen document is not; an empty selection is a no-op for `execCommand`, hence the space), then closes. Firefox has no offscreen API: there, the clear happens only while the popup stays open, and the copied toast says "Copied. Clears in 30 seconds while this window is open." on Firefox and "Copied. Clears in 30 seconds." on Chrome. The background clears blind; it cannot read the clipboard, so a value the user copied elsewhere in those 30 seconds is replaced by a space once. Stated in the README. `ponytail:` adding `clipboardRead` would let the offscreen document compare before clearing, at the price of the "read data you copy" install warning; take it only if users report lost clipboard contents.

- [ ] **Step 1: Write the failing tests**

```ts
// extension/src/lib/domain.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain, sameSite } from "./domain";

test("last two labels, or three under a listed second-level suffix", () => {
  assert.equal(registrableDomain("login.accounts.example.com"), "example.com");
  assert.equal(registrableDomain("Example.COM."), "example.com");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("shop.example.com.au"), "example.com.au");
  assert.equal(registrableDomain("localhost"), "localhost");
  assert.equal(registrableDomain("10.0.0.5"), "10.0.0.5");
  assert.equal(registrableDomain("[::1]"), "[::1]");
});

test("sameSite is registrable-domain equality", () => {
  assert.equal(sameSite("id.example.com", "www.example.com"), true);
  assert.equal(sameSite("example.com", "example.co"), false);
  assert.equal(sameSite("evil-example.com", "example.com"), false);
});
```

```ts
// extension/src/lib/rank.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { rankEntries, type EntryView } from "./rank";

const e = (uuid: string, title: string, url: string, username = "u"): EntryView => ({ uuid, title, url, username, hasPassword: true, hasTotp: false, reused: 0 });
const all = [e("a", "Zulu mail", "https://mail.example.com"), e("b", "Example", "https://www.example.com/login"), e("c", "Other", "https://other.test"), e("d", "Alpha exact", "https://www.example.com"), e("e", "Broken", "not a url")];

test("exact host first, then same site, nothing else without a query", () => {
  assert.deepEqual(rankEntries(all, "www.example.com", "").map((x) => x.uuid), ["d", "b", "a"]);
  assert.deepEqual(rankEntries(all, undefined, "").map((x) => x.uuid), []);
});

test("a query searches everything and keeps site matches on top", () => {
  assert.deepEqual(rankEntries(all, "www.example.com", "e").map((x) => x.uuid), ["d", "b", "a", "e", "c"]);
  assert.deepEqual(rankEntries(all, undefined, "alpha").map((x) => x.uuid), ["d"]);
  assert.deepEqual(rankEntries(all, "www.example.com", "zzz").map((x) => x.uuid), []);
});
```

The default matcher is a title-plus-URL substring check; the background passes `entryMatches` from `entryMeta.ts` over the full entry so tags and custom field names are searchable too.

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`domain.ts`:

```ts
const SECOND_LEVEL = new Set("co.uk org.uk gov.uk ac.uk me.uk co.jp ne.jp or.jp ac.jp com.au net.au org.au edu.au co.nz org.nz com.br net.br co.za org.za com.mx com.ar com.tr com.sg com.hk co.kr co.in co.id com.my com.ph".split(" "));

export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || /^\d+(\.\d+){3}$/.test(host)) return host;
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const take = SECOND_LEVEL.has(labels.slice(-2).join(".")) ? 3 : 2;
  return labels.slice(-take).join(".");
}

export function sameSite(a: string, b: string): boolean { return registrableDomain(a) === registrableDomain(b); }
```

`rank.ts`: `rankEntries(entries, tabHost, query, matches = (e, q) => (e.title + " " + e.url).toLowerCase().includes(q))`. `hostOf(url)` is `new URL(url).hostname` in a try, empty string on failure; `tier(e)` is 0 for `host === tabHost`, 1 for `sameSite(host, tabHost)`, else 2; without a query keep `tier < 2`, with a query keep `matches(e, query.trim().toLowerCase())`. Sort by `(tier, title)` with `localeCompare`. `vaultState.listEntries` calls it with `(e) => entryMatches(fullEntryByUuid.get(e.uuid)!, query)`.

`vaultState.ts`: `listEntries(query, tabHost)` maps `vault.getLiveEntries()` through `entryMatches` when a query is present, projects to `EntryView` with `reused` from `findReusedPasswords`, then `rankEntries`. `secret(uuid, field)` returns the username, password or `(await generateTOTP(entry.totpSeed)).code`.

Popup: render rows from `entries`; the search input debounces 150 ms and re-asks; copy buttons call `copy`, then `copyText`, then `copied` with `digest = hex(sha256(value))`. On `RevokedError` text from the background, switch to the pair message. Background alarm `clipboard` → Chrome path with `ext.offscreen` when defined, else nothing.

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd extension && npm test && npm run build && npm run lint`. Browser: on a site with entries, the exact-host entry is first; search finds a tag; Copy TOTP produces the same code as the web app at the same second; after 30 seconds with the popup closed, the clipboard holds a space on Chrome.

`extension/AGENTS.md`: ranking rule and the `ponytail:` note; copy and clear behaviour per browser.

```bash
git add extension
git commit -m "extension popup: site-ranked entries, search, copy with timed clear, TOTP"
```

---

### Task 5: Fill on click

**Files:**
- Create: `extension/src/lib/fillTargets.ts`, `extension/src/lib/fillTargets.test.ts`
- Modify: `extension/src/content/fill.ts`, `extension/src/background.ts`, `extension/src/messages.ts`, `extension/src/popup/main.ts`, `extension/AGENTS.md`

**Interfaces:**
- `fillTargets.ts` is pure and DOM-free: `type Candidate = { index: number; type: string; visible: boolean; focused: boolean; autocomplete: string }`; `chooseTargets(fields: Candidate[]): { password: number; username?: number } | undefined`. Rules: the password target is the focused visible `password` input, else the first visible `password` input; none → `undefined`. The username target is the nearest preceding visible input of type `text`, `email`, or empty type, preferring one whose `autocomplete` is `username` or `email` when it appears anywhere before the password field; none → `username` undefined. Hidden inputs (`visible === false`) are never targets.
- `content/fill.ts` (built as an IIFE, injected by file): guards with `if (!(window as { __kyvaultFill?: true }).__kyvaultFill)` then registers `ext.runtime.onMessage` for `{ type: "fill", username, password, domain }`. It refuses unless `location.hostname === domain || location.hostname.endsWith("." + domain)` (the domain is precomputed by the background with `registrableDomain`), answering `{ filled: false, reason: "cross-site" }`. It collects `document.querySelectorAll("input")` into `Candidate[]` where `visible` is `el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden"` and `focused` is `document.activeElement === el`, calls `chooseTargets`, and sets values through the native setter so React and Vue forms notice:

```ts
function setValue(el: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  el.focus();
  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}
```

  It never submits the form and returns `{ filled: true, username: boolean }`.
- Background `fill` message `{ uuid }`: resolve the active tab, compute `domain = registrableDomain(hostOf(entry.url))`; refuse with "This login is for <entry domain>, not <tab host>." when the tab is not the same site (so the popup cannot inject a mismatched entry even by search); `ext.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content/fill.js"] })`, then `ext.tabs.sendMessage(tabId, { type: "fill", username, password, domain })` and report `filled` from the first frame that answers true. `allFrames` so a same-site login iframe is reached; cross-site frames refuse themselves by the hostname check and never receive the credential values? They do receive the message; the check runs before any DOM access, and the values are discarded. To keep the credential out of cross-site frames entirely, send per frame: `ext.webNavigation` is not in the permission set, so instead have the injected script answer a first `{ type: "probe" }` with its hostname and only then send `fill` to the frames whose hostname passes, using `{ frameId }`. Do this; it is two messages and no extra permission.
- Popup: Fill button per row; disabled with the reason as `title` when the row's site is not the tab's. After a fill: "Filled." or the refusal text.

- [ ] **Step 1: Write the failing test**

```ts
// extension/src/lib/fillTargets.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { chooseTargets, type Candidate } from "./fillTargets";

const c = (index: number, type: string, o: Partial<Candidate> = {}): Candidate => ({ index, type, visible: true, focused: false, autocomplete: "", ...o });

test("first visible password field and the nearest preceding text field", () => {
  const fields = [c(0, "search"), c(1, "email"), c(2, "text", { visible: false }), c(3, "password"), c(4, "password")];
  assert.deepEqual(chooseTargets(fields), { password: 3, username: 1 });
});

test("a focused password field wins over an earlier one", () => {
  const fields = [c(0, "text"), c(1, "password"), c(2, "text"), c(3, "password", { focused: true })];
  assert.deepEqual(chooseTargets(fields), { password: 3, username: 2 });
});

test("autocomplete=username is preferred even when not nearest", () => {
  const fields = [c(0, "text", { autocomplete: "username" }), c(1, "text"), c(2, "password")];
  assert.deepEqual(chooseTargets(fields), { password: 2, username: 0 });
});

test("hidden password fields and pages without one", () => {
  assert.equal(chooseTargets([c(0, "text"), c(1, "password", { visible: false })]), undefined);
  assert.deepEqual(chooseTargets([c(0, "password")]), { password: 0, username: undefined });
});
```

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
// extension/src/lib/fillTargets.ts
export type Candidate = { index: number; type: string; visible: boolean; focused: boolean; autocomplete: string };
const USERNAME_TYPES = new Set(["text", "email", ""]);

export function chooseTargets(fields: Candidate[]): { password: number; username?: number } | undefined {
  const passwords = fields.filter((f) => f.visible && f.type === "password");
  const password = passwords.find((f) => f.focused) ?? passwords[0];
  if (!password) return undefined;
  const before = fields.filter((f) => f.index < password.index && f.visible && USERNAME_TYPES.has(f.type));
  const labelled = before.find((f) => f.autocomplete === "username" || f.autocomplete === "email");
  const username = (labelled ?? before[before.length - 1])?.index;
  return { password: password.index, username };
}
```

`content/fill.ts` imports `chooseTargets` and `ext`; Vite bundles both into the IIFE. Message handling: `probe` → `{ hostname: location.hostname }`; `fill` → hostname check, collect candidates, `chooseTargets`, `setValue` on each target, answer. The handler returns `true` and calls `sendResponse` synchronously; nothing is stored in page-visible globals except the guard flag.

Background: `executeScript` with `files`, then `tabs.sendMessage(tabId, { type: "probe" }, { frameId })` for each frame id from the `executeScript` results, then `fill` only to passing frames, stop at the first `{ filled: true }`. Wrap in try/catch: pages where injection is refused (`chrome://`, the Web Store, PDF viewers) surface "KyVault cannot fill on this page."

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd extension && npm test && npm run build && npm run lint`. Browser: a plain HTML login form, a React form (any create-react-app style login shows the value in state after fill), a page whose login lives in a same-site iframe, and a page with a cross-site iframe containing a password field (a local test page embedding another local origin): the last must report nothing filled. Confirm that opening the popup on a page fills nothing until Fill is clicked.

`extension/AGENTS.md`: the fill contract (click only, same-site only, probe then fill per frame, native setter and events, no submit).

```bash
git add extension
git commit -m "extension fill: click-only same-site injection choosing the password and username fields"
```

---

### Task 6: Save login (5b)

**Files:**
- Create: `extension/src/lib/save.ts`, `extension/src/lib/save.test.ts`
- Modify: `extension/src/vaultState.ts`, `extension/src/background.ts`, `extension/src/messages.ts`, `extension/src/popup/main.ts`, `extension/AGENTS.md`

**Interfaces:**
- `save.ts`: `uploadVault(io, binary: ArrayBuffer, version: number, deviceId: string): Promise<number>`: `POST /api/vault/upload` through `serverFetch` with `Content-Type: application/octet-stream`, `If-Match: "<version>"`, `X-Device-ID: deviceId`; on 409 throws `class ConflictError extends Error` (message "The vault changed elsewhere. Unlock again to refresh."); on 413 "The vault is over the 50 MiB upload limit."; otherwise parses `{ metadata: { version } }` the way `frontend/src/lib/vaultSave.ts` does and refuses a version that is not a safe integer greater than the sent one.
- `vaultState.saveLogin({ title, username, password, url })`: `vault.createEntry({ title, username, password, url, notes: "", groupUuid: rootGroup })` where `rootGroup` is `vault.getLiveGroups()[0].uuid`; `exportBinary()`; `uploadVault`; on success `open.version = newVersion`; on `ConflictError` call `lock()` and rethrow (the next unlock downloads the newer vault; the typed entry is lost, and the message says so: "The vault changed elsewhere. Unlock again to refresh, then add the login again."). On any other failure remove the entry again with `vault.deleteEntry(uuid)` so memory matches the server. The whole call is serialised behind a module-level promise so two popups cannot interleave uploads.
- Popup: a "Save login for this site" form below the list (title prefilled with the tab host, URL prefilled with the tab origin, username, password with a Generate button that uses `generatePassword` from `frontend/src/lib/generatePassword.ts` with its defaults). Save sends `saveLogin`; the list refreshes.

- [ ] **Step 1: Write the failing test**

```ts
// extension/src/lib/save.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { ConflictError, uploadVault } from "./save";

function io(status: number, body: unknown) {
  const seen: { init?: RequestInit; url?: string } = {};
  return {
    seen,
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", autoLockMinutes: 5 as const }),
    forget: async () => {},
    fetch: async (url: string, init: RequestInit) => { seen.url = url; seen.init = init; return new Response(JSON.stringify(body), { status }); },
  };
}

test("sends If-Match and the device id and returns the new version", async () => {
  const fake = io(200, { ok: true, metadata: { version: 8 } });
  assert.equal(await uploadVault(fake, new Uint8Array([1, 2]).buffer, 7, "dev-1"), 8);
  const h = new Headers(fake.seen.init!.headers);
  assert.equal(h.get("If-Match"), '"7"');
  assert.equal(h.get("X-Device-ID"), "dev-1");
  assert.equal(h.get("Content-Type"), "application/octet-stream");
  assert.equal(fake.seen.url, "https://v.example/api/vault/upload");
});

test("409 is a ConflictError and a non-advancing version is refused", async () => {
  await assert.rejects(uploadVault(io(409, { currentVersion: 9, expectedVersion: 7, conflictId: "c" }), new Uint8Array([1]).buffer, 7, "d"), ConflictError);
  await assert.rejects(uploadVault(io(200, { ok: true, metadata: { version: 7 } }), new Uint8Array([1]).buffer, 7, "d"), /did not confirm/);
});
```

Append to `session.test.ts` or keep here: a round-trip through `KeePassVault.createNew`, `createEntry`, `exportBinary`, `KeePassVault.open` proving the saved entry reads back with the URL and password intact. It runs under Node because hash-wasm does; copy the pattern from `frontend/src/lib/vaultSave.test.ts`.

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
// extension/src/lib/save.ts
import { serverFetch, type SessionIO } from "./session";

export class ConflictError extends Error {
  constructor() { super("The vault changed elsewhere. Unlock again to refresh."); this.name = "ConflictError"; }
}

export async function uploadVault(io: SessionIO, binary: ArrayBuffer, version: number, deviceId: string): Promise<number> {
  const res = await serverFetch(io, "/api/vault/upload", {
    method: "POST", body: binary,
    headers: { "Content-Type": "application/octet-stream", "If-Match": `"${version}"`, "X-Device-ID": deviceId },
  });
  if (res.status === 409) throw new ConflictError();
  if (res.status === 413) throw new Error("The vault is over the 50 MiB upload limit.");
  if (!res.ok) throw new Error(`The server answered ${res.status}.`);
  const data = (await res.json()) as { metadata?: { version?: unknown } };
  const v = data.metadata?.version;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= version) throw new Error("The server did not confirm the saved vault version.");
  return v;
}
```

`serverFetch` returns the `Response` without throwing on non-2xx other than 401, so callers map statuses; adjust Task 3 if it was written to throw.

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd extension && npm test && npm run build && npm run lint`. Browser: save a login, see it in the web app after a reload with the right folder (root), and in the web app's Version History as "saved by <device name>". Then edit in the web app, and save from the extension without re-unlocking: the 409 message appears, the popup is locked, and after unlock the web app's edit is present.

`extension/AGENTS.md`: the write path, the 409 rule, and that save is the only write.

```bash
git add extension
git commit -m "extension save login: version-checked upload, conflict locks the vault"
```

---

### Task 7: Firefox specifics and lint

**Files:**
- Modify: `extension/src/manifest.ts` (only if lint demands), `extension/src/background.ts`, `extension/src/popup/main.ts`, `extension/README.md`, `extension/AGENTS.md`

- [ ] **Step 1: Run Firefox**

`npm run build && npm run run:firefox`. Pair (Firefox's permission prompt appears from the options page click), unlock, list, copy, fill, save. Note `web-ext run` uses a throwaway profile; pair each run.

- [ ] **Step 2: Fix what Firefox shows**

Known differences to check, each with the fix if it bites: `ext.offscreen` is undefined (the Task 4 guard handles it; the copied toast wording switches on `typeof ext.offscreen`); `alarms.create` with `when` less than 30 seconds out is fine on Firefox; `scripting.executeScript` results include `frameId` on both browsers; `tabs.query` on Firefox returns `url` only with `activeTab` after the action click, which the popup is. If Firefox refuses the module background (`type: "module"` with `scripts`), keep the key and add `strict_min_version` accordingly; the manifest test then pins the answer.

- [ ] **Step 3: Lint is clean**

`npm run lint` → 0 errors. Any warning that is not the `service_worker` key on Firefox gets fixed or documented in the README with the reason.

- [ ] **Step 4: Manifest test reflects reality, DOX, commit**

Update `manifest.test.ts` if Step 2 changed a field. README: a "Firefox" section (how to install the unsigned build temporarily via `about:debugging`, and that permanent installs need AMO signing).

```bash
git add extension
git commit -m "extension: Firefox run notes and web-ext lint clean"
```

---

### Task 8: End-of-phase verification and PR (controller)

- [ ] Full gates, in this order: `cd frontend && npm ci && npm test && npm run build`; `cd extension && npm ci && npm test && npm run build && npm run lint && npm audit --audit-level=high`; the Go gates unchanged (`gofmt -l . ; go vet ./... ; go test -race ./...`), since no Go file changed, confirm with `git diff master --stat -- internal cmd`.
- [ ] Browser pass on Chrome and Firefox against a real server: pair, unlock, idle lock at 1 minute, service-worker eviction without a password prompt, revoke from the web app then 401 handling, site ranking, search on a tag, copy user/password/TOTP and the 30 second clear (Chrome: a space after the popup closed; Firefox: only while open), fill on plain, React and same-site iframe forms, refusal on a cross-site iframe and on `chrome://` pages, save login and the 409 path.
- [ ] Key material audit, run and pasted into the PR: `grep -rn "storage.local" extension/src` lists only the five settings keys; `grep -rn "console\." extension/src` shows nothing that could print a secret; DevTools → Application → Storage shows `keyHex` only under session storage while unlocked and nothing after Lock.
- [ ] Read the diff of every task, not the commit messages. Confirm no file under `frontend/src/lib` changed; if one had to, say why in the PR.
- [ ] DOX closeout: root `AGENTS.md` Child DOX Index has the `extension/` line, the Verification list names seven CI jobs, and `extension/AGENTS.md` reads as a current contract with no diary entries.
- [ ] Open the PR with the `pull-request` skill. Title: `Phase 5 browser extension for Chrome and Firefox`. Base: `master`. Body: the design decision (master password per unlock, no device envelope, with the reason), the three `ponytail:` markers (suffix heuristic instead of the PSL, blind clipboard clear, copy value crossing one in-process message), the Firefox limitation on clipboard clearing, and the store-submission steps as documentation only.
