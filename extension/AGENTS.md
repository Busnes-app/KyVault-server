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
