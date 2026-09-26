# KyVault Browser Extension

Chrome and Firefox MV3 extension that pairs with KyVault like any other device,
unlocks the vault with the master password in the browser, lists entries for
the current site, copies and fills credentials on click, generates TOTP codes,
and saves new logins through the version-checked upload path.

## Copy and clipboard

Copied usernames, passwords and TOTP codes clear from the clipboard after 30 seconds.
The clear is blind: it cannot read the clipboard first, so a value you copied
elsewhere in those 30 seconds is replaced by a space once.

## Build

```bash
cd frontend && npm ci   # crypto modules resolve their deps from here
cd ../extension && npm ci
npm test
npm run build
```

`npm run build` runs `tsc`, builds the popup/options/offscreen/background
bundle, builds `content/fill.js` as a standalone IIFE, then writes
`dist/chrome/` and `dist/firefox/` with each browser's own `manifest.json`.

## Load unpacked (Chrome)

Open `chrome://extensions`, enable Developer mode, "Load unpacked", pick
`dist/chrome`.

## Run in Firefox

```bash
npm run run:firefox
```

Launches a temporary Firefox profile with `dist/firefox` loaded. `npm run lint`
runs `web-ext lint` against the same directory; expect 0 errors. The
`BACKGROUND_SERVICE_WORKER_IGNORED` warning is expected: Firefox ignores
`background.service_worker` and uses `background.scripts` instead, which the
manifest also sets. Two warnings about `strict_min_version` predating
`data_collection_permissions` support are also expected and harmless; Firefox
ignores that key below the versions named rather than rejecting the manifest.

## Store submission

Not automated; both stores are manual uploads.

### Chrome Web Store

- Zip the contents of `dist/chrome` (not the folder itself) and upload through
  the developer dashboard.
- Privacy tab: no user data collected.
- Permission justifications:
  - `storage`: server origin, session token, device name and settings.
  - `alarms`: periodic session/vault refresh.
  - `activeTab`: read the current tab's URL to match vault entries.
  - `scripting`: inject the fill script only after a click in the popup.
  - `offscreen`: run WebCrypto/Argon2id work outside the service worker.
  - Optional host access: reach the KyVault server the user pairs with.

### Firefox (AMO)

- Zip the contents of `dist/firefox` and upload as the extension package.
- Also upload a source zip: the shipped bundle is minified, so reviewers need
  `npm ci && npm run build` (run from the repository root, in `frontend/` then
  `extension/`) to reproduce it.
- `data_collection_permissions` is declared as `none`.
