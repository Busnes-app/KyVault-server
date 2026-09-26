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

Launches a temporary Firefox profile with `dist/firefox` loaded. Pair again
each run: `web-ext run` uses a throwaway profile.

### Install unsigned (about:debugging)

Open `about:debugging#/runtime/this-firefox`, "Load Temporary Add-on", pick
`dist/firefox/manifest.json`. This install is removed when Firefox closes.
A permanent install needs the package signed by AMO (see Store submission
below); Firefox refuses to load an unsigned `.xpi` permanently.

### Lint

`npm run lint` runs `web-ext lint` against `dist/firefox`; expect 0 errors
and 2 warnings, both `KEY_FIREFOX_*_UNSUPPORTED_BY_MIN_VERSION`. They say
`strict_min_version: "128.0"` is older than the Firefox versions that added
`data_collection_permissions` support (140 desktop, 142 Android). Firefox
ignores that manifest key below the version it needs rather than rejecting
the manifest, so keeping `strict_min_version` at 128 (the earliest version
this extension otherwise needs) is correct: raising it to 140 would refuse
to install on Firefox 128 through 139 for no functional gain.

## Manual test checklist

Run this on both Chrome (`dist/chrome` loaded unpacked) and Firefox
(`npm run run:firefox`) against a real KyVault server before each release:

- Pair from the options page.
- Unlock with the master password.
- List entries for the current site.
- Copy username, password and TOTP; confirm the 30 second clipboard clear
  (Chrome: a space after the popup closes; Firefox: only while the popup
  stays open).
- Fill on a plain HTML form and on a React-controlled form.
- Fill a same-site login iframe; confirm a cross-site iframe is not filled.
- Confirm nothing fills merely from opening the popup, with no click.
- Save a new login, then force a 409 (edit the vault elsewhere first) and
  confirm the lock-and-refresh message.
- Revoke the device from the KyVault web app, then confirm the extension's
  next action shows the revoked message instead of retrying silently.
- Leave the popup closed past the idle lock window, then confirm the next
  open asks for the master password again.

## Known limitations

- Firefox has no Offscreen API, so the clipboard clears there only while the
  popup stays open; Chrome clears it 30 seconds later regardless.
- Fill does not reach a login form inside a cross-site iframe, by design:
  filling only applies to the top frame and same-site frames.

## Store submission

Not automated; both stores are manual uploads.

### Chrome Web Store

- Zip the contents of `dist/chrome` (not the folder itself) and upload through
  the developer dashboard.
- Privacy tab: no user data collected.
- Permission justifications:
  - `storage`: server origin, session token, device name and settings.
  - `alarms`: lock the vault after the idle window and clear a copied secret
    from the clipboard after 30 seconds.
  - `activeTab`: read the current tab's URL to match vault entries.
  - `scripting`: inject the fill script only after a click in the popup.
  - `clipboardWrite`: copy a username, password or TOTP code after a click in
    the popup.
  - `offscreen`: open a hidden page that overwrites the clipboard 30 seconds
    after a copy, since the service worker has no clipboard access.
  - Optional host access: reach the KyVault server the user pairs with.

### Firefox (AMO)

- Zip the contents of `dist/firefox` and upload as the extension package.
- Also upload a source zip: the shipped bundle is minified, so reviewers need
  `npm ci && npm run build` (run from the repository root, in `frontend/` then
  `extension/`) to reproduce it.
- `data_collection_permissions` is declared as `none`.

## Servers on a non-default port

The host permission is requested for the host alone (`https://vault.example.com/*`),
never with a port. Firefox match patterns do not match a port, so a pattern with one
would be granted and yet never lift CORS for a single request. Granting the host covers
every port on it; the extension still fetches only the exact origin you paired with.

## Testing in LibreWolf

`web-ext run` cannot attach to LibreWolf, which forces `devtools.debugger.remote-enabled`
off. Install the built `dist/firefox` through WebDriver BiDi instead (Puppeteer with
`browser: "firefox"` and `installExtension`), or load it by hand from `about:debugging`.
