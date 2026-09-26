# Extension e2e (local only)

Browser runs of the built extension against the frontend's mock API. Not wired into CI:
they need a browser binary, take about five minutes (real 30 s and 60 s timers), and bind
fixed local ports.

## Prerequisites

- `npm ci` in `frontend/` (the mock and the crypto the extension imports), then `npm ci` and
  `npm run build` in `extension/`.
- `openssl` on `PATH` (the self-signed certificate is generated once into the gitignored
  `e2e/.certs/`).
- Chromium: Playwright's Chromium in `~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`
  (`npx playwright install chromium`), or set `KYVAULT_E2E_CHROME` to a Chromium or Chrome for
  Testing binary. Branded Chrome ignores `--load-extension`.
- Firefox: `/usr/bin/librewolf`, or set `KYVAULT_E2E_FIREFOX`. Without it the suite reports NOT RUN.
- Ports 5200, 5443 and 5444 free on 127.0.0.1 and ::1. The suite refuses to start rather than
  stop whatever holds them. It never uses 5199.

## Run

```bash
npm run e2e:chromium
npm run e2e:firefox   # KYVAULT_E2E_HEADFUL=1 shows the LibreWolf window
```

Each run starts the mock (`frontend` vite with `KYVAULT_MOCK_API=1` on 5200), the TLS proxy
(5443, the server the extension pairs with) and the test site, creates a fresh vault through
the web app with the fixture entries, runs the items as `node:test` cases, prints a
PASS / FAIL / NOT RUN summary, then stops everything and deletes its temporary profile.
`KYVAULT_E2E_VERBOSE=1` also prints the proxy and mock log.

## What the harness is

- `servers.mjs`: the mock, the proxy and the test site on `https://127.0.0.1:5444` (plain
  form, React-style form whose value tracker only sees prototype-setter changes, same-site
  iframe). The cross-site iframe comes from `https://[::1]:5444`, so no localhost or
  127.0.0.1 grant can make it look filled.
- `chromium.mjs`: puppeteer-core over the pipe transport, which allows
  `Extensions.triggerAction`, the real toolbar click. Playwright refuses that command, so the
  popup would never get activeTab the way a user's click grants it.
- `firefox.mjs`: LibreWolf over WebDriver BiDi. `web-ext run` cannot attach to LibreWolf, so
  `dist/firefox` is installed as a temporary add-on; the popup is opened with
  `browserAction.triggerAction` and driven by a frame script from the chrome scope
  (`--remote-allow-system-access`).
- `helpers.mjs`: fixtures, web app steps, form checks, an independent RFC 6238 TOTP and the
  summary.

## What each Chromium item proves

1. The extension loads with no manifest errors or install warnings; the icons are the
   declared sizes and match `public/icons`.
2. Pairing requests exactly `https://localhost/*` (no port), shows the wrong-PIN sentence,
   pairs with the real PIN, never shows the token, keeps `storage.session` empty.
3. A wrong password stores nothing; unlocking puts `keyHex`, `envelope`, `lockAt` in
   `storage.session` and never the key in `storage.local`.
4. With the test-site tab active, only its entries list; a search ranks them first.
5. Copy password twice: the popup writes the entry's password, the offscreen document reports
   the clear about 30 s later with the popup closed, and no offscreen document stays open.
6. The copied TOTP equals an independent RFC 6238 computation (itself checked against RFC 6238
   Appendix B).
7. Fill: plain, React-style and same-site iframe filled with bubbling `input`/`change` and no
   submit; opening the popup changes nothing; the cross-site iframe is not filled; an entry for
   another host has Fill disabled and the background refuses it too.
8. Save login advances the version and the web app lists it; after the web app moves the
   version, a save locks with "The vault changed elsewhere"; with the proxy killed mid-upload the
   form keeps the typed values, says the save could not be confirmed, and no entry appears.
9. After a revoke in the web app, the popup still lists within 60 s of the last server
   contact, then shows the revoked sentence and the token is gone.
10. Setting 1 minute from the paired options view does not lock at once; after it passes
    `storage.session` is empty and the popup asks for the password.
11. No console error or exception from the service worker, popup, options or offscreen
    documents, and no runtime errors in chrome://extensions.

The Firefox suite runs pairing, unlock, list, fill and save (F2, F3, F4, F7, F8) and reports
the rest as NOT RUN.

## Limits

- The mock accepts any PIN. The proxy answers 400 for every PIN but `483920`, as the real
  server does for a wrong code.
- Headless Chromium cannot accept the host permission prompt. Item 2 records the request
  still pending, then grants the host from chrome://extensions Site access (as a user can),
  after which the request resolves without a prompt. Item 2b is NOT RUN for that reason.
- Headless Chromium's clipboard is a no-op store: reading it returns an empty string even
  after a page's own write. Items 5 and 6 check the value the popup writes and the offscreen
  document's clear reply instead; item 5b (reading the space back) is NOT RUN.
- In Firefox the doorhanger is accepted by calling its main action from the chrome scope; if
  that does not grant the host, the host is added through `ExtensionPermissions` and F2 says so.
