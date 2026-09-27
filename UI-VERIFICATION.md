# Shared UI verification

## Change

Keep vault layout and security flows product-owned; remove active-navigation border width changes. Shared assets are pinned to ky-ui 0.2.0 with content hashes. Product layouts, saved theme keys and named presets remain local.

## Capture conditions

Captured 2026-09-25 from this branch, using the application UI (not a design mockup). Real React UI served by Vite, with browser-only read fixtures for /api/auth/me and /api/vault/metadata. The vault is locked; API writes are refused by the fixture.

OS-following Busnes Light and Dark were captured at 1280×900 and 390×844 CSS pixels. Browser device scaling may make PNG dimensions larger. Document width stayed within the viewport in these captured states; local navigation/table scrolling is intentional. Screenshots show the selected-page accent, not a complete accessibility audit.

Live KyIdentity SSO and vault unlock were NOT exercised. The backend correctly refused startup without a configured HTTPS identity provider; authentication was not weakened.

## Checks

83 frontend tests and production build passed. Central ky-ui sync --check verified all ten consumers. Screenshot coverage is Busnes Light/Dark; existing named choices are retained, but not every named palette/page combination was visually exercised.

## Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/ky-ui-light-desktop.png) | ![Desktop dark](docs/ky-ui-dark-desktop.png) |
| ![Mobile light](docs/ky-ui-light-mobile.png) | ![Mobile dark](docs/ky-ui-dark-mobile.png) |

## Reproduce

Run npm ci, npm test (where configured), and npm run build in frontend/, then start the product with isolated local preview data following its README. Use System theme, emulate OS light/dark, and inspect both viewport sizes. Do not point preview instances at production data. For KyVault, use a configured development KyIdentity or explicitly labeled read-only browser fixtures; never bypass backend authentication.

## Watchtower

Captured 2026-09-26 from `npm run dev:mock` (`frontend/mock/api.ts`, browser-only, dev-only, never built), which serves a signed-in mock user and supports creating/unlocking a real in-browser vault. No backend or KySignOn was involved.

Exercised in the browser: created a vault and four entries (two `Password1234!`, one at `https://github.com`, one plain; one at `http://shop.example` with a strong password; one unrelated strong/unique password). Watchtower nav item sits between Vault and Security. `#/watchtower` on a locked vault (both after clicking Lock and on a cold reload of the route) shows the "Vault is Locked" screen with an Unlock button and does not auto-open the unlock dialog — only the Vault tab does that. Category counts matched expectations: Reused 2, Weak 2, Insecure URL 1, Missing 2FA 1, Breached `?` (not run). Selecting the Personal folder (which does not contain the GitHub entry) and then clicking the GitHub row under Missing 2FA reset the vault view to All Items and opened the GitHub entry, visible and selected. Toggling the auto-check checkbox opened the HIBP confirm dialog; Cancel left it unchecked. Clicking "Check breaches" and confirming ran a real request to `api.pwnedpasswords.com`, since this sandbox has outbound internet access and the mock does not intercept that call; it returned 2 breached (both `Password1234!` entries), unlike the network-failure result assumed when the sandbox lacks connectivity. Locking and returning to Watchtower showed the unlock prompt again; unlocking put the breach state back to "not run" (`?`) while the other counts were unchanged. At 390px width the category grid was a single column with no horizontal scroll (`scrollWidth === clientWidth === 390`).

Not exercised: live HIBP behind a network-restricted sandbox (a genuine fetch failure path), and KySignOn SSO/vault unlock end to end — both out of scope for the mock harness per existing UI-VERIFICATION conventions above.

### Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/watchtower-light-desktop.png) | ![Desktop dark](docs/watchtower-dark-desktop.png) |
| ![Mobile light](docs/watchtower-light-mobile.png) | ![Mobile dark](docs/watchtower-dark-mobile.png) |
