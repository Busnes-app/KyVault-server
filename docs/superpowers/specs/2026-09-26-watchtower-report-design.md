# Watchtower report (individual) — design

Sub-project 2 of 4 in the reporting effort. Order: (2) individual Watchtower report,
(1) user key pairs, (3) shared vaults, (4) admin server-wide encrypted report. This spec
covers only (2). No Go backend change.

## Goal

A per-user security report in the browser, replacing the Vault Health dialog, that flags
passwords and entries needing attention and gives an overall score. No password, hash or
password-derived value appears in the report, which is the shape sub-project 4 builds on.

## Decisions

- Strength: zxcvbn-ts (`@zxcvbn-ts/core`, `language-common`, `language-en`, MIT, pinned),
  lazily imported. Replaces the length/class heuristic `passwordWeakness`.
- Categories: breached, reused, weak, insecure URL, missing 2FA, expired, expiring.
- Not included: password age (NIST SP 800-63B: no periodic rotation; change on evidence of
  compromise, which the breach check covers) and duplicate logins (clutter, not security).
- Placement: its own top tab `#/watchtower`; the Health button and dialog are removed.
- Breach check: per-click, plus a per-browser opt-in to check automatically on open.

## Data model

`frontend/src/lib/watchtower.ts`:

```ts
type Category = "breached" | "reused" | "weak" | "insecureUrl" | "missing2fa" | "expired" | "expiring";
type Finding = { uuid: string; title: string; detail: string };
type WatchtowerReport = {
  score: number | null;     // 0–100; null for a vault with no live entries
  breachChecked: boolean;
  categories: Record<Category, Finding[]>;
};
```

`detail` is a fixed reason string or zxcvbn feedback text, never derived from secret
field contents beyond that feedback. Only live entries (`getLiveEntries()`) are reported.

## Checks

| Category | Rule |
|---|---|
| weak | zxcvbn score ≤ 2; empty password is weak. `detail` = zxcvbn warning or "empty". |
| reused | existing `findReusedPasswords`; `detail` = "used N times". |
| breached | existing `checkBreached`; `detail` = "seen N times". |
| insecureUrl | URL scheme `http:` and host is not `localhost`, `*.localhost`, `*.local`, `*.lan`, `*.home.arpa`, `*.internal`, a single-label hostname (no dot), or a loopback, private (RFC 1918, ULA `fc00::/7`), link-local (`169.254/16`, `fe80::/10`), or CGNAT/Tailscale (`100.64.0.0/10`) address. Unparseable URLs are ignored. |
| missing2fa | entry has no TOTP and its URL host equals, or is a subdomain of, a domain in the bundled 2fa.directory TOTP list. Suffix match on label boundaries only; no public-suffix library. |
| expired / expiring | existing `isExpired` / `expiresWithin(entry, 30)`. |

## Score

`score = round(100 × (1 − min(1, Σ weight·affected / (liveEntries × 4))))`, where
`affected` counts entries per category and weights are breached 4, reused 3, weak 2,
insecureUrl 1, missing2fa 1, expired 1, expiring 0. An entry in several categories counts in
each. When the breach check has not run, breached contributes 0 and the UI labels the score
"breach check not run".

## Computation cost

- zxcvbn-ts and the 2FA list are dynamic imports loaded when the Watchtower tab first
  renders while unlocked; neither is in the entry chunk. Measured: the zxcvbn chunk with
  common + en dictionaries is ~1.66 MB minified, ~850 KB gzip, downloaded once and cached.
- zxcvbn runs with `l33tMaxSubstitutions: 10`. Measured on 300 mixed passwords: default
  (100) costs ~18 ms per password, 10 costs ~2.7 ms, with identical scores on the probe set
  (`Password1234!`, `qwertyuiop123`, `p@ssw0rd2024` → 1; passphrases → 4).
  zxcvbn scores `Summer2026!!!` 3, so it is not reported weak; that is zxcvbn's judgment.
- Scoring runs in async chunks that yield to the event loop after ~10 ms of work.
- An in-memory cache keyed by entry UUID + `updatedAt` holds per-entry zxcvbn results
  for the unlocked session; edits re-score only changed entries. Lock clears it.
- ponytail: no Web Worker. If chunked scoring is too slow on very large vaults, move the
  scorer into a module worker (`default-src 'self'` already permits it).

## UI

- Route: `route.ts` gains `tab: "watchtower"` ↔ `#/watchtower`. Nav item between Vault and
  Security, marked `ky-nav-item`. Locked: the existing unlock prompt.
- `frontend/src/pages/WatchtowerPage.tsx` in the `.settings-page` scroll area:
  - Header: score, one-line verdict, breach status ("not run" / "checked at HH:MM"), Check
    breaches button with progress.
  - Category cards with count and severity colour from existing tokens; zero is muted.
  - Selecting a card lists its findings below; a row navigates to `#/vault/<uuid>`.
    `WatchtowerPage` stays mounted while unlocked (`hidden` prop, like `VaultPage`), so its
    state (selected category, cache, breach results) survives tab switches and is dropped
    when lock unmounts it. Opening an entry resets the vault's folder/smart view/search if
    the entry would otherwise be filtered out of the list.
  - Under 900px the grid is one column (`useMediaQuery`).
- Breach auto-check: checkbox "Check automatically when I open Watchtower", `localStorage`
  key `kyvault.watchtower.autoBreach:<userId>` (per account, since `localStorage` is shared
  across accounts on a device), default off. Enabling shows the existing HIBP
  disclosure via `useDialogs().confirm`; declining leaves it off.
- Breach results are keyed by entry UUID + `updatedAt`; an entry edited after the check is
  no longer reported breached until checked again. In-flight checks abort on unmount.
- Remove the Health button from `VaultPage` and delete `components/HealthReport.tsx`.

## 2FA list

- `frontend/scripts/update-2fa-list.mjs` fetches `https://api.2fa.directory/v3/totp.json`,
  parses the `[name, {domain, "additional-domains"?, tfa}]` array (checked 2026-09-26), extracts `domain` plus `additional-domains`, lowercases, dedupes, sorts and writes
  `frontend/src/lib/twoFactorDomains.ts` with a header naming source, date and MIT licence.
- Run by hand before a release; the generated file is committed. Nothing fetches it at build
  or runtime, so CSP `connect-src` is unchanged.

## Security properties

- Passwords and secrets stay in the browser; the report holds UUIDs, titles and reasons.
- Only network traffic: the existing HIBP k-anonymity prefix request, after consent.
- The report is never persisted or transmitted.
- CSP unchanged.

## Testing

- `watchtower.test.ts` on kdbxweb-built vaults: each category detected; recycled entries
  excluded; score arithmetic and the breach-not-run state; cache re-scores only an edited
  entry; serialised report contains no password, TOTP secret or protected field value.
- insecureUrl table: `http://example.com` flagged; `http://192.168.1.1`, `http://10.0.0.5`,
  `http://[fe80::1]`, `http://[fd00::1]`, `http://nas.local`, `http://localhost:8080`,
  `http://nas:5000`, `http://router.lan`, `http://pve.home.arpa`, `http://grafana.internal`,
  `http://100.100.1.1`, `https://example.com` and non-URL text not flagged;
  `http://100.128.0.1` (outside the CGNAT range) is flagged.
- missing2fa: `login.github.com` matches `github.com`; `github.com.evil.example` and
  `notgithub.com` do not; TOTP present suppresses it.
- `update-2fa-list.mjs` parser tested on a fixture, no network.
- HIBP tests move from `health.test.ts`; `passwordWeakness` tests become zxcvbn threshold
  tests.
- Bundle split: a test script run after `npm run build` asserts zxcvbn dictionaries and
  `twoFactorDomains` are absent from the entry chunk.
- `route.test.ts` covers `#/watchtower`.

## Docs

- `KyVault-server/AGENTS.md`: replace the `lib/health.ts` entry with `lib/watchtower.ts` /
  `pages/WatchtowerPage.tsx` (categories, lazy load, auto-breach key, 2FA list refresh,
  exclusions and why); update the `route.ts` entry and the Verification list if the bundle
  check becomes a separate command.

## Out of scope

User key pairs, shared vaults, admin reporting, any server change.
