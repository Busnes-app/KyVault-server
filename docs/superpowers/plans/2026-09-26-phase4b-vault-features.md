# Phase 4b: Vault Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the Phase 4 list from the 2026-09-25 audit that 4a left out: passphrase generator with an entropy meter, a vault health report with an opt-in HIBP range check, vault key rotation, device UX, snapshot preview with a diff before rollback, two-way conflict comparison, a PWA manifest, and locked-draft cleanup.

**Architecture:** Pure libs under `frontend/src/lib/` with `node --test` proofs, wired into `SecuritySettings`, `VaultPage`, `HistoryModal` and `PasswordGenerator` through the existing dialog host. Three small Go changes: a CSP `connect-src` entry, `PATCH /api/devices/{id}` plus device-session revocation, and `GET /api/vault/history/{id}` with snapshot id validation. Everything else is client side.

**Tech Stack:** React 18 + TypeScript, kdbxweb 2.x, WebCrypto (`crypto.subtle.digest` for SHA-1, AES-GCM in `vaultCrypto.ts`), `tsx --test`, Go 1.26 `net/http` mux with path values.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md`, "Phase 4: Missing features", every bullet not covered by `2026-09-26-phase4a-vault-data.md`. Look-alike exclusion already exists (`excludeLookalikes` in `generatePassword.ts`, Phase 3); Task 1 keeps it and adds the passphrase mode and entropy. The pairing modal already polls `/api/devices` every 3 s and closes on success (`DEVICE_POLL_MS` in `DevicePairingModal.tsx`, Phase 2); Task 4 verifies it in the browser pass and does not rewrite it.

## Global Constraints

- Branch `feat/phase4b-features` stacked on `fix/phase4a-data` (PR #62); rebase onto `master` once #62 merges. One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`. Browser pass with `npm run dev:mock` at 1280px and 390px for every flow a task changes.
- No new runtime dependencies. The EFF wordlist is a generated TS module, not a package. No zxcvbn.
- Zero knowledge: nothing plaintext leaves the browser. The only exception is the first five hex characters of a SHA-1 of a password, sent to `api.pwnedpasswords.com` after the user opts in per click (Task 2). Health and HIBP results live in React state and die with the unlocked vault.
- No native dialogs; questions go through `useDialogs()` (`noNativeDialogs.test.ts` enforces it). Copy rules: sentences, no em-dashes, no "successfully".
- DOX: every task updates `AGENTS.md` (the Child DOX Index bullet named in the task). Go changes also update the route list in the AGENTS.md sections they touch.

## Review Focus

1. Rotation must never strand the user: the new KDBX and both new envelopes go to the server in one `POST /api/vault/upload`, which `vault.Store.SaveVault` writes under one lock with the `If-Match` version check. Envelopes are never written in a separate request before the vault. Pinned: Task 3 `keyRotation.test.ts` plus the order in Step 5.
2. HIBP sends exactly five hex characters and nothing else, only after a confirm that names what leaves the browser. Pinned: Task 2 `health.test.ts` (`hibpPrefix`) and the confirm copy.
3. `GET /api/vault/history/{id}` returns ciphertext only to the owner and refuses path-shaped ids; `RestoreHistory` gets the same id check. Pinned: Task 5 `history_download_test.go`.
4. Revoking a device ends its bearer sessions. Today `handleDeviceRevoke` deletes the device record and its envelope but never touches `s.sessions`, so a revoked phone keeps its 90-day session. Pinned: Task 4 `TestDeviceRevokeEndsSession`.
5. Draft pruning deletes only this account's drafts, never the one the current tab points at, and stamps legacy drafts instead of deleting them blind. Pinned: Task 7 `lockedDraft.test.ts`.

---

### Task 1: Passphrase generator and entropy meter

**Files:**
- Create: `frontend/src/lib/effWordlist.ts` (generated), `frontend/src/lib/passphrase.ts`, `frontend/src/lib/passphrase.test.ts`
- Modify: `frontend/src/lib/generatePassword.ts` (`passwordEntropyBits`), `frontend/src/lib/generatePassword.test.ts` (append)
- Modify: `frontend/src/components/PasswordGenerator.tsx` (mode toggle, meter)
- Modify: `AGENTS.md`

**Wordlist:** the download worked while planning (`curl -fsSL https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`, 7776 lines, format `NNNNN<TAB>word`, 7776 unique words, longest 9 characters, four contain a hyphen: `drop-down`, `felt-tip`, `t-shirt`, `yo-yo`). Generate the module once and commit it; do not fetch at build time:

```bash
curl -fsSL https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt -o /tmp/eff_large_wordlist.txt
test "$(wc -l < /tmp/eff_large_wordlist.txt)" = 7776
{ printf '// EFF long wordlist (2016), 7776 words, CC BY 3.0. Generated from\n// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt; do not edit by hand.\nexport const EFF_WORDS: readonly string[] = "';
  awk '{ printf "%s%s", (NR > 1 ? " " : ""), $2 }' /tmp/eff_large_wordlist.txt;
  printf '".split(" ");\n'; } > frontend/src/lib/effWordlist.ts
```

If the download fails when the task runs, stop and say so; do not substitute another list, because the entropy figure in the UI names the EFF list.

**Interfaces:**
- `passphrase.ts`: `type PassphraseOptions = { words: number; separator: string; capitalize: boolean }`, `DEFAULT_PASSPHRASE = { words: 6, separator: "-", capitalize: false }`, `generatePassphrase(opts, random?)`, `passphraseEntropyBits(opts)` (= `words * log2(7776)`), `loadPassphraseOptions` / `savePassphraseOptions` on `localStorage` key `kyvault.passphrase` with the same untrusted-input rules as `loadGeneratorOptions`.
- `generatePassword.ts`: `passwordEntropyBits(opts: GeneratorOptions): number` (= `length * log2(pool)` where pool is the union of the selected sets after look-alike removal; 0 when no class is selected). The one-per-class guarantee shrinks the space slightly; the meter says "about".

- [ ] **Step 1: Write the failing tests**

```ts
// frontend/src/lib/passphrase.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { EFF_WORDS } from "./effWordlist";
import { generatePassphrase, passphraseEntropyBits, loadPassphraseOptions, DEFAULT_PASSPHRASE } from "./passphrase";

test("the bundled list is the EFF long list", () => {
  assert.equal(EFF_WORDS.length, 7776);
  assert.equal(new Set(EFF_WORDS).size, 7776);
  assert.ok(EFF_WORDS.every((w) => /^[a-z-]+$/.test(w) && w.length <= 9));
  assert.equal(EFF_WORDS[0], "abacus");
});

test("passphrases use the list, the separator and capitalisation", () => {
  const p = generatePassphrase({ words: 5, separator: " ", capitalize: true });
  const parts = p.split(" ");
  assert.equal(parts.length, 5);
  for (const w of parts) assert.ok(EFF_WORDS.includes(w.toLowerCase()) && /^[A-Z]/.test(w), w);
  assert.throws(() => generatePassphrase({ words: 3, separator: "-", capitalize: false }), /between 4 and 10/);
  assert.throws(() => generatePassphrase({ words: 11, separator: "-", capitalize: false }), /between 4 and 10/);
  const zeros = (a: Uint32Array) => { a.fill(0); };
  assert.equal(generatePassphrase({ words: 4, separator: ".", capitalize: false }, zeros), "abacus.abacus.abacus.abacus");
});

test("entropy is log2 of the space", () => {
  assert.ok(Math.abs(passphraseEntropyBits({ words: 6, separator: "-", capitalize: true }) - 77.55) < 0.01);
  assert.equal(loadPassphraseOptions({ getItem: () => JSON.stringify({ words: 99, separator: 5 }) }), DEFAULT_PASSPHRASE);
});
```

Append to `generatePassword.test.ts`:

```ts
test("character entropy is length times log2 of the pool", () => {
  // pools: 26+26+10+26 = 88; lowercase minus the look-alike "l" = 25 (LOOKALIKES is /[O0Il1|]/g)
  assert.ok(Math.abs(passwordEntropyBits({ length: 20, upper: true, lower: true, numbers: true, symbols: true }) - 20 * Math.log2(88)) < 1e-9);
  assert.ok(Math.abs(passwordEntropyBits({ length: 10, upper: false, lower: true, numbers: false, symbols: false, excludeLookalikes: true }) - 10 * Math.log2(25)) < 1e-9);
  assert.equal(passwordEntropyBits({ length: 10, upper: false, lower: false, numbers: false, symbols: false }), 0);
});
```

(Add `passwordEntropyBits` to the file's existing import line.)

- [ ] **Step 2: Run to see them fail**

Run: `cd frontend && npx tsx --test src/lib/passphrase.test.ts src/lib/generatePassword.test.ts` → FAIL (module not found).

- [ ] **Step 3: Implement**

`passphrase.ts`:

```ts
import { EFF_WORDS } from "./effWordlist";

export type PassphraseOptions = { words: number; separator: string; capitalize: boolean };
export const DEFAULT_PASSPHRASE: PassphraseOptions = { words: 6, separator: "-", capitalize: false };
const MIN_WORDS = 4, MAX_WORDS = 10, MAX_SEPARATOR = 3;

export function generatePassphrase(opts: PassphraseOptions, random: (a: Uint32Array<ArrayBuffer>) => void = (a) => { crypto.getRandomValues(a); }): string {
  if (!Number.isInteger(opts.words) || opts.words < MIN_WORDS || opts.words > MAX_WORDS) throw new Error(`Choose between ${MIN_WORDS} and ${MAX_WORDS} words.`);
  const limit = Math.floor(0x100000000 / EFF_WORDS.length) * EFF_WORDS.length;
  const buf = new Uint32Array(1);
  const words: string[] = [];
  while (words.length < opts.words) {
    do { random(buf); } while (buf[0] >= limit);
    const w = EFF_WORDS[buf[0] % EFF_WORDS.length];
    words.push(opts.capitalize ? w[0].toUpperCase() + w.slice(1) : w);
  }
  return words.join(opts.separator);
}

export function passphraseEntropyBits(opts: Pick<PassphraseOptions, "words">): number {
  return opts.words * Math.log2(EFF_WORDS.length);
}
```

`loadPassphraseOptions(storage)` and `savePassphraseOptions(opts, storage)` follow `loadGeneratorOptions` exactly: integer `words` in range, `separator` a string of at most 3 characters, `capitalize` strictly boolean, else the default. Move the shared rejection sampler into an exported `uniformBelow(n, random)` in `generatePassword.ts` if you want one copy; the test does not care.

`generatePassword.ts`: export `passwordEntropyBits(opts)` computing the union length with the same `setFor` logic as `generatePassword`.

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: Generator UI**

`PasswordGenerator.tsx`: a two-button segmented toggle "Characters | Passphrase" (state `mode`, persisted under `kyvault.generator.mode`, validated to the two literals). Passphrase mode shows Words (`<input type="number" min={4} max={10}>` plus range), Separator (`<select>`: hyphen, space, period, none), and a Capitalise checkbox; `regenerate` calls `generatePassphrase`. Both modes show a meter line under the output: `<meter min={0} max={128} low={50} high={80} optimum={100} value={bits}>` with the text "About N bits of entropy" and, in passphrase mode, "from the EFF long wordlist". `use` is unchanged (the confirm still guards overwrite). Keep the output `font-mono` span; passphrases with spaces need `wordBreak: "break-word"`.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: open the generator on an entry, switch modes, change words and separator, see the meter move, use the passphrase.

`AGENTS.md`: add a bullet "`frontend/src/lib/passphrase.ts` and `effWordlist.ts`: passphrases draw uniformly from the bundled EFF long list (7776 words, generated module, never fetched); `passphraseEntropyBits` and `passwordEntropyBits` are log2 of the search space and the meter says "about". `passphrase.test.ts` pins the list size, charset and a zero-randomness phrase."

```bash
git add frontend/src/lib/effWordlist.ts frontend/src/lib/passphrase.ts frontend/src/lib/passphrase.test.ts frontend/src/lib/generatePassword.ts frontend/src/lib/generatePassword.test.ts frontend/src/components/PasswordGenerator.tsx AGENTS.md
git commit -m "passphrase generator from the EFF list with an entropy meter"
```

---

### Task 2: Health report with opt-in HIBP range check

**Files:**
- Create: `frontend/src/lib/health.ts`, `frontend/src/lib/health.test.ts`, `frontend/src/components/HealthReport.tsx`
- Modify: `frontend/src/pages/VaultPage.tsx` (sidebar "Health" button, `showHealth` state)
- Modify: `internal/api/headers.go`, `internal/api/headers_test.go`
- Modify: `AGENTS.md`

**Interfaces:**
- `health.ts`:
  - `passwordWeakness(password: string): string | null`: `"empty"` for `""`, `"shorter than 12 characters"` under 12, `"only one kind of character"` when a single class, `"repeats one character"` when all characters equal, `"fewer than 16 characters with two kinds"` when exactly two classes and under 16; otherwise `null`.
  - `buildHealthReport(vault: KeePassVault, now = new Date()): HealthReport` with `type HealthReport = { weak: Array<{ uuid: string; title: string; reason: string }>; reused: Array<{ uuid: string; title: string; count: number }>; expired: Array<{ uuid: string; title: string }>; expiring: Array<{ uuid: string; title: string }> }` built from `getLiveEntries()`, `findReusedPasswords`, `isExpired`, `expiresWithin(e, 30, now)`. Titles and uuids only, never passwords.
  - `sha1Hex(text: string): Promise<string>` (WebCrypto, upper-case hex), `hibpPrefix(hashHex): string` (first 5), `hibpSuffix(hashHex): string` (the other 35), `parseRangeResponse(body: string, suffix: string): number` (lines `SUFFIX:COUNT`, CRLF or LF, case-insensitive suffix match, 0 when absent or when the padded line count is 0), `HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"`.
  - `checkBreached(passwords: Map<string, string[]>, signal: AbortSignal, fetchFn = fetch): Promise<Map<string, number>>`: one request per distinct password, sequential, `headers: { "Add-Padding": "true" }`, `credentials: "omit"`, `referrerPolicy: "no-referrer"`, `cache: "no-store"`; returns uuid to count for counts above 0. The map key is the password, its value the uuids sharing it, so a reused password is looked up once.

- [ ] **Step 1: Write the failing tests**

```ts
// frontend/src/lib/health.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { passwordWeakness, buildHealthReport, sha1Hex, hibpPrefix, hibpSuffix, parseRangeResponse, checkBreached } from "./health";

test("weakness heuristic", () => {
  assert.equal(passwordWeakness(""), "empty");
  assert.equal(passwordWeakness("short1!A"), "shorter than 12 characters");
  assert.equal(passwordWeakness("aaaaaaaaaaaaaaaa"), "repeats one character");
  assert.equal(passwordWeakness("abcdefghijklmnop"), "only one kind of character");
  assert.equal(passwordWeakness("abcdefgh1234"), "fewer than 16 characters with two kinds");
  assert.equal(passwordWeakness("abcdefgh12345678"), null);
  assert.equal(passwordWeakness("correct-horse-battery-staple"), null);
});

test("report lists weak, reused, expired and expiring by uuid and title only", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(4));
  const root = vault.getLiveGroups()[0].uuid;
  const base = { username: "", url: "", notes: "", groupUuid: root, tags: [], favorite: false, custom: [] };
  const a = vault.createEntry({ ...base, title: "A", password: "same-password-1" });
  const b = vault.createEntry({ ...base, title: "B", password: "same-password-1" });
  const c = vault.createEntry({ ...base, title: "C", password: "short", expiresAt: new Date(Date.now() - 1000) });
  const d = vault.createEntry({ ...base, title: "D", password: "long enough and mixed 9", expiresAt: new Date(Date.now() + 5 * 86_400_000) });
  const r = buildHealthReport(vault);
  assert.deepEqual(r.reused.map((x) => x.uuid).sort(), [a.uuid, b.uuid].sort());
  assert.deepEqual(r.weak.map((x) => x.uuid), [c.uuid]);
  assert.deepEqual(r.expired.map((x) => x.uuid), [c.uuid]);
  assert.deepEqual(r.expiring.map((x) => x.uuid), [d.uuid]);
  assert.equal(JSON.stringify(r).includes("same-password-1"), false);
});

test("hibp prefix and range parsing", async () => {
  const hash = await sha1Hex("password");
  assert.equal(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assert.equal(hibpPrefix(hash), "5BAA6");
  assert.equal(hibpSuffix(hash), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
  const body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n00000000000000000000000000000000000:0\r\n";
  assert.equal(parseRangeResponse(body, hibpSuffix(hash)), 12345);
  assert.equal(parseRangeResponse(body, "00000000000000000000000000000000000"), 0);
  assert.equal(parseRangeResponse(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
});

test("checkBreached sends only the prefix and never the password", async () => {
  const urls: string[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    urls.push(url);
    assert.equal((init.headers as Record<string, string>)["Add-Padding"], "true");
    assert.equal(init.credentials, "omit");
    return new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\n");
  }) as unknown as typeof fetch;
  const out = await checkBreached(new Map([["password", ["u1", "u2"]], ["unique-and-safe-xyz", ["u3"]]]), new AbortController().signal, fetchFn);
  assert.deepEqual(urls, ["https://api.pwnedpasswords.com/range/5BAA6", `https://api.pwnedpasswords.com/range/${hibpPrefix(await sha1Hex("unique-and-safe-xyz"))}`]);
  assert.ok(urls.every((u) => !u.includes("password")));
  assert.deepEqual([...out.entries()], [["u1", 7], ["u2", 7]]);
});
```

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement `health.ts`**

```ts
export function passwordWeakness(password: string): string | null {
  if (password === "") return "empty";
  if (password.length < 12) return "shorter than 12 characters";
  if (/^(.)\1*$/.test(password)) return "repeats one character";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes === 1) return "only one kind of character";
  if (classes === 2 && password.length < 16) return "fewer than 16 characters with two kinds";
  return null;
}

export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}
export const hibpPrefix = (h: string) => h.slice(0, 5);
export const hibpSuffix = (h: string) => h.slice(5);

export function parseRangeResponse(body: string, suffix: string): number {
  const want = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [s, n] = line.split(":");
    if (s?.toUpperCase() === want) return Number.parseInt(n ?? "0", 10) || 0;
  }
  return 0;
}

```

`checkBreached` loops the map sequentially: `sha1Hex`, `fetchFn(HIBP_RANGE_URL + hibpPrefix(hash), { headers: { "Add-Padding": "true" }, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal })`, throw on `!res.ok`, `parseRangeResponse(await res.text(), hibpSuffix(hash))`, and sets every uuid of that password when the count is above 0. `buildHealthReport` composes `getLiveEntries()`, `passwordWeakness`, `findReusedPasswords(vault)`, `isExpired`, `expiresWithin(e, 30, now)`.

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: CSP**

`headers.go`: change `connect-src 'self'` to `connect-src 'self' https://api.pwnedpasswords.com`. `headers_test.go` `TestSecurityHeadersOnEveryResponse`: add `"connect-src 'self' https://api.pwnedpasswords.com"` to the directive list. Run `go test ./internal/api -run TestSecurityHeaders`.

- [ ] **Step 6: Health UI**

`HealthReport.tsx` (`Dialog size="lg"`, props `{ vault: KeePassVault; onOpenEntry: (uuid: string) => void; onClose: () => void }`): computes `buildHealthReport` once on open (`useMemo`), renders four sections with counts and one row per entry (title as a button calling `onOpenEntry` then `onClose`; reason or count beside it). A fifth section "Breached passwords" starts empty with the button "Check against Have I Been Pwned", which asks `dialogs.confirm({ title: "Check passwords against Have I Been Pwned?", message: "For each distinct password, the first five characters of its SHA-1 hash are sent to api.pwnedpasswords.com. The password, the rest of the hash, your entries and your account never leave this browser. Results are kept in memory until you lock the vault.", confirmLabel: "Check" })`, then runs `checkBreached` with an `AbortController` aborted on close, shows progress "n of m checked", and lists matches with the count ("seen 12,345 times"). Errors show inline with a Retry. `VaultPage.tsx`: a sidebar button "Health" (`HeartPulse` from lucide) sets `showHealth`; `onOpenEntry` uses the existing entry selection (`navigate({ tab: "vault", entry: uuid })`).

- [ ] **Step 7: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build` and `go test ./internal/api`. Mock at 1280 and 390: open Health, click an entry, run the HIBP check on the mock vault (real network; the mock server does not proxy it, so confirm in DevTools that the request is `GET /range/XXXXX` with `Add-Padding` and no cookies). If the preflight rejects `Add-Padding`, keep the header out and change the confirm copy to drop the padding sentence; note it in the PR.

`AGENTS.md`: bullet "`frontend/src/lib/health.ts` and `components/HealthReport.tsx`: the report is computed from live entries in memory (weak heuristic, reuse, expiry) and names entries by uuid and title only. The HIBP check is opt-in per click behind a confirm that states what leaves the browser; it sends the 5-character SHA-1 prefix with `Add-Padding` and no credentials, keeps results in memory, and is the only allowed non-self `connect-src` in `internal/api/headers.go`. `health.test.ts` pins the heuristic, the parser and the request shape."

```bash
git add frontend/src/lib/health.ts frontend/src/lib/health.test.ts frontend/src/components/HealthReport.tsx frontend/src/pages/VaultPage.tsx internal/api/headers.go internal/api/headers_test.go AGENTS.md
git commit -m "vault health report with an opt-in HIBP range check"
```

---

### Task 3: Vault key rotation

**Files:**
- Create: `frontend/src/lib/keyRotation.ts`, `frontend/src/lib/keyRotation.test.ts`, `frontend/src/lib/paperCode.ts`
- Modify: `frontend/src/lib/kdbx.ts` (`rekey`), `frontend/src/lib/vaultSave.ts` (`uploadVault` gains `recoveryEnvelope`), `frontend/src/lib/api.ts` (no change unless `patchJSON` is wanted early; see Task 4)
- Modify: `frontend/src/pages/SecuritySettings.tsx` (new section, reuse paper code display), `frontend/src/App.tsx` (rotation props)
- Modify: `AGENTS.md`

**Server facts that fix the order (verified in `internal/api/vault_handlers.go` and `internal/vault/vault.go`):**
- `POST /api/vault/upload` (raw body) reads `If-Match`, `X-Password-Envelope`, `X-Recovery-Envelope` and `X-Device-ID`; `handleVaultUpload` passes all of them to `vault.Store.SaveVault(userID, expectedVersion, kdbxData, passwordEnvelope, recoveryEnvelope, deviceID)`, which under one `s.mu.Lock()` checks the version (409 plus a preserved conflict file on mismatch, nothing overwritten), archives the current KDBX to history, renames the new KDBX into place, then writes the metadata with the new envelopes. Non-empty envelopes replace the old ones; device envelopes are carried over.
- `PUT /api/vault/envelopes` (`handleVaultEnvelopes` → `SaveEnvelopes`) has no version check and is a separate request. It must not be used for rotation, because a client that dies between "PUT new envelopes" and "upload new KDBX" leaves envelopes that unwrap a key the stored vault was never encrypted with. The reverse order strands the same way.
- Therefore: **one upload request carries the new KDBX and both new envelopes.** Client-side the request is atomic. Server-side the only window is a process crash between the KDBX rename and the metadata write inside `SaveVault`; it leaves the new KDBX beside the old envelopes, and the previous KDBX is already archived in history with a `_v{N}` id. Recovery for that case is Rollback to the newest snapshot (the old envelopes still unwrap the old key). The order KDBX-then-metadata is the fail-safe one; metadata-first would leave no snapshot the surviving envelopes can open. Do not reorder `SaveVault`.
- After the upload, every snapshot older than the rotation is encrypted with the retired key and can no longer be opened with the pinned key. Task 5's preview labels them; the confirm here says so and offers the KDBX download first.

**Client order:**
1. Prove the current password with the existing `proveCurrentPassword` (unwraps the stored envelope; never sent).
2. Refuse unless `saveState.kind === "saved"` (no in-flight or failed save). VaultPage is hidden on the Security tab, so no edit can enqueue during the flow.
3. `rotateVaultKey(vault, password, paperCode)` in memory: new 256-bit key, `vault.rekey(newKey)`, `exportBinary()`, `wrapVaultKey(newKey, password)`, `wrapVaultKey(newKey, paperCode)`.
4. `uploadVault(binary, version, passwordEnvelope, recoveryEnvelope)` with `If-Match`. On any failure: `vault.rekey(oldKey)`, show the error, nothing changed on the server (409 means another client saved; reload and try again).
5. On success (new version returned): `onKeyRotated(newKey, newVersion)` in App replaces `vaultKey`, builds `new VaultSaveQueue(vault, newVersion)`, and re-caches the device key (`clearDeviceVaultKey` then `storeDeviceVaultKey(u.username, bytesToHex(newKey))`). Then show the paper code with the existing type-it-back block (`paperCode`, `paperConfirmInput`, `normalizeCode`, `useHideAfter`). If the tab dies here the user still unlocks with the password; the paper code is simply regenerated later. Say that in the section copy.
6. Then, best effort and idempotent: `putJSON("/api/vault/envelopes", { deviceEnvelopes: {} })` (a non-nil empty map replaces the whole map in `SaveEnvelopes`), then `deleteJSON("/api/devices/" + id)` for every device (404 counts as done). Devices held the old key, which now opens nothing on the server, so a failure here is a cleanup gap not a security gap. List failures with "Retry revoking".

**Interfaces:**
- `KeePassVault.rekey(vaultKey: Uint8Array): void` sets `this.credentials = credentialFor(vaultKey)` and `this.db.credentials = this.credentials` (the same assignment `open` already makes for legacy files).
- `paperCode.ts`: `generatePaperCode(): string` moved out of `handleGeneratePaperRecovery` (32-symbol alphabet, `KYPASS-XXXX-XXXX-XXXX-XXXX`), reused by both flows.
- `keyRotation.ts`: `rotateVaultKey(vault: KeePassVault, password: string, paperCode: string): Promise<{ key: Uint8Array; binary: ArrayBuffer; passwordEnvelope: string; recoveryEnvelope: string }>`.
- `uploadVault(binary, version, passwordEnvelope?, recoveryEnvelope?, signal?)`; sets `X-Recovery-Envelope` when given. Update the one caller in `App.tsx` (`uploadVault(binary, 0, pwEnvelope)`) and `VaultSaveQueue` if it passes positional args.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/keyRotation.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { unwrapVaultKey } from "./vaultCrypto";
import { rotateVaultKey } from "./keyRotation";
import { generatePaperCode } from "./paperCode";

test("rotation re-encrypts under a fresh key and wraps it for the password and paper code", async () => {
  const oldKey = new Uint8Array(32).fill(6);
  const vault = await KeePassVault.createNew(oldKey);
  const root = vault.getLiveGroups()[0].uuid;
  const e = vault.createEntry({ title: "Keep me", username: "u", password: "p", url: "", notes: "", groupUuid: root, tags: [], favorite: false, custom: [] });
  const code = generatePaperCode();
  assert.match(code, /^KYPASS(-[A-HJ-NP-Z2-9]{4}){4}$/);
  const r = await rotateVaultKey(vault, "correct horse battery staple", code);
  assert.equal(r.key.length, 32);
  assert.notDeepEqual([...r.key], [...oldKey]);
  const reopened = await KeePassVault.open(r.binary, r.key);
  assert.ok(reopened.getLiveEntries().some((x) => x.uuid === e.uuid));
  await assert.rejects(KeePassVault.open(r.binary, oldKey), /key/i);
  assert.deepEqual([...await unwrapVaultKey(r.passwordEnvelope, "correct horse battery staple")], [...r.key]);
  assert.deepEqual([...await unwrapVaultKey(r.recoveryEnvelope, code)], [...r.key]);
  // The live vault object now saves under the new key; rekey back restores the old one.
  vault.rekey(oldKey);
  assert.ok(await KeePassVault.open(await vault.exportBinary(), oldKey));
});
```

If `KeePassVault.open` with the wrong key throws a `KdbxError` whose message does not contain "key", match on `err.code === Consts.ErrorCodes.InvalidKey` instead; check the actual message before adjusting. Argon2 at 64 MiB runs twice in this test; keep it in one test to bound runtime.

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
// frontend/src/lib/keyRotation.ts
import type { KeePassVault } from "./kdbx";
import { generateVaultMasterKey, wrapVaultKey } from "./vaultCrypto";

// One in-memory step. The caller sends binary and both envelopes in ONE upload so the
// server writes them under one lock; on failure it calls vault.rekey(oldKey).
export async function rotateVaultKey(vault: KeePassVault, password: string, paperCode: string) {
  const key = generateVaultMasterKey();
  vault.rekey(key);
  const binary = await vault.exportBinary();
  const [passwordEnvelope, recoveryEnvelope] = await Promise.all([wrapVaultKey(key, password), wrapVaultKey(key, paperCode)]);
  return { key, binary, passwordEnvelope, recoveryEnvelope };
}
```

`kdbx.ts` after `openForeign`:

```ts
  public rekey(vaultKey: Uint8Array): void {
    this.credentials = KeePassVault.credentialFor(vaultKey);
    this.db.credentials = this.credentials;
  }
```

- [ ] **Step 4: Run the test** → PASS.

- [ ] **Step 5: Wiring**

`App.tsx` passes to `SecuritySettings`: `vault`, `vaultVersion={saveState.version}`, `canRotate={saveState.kind === "saved"}`, `onExport={handleExportKdbx}`, and `onKeyRotated={(key, version) => { setVaultKey(key); setSaveQueue(new VaultSaveQueue(vault, version)); void clearDeviceVaultKey(user.username).then(() => storeDeviceVaultKey(user.username, bytesToHex(key))).catch(() => setLockNotice("Could not cache the new device key; you may need your master password again.")); }}`. Check how `saveQueue` is subscribed (`subscribe`) so the replacement queue is observed the same way the first one is.

`SecuritySettings.tsx`: new `<section className="field-card">` "Rotate Vault Key" between "Paper Recovery Code" and "Offline Vault Key": copy explaining that a new random key re-encrypts the vault, the password stays the same, every paired device is signed out, and snapshots from before today cannot be restored afterwards. Fields: current password (reuse `currentPassword`), button "Download vault first" (`onExport`), button "Rotate key" disabled unless `canRotate` (tooltip "Save or discard your unsaved edits first."). Flow: `dialogs.confirm({ title: "Rotate the vault key?", message: "All paired devices and extensions will be signed out and need pairing again. Snapshots taken before now cannot be rolled back to. Your master password does not change. A new paper recovery code will be shown once; the old one stops working.", confirmLabel: "Rotate", danger: true })`, then steps 1 to 6 above. Failures in step 6 render a list with "Retry revoking".

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock at 1280 and 390: rotate, see the paper code, type it back, confirm the mock's `dev-1` is gone, lock and unlock with the password, check the vault contents survive. Reload the tab after rotating: the cached device key must open the vault.

`AGENTS.md` Authentication section, after the paper recovery bullet: "Key rotation (`keyRotation.ts`, Security → Rotate Vault Key) generates a new vault key, re-encrypts the KDBX and sends it with both new envelopes in one `POST /api/vault/upload` with `If-Match`, so `SaveVault` writes vault and envelopes under one lock; `PUT /api/vault/envelopes` is never used for rotation. Device envelopes are then cleared and devices revoked best effort. Snapshots older than a rotation are encrypted with a retired key. `keyRotation.test.ts` proves old key refused, new key and both envelopes open."

```bash
git add frontend/src/lib/keyRotation.ts frontend/src/lib/keyRotation.test.ts frontend/src/lib/paperCode.ts frontend/src/lib/kdbx.ts frontend/src/lib/vaultSave.ts frontend/src/pages/SecuritySettings.tsx frontend/src/App.tsx AGENTS.md
git commit -m "vault key rotation in one atomic upload"
```

---

### Task 4: Devices: this device, rename, revoke all others, session revocation

**Files:**
- Modify: `internal/api/server.go` (`Session.DeviceID`, `PATCH /api/devices/{id}` route), `internal/api/device_handlers.go`, `internal/devices/devices.go` (`Rename`), `internal/api/api_test.go` (append), `internal/devices/devices_test.go` (append)
- Modify: `frontend/src/lib/api.ts` (`patchJSON`), `frontend/src/pages/SecuritySettings.tsx`, `frontend/mock/api.ts`
- Modify: `AGENTS.md`

**Interfaces:**
- `Session` gains `DeviceID string` (empty for browser sessions). `startSessionWithToken(userID, id, deviceID)` sets it (called from `handlePairingRedeem` with `dev.ID`; update `logoutFixture.pairDevice` in `sso_logout_test.go` if it calls the helper directly).
- `GET /api/devices` returns `[]deviceView` where `type deviceView struct { devices.Device; Current bool \`json:"current"\` }` and `Current = d.ID == sess.DeviceID` (read `sess, _ := s.currentSession(r)` inside the handler; browser sessions mark nothing). Encode an empty list as `[]`, not `null`.
- `PATCH /api/devices/{id}` body `{"name": string}`: owner check like revoke (404 otherwise), name trimmed, 1 to 64 characters, no `unicode.IsControl` runes, else 400; `devices.Store.Rename(deviceID, name string) error`; audit `device.renamed`; returns the updated `deviceView`.
- `handleDeviceRevoke` also deletes every session whose `DeviceID == deviceID` under `s.sessMu`.
- Frontend: `patchJSON<T>(path, body)` in `api.ts`; `Device` gains `current?: boolean`.

- [ ] **Step 1: Write the failing Go tests**

Append to `internal/api/api_test.go`:

```go
func TestDeviceRevokeEndsSession(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, sessCookie := signedInUser(t, srv, "erin", users.RoleUser)
	deviceID, token := pairDeviceForTest(t, handler, sessCookie)

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var listed []map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&listed)
	if len(listed) != 1 || listed[0]["current"] != true {
		t.Fatalf("device session should see itself as current: %+v", listed)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/devices/"+deviceID, nil)
	req.AddCookie(sessCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/vault/metadata", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device token still works: %d", rec.Code)
	}
}

func TestDeviceRename(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, owner := signedInUser(t, srv, "fay", users.RoleUser)
	_, other := signedInUser(t, srv, "gus", users.RoleUser)
	deviceID, _ := pairDeviceForTest(t, handler, owner)
	for _, tc := range []struct {
		cookie *http.Cookie
		body   string
		want   int
	}{
		{owner, `{"name":"  Kitchen tablet "}`, http.StatusOK},
		{owner, `{"name":""}`, http.StatusBadRequest},
		{owner, `{"name":"bad\u0007name"}`, http.StatusBadRequest},
		{owner, `{"name":"` + strings.Repeat("x", 65) + `"}`, http.StatusBadRequest},
		{other, `{"name":"mine now"}`, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodPatch, "/api/devices/"+deviceID, strings.NewReader(tc.body))
		req.AddCookie(tc.cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("PATCH %s with %s = %d, want %d", tc.cookie.Value[:4], tc.body, rec.Code, tc.want)
		}
	}
	dev, _ := srv.devices.Get(deviceID)
	if dev.Name != "Kitchen tablet" {
		t.Fatalf("name = %q", dev.Name)
	}
}
```

`pairDeviceForTest(t, handler, cookie) (deviceID, token string)` is a new helper that performs the start and redeem calls exactly as `TestDevicePairingFlow` does and returns `deviceId` and `sessionToken`. Refactor `TestDevicePairingFlow` to use it. Add `"strings"` to the imports if missing.

- [ ] **Step 2: Run to see them fail**

Run: `go test ./internal/api -run 'TestDeviceRevokeEndsSession|TestDeviceRename'` → FAIL (405 on PATCH, 200 after revoke).

- [ ] **Step 3: Implement**

`devices.go`: `func (s *Store) Rename(deviceID, name string) error` with the shape of `Revoke` (lock, lookup or `ErrNotFound`, `d.Name = name`, write back, `saveLocked()`); validation stays in the handler.

`device_handlers.go`: `handleDeviceRename` decodes `{Name string}` with `http.MaxBytesReader(w, r.Body, 4096)`, `name := strings.TrimSpace(req.Name)`, rejects `name == "" || utf8.RuneCountInString(name) > 64 || strings.ContainsFunc(name, unicode.IsControl)` with 400, owner check, `s.devices.Rename`, `s.record(r, "device.renamed", u.ID, deviceID, clientIP(r), "renamed device to "+name)`, returns the view. In `handleDeviceRevoke`, after `Revoke`, take `s.sessMu.Lock()` and `delete(s.sessions, tok)` for every session whose `DeviceID == deviceID`.

`server.go`: `mux.HandleFunc("PATCH /api/devices/{id}", s.withAuth(s.handleDeviceRename))`. The DELETE route has no CSRF check beyond the session cookie today (`validCSRF` is only used by backup handlers); follow the same pattern for PATCH and leave the CSRF question to a separate change, noted in the PR.

- [ ] **Step 4: Run the Go gates**

Run: `gofmt -l . ; go vet ./... ; go test -race ./internal/api ./internal/devices` → PASS.

- [ ] **Step 5: Frontend**

`api.ts`: `export function patchJSON<T>(path, body) { return requestJSON<T>(path, { method: "PATCH", body: JSON.stringify(body) }); }` mirroring `putJSON`.

`SecuritySettings.tsx` devices section: a `badge badge-cyan` "This device" when `d.current`; a "Rename" button → `dialogs.prompt({ title: "Rename device", label: "Name", defaultValue: d.name, validate: (v) => v.trim() ? (v.trim().length > 64 ? "Use at most 64 characters." : null) : "Enter a name." })` → `patchJSON(...)` → replace the device in state. A header button "Revoke all others" (visible when more than one device, or when at least one device and none is current) → `dialogs.confirm({ title: "Revoke every other device?", message: "Each paired app and extension except this one is signed out and must pair again. Your vault data is not changed.", confirmLabel: "Revoke all", danger: true })` → sequential `deleteJSON` over `devices.filter((d) => !d.current)`, treating `HttpError` 404 as done, then `loadDevices()`. Revoke of the current device keeps the existing per-row confirm.

`mock/api.ts`: add `current: false` to `dev-1`, seed a second device, and a `PATCH /api/devices/:id` branch that renames in `store.devices`.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock at 1280 and 390: rename, revoke all others, open the pairing modal and confirm it still polls and closes when the mock list grows (add a temporary device in the mock or rely on the countdown copy; document what was checked).

`AGENTS.md` Core Capabilities item 6: add "Device sessions carry `DeviceID`; revoking a device deletes its sessions. `GET /api/devices` marks the caller's own device `current`; `PATCH /api/devices/{id}` renames (1 to 64 characters, no control runes). `api_test.go` covers revoke ending the session and rename validation."

```bash
git add internal/api/server.go internal/api/device_handlers.go internal/api/api_test.go internal/api/sso_logout_test.go internal/devices/devices.go internal/devices/devices_test.go frontend/src/lib/api.ts frontend/src/pages/SecuritySettings.tsx frontend/mock/api.ts AGENTS.md
git commit -m "device rename, this-device marker, revoke all others, revoke ends sessions"
```

---

### Task 5: Snapshot preview and two-way conflict comparison

**Files:**
- Modify: `internal/vault/vault.go` (`OpenHistory`, id check in `RestoreHistory`), `internal/api/vault_handlers.go` (`handleVaultHistoryDownload`), `internal/api/server.go` (route)
- Create: `internal/api/history_download_test.go` (model: `conflict_download_test.go`)
- Create: `frontend/src/lib/vaultDiff.ts`, `frontend/src/lib/vaultDiff.test.ts`
- Modify: `frontend/src/lib/conflictComparison.ts`, `frontend/src/lib/conflictComparison.test.ts`, `frontend/src/lib/kdbx.ts` (`recoverEntryCopy` option `preferOriginalGroup`)
- Modify: `frontend/src/components/HistoryModal.tsx`, `frontend/src/components/ConflictComparison.tsx`, `frontend/src/App.tsx`, `frontend/mock/api.ts`
- Modify: `AGENTS.md`

**Interfaces:**
- Go: `validConflictID` is reused for history ids (rename to `validFileID` with both call sites, or keep and comment). `Store.OpenHistory(userID, historyID string) (io.ReadCloser, error)` mirrors `OpenConflict` (`os.OpenInRoot(s.historyDir(userID), id+".kdbx")`, regular file, `ErrNotFound`). `RestoreHistory` returns `ErrNotFound` for an invalid id before touching the filesystem; `handleVaultHistoryRestore` maps `ErrNotFound` to 404. `GET /api/vault/history/{id}` → `handleVaultHistoryDownload`: owner only, `Content-Type: application/x-keepass2`, `Cache-Control: no-store`, audit `vault.snapshot_downloaded` with the id.
- `vaultDiff.ts`: `diffVaults(live: VaultEntry[], other: VaultEntry[]): { added: Row[]; removed: Row[]; changed: Array<Row & { fields: string[] }>; counts: { live: number; other: number } }` with `type Row = { uuid: string; title: string }`. "added" means present in `other` only, "removed" means present in `live` only, "changed" compares `comparisonFields` from `conflictComparison.ts`. Titles only; no secrets in the result.
- `conflictComparison.ts`: `compareConflictEntries` additionally returns rows for entries only in `current` with `side: "current"` (existing rows get `side: "conflict"`), so the UI can list both directions. `recoverEntryCopy(source, uuid, { preferOriginalGroup: true })` lands the copy in the live group with the source entry's `groupUuid` when it exists in `this` and is not recycled, else the root.
- `HistoryModal` gains `snapshot?: { vault: KeePassVault; vaultKey: Uint8Array }` (App passes it whenever unlocked) and `allowRollback` becomes true while unlocked when `saveState.kind === "saved"`; the existing `onRestored` → `initVault(user)` reload path stays.

- [ ] **Step 1: Write the failing tests**

```go
// internal/api/history_download_test.go
package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kyvault-server/internal/users"
)

func TestHistoryDownloadOwnerOnlyAndSafeIDs(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.Routes()
	_, owner := signedInUser(t, srv, "hana", users.RoleUser)
	_, other := signedInUser(t, srv, "ivo", users.RoleUser)
	do := func(cookie *http.Cookie, method, path string, body []byte, ifMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	first := []byte("kdbx-v1")
	// Two uploads so the first becomes a history snapshot.
	for i, body := range [][]byte{first, []byte("kdbx-v2")} {
		if rec := do(owner, http.MethodPost, "/api/vault/upload", body, fmt.Sprintf("%q", strconv.Itoa(i))); rec.Code != http.StatusOK {
			t.Fatalf("upload %d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	var list []map[string]any
	_ = json.NewDecoder(do(owner, http.MethodGet, "/api/vault/history", nil, "").Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("history = %+v", list)
	}
	id := list[0]["id"].(string)
	if rec := do(owner, http.MethodGet, "/api/vault/history/"+id, nil, ""); rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), first) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("owner download = %d %q", rec.Code, rec.Header())
	}
	if rec := do(other, http.MethodGet, "/api/vault/history/"+id, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("other user = %d", rec.Code)
	}
	if rec := do(nil, http.MethodGet, "/api/vault/history/"+id, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", rec.Code)
	}
	for _, bad := range []string{"..", "..%2F..%2Fvault", "a%2Fb", "%00"} {
		if rec := do(owner, http.MethodGet, "/api/vault/history/"+bad, nil, ""); rec.Code != http.StatusNotFound {
			t.Errorf("download %q = %d, want 404", bad, rec.Code)
		}
		if rec := do(owner, http.MethodPost, "/api/vault/history/"+bad+"/restore", nil, ""); rec.Code != http.StatusNotFound {
			t.Errorf("restore %q = %d, want 404", bad, rec.Code)
		}
	}
}
```

Imports also need `"encoding/json"`, `"fmt"` and `"strconv"`. The `If-Match` values assume versions 0 then 1; read `metadata.version` from the first response if the test proves otherwise.

```ts
// frontend/src/lib/vaultDiff.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { diffVaults } from "./vaultDiff";

test("diff names added, removed and changed entries by title without secrets", async () => {
  const key = new Uint8Array(32).fill(11);
  const live = await KeePassVault.createNew(key);
  const root = live.getLiveGroups()[0].uuid;
  const base = { username: "", url: "", notes: "", groupUuid: root, tags: [], favorite: false, custom: [] };
  const keep = live.createEntry({ ...base, title: "Keep", password: "k" });
  const change = live.createEntry({ ...base, title: "Change", password: "old-secret" });
  const gone = live.createEntry({ ...base, title: "Gone", password: "g" });
  const snapshot = await KeePassVault.open(await live.exportBinary(), key);
  live.deleteEntry(gone.uuid);
  live.updateEntry({ ...live.getEntries().find((e) => e.uuid === change.uuid)!, password: "new-secret" });
  live.createEntry({ ...base, title: "New", password: "n" });
  const d = diffVaults(live.getLiveEntries(), snapshot.getLiveEntries());
  assert.deepEqual(d.added.map((r) => r.title), ["Gone"]);
  assert.deepEqual(d.removed.map((r) => r.title), ["New"]);
  assert.deepEqual(d.changed.map((r) => [r.title, r.fields]), [["Change", ["Password"]]]);
  assert.deepEqual(d.counts, { live: 3, other: 3 });
  assert.equal(JSON.stringify(d).includes("secret"), false);
  assert.ok(d.added.every((r) => r.uuid !== keep.uuid));
});
```

Append to `conflictComparison.test.ts`:

```ts
test("rows cover both directions and recovery prefers the original folder", async () => {
  const key = new Uint8Array(32).fill(12);
  const current = await KeePassVault.createNew(key);
  const root = current.getLiveGroups()[0].uuid;
  const work = current.createGroup("Work", root);
  const base = { username: "", url: "", notes: "", groupUuid: work.uuid, tags: [], favorite: false, custom: [] };
  const shared = current.createEntry({ ...base, title: "Shared", password: "a" });
  const onlyHere = current.createEntry({ ...base, title: "Only here", password: "b" });
  const conflict = await KeePassVault.open(await current.exportBinary(), key);
  conflict.deleteEntry(onlyHere.uuid);
  const onlyThere = conflict.createEntry({ ...base, title: "Only there", password: "c" });
  const rows = compareConflictEntries(current.getLiveEntries(), conflict.getLiveEntries());
  assert.deepEqual(rows.map((r) => [r.entry.title, r.side]).sort(), [["Only here", "current"], ["Only there", "conflict"], ["Shared", "conflict"]]);
  const copy = current.recoverEntryCopy(conflict, onlyThere.uuid, { preferOriginalGroup: true });
  assert.equal(current.getEntries().find((e) => e.uuid === copy)?.groupUuid, work.uuid);
  current.deleteGroup(work.uuid);
  const fallback = current.recoverEntryCopy(conflict, shared.uuid, { preferOriginalGroup: true });
  assert.equal(current.getEntries().find((e) => e.uuid === fallback)?.groupUuid, root);
});
```

(`deleteGroup` recycles when recycling is enabled; the recycled group must not count as "exists", which is why the fallback lands at root. If the test vault has recycling disabled, the group is gone outright and the assertion holds the same way.)

- [ ] **Step 2: Run to see them fail** → FAIL (Go 405 on the new route; TS missing exports).

- [ ] **Step 3: Implement**

Go: `OpenHistory` next to `OpenConflict`; in `RestoreHistory` first line `if !validConflictID(historyID) { return Metadata{}, ErrNotFound }`; handler:

```go
func (s *Server) handleVaultHistoryDownload(w http.ResponseWriter, r *http.Request, u users.User) {
	id := r.PathValue("id")
	file, err := s.vault.OpenHistory(u.ID, id)
	if errors.Is(err, vault.ErrNotFound) {
		http.Error(w, "snapshot not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "failed to open snapshot", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	s.record(r, "vault.snapshot_downloaded", u.ID, "", clientIP(r), "downloaded snapshot "+id)
	w.Header().Set("Content-Type", "application/x-keepass2")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, file)
}
```

`handleVaultHistoryRestore`: map `vault.ErrNotFound` to 404 instead of 500. Route: `mux.HandleFunc("GET /api/vault/history/{id}", s.withAuth(s.handleVaultHistoryDownload))`. Confirm `vault.ErrNotFound` is the sentinel `OpenConflict` returns.

`vaultDiff.ts`:

```ts
import type { VaultEntry } from "./kdbx";
import { comparisonFields } from "./conflictComparison";
type Row = { uuid: string; title: string };
export function diffVaults(live: VaultEntry[], other: VaultEntry[]) {
  const liveById = new Map(live.map((e) => [e.uuid, e]));
  const otherById = new Map(other.map((e) => [e.uuid, e]));
  const row = (e: VaultEntry): Row => ({ uuid: e.uuid, title: e.title });
  const added = other.filter((e) => !liveById.has(e.uuid)).map(row);
  const removed = live.filter((e) => !otherById.has(e.uuid)).map(row);
  const changed = other.flatMap((e) => {
    const l = liveById.get(e.uuid);
    if (!l) return [];
    const fields = comparisonFields.filter(([k]) => (e[k] || "") !== (l[k] || "")).map(([, label]) => label);
    return fields.length ? [{ ...row(e), fields }] : [];
  });
  return { added, removed, changed, counts: { live: live.length, other: other.length } };
}
```

`conflictComparison.ts`: after mapping conflict rows, append `current.filter((e) => !conflictIds.has(e.uuid)).map((entry) => ({ entry, current: entry, changedFields: [], side: "current" as const }))`; existing rows get `side: "conflict" as const`. `kdbx.ts` `recoverEntryCopy`: when `options?.preferOriginalGroup`, resolve `source`'s entry `parentGroup.uuid`, and if `this.findGroup(thatUuid)` exists and is not in `recycledGroupIds()`, use it as the target; `into` still wins when given.

- [ ] **Step 4: Run the tests** → PASS (`go test ./internal/api ./internal/vault` and `npx tsx --test src/lib/vaultDiff.test.ts src/lib/conflictComparison.test.ts`).

- [ ] **Step 5: UI**

`HistoryModal.tsx`: each snapshot row gains "Preview" (enabled when `snapshot` is set). Preview fetches `getBinary(`/api/vault/history/${id}`, signal)` and `KeePassVault.open(bytes, snapshot.vaultKey)`; on `KdbxError` `InvalidKey` show "This snapshot was encrypted with a previous vault key. It cannot be opened or rolled back to with the current key." and disable that row's Rollback. On success render counts ("14 entries, 5 folders in the snapshot; 15 and 5 now") and three lists from `diffVaults(snapshot.vault.getLiveEntries(), opened.getLiveEntries())`: "Entries in the snapshot only", "Entries now only", "Changed" with field labels. Rollback's confirm message becomes the counts sentence when a preview exists. `allowRollback` in App: `!vault ? !saveQueue : saveState.kind === "saved"`; the tooltip copy already fits. App also passes `recovery={vault && vaultKey && saveQueue ? { vault, vaultKey, onRecovered: () => saveQueue.changed() } : undefined}` (today the prop is never passed, so conflict comparison is unreachable from the app; this wires it).

`ConflictComparison.tsx`: rows with `side === "current"` render under "Only in your vault" with no Recover button; "Recover as copy" passes `{ preferOriginalGroup: true }` and the message says "Recovered a copy into its original folder." or "...into the top-level folder." depending on the resulting `groupUuid`.

`mock/api.ts`: `GET /api/vault/history/:id` serves the bytes recorded at upload time (store them beside the history entry), `POST /api/vault/history/:id/restore` swaps them in and bumps the version, and `GET /api/vault/conflicts/:id` serves a stored conflict so both flows are reachable in the mock.

- [ ] **Step 6: Verify, DOX, commit**

Run full Go gates and `cd frontend && npm test && npm run build`. Mock at 1280 and 390: make two saves, preview the older snapshot, read the diff, roll back while unlocked, see the reload.

`AGENTS.md` conflict bullets: add "`GET /api/vault/history/{id}` returns snapshot ciphertext to the owner with no-store and an audit row; history ids share `validConflictID` and `RestoreHistory` refuses path-shaped ids with 404. `HistoryModal` previews a snapshot with the current key and shows `diffVaults` (titles and field labels only) before Rollback, which is allowed while unlocked when nothing is unsaved; snapshots under a retired key are labelled and cannot be rolled back to from the UI. Conflict rows cover both directions; recovery prefers the original live folder."

```bash
git add internal/vault/vault.go internal/api/vault_handlers.go internal/api/server.go internal/api/history_download_test.go frontend/src/lib/vaultDiff.ts frontend/src/lib/vaultDiff.test.ts frontend/src/lib/conflictComparison.ts frontend/src/lib/conflictComparison.test.ts frontend/src/lib/kdbx.ts frontend/src/components/HistoryModal.tsx frontend/src/components/ConflictComparison.tsx frontend/src/App.tsx frontend/mock/api.ts AGENTS.md
git commit -m "snapshot preview with a diff before rollback; two-way conflict comparison"
```

---

### Task 6: PWA manifest

**Files:**
- Create: `frontend/public/manifest.webmanifest`, `frontend/public/icon-512.png` (copied from the tracked `KyVault.png`, 1024x1024, resized), `frontend/src/lib/pwa.test.ts`
- Modify: `frontend/index.html`, `internal/api/static.go`, `internal/api/static_test.go`
- Modify: `AGENTS.md`

**Decisions:** `frontend/public/logo.png` is 256x256 and `KyVault.png` at the repo root is the tracked 1024x1024 master. Produce `icon-512.png` with `magick KyVault.png -resize 512x512 frontend/public/icon-512.png`; if `magick` is absent, copy the master verbatim as `frontend/public/icon-1024.png` and declare `sizes: "1024x1024"` (never label a file with a size it is not). Either satisfies the 512 minimum. No service worker (offline unlock is out of scope by AGENTS.md). Theme colours are the Busnes tokens in `styles.css`: light `--ky-bg: #f8f6f0`, dark `#182326`.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/pwa.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("manifest is valid, icons exist and index.html references it", () => {
  const manifest = JSON.parse(readFileSync(join(root, "public", "manifest.webmanifest"), "utf8"));
  assert.equal(manifest.name, "KyVault");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.start_url, "/");
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2);
  for (const icon of manifest.icons) {
    assert.ok(existsSync(join(root, "public", icon.src.replace(/^\//, ""))), icon.src);
    assert.match(icon.sizes, /^\d+x\d+$/);
    assert.equal(icon.type, "image/png");
  }
  assert.ok(manifest.icons.some((i: { sizes: string }) => Number(i.sizes.split("x")[0]) >= 512));
  const html = readFileSync(join(root, "index.html"), "utf8");
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest"/);
  assert.match(html, /<meta name="theme-color" content="#f8f6f0" media="\(prefers-color-scheme: light\)"/);
  assert.match(html, /<meta name="theme-color" content="#182326" media="\(prefers-color-scheme: dark\)"/);
  assert.ok(!html.includes("serviceWorker"));
});
```

Go, append `TestManifestContentType` to `static_test.go`, built like `TestSPAHandlerNeverListsDirectories`: `dir := t.TempDir()`, write `index.html` and `manifest.webmanifest` (`{}`), `h := SPAHandler(dir)`, `GET /manifest.webmanifest` → 200 and `Content-Type` starting with `application/manifest+json`.

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`manifest.webmanifest`:

```json
{ "name": "KyVault", "short_name": "KyVault", "description": "Zero-knowledge KeePass vault",
  "start_url": "/", "scope": "/", "display": "standalone",
  "background_color": "#f8f6f0", "theme_color": "#f8f6f0",
  "icons": [ { "src": "/logo.png", "sizes": "256x256", "type": "image/png", "purpose": "any" },
             { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" } ] }
```

`index.html` head: `<link rel="manifest" href="/manifest.webmanifest" />` and the two `theme-color` metas. `static.go`: `mime.AddExtensionType(".webmanifest", "application/manifest+json")` in an `init()` (Go's built-in table does not include the extension; verify by running the test before adding it). The CSP needs no change: `manifest-src` falls back to `default-src 'self'`.

- [ ] **Step 4: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`, `go test ./internal/api -run TestManifest`. Browser: Chrome DevTools → Application → Manifest shows no errors and the install prompt is offered on the mock.

`AGENTS.md` Core Capabilities item 8: add "Installable as a PWA through `frontend/public/manifest.webmanifest` (icons from `logo.png` and a 512px export of `KyVault.png`; no service worker, so nothing works offline). `pwa.test.ts` validates the manifest and the `index.html` references; `static.go` serves `.webmanifest` as `application/manifest+json`."

```bash
git add frontend/public/manifest.webmanifest frontend/public/icon-512.png frontend/src/lib/pwa.test.ts frontend/index.html internal/api/static.go internal/api/static_test.go AGENTS.md
git commit -m "PWA manifest and theme colours, no service worker"
```

---

### Task 7: Locked-draft inventory and 7-day cleanup

**Files:**
- Modify: `frontend/src/lib/lockedDraft.ts`, `frontend/src/lib/lockedDraft.test.ts` (append), `frontend/src/App.tsx` (call after unlock)
- Modify: `AGENTS.md`

**Store shape today (`lockedDraft.ts`):** IndexedDB `kypassword-locked-drafts` v1, object store `drafts` with out-of-line keys. `App.tsx` writes key `${u.id}:${crypto.randomUUID()}` and value `LockedDraft { iv, ciphertext }`; the pointer for this tab is `sessionStorage["kyvault.draft:" + u.id]`. Account binding is the key prefix plus the AAD inside the ciphertext; there is no timestamp.

**Interfaces:**
- `LockedDraft` gains `sealedAt?: number` (ms since epoch). `sealDraft` sets it. `openDraft` ignores it (AAD unchanged, so older checkpoints still open; `5e2ca9d` already made `openDraft` tolerant of missing fields).
- `DRAFT_MAX_AGE_MS = 7 * 86_400_000`.
- Pure: `planDraftCleanup(entries: Array<{ id: string; sealedAt?: number }>, keep: string | undefined, now: number): { remove: string[]; stamp: string[] }`: `remove` = ids other than `keep` whose `sealedAt` is older than the max age; `stamp` = ids without `sealedAt` (legacy), which get `sealedAt = now` so they age out a week later instead of being deleted blind.
- `pruneDrafts(userId: string, keep: string | undefined, now = Date.now()): Promise<void>`: opens one readwrite transaction, cursors over `IDBKeyRange.bound(`${userId}:`, `${userId}:￿`)`, applies the plan (`cursor.delete()` / `cursor.update({ ...value, sealedAt: now })`). Errors are swallowed like `removeDraft`; this is housekeeping.

- [ ] **Step 1: Write the failing test**

Append to `lockedDraft.test.ts`:

```ts
test("cleanup plan removes old drafts of this account, keeps the current pointer and stamps legacy ones", async () => {
  // add planDraftCleanup and DRAFT_MAX_AGE_MS to the file's existing import from "./lockedDraft"
  const now = 1_800_000_000_000;
  const plan = planDraftCleanup([
    { id: "u1:old", sealedAt: now - DRAFT_MAX_AGE_MS - 1 },
    { id: "u1:fresh", sealedAt: now - 1000 },
    { id: "u1:legacy" },
    { id: "u1:current", sealedAt: now - DRAFT_MAX_AGE_MS * 2 },
  ], "u1:current", now);
  assert.deepEqual(plan, { remove: ["u1:old"], stamp: ["u1:legacy"] });
  const sealed = await sealDraft(new Uint8Array([1]).buffer, { version: 1, dirty: false, entry: null }, new Uint8Array(32).fill(1), "u1");
  assert.ok(typeof sealed.sealedAt === "number" && Math.abs(sealed.sealedAt - Date.now()) < 5000);
});
```

The existing "recovery copy authenticates..." test compares `openDraft` output, not the sealed object, so adding `sealedAt` does not break it; if a `deepEqual` on the sealed value exists elsewhere, extend it.

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
export const DRAFT_MAX_AGE_MS = 7 * 86_400_000;

export function planDraftCleanup(entries: Array<{ id: string; sealedAt?: number }>, keep: string | undefined, now: number) {
  const remove: string[] = [], stamp: string[] = [];
  for (const { id, sealedAt } of entries) {
    if (id === keep) continue;
    if (sealedAt === undefined) stamp.push(id);
    else if (now - sealedAt > DRAFT_MAX_AGE_MS) remove.push(id);
  }
  return { remove, stamp };
}

```

`pruneDrafts` opens one `readwrite` transaction, walks `store.openCursor(IDBKeyRange.bound(`${userId}:`, `${userId}:￿`))` collecting `{ id: String(cursor.key), sealedAt: cursor.value.sealedAt, value }`, then applies `planDraftCleanup`: `store.delete(id)` for `remove`, `store.put({ ...value, sealedAt: now }, id)` for `stamp`. Wrap the whole thing in `try {} catch {}` like `removeDraft`. Extract `withDraftStore(mode, fn)` from `draftStore` (open, transaction, `oncomplete`/`onabort`/`onerror`, `db.close()` in `finally`) and have both call it, so the open/close logic exists once. In `App.tsx`, after a successful unlock in `initVault` (where `removeDraft(id)` runs), add `void pruneDrafts(u.id, recoveryId(u))`. Pass the pointer as `keep` even though the unlock consumed it: a second tab may still be pointing at its own draft, which the prefix scan covers by age only.

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: lock with unsaved edits, unlock, check DevTools → Application → IndexedDB shows the draft gone (consumed) and a `sealedAt` on any draft made in a second tab; set the system clock is not needed, `planDraftCleanup` is the proof.

`AGENTS.md` `lockedDraft.ts` bullet: replace the `ponytail:` sentence with "Drafts record `sealedAt`; after each unlock `pruneDrafts` scans this account's key prefix and deletes drafts older than 7 days, stamps legacy drafts without a timestamp so they age out, and never touches the current tab's pointer. `planDraftCleanup` is the tested decision; the IndexedDB walk is exercised in the browser pass."

```bash
git add frontend/src/lib/lockedDraft.ts frontend/src/lib/lockedDraft.test.ts frontend/src/App.tsx AGENTS.md
git commit -m "prune locked drafts older than seven days on unlock"
```

---

### Task 8: End-of-phase verification and PR (controller)

- [ ] Full gates: `gofmt -l . ; go vet ./... ; go test -race ./...` and `cd frontend && npm test && npm run build`. `govulncheck ./...` and `npm audit --audit-level=high` as CI runs them.
- [ ] Browser pass with the mock at 1280px and 390px: passphrase mode and meter; Health report and one real HIBP check (inspect the request in DevTools: path prefix only, `Add-Padding: true`, no cookies); key rotation end to end including reload with the cached device key and a locked unlock with the password; device rename, "This device" badge (visible only from a device session, so confirm the field is `false` in the mock and the badge is absent), revoke all others, pairing modal closing on a mock-added device; snapshot preview, diff, rollback while unlocked, conflict recover into its original folder; manifest install prompt; draft `sealedAt` in IndexedDB.
- [ ] Read the diff of every task, not the commit messages; confirm `noNativeDialogs.test.ts` still passes and no `alert(`/`confirm(` crept into `HealthReport.tsx` or `HistoryModal.tsx`.
- [ ] Open the PR with the `pull-request` skill. Title: `Phase 4b vault features from the 2026-09-25 audit`. Base: `master`. Body lists the two behaviour changes reviewers must know: revoking a device now ends its sessions, and Rollback is available while unlocked when nothing is unsaved. Note the CSRF gap on `DELETE`/`PATCH /api/devices/{id}` as a follow-up, not fixed here.
