# Phase 3b: Flows, Polish and KyForge Release Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Track B is planned only: do not execute any Track B task until Yoshi says go.

**Goal:** Finish the Phase 3 annoyances on the KyVault web app (Track A), and record the approved-for-planning route to restore KyForge's release attestation on a private repository (Track B).

**Architecture:** Track A builds on the Phase 3a foundation (dialog host, hash routes, dev mock): each task is a page-level flow fix with a pure helper and a `node --test` where logic exists, verified against `npm run dev:mock`. Track B replaces GitHub's attestation store (Enterprise Cloud only for private repos) with keyless cosign signing and SLSA provenance against the public Sigstore instance, keeping the tested-image hand-off, digest verification and tip-of-master promotion exactly as they are.

**Tech Stack:** React 18 + TypeScript, `tsx --test`, Go stdlib; GitHub Actions, `sigstore/cosign-installer`, `cosign` v2.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md` (Phase 3 list) and `/home/yoshi/busness.app/kyforge-release-attestation-handoff.md` (Track B).

## Global Constraints

- Track A: branch `fix/phase3b-flows` from `master` (PR #60 merged). One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`. Browser pass with `npm run dev:mock` at 1280px and 390px for every flow a task changes, including a browser Back step and a Security-then-Vault tab hop.
- No native `confirm`/`prompt`/`alert` (the `noNativeDialogs` test enforces it). Every question goes through `useDialogs()`.
- The master password, paper code and vault key never leave the browser. Printing uses the browser's print dialog on a print-only region; nothing is sent anywhere.
- No new runtime dependencies in Track A. Copy rules: sentences, no em-dashes, no "successfully".
- Track B: no billing change, no visibility change, no `continue-on-error`, no manual `:latest` move, no removal of verification. The tested image is published without a rebuild. `:latest` advances only at the tip of `master` to the verified digest. Docs, CI and DOX must agree.
- DOX: update `AGENTS.md` where a task changes a contract.

## Review Focus

1. A brand-new user must never see "Unlock" wording: the first password they type is clearly a creation with a confirm field. Pinned: Task A1 helper test plus the browser pass.
2. Cancelling a never-applied new entry leaves no entry and no save revision. Pinned: Task A2 `newEntryDraft.test.ts`.
3. A generated password with "Numbers" ticked always contains a digit; with no class ticked nothing is generated. Pinned: Task A5 `generatePassword.test.ts`.
4. Audit paging returns older entries than the last shown, never duplicates, and stops cleanly. Pinned: Task A6 Go test.
5. Track B: `cosign verify-attestation` on the promoted `:latest` digest must succeed with the workflow identity and fail for any other identity. Pinned: Task B3 verify step and Task B4 docs.

---

## Track A: KyVault flows and polish

### Task 1 (A1): First-run creates a master password; the unlock dialog stays on the vault tab

**Files:**
- Create: `frontend/src/lib/unlockMode.ts`, `frontend/src/lib/unlockMode.test.ts`
- Modify: `frontend/src/App.tsx` (unlock modal, `initVault` case 1, auto-open logic)
- Modify: `AGENTS.md` (Authentication)

**Interfaces:**
- Produces: `unlockMode(version: number | undefined): "create" | "unlock"`; `checkCreatePassword(password: string, confirm: string): string | null` (reuses `checkMasterPassword`, adds "The passwords do not match.").
- `App` state `vaultLockedReason: "new" | "locked" | null` replaces the implicit "open the modal" calls: `initVault` sets the reason and the modal renders only when `route.tab === "vault"` and the reason is set; other tabs show the existing "Vault is Locked" panel whose button opens the modal.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/unlockMode.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { unlockMode, checkCreatePassword } from "./unlockMode";

test("a vault with no version is created, anything else is unlocked", () => {
  assert.equal(unlockMode(undefined), "create");
  assert.equal(unlockMode(0), "create");
  assert.equal(unlockMode(1), "unlock");
});

test("create checks length then match", () => {
  assert.match(checkCreatePassword("short", "short") ?? "", /12/);
  assert.equal(checkCreatePassword("correct horse battery", "correct horse batter"), "The passwords do not match.");
  assert.equal(checkCreatePassword("correct horse battery", "correct horse battery"), null);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/unlockMode.test.ts` → FAIL.

- [ ] **Step 3: Implement the helper**

```ts
// frontend/src/lib/unlockMode.ts
import { checkMasterPassword } from "./masterPassword";

export function unlockMode(version: number | undefined): "create" | "unlock" {
  return version ? "unlock" : "create";
}

export function checkCreatePassword(password: string, confirm: string): string | null {
  return checkMasterPassword(password) ?? (password === confirm ? null : "The passwords do not match.");
}
```

- [ ] **Step 4: Rework the modal in `App.tsx`**

- Keep `VaultMetadata` in state (`const [meta, setMeta] = useState<VaultMetadata | null>(null)`, set in `initVault` after the metadata fetch) so the modal knows the mode: `const mode = unlockMode(meta?.version)`.
- Replace every `setShowUnlockModal(true)` inside `initVault` with `setLockedReason(meta?.version ? "locked" : "new")` (keep `setShowUnlockModal(false)` on success). Render the modal when `showUnlockModal || (lockedReason && route.tab === "vault")`. The "Unlock Vault" button on the locked panel sets `showUnlockModal` true. Closing the modal clears `showUnlockModal` and sets `lockedReason` to `null` so it does not reopen until the next lock.
- Create mode copy: title "Create your master password"; paragraph "This password encrypts your vault key in your browser. It is never sent to the server, so nobody can reset it for you. Use at least 12 characters; a short sentence works well."; two fields (`autoComplete="new-password"`, `data-autofocus` on the first) labelled "Master password" and "Confirm master password"; submit label "Create vault"; the "Rollback / History" button hidden. `handleUnlockSubmit` in create mode runs `checkCreatePassword` first and shows the message in the existing error box.
- After a successful create, set `lockNotice` to "Vault created. Generate a paper recovery code from Security so a forgotten password does not lock you out." with a button that navigates to `{ tab: "security" }`.
- Unlock mode is unchanged except `autoComplete="current-password"` and `data-autofocus` on the input, and the close button is disabled while `unlocking`.

- [ ] **Step 5: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. With the mock (fresh server so version is 0): the create dialog shows with two fields, a mismatch shows the message, a 12-character match creates the vault and the notice appears; then Lock, go to Admin, reload: no dialog on Admin, the locked panel shows; the Vault tab shows the dialog.

`AGENTS.md` Authentication: after the master password bullet add "A version-0 vault shows a create dialog with a confirm field (`lib/unlockMode.ts`); the unlock dialog auto-opens only on the vault tab."

```bash
git add frontend/src/lib/unlockMode.ts frontend/src/lib/unlockMode.test.ts frontend/src/App.tsx AGENTS.md
git commit -m "first run creates a master password; unlock dialog stays on the vault tab"
```

---

### Task 2 (A2): New entries are drafts until applied; folders drive the selection; All Items is a button

**Files:**
- Create: `frontend/src/lib/newEntryDraft.ts`, `frontend/src/lib/newEntryDraft.test.ts`
- Modify: `frontend/src/pages/VaultPage.tsx`

**Interfaces:**
- Produces: `type NewEntryDraft = { groupUuid: string }`; `createFromDraft(vault, draft, fields): VaultEntry` (calls `vault.createEntry` with the applied fields); `VaultPage` state `newDraft: NewEntryDraft | null`. While `newDraft` is set the editor shows empty fields; Apply creates the entry and selects it; Cancel clears the draft with no vault mutation.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/newEntryDraft.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { createFromDraft } from "./newEntryDraft";

test("a draft creates nothing until applied", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(4));
  const before = vault.getLiveEntries().length;
  const root = vault.getLiveGroups()[0].uuid;
  const draft = { groupUuid: root };
  assert.equal(vault.getLiveEntries().length, before);
  const entry = createFromDraft(vault, draft, { title: "Bank", username: "me", password: "pw", url: "", notes: "", totpSeed: "" });
  assert.equal(vault.getLiveEntries().length, before + 1);
  assert.equal(entry.groupUuid, root);
  assert.equal(entry.title, "Bank");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd frontend && npx tsx --test src/lib/newEntryDraft.test.ts` → FAIL.

- [ ] **Step 3: Implement**

```ts
// frontend/src/lib/newEntryDraft.ts
import type { KeePassVault, VaultEntry } from "./kdbx";

export type NewEntryDraft = { groupUuid: string };
export type EntryFields = { title: string; username: string; password: string; url: string; notes: string; totpSeed: string };

// The vault is not touched until the user applies the first edit, so Cancel leaves
// no entry and no save revision behind.
export function createFromDraft(vault: KeePassVault, draft: NewEntryDraft, fields: EntryFields): VaultEntry {
  return vault.createEntry({ ...fields, totpSeed: fields.totpSeed || undefined, groupUuid: draft.groupUuid, title: fields.title || "Untitled" });
}
```

- [ ] **Step 4: Wire the page**

- `handleCreateNewEntry`: after `canChangeEntry()`, set `newDraft = { groupUuid }` (same group choice as today), clear `selectedEntryUuid`, `navigate({ tab: "vault" })`, `setPane("detail")`, set the editor fields to empty strings with `editGroupUuid = groupUuid`, `setIsEditing(true)`. Do not call `vault.createEntry` or `onChanged`.
- The detail pane renders the editor when `selectedEntry || newDraft`; the header reads "New entry" for a draft.
- `handleSaveEntry`: when `newDraft` is set, `const entry = createFromDraft(vault, newDraft, fields)`; then `onChanged()`, `refreshVaultData()`, select it, `navigate` to it, clear `newDraft`.
- Cancel while `newDraft`: clear the draft, `setIsEditing(false)`, pane to list. `draftDirty` treats a draft with any non-empty field as dirty so `canChangeEntry` still asks.
- Folder selection (every group button, All Items, Recycle Bin): if the selected entry is not in the chosen folder (`entry.groupUuid !== uuid` for a group; recycled state for the bin), clear the selection and `navigate({ tab: "vault" })`.
- "All Items" becomes a `<button type="button" className="group-item …" aria-pressed>` like the other groups.

- [ ] **Step 5: Verify and commit**

Run: `cd frontend && npm test && npm run build`. Mock: Add Entry, Cancel: list unchanged and "All changes saved" stays; Add Entry, type a title, Apply: entry appears and autosave runs; select a folder while an entry from another folder is open: the detail pane clears; Tab to "All Items" and press Enter: it selects.

```bash
git add frontend/src/lib/newEntryDraft.ts frontend/src/lib/newEntryDraft.test.ts frontend/src/pages/VaultPage.tsx
git commit -m "new entries are drafts until applied; folders drive the selection"
```

---

### Task 3 (A3): Paper code and vault key are handled like secrets

**Files:**
- Create: `frontend/src/lib/secretDisplay.ts`, `frontend/src/lib/secretDisplay.test.ts`
- Modify: `frontend/src/pages/SecuritySettings.tsx`, `frontend/src/styles/styles.css`

**Interfaces:**
- Produces: `groupHex(hex: string, size = 8): string` ("aabbccdd eeff0011 …"); `useHideAfter(ms: number, visible: boolean, hide: () => void)` hook that hides a revealed secret after `ms` and on `visibilitychange` to hidden; a `PrintOnly` region using `@media print` so only the secret block prints.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/secretDisplay.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { groupHex } from "./secretDisplay";

test("hex is grouped for reading and copies back without spaces", () => {
  const hex = "ab".repeat(32);
  const grouped = groupHex(hex);
  assert.equal(grouped.split(" ").length, 8);
  assert.equal(grouped.replace(/ /g, ""), hex);
  assert.equal(groupHex("abc", 2), "ab c");
});
```

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
// frontend/src/lib/secretDisplay.ts
import { useEffect } from "react";

export function groupHex(hex: string, size = 8): string {
  return hex.match(new RegExp(`.{1,${size}}`, "g"))?.join(" ") ?? "";
}

// A revealed secret hides itself: after a timeout, and as soon as the tab is hidden.
export function useHideAfter(ms: number, visible: boolean, hide: () => void): void {
  useEffect(() => {
    if (!visible) return;
    const timer = setTimeout(hide, ms);
    const onVisibility = () => { if (document.visibilityState === "hidden") hide(); };
    document.addEventListener("visibilitychange", onVisibility);
    return () => { clearTimeout(timer); document.removeEventListener("visibilitychange", onVisibility); };
  }, [visible, ms, hide]);
}
```

- [ ] **Step 4: Page changes**

- Vault key block: show `groupHex(bytesToHex(vaultKey))`, a "Copy" button (`copyText(hex, { clearAfterMs: SECRET_CLIPBOARD_MS })`, tick on success, "Cleared from the clipboard after 30 seconds when the browser allows it."), a "Print" button that calls `window.print()`, and `useHideAfter(60_000, showVaultKey, () => setShowVaultKey(false))`.
- Paper code block: same Copy and Print, `useHideAfter(120_000, …)`, plus a "type it back" step: an input "Type the code to confirm you saved it" and a "Done" button enabled only when the typed value equals the code (case-insensitive, dashes optional); Done hides the code. Until Done, a line reads "Not confirmed yet."
- Print: wrap each secret block in `<div className="print-only-secret">`; add to `styles.css`:

```css
@media print {
  body * { visibility: hidden; }
  .print-only-secret, .print-only-secret * { visibility: visible; }
  .print-only-secret { position: absolute; left: 0; top: 0; font-family: var(--font-mono); font-size: 14pt; }
}
```

- [ ] **Step 5: Verify and commit**

Run: `cd frontend && npm test && npm run build`. Mock: reveal the key, Copy shows the tick, switch tabs and back: the key is hidden; generate a paper code, type it back, Done hides it.

```bash
git add frontend/src/lib/secretDisplay.ts frontend/src/lib/secretDisplay.test.ts frontend/src/pages/SecuritySettings.tsx frontend/src/styles/styles.css
git commit -m "copy, print, auto-hide and type-back for the paper code and vault key"
```

---

### Task 4 (A4): Messages survive their modal; disabled actions say why

**Files:**
- Modify: `frontend/src/components/HistoryModal.tsx`, `frontend/src/components/DevicePairingModal.tsx`, `frontend/src/pages/VaultPage.tsx`, `frontend/src/App.tsx`, `frontend/src/pages/SecuritySettings.tsx`

- [ ] **Step 1: Lift the messages**

- `HistoryModal` gains `onNotice: (text: string) => void`; after a rollback it calls `onNotice("Vault restored to the selected version.")` instead of setting local state, then `onRestored()`. `App.tsx` and `VaultPage.tsx` pass a setter for their existing notice banner (`lockNotice` in App; `importMessage` in VaultPage).
- `DevicePairingModal` gains `onPaired?: () => void` and polls `GET /api/devices` every 3 seconds while open; when the device count grows, it calls `onPaired` and closes. `SecuritySettings` shows "Device paired." and refreshes the list; `VaultPage` shows the same in its banner.
- Rollback and Discard buttons in `HistoryModal`: `title` explains the disabled state: "Save or discard your unsaved edits first." when `!allowRollback`.
- Rename "Vault successfully restored." (unchanged line) to the lifted copy above.

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`. Mock: roll back from the history modal: the modal closes and the banner shows; open pairing, delete a device in another tab of the mock (or accept the polling path via the mock's device list), the modal closes on count change.

```bash
git add frontend/src/components/HistoryModal.tsx frontend/src/components/DevicePairingModal.tsx frontend/src/pages/VaultPage.tsx frontend/src/App.tsx frontend/src/pages/SecuritySettings.tsx
git commit -m "lift modal outcomes to page banners; explain disabled rollback"
```

---

### Task 5 (A5): Password generator you can trust

**Files:**
- Create: `frontend/src/lib/generatePassword.ts`, `frontend/src/lib/generatePassword.test.ts`
- Modify: `frontend/src/components/PasswordGenerator.tsx`
- Modify: `AGENTS.md` (Child DOX Index)

**Interfaces:**
- Produces: `type GeneratorOptions = { length: number; upper: boolean; lower: boolean; numbers: boolean; symbols: boolean }`; `generatePassword(opts, random = crypto.getRandomValues.bind(crypto)): string` guaranteeing at least one character from every selected class, throwing `Error("Select at least one character set.")` when none is selected, and `Error("Length must be between 8 and 128.")` outside that range. `loadGeneratorOptions()/saveGeneratorOptions()` on `localStorage` key `kyvault.generator`.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/generatePassword.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePassword } from "./generatePassword";

test("every selected class appears at least once", () => {
  for (let i = 0; i < 200; i++) {
    const p = generatePassword({ length: 8, upper: true, lower: true, numbers: true, symbols: true });
    assert.equal(p.length, 8);
    assert.match(p, /[A-Z]/); assert.match(p, /[a-z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
  }
});

test("unselected classes never appear and bad options throw", () => {
  const p = generatePassword({ length: 32, upper: false, lower: true, numbers: false, symbols: false });
  assert.match(p, /^[a-z]{32}$/);
  assert.throws(() => generatePassword({ length: 12, upper: false, lower: false, numbers: false, symbols: false }), /at least one/);
  assert.throws(() => generatePassword({ length: 7, upper: true, lower: true, numbers: true, symbols: true }), /between 8 and 128/);
});
```

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

```ts
// frontend/src/lib/generatePassword.ts
export type GeneratorOptions = { length: number; upper: boolean; lower: boolean; numbers: boolean; symbols: boolean };
const SETS = { upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", lower: "abcdefghijklmnopqrstuvwxyz", numbers: "0123456789", symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?" } as const;
export const DEFAULT_GENERATOR: GeneratorOptions = { length: 20, upper: true, lower: true, numbers: true, symbols: true };

// Rejection sampling keeps every pick uniform; one guaranteed pick per selected class,
// then the rest from the union, then a Fisher-Yates shuffle so the guaranteed picks
// are not always at the front.
export function generatePassword(opts: GeneratorOptions, random: (a: Uint32Array) => Uint32Array = (a) => crypto.getRandomValues(a)): string {
  if (opts.length < 8 || opts.length > 128 || !Number.isInteger(opts.length)) throw new Error("Length must be between 8 and 128.");
  const classes = (Object.keys(SETS) as Array<keyof typeof SETS>).filter((k) => opts[k]);
  if (classes.length === 0) throw new Error("Select at least one character set.");
  const union = classes.map((k) => SETS[k]).join("");
  const pick = (from: string) => {
    const limit = Math.floor(0x100000000 / from.length) * from.length;
    const buf = new Uint32Array(1);
    do { random(buf); } while (buf[0] >= limit);
    return from[buf[0] % from.length];
  };
  const uniformBelow = (n: number) => {
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    do { random(buf); } while (buf[0] >= limit);
    return buf[0] % n;
  };
  const chars = classes.map((k) => pick(SETS[k]));
  while (chars.length < opts.length) chars.push(pick(union));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = uniformBelow(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

const KEY = "kyvault.generator";
export function loadGeneratorOptions(storage: Pick<Storage, "getItem"> = localStorage): GeneratorOptions {
  try {
    const raw = storage.getItem(KEY);
    if (!raw) return DEFAULT_GENERATOR;
    const parsed = JSON.parse(raw) as Partial<GeneratorOptions>;
    const merged = { ...DEFAULT_GENERATOR, ...parsed };
    return Number.isInteger(merged.length) && merged.length >= 8 && merged.length <= 128 ? merged : DEFAULT_GENERATOR;
  } catch { return DEFAULT_GENERATOR; }
}
export function saveGeneratorOptions(opts: GeneratorOptions, storage: Pick<Storage, "setItem"> = localStorage): void {
  try { storage.setItem(KEY, JSON.stringify(opts)); } catch { /* preference only */ }
}
```

Add a test that `generatePassword` with a stubbed `random` returning zeros yields a deterministic string of the expected length (proves the shuffle terminates and does not depend on Math.random).

- [ ] **Step 4: Rework the component**

- State comes from `loadGeneratorOptions()`; every change calls `saveGeneratorOptions`.
- Length is a number input (8 to 128) plus the slider, both bound to the same value.
- When no class is selected, the output area shows "Select at least one character set." and Copy and Use are disabled.
- "Use Password": if the target field is non-empty, `dialogs.confirm({ title: "Replace the current password?", message: "The current password will be replaced in the editor. Apply Edits keeps the previous one in entry history.", confirmLabel: "Replace" })` first. The component receives `currentValue: string` from `VaultPage` for that check.
- Add "Exclude look-alike characters (O, 0, I, l, 1, |)" checkbox: when on, those characters are filtered from each set before generation (extend `GeneratorOptions` with `excludeLookalikes: boolean`, default false, and filter inside `generatePassword`; a class whose filtered set is empty is treated as unselected).

- [ ] **Step 5: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: untick everything: message and disabled buttons; length 8 with all classes: every class present; reopen the generator: settings persisted.

`AGENTS.md` Child DOX Index add: `- \`frontend/src/lib/generatePassword.ts\`: uniform rejection sampling, one guaranteed character per selected class, length 8 to 128, optional look-alike exclusion, settings persisted under \`kyvault.generator\`. \`generatePassword.test.ts\` pins class coverage and the error cases.`

```bash
git add frontend/src/lib/generatePassword.ts frontend/src/lib/generatePassword.test.ts frontend/src/components/PasswordGenerator.tsx frontend/src/pages/VaultPage.tsx AGENTS.md
git commit -m "password generator guarantees every selected class and remembers settings"
```

---

### Task 6 (A6): Admin polish: pin-key confirm, audit paging, lazy verify, role change, copy buttons

**Files:**
- Modify: `internal/api/admin_handlers.go` (`handleAuditList` gains `before`), `internal/audit/audit.go` (`ListBefore(before, limit)`), tests in `internal/api/api_test.go` and `internal/audit/audit_test.go`
- Modify: `frontend/src/pages/AdminPanel.tsx`, `frontend/src/components/AdminBackup.tsx`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `GET /api/audit?limit=N&before=<index>` returns the N entries with `index < before`, newest first; without `before` the newest N. `Store.ListBefore(before int64, limit int) ([]Entry, error)`; `List(limit)` stays as `ListBefore(math.MaxInt64, limit)`.
- `PUT /api/admin/users/{id}/role` used by a role select in the users table (409 from the last-admin guard shown inline; the caller's own row is disabled).

- [ ] **Step 1: Write the failing Go tests**

`internal/audit/audit_test.go` (use the file's existing store constructor):

```go
func TestListBeforePagesWithoutOverlap(t *testing.T) {
	dir, keyDir := t.TempDir(), t.TempDir()
	store := loggedStore(t, dir, keyDir, 7)
	first, err := store.ListBefore(math.MaxInt64, 3)
	if err != nil || len(first) != 3 {
		t.Fatalf("first page: %v %d", err, len(first))
	}
	second, err := store.ListBefore(first[len(first)-1].Index, 3)
	if err != nil || len(second) != 3 {
		t.Fatalf("second page: %v %d", err, len(second))
	}
	if second[0].Index >= first[len(first)-1].Index {
		t.Fatalf("pages overlap: %d >= %d", second[0].Index, first[len(first)-1].Index)
	}
	third, _ := store.ListBefore(second[len(second)-1].Index, 3)
	if len(third) != 1 {
		t.Fatalf("last page = %d entries, want 1", len(third))
	}
	if rest, _ := store.ListBefore(third[0].Index, 3); len(rest) != 0 {
		t.Fatalf("beyond the oldest = %d, want 0", len(rest))
	}
}
```

`loggedStore(t, dir, keyDir, n)` exists in the audit tests (it writes n records); if its signature differs, adapt the call, not the assertions. `internal/api/api_test.go`:

```go
func TestAuditListBefore(t *testing.T) {
	srv := newTestServer(t)
	_, cookie := signedInUser(t, srv, "admin", users.RoleAdmin)
	get := func(q string) []map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/audit?"+q, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v %s", err, rec.Body)
		}
		return out
	}
	all := get("limit=100")
	if len(all) < 2 {
		t.Skip("need at least two audit rows")
	}
	last := int64(all[0]["index"].(float64))
	older := get(fmt.Sprintf("limit=1&before=%d", last))
	if len(older) != 1 || int64(older[0]["index"].(float64)) >= last {
		t.Fatalf("before did not page: %v", older)
	}
	if bad := get("limit=1&before=x"); len(bad) == 0 {
		t.Fatalf("an invalid before must be ignored, not fail")
	}
}
```

- [ ] **Step 2: Run to see them fail** → FAIL (`ListBefore` undefined).

- [ ] **Step 3: Implement**

In `internal/audit/audit.go` add `ListBefore(before int64, limit int)` beside `List`, sharing its read path but skipping entries with `Index >= before`; make `List(limit)` call it with `math.MaxInt64`. In `handleAuditList` parse `before` with `strconv.ParseInt`; on error or absence use `math.MaxInt64`.

- [ ] **Step 4: Frontend**

- Audit tab: state `auditLogs`, `auditDone`; "Load older" button appends `getJSON(`/api/audit?limit=50&before=${last.index}`)`; hides when fewer than 50 came back. Verification (`/api/audit/verify`) runs only when the audit tab becomes active (effect on `route.admin === "audit"`), showing "Checking chain…" meanwhile; the users tab label shows "User Directory" without a count until loaded.
- Users table: a `<select>` with "user"/"admin" per row calling `putJSON(`/api/admin/users/${u.id}/role`, { role })` after `dialogs.confirm({ title: "Change role?", message: `Make ${u.username} an ${role}?`, confirmLabel: "Change" })`; disabled for the current user; a 409 shows its message inline.
- SCIM base URL and the KySignOn redirect URI (`${origin}/api/auth/oidc/callback`) get Copy buttons via `copyText` (no clear).
- `AdminBackup` "Pin public key": `dialogs.confirm({ title: "Pin this recovery key?", message: "Pinning is write-once. Every backup from now on is sealed to this key and only its custodians can open them. Compare the fingerprint with the ceremony page before continuing.", confirmLabel: "Pin", danger: true })`; after success the status refresh shows the key id (already rendered).

- [ ] **Step 5: Verify, DOX, commit**

Run: full gates. Mock: Load older on Audit (the mock returns one row, so the button hides), role select on the second user shows the confirm, pin key shows the confirm.

`AGENTS.md`: Core Capabilities item 7 append "`GET /api/audit` pages with `before=<index>` (newest first)." and the Admin bullet about roles: "Admin → User Directory changes roles through `PUT /api/admin/users/{id}/role`; the caller's row is disabled and the last-admin 409 is shown inline."

```bash
git add internal/audit/audit.go internal/audit/audit_test.go internal/api/admin_handlers.go internal/api/api_test.go frontend/src/pages/AdminPanel.tsx frontend/src/components/AdminBackup.tsx AGENTS.md
git commit -m "admin: audit paging, lazy verify, role changes, copy buttons, pin-key confirm"
```

---

### Task 7 (A7): Login page and small gates

**Files:**
- Modify: `frontend/src/pages/LoginPage.tsx`, `frontend/src/styles/styles.css`, `frontend/src/lib/noNativeDialogs.test.ts`, `frontend/src/App.tsx`

- [ ] **Step 1: Implement**

- Login page: move the `ThemeSwitcher` out of the card to a fixed top-right corner (`.auth-theme { position: fixed; top: 12px; right: 12px; }`) with a visually hidden label "Color theme" (the switcher already has one; keep it) so the card reads logo, title, button.
- Unlock dialog: while `unlocking`, the close button and Escape are ignored (`onClose` no-ops when `unlocking`).
- `noNativeDialogs.test.ts`: change the regex to `/(?<!dialogs\.)\b(confirm|prompt|alert)\(/` so `window.confirm(` is caught; keep the file:line message.
- Logout button gets `aria-label="Log out"` and visible text "Log out" on desktop (hidden under 600px like the others).

- [ ] **Step 2: Verify and commit**

Run: `cd frontend && npm test && npm run build`. Mock: the login page (open `http://localhost:5199/` after `Log out`) shows the switcher in the corner at 1280px and 390px.

```bash
git add frontend/src/pages/LoginPage.tsx frontend/src/styles/styles.css frontend/src/lib/noNativeDialogs.test.ts frontend/src/App.tsx
git commit -m "login page theme switcher placement; unlock dialog holds while unlocking; tighter dialog gate"
```

---

### Task 8 (A8): End-of-track verification and PR (controller)

- [ ] Full gates: `gofmt -l . ; go vet ./... ; go test -race ./...` and `cd frontend && npm test && npm run build`.
- [ ] Browser pass with the mock at 1280px and 390px: first-run create, lock and Admin reload, new entry cancel and apply, folder switch clears the detail, key reveal and auto-hide, paper code type-back, generator with no classes, audit Load older, role select confirm, login page corner switcher, browser Back from an entry, Security then Vault hop.
- [ ] Open the PR with the `pull-request` skill. Title: `Phase 3b flows and polish from the 2026-09-25 audit`. Base: `master`.

---

## Track B: KyForge release trust on a private repository (planned, not authorized to execute)

**Decision recorded 2026-09-25:** Yoshi chose "plan only, do not execute yet". The route below is the keyless one; nothing in Track B runs until Yoshi says go, and the guardrails in the hand-off apply verbatim.

**Why the current flow fails.** `actions/attest-build-provenance` stores attestations in GitHub's attestation store, which private repositories can use only on GitHub Enterprise Cloud. The `Busnes-app` organisation is on the Free plan and `KyForge-Server` is private, so the publish job stops at "Feature not available for the Busnes-app organization". KyVault-server is public, which is why its identical workflow passes.

**Chosen route (pending go).** Sign and attest the tested digest with keyless cosign against the public Sigstore instance (Fulcio certificate bound to the workflow's GitHub OIDC identity, entry recorded in the public Rekor log). Verification stays identity-based, offline of GitHub's store, and needs no secrets or billing. Trade-off Yoshi accepted for planning: the repository name and workflow path become visible in the public transparency log.

**Rejected for now.** Key-based cosign (private but trust rests on a long-lived secret); Enterprise Cloud upgrade (billing decision, not authorized); making the repo public (explicitly forbidden by the hand-off).

### Task 9 (B1): Spike the keyless flow on a throwaway tag (read-only on trust; no `:latest` move)

**Files:** none in the repo; a temporary workflow file on a branch that is deleted afterwards.

- [ ] Create branch `spike/cosign-keyless` in a fresh worktree of `KyForge-Server` from `master`. Add `.github/workflows/spike-cosign.yml` triggered by `workflow_dispatch` with `permissions: { contents: read, packages: write, id-token: write }` that builds nothing: it pulls `ghcr.io/busnes-app/kyforge-server:<the tested commit sha from the failed run>` by digest `sha256:98c68cc36ebf7f4c25b890f9a01eb0fa0884e0fe99391d0e48ead6914ba051fa`, runs `cosign sign --yes "$NAME@$DIGEST"` and `cosign attest --yes --predicate provenance.json --type slsaprovenance "$NAME@$DIGEST"` where `provenance.json` is generated by `slsa-framework/slsa-github-generator`'s container generator or a minimal in-toto SLSA v1 predicate naming the workflow, run id and commit, then `cosign verify-attestation --type slsaprovenance --certificate-identity "https://github.com/Busnes-app/KyForge-Server/.github/workflows/spike-cosign.yml@refs/heads/spike/cosign-keyless" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$NAME@$DIGEST"`.
- [ ] Run it once by hand (`gh workflow run`), record the Rekor log index and the verify output in the spike PR description. Delete the workflow file and branch after the record is captured. This step only proves the public Sigstore path works for this private repo; it moves no tag.

### Task 10 (B2): Replace the attestation step in `publish`

**Files:** `KyForge-Server/.github/workflows/ci.yml` (`publish` job)

- [ ] Replace `actions/attest-build-provenance` and the `gh attestation verify` step with:

```yaml
      - uses: sigstore/cosign-installer@<pinned sha> # v3.x
      - id: provenance
        run: |
          set -euo pipefail
          cat > provenance.json <<EOF
          {"buildDefinition":{"buildType":"https://github.com/Busnes-app/KyForge-Server/ci","externalParameters":{"workflow":{"ref":"${GITHUB_REF}","repository":"https://github.com/${GITHUB_REPOSITORY}","path":".github/workflows/ci.yml"}},"resolvedDependencies":[{"uri":"git+https://github.com/${GITHUB_REPOSITORY}@${GITHUB_REF}","digest":{"gitCommit":"${GITHUB_SHA}"}}]},"runDetails":{"builder":{"id":"https://github.com/${GITHUB_REPOSITORY}/.github/workflows/ci.yml@${GITHUB_REF}"},"metadata":{"invocationId":"https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"}}}
          EOF
      - env:
          NAME: ${{ steps.push.outputs.name }}
          DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          set -euo pipefail
          cosign sign --yes "$NAME@$DIGEST"
          cosign attest --yes --type slsaprovenance1 --predicate provenance.json "$NAME@$DIGEST"
          cosign verify --certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/ci.yml@refs/heads/master" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com "$NAME@$DIGEST"
          cosign verify-attestation --type slsaprovenance1 \
            --certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/ci.yml@refs/heads/master" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com "$NAME@$DIGEST" > /dev/null
```

- [ ] Remove `attestations: write` from the job permissions (keep `id-token: write`, `packages: write`). Keep the artifact download, `docker load`, tag, push and digest steps unchanged.
- [ ] Tests: the workflow's own verify steps are the test; add a `workflow_dispatch`-free check in the `go` job's "coordinates" step that every doc mentioning `gh attestation verify` for KyForge now mentions `cosign verify` instead (grep in CI, as the existing coordinate checks do).

### Task 11 (B3): `promote` verifies with cosign before and after moving `:latest`

**Files:** `KyForge-Server/.github/workflows/ci.yml` (`promote` job)

- [ ] Replace the `gh attestation verify "oci://$NAME:latest"` step with `cosign verify-attestation --type slsaprovenance1 --certificate-identity … --certificate-oidc-issuer … "$NAME:latest"` and add the same `cosign-installer` step. Keep the tip-of-master check, `--prefer-index=false`, and the digest equality assertion exactly as they are. Add a negative check: `! cosign verify --certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/other.yml@refs/heads/master" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$NAME@$DIGEST"` must fail (proves identity binding is enforced, per Review Focus 5).

### Task 12 (B4): Operator docs and DOX

**Files:** `KyForge-Server/README.md`, `KyForge-Server/docs/RESTORE.md`, `KyForge-Server/AGENTS.md`

- [ ] `docs/RESTORE.md` lines 86 to 98: replace the two `gh attestation verify` commands with the `cosign verify` and `cosign verify-attestation` pair (same identity and issuer flags as CI), and say that the signature and provenance live in the registry beside the image and in the public Rekor log, not in GitHub's attestation store. Keep the "images built before 2026-09-16" warning.
- [ ] `README.md` line 319 area: the re-pin procedure names cosign.
- [ ] `AGENTS.md` line 96: "attests it and verifies the attestation" becomes "signs it and attaches SLSA provenance with keyless cosign, then verifies both by workflow identity". Add one sentence on the trade-off: the repo name and workflow path are visible in the public Sigstore transparency log; this is accepted because the repository's existence is not a secret.
- [ ] Add the hand-off's guardrails as a short "Release trust" subsection in `AGENTS.md`: no `continue-on-error`, no manual `:latest`, no rebuild between test and publish.

### Task 13 (B5): Verification after merge (controller, only after Yoshi authorises the merge)

- [ ] Watch the first `master` run: `publish` signs, attests and verifies; `promote` moves `:latest` only at the tip and both verifies pass; the negative identity check fails as expected. Record run ids in the hand-off file and on myslop. Then run the `docs/RESTORE.md` verify commands from a workstation against `:latest`.
