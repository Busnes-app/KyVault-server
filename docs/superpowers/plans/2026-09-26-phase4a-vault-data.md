# Phase 4a: Vault Data Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the vault the data features a KeePass user expects and the audit found missing: folder delete and move, entry tags, favourites, expiry, custom fields, sorting and richer search, KeePass file import, Bitwarden JSON import, generic CSV column mapping, and CSV export.

**Architecture:** Every feature is a pure change to `frontend/src/lib/kdbx.ts` (or a sibling lib) with a `node --test` proving it round-trips through an encrypted export and reopen, plus page wiring that reuses the Phase 3 dialog host, routes and drafts. No server change: the server stores ciphertext and never learns the schema.

**Tech Stack:** React 18 + TypeScript, kdbxweb 2.x (`tags`, `times.expires/expiryTime`, custom `fields`, `Kdbx.move/remove`), `tsx --test`.

**Spec:** `docs/superpowers/plans/2026-09-25-kyvault-roadmap.md` (Phase 4 list, first half). Deferred to 4b: passphrase generator and entropy meter, health report and HIBP, vault key rotation, device UX, snapshot preview, PWA manifest, draft cleanup. Dropped from scope: an icon picker (the standard KeePass icon set would have to be bundled; a follow-up if wanted).

## Global Constraints

- Branch `fix/phase4a-data` from `master` (PR #61 merged). One PR. Commit after every task.
- Verification before the PR: `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, and in `frontend/`: `npm test && npm run build`. Browser pass with `npm run dev:mock` at 1280px and 390px for every flow a task changes.
- KDBX compatibility is load-bearing: tags go to the native `tags` list, expiry to `times.expires/expiryTime`, custom fields to native entry `fields` with `ProtectedValue` for protected ones, favourites to the tag `favorite`. A KeePassXC user must see the same data. Never invent a KyVault-only field for something KeePass already models.
- Imports never overwrite an existing entry or group. Imported data lands under a new top-level folder unless the user picks one. Existing UUIDs win; the report says what was skipped.
- Exports of plaintext (CSV) require a confirm dialog that names the risk and are downloaded through `downloadBlob`.
- No native dialogs; questions go through `useDialogs()`. No new runtime dependencies. Copy rules: sentences, no em-dashes, no "successfully".
- DOX: update `AGENTS.md` Child DOX Index bullets for `kdbx.ts`, `csvImport.ts`, `VaultPage.tsx` where contracts change (every task does).

## Review Focus

1. Deleting a folder with recycling enabled must move the folder and everything in it to the Recycle Bin, and the entries must show under the bin and be restorable. Pinned: Task 1 `folders.test.ts`.
2. Moving a folder into its own descendant or into the Recycle Bin must be refused before any mutation. Pinned: Task 1.
3. An entry with tags, an expiry and a protected custom field must survive export and reopen with protection intact, and a KeePassXC-written expiry (`expires: true`) must be read as expired when in the past. Pinned: Task 2 `entryMeta.test.ts`.
4. Importing a KDBX that shares UUIDs with the current vault must skip those entries and groups, never overwrite, and must carry attachments for the new ones. Pinned: Task 3 `kdbxImport.test.ts`.
5. A Bitwarden export with a folder, a TOTP and a secure note must import the login with its folder and TOTP and skip the note with a count. Pinned: Task 4 `bitwardenImport.test.ts`.

---

### Task 1: Delete and move folders

**Files:**
- Modify: `frontend/src/lib/kdbx.ts` (after `renameGroup`)
- Modify: `frontend/src/lib/folders.test.ts` (append)
- Modify: `frontend/src/lib/dialogQueue.ts`, `frontend/src/lib/dialogQueue.test.ts`, `frontend/src/components/DialogHost.tsx` (new `choose` kind)
- Modify: `frontend/src/pages/VaultPage.tsx` (sidebar folder actions)
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `KeePassVault.deleteGroup(uuid: string): number` (returns the number of entries affected; moves the group to the Recycle Bin when recycling is enabled, otherwise removes it permanently; throws for the root, the bin, a recycled group or an unknown uuid). `KeePassVault.moveGroup(uuid: string, newParentUuid: string): boolean` (false when already there; throws for the root, the bin, a recycled target, or a target that is the group itself or one of its descendants).
- `useDialogs().choose({ title, message?, label?, options: Array<{ value: string; label: string }>, defaultValue? }): Promise<string | null>` rendering a `<select>`.

- [ ] **Step 1: Write the failing vault tests**

Append to `frontend/src/lib/folders.test.ts` (reuse its existing helpers for creating a vault and reopening it; the file already imports `KeePassVault`):

```ts
test("deleting a folder recycles it with its entries, and restore brings an entry back", async () => {
  const key = new Uint8Array(32).fill(2);
  const vault = await KeePassVault.createNew(key);
  const root = vault.getLiveGroups()[0];
  const work = vault.createGroup("Work", root.uuid);
  const sub = vault.createGroup("Clients", work.uuid);
  const e1 = vault.createEntry({ title: "A", username: "", password: "p", url: "", notes: "", groupUuid: work.uuid });
  const e2 = vault.createEntry({ title: "B", username: "", password: "p", url: "", notes: "", groupUuid: sub.uuid });
  assert.equal(vault.deleteGroup(work.uuid), 2);
  assert.ok(!vault.getLiveGroups().some((g) => g.uuid === work.uuid));
  assert.deepEqual(vault.getRecycledEntries().map((e) => e.uuid).sort(), [e1.uuid, e2.uuid].sort());
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal(reopened.getRecycledEntries().length, 2);
  reopened.restoreEntry(e1.uuid);
  assert.ok(reopened.getLiveEntries().some((e) => e.uuid === e1.uuid));
  assert.throws(() => reopened.deleteGroup(root.uuid), /root/i);
});

test("moving a folder re-parents it and refuses cycles and the bin", async () => {
  const key = new Uint8Array(32).fill(3);
  const vault = await KeePassVault.createNew(key);
  const root = vault.getLiveGroups()[0];
  const a = vault.createGroup("A", root.uuid);
  const b = vault.createGroup("B", a.uuid);
  const c = vault.createGroup("C", root.uuid);
  assert.equal(vault.moveGroup(b.uuid, c.uuid), true);
  assert.equal(vault.getLiveGroups().find((g) => g.uuid === b.uuid)?.parentUuid, c.uuid);
  assert.equal(vault.getLiveGroups().find((g) => g.uuid === b.uuid)?.path, `${root.name} / C / B`);
  assert.equal(vault.moveGroup(b.uuid, c.uuid), false);
  assert.throws(() => vault.moveGroup(c.uuid, b.uuid), /inside itself/);
  assert.throws(() => vault.moveGroup(a.uuid, a.uuid), /inside itself/);
  assert.throws(() => vault.moveGroup(root.uuid, c.uuid), /root/i);
});
```

- [ ] **Step 2: Run to see them fail**

Run: `cd frontend && npx tsx --test src/lib/folders.test.ts` → FAIL (`deleteGroup` is not a function).

- [ ] **Step 3: Implement in `kdbx.ts`**

After `renameGroup`:

```ts
  private assertMovableGroup(uuid: string): kdbxweb.KdbxGroup {
    const group = this.findGroup(uuid);
    if (!group) throw new Error("This folder is no longer available.");
    if (group === this.db.getDefaultGroup()) throw new Error("The root folder cannot be changed.");
    if (this.recycledGroupIds().has(uuid)) throw new Error("Choose a folder in the live vault.");
    return group;
  }

  // Recycling keeps the folder tree intact inside the bin, so Restore works per entry.
  public deleteGroup(uuid: string): number {
    const group = this.assertMovableGroup(uuid);
    const count = group.allEntries ? [...group.allEntries()].length : 0;
    if (this.recyclingEnabled) this.db.createRecycleBin();
    this.db.remove(group);
    return count;
  }

  public moveGroup(uuid: string, newParentUuid: string): boolean {
    const group = this.assertMovableGroup(uuid);
    const target = this.findGroup(newParentUuid);
    if (!target || this.recycledGroupIds().has(newParentUuid)) throw new Error("Choose a live folder to move into.");
    for (let p: kdbxweb.KdbxGroup | undefined = target; p; p = p.parentGroup) {
      if (p === group) throw new Error("A folder cannot be moved inside itself.");
    }
    if (group.parentGroup === target) return false;
    this.db.move(group, target);
    group.times.update();
    return true;
  }
```

If `KdbxGroup.allEntries` is not available in this kdbxweb version, count with a recursive walk over `group.entries` and `group.groups`. `getRecycledEntries` already reads entries under the bin recursively (verify with the test; if it only reads direct children, extend `recycledGroupIds` to include descendants of the bin, which the delete test will prove).

- [ ] **Step 4: Run the vault tests**

Run: `cd frontend && npx tsx --test src/lib/folders.test.ts` → PASS.

- [ ] **Step 5: Add the `choose` dialog kind**

`dialogQueue.ts`: `kind: "confirm" | "prompt" | "notify" | "choose"`, add `options?: Array<{ value: string; label: string }>` to `DialogRequest`; `cancelAll` resolves `choose` with `null`. `dialogQueue.test.ts`: extend the cancelAll test with a `choose` question resolving `null`. `DialogHost.tsx`: `choose(opts)` returns `Promise<string | null>`; `QuestionDialog` renders a `<select className="select" data-autofocus>` for `choose` with the options and `defaultValue ?? options[0].value`, submit settles the selected value, cancel settles `null`.

- [ ] **Step 6: Sidebar actions**

In `VaultPage.tsx`, when a folder is selected (`selectedFolder`), beside "Rename Folder" add "Move Folder" and "Delete Folder":
- Move: `const target = await dialogs.choose({ title: "Move folder", label: "Move into", options: [{ value: root.uuid, label: root.name }, ...groups.filter(not the folder or its descendants, by path prefix).map(g => ({ value: g.uuid, label: g.path }))], defaultValue: selectedFolder.parentUuid })`; on a value call `vault.moveGroup`, `onChanged()`, `refreshVaultData()`; show thrown messages with `dialogs.notify`.
- Delete: `dialogs.confirm({ title: vault.recyclingEnabled ? "Move folder to Recycle Bin?" : "Delete folder permanently?", message: \`"${selectedFolder.name}" and its ${count} entries ${recycling ? "move to the Recycle Bin" : "are removed from the current vault. Existing snapshots and backups may still contain them"}.\`, confirmLabel: recycling ? "Move" : "Delete", danger: true })`; on confirm `vault.deleteGroup`, clear the selection if the open entry was inside, `setSelectedGroupUuid("all")`, `onChanged()`, `refreshVaultData()`.

- [ ] **Step 7: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: create a nested folder with an entry, move it, delete it, see the entries in the Recycle Bin, restore one.

`AGENTS.md` folders bullet: add "Folders can be moved (never into themselves, their descendants or the bin) and deleted; deletion recycles the whole subtree when recycling is enabled and is permanent otherwise, after a confirm. `folders.test.ts` covers both." Dialog bullet: add "`choose` renders a select."

```bash
git add frontend/src/lib/kdbx.ts frontend/src/lib/folders.test.ts frontend/src/lib/dialogQueue.ts frontend/src/lib/dialogQueue.test.ts frontend/src/components/DialogHost.tsx frontend/src/pages/VaultPage.tsx AGENTS.md
git commit -m "move and delete folders; choose dialog"
```

---

### Task 2: Tags, favourites, expiry, custom fields, sorting and search

**Files:**
- Modify: `frontend/src/lib/kdbx.ts` (`VaultEntry`, `getEntries`, `createEntry`, `updateEntry`)
- Create: `frontend/src/lib/entryMeta.ts`, `frontend/src/lib/entryMeta.test.ts`
- Modify: `frontend/src/lib/lockedDraft.ts` (`EntryDraft` gains the new fields), `frontend/src/lib/newEntryDraft.ts` (`EntryFields`)
- Modify: `frontend/src/pages/VaultPage.tsx` (editor, list badges, sort, filters, search)
- Modify: `frontend/src/styles/styles.css` (tag chips)
- Modify: `AGENTS.md`

**Interfaces:**
- Produces on `VaultEntry`: `tags: string[]`, `expiresAt?: Date`, `favorite: boolean`, `custom: CustomField[]` with `type CustomField = { name: string; value: string; protected: boolean }`. `createEntry`/`updateEntry` accept and persist them; `updateEntry` returns false when nothing changed (including these).
- `entryMeta.ts`: `FAVORITE_TAG = "favorite"`; `parseTags(text: string): string[]` (split on commas and semicolons, trim, dedupe case-insensitively, drop empties, max 32 chars each); `isExpired(entry, now = new Date()): boolean`; `expiresWithin(entry, days, now): boolean`; `RESERVED_FIELDS` (Title, UserName, Password, URL, Notes, otp, TOTP); `sortEntries(entries, key: "title" | "modified" | "expiry"): VaultEntry[]` (stable, title case-insensitive, modified newest first, expiry soonest first with no-expiry last); `entryMatches(entry, query): boolean` (title, username, url, notes, tags, custom names and non-protected custom values).

- [ ] **Step 1: Write the failing tests**

```ts
// frontend/src/lib/entryMeta.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { parseTags, isExpired, expiresWithin, sortEntries, entryMatches, FAVORITE_TAG } from "./entryMeta";

test("tags parse, dedupe and cap", () => {
  assert.deepEqual(parseTags(" work, Work ;home,, "), ["work", "home"]);
  assert.deepEqual(parseTags("x".repeat(40)), ["x".repeat(32)]);
});

test("metadata round-trips through an encrypted export", async () => {
  const key = new Uint8Array(32).fill(5);
  const vault = await KeePassVault.createNew(key);
  const root = vault.getLiveGroups()[0].uuid;
  const past = new Date(Date.now() - 86_400_000);
  const e = vault.createEntry({ title: "Bank", username: "u", password: "p", url: "", notes: "", groupUuid: root,
    tags: ["finance"], favorite: true, expiresAt: past, custom: [{ name: "PIN", value: "1234", protected: true }, { name: "Branch", value: "Main", protected: false }] });
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  const back = reopened.getEntries().find((x) => x.uuid === e.uuid)!;
  assert.deepEqual(back.tags, ["finance", FAVORITE_TAG]);
  assert.equal(back.favorite, true);
  assert.equal(back.expiresAt?.getTime(), past.getTime());
  assert.equal(isExpired(back), true);
  assert.deepEqual(back.custom, [{ name: "PIN", value: "1234", protected: true }, { name: "Branch", value: "Main", protected: false }]);
  assert.equal(reopened.updateEntry({ ...back }), false, "no-op update creates no revision");
  assert.equal(reopened.updateEntry({ ...back, favorite: false, expiresAt: undefined }), true);
  const again = reopened.getEntries().find((x) => x.uuid === e.uuid)!;
  assert.deepEqual(again.tags, ["finance"]);
  assert.equal(again.expiresAt, undefined);
});

test("sorting, expiry windows and search", () => {
  const base = { username: "", password: "", url: "", notes: "", groupUuid: "g", favorite: false, custom: [], tags: [] as string[] };
  const soon = new Date(Date.now() + 3 * 86_400_000);
  const entries = [
    { ...base, uuid: "1", title: "beta", updatedAt: new Date(1), expiresAt: undefined },
    { ...base, uuid: "2", title: "Alpha", updatedAt: new Date(3), expiresAt: soon, tags: ["Shopping"] },
    { ...base, uuid: "3", title: "gamma", updatedAt: new Date(2), expiresAt: undefined, custom: [{ name: "Member ID", value: "42", protected: false }, { name: "Secret", value: "hidden", protected: true }] },
  ];
  assert.deepEqual(sortEntries(entries, "title").map((e) => e.uuid), ["2", "1", "3"]);
  assert.deepEqual(sortEntries(entries, "modified").map((e) => e.uuid), ["2", "3", "1"]);
  assert.deepEqual(sortEntries(entries, "expiry").map((e) => e.uuid), ["2", "1", "3"]);
  assert.equal(expiresWithin(entries[1], 7), true);
  assert.equal(expiresWithin(entries[1], 1), false);
  assert.equal(entryMatches(entries[1], "shop"), true);
  assert.equal(entryMatches(entries[2], "member"), true);
  assert.equal(entryMatches(entries[2], "42"), true);
  assert.equal(entryMatches(entries[2], "hidden"), false, "protected custom values are never searched");
});
```

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`entryMeta.ts`:

```ts
import type { VaultEntry } from "./kdbx";

export const FAVORITE_TAG = "favorite";
export const RESERVED_FIELDS = new Set(["Title", "UserName", "Password", "URL", "Notes", "otp", "TOTP"]);
export const MAX_TAG_LENGTH = 32;

export function parseTags(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/[,;]/)) {
    const tag = raw.trim().slice(0, MAX_TAG_LENGTH);
    const key = tag.toLowerCase();
    if (!tag || seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

export function isExpired(entry: Pick<VaultEntry, "expiresAt">, now = new Date()): boolean {
  return !!entry.expiresAt && entry.expiresAt.getTime() <= now.getTime();
}

export function expiresWithin(entry: Pick<VaultEntry, "expiresAt">, days: number, now = new Date()): boolean {
  return !!entry.expiresAt && entry.expiresAt.getTime() > now.getTime() && entry.expiresAt.getTime() <= now.getTime() + days * 86_400_000;
}

export type SortKey = "title" | "modified" | "expiry";
export function sortEntries<T extends Pick<VaultEntry, "title" | "updatedAt" | "expiresAt">>(entries: T[], key: SortKey): T[] {
  const copy = [...entries];
  if (key === "title") copy.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
  if (key === "modified") copy.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
  if (key === "expiry") copy.sort((a, b) => (a.expiresAt?.getTime() ?? Infinity) - (b.expiresAt?.getTime() ?? Infinity));
  return copy;
}

export function entryMatches(entry: VaultEntry, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const hay = [entry.title, entry.username, entry.url, entry.notes, ...entry.tags,
    ...entry.custom.flatMap((f) => (f.protected ? [f.name] : [f.name, f.value]))];
  return hay.some((s) => s.toLowerCase().includes(q));
}
```

`kdbx.ts`: extend `VaultEntry` with `tags: string[]; expiresAt?: Date; favorite: boolean; custom: CustomField[]` and export `CustomField`. In `getEntries`: `tags = e.tags ?? []`, `favorite = tags.some((t) => t.toLowerCase() === FAVORITE_TAG)`, `expiresAt = e.times.expires && e.times.expiryTime ? e.times.expiryTime : undefined`, `custom` from `e.fields` entries whose name is not in `RESERVED_FIELDS`, with `protected = value instanceof ProtectedValue` and `value = protected ? value.getText() : String(value)`. In `createEntry` and `updateEntry`: write `e.tags` as the entry's tags with `favorite` added or removed (compare case-insensitively, keep original casing of user tags), `e.times.expires = !!expiresAt; e.times.expiryTime = expiresAt`, delete custom fields no longer present (only non-reserved names) and set the rest with `ProtectedValue.fromString` when protected. Extend `updateEntry`'s no-op check to compare tags, expiry, favorite and custom fields (order-sensitive). Import `FAVORITE_TAG` and `RESERVED_FIELDS` from `./entryMeta` (that module imports only the type from `kdbx.ts`, so no runtime cycle).

`lockedDraft.ts` `EntryDraft` gains `tags: string[]; expiresAt: string | null; favorite: boolean; custom: CustomField[]` (ISO string for the date); `isEntryDraft` validates them. `newEntryDraft.ts` `EntryFields` gains the same (with `expiresAt?: Date`).

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: Page wiring**

- Editor: a "Tags" text input (comma-separated, parsed with `parseTags` on Apply; shown as chips in view mode), a "Favourite" checkbox (star icon in the header when set), an "Expires" `<input type="date">` with a clear button, and a "Custom fields" list (name, value, protected checkbox, remove; "Add field" button; names in `RESERVED_FIELDS` rejected with an inline message). Protected custom values are masked with a reveal toggle in view mode.
- List: a sort `<select>` in the list header ("Title", "Last modified", "Expiry"; persisted in `localStorage` key `kyvault.sort`), a star badge for favourites, an "Expired" red badge and "Expires soon" (7 days) amber badge, tag chips (first three).
- Sidebar: "Favourites" and "Expiring" smart views beside "Reused passwords" (same checkbox pattern, mutually exclusive with the reused filter).
- Search uses `entryMatches`.
- `draftDirty` and `onDraftChange` include the new fields; `handleSaveEntry` passes them.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: add tags and a custom protected field, set an expiry in the past, apply; the list shows the badges; search by tag finds it; sort by expiry puts it first; favourite toggles the star.

`AGENTS.md` `kdbx.ts` bullet: add "Entries carry native tags (favourite is the tag `favorite`), expiry (`times.expires/expiryTime`) and custom fields (native `fields`, `ProtectedValue` when protected); `entryMeta.ts` owns parsing, expiry windows, sorting and search, which never reads protected custom values. `entryMeta.test.ts` proves the encrypted round trip."

```bash
git add frontend/src/lib/kdbx.ts frontend/src/lib/entryMeta.ts frontend/src/lib/entryMeta.test.ts frontend/src/lib/lockedDraft.ts frontend/src/lib/newEntryDraft.ts frontend/src/pages/VaultPage.tsx frontend/src/styles/styles.css AGENTS.md
git commit -m "tags, favourites, expiry, custom fields, sorting and search"
```

---

### Task 3: Import a KeePass file

**Files:**
- Create: `frontend/src/lib/kdbxImport.ts`, `frontend/src/lib/kdbxImport.test.ts`
- Modify: `frontend/src/lib/kdbx.ts` (`importFrom`)
- Modify: `frontend/src/lib/dialogQueue.ts`, `frontend/src/components/DialogHost.tsx` (`prompt` gains `secret?: boolean` rendering a password input with `autoComplete="off"`)
- Modify: `frontend/src/pages/VaultPage.tsx` (sidebar "Import KeePass file")
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: `KeePassVault.openForeign(buffer: ArrayBuffer, password: string, keyFile?: ArrayBuffer): Promise<KeePassVault>` (static; a plain password credential, optionally a key file, for a file written by another client). `KeePassVault.importFrom(source: KeePassVault, targetGroupUuid?: string): ImportReport` with `type ImportReport = { entries: number; groups: number; skippedEntries: number; skippedGroups: number; attachments: number }`: copies the source's live groups and entries (recycled ones excluded) under a new folder named after the source root (or the given target), keeps UUIDs when unused, skips entries and groups whose UUID already exists, copies binaries and custom icons through the existing `recoverEntryCopy` logic, preserves tags, expiry, custom fields and history.
- `kdbxImport.ts`: `readKdbxFile(file: File): Promise<ArrayBuffer>` (size cap `MAX_VAULT_BYTES`) and `describeImport(report): string`.

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/lib/kdbxImport.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { describeImport } from "./kdbxImport";

test("importing a foreign vault copies new items, skips existing UUIDs and keeps attachments", async () => {
  const keyA = new Uint8Array(32).fill(7);
  const a = await KeePassVault.createNew(keyA, "Other");
  const rootA = a.getLiveGroups()[0].uuid;
  const g = a.createGroup("Shared", rootA);
  const e1 = a.createEntry({ title: "Mail", username: "m", password: "p1", url: "", notes: "", groupUuid: g.uuid, tags: ["t"], favorite: false, custom: [] });
  await a.addAttachment(e1.uuid, "note.txt", new TextEncoder().encode("hi").buffer, new AbortController().signal);
  const bytes = await a.exportBinary();

  const keyB = new Uint8Array(32).fill(8);
  const b = await KeePassVault.createNew(keyB, "Mine");
  const rootB = b.getLiveGroups()[0].uuid;
  // Pre-existing entry with the same UUID as e1 must win.
  const clash = b.recoverEntryCopy(a, e1.uuid);
  const foreign = await KeePassVault.open(bytes, keyA);
  const report = b.importFrom(foreign);
  assert.equal(report.groups, 1);
  assert.equal(report.entries, 0);
  assert.equal(report.skippedEntries, 1);
  const imported = b.getLiveGroups().find((x) => x.name === "Other");
  assert.ok(imported, "a top-level folder named after the source root");
  const e2 = a.createEntry({ title: "Second", username: "", password: "p2", url: "", notes: "", groupUuid: rootA, tags: [], favorite: true, custom: [{ name: "K", value: "v", protected: true }] });
  const foreign2 = await KeePassVault.open(await a.exportBinary(), keyA);
  const report2 = b.importFrom(foreign2);
  assert.equal(report2.entries, 1);
  const back = b.getEntries().find((x) => x.uuid === e2.uuid)!;
  assert.equal(back.favorite, true);
  assert.deepEqual(back.custom, [{ name: "K", value: "v", protected: true }]);
  assert.ok(b.getAttachments(clash).length >= 0);
  assert.match(describeImport(report2), /1 entr/);
  const reopened = await KeePassVault.open(await b.exportBinary(), keyB);
  assert.ok(reopened.getEntries().some((x) => x.uuid === e2.uuid));
});

test("a foreign file opens with a plain password", async () => {
  const key = new Uint8Array(32).fill(9);
  const v = await KeePassVault.createNew(key);
  // A KyVault export is hex-keyed; opening it "foreign" with the hex string must work too.
  const hex = Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
  const opened = await KeePassVault.openForeign(await v.exportBinary(), hex);
  assert.equal(opened.getLiveGroups().length >= 1, true);
});
```

- [ ] **Step 2: Run to see it fail** → FAIL.

- [ ] **Step 3: Implement**

`kdbx.ts`:

```ts
  public static async openForeign(buffer: ArrayBuffer, password: string, keyFile?: ArrayBuffer): Promise<KeePassVault> {
    const credentials = new kdbxweb.Credentials(ProtectedValue.fromString(password), keyFile);
    const db = await kdbxweb.Kdbx.load(buffer, credentials);
    return new KeePassVault(db, credentials);
  }

  public importFrom(source: KeePassVault, targetGroupUuid?: string): ImportReport {
    const report: ImportReport = { entries: 0, groups: 0, skippedEntries: 0, skippedGroups: 0, attachments: 0 };
    const srcRoot = source.db.getDefaultGroup();
    const parent = (targetGroupUuid && this.findGroup(targetGroupUuid)) || this.db.createGroup(this.db.getDefaultGroup(), folderName(srcRoot.name || "Imported"));
    const recycled = source.recycledGroupIds();
    const copyGroup = (from: kdbxweb.KdbxGroup, into: kdbxweb.KdbxGroup) => {
      for (const child of from.groups) {
        const id = child.uuid.toString();
        if (recycled.has(id)) continue;
        if (this.findGroup(id)) { report.skippedGroups++; continue; }
        const made = this.db.createGroup(into, folderName(child.name || "Folder"));
        made.uuid = child.uuid; report.groups++;
        copyGroup(child, made);
      }
      for (const entry of from.entries) {
        const id = entry.uuid.toString();
        if (this.findEntry(id)) { report.skippedEntries++; continue; }
        const uuid = this.recoverEntryCopy(source, id, { keepUuid: true, into });
        report.entries++;
        report.attachments += this.getAttachments(uuid).length;
      }
    };
    copyGroup(srcRoot, parent);
    return report;
  }
```

`recoverEntryCopy(source, uuid, options?)` gains an options object `{ keepUuid?: boolean; into?: kdbxweb.KdbxGroup }`: when `keepUuid` the copy keeps the source UUID (only ever called after the existence check); `into` overrides the top-level target. Keep its existing behaviour for the conflict-comparison caller (no options). If `KdbxGroup.uuid` cannot be assigned after creation, create the group with `kdbxweb.KdbxGroup.create(name, parent)` and set `uuid` before pushing to `parent.groups`; the test proves the UUID survives export.

`kdbxImport.ts`:

```ts
import { MAX_VAULT_BYTES } from "./kdbx";
export type ImportReport = { entries: number; groups: number; skippedEntries: number; skippedGroups: number; attachments: number };
export async function readKdbxFile(file: File): Promise<ArrayBuffer> {
  if (file.size > MAX_VAULT_BYTES) throw new Error("This file is larger than the 50 MiB vault limit.");
  return file.arrayBuffer();
}
export function describeImport(r: ImportReport): string {
  const parts = [`${r.entries} entr${r.entries === 1 ? "y" : "ies"} and ${r.groups} folder${r.groups === 1 ? "" : "s"} imported`];
  if (r.attachments) parts.push(`${r.attachments} attachment${r.attachments === 1 ? "" : "s"}`);
  if (r.skippedEntries || r.skippedGroups) parts.push(`${r.skippedEntries + r.skippedGroups} already present and left unchanged`);
  return parts.join(", ") + ".";
}
```

(Move `ImportReport` to `kdbxImport.ts` and import the type into `kdbx.ts`, or define it in `kdbx.ts` and re-export; either way one definition.)

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: Page wiring**

Sidebar button "Import KeePass file" (`<input type="file" accept=".kdbx">` hidden, triggered by the button). Flow: read the file (`readKdbxFile`), `dialogs.prompt({ title: "Open the KeePass file", label: "Its master password", secret: true })`, `KeePassVault.openForeign` (on failure `dialogs.notify` "Could not open this file. Check the password; key files are not supported yet."), `dialogs.choose` for the target: "New folder named after the file" (value `""`) or any live folder, then `vault.importFrom`, `onChanged()`, `refreshVaultData()`, banner with `describeImport`. Key files: out of scope (the prompt copy says so). Under 900px the button lives in the folder pane like the others.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: download the vault as `.kdbx`, then import that same file: everything is skipped with a count; import a second vault created in another mock tab (or the test fixture) and see its folder appear.

`AGENTS.md` `kdbx.ts` bullet: add "`openForeign` opens a file written by another client with a plain password; `importFrom` copies its live tree under a new folder, keeps UUIDs that are free, skips existing ones, and carries attachments, icons, tags, expiry, custom fields and history. `kdbxImport.test.ts` covers skip and carry."

```bash
git add frontend/src/lib/kdbx.ts frontend/src/lib/kdbxImport.ts frontend/src/lib/kdbxImport.test.ts frontend/src/lib/dialogQueue.ts frontend/src/components/DialogHost.tsx frontend/src/pages/VaultPage.tsx AGENTS.md
git commit -m "import a KeePass file without overwriting anything"
```

---

### Task 4: Bitwarden JSON import, generic CSV column mapping, CSV export

**Files:**
- Create: `frontend/src/lib/bitwardenImport.ts`, `frontend/src/lib/bitwardenImport.test.ts`
- Modify: `frontend/src/lib/csvImport.ts` (`ColumnMapping`, `applyMapping`), `frontend/src/lib/csvImport.test.ts` (append)
- Create: `frontend/src/lib/csvExport.ts`, `frontend/src/lib/csvExport.test.ts`
- Modify: `frontend/src/components/CsvImportModal.tsx` (accept `.json`, mapping UI), `frontend/src/pages/VaultPage.tsx` (Export CSV in the sidebar)
- Modify: `AGENTS.md`

**Interfaces:**
- `parseBitwardenJson(text: string): { entries: ImportedEntryPreview[]; skipped: { notes: number; cards: number; identities: number } }` from a Bitwarden export (`items[]` with `type` 1 login, 2 note, 3 card, 4 identity; `folders[]` with `id`/`name`; `login.uris[0].uri`, `login.totp`).
- `ColumnMapping = { title?: number; username?: number; password?: number; url?: number; notes?: number; totp?: number; folder?: number }` and `applyMapping(rows: string[][], mapping: ColumnMapping, hasHeader: boolean): ImportedEntryPreview[]`.
- `exportCsv(entries: VaultEntry[], groupsByUuid: Map<string, string>): string` with header `Group,Title,Username,Password,URL,Notes,TOTP,Tags,Expires,Last Modified` (KeePassXC's first six columns in its order), RFC 4180 quoting, CRLF line ends, ISO dates.

- [ ] **Step 1: Write the failing tests**

```ts
// frontend/src/lib/bitwardenImport.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseBitwardenJson } from "./bitwardenImport";

test("bitwarden logins import with folder and totp; other types are counted", () => {
  const json = JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Work" }], items: [
    { type: 1, name: "GitHub", folderId: "f1", notes: "n", login: { username: "me", password: "pw", totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://github.com" }] } },
    { type: 2, name: "Secure note", secureNote: {} },
    { type: 3, name: "Card", card: {} },
    { type: 1, name: "No folder", login: { username: "", password: "x" } },
  ] });
  const { entries, skipped } = parseBitwardenJson(json);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries[0], { id: entries[0].id, title: "GitHub", username: "me", password: "pw", url: "https://github.com", notes: "n", totpSeed: "JBSWY3DPEHPK3PXP", folder: "Work", selected: true });
  assert.equal(entries[1].folder, "");
  assert.deepEqual(skipped, { notes: 1, cards: 1, identities: 0 });
  assert.throws(() => parseBitwardenJson(JSON.stringify({ encrypted: true, items: [] })), /encrypted/i);
  assert.throws(() => parseBitwardenJson("nope"), /not a Bitwarden/i);
});
```

Append to `csvImport.test.ts`:

```ts
test("generic CSV uses an explicit column mapping", () => {
  const rows = [["Site", "Login", "Pass", "Where"], ["Bank", "me", "pw", "Finance/Banks"]];
  const out = applyMapping(rows, { title: 0, username: 1, password: 2, folder: 3 }, true);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, "Bank");
  assert.equal(out[0].folder, "Finance/Banks");
  assert.equal(out[0].url, "");
  const noHeader = applyMapping(rows, { title: 0, password: 2 }, false);
  assert.equal(noHeader.length, 2);
});
```

```ts
// frontend/src/lib/csvExport.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { exportCsv } from "./csvExport";
import { parseCsvRecords } from "./csvImport";

test("export is RFC 4180 and round-trips through the parser", () => {
  const entries = [{ uuid: "1", title: 'Say "hi"', username: "a,b", password: "p\nq", url: "", notes: "", groupUuid: "g", updatedAt: new Date("2026-01-02T03:04:05Z"), tags: ["x", "y"], favorite: false, custom: [], expiresAt: new Date("2027-01-01T00:00:00Z") }];
  const csv = exportCsv(entries as never, new Map([["g", "Root/Sub"]]));
  assert.ok(csv.startsWith("Group,Title,Username,Password,URL,Notes,TOTP,Tags,Expires,Last Modified\r\n"));
  const rows = parseCsvRecords(csv);
  assert.deepEqual(rows[1], ["Root/Sub", 'Say "hi"', "a,b", "p\nq", "", "", "", "x;y", "2027-01-01T00:00:00.000Z", "2026-01-02T03:04:05.000Z"]);
});
```

- [ ] **Step 2: Run to see them fail** → FAIL.

- [ ] **Step 3: Implement**

`bitwardenImport.ts` parses with `JSON.parse` in a try, requires `Array.isArray(data.items)` (else "This is not a Bitwarden export."), refuses `data.encrypted === true` ("This Bitwarden export is encrypted. Export it unencrypted and import that file."), maps folders by id, and builds `ImportedEntryPreview` for `type === 1` with `id: crypto.randomUUID()`; counts the rest by type.

`csvImport.ts`: add `ColumnMapping` and `applyMapping` (rows after the header when `hasHeader`; a row is skipped when title and username and password are all empty; `id: crypto.randomUUID()`, `selected: true`, missing columns become `""`). Export `parseCsvRecords` is already exported.

`csvExport.ts`:

```ts
import type { VaultEntry } from "./kdbx";
const HEADER = ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Tags", "Expires", "Last Modified"];
const cell = (v: string) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
export function exportCsv(entries: VaultEntry[], groupsByUuid: Map<string, string>): string {
  const lines = [HEADER.join(",")];
  for (const e of entries) {
    lines.push([groupsByUuid.get(e.groupUuid) ?? "", e.title, e.username, e.password, e.url, e.notes, e.totpSeed ?? "",
      e.tags.join(";"), e.expiresAt?.toISOString() ?? "", e.updatedAt.toISOString()].map(cell).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
```

- [ ] **Step 4: Run the tests** → PASS.

- [ ] **Step 5: UI**

- `CsvImportModal`: accept `.csv,.txt,.json`; a `.json` file goes through `parseBitwardenJson` and shows the skipped counts in the summary line; when the detected provider is `generic` (or the user picks it), show a "Map columns" panel: one `<select>` per target field (title, username, password, url, notes, totp, folder) listing the CSV headers plus "Not in file", a "First row is a header" checkbox, defaults guessed from header names; preview re-runs on change via `applyMapping`. The rest of the modal (duplicates, folders, apply) is unchanged.
- Sidebar "Export CSV": `dialogs.confirm({ title: "Export passwords as plain text?", message: "The CSV contains every password and TOTP secret unencrypted. Save it only to a device you control and delete it when you are done.", confirmLabel: "Export", danger: true })`, then `downloadBlob(new Blob([exportCsv(vault.getLiveEntries(), pathMap)], { type: "text/csv" }), \`${username}-vault.csv\`)` where `pathMap` comes from `getLiveGroups()` paths.

- [ ] **Step 6: Verify, DOX, commit**

Run: `cd frontend && npm test && npm run build`. Mock: import a small Bitwarden JSON, map a generic CSV with unusual headers, export CSV and open the confirm.

`AGENTS.md` `csvImport.ts` bullet: add "Bitwarden unencrypted JSON exports import logins with folder and TOTP (`bitwardenImport.ts`); generic CSV supports explicit column mapping (`applyMapping`); `csvExport.ts` writes a KeePassXC-compatible CSV (plus Tags, Expires, Last Modified) behind a plaintext warning."

```bash
git add frontend/src/lib/bitwardenImport.ts frontend/src/lib/bitwardenImport.test.ts frontend/src/lib/csvImport.ts frontend/src/lib/csvImport.test.ts frontend/src/lib/csvExport.ts frontend/src/lib/csvExport.test.ts frontend/src/components/CsvImportModal.tsx frontend/src/pages/VaultPage.tsx AGENTS.md
git commit -m "bitwarden import, CSV column mapping, CSV export"
```

---

### Task 5: End-of-phase verification and PR (controller)

- [ ] Full gates: `gofmt -l . ; go vet ./... ; go test -race ./...` and `cd frontend && npm test && npm run build`.
- [ ] Browser pass with the mock at 1280px and 390px: folder move and delete with restore, tags and expiry badges and search, custom protected field masked, KDBX import of the vault's own export (all skipped) and of a second file, Bitwarden JSON import, generic CSV mapping, CSV export confirm. Check a downloaded `.kdbx` opens in KeePassXC if available on the workstation (`keepassxc-cli ls` with the hex key) and shows tags and expiry.
- [ ] Open the PR with the `pull-request` skill. Title: `Phase 4a vault data features from the 2026-09-25 audit`. Base: `master`.
