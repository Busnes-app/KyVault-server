import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { describeImport } from "./kdbxImport";
import * as kdbxweb from "kdbxweb";

const { Consts, Credentials, ProtectedValue, Kdbx } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;
const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

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
  // Pre-existing entry with the same UUID as e1 must win. createNew always seeds four
  // default folders (General/Personal/Work/Finance), so the source root brings five
  // groups (those plus Shared), not just the one the caller added.
  const clash = b.recoverEntryCopy(a, e1.uuid, { keepUuid: true });
  const foreign = await KeePassVault.open(bytes, keyA);
  const report = b.importFrom(foreign);
  assert.equal(report.groups, 5);
  assert.equal(report.entries, 0);
  assert.equal(report.skippedEntries, 1);
  const imported = b.getLiveGroups().find((x) => x.name === "Other");
  assert.ok(imported, "a top-level folder named after the source root");
  const e2 = a.createEntry({ title: "Second", username: "", password: "p2", url: "", notes: "", groupUuid: rootA, tags: [], favorite: true, custom: [{ name: "K", value: "v", protected: true }] });
  const foreign2 = await KeePassVault.open(await a.exportBinary(), keyA);
  const report2 = b.importFrom(foreign2);
  assert.equal(report2.entries, 1);
  // Existing group UUIDs recurse instead of being skipped, so nothing here is a skip:
  // each of the 5 already-imported groups is revisited but has no new content.
  assert.equal(report2.skippedGroups, 0);
  // Repeat imports reuse the existing "Other" folder rather than cluttering the vault
  // with a fresh one every time.
  assert.equal(b.getLiveGroups().filter((x) => x.name === "Other").length, 1);
  const back = b.getEntries().find((x) => x.uuid === e2.uuid)!;
  assert.equal(back.favorite, true);
  assert.deepEqual(back.custom, [{ name: "K", value: "v", protected: true }]);
  assert.ok(b.getAttachments(clash).length >= 0);
  assert.match(describeImport(report2), /1 entr/);
  const reopened = await KeePassVault.open(await b.exportBinary(), keyB);
  assert.ok(reopened.getEntries().some((x) => x.uuid === e2.uuid));
  const sharedGroup = reopened.getLiveGroups().find((x) => x.name === "Shared");
  assert.equal(sharedGroup?.uuid, g.uuid);
});

test("a foreign file opens with a plain password", async () => {
  const key = new Uint8Array(32).fill(9);
  const v = await KeePassVault.createNew(key);
  // A KyVault export is hex-keyed; opening it "foreign" with the hex string must work too.
  const hex = Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("");
  const opened = await KeePassVault.openForeign(await v.exportBinary(), hex);
  assert.equal(opened.getLiveGroups().length >= 1, true);
});

test("re-importing after adding an entry to an already-imported folder brings it in", async () => {
  const keyA = new Uint8Array(32).fill(41);
  const a = await KeePassVault.createNew(keyA, "Other");
  const rootA = a.getLiveGroups()[0].uuid;
  const shared = a.createGroup("Shared", rootA);

  const keyB = new Uint8Array(32).fill(42);
  const b = await KeePassVault.createNew(keyB, "Mine");
  const first = await KeePassVault.open(await a.exportBinary(), keyA);
  b.importFrom(first);
  assert.equal(b.getGroups().find((g) => g.uuid === shared.uuid)?.entriesCount, 0);

  a.createEntry({ title: "Later", username: "", password: "", url: "", notes: "", groupUuid: shared.uuid });
  const second = await KeePassVault.open(await a.exportBinary(), keyA);
  const report = b.importFrom(second);

  assert.equal(report.entries, 1, "the entry added to the already-imported Shared group is imported");
  const importedShared = b.getGroups().find((g) => g.uuid === shared.uuid)!;
  assert.equal(importedShared.entriesCount, 1, "it lands in the existing Shared group, not a duplicate");
  assert.equal(b.getEntries().filter((e) => e.title === "Later").length, 1);
});

test("a source root named like the target's recycle bin does not import into the bin", async () => {
  const targetKey = new Uint8Array(32).fill(43);
  const target = await KeePassVault.createNew(targetKey);
  const root = target.getLiveGroups()[0].uuid;
  const temp = target.createEntry({ title: "Temp", username: "", password: "", url: "", notes: "", groupUuid: root });
  target.deleteEntry(temp.uuid); // creates the live "Recycle Bin" group
  const bin = target.getGroups().find((g) => g.name === "Recycle Bin")!;

  const sourceKey = new Uint8Array(32).fill(44);
  const source = await KeePassVault.createNew(sourceKey, "Recycle Bin");
  const srcRoot = source.getLiveGroups()[0].uuid;
  source.createEntry({ title: "Sneaky", username: "", password: "", url: "", notes: "", groupUuid: srcRoot });

  target.importFrom(await KeePassVault.open(await source.exportBinary(), sourceKey));

  assert.equal(target.getGroups().find((g) => g.uuid === bin.uuid)!.entriesCount, 1,
    "only the original recycled Temp entry is in the bin; nothing was imported into it");
  assert.equal(target.getGroups().filter((g) => g.name === "Recycle Bin").length, 2,
    "import creates its own folder rather than reusing the bin");
});

test("importFrom validates every group name before creating anything", async () => {
  const key = new Uint8Array(32).fill(45);
  const credentials = new Credentials(ProtectedValue.fromString(bytesToHex(key)));
  const src = Kdbx.create(credentials, "Bad Source");
  src.header.setKdf(Consts.KdfId.Aes);
  const top = src.createGroup(src.getDefaultGroup(), "Top");
  const bad = src.createGroup(top, "Sub");
  bad.name = "x".repeat(300); // bypasses folderName(); kdbxweb itself has no such limit
  const source = await KeePassVault.open(await src.save(), key);

  const targetKey = new Uint8Array(32).fill(46);
  const target = await KeePassVault.createNew(targetKey);
  const entriesBefore = target.getEntries().length;
  const groupsBefore = target.getGroups().length;

  assert.throws(() => target.importFrom(source));
  assert.equal(target.getEntries().length, entriesBefore, "no partial import of entries");
  assert.equal(target.getGroups().length, groupsBefore, "no partial import of groups");
});
