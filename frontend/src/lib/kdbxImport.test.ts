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
  assert.equal(report2.skippedGroups, 5);
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
