import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault, isWrongVaultKey } from "./kdbx.js";
import { diffVaults } from "./vaultDiff.js";

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

test("a snapshot under another vault key is refused as InvalidKey", async () => {
  const oldKey = new Uint8Array(32).fill(1);
  const snapshot = await (await KeePassVault.createNew(oldKey)).exportBinary();
  const error = await KeePassVault.open(snapshot, new Uint8Array(32).fill(2)).then(() => undefined, (e: unknown) => e);
  assert.equal(isWrongVaultKey(error), true);
  assert.equal(isWrongVaultKey(new Error("network")), false);
});
