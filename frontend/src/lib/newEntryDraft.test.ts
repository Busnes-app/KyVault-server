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
