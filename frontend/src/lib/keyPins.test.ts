import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { generateUserKey, fingerprint, b64 } from "./userKey";
import { lookupKey, pinKey, readPin, pinKeyFor, type PublishedKey } from "./keyPins";

async function published(userId: string, publicKey: Uint8Array): Promise<PublishedKey> {
  return { userId, publicKey, fingerprint: await fingerprint(publicKey), createdAt: "2026-09-27T00:00:00Z", previous: [] };
}

test("lookup with no published key", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(1));
  const r = await lookupKey(vault, "bob", async () => null);
  assert.deepEqual(r, { state: "unknown", published: null });
});

test("unknown, pinned, changed; pins survive an encrypted reopen", async () => {
  const key = new Uint8Array(32).fill(2);
  const vault = await KeePassVault.createNew(key);
  const k1 = await generateUserKey();
  const k2 = await generateUserKey();
  const fetch1 = async (id: string) => published(id, k1.publicKey);
  const fetch2 = async (id: string) => published(id, k2.publicKey);

  assert.equal((await lookupKey(vault, "bob", fetch1)).state, "unknown");
  let changed = 0;
  const pin = await pinKey(vault, "bob", k1.publicKey, () => { changed++; });
  assert.equal(changed, 1);
  assert.equal(pin.publicKey, b64.encode(k1.publicKey));
  assert.equal(readPin(vault, "bob")?.fingerprint, await fingerprint(k1.publicKey));
  assert.equal((await lookupKey(vault, "bob", fetch1)).state, "pinned");
  const r = await lookupKey(vault, "bob", fetch2);
  assert.equal(r.state, "changed");
  if (r.state === "changed") assert.notEqual(r.pin.fingerprint, r.published.fingerprint);

  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  assert.equal((await lookupKey(reopened, "bob", fetch1)).state, "pinned");
  assert.equal(reopened.getCustomData(pinKeyFor("bob")), vault.getCustomData(pinKeyFor("bob")));
  assert.deepEqual(reopened.customDataKeys("kyvault.pin."), [pinKeyFor("bob")]);
});

test("a malformed pin counts as unknown and is overwritten by pinKey", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(3));
  vault.setCustomData(pinKeyFor("bob"), "{not json");
  const k = await generateUserKey();
  assert.equal((await lookupKey(vault, "bob", async (id) => published(id, k.publicKey))).state, "unknown");
  await pinKey(vault, "bob", k.publicKey, () => {});
  assert.equal(readPin(vault, "bob")?.publicKey, b64.encode(k.publicKey));
});
