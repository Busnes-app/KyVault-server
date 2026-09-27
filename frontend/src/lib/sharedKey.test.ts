import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, b64 } from "./userKey";
import { newSharedKey, sealSharedKey, openSharedKey, SEALED_KEY_BYTES, SHARED_KEY_BYTES } from "./sharedKey";

test("shared key seals to a public key and opens with its seed", async () => {
  const alice = await generateUserKey();
  const key = newSharedKey();
  assert.equal(key.length, SHARED_KEY_BYTES);
  const sealed = await sealSharedKey(alice.publicKey, key);
  assert.equal(b64.decode(sealed).length, SEALED_KEY_BYTES);
  const opened = await openSharedKey(alice.seed, sealed);
  assert.deepEqual([...opened], [...key]);
});

test("a different seed cannot open the key", async () => {
  const alice = await generateUserKey();
  const mallory = await generateUserKey();
  const sealed = await sealSharedKey(alice.publicKey, newSharedKey());
  await assert.rejects(openSharedKey(mallory.seed, sealed));
});

test("sealing refuses a key of the wrong length", async () => {
  const alice = await generateUserKey();
  await assert.rejects(sealSharedKey(alice.publicKey, new Uint8Array(16)), /32 bytes/);
});

test("two fresh keys differ", () => {
  assert.notDeepEqual([...newSharedKey()], [...newSharedKey()]);
});
