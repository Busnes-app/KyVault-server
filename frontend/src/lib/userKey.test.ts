import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { generateUserKey, publicKeyFromSeed, fingerprint, wrapSeed, unwrapSeed, seal, open, b64 } from "./userKey";

const VECTOR = new URL("./testdata/hpke-xwing-vector.json", import.meta.url);
const vaultKey = new Uint8Array(32).fill(7);
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

test("generate, derive, wrap and unwrap", async () => {
  const { seed, publicKey } = await generateUserKey();
  assert.equal(seed.length, 32);
  assert.equal(publicKey.length, 1216);
  assert.deepEqual(await publicKeyFromSeed(seed), publicKey);
  const wrapped = await wrapSeed(seed, vaultKey, "u-1");
  assert.equal(wrapped.length, 60);
  assert.deepEqual(await unwrapSeed(wrapped, vaultKey, "u-1"), seed);
  await assert.rejects(unwrapSeed(wrapped, new Uint8Array(32).fill(8), "u-1"));
  await assert.rejects(unwrapSeed(wrapped, vaultKey, "u-2"));
});

test("seal and open round trip; wrong seed and wrong info fail", async () => {
  const a = await generateUserKey();
  const b = await generateUserKey();
  const sealed = await seal(a.publicKey, "kyvault/test/1", enc("secret"));
  assert.equal(dec(await open(a.seed, "kyvault/test/1", sealed)), "secret");
  await assert.rejects(open(b.seed, "kyvault/test/1", sealed));
  await assert.rejects(open(a.seed, "kyvault/other/1", sealed));
});

test("fingerprint matches the Go vector", async () => {
  const pk = new Uint8Array(1216);
  for (let i = 0; i < pk.length; i++) pk[i] = i & 0xff;
  assert.equal(await fingerprint(pk), GO_FINGERPRINT_OF_COUNTING_KEY);
});

test("HPKE interop with Go crypto/hpke", async () => {
  const v = JSON.parse(readFileSync(VECTOR, "utf8"));
  const seed = b64.decode(v.seed);
  assert.deepEqual(await publicKeyFromSeed(seed), b64.decode(v.publicKey));
  assert.equal(dec(await open(seed, v.info, b64.decode(v.goSealed))), v.plaintext);
  if (process.env.UPDATE_VECTOR === "1") {
    v.jsSealed = b64.encode(await seal(b64.decode(v.publicKey), v.info, enc("hello from js")));
    writeFileSync(VECTOR, JSON.stringify(v, null, 2) + "\n");
  } else {
    assert.ok(v.jsSealed, "jsSealed missing; run once with UPDATE_VECTOR=1");
  }
});

// Copy from internal/userkey/userkey_test.go fingerprintOfCountingKey.
const GO_FINGERPRINT_OF_COUNTING_KEY = "B74C BE6A BEFF 8BF1 95BA";
