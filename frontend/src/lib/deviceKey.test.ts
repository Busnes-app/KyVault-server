import { test } from "node:test";
import assert from "node:assert/strict";
import { newWrappingKey, sealKeyHex, openKeyHex } from "./deviceKey";

test("device key round-trips under a non-extractable wrapping key", async () => {
  const wrapping = await newWrappingKey();
  assert.equal(wrapping.extractable, false);
  const sealed = await sealKeyHex(wrapping, "ab".repeat(32));
  assert.equal(await openKeyHex(wrapping, sealed), "ab".repeat(32));
});

test("tampered ciphertext and a different wrapping key both fail", async () => {
  const wrapping = await newWrappingKey();
  const sealed = await sealKeyHex(wrapping, "cd".repeat(32));
  const tampered = { ...sealed, ciphertext: sealed.ciphertext.map((b, i) => (i === 3 ? b ^ 1 : b)) };
  await assert.rejects(openKeyHex(wrapping, tampered));
  await assert.rejects(openKeyHex(await newWrappingKey(), sealed));
});
