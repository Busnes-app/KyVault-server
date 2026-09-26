import { test } from "node:test";
import assert from "node:assert/strict";
import { cacheDeviceKey } from "./deviceKeyCache";

test("a forget that completes while the store is pending leaves no cached key", async () => {
  let cached: string | undefined;
  let generation = 1;
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const run = cacheDeviceKey({
    store: async () => { await gate; cached = "key"; },
    clear: async () => { cached = undefined; },
    stillCurrent: () => generation === 1,
  });
  // Forget This Device: clears the cache and invalidates the generation.
  cached = undefined;
  generation = 2;
  release();
  assert.equal(await run, "discarded");
  assert.equal(cached, undefined);
});

test("an uncontested store stays cached; an already stale one never writes", async () => {
  let cached: string | undefined;
  assert.equal(await cacheDeviceKey({ store: async () => { cached = "key"; }, clear: async () => { cached = undefined; }, stillCurrent: () => true }), "cached");
  assert.equal(cached, "key");
  let wrote = false;
  assert.equal(await cacheDeviceKey({ store: async () => { wrote = true; }, clear: async () => {}, stillCurrent: () => false }), "discarded");
  assert.equal(wrote, false);
  assert.equal(await cacheDeviceKey({ store: async () => { throw new Error("quota"); }, clear: async () => {}, stillCurrent: () => true }), "failed");
});
