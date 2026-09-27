import { test } from "node:test";
import assert from "node:assert/strict";
import { adoptUserKey, newUserKeyRecord, rewrapUserKey } from "./userKeyState";
import { b64, unwrapSeed } from "./userKey";

const vk = new Uint8Array(32).fill(4);

test("no record yields none; a fresh record round-trips to ready", async () => {
  assert.deepEqual(await adoptUserKey(undefined, vk, "u1"), { kind: "none" });
  const made = await newUserKeyRecord(vk, "u1");
  assert.equal(made.record.alg, "xwing");
  assert.equal(b64.decode(made.record.publicKey).length, 1216);
  const adopted = await adoptUserKey(made.record, vk, "u1");   // unlock adopts an existing record instead of generating
  assert.equal(adopted.kind, "ready");
  if (adopted.kind === "ready") assert.deepEqual(adopted.seed, made.seed);
});

test("unwrap failure yields a mismatch state", async () => {
  const made = await newUserKeyRecord(vk, "u1");
  const wrong = await adoptUserKey(made.record, new Uint8Array(32).fill(5), "u1");
  assert.equal(wrong.kind, "mismatch");
  const truncated = { ...made.record, wrappedSeed: made.record.wrappedSeed.slice(0, 20) };
  assert.equal((await adoptUserKey(truncated, vk, "u1")).kind, "mismatch");
  const swapped = { ...made.record, publicKey: b64.encode(new Uint8Array(1216)) };
  const s = await adoptUserKey(swapped, vk, "u1");
  assert.equal(s.kind, "mismatch");
  if (s.kind === "mismatch") assert.match(s.reason, /does not match/);
});

test("rewrap keeps the seed and public key under the new vault key", async () => {
  const made = await newUserKeyRecord(vk, "u1");
  const state = await adoptUserKey(made.record, vk, "u1");
  const nvk = new Uint8Array(32).fill(6);
  const rec = await rewrapUserKey(state, nvk, "u1");
  assert.ok(rec);
  assert.equal(rec!.publicKey, made.record.publicKey);
  assert.deepEqual(await unwrapSeed(b64.decode(rec!.wrappedSeed), nvk, "u1"), made.seed);
  assert.equal(await rewrapUserKey({ kind: "none" }, nvk, "u1"), undefined);
});
