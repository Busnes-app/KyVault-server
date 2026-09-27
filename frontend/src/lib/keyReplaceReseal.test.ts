import { test } from "node:test";
import assert from "node:assert/strict";
import { planReplace, replaceWarning, resealHeld, zeroKeys, type HeldKey } from "./keyReplaceReseal";
import { generateUserKey, fingerprint } from "./userKey";
import { sealSharedKey, openSharedKey, newSharedKey } from "./sharedKey";

const row = (id: string, name: string, role: any, sealedKey: string, state = "active"): any => ({ id, name, role, state, keyEpoch: 1, myKey: { sealedKey, keyFingerprint: "", keyEpoch: 1, sealedBy: "", sealedByFingerprint: "" } });

const A = "sv_aaaaaaaaaaaaaaaaaaaaaa";
const B = "sv_bbbbbbbbbbbbbbbbbbbbbb";
const C = "sv_cccccccccccccccccccccc";

test("planReplace holds openable keys and names the rest", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const k1 = newSharedKey();
  const vaults = [
    row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1)),
    row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey())),
    row(C, "Invited", "editor", "AAAA", "invited"),
  ];
  const detail = async (id: string) => ({ id, name: "", createdBy: "", createdAt: "", keyEpoch: 1, members: id.startsWith("sv_b") ? [{ userId: "me", role: "owner", state: "active" }] : [] } as any);
  const plan = await planReplace(vaults, me.seed, openSharedKey, detail);
  assert.deepEqual(plan.held.map((h) => h.id), [A]);
  assert.deepEqual([...plan.held[0].key], [...k1]);
  assert.deepEqual(plan.unopenable, [{ id: B, name: "Ops", soleOwner: true }]);
  assert.match(replaceWarning(plan) ?? "", /Ops.*contents will be lost/s);
  assert.equal(replaceWarning({ held: [], unopenable: [] }), null);
});

test("planReplace keeps a co-owned vault out of the lost-contents warning", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const vaults = [row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey()))];
  const detail = async (id: string) => ({
    id, name: "", createdBy: "", createdAt: "", keyEpoch: 1,
    members: [{ userId: "me", role: "owner", state: "active" }, { userId: "them", role: "owner", state: "active" }],
  } as any);
  const plan = await planReplace(vaults, me.seed, openSharedKey, detail);
  assert.deepEqual(plan.unopenable, [{ id: B, name: "Ops", soleOwner: false }]);
  const warning = replaceWarning(plan) ?? "";
  assert.match(warning, /"Ops"/);
  assert.doesNotMatch(warning, /contents will be lost/);
});

test("planReplace treats an unreadable member list as sole ownership", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const vaults = [row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey()))];
  const detail = async () => { throw new Error("internal error"); };
  const plan = await planReplace(vaults, me.seed, openSharedKey, detail);
  assert.deepEqual(plan.unopenable, [{ id: B, name: "Ops", soleOwner: true }]);
  assert.match(replaceWarning(plan) ?? "", /Ops.*contents will be lost/s);
});

test("planReplace with no usable key names every vault it holds a row in", async () => {
  const other = await generateUserKey();
  const vaults = [
    row(A, "Finance", "editor", await sealSharedKey(other.publicKey, newSharedKey())),
    row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey())),
    row(C, "Invited", "editor", "AAAA", "invited"),
  ];
  const detail = async (id: string) => ({ id, name: "", createdBy: "", createdAt: "", keyEpoch: 1, members: [] } as any);
  const plan = await planReplace(vaults, null, openSharedKey, detail);
  assert.deepEqual(plan.held, []);
  assert.deepEqual(plan.unopenable, [{ id: A, name: "Finance", soleOwner: false }, { id: B, name: "Ops", soleOwner: true }]);
});

test("resealHeld reseals to the new key and collects failures", async () => {
  const me = await generateUserKey();
  const held = [{ id: A, name: "Finance", key: newSharedKey() }, { id: B, name: "Ops", key: newSharedKey() }];
  const calls: any[] = [];
  const api: any = { updateMember: async (id: string, userId: string, patch: any) => { calls.push([id, userId, patch]); if (id.startsWith("sv_b")) throw new Error("boom"); } };
  const fp = await fingerprint(me.publicKey);
  const { failed } = await resealHeld(held, { id: "me", publicKey: me.publicKey, fingerprint: fp }, api);
  assert.deepEqual(failed.map((f) => f.id), [B]);
  assert.deepEqual(failed.map((f) => f.error), ["boom"]);
  assert.equal(calls[0][2].keyFingerprint, fp);
  assert.equal(calls[0][1], "me");
  assert.equal("role" in calls[0][2], false);
  assert.deepEqual([...(await openSharedKey(me.seed, calls[0][2].sealedKey))], [...held[0].key]);
});

test("a retry reseals only the failed subset from the keys still held", async () => {
  const me = await generateUserKey();
  const held: HeldKey[] = [{ id: A, name: "Finance", key: newSharedKey() }, { id: B, name: "Ops", key: newSharedKey() }];
  let refuse = true;
  const calls: string[] = [];
  const api: any = { updateMember: async (id: string, _userId: string, _patch: any) => { calls.push(id); if (refuse && id === B) throw new Error("re-authenticate to change this vault"); } };
  const fp = await fingerprint(me.publicKey);
  const me2 = { id: "me", publicKey: me.publicKey, fingerprint: fp };
  const first = await resealHeld(held, me2, api);
  assert.deepEqual(first.failed.map((f) => f.error), ["re-authenticate to change this vault"]);
  // The succeeded key is wiped; the failed one is still usable for the retry.
  const stillNeeded = held.filter((h) => first.failed.some((f) => f.id === h.id));
  zeroKeys(held.filter((h) => !first.failed.some((f) => f.id === h.id)));
  assert.deepEqual([...held[0].key], new Array(32).fill(0));
  refuse = false;
  const retry = await resealHeld(stillNeeded, me2, api);
  assert.deepEqual(retry.failed, []);
  assert.deepEqual(calls, [A, B, B]);
  zeroKeys(stillNeeded);
  assert.deepEqual([...held[1].key], new Array(32).fill(0));
});
