import { test } from "node:test";
import assert from "node:assert/strict";
import { planReplace, replaceWarning, resealHeld, retryPending, runKeyReplace, zeroKeys, type HeldKey, type SealIdentity } from "./keyReplaceReseal";
import { generateUserKey, fingerprint } from "./userKey";
import { sealSharedKey, openSharedKey, newSharedKey } from "./sharedKey";

const row = (id: string, name: string, role: any, sealedKey: string, state = "active"): any => ({ id, name, role, state, keyEpoch: 1, myKey: { sealedKey, keyFingerprint: "", keyEpoch: 1, sealedBy: "", sealedByFingerprint: "" } });

const A = "sv_aaaaaaaaaaaaaaaaaaaaaa";
const B = "sv_bbbbbbbbbbbbbbbbbbbbbb";
const C = "sv_cccccccccccccccccccccc";
const D = "sv_dddddddddddddddddddddd";

const noMembers = async (id: string) => ({ id, name: "", createdBy: "", createdAt: "", keyEpoch: 1, members: [] } as any);
// An api the tests can drive: list is what planReplace must read, get is the member list.
const fakeApi = (vaults: any[], get = noMembers, updateMember: any = async () => {}): any => ({ list: async () => vaults, get, updateMember });

test("planReplace holds openable keys and names the rest", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const k1 = newSharedKey();
  const vaults = [
    row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1)),
    row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey())),
    row(C, "Invited", "editor", "AAAA", "invited"),
  ];
  const get = async (id: string) => ({ id, name: "", createdBy: "", createdAt: "", keyEpoch: 1, members: id.startsWith("sv_b") ? [{ userId: "me", role: "owner", state: "active" }] : [] } as any);
  const plan = await planReplace(me.seed, fakeApi(vaults, get), openSharedKey);
  assert.deepEqual(plan.held.map((h) => h.id), [A]);
  assert.deepEqual([...plan.held[0].key], [...k1]);
  assert.deepEqual(plan.unopenable, [{ id: B, name: "Ops", soleOwner: true }]);
  assert.match(replaceWarning(plan) ?? "", /Ops.*contents will be lost/s);
  assert.equal(replaceWarning({ held: [], unopenable: [] }), null);
});

test("planReplace reads the list itself, so a stale cache cannot empty the plan", async () => {
  const me = await generateUserKey();
  const k1 = newSharedKey();
  let calls = 0;
  const api: any = {
    list: async () => { calls++; return [row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1))]; },
    get: noMembers,
  };
  const plan = await planReplace(me.seed, api, openSharedKey);
  assert.equal(calls, 1);
  assert.deepEqual(plan.held.map((h) => h.name), ["Finance"]);
});

test("planReplace rejects when the list cannot be read", async () => {
  const me = await generateUserKey();
  const api: any = { list: async () => { throw new Error("service unavailable"); }, get: noMembers };
  await assert.rejects(() => planReplace(me.seed, api, openSharedKey), /service unavailable/);
});

test("planReplace skips rows no key can open today", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const vaults = [
    row(A, "Stale", "owner", await sealSharedKey(other.publicKey, newSharedKey()), "stale"),
    row(B, "Suspended", "owner", await sealSharedKey(other.publicKey, newSharedKey()), "suspended"),
    row(C, "Invited", "editor", "AAAA", "invited"),
  ];
  const plan = await planReplace(me.seed, fakeApi(vaults), openSharedKey);
  assert.deepEqual(plan, { held: [], unopenable: [] });
  assert.equal(replaceWarning(plan), null);
});

test("planReplace keeps a co-owned vault out of the lost-contents warning", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const vaults = [row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey()))];
  const get = async (id: string) => ({
    id, name: "", createdBy: "", createdAt: "", keyEpoch: 1,
    members: [{ userId: "me", role: "owner", state: "active" }, { userId: "them", role: "owner", state: "active" }],
  } as any);
  const plan = await planReplace(me.seed, fakeApi(vaults, get), openSharedKey);
  assert.deepEqual(plan.unopenable, [{ id: B, name: "Ops", soleOwner: false }]);
  const warning = replaceWarning(plan) ?? "";
  assert.match(warning, /this shared vault: "Ops"/);
  assert.doesNotMatch(warning, /contents will be lost/);
});

test("planReplace treats an unreadable member list as sole ownership", async () => {
  const me = await generateUserKey();
  const other = await generateUserKey();
  const vaults = [row(B, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey()))];
  const get = async () => { throw new Error("internal error"); };
  const plan = await planReplace(me.seed, fakeApi(vaults, get), openSharedKey);
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
  const plan = await planReplace(null, fakeApi(vaults), openSharedKey);
  assert.deepEqual(plan.held, []);
  assert.deepEqual(plan.unopenable, [{ id: A, name: "Finance", soleOwner: false }, { id: B, name: "Ops", soleOwner: true }]);
  const warning = replaceWarning(plan) ?? "";
  assert.match(warning, /these shared vaults: "Finance"; "Ops" \(you are its only owner/);
  assert.match(warning, /does not recover them/);
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

test("retryPending reseals only the failed subset from the keys still held", async () => {
  const me = await generateUserKey();
  const held: HeldKey[] = [{ id: B, name: "Ops", key: newSharedKey() }];
  const fp = await fingerprint(me.publicKey);
  const pending = { failed: [{ id: B, name: "Ops", error: "re-authenticate to continue" }], held, me: { id: "me", publicKey: me.publicKey, fingerprint: fp } };
  const calls: string[] = [];
  let refuse = true;
  const api: any = { updateMember: async (id: string) => { calls.push(id); if (refuse) throw new Error("re-authenticate to continue"); } };
  const again = await retryPending(pending, api);
  assert.deepEqual(again?.held, held);
  assert.deepEqual(again?.failed.map((f) => f.id), [B]);
  refuse = false;
  assert.equal(await retryPending(again!, api), null);
  assert.deepEqual(calls, [B, B]);
  // The keys are the caller's to wipe once it drops the pending.
  zeroKeys(held);
  assert.deepEqual([...held[0].key], new Array(32).fill(0));
});

const steps = (over: any) => ({
  seed: over.seed ?? null,
  api: over.api,
  prove: over.prove ?? (async () => 7),
  confirm: over.confirm ?? (async () => true),
  publish: over.publish ?? (async () => { throw new Error("publish must not run"); }),
});

test("runKeyReplace never publishes when the list cannot be read", async () => {
  let published = false;
  const api: any = { list: async () => { throw new Error("service unavailable"); }, get: noMembers, updateMember: async () => {} };
  await assert.rejects(() => runKeyReplace(steps({ api, publish: async () => { published = true; throw new Error("unreachable"); } })), /service unavailable/);
  assert.equal(published, false);
});

test("runKeyReplace confirms with the warning, then re-seals what it holds", async () => {
  const me = await generateUserKey();
  const next = await generateUserKey();
  const other = await generateUserKey();
  const k1 = newSharedKey();
  const vaults = [
    row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1)),
    row(D, "Ops", "owner", await sealSharedKey(other.publicKey, newSharedKey())),
  ];
  const patches: any[] = [];
  const api = fakeApi(vaults, noMembers, async (id: string, userId: string, patch: any) => { patches.push([id, userId, patch]); });
  let shown = "";
  const order: string[] = [];
  const identity: SealIdentity = { id: "me", publicKey: next.publicKey, fingerprint: await fingerprint(next.publicKey) };
  const out = await runKeyReplace(steps({
    seed: me.seed, api,
    prove: async () => { order.push("prove"); return 7; },
    confirm: async (message: string) => { order.push("confirm"); shown = message; return true; },
    publish: async (version: number) => { order.push(`publish:${version}`); return identity; },
  }));
  assert.deepEqual(order, ["prove", "confirm", "publish:7"]);
  assert.match(shown, /verify the new one/);
  assert.match(shown, /"Ops" \(you are its only owner, so its contents will be lost\)/);
  assert.deepEqual(out, { replaced: true, pending: null });
  assert.deepEqual(patches.map((p) => p[0]), [A]);
  assert.deepEqual([...(await openSharedKey(next.seed, patches[0][2].sealedKey))], [...k1]);
});

test("runKeyReplace hands back only the failed keys and wipes the rest", async () => {
  const me = await generateUserKey();
  const next = await generateUserKey();
  const k1 = newSharedKey();
  const k2 = newSharedKey();
  const vaults = [
    row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1)),
    row(B, "Ops", "editor", await sealSharedKey(me.publicKey, k2)),
  ];
  const api = fakeApi(vaults, noMembers, async (id: string) => { if (id === B) throw new Error("re-authenticate to continue"); });
  const identity: SealIdentity = { id: "me", publicKey: next.publicKey, fingerprint: await fingerprint(next.publicKey) };
  const out = await runKeyReplace(steps({ seed: me.seed, api, publish: async () => identity }));
  assert.equal(out.replaced, true);
  assert.deepEqual(out.pending?.failed.map((f) => f.id), [B]);
  assert.deepEqual(out.pending?.held.map((h) => h.id), [B]);
  assert.deepEqual([...out.pending!.held[0].key], [...k2]);
  assert.equal(out.pending?.me, identity);
});

test("runKeyReplace wipes every held key when the user refuses", async () => {
  const me = await generateUserKey();
  const k1 = newSharedKey();
  const vaults = [row(A, "Finance", "owner", await sealSharedKey(me.publicKey, k1))];
  const api = fakeApi(vaults);
  const opened: HeldKey[] = [];
  const openKey = async (seed: Uint8Array, sealed: string) => {
    const key = await openSharedKey(seed, sealed);
    opened.push({ id: A, name: "Finance", key });
    return key;
  };
  const wrongPassword = await runKeyReplace({ ...steps({ seed: me.seed, api, prove: async () => null }), openKey });
  assert.deepEqual(wrongPassword, { replaced: false, pending: null });
  assert.deepEqual([...opened[0].key], new Array(32).fill(0));
  const cancelled = await runKeyReplace({ ...steps({ seed: me.seed, api, confirm: async () => false }), openKey });
  assert.deepEqual(cancelled, { replaced: false, pending: null });
  assert.deepEqual([...opened[1].key], new Array(32).fill(0));
});

test("runKeyReplace wipes held keys when publishing throws", async () => {
  const me = await generateUserKey();
  const vaults = [row(A, "Finance", "owner", await sealSharedKey(me.publicKey, newSharedKey()))];
  const opened: HeldKey[] = [];
  const openKey = async (seed: Uint8Array, sealed: string) => {
    const key = await openSharedKey(seed, sealed);
    opened.push({ id: A, name: "Finance", key });
    return key;
  };
  await assert.rejects(() => runKeyReplace({ ...steps({ seed: me.seed, api: fakeApi(vaults), publish: async () => { throw new Error("409"); } }), openKey }), /409/);
  assert.deepEqual([...opened[0].key], new Array(32).fill(0));
});
