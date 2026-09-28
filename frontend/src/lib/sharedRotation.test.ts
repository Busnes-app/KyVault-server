import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, fingerprint } from "./userKey";
import { newSharedKey, sealSharedKey, openSharedKey } from "./sharedKey";
import { planRotation, rotateSharedVault, rotationLanded, rotateBlocked, rotationBanner, rotationReport, pendingName,
  type KeyView, type RotateDeps } from "./sharedRotation";
import { formatWhen } from "./format";
import type { Pending } from "./sharedVaults";
import type { Member, SharedVaultSummary } from "./sharedVaults";

const VAULT = "sv_abcdefghijklmnopqrstuv";

const member = (userId: string, over: Partial<Member> = {}): Member => ({
  userId, username: userId, role: "editor", state: "active", keyFingerprint: "FP",
  keyEpoch: 1, addedAt: "2026-09-27T00:00:00Z", ...over,
});
const view = (state: "pinned" | "unknown" | "changed", publicKey: Uint8Array): KeyView =>
  ({ key: { state, fingerprint: "FP", publicKey } });
const row = (id: string, keyEpoch: number, sealedKey: string): SharedVaultSummary => ({
  id, name: "Finance", role: "owner", state: "active", keyEpoch,
  myKey: { sealedKey, keyFingerprint: "FP", keyEpoch, sealedBy: "me", sealedByFingerprint: "FP" },
});

test("planRotation seals to me, to matching and unpinned members, and names the rest", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const carol = await generateUserKey();
  const dave = await generateUserKey();
  const members = [member("me"), member("bob"), member("carol"), member("dave"), member("erin")];
  const views: Record<string, KeyView> = {
    bob: view("pinned", bob.publicKey),
    carol: view("unknown", carol.publicKey),
    dave: view("changed", dave.publicKey),
    erin: { problem: "Could not check this key" },
  };
  const plan = planRotation(members, views, { id: "me", publicKey: me.publicKey, fingerprint: await fingerprint(me.publicKey) });
  assert.deepEqual(plan.seal.map((s) => s.userId).sort(), ["bob", "carol", "me"]);
  assert.deepEqual(plan.leftBehind.map((l) => l.userId).sort(), ["dave", "erin"]);
  assert.match(plan.leftBehind.find((l) => l.userId === "dave")!.reason, /changed/i);
  assert.equal(plan.leftBehind.find((l) => l.userId === "erin")!.reason, "Could not check this key");
});

// The server refuses a rotation that does not seal the caller's own row, so my own copy is
// not a convenience: it is what makes the request valid.
test("planRotation always seals to me, whatever view the dialog holds of my key", async () => {
  const me = await generateUserKey();
  const my = { id: "me", publicKey: me.publicKey, fingerprint: await fingerprint(me.publicKey) };
  const cases: Record<string, KeyView>[] = [{}, { me: { problem: "Could not check this key" } }, { me: view("changed", new Uint8Array(1216)) }];
  for (const views of cases) {
    const plan = planRotation([member("me", { role: "owner" })], views, my);
    assert.deepEqual(plan.seal.map((s) => s.userId), ["me"]);
    assert.deepEqual([...plan.seal[0].publicKey], [...me.publicKey]);
    assert.equal(plan.seal[0].pin.state, "pinned");
    assert.equal(plan.seal[0].pin.fingerprint, my.fingerprint);
    assert.deepEqual(plan.leftBehind, []);
  }
});

// A suspended member cannot sign in, but keeping their row current means a reactivation
// needs no owner, so a usable key is sealed to like anyone else's.
test("planRotation seals to a suspended member with a usable key", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const plan = planRotation([member("me"), member("bob", { state: "suspended" })],
    { bob: view("pinned", bob.publicKey) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  assert.deepEqual(plan.seal.map((s) => s.userId).sort(), ["bob", "me"]);
  assert.deepEqual(plan.leftBehind, []);
});

test("rotateSharedVault seals a fresh key to everyone in the plan and pins the unknown ones", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const pinned: string[] = [];
  const requests: { epoch: number; version: number; kdbx: ArrayBuffer; sealed: { userId: string; sealedKey: string; keyFingerprint: string }[] }[] = [];
  const reEncrypted: { key: Uint8Array; kdbx: ArrayBuffer }[] = [];
  const plan = planRotation([member("me"), member("bob")], { bob: view("unknown", bob.publicKey) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  const deps: RotateDeps = {
    api: {
      rotate: async (_id, kdbx, epoch, version, sealed) => { requests.push({ epoch, version, kdbx, sealed }); return { keyEpoch: 2, leftBehind: [], metadata: { version: 4 }, historyCleared: true }; },
      list: async () => [],
    },
    pinUnknown: async (userId) => { pinned.push(userId); },
    // The vault has to be re-encrypted under the key that was sealed, and the bytes that come
    // back have to be the ones that are sent: either mistake ships a vault nobody can open.
    reEncrypt: async (key) => { const kdbx = new ArrayBuffer(8); reEncrypted.push({ key, kdbx }); return kdbx; },
    seed: me.seed,
  };
  const out = await rotateSharedVault(VAULT, 1, 3, plan, deps);
  assert.equal(out.keyEpoch, 2);
  assert.equal(out.version, 4, "the version the rotation wrote rebuilds the save queue");
  assert.equal(out.historyCleared, true);
  assert.deepEqual(out.leftBehind, []);
  assert.deepEqual(pinned, ["bob"]);
  assert.equal(requests.length, 1);
  const req = requests[0];
  assert.deepEqual(req.sealed.map((s) => s.userId).sort(), ["bob", "me"]);
  assert.equal(req.epoch, 1);
  assert.equal(req.version, 3);
  assert.equal(req.sealed.find((s) => s.userId === "me")!.keyFingerprint, "MY FP");
  // Both sealed copies open to the same fresh key.
  const mine = await openSharedKey(me.seed, req.sealed.find((s) => s.userId === "me")!.sealedKey);
  const his = await openSharedKey(bob.seed, req.sealed.find((s) => s.userId === "bob")!.sealedKey);
  assert.deepEqual([...mine], [...his]);
  assert.deepEqual([...out.key], [...mine]);
  assert.equal(reEncrypted.length, 1);
  assert.deepEqual([...reEncrypted[0].key], [...mine]);
  assert.equal(req.kdbx, reEncrypted[0].kdbx);
});

// historyCleared:false is the owner's cue to rotate again, so it has to survive the call.
test("rotateSharedVault reports a history the server could not clear", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me")], {}, { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  const out = await rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => ({ keyEpoch: 2, leftBehind: [], metadata: { version: 4 }, historyCleared: false }),
      list: async () => [],
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  });
  assert.equal(out.historyCleared, false);
});

test("a lost response is adopted, with the plan's own left-behind list", async () => {
  const me = await generateUserKey();
  const dave = await generateUserKey();
  const plan = planRotation([member("me"), member("dave")], { dave: view("changed", dave.publicKey) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  let sealedForMe = "";
  const out = await rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async (_id, _kdbx, _epoch, _version, sealed) => {
        sealedForMe = sealed.find((s) => s.userId === "me")!.sealedKey;
        throw new Error("network");
      },
      list: async () => [row(VAULT, 2, sealedForMe)],
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  });
  assert.equal(out.keyEpoch, 2);
  // The response is gone, so the clear is unknown and reported as not done.
  assert.equal(out.historyCleared, false);
  assert.deepEqual(out.leftBehind.map((l) => l.userId), ["dave"]);
  assert.deepEqual([...await openSharedKey(me.seed, sealedForMe)], [...out.key]);
});

test("a rotation that did not land keeps its own error", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me")], {}, { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  const other = await sealSharedKey(me.publicKey, newSharedKey());
  await assert.rejects(rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => { throw new Error("network"); },
      list: async () => [row(VAULT, 1, other)],
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  }), /network/);
});

// A list that fails says nothing about the rotation, so the caller sees the rotation's
// error, never a claim that it did not land.
test("a failed lookup after a lost response reports the rotation's error", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me")], {}, { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  await assert.rejects(rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => { throw new Error("network"); },
      list: async () => { throw new Error("offline"); },
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  }), /network/);
});

// A user with no published key reads as `unknown` with an empty key, so "unknown" is not on
// its own permission to seal: pinning zero bytes would leave them "changed" in every later
// verdict until the owner forgot the pin by hand. This is sharedFlows' NO_KEY rule, here.
test("planRotation leaves behind a member with no published key and pins nothing", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me"), member("bob")], { bob: view("unknown", new Uint8Array()) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  assert.deepEqual(plan.seal.map((s) => s.userId), ["me"]);
  assert.deepEqual(plan.leftBehind, [{ userId: "bob", username: "bob", reason: "No published key" }]);
  const pinned: string[] = [];
  const out = await rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => ({ keyEpoch: 2, leftBehind: ["bob"], metadata: { version: 4 }, historyCleared: true }),
      list: async () => [],
    },
    pinUnknown: async (userId) => { pinned.push(userId); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  });
  assert.deepEqual(pinned, []);
  assert.deepEqual(out.leftBehind.map((l) => l.reason), ["No published key"]);
});

// planRotation never puts a changed pin in the plan; the seal refuses one anyway, so a
// hand-built plan cannot hand a departed member the next key — and refuses it before the
// loop, so no pin lands for an earlier member on the way to the throw.
test("rotateSharedVault refuses a changed pin before anything is pinned", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const dave = await generateUserKey();
  const plan = planRotation([member("me"), member("bob")], { bob: view("unknown", bob.publicKey) },
    { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  plan.seal.push({ userId: "dave", publicKey: dave.publicKey, pin: { state: "changed", fingerprint: "FP", publicKey: dave.publicKey } });
  let rotates = 0;
  const pinned: string[] = [];
  await assert.rejects(rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => { rotates++; return { keyEpoch: 2, leftBehind: [], metadata: { version: 4 }, historyCleared: true }; },
      list: async () => [],
    },
    pinUnknown: async (userId) => { pinned.push(userId); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  }), /Re-pin it/);
  assert.equal(rotates, 0);
  assert.deepEqual(pinned, []);
});

test("rotationLanded matches our own key and nothing else", async () => {
  const me = await generateUserKey();
  const bob = await generateUserKey();
  const key = newSharedKey();
  const sealedForMe = await sealSharedKey(me.publicKey, key);
  const deps: RotateDeps = {
    api: {
      rotate: async () => { throw new Error("not used here"); },
      list: async () => [row(VAULT, 2, sealedForMe)],
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  };
  assert.deepEqual(await rotationLanded(VAULT, key, deps), { keyEpoch: 2 });
  // A different key means it did not land.
  assert.equal(await rotationLanded(VAULT, newSharedKey(), deps), null);
  // A vault that is no longer in the list means it did not land.
  assert.equal(await rotationLanded("sv_zzzzzzzzzzzzzzzzzzzzzz", key, deps), null);
  // A copy this seed cannot open is not ours either.
  const sealedForBob = await sealSharedKey(bob.publicKey, key);
  assert.equal(await rotationLanded(VAULT, key, { ...deps, api: { ...deps.api, list: async () => [row(VAULT, 2, sealedForBob)] } }), null);
});

test("rotationLanded throws when the list itself fails", async () => {
  const me = await generateUserKey();
  await assert.rejects(rotationLanded(VAULT, newSharedKey(), {
    api: {
      rotate: async () => { throw new Error("not used here"); },
      list: async () => { throw new Error("offline"); },
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  }), /offline/);
});

// The empty-publicKey rule lives in planRotation and here, exactly as the `changed` rule does:
// a plan built by hand must not be able to write a pin for zero bytes.
test("rotateSharedVault refuses an empty public key before anything is pinned", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me")], {}, { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  plan.seal.push({ userId: "bob", publicKey: new Uint8Array(), pin: { state: "unknown", fingerprint: "", publicKey: new Uint8Array() } });
  const pinned: string[] = [];
  let rotates = 0;
  await assert.rejects(rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async () => { rotates++; return { keyEpoch: 2, leftBehind: [], metadata: { version: 4 }, historyCleared: true }; },
      list: async () => [],
    },
    pinUnknown: async (userId) => { pinned.push(userId); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  }), /no published key/i);
  assert.equal(rotates, 0);
  assert.deepEqual(pinned, [], "a pin for zero bytes would poison that member's verdict");
});

// Nothing on this path proves which version the vault is on: a member this rotation re-sealed
// may have saved between the commit and the check. Reporting no version is what makes the
// caller re-open instead of letting a save queue claim one and upload over those edits.
test("a lost response reports no version at all", async () => {
  const me = await generateUserKey();
  const plan = planRotation([member("me")], {}, { id: "me", publicKey: me.publicKey, fingerprint: "MY FP" });
  let sealedForMe = "";
  const out = await rotateSharedVault(VAULT, 1, 3, plan, {
    api: {
      rotate: async (_id, _kdbx, _epoch, _version, sealed) => { sealedForMe = sealed[0].sealedKey; throw new Error("network"); },
      list: async () => [row(VAULT, 2, sealedForMe)],
    },
    pinUnknown: async () => { throw new Error("nothing to pin"); },
    reEncrypt: async () => new ArrayBuffer(8),
    seed: me.seed,
  });
  assert.equal(out.keyEpoch, 2);
  assert.equal(out.version, undefined);
});

test("rotateBlocked names the first thing standing in the way, in that order", () => {
  const ok = { activeOwner: true, keyReady: true, open: true, keysLoaded: true, unsaved: false };
  assert.equal(rotateBlocked(ok), null);
  assert.match(rotateBlocked({ ...ok, activeOwner: false })!, /active owner/);
  assert.match(rotateBlocked({ ...ok, activeOwner: false, unsaved: true })!, /active owner/, "authority is named before housekeeping");
  assert.match(rotateBlocked({ ...ok, keyReady: false })!, /user key/);
  assert.match(rotateBlocked({ ...ok, open: false })!, /Open this vault/);
  // The one that matters: planRotation strands every member whose verdict has not arrived.
  assert.match(rotateBlocked({ ...ok, keysLoaded: false })!, /Still checking every member/);
  assert.match(rotateBlocked({ ...ok, keysLoaded: false, unsaved: true })!, /Still checking every member/);
  assert.match(rotateBlocked({ ...ok, unsaved: true })!, /unsaved edits/);
});

const SINCE = "2026-09-27T10:00:00Z";
const pending = (over: Partial<Pending> = {}): Pending => ({ since: SINCE, userId: "u-9", reason: "removed", ...over });

test("the rotation banner names who left, how, when, and what their copy still opens", () => {
  const members = [{ userId: "u-1", username: "mock-admin" }];
  const removed = rotationBanner(pending(), members);
  assert.match(removed, /^u-9 was removed on /, "a departed member is no longer in the list, so their id names them");
  assert.ok(removed.includes(formatWhen(SINCE)));
  assert.match(removed, /Their copy of the key still opens anything this vault saved before a rotation\./);
  assert.match(removed, /Rotating re-keys the vault for everyone who remains\.$/);
  assert.match(rotationBanner(pending({ reason: "left", userId: "u-1" }), members), /^mock-admin left on /);
  assert.match(rotationBanner(pending({ reason: "declined" }), members), /^u-9 declined the invitation on /);
  assert.equal(pendingName(pending({ userId: "u-1" }), members), "mock-admin");
});

test("the rotation report counts the new copies, names who was left behind, and a history that stayed", () => {
  const clean = rotationReport(3, { leftBehind: [], historyCleared: true });
  assert.equal(clean, "Rotated. 3 members have the new key.");
  assert.equal(rotationReport(1, { leftBehind: [], historyCleared: true }), "Rotated. 1 member has the new key.");

  const left = rotationReport(2, { leftBehind: [{ userId: "u-3", username: "dana", reason: "their key changed since you pinned it" }], historyCleared: true });
  assert.match(left, /dana \(their key changed since you pinned it\)/);
  assert.match(left, /Verify their key and re-seal them from this dialog\.$/);

  const kept = rotationReport(2, { leftBehind: [], historyCleared: false });
  assert.match(kept, /could not be deleted/);
  assert.match(kept, /Rotate again/);
});
