import { test } from "node:test";
import assert from "node:assert/strict";
import { generateUserKey, fingerprint } from "./userKey";
import { openSharedKey } from "./sharedKey";
import { createSharedVault, resolveInvitee, inviteMember, resealMember, acceptInvitation, inviterStatus, type FlowDeps, type PinStatus } from "./sharedFlows";
import { lookupKey, pinKey, readPin, type PublishedKey } from "./keyPins";
import type { KeePassVault } from "./kdbx";
import type { SharedApi, SharedVaultSummary } from "./sharedVaults";

// A vault stand-in: pins are database custom data, so a Map is the whole contract.
function fakeVault(): KeePassVault {
  const m = new Map<string, string>();
  return {
    getCustomData: (k: string) => m.get(k),
    setCustomData: (k: string, v: string | undefined) => { if (v === undefined) m.delete(k); else m.set(k, v); },
    customDataKeys: (p: string) => [...m.keys()].filter((k) => k.startsWith(p)).sort(),
  } as unknown as KeePassVault;
}

type Call = unknown[];

async function setup() {
  const alice = await generateUserKey();
  const bob = await generateUserKey();
  const bobFingerprint = await fingerprint(bob.publicKey);
  const published: Record<string, PublishedKey> = {
    "u-bob": { userId: "u-bob", publicKey: bob.publicKey, fingerprint: bobFingerprint, createdAt: "", previous: [] },
    "u-alice": { userId: "u-alice", publicKey: alice.publicKey, fingerprint: await fingerprint(alice.publicKey), createdAt: "", previous: [] },
  };
  const calls: Call[] = [];
  const api = {
    create: async (name: string, sealedKey: string, fp: string) => { calls.push(["create", name, fp, sealedKey]); return { id: "sv_abcdefghijklmnopqrstuv" }; },
    invite: async (...a: unknown[]) => { calls.push(["invite", ...a]); },
    updateMember: async (...a: unknown[]) => { calls.push(["update", ...a]); },
    accept: async (id: string) => { calls.push(["accept", id]); },
    lookupUser: async (name: string) => (name === "bob" ? { userId: "u-bob", username: "bob", fingerprint: bobFingerprint } : null),
  } as unknown as SharedApi;
  const pinVault = fakeVault();
  let pinSaves = 0;
  const deps: FlowDeps = {
    api,
    pinVault,
    onPinChanged: () => { pinSaves++; },
    lookupKey: (v, id) => lookupKey(v, id, async (u) => published[u] ?? null),
    pinKey,
    me: { id: "u-alice", publicKey: alice.publicKey, fingerprint: published["u-alice"].fingerprint },
  };
  return { alice, bob, api, calls, deps, pinVault, published, pinSaves: () => pinSaves };
}

const invitation = (s: Awaited<ReturnType<typeof setup>>, fp?: string): SharedVaultSummary => ({
  id: "sv_abcdefghijklmnopqrstuv",
  name: "Finance",
  role: "editor",
  state: "invited",
  keyEpoch: 1,
  myKey: { sealedKey: "", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-bob", sealedByFingerprint: "" },
  invitedBy: { userId: "u-bob", username: "bob", fingerprint: fp ?? s.published["u-bob"].fingerprint },
});

test("create seals the new key to myself", async () => {
  const s = await setup();
  const { id, key } = await createSharedVault("Finance", s.deps);
  assert.equal(id, "sv_abcdefghijklmnopqrstuv");
  assert.deepEqual(s.calls[0].slice(0, 3), ["create", "Finance", s.deps.me.fingerprint]);
  assert.deepEqual([...(await openSharedKey(s.alice.seed, s.calls[0][3] as string))], [...key]);
});

test("invite pins an unknown user, seals to their key, and writes the personal vault", async () => {
  const s = await setup();
  const invitee = await resolveInvitee("bob", s.deps);
  assert.equal(invitee?.pin.state, "unknown");
  const key = crypto.getRandomValues(new Uint8Array(32));
  await inviteMember("sv_abcdefghijklmnopqrstuv", invitee!, "editor", key, s.deps);
  const [, , userId, role, sealed, fp] = s.calls.find((c) => c[0] === "invite")!;
  assert.equal(userId, "u-bob");
  assert.equal(role, "editor");
  assert.equal(fp, s.published["u-bob"].fingerprint);
  assert.deepEqual([...(await openSharedKey(s.bob.seed, sealed as string))], [...key]);
  assert.ok(readPin(s.pinVault, "u-bob"));
  assert.equal(s.pinSaves(), 1);
});

test("invite refuses a changed pin and an unknown username", async () => {
  const s = await setup();
  await pinKey(s.pinVault, "u-bob", s.alice.publicKey, () => {}); // wrong key pinned
  const invitee = await resolveInvitee("bob", s.deps);
  assert.equal(invitee?.pin.state, "changed");
  await assert.rejects(inviteMember("sv_x", invitee!, "reader", new Uint8Array(32), s.deps), /Re-pin/);
  assert.equal(await resolveInvitee("nobody", s.deps), null);
});

// The row's own verdict, as the dialog loaded it: what resealMember is handed.
const shown = (s: Awaited<ReturnType<typeof setup>>, userId: string, state: PinStatus["state"] = "unknown"): PinStatus =>
  ({ state, fingerprint: s.published[userId].fingerprint, publicKey: s.published[userId].publicKey });

test("re-seal follows the same pin rules and patches the member", async () => {
  const s = await setup();
  const key = crypto.getRandomValues(new Uint8Array(32));
  await resealMember("sv_abcdefghijklmnopqrstuv", "u-bob", shown(s, "u-bob"), key, s.deps);
  const [, vaultId, userId, patch] = s.calls.find((c) => c[0] === "update")! as [string, string, string, { sealedKey: string; keyFingerprint: string }];
  assert.equal(vaultId, "sv_abcdefghijklmnopqrstuv");
  assert.equal(userId, "u-bob");
  assert.equal(patch.keyFingerprint, s.published["u-bob"].fingerprint);
  assert.deepEqual([...(await openSharedKey(s.bob.seed, patch.sealedKey))], [...key]);

  await assert.rejects(resealMember("sv_x", "u-bob", shown(s, "u-bob", "changed"), key, s.deps), /Re-pin/);
});

test("re-seal seals the key the row displayed, not whatever is published when it is clicked", async () => {
  const s = await setup();
  const key = crypto.getRandomValues(new Uint8Array(32));
  const row = shown(s, "u-bob", "pinned");
  // bob's published key moves after the row was drawn: the seal must still go to the key
  // whose fingerprint the user was looking at.
  s.published["u-bob"] = { ...s.published["u-bob"], publicKey: s.alice.publicKey };
  await resealMember("sv_abcdefghijklmnopqrstuv", "u-bob", row, key, s.deps);
  const patch = s.calls.find((c) => c[0] === "update")![3] as { sealedKey: string; keyFingerprint: string };
  assert.deepEqual([...(await openSharedKey(s.bob.seed, patch.sealedKey))], [...key]);
});

test("re-sealing my own row uses my own key and pins nothing", async () => {
  const s = await setup();
  const key = crypto.getRandomValues(new Uint8Array(32));
  await resealMember("sv_abcdefghijklmnopqrstuv", "u-alice", shown(s, "u-alice"), key, s.deps);
  const patch = s.calls.find((c) => c[0] === "update")![3] as { sealedKey: string; keyFingerprint: string };
  assert.equal(patch.keyFingerprint, s.deps.me.fingerprint);
  assert.deepEqual([...(await openSharedKey(s.alice.seed, patch.sealedKey))], [...key]);
  assert.equal(readPin(s.pinVault, "u-alice"), null);
  assert.equal(s.pinSaves(), 0);
});

test("accept reports inviter pin status and pins on accept", async () => {
  const s = await setup();
  const row = invitation(s);
  const status = await inviterStatus(row, s.deps);
  assert.equal(status.state, "unknown");
  await acceptInvitation(row, status, s.deps);
  assert.ok(readPin(s.pinVault, "u-bob"));
  assert.deepEqual(s.calls.at(-1), ["accept", row.id]);
  assert.equal((await inviterStatus(row, s.deps)).state, "pinned");
});

test("accepting a changed key needs the dialog's confirmation", async () => {
  const s = await setup();
  const row = invitation(s);
  await pinKey(s.pinVault, "u-bob", s.alice.publicKey, () => {}); // wrong key pinned
  const before = readPin(s.pinVault, "u-bob");
  const status = await inviterStatus(row, s.deps);
  assert.equal(status.state, "changed");

  await assert.rejects(acceptInvitation(row, status, s.deps), /changed/);
  assert.deepEqual(readPin(s.pinVault, "u-bob"), before);
  assert.equal(s.calls.find((c) => c[0] === "accept"), undefined);

  await acceptInvitation(row, status, s.deps, { repinConfirmed: true });
  assert.equal(readPin(s.pinVault, "u-bob")?.fingerprint, s.published["u-bob"].fingerprint);
  assert.deepEqual(s.calls.at(-1), ["accept", row.id]);
});

test("inviting an already pinned user writes no new pin", async () => {
  const s = await setup();
  await pinKey(s.pinVault, "u-bob", s.bob.publicKey, () => {});
  const invitee = await resolveInvitee("bob", s.deps);
  assert.equal(invitee?.pin.state, "pinned");
  const key = crypto.getRandomValues(new Uint8Array(32));
  await inviteMember("sv_abcdefghijklmnopqrstuv", invitee!, "reader", key, s.deps);
  assert.equal(s.pinSaves(), 0);
  const sealed = s.calls.find((c) => c[0] === "invite")![4] as string;
  assert.deepEqual([...(await openSharedKey(s.bob.seed, sealed))], [...key]);
});

test("inviter status reports the key that signed the invitation changing", async () => {
  const s = await setup();
  const row = invitation(s, "AAAA BBBB CCCC DDDD EEEE");
  await pinKey(s.pinVault, "u-bob", s.bob.publicKey, () => {});
  const status = await inviterStatus(row, s.deps);
  assert.equal(status.state, "changed");
  assert.equal(status.drift, "invitation");
  // A pin that no longer matches the published key is the stronger warning of the two.
  await pinKey(s.pinVault, "u-bob", s.alice.publicKey, () => {});
  const stale = await inviterStatus(row, s.deps);
  assert.equal(stale.state, "changed");
  assert.equal(stale.drift, "pin");
});

test("an inviter with no published key cannot be pinned on accept", async () => {
  const s = await setup();
  const row = invitation(s);
  row.invitedBy = { userId: "u-ghost", username: "ghost", fingerprint: "AAAA BBBB CCCC DDDD EEEE" };
  const status = await inviterStatus(row, s.deps);
  assert.deepEqual(status, { state: "unknown", fingerprint: "AAAA BBBB CCCC DDDD EEEE", publicKey: new Uint8Array() });
  await acceptInvitation(row, status, s.deps);
  assert.equal(readPin(s.pinVault, "u-ghost"), null);
  assert.deepEqual(s.calls.at(-1), ["accept", row.id]);
});

test("a user with no published key cannot be invited", async () => {
  const s = await setup();
  delete s.published["u-bob"];
  await assert.rejects(resolveInvitee("bob", s.deps), /no published key/);
});
