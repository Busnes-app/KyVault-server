import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveSelection, openShared, selectionScope, selectionBase, personal, type OpenDeps } from "./vaultSelection";
import type { SharedVaultSummary } from "./sharedVaults";

const ID = "sv_abcdefghijklmnopqrstuv";
const row = (over: Partial<SharedVaultSummary> = {}): SharedVaultSummary => ({
  id: ID, name: "Finance", role: "editor", state: "active", keyEpoch: 1,
  myKey: { sealedKey: "AAAA", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" }, ...over,
});

test("resolveSelection", () => {
  assert.deepEqual(resolveSelection(undefined, [row()]), { selected: personal, notice: null });
  assert.deepEqual(resolveSelection(ID, [row()]), { selected: { kind: "shared", id: ID }, notice: null });
  assert.equal(resolveSelection(ID, [row({ state: "invited" })]).selected.kind, "personal");
  assert.match(resolveSelection(ID, [row({ state: "invited" })]).notice ?? "", /invitation/i);
  assert.match(resolveSelection("sv_zzzzzzzzzzzzzzzzzzzzzz", [row()]).notice ?? "", /not a member/i);
  assert.equal(selectionScope(personal), "personal");
  assert.equal(selectionScope({ kind: "shared", id: ID }), ID);
  assert.equal(selectionBase({ kind: "shared", id: ID }), `/api/shared/${ID}`);
});

const fakeVault = { name: "v" } as any;
const deps = (over: Partial<OpenDeps>): OpenDeps => ({
  loadCrypto: async () => {},
  openKey: async () => new Uint8Array(32),
  fetchMetadata: async () => ({ version: 3 }),
  fetchKdbx: async () => new ArrayBuffer(8),
  openVault: async () => fakeVault,
  createVault: async () => { throw new Error("should not create"); },
  upload: async () => { throw new Error("should not upload"); },
  ...over,
});

test("openShared opens an existing vault read-only for readers", async () => {
  const calls: string[] = [];
  const opened = await openShared(row({ role: "reader" }), new Uint8Array(32), deps({
    fetchKdbx: async (base) => { calls.push(base); return new ArrayBuffer(8); },
  }));
  assert.equal(opened.vault, fakeVault);
  assert.equal(opened.version, 3);
  assert.equal(opened.readOnly, true);
  assert.deepEqual(calls, [`/api/shared/${ID}`]);
  assert.equal(opened.keyEpoch, 1);
});

test("openShared creates and uploads an empty vault at version 0", async () => {
  let uploaded: [number, string, number] | null = null;
  const opened = await openShared(row(), new Uint8Array(32), deps({
    fetchMetadata: async () => ({ version: 0 }),
    createVault: async () => ({ ...fakeVault, exportBinary: async () => new ArrayBuffer(4) }),
    upload: async (_b, version, base, keyEpoch) => { uploaded = [version, base, keyEpoch]; return 1; },
  }));
  assert.deepEqual(uploaded, [0, `/api/shared/${ID}`, 1], "the first upload of an empty shared vault claims the vault's epoch too");
  assert.equal(opened.keyEpoch, 1);
  assert.equal(opened.version, 1);
  assert.equal(opened.readOnly, false);
});

test("openShared reports an unopenable key", async () => {
  await assert.rejects(openShared(row(), new Uint8Array(32), deps({ openKey: async () => { throw new Error("bad"); } })), /ask an owner to re-seal/);
});

// A lazy chunk that 404'd after a deploy is not a key anyone has to re-seal, and sending the
// user to an owner for it would be a wrong answer they cannot act on.
test("openShared tells a missing crypto chunk apart from a key that will not open", async () => {
  let opened = 0;
  await assert.rejects(openShared(row(), new Uint8Array(32), deps({
    loadCrypto: async () => { throw new Error("Failed to fetch dynamically imported module"); },
    openKey: async () => { opened++; return new Uint8Array(32); },
  })), /Reload the page and try again/);
  assert.equal(opened, 0, "nothing is unsealed before the code that unseals it has loaded");
});

test("openShared refuses to create for a reader on an empty vault", async () => {
  await assert.rejects(
    openShared(row({ role: "reader" }), new Uint8Array(32), deps({ fetchMetadata: async () => ({ version: 0 }) })),
    /empty; an owner or editor must add the first entry/,
  );
});

// A rotation leaves a member it could not seal for `stale` at the retired epoch. Their sealed
// copy still unseals — it opens the old key — so only the vault bytes would refuse it, as a raw
// kdbxweb InvalidKey. The row's state is checked first, before anything is fetched.
test("openShared refuses a row a rotation left behind before it fetches anything", async () => {
  for (const state of ["stale", "invited", "suspended"] as const) {
    let touched = 0;
    await assert.rejects(openShared(row({ state, keyEpoch: 1 }), new Uint8Array(32), deps({
      loadCrypto: async () => { touched++; },
      openKey: async () => { touched++; return new Uint8Array(32); },
      fetchMetadata: async () => { touched++; return { version: 3 }; },
      fetchKdbx: async () => { touched++; return new ArrayBuffer(8); },
    })), /ask an owner to re-seal/, state);
    assert.equal(touched, 0, `${state}: nothing was loaded, unsealed or fetched`);
  }
});
