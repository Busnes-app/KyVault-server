import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { unwrapVaultKey } from "./vaultCrypto";
import { rotateVaultKey, rotateAndUpload, revokeDevices, RotationUnconfirmedError, uploadRotatedVault } from "./keyRotation";
import { generatePaperCode } from "./paperCode";
import { HttpError } from "./api";

const PASSWORD = "correct horse battery staple";

async function vaultWithEntry(key: Uint8Array) {
  const vault = await KeePassVault.createNew(key);
  const root = vault.getLiveGroups()[0].uuid;
  const entry = vault.createEntry({ title: "Keep me", username: "u", password: "p", url: "", notes: "", groupUuid: root, tags: [], favorite: false, custom: [] });
  return { vault, entry };
}

test("rotation re-encrypts under a fresh key and wraps it for the password and paper code", async () => {
  const oldKey = new Uint8Array(32).fill(6);
  const { vault, entry } = await vaultWithEntry(oldKey);
  const code = generatePaperCode();
  assert.match(code, /^KYPASS(-[A-HJ-NP-Z2-9]{4}){4}$/);
  const r = await rotateVaultKey(vault, PASSWORD, code);
  assert.equal(r.key.length, 32);
  assert.notDeepEqual([...r.key], [...oldKey]);
  const reopened = await KeePassVault.open(r.binary, r.key);
  assert.ok(reopened.getLiveEntries().some((x) => x.uuid === entry.uuid));
  await assert.rejects(KeePassVault.open(r.binary, oldKey), /key/i);
  assert.deepEqual([...await unwrapVaultKey(r.passwordEnvelope, PASSWORD)], [...r.key]);
  assert.deepEqual([...await unwrapVaultKey(r.recoveryEnvelope, code)], [...r.key]);
  // The live vault object now saves under the new key; rekey back restores the old one.
  vault.rekey(oldKey);
  assert.ok(await KeePassVault.open(await vault.exportBinary(), oldKey));
});

test("rotation sends the KDBX and both envelopes in one upload and restores the old key when it fails", async () => {
  const oldKey = new Uint8Array(32).fill(7);
  const { vault, entry } = await vaultWithEntry(oldKey);
  const code = generatePaperCode();
  const calls: Array<{ binary: ArrayBuffer; pw: string; rec: string }> = [];
  let metadataReads = 0;
  const refused = rotateAndUpload(vault, oldKey, PASSWORD, code, 2, {
    upload: async (binary, pw, rec) => { calls.push({ binary, pw, rec }); throw new HttpError(409, "conflict"); },
    metadata: async () => { metadataReads++; return {}; },
  });
  await assert.rejects(refused, /409/);
  assert.equal(calls.length, 1, "exactly one upload request carries the rotation");
  assert.ok(calls[0].pw && calls[0].rec, "both envelopes ride on the upload");
  assert.equal(metadataReads, 0, "a server answer means nothing was written; no reconcile needed");
  const afterFailure = await KeePassVault.open(await vault.exportBinary(), oldKey);
  assert.ok(afterFailure.getLiveEntries().some((x) => x.uuid === entry.uuid), "the live vault is back on the old key");

  const sent: Array<{ pw: string; rec: string }> = [];
  const done = await rotateAndUpload(vault, oldKey, PASSWORD, code, 2, {
    upload: async (_binary, pw, rec) => { sent.push({ pw, rec }); return 9; },
    metadata: async () => { throw new Error("not consulted on success"); },
  });
  assert.equal(done.version, 9);
  assert.equal(done.passwordEnvelope, sent[0].pw);
  assert.equal(sent.length, 1);
  assert.deepEqual([...await unwrapVaultKey(sent[0].pw, PASSWORD)], [...done.key]);
  assert.deepEqual([...await unwrapVaultKey(sent[0].rec, code)], [...done.key]);
  assert.ok(await KeePassVault.open(await vault.exportBinary(), done.key), "the live vault saves under the new key");
});

test("a lost upload response is reconciled against the stored envelopes", async () => {
  const oldKey = new Uint8Array(32).fill(8);
  const { vault } = await vaultWithEntry(oldKey);
  const code = generatePaperCode();
  // The server wrote the rotation, then the connection dropped before the answer arrived.
  let stored: { version: number; passwordEnvelope?: string; recoveryEnvelope?: string } = { version: 3 };
  const landed = await rotateAndUpload(vault, oldKey, PASSWORD, code, 3, {
    upload: async (_b, pw, rec) => { stored = { version: 4, passwordEnvelope: pw, recoveryEnvelope: rec }; throw new TypeError("Failed to fetch"); },
    metadata: async () => stored,
  });
  assert.equal(landed.version, 4);
  assert.equal(landed.passwordEnvelope, stored.passwordEnvelope);
  assert.ok(await KeePassVault.open(await vault.exportBinary(), landed.key));

  // Our envelopes landed, but another tab has saved on top since: adopting that later version
  // would let this tab overwrite that save without a 409, so the caller must lock instead.
  const beforeLater = landed.key;
  await assert.rejects(rotateAndUpload(vault, beforeLater, PASSWORD, code, 4, {
    upload: async (_b, pw, rec) => { stored = { version: 6, passwordEnvelope: pw, recoveryEnvelope: rec }; throw new TypeError("Failed to fetch"); },
    metadata: async () => stored,
  }), RotationUnconfirmedError);

  // The request never arrived: the stored envelopes are not ours, so the old key comes back.
  const currentKey = landed.key;
  stored = { version: 4 };
  await assert.rejects(rotateAndUpload(vault, currentKey, PASSWORD, code, 4, {
    upload: async () => { throw new TypeError("Failed to fetch"); },
    metadata: async () => stored,
  }), /Failed to fetch/);
  assert.ok(await KeePassVault.open(await vault.exportBinary(), currentKey));

  // Neither the answer nor the metadata arrived: the caller is told to lock, not to carry on.
  await assert.rejects(rotateAndUpload(vault, currentKey, PASSWORD, code, 4, {
    upload: async () => { throw new TypeError("Failed to fetch"); },
    metadata: async () => { throw new TypeError("Failed to fetch"); },
  }), RotationUnconfirmedError);
});

test("device revocation is best effort, idempotent and treats 404 as done", async () => {
  const seen: string[] = [];
  const failed = await revokeDevices(["a", "b", "c"], async (id) => {
    seen.push(id);
    if (id === "b") throw new HttpError(404, "device not found");
    if (id === "c") throw new TypeError("Failed to fetch");
  });
  assert.deepEqual(seen, ["a", "b", "c"], "one failure does not stop the rest");
  assert.deepEqual(failed, ["c"]);
});

test("the rotation upload carries both envelopes and the key-rotated flag in one request", async (t) => {
  Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "csrf_token=test-csrf" } });
  t.after(() => { Reflect.deleteProperty(globalThis, "document"); });
  const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({ metadata: { version: 8 } }));
  assert.equal(await uploadRotatedVault(new ArrayBuffer(4), 7, "pw-env", "rec-env"), 8);
  assert.equal(fetch.mock.callCount(), 1);
  const [url, options] = fetch.mock.calls[0].arguments as [string, RequestInit];
  const headers = new Headers(options.headers);
  assert.equal(url, "/api/vault/upload");
  assert.equal(headers.get("X-Vault-Key-Rotated"), "1");
  assert.equal(headers.get("If-Match"), '"7"');
  assert.equal(headers.get("X-Password-Envelope"), "pw-env");
  assert.equal(headers.get("X-Recovery-Envelope"), "rec-env");
});
