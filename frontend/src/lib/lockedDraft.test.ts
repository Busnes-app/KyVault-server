import test from "node:test";
import assert from "node:assert/strict";
import { draftPointer, openDraft, sealDraft, planDraftCleanup, DRAFT_MAX_AGE_MS, type DraftMetadata } from "./lockedDraft";

test("draft pointer reads the renamed key and falls back to the legacy key", () => {
  const values = new Map([["kypassword.draft:u1", "legacy-checkpoint"]]);
  const storage = { getItem: (key: string) => values.get(key) ?? null };
  assert.equal(draftPointer(storage, "u1"), "legacy-checkpoint");
  values.set("kyvault.draft:u1", "current-checkpoint");
  assert.equal(draftPointer(storage, "u1"), "current-checkpoint");
});

test("recovery copy authenticates account, version, draft and binary with the vault key", async (t) => {
  let metadataBytes: Uint8Array | undefined;
  const encode = TextEncoder.prototype.encode;
  t.mock.method(TextEncoder.prototype, "encode", function (this: TextEncoder, input?: string) {
    const bytes = encode.call(this, input);
    if (input?.includes("secret-draft")) metadataBytes = bytes;
    return bytes;
  });
  const key = crypto.getRandomValues(new Uint8Array(32));
  const binary = new Uint8Array([1, 2, 3, 4]).buffer;
  const metadata = { version: 7, dirty: true, entry: { uuid: "entry", title: "unsaved", username: "alice", password: "secret-draft", url: "", notes: "note", totpSeed: "", groupUuid: "group",
    tags: [], expiresAt: null, favorite: false, custom: [] } };
  const sealed = await sealDraft(binary, metadata, key, "account-a");
  assert.ok(metadataBytes?.every(byte => byte === 0), "serialized password draft is wiped");
  assert.equal(new TextDecoder().decode(sealed.ciphertext).includes("secret-draft"), false);
  assert.deepEqual(await openDraft(sealed, key, "account-a"), { binary, metadata });
  await assert.rejects(openDraft(sealed, key, "account-b"));
  await assert.rejects(openDraft(sealed, new Uint8Array(32), "account-a"));
  new Uint8Array(sealed.ciphertext)[0] ^= 1;
  await assert.rejects(openDraft(sealed, key, "account-a"));
});

test("recovery storage outages resolve as degraded results rather than aborting unlock", async (t) => {
  const { readDraft, removeDraft } = await import("./lockedDraft");
  const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
    open() { throw new DOMException("Site storage denied", "SecurityError"); },
  } });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "indexedDB", previous);
    else Reflect.deleteProperty(globalThis, "indexedDB");
  });
  assert.deepEqual(await readDraft("account:checkpoint"), { kind: "unavailable" });
  assert.equal(await removeDraft("account:checkpoint"), false);
  assert.deepEqual(await readDraft(undefined), { kind: "available", draft: undefined });
});

test("a checkpoint sealed before tags/expiry/favourite/custom existed still opens, with defaults filled in", async () => {
  const key = new Uint8Array(32).fill(2);
  const binary = new Uint8Array([5, 5, 5]).buffer;
  // Pre-feature shape: no tags/expiresAt/favorite/custom on the entry. Cast past the
  // current EntryDraft type, since this is exactly the shape an old client wrote.
  const preFeatureMetadata = {
    version: 4, dirty: true,
    entry: { uuid: "entry", title: "old", username: "alice", password: "pw", url: "", notes: "", totpSeed: "", groupUuid: "group" },
  } as unknown as DraftMetadata;
  const sealed = await sealDraft(binary, preFeatureMetadata, key, "acct");
  const opened = await openDraft(sealed, key, "acct");
  assert.deepEqual(opened.metadata.entry, {
    uuid: "entry", title: "old", username: "alice", password: "pw", url: "", notes: "", totpSeed: "", groupUuid: "group",
    tags: [], expiresAt: null, favorite: false, custom: [],
  });
});

test("openDraft returns copies and does not keep the decrypted buffer", async () => {
  const key = new Uint8Array(32).fill(1);
  const binary = new Uint8Array([9, 8, 7]).buffer;
  const draft = await sealDraft(binary, { version: 3, dirty: true, entry: null }, key, "acct");
  const opened = await openDraft(draft, key, "acct");
  assert.deepEqual(new Uint8Array(opened.binary), new Uint8Array([9, 8, 7]));
  assert.equal(opened.metadata.version, 3);
  // The returned buffers are slices, so zeroing the internal plaintext cannot touch them.
  assert.notEqual(opened.binary.byteLength, 0);
});

test("cleanup plan removes old drafts of this account, keeps the current pointer and stamps legacy ones", async () => {
  const now = 1_800_000_000_000;
  const plan = planDraftCleanup([
    { id: "u1:old", sealedAt: now - DRAFT_MAX_AGE_MS - 1 },
    { id: "u1:fresh", sealedAt: now - 1000 },
    { id: "u1:legacy" },
    { id: "u1:current", sealedAt: now - DRAFT_MAX_AGE_MS * 2 },
  ], "u1:current", now);
  assert.deepEqual(plan, { remove: ["u1:old"], stamp: ["u1:legacy"] });
  const sealed = await sealDraft(new Uint8Array([1]).buffer, { version: 1, dirty: false, entry: null }, new Uint8Array(32).fill(1), "u1");
  assert.ok(typeof sealed.sealedAt === "number" && Math.abs(sealed.sealedAt - Date.now()) < 5000);
});
