import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpError } from "./api";
import { canOpen, stateLabel, SHARED_ID, sharedBase, sharedApi, type SharedVaultSummary } from "./sharedVaults";

const row = (over: Partial<SharedVaultSummary>): SharedVaultSummary => ({
  id: "sv_abcdefghijklmnopqrstuv", name: "Finance", role: "editor", state: "active", keyEpoch: 1,
  myKey: { sealedKey: "", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" }, ...over,
});

test("only active rows open", () => {
  assert.equal(canOpen(row({})), true);
  assert.equal(canOpen(row({ state: "invited" })), false);
  assert.equal(canOpen(row({ state: "stale" })), false);
  assert.equal(canOpen(row({ state: "suspended" })), false);
});

test("state labels", () => {
  assert.equal(stateLabel(row({})), null);
  assert.equal(stateLabel(row({ role: "reader" })), "Read-only");
  assert.equal(stateLabel(row({ state: "invited" })), "Invitation");
  assert.equal(stateLabel(row({ state: "stale" })), "Key changed");
});

test("id pattern and base path", () => {
  assert.equal(SHARED_ID.test("sv_abcdefghijklmnopqrstuv"), true);
  assert.equal(SHARED_ID.test("sv_../x"), false);
  assert.equal(SHARED_ID.test("u-1"), false);
  assert.equal(sharedBase("sv_abcdefghijklmnopqrstuv"), "/api/shared/sv_abcdefghijklmnopqrstuv");
});

// Browser cookie input only; sharedApi.lookupUser exercises the real fetch wrapper.
function browserCookie(t: import("node:test").TestContext) {
  Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
  t.after(() => { Reflect.deleteProperty(globalThis, "document"); });
}

test("lookupUser returns null on 404", async (t) => {
  browserCookie(t);
  t.mock.method(globalThis, "fetch", async () => new Response("not found", { status: 404, statusText: "Not Found" }));
  assert.equal(await sharedApi.lookupUser("nope"), null);
});

test("lookupUser returns the parsed result on 200", async (t) => {
  browserCookie(t);
  const body = { userId: "u-2", username: "alice", fingerprint: "ABCD1234" };
  t.mock.method(globalThis, "fetch", async () => Response.json(body));
  assert.deepEqual(await sharedApi.lookupUser("alice"), body);
});

test("lookupUser rejects with HttpError on 500", async (t) => {
  browserCookie(t);
  t.mock.method(globalThis, "fetch", async () => new Response("boom", { status: 500, statusText: "Internal Server Error" }));
  await assert.rejects(() => sharedApi.lookupUser("alice"), HttpError);
});
