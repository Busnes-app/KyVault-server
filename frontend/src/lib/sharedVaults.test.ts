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

test("rotate posts the kdbx part then the keys part, versioned, with no hand-set content type", async (t) => {
  browserCookie(t);
  const calls: { url: string; method: string; ifMatch: string | null; contentType: string | null; parts: string[]; keys: string }[] = [];
  t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options: RequestInit = {}) => {
    const headers = new Headers(options.headers);
    const form = options.body as FormData;
    calls.push({
      url: String(url), method: options.method ?? "GET",
      ifMatch: headers.get("If-Match"), contentType: headers.get("Content-Type"),
      parts: [...form.keys()], keys: String(form.get("keys")),
    });
    return Response.json({ ok: true, metadata: { version: 9 }, keyEpoch: 3, leftBehind: ["u-4"], historyCleared: false });
  });
  const result = await sharedApi.rotate("sv_abcdefghijklmnopqrstuv", new Uint8Array([1, 2, 3, 4]).buffer, 2, 8,
    [{ userId: "u-2", sealedKey: "AAAA", keyFingerprint: "FFFF" }]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/shared/sv_abcdefghijklmnopqrstuv/rotate");
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].ifMatch, '"8"');
  assert.equal(calls[0].contentType, null, "the browser must supply the multipart boundary");
  assert.deepEqual(calls[0].parts, ["kdbx", "keys"], "the server reads the parts positionally");
  assert.deepEqual(JSON.parse(calls[0].keys), { epoch: 2, sealed: [{ userId: "u-2", sealedKey: "AAAA", keyFingerprint: "FFFF" }] });
  assert.deepEqual(result, { ok: true, metadata: { version: 9 }, keyEpoch: 3, leftBehind: ["u-4"], historyCleared: false });
});
