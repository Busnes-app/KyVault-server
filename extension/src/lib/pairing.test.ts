import { test } from "node:test";
import assert from "node:assert/strict";
import { browserPairIO, pair } from "./pairing";
import { hostPattern } from "./pairing";

function io(opts: { grant: boolean; status: number; body: unknown }) {
  const calls: { origins?: string[]; url?: string; init?: RequestInit } = {};
  return {
    calls,
    requestHost: async (pattern: string) => { calls.origins = [pattern]; return opts.grant; },
    fetch: async (url: string, init: RequestInit) => {
      calls.url = url; calls.init = init;
      return new Response(typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body), { status: opts.status });
    },
  };
}

test("requests exactly the server origin and posts platform extension", async () => {
  const fake = io({ grant: true, status: 200, body: { ok: true, deviceId: "d1", sessionToken: "t1", user: { id: "u1" } } });
  const got = await pair(fake, "https://vault.example.com", "123456", "Work laptop");
  assert.deepEqual(got, { deviceId: "d1", sessionToken: "t1" });
  assert.deepEqual(fake.calls.origins, ["https://vault.example.com/*"]);
  assert.equal(fake.calls.url, "https://vault.example.com/api/devices/pairing/redeem");
  assert.deepEqual(JSON.parse(fake.calls.init!.body as string), { codeOrPin: "123456", deviceName: "Work laptop", platform: "extension" });
  assert.equal(fake.calls.init!.credentials, "omit");
  assert.equal(fake.calls.init!.redirect, "error");
});

test("denied permission, expired code and inactive account are distinct messages", async () => {
  await assert.rejects(pair(io({ grant: false, status: 200, body: {} }), "https://v.example", "1", "n"), /needs access/);
  await assert.rejects(pair(io({ grant: true, status: 400, body: "pairing code expired or invalid\n" }), "https://v.example", "1", "n"), /wrong or has expired/);
  await assert.rejects(pair(io({ grant: true, status: 401, body: "x" }), "https://v.example", "1", "n"), /inactive or signed out/);
  await assert.rejects(pair(io({ grant: true, status: 429, body: "x" }), "https://v.example", "1", "n"), /too many attempts/i);
  await assert.rejects(pair(io({ grant: true, status: 200, body: { ok: true } }), "https://v.example", "1", "n"), /did not return a session/);
});

test("network failure and bad device names are refused before the request completes", async () => {
  const failing = io({ grant: true, status: 200, body: {} });
  failing.fetch = () => Promise.reject(new Error("network down"));
  await assert.rejects(pair(failing, "https://v.example", "1", "n"), /could not reach https:\/\/v\.example/i);

  await assert.rejects(pair(io({ grant: true, status: 200, body: {} }), "https://v.example", "1", ""), /1 to 64 characters/);
  await assert.rejects(pair(io({ grant: true, status: 200, body: {} }), "https://v.example", "1", "a".repeat(65)), /1 to 64 characters/);
  await assert.rejects(pair(io({ grant: true, status: 200, body: {} }), "https://v.example", "1", "bad\u0000name"), /1 to 64 characters/);
});

// The browser's fetch throws "Illegal invocation" unless called with this = the global.
test("the options page's io calls fetch unbound", async () => {
  const strictFetch = function (this: unknown) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return Promise.resolve(new Response(JSON.stringify({ deviceId: "d1", sessionToken: "t1" }), { status: 200 }));
  } as unknown as typeof fetch;
  const got = await pair(browserPairIO(async () => true, strictFetch), "https://v.example", "1", "n");
  assert.deepEqual(got, { deviceId: "d1", sessionToken: "t1" });
});

test("the host permission pattern drops the port, which Firefox patterns never match", () => {
  assert.equal(hostPattern("https://localhost:5443"), "https://localhost/*");
  assert.equal(hostPattern("https://vault.example.com"), "https://vault.example.com/*");
  assert.equal(hostPattern("https://[::1]:8443"), "https://[::1]/*");
});
