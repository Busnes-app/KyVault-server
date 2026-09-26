import { test } from "node:test";
import assert from "node:assert/strict";
import { pair } from "./pairing";

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
  await assert.rejects(pair(io({ grant: true, status: 400, body: "pairing code expired or invalid\n" }), "https://v.example", "1", "n"), /expired or invalid/);
  await assert.rejects(pair(io({ grant: true, status: 401, body: "x" }), "https://v.example", "1", "n"), /inactive or signed out/);
  await assert.rejects(pair(io({ grant: true, status: 200, body: { ok: true } }), "https://v.example", "1", "n"), /did not return a session/);
});
