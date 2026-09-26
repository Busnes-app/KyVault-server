import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { readBody, RevokedError, serverFetch } from "./session";

function io(status: number) {
  const seen: { url?: string; init?: RequestInit; forgot: number } = { forgot: 0 };
  return {
    seen,
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", autoLockMinutes: 5 as const }),
    forget: async () => { seen.forgot++; },
    fetch: async (url: string, init: RequestInit) => { seen.url = url; seen.init = init; return new Response("{}", { status }); },
  };
}

test("bearer, no cookies, no redirects", async () => {
  const fake = io(200);
  await serverFetch(fake, "/api/vault/metadata", { method: "GET" });
  assert.equal(fake.seen.url, "https://v.example/api/vault/metadata");
  assert.equal(new Headers(fake.seen.init!.headers).get("Authorization"), "Bearer tok");
  assert.equal(fake.seen.init!.credentials, "omit");
  assert.equal(fake.seen.init!.redirect, "error");
  assert.equal(fake.seen.init!.cache, "no-store");
  assert.ok(fake.seen.init!.signal instanceof AbortSignal);
  assert.equal(fake.seen.forgot, 0);
});

test("401 forgets the session and says the device was revoked", async () => {
  const fake = io(401);
  await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), RevokedError);
  await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), /This device was revoked\. Pair again from the KyVault options page\./);
  assert.equal(fake.seen.forgot, 2);
});

test("unpaired is a clear instruction, not a fetch", async () => {
  const fake = { ...io(200), settings: async () => ({ autoLockMinutes: 5 as const }) };
  await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), /Pair this extension/);
  assert.equal(fake.seen.url, undefined);
});

test("a stored origin that is not bare https is refused before any fetch", async () => {
  for (const origin of ["http://v.example", "https://v.example/evil", "https://u:p@v.example"]) {
    const fake = { ...io(200), settings: async () => ({ serverOrigin: origin, sessionToken: "tok", autoLockMinutes: 5 as const }) };
    await assert.rejects(serverFetch(fake, "/api/vault/metadata", { method: "GET" }), /Pair this extension/, origin);
    assert.equal(fake.seen.url, undefined, origin);
  }
});

test("a server that never answers times out with a sentence", async () => {
  const fake = {
    ...io(200),
    timeoutMs: 20,
    fetch: (_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener("abort", () => reject(init.signal!.reason));
    }),
  };
  await assert.rejects(serverFetch(fake, "/api/vault/kdbx", { method: "GET" }), /did not answer in time/);
});

test("a network failure or refused redirect names the server and does not forget the session", async () => {
  const fake = { ...io(200), fetch: async () => { throw new TypeError("Failed to fetch"); } };
  await assert.rejects(serverFetch(fake, "/api/vault/kdbx", { method: "GET" }), /Could not reach https:\/\/v\.example\./);
  assert.equal(fake.seen.forgot, 0);
});

// Review focus 1: key material never reaches storage.local, and session storage keeps
// its default (trusted contexts only) access level.
test("only settings.ts touches storage.local, and only vaultState.ts names the session key", () => {
  const root = join(import.meta.dirname, "..");
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const d of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, d.name);
      if (d.isDirectory()) walk(p);
      else if (p.endsWith(".ts") && !p.endsWith(".test.ts")) files.push(p);
    }
  };
  walk(root);
  const using = (needle: string) => files.filter((f) => readFileSync(f, "utf8").includes(needle)).map((f) => relative(root, f)).sort();
  assert.deepEqual(using("storage.local."), ["lib/settings.ts"]);
  assert.deepEqual(using("keyHex"), ["lib/vaultState.ts"]);
  assert.deepEqual(using("setAccessLevel"), []);
});

test("a body that stalls past the timeout is a sentence, not an AbortError", async () => {
  // A real timer, not AbortSignal.timeout: Node unrefs that timer, so on a slow runner the
  // event loop can drain before it fires and the test dies with a pending promise.
  const stalled = new ReadableStream({
    start: (c) => { setTimeout(() => c.error(new DOMException("The operation timed out.", "TimeoutError")), 10); },
  });
  await assert.rejects(readBody(new Response(stalled)), /^Error: The server did not answer in time\./);
});
