import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "../../../frontend/src/lib/kdbx";
import { ConflictError, uploadVault } from "./save";
import { createVaultState, LockedError, type VaultDeps } from "./vaultState";

function io(status: number, body: unknown) {
  const seen: { init?: RequestInit; url?: string } = {};
  return {
    seen,
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", autoLockMinutes: 5 as const }),
    forget: async () => {},
    fetch: async (url: string, init: RequestInit) => { seen.url = url; seen.init = init; return new Response(JSON.stringify(body), { status }); },
  };
}

test("sends If-Match and the device id and returns the new version", async () => {
  const fake = io(200, { ok: true, metadata: { version: 8 } });
  assert.equal(await uploadVault(fake, new Uint8Array([1, 2]).buffer, 7, "dev-1"), 8);
  const h = new Headers(fake.seen.init!.headers);
  assert.equal(h.get("If-Match"), '"7"');
  assert.equal(h.get("X-Device-ID"), "dev-1");
  assert.equal(h.get("Content-Type"), "application/octet-stream");
  assert.equal(fake.seen.url, "https://v.example/api/vault/upload");
});

test("409 is a ConflictError and a non-advancing version is refused", async () => {
  await assert.rejects(uploadVault(io(409, { currentVersion: 9, expectedVersion: 7, conflictId: "c" }), new Uint8Array([1]).buffer, 7, "d"), ConflictError);
  await assert.rejects(uploadVault(io(200, { ok: true, metadata: { version: 7 } }), new Uint8Array([1]).buffer, 7, "d"), /did not confirm/);
  await assert.rejects(uploadVault(io(413, {}), new Uint8Array([1]).buffer, 7, "d"), /^Error: The vault is over the 50 MiB upload limit\.$/);
});

// saveLogin against a fake server holding a real KDBX.
const T0 = 1_800_000_000_000;
const KEY = new Uint8Array(32).fill(9);
const ENVELOPE = '{"kdf":"argon2id","salt":"aa"}';
const LOGIN = { title: "shop.example", username: "me@shop.example", password: "  s3cret pw ", url: "https://shop.example" };

type Upload = { url: string; init: RequestInit; body: ArrayBuffer };

async function server(opts: { uploadStatus?: number; realOpen?: boolean } = {}) {
  const seed = await KeePassVault.createNew(KEY);
  const state = { bytes: await seed.exportBinary(), version: 3, envelope: ENVELOPE, uploadStatus: opts.uploadStatus ?? 200 };
  const paths: string[] = [];
  const uploads: Upload[] = [];
  const session = new Map<string, unknown>();
  const deps: VaultDeps = {
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", deviceId: "dev-1", autoLockMinutes: 5 }),
    forget: async () => {},
    fetch: async (url, init) => {
      const path = new URL(url).pathname;
      paths.push(path);
      if (path === "/api/vault/metadata") {
        return new Response(JSON.stringify({ version: state.version, passwordEnvelope: state.envelope, recoveryEnvelope: "" }));
      }
      if (path === "/api/vault/kdbx") return new Response(state.bytes, { headers: { "X-Vault-Version": String(state.version) } });
      if (path === "/api/vault/upload") {
        const body = await new Response(init.body as ArrayBuffer).arrayBuffer();
        uploads.push({ url, init, body });
        if (state.uploadStatus === 409) return new Response(JSON.stringify({ currentVersion: 9, expectedVersion: state.version, conflictId: "c1" }), { status: 409 });
        if (state.uploadStatus !== 200) return new Response("failed to save vault", { status: state.uploadStatus });
        state.bytes = body;
        state.version++;
        return new Response(JSON.stringify({ ok: true, metadata: { version: state.version } }));
      }
      return new Response("", { status: 404 });
    },
    session: {
      get: async (keys) => Object.fromEntries(keys.filter((k) => session.has(k)).map((k) => [k, session.get(k)])),
      set: async (items) => { for (const [k, v] of Object.entries(items)) session.set(k, v); },
      clear: async () => { session.clear(); },
    },
    alarms: { create: () => {}, clear: () => true },
    now: () => T0,
    unwrap: async () => KEY.slice(),
    // A fresh parse per download, so a phantom entry can only survive in memory.
    openVault: opts.realOpen ? undefined : async (bytes) => KeePassVault.open(bytes, KEY),
  };
  return { state, paths, uploads, session, deps };
}

test("saveLogin writes one root entry, uploads it version-checked, and the bytes reopen with the key", async () => {
  const s = await server({ realOpen: true });
  const vault = createVaultState(s.deps);
  await vault.unlock("pw");
  await vault.saveLogin(LOGIN);

  assert.equal(s.uploads.length, 1);
  const { url, init, body } = s.uploads[0];
  assert.equal(url, "https://v.example/api/vault/upload");
  assert.equal(init.method, "POST");
  assert.equal(init.redirect, "error");
  assert.equal(init.credentials, "omit");
  assert.ok(init.signal);
  const h = new Headers(init.headers);
  assert.equal(h.get("If-Match"), '"3"');
  assert.equal(h.get("X-Device-ID"), "dev-1");
  assert.equal(h.get("Authorization"), "Bearer tok");
  assert.equal(h.get("Content-Type"), "application/octet-stream");
  // The rotation check reads metadata right before the upload.
  assert.deepEqual(s.paths.slice(-2), ["/api/vault/metadata", "/api/vault/upload"]);

  const reopened = await KeePassVault.open(body, KEY);
  const saved = reopened.getLiveEntries().filter((e) => e.title === LOGIN.title);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].password, LOGIN.password);
  assert.equal(saved[0].username, LOGIN.username);
  assert.equal(saved[0].url, LOGIN.url);
  assert.equal(saved[0].groupUuid, reopened.getLiveGroups()[0].uuid);
  assert.equal((await vault.ensure()).version, 4);
});

test("two saves in a row are serialised and the second sends the version the first returned", async () => {
  const s = await server();
  const vault = createVaultState(s.deps);
  await vault.unlock("pw");
  await Promise.all([vault.saveLogin(LOGIN), vault.saveLogin({ ...LOGIN, title: "other.example" })]);
  assert.deepEqual(s.uploads.map((u) => new Headers(u.init.headers).get("If-Match")), ['"3"', '"4"']);
  const titles = (await KeePassVault.open(s.state.bytes, KEY)).getLiveEntries().map((e) => e.title).sort();
  assert.deepEqual(titles, ["other.example", "shop.example"]);
});

test("409 discards the local vault and locks with the refresh sentence", async () => {
  const s = await server({ uploadStatus: 409 });
  const vault = createVaultState(s.deps);
  await vault.unlock("pw");
  await assert.rejects(vault.saveLogin(LOGIN), (err: unknown) =>
    err instanceof LockedError && /^The vault changed elsewhere\. Unlock again to refresh/.test(err.message));
  assert.equal(s.session.size, 0);
  await assert.rejects(vault.ensure(), LockedError);
});

test("any other failure leaves no phantom entry: the next request re-downloads", async () => {
  const s = await server({ uploadStatus: 500 });
  const vault = createVaultState(s.deps);
  await vault.unlock("pw");
  await assert.rejects(vault.saveLogin(LOGIN), /The server answered 500/);
  assert.ok(s.session.has("keyHex"), "a transient failure does not lock");
  const downloads = s.paths.filter((p) => p === "/api/vault/kdbx").length;
  assert.deepEqual(await vault.listEntries("shop", undefined), []);
  assert.equal(s.paths.filter((p) => p === "/api/vault/kdbx").length, downloads + 1);

  // A later save does not carry the failed entry either.
  s.state.uploadStatus = 200;
  await vault.saveLogin({ ...LOGIN, title: "later.example" });
  const reopened = await KeePassVault.open(s.uploads.at(-1)!.body, KEY);
  assert.deepEqual([...reopened.getEntries().map((e) => e.title)], ["later.example"]);
});

test("a rotated password envelope refuses before uploading and locks", async () => {
  const s = await server();
  const vault = createVaultState(s.deps);
  await vault.unlock("pw");
  s.state.envelope = '{"kdf":"argon2id","salt":"bb"}';
  await assert.rejects(vault.saveLogin(LOGIN), (err: unknown) =>
    err instanceof LockedError && /The vault key changed/.test(err.message));
  assert.equal(s.uploads.length, 0);
  assert.equal(s.session.size, 0);
});

test("the envelope survives worker eviction, and bad input is refused before anything is sent", async () => {
  const s = await server();
  await createVaultState(s.deps).unlock("pw");
  const fresh = createVaultState(s.deps); // new worker, same session storage
  for (const bad of [{ ...LOGIN, title: " " }, { ...LOGIN, password: "" }, { ...LOGIN, url: "javascript:alert(1)" }]) {
    await assert.rejects(fresh.saveLogin(bad));
  }
  assert.equal(s.uploads.length, 0);
  await fresh.saveLogin(LOGIN);
  assert.equal(s.uploads.length, 1);
});

test("an unlock waits for a save in flight, then downloads the saved vault", async () => {
  const s = await server({ realOpen: true });
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const vault = createVaultState({
    ...s.deps,
    fetch: async (url, init) => {
      if (new URL(url).pathname === "/api/vault/upload") await gate;
      return s.deps.fetch(url, init);
    },
  });
  await vault.unlock("pw");
  const save = vault.saveLogin(LOGIN);
  // Past the rotation check, with the upload held at the gate.
  while (s.paths.filter((p) => p === "/api/vault/metadata").length < 2) await new Promise((r) => setTimeout(r, 1));
  await new Promise((r) => setTimeout(r, 20));
  const before = s.paths.length;
  const unlock = vault.unlock("pw");
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(s.paths.length, before, "no request while the upload is pending");
  release();
  await save;
  await unlock;
  assert.deepEqual(s.paths.slice(before), ["/api/vault/upload", "/api/vault/metadata", "/api/vault/kdbx"]);
  const opened = await vault.ensure();
  assert.equal(opened.version, 4);
  assert.deepEqual(opened.vault.getLiveEntries().map((e) => e.title), [LOGIN.title]);
});
