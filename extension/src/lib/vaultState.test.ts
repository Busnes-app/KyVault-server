import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { KeePassVault } from "../../../frontend/src/lib/kdbx";
import { bytesToHex, wrapVaultKey } from "../../../frontend/src/lib/vaultCrypto";
import { createVaultState, LockedError, type VaultDeps } from "./vaultState";
import { RevokedError } from "./session";

// The same kdbxweb instance kdbx.ts loads, so isWrongVaultKey recognises the error.
const { KdbxError, Consts } = createRequire(new URL("../../../frontend/src/lib/kdbx.ts", import.meta.url))("kdbxweb");
const T0 = 1_800_000_000_000;
const KEY = new Uint8Array(32).fill(7);

type Serve = { meta?: unknown; metaStatus?: number; kdbx?: ArrayBuffer; kdbxStatus?: number; version?: string };

function fakes(serve: Serve, session = new Map<string, unknown>()) {
  const log = { paths: [] as string[], forgot: 0, alarms: [] as Array<[string, number]>, cleared: 0, localWrites: 0 };
  let now = T0;
  const deps: VaultDeps = {
    settings: async () => ({ serverOrigin: "https://v.example", sessionToken: "tok", deviceId: "d1", autoLockMinutes: 5 }),
    forget: async () => { log.forgot++; },
    fetch: async (url: string) => {
      const path = new URL(url).pathname;
      log.paths.push(path);
      if (path === "/api/vault/metadata") return new Response(JSON.stringify(serve.meta), { status: serve.metaStatus ?? 200 });
      if (path === "/api/vault/kdbx") {
        return new Response(serve.kdbx ?? "vault does not exist yet\n", {
          status: serve.kdbxStatus ?? 200,
          headers: { "X-Vault-Version": serve.version ?? "3", "X-Vault-Checksum": "abc", ETag: `"${serve.version ?? "3"}"` },
        });
      }
      return new Response("", { status: 404 });
    },
    session: {
      get: async (keys) => Object.fromEntries(keys.filter((k) => session.has(k)).map((k) => [k, session.get(k)])),
      set: async (items) => { for (const [k, v] of Object.entries(items)) session.set(k, v); },
      clear: async () => { session.clear(); log.cleared++; },
    },
    alarms: {
      create: (name, info) => { log.alarms.push([name, info.when]); },
      clear: async () => true,
    },
    now: () => now,
  };
  return { deps, session, log, setNow: (t: number) => { now = t; } };
}

const META = { version: 3, checksum: "abc", passwordEnvelope: "{}", recoveryEnvelope: "" };
const fakeUnwrap = (ok = true) => async (_env: Array<string | undefined>, password: string) => {
  if (!ok || password !== "pw") throw new Error("Incorrect master password or paper code");
  return KEY.slice();
};
const fakeOpen = (seen: Uint8Array[] = []) => async (_bytes: ArrayBuffer, key: Uint8Array) => {
  seen.push(key);
  return {} as KeePassVault;
};

// The one real crypto round trip: Argon2id envelope, Argon2d KDBX, hex credential.
test("unlock opens a real vault, and a fresh worker reopens it from the session key without the password", async () => {
  const vault = await KeePassVault.createNew(KEY);
  vault.createEntry({ title: "Mail", username: "me", password: "hunter2", url: "https://mail.example", notes: "", groupUuid: "" });
  const bytes = await vault.exportBinary();
  const envelope = await wrapVaultKey(KEY, "correct horse");
  const f = fakes({ meta: { ...META, passwordEnvelope: envelope }, kdbx: bytes, version: "3" });

  await createVaultState(f.deps).unlock("correct horse");
  assert.deepEqual(f.log.paths, ["/api/vault/metadata", "/api/vault/kdbx"]);
  assert.equal(f.session.get("keyHex"), bytesToHex(KEY));
  assert.equal(f.session.get("lockAt"), T0 + 5 * 60_000);
  assert.deepEqual(f.log.alarms, [["lock", T0 + 5 * 60_000]]);

  // Worker evicted: new state object, same session storage, no password.
  const g = fakes({ meta: META, kdbx: bytes, version: "3" }, f.session);
  g.setNow(T0 + 60_000);
  const reopened = await createVaultState({ ...g.deps, unwrap: fakeUnwrap(false) }).ensure();
  assert.deepEqual(g.log.paths, ["/api/vault/kdbx"]);
  assert.equal(reopened.version, 3);
  assert.equal(reopened.vault.getLiveEntries()[0].password, "hunter2");
  assert.equal(f.session.get("lockAt"), T0 + 6 * 60_000);
});

test("wrong password is a sentence and leaves nothing behind", async () => {
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8) });
  const state = createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: fakeOpen() });
  await assert.rejects(state.unlock("nope"), /^Error: That password did not unlock the vault\. Check it and try again\.$/);
  assert.equal(f.session.size, 0);
  assert.deepEqual(f.log.alarms, []);
  assert.deepEqual(f.log.paths, ["/api/vault/metadata"]);
});

test("an empty vault points at the web app", async () => {
  const opts = { unwrap: fakeUnwrap(), openVault: fakeOpen() };
  const f = fakes({ meta: { version: 0, checksum: "" } });
  await assert.rejects(createVaultState({ ...f.deps, ...opts }).unlock("pw"), /Create your vault in the KyVault web app first\./);
  const g = fakes({ meta: META, kdbxStatus: 404 });
  await assert.rejects(createVaultState({ ...g.deps, ...opts }).unlock("pw"), /Create your vault in the KyVault web app first\./);
  assert.equal(g.session.size, 0);
});

test("the version comes from the kdbx response, and a missing one is refused", async () => {
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8), version: "9" });
  const state = createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: fakeOpen() });
  await state.unlock("pw");
  assert.equal((await state.ensure()).version, 9);
  const g = fakes({ meta: META, kdbx: new ArrayBuffer(8), version: "" });
  await assert.rejects(createVaultState({ ...g.deps, unwrap: fakeUnwrap(), openVault: fakeOpen() }).unlock("pw"), /unexpected answer/);
  assert.equal(g.session.size, 0);
});

test("InvalidKey after a good unwrap means the key was rotated: say so and lock", async () => {
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8) });
  const rotated = async () => { throw new KdbxError(Consts.ErrorCodes.InvalidKey); };
  await assert.rejects(
    createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: rotated }).unlock("pw"),
    /The vault key changed\. Unlock with your master password again\./,
  );
  assert.equal(f.session.size, 0);

  // Same on the reopen path after eviction: the stored key is dropped.
  f.session.set("keyHex", bytesToHex(KEY)).set("lockAt", T0 + 60_000);
  await assert.rejects(createVaultState({ ...f.deps, openVault: rotated }).ensure(), /The vault key changed/);
  assert.equal(f.session.size, 0);
});

test("401 anywhere forgets the pairing and locks", async () => {
  const f = fakes({ meta: META, metaStatus: 401 });
  await assert.rejects(createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: fakeOpen() }).unlock("pw"), RevokedError);
  assert.equal(f.log.forgot, 1);

  const g = fakes({ meta: META, kdbxStatus: 401 });
  g.session.set("keyHex", bytesToHex(KEY)).set("lockAt", T0 + 60_000);
  await assert.rejects(createVaultState({ ...g.deps, openVault: fakeOpen() }).ensure(), RevokedError);
  assert.equal(g.log.forgot, 1);
  assert.equal(g.session.size, 0);
});

test("idle deadline: activity extends it, expiry and a backwards clock lock", async () => {
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8) });
  const state = createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: fakeOpen() });
  await state.unlock("pw");
  f.setNow(T0 + 4 * 60_000);
  await state.ensure();
  assert.equal(f.session.get("lockAt"), T0 + 9 * 60_000);
  assert.deepEqual(await state.status(), { unlocked: true, lockAt: T0 + 9 * 60_000 });

  f.setNow(T0 + 9 * 60_000);
  assert.deepEqual(await state.status(), { unlocked: false, lockAt: undefined });
  await assert.rejects(state.ensure(), LockedError);
  assert.equal(f.session.size, 0);

  await state.unlock("pw");
  f.setNow(T0 - 60 * 60_000); // clock jumped back an hour
  await assert.rejects(state.ensure(), LockedError);
  assert.equal(f.session.size, 0);
});

test("the in-memory key is zeroed once the vault is open", async () => {
  const seen: Uint8Array[] = [];
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8) });
  await createVaultState({ ...f.deps, unwrap: fakeUnwrap(), openVault: fakeOpen(seen) }).unlock("pw");
  await createVaultState({ ...f.deps, openVault: fakeOpen(seen) }).ensure();
  assert.equal(seen.length, 2);
  for (const key of seen) assert.ok(key.every((b) => b === 0));
  assert.equal(f.session.get("keyHex"), bytesToHex(KEY));
});

test("a lock during an unlock in flight wins", async () => {
  const f = fakes({ meta: META, kdbx: new ArrayBuffer(8) });
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const state = createVaultState({
    ...f.deps,
    unwrap: fakeUnwrap(),
    openVault: async () => { await gate; return {} as KeePassVault; },
  });
  const pending = state.unlock("pw");
  await new Promise((r) => setTimeout(r, 5));
  await state.lock();
  release();
  await assert.rejects(pending, LockedError);
  assert.equal(f.session.size, 0);
  await assert.rejects(state.ensure(), LockedError);
});
