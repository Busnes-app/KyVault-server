// Background-only owner of the open vault. The password is used once to unwrap the
// envelope and dropped; the key lives in storage.session (keyHex) and, for the length
// of one open call, in memory, where it is zeroed afterwards.
import { KeePassVault, isWrongVaultKey } from "../../../frontend/src/lib/kdbx";
import { bytesToHex, hexToBytes, unwrapVaultKeyFromEnvelopes } from "../../../frontend/src/lib/vaultCrypto";
import { isLocked, lockDeadline } from "./lock";
import { RevokedError, serverFetch, type SessionIO } from "./session";

export class LockedError extends Error {
  constructor() {
    super("The vault is locked. Unlock it with your master password.");
    this.name = "LockedError";
  }
}

export type OpenVault = { vault: KeePassVault; version: number; checksum: string };

export type VaultDeps = SessionIO & {
  session: {
    get: (keys: string[]) => Promise<Record<string, unknown>>;
    set: (items: Record<string, unknown>) => Promise<void>;
    clear: () => Promise<void>;
  };
  alarms: { create: (name: string, info: { when: number }) => unknown; clear: (name: string) => unknown };
  now?: () => number;
  unwrap?: typeof unwrapVaultKeyFromEnvelopes;
  openVault?: (bytes: ArrayBuffer, key: Uint8Array) => Promise<KeePassVault>;
};

export const LOCK_ALARM = "lock";
const EMPTY = "Create your vault in the KyVault web app first.";
const NO_ENVELOPE = "This vault has no master password yet. Set one in the KyVault web app first.";
const WRONG = "That password did not unlock the vault. Check it and try again.";
const ROTATED = "The vault key changed. Unlock with your master password again.";
const UNREADABLE = "The vault file could not be opened. Try again, or open it in the KyVault web app.";
const UNEXPECTED = "The server sent an unexpected answer. Try again later.";

const failed = (res: Response) => new Error(`The server answered ${res.status}. Try again later.`);

function parseMetadata(raw: unknown): { version: number; envelopes: string[] } {
  const m = raw as { version?: unknown; passwordEnvelope?: unknown; recoveryEnvelope?: unknown } | null;
  if (!m || typeof m !== "object" || !Number.isSafeInteger(m.version) || (m.version as number) < 0) throw new Error(UNEXPECTED);
  const envelopes = [m.passwordEnvelope, m.recoveryEnvelope].filter((e): e is string => typeof e === "string" && e !== "");
  return { version: m.version as number, envelopes };
}

export function createVaultState(deps: VaultDeps) {
  const now = deps.now ?? Date.now;
  const unwrap = deps.unwrap ?? unwrapVaultKeyFromEnvelopes;
  const openVault = deps.openVault ?? ((bytes, key) => KeePassVault.open(bytes, key));
  let open: OpenVault | undefined;
  let reopening: Promise<OpenVault> | undefined;
  // Bumped by lock(); work that started before a lock must not commit after it.
  let generation = 0;

  async function lock(): Promise<void> {
    generation++;
    open = undefined;
    reopening = undefined;
    await deps.session.clear();
    await deps.alarms.clear(LOCK_ALARM);
  }

  // Whatever fails, a revoked device holds no key afterwards.
  async function guarded<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (err) {
      if (err instanceof RevokedError) await lock();
      throw err;
    }
  }

  // Downloads and opens the current KDBX, then zeroes `key`. The version is taken from
  // this response, never from the earlier metadata call, so the two cannot disagree.
  async function download(key: Uint8Array, gen: number): Promise<OpenVault> {
    try {
      const res = await serverFetch(deps, "/api/vault/kdbx", { method: "GET" });
      if (res.status === 404) throw new Error(EMPTY);
      if (!res.ok) throw failed(res);
      const version = Number(res.headers.get("X-Vault-Version"));
      if (!Number.isSafeInteger(version) || version < 1) throw new Error(UNEXPECTED);
      const checksum = res.headers.get("X-Vault-Checksum") ?? "";
      const bytes = await res.arrayBuffer();
      let vault: KeePassVault;
      try {
        vault = await openVault(bytes, key);
      } catch (err) {
        if (!isWrongVaultKey(err)) throw new Error(UNREADABLE);
        await lock();
        throw new Error(ROTATED);
      }
      if (gen !== generation) throw new LockedError();
      return { vault, version, checksum };
    } finally {
      key.fill(0);
    }
  }

  // Writes the new deadline (and, on unlock, the key) and arms the alarm, unless a lock
  // ran meanwhile.
  async function commit(gen: number, opened: OpenVault, keyHex?: string): Promise<void> {
    const { autoLockMinutes } = await deps.settings();
    const lockAt = lockDeadline(now(), autoLockMinutes);
    await deps.session.set(keyHex ? { keyHex, lockAt } : { lockAt });
    if (gen !== generation) {
      await deps.session.clear();
      throw new LockedError();
    }
    open = opened;
    await deps.alarms.create(LOCK_ALARM, { when: lockAt });
  }

  async function unlock(password: string): Promise<void> {
    await lock();
    const gen = generation;
    return guarded(async () => {
      const res = await serverFetch(deps, "/api/vault/metadata", { method: "GET" });
      if (!res.ok) throw failed(res);
      const meta = parseMetadata(await res.json().catch(() => null));
      if (meta.version === 0) throw new Error(EMPTY);
      if (meta.envelopes.length === 0) throw new Error(NO_ENVELOPE);
      let key: Uint8Array;
      try {
        key = await unwrap(meta.envelopes, password);
      } catch {
        throw new Error(WRONG);
      }
      const keyHex = bytesToHex(key);
      await commit(gen, await download(key, gen), keyHex);
    });
  }

  // The vault for a request. After the worker was evicted this reopens it from the
  // session key: one download, one KDBX open, no password. Extends the idle deadline.
  async function ensure(): Promise<OpenVault> {
    const { keyHex, lockAt } = await deps.session.get(["keyHex", "lockAt"]);
    const { autoLockMinutes } = await deps.settings();
    if (typeof keyHex !== "string" || !/^[0-9a-f]{64}$/.test(keyHex) || typeof lockAt !== "number" || isLocked(lockAt, now(), autoLockMinutes)) {
      await lock();
      throw new LockedError();
    }
    const gen = generation;
    return guarded(async () => {
      const opened = open ?? (await (reopening ??= download(hexToBytes(keyHex), gen).finally(() => { reopening = undefined; })));
      await commit(gen, opened);
      return opened;
    });
  }

  // Also the per-message sweep: an expired deadline locks here even if the alarm was missed.
  async function status(): Promise<{ unlocked: boolean; lockAt: number | undefined }> {
    const { keyHex, lockAt } = await deps.session.get(["keyHex", "lockAt"]);
    const { autoLockMinutes } = await deps.settings();
    if (typeof keyHex === "string" && typeof lockAt === "number" && !isLocked(lockAt, now(), autoLockMinutes)) {
      return { unlocked: true, lockAt };
    }
    if (keyHex !== undefined || lockAt !== undefined || open) await lock();
    return { unlocked: false, lockAt: undefined };
  }

  return { unlock, ensure, lock, status };
}
