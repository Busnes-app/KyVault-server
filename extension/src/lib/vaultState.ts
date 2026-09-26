// Background-only owner of the open vault. The password is used once to unwrap the
// envelope and dropped; the key lives in storage.session (keyHex) and, for the length
// of one open call, in memory, where it is zeroed afterwards.
import { KeePassVault, isWrongVaultKey } from "../../../frontend/src/lib/kdbx";
import { bytesToHex, hexToBytes, unwrapVaultKey } from "../../../frontend/src/lib/vaultCrypto";
import { entryMatches } from "../../../frontend/src/lib/entryMeta";
import { findReusedPasswords } from "../../../frontend/src/lib/passwordReuse";
import { generateTOTP } from "../../../frontend/src/lib/totp";
import { isLocked, lockDeadline } from "./lock";
import { rankEntries, type EntryView } from "./rank";
import { readBody, RevokedError, serverFetch, type SessionIO } from "./session";

export type SecretField = "username" | "password" | "totp";

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
  // One envelope. Throws a DOMException "OperationError" (AES-GCM) for a wrong password.
  unwrap?: typeof unwrapVaultKey;
  openVault?: (bytes: ArrayBuffer, key: Uint8Array) => Promise<KeePassVault>;
};

export const LOCK_ALARM = "lock";
const EMPTY = "Create your vault in the KyVault web app first.";
const NO_ENVELOPE = "This vault has no master password yet. Set one in the KyVault web app first.";
const WRONG = "That password did not unlock the vault. Check it and try again.";
const ROTATED = "The vault key changed. Unlock with your master password again.";
const UNREADABLE = "The vault file could not be opened. Try again, or open it in the KyVault web app.";
const CORRUPT = "The stored key envelope could not be read. Unlock in the KyVault web app to check the vault.";
const UNEXPECTED = "The server sent an unexpected answer. Try again later.";

const failed = (res: Response) => new Error(`The server answered ${res.status}. Try again later.`);

const HEX = /^(?:[0-9a-f]{2})+$/;
const positiveInt = (v: unknown) => Number.isSafeInteger(v) && (v as number) > 0;

// unwrapVaultKey reads an unknown kdf as PBKDF2 and garbage as a failed decrypt; check
// the shape first so a broken envelope is not reported as a wrong password.
async function unwrapChecked(envelopeJSON: string, password: string): Promise<Uint8Array> {
  const e = JSON.parse(envelopeJSON) as Record<string, unknown> | null;
  const hex = (v: unknown) => typeof v === "string" && HEX.test(v);
  const params =
    e?.kdf === "argon2id" ? positiveInt(e.memoryKiB) && positiveInt(e.iterations) && positiveInt(e.parallelism)
    : e?.kdf === undefined ? e?.iterations === undefined || positiveInt(e.iterations)
    : false;
  if (!e || typeof e !== "object" || !params || !hex(e.salt) || !hex(e.iv) || !hex(e.ciphertext)) throw new Error("malformed envelope");
  return unwrapVaultKey(envelopeJSON, password);
}

const isWrongPassword = (err: unknown) => err instanceof DOMException && err.name === "OperationError";

function parseMetadata(raw: unknown): { version: number; envelopes: string[] } {
  const m = raw as { version?: unknown; passwordEnvelope?: unknown; recoveryEnvelope?: unknown } | null;
  if (!m || typeof m !== "object" || !Number.isSafeInteger(m.version) || (m.version as number) < 0) throw new Error(UNEXPECTED);
  const envelopes = [m.passwordEnvelope, m.recoveryEnvelope].filter((e): e is string => typeof e === "string" && e !== "");
  return { version: m.version as number, envelopes };
}

export function createVaultState(deps: VaultDeps) {
  const now = deps.now ?? Date.now;
  const unwrap = deps.unwrap ?? unwrapChecked;
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
      const bytes = await readBody(res);
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
      const text = new TextDecoder().decode(await readBody(res));
      let raw: unknown = null;
      try { raw = JSON.parse(text); } catch { /* parseMetadata refuses null */ }
      const meta = parseMetadata(raw);
      if (meta.version === 0) throw new Error(EMPTY);
      if (meta.envelopes.length === 0) throw new Error(NO_ENVELOPE);
      // The password or the paper code; each has its own envelope. A malformed envelope
      // wins over a wrong password, since retyping cannot fix it.
      let key: Uint8Array | undefined;
      let malformed = false;
      for (const envelope of meta.envelopes) {
        try {
          key = await unwrap(envelope, password);
          break;
        } catch (err) {
          if (!isWrongPassword(err)) malformed = true;
        }
      }
      if (!key) throw new Error(malformed ? CORRUPT : WRONG);
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

  // Entries ranked for the popup, never the password or TOTP seed. Also extends the
  // idle deadline: this is the popup's own activity.
  async function listEntries(query: string, tabHost: string | undefined): Promise<EntryView[]> {
    const { vault } = await ensure();
    const reused = findReusedPasswords(vault);
    const entries = vault.getLiveEntries();
    const byUuid = new Map(entries.map((e) => [e.uuid, e]));
    const views: EntryView[] = entries.map((e) => ({
      uuid: e.uuid,
      title: e.title,
      username: e.username,
      url: e.url,
      hasPassword: e.password !== "",
      hasTotp: Boolean(e.totpSeed),
      reused: reused.get(e.uuid) ?? 0,
    }));
    return rankEntries(views, tabHost, query, (view, q) => entryMatches(byUuid.get(view.uuid)!, q));
  }

  // One secret field, generated on demand. The popup writes the clipboard; this never does.
  async function secret(uuid: string, field: SecretField): Promise<string> {
    const { vault } = await ensure();
    const entry = vault.getLiveEntries().find((e) => e.uuid === uuid);
    if (!entry) throw new Error("That entry no longer exists.");
    if (field === "username") return entry.username;
    if (field === "password") return entry.password;
    if (!entry.totpSeed) throw new Error("This entry has no TOTP code.");
    return (await generateTOTP(entry.totpSeed)).code;
  }

  // The fill payload for one entry; the background hands it only to fillTab.
  async function login(uuid: string): Promise<{ url: string; username: string; password: string }> {
    const { vault } = await ensure();
    const entry = vault.getLiveEntries().find((e) => e.uuid === uuid);
    if (!entry) throw new Error("That entry no longer exists.");
    return { url: entry.url, username: entry.username, password: entry.password };
  }

  return { unlock, ensure, lock, status, listEntries, secret, login };
}
