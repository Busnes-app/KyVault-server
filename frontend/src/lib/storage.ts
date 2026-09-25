// Local device vault storage for zero-knowledge KeePass vault master keys
// Enables 1-click SSO unlock on trusted devices without exposing master keys to server.

import { newWrappingKey, sealKeyHex, openKeyHex, type SealedKey } from "./deviceKey";

const DB_NAME = "kypasswords-device-vault";
const STORE_NAME = "keys";

// ponytail: the wrapping CryptoKey lives in the same "keys" store under a reserved
// username so the database version stays 1 for tabs still running the old client.
// Upgrade path: a second object store behind a version bump once every client is current.
const WRAPPING_RECORD = "\u0000device-wrapping-key";

type KeyRecord = { username: string; sealed?: SealedKey; keyHex?: string; updatedAt: string };
type WrappingRecord = { username: typeof WRAPPING_RECORD; cryptoKey: CryptoKey };

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME, { keyPath: "username" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open local key store"));
  });
}

function run<T>(db: IDBDatabase, mode: IDBTransactionMode, op: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const req = op(tx.objectStore(STORE_NAME));
    tx.oncomplete = () => resolve(req.result);
    tx.onerror = () => reject(tx.error ?? new Error("Local key store transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("Local key store transaction aborted"));
  });
}

async function wrappingKey(db: IDBDatabase): Promise<CryptoKey> {
  const existing = await run<WrappingRecord | undefined>(db, "readonly", (s) => s.get(WRAPPING_RECORD));
  if (existing?.cryptoKey) return existing.cryptoKey;
  const cryptoKey = await newWrappingKey();
  try {
    // add (not put) so a concurrent first writer fails instead of overwriting; the loser
    // re-reads and uses the winner's key so both tabs seal under the same wrapping key.
    await run(db, "readwrite", (s) => s.add({ username: WRAPPING_RECORD, cryptoKey } satisfies WrappingRecord));
    return cryptoKey;
  } catch {
    const stored = await run<WrappingRecord | undefined>(db, "readonly", (s) => s.get(WRAPPING_RECORD));
    if (!stored?.cryptoKey) throw new Error("Unable to establish the device wrapping key");
    return stored.cryptoKey;
  }
}

export async function storeDeviceVaultKey(username: string, keyHex: string): Promise<void> {
  const db = await openDatabase();
  try {
    const sealed = await sealKeyHex(await wrappingKey(db), keyHex);
    await run(db, "readwrite", (s) => s.put({ username, sealed, updatedAt: new Date().toISOString() } satisfies KeyRecord));
  } finally {
    db.close();
  }
}

export async function getDeviceVaultKey(username: string): Promise<string | undefined> {
  const db = await openDatabase();
  try {
    const record = await run<KeyRecord | undefined>(db, "readonly", (s) => s.get(username));
    // A legacy plain-hex record is deleted on sight; the next password unlock writes a sealed record.
    if (!record?.sealed) {
      await run(db, "readwrite", (s) => s.delete(username));
      return undefined;
    }
    return await openKeyHex(await wrappingKey(db), record.sealed);
  } finally {
    db.close();
  }
}

export async function clearDeviceVaultKey(username: string): Promise<void> {
  const db = await openDatabase();
  try {
    await run(db, "readwrite", (s) => s.delete(username));
  } finally {
    db.close();
  }
}
