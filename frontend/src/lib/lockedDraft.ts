import type { CustomField } from "./kdbx";

// A per-tab encrypted checkpoint of the vault bytes and unapplied entry fields (which can
// include an entry password). It never contains the master password or the vault key.
export type EntryDraft = {
  uuid: string; title: string; username: string; password: string;
  url: string; notes: string; totpSeed: string; groupUuid: string;
  tags: string[]; expiresAt: string | null; favorite: boolean; custom: CustomField[];
};
export type DraftMetadata = { version: number; dirty: boolean; entry: EntryDraft | null };
export type LockedDraft = { iv: Uint8Array<ArrayBuffer>; ciphertext: ArrayBuffer; sealedAt?: number };

export const DRAFT_MAX_AGE_MS = 7 * 86_400_000;

export function draftPointer(storage: Pick<Storage, "getItem">, userId: string): string | undefined {
  return storage.getItem(`kyvault.draft:${userId}`) ?? storage.getItem(`kypassword.draft:${userId}`) ?? undefined;
}

export async function sealDraft(binary: ArrayBuffer, metadata: DraftMetadata, key: Uint8Array, account: string): Promise<LockedDraft> {
  const json = new TextEncoder().encode(JSON.stringify(metadata));
  const plain = new Uint8Array(4 + json.length + binary.byteLength);
  new DataView(plain.buffer).setUint32(0, json.length);
  plain.set(json, 4);
  json.fill(0);
  plain.set(new Uint8Array(binary), 4 + json.length);
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(account) }, cryptoKey, plain);
    return { iv, ciphertext, sealedAt: Date.now() };
  } finally { plain.fill(0); }
}

export async function openDraft(draft: LockedDraft, key: Uint8Array, account: string): Promise<{ binary: ArrayBuffer; metadata: DraftMetadata }> {
  const cryptoKey = await crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: draft.iv, additionalData: new TextEncoder().encode(account) }, cryptoKey, draft.ciphertext);
  try {
    const length = new DataView(plain).getUint32(0);
    if (length > plain.byteLength - 4) throw new Error("Invalid recovery copy");
    const metadata: unknown = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + length)));
    if (typeof metadata !== "object" || metadata === null || !("version" in metadata) || typeof metadata.version !== "number" ||
        !Number.isSafeInteger(metadata.version) || metadata.version < 1 || !("dirty" in metadata) || typeof metadata.dirty !== "boolean" ||
        !("entry" in metadata) || !isEntryDraft(metadata.entry)) throw new Error("Invalid recovery copy");
    // Checkpoints sealed before tags/expiry/favourite/custom existed omit those fields;
    // fill defaults so an old checkpoint still opens instead of failing unlock outright.
    const entry: EntryDraft | null = metadata.entry ? {
      ...metadata.entry,
      tags: metadata.entry.tags ?? [],
      expiresAt: metadata.entry.expiresAt ?? null,
      favorite: metadata.entry.favorite ?? false,
      custom: metadata.entry.custom ?? [],
    } : null;
    return { binary: plain.slice(4 + length), metadata: { version: metadata.version, dirty: metadata.dirty, entry } };
  } finally { new Uint8Array(plain).fill(0); }
}

function isCustomField(value: unknown): value is CustomField {
  return typeof value === "object" && value !== null && "name" in value && typeof value.name === "string" &&
    "value" in value && typeof value.value === "string" && "protected" in value && typeof value.protected === "boolean";
}

// Checkpoints sealed before tags/expiry/favourite/custom fields existed have none of
// them; accept a draft either without a field entirely or with a validly-typed one so
// pre-feature checkpoints still open (openDraft fills in the missing defaults).
function isEntryDraft(value: unknown): value is EntryDraft | null {
  if (value === null) return true;
  return typeof value === "object" && "uuid" in value && typeof value.uuid === "string" &&
    "title" in value && typeof value.title === "string" && "username" in value && typeof value.username === "string" &&
    "password" in value && typeof value.password === "string" && "url" in value && typeof value.url === "string" &&
    "notes" in value && typeof value.notes === "string" && "totpSeed" in value && typeof value.totpSeed === "string" &&
    "groupUuid" in value && typeof value.groupUuid === "string" &&
    (!("tags" in value) || (Array.isArray(value.tags) && value.tags.every((t) => typeof t === "string"))) &&
    (!("expiresAt" in value) || value.expiresAt === null || typeof value.expiresAt === "string") &&
    (!("favorite" in value) || typeof value.favorite === "boolean") &&
    (!("custom" in value) || (Array.isArray(value.custom) && value.custom.every(isCustomField)));
}

// fn runs synchronously against the store; its return value (typically an IDBRequest,
// read via a callback once the transaction completes) becomes the resolved value.
async function withDraftStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore, resolve: (value: T) => void) => void): Promise<T> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("kypassword-locked-drafts", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("drafts");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction("drafts", mode);
      let result: T;
      try { fn(tx.objectStore("drafts"), (value) => { result = value; }); } catch (err) { reject(err); return; }
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(tx.error ?? new Error("Recovery storage failed"));
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}

// Separate database preserves compatibility with older clients opening the device-key DB.
export async function draftStore(id: string, operation: "get" | "put" | "delete", value?: LockedDraft): Promise<LockedDraft | undefined> {
  return withDraftStore<LockedDraft | undefined>(operation === "get" ? "readonly" : "readwrite", (store, resolve) => {
    const request = operation === "get" ? store.get(id) : operation === "put" ? store.put(value, id) : store.delete(id);
    request.onsuccess = () => resolve(operation === "get" ? request.result : undefined);
  });
}

// A recovery-store outage must not prevent opening the server vault. Keep failure
// distinct from an absent copy so the UI can warn and retain its recovery reference.
export async function readDraft(id: string | undefined): Promise<
  { kind: "available"; draft: LockedDraft | undefined } | { kind: "unavailable" }
> {
  try { return { kind: "available", draft: id ? await draftStore(id, "get") : undefined }; }
  catch { return { kind: "unavailable" }; }
}

export async function removeDraft(id: string | undefined): Promise<boolean> {
  try { if (id) await draftStore(id, "delete"); return true; }
  catch { return false; }
}

// remove: drafts of this account older than DRAFT_MAX_AGE_MS, never the current pointer.
// stamp: drafts with no sealedAt (sealed before this field existed), so they age out
// a week from now instead of being deleted on an unknown age.
export function planDraftCleanup(entries: Array<{ id: string; sealedAt?: number }>, keep: string | undefined, now: number): { remove: string[]; stamp: string[] } {
  const remove: string[] = [], stamp: string[] = [];
  for (const { id, sealedAt } of entries) {
    if (id === keep) continue;
    if (sealedAt === undefined) stamp.push(id);
    else if (now - sealedAt > DRAFT_MAX_AGE_MS) remove.push(id);
  }
  return { remove, stamp };
}

// Housekeeping after unlock: prune this account's stale drafts. Failures are swallowed
// like removeDraft; a missed sweep just tries again next unlock.
export async function pruneDrafts(userId: string, keep: string | undefined, now = Date.now()): Promise<void> {
  try {
    await withDraftStore<void>("readwrite", (store, resolve) => {
      const entries: Array<{ id: string; sealedAt?: number; value: LockedDraft }> = [];
      const request = store.openCursor(IDBKeyRange.bound(`${userId}:`, `${userId}:￿`));
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) {
          const { remove, stamp } = planDraftCleanup(entries, keep, now);
          for (const id of remove) store.delete(id);
          for (const id of stamp) {
            const entry = entries.find((e) => e.id === id);
            if (entry) store.put({ ...entry.value, sealedAt: now }, id);
          }
          resolve(undefined);
          return;
        }
        entries.push({ id: String(cursor.key), sealedAt: (cursor.value as LockedDraft).sealedAt, value: cursor.value as LockedDraft });
        cursor.continue();
      };
    });
  } catch { /* housekeeping only */ }
}
