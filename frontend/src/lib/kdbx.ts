import * as kdbxweb from "kdbxweb";
import { bytesToHex } from "./vaultCrypto";
import { argon2d, argon2i, argon2id } from "hash-wasm";
import { FAVORITE_TAG, RESERVED_FIELDS } from "./entryMeta";
import type { ImportReport } from "./kdbxImport";
// kdbxweb's UMD bundle defeats Node's CJS export lexer; classes arrive under `default`.
const { CryptoEngine, Credentials, ProtectedValue, Kdbx, KdbxBinaries, KdbxError, KdbxUuid, Consts, VarDictionary, Int64 } =
  (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;

// KyAuth's KDBX vaults are Argon2d, so opening or writing one needs an Argon2 engine.
// hash-wasm rather than argon2-browser because it runs under Node too — argon2-browser
// resolves its WASM by URL and dies outside a browser, which left every Argon2 path in
// this file untestable.
// Exported only so a test can pin it. Getting the memory unit wrong here weakens every
// vault by a factor of a thousand while leaving encryption, decryption and every
// round-trip working perfectly — the header still advertises the strong parameters,
// because the header is written independently of what the KDF actually consumed. Nothing
// short of checking the derived bytes catches that, hence the pinned-key test in kdbx.test.ts.
export async function deriveArgon2Key(
  password: ArrayBuffer,
  salt: ArrayBuffer,
  memory: number,
  iterations: number,
  length: number,
  parallelism: number,
  type: number,
  _version: number
): Promise<ArrayBuffer> {
  const options = {
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    parallelism,
    iterations,
    // kdbxweb passes memory in KiB and hash-wasm's memorySize is KiB, so this is a
    // straight hand-off. Do not "convert" it.
    memorySize: memory,
    hashLength: length,
    outputType: "binary" as const,
  };
  // KDBX header type values: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id.
  const hash =
    type === 0 ? await argon2d(options) : type === 2 ? await argon2id(options) : await argon2i(options);
  return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength) as ArrayBuffer;
}

CryptoEngine.setArgon2Impl(deriveArgon2Key);

// KyAuth writes its vaults with kotpass's Ver4x defaults. Matching them exactly is what
// lets either client open the other's vault, and lets a downloaded file open in KeePassXC.
const KOTPASS_ARGON2 = { memoryBytes: 32 * 1024 * 1024, iterations: 8, parallelism: 2 };
export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
// Matches handleVaultUpload's wire limit; reserve 10 MiB for fields/XML/encryption.
export const MAX_VAULT_BYTES = 50 * 1024 * 1024;
export const MAX_VAULT_ATTACHMENT_BYTES = MAX_VAULT_BYTES - 10 * 1024 * 1024;

export type CustomField = { name: string; value: string; protected: boolean };

export type VaultEntry = {
  uuid: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpSeed?: string;
  groupUuid: string;
  updatedAt: Date;
  tags: string[];
  expiresAt?: Date;
  favorite: boolean;
  custom: CustomField[];
};

export type VaultGroup = {
  uuid: string;
  name: string;
  parentUuid?: string;
  entriesCount: number;
  path: string;
  depth: number;
};

function groupView(group: kdbxweb.KdbxGroup): VaultGroup {
  const names: string[] = [];
  for (let parent: kdbxweb.KdbxGroup | undefined = group; parent; parent = parent.parentGroup) {
    names.unshift(parent.name || "Folder");
  }
  return { uuid: group.uuid.toString(), name: group.name || "Folder",
    parentUuid: group.parentGroup?.uuid.toString(), entriesCount: group.entries.length,
    path: names.join(" / "), depth: names.length - 1 };
}

const MAX_FOLDER_NAME_LENGTH = 255;
// C0/C1 controls plus bidi overrides and zero-width characters: names drive rendered paths.
const FOLDER_NAME_FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;

export function folderName(name: string): string {
  const trimmed = name.trim();
  if (!trimmed || FOLDER_NAME_FORBIDDEN.test(trimmed)) throw new Error("Enter a folder name without control characters.");
  if (trimmed.length > MAX_FOLDER_NAME_LENGTH) throw new Error(`Enter a folder name of ${MAX_FOLDER_NAME_LENGTH} characters or fewer.`);
  return trimmed;
}

function entryFieldText(entry: kdbxweb.KdbxEntry, name: string): string {
  const value = entry.fields.get(name);
  return typeof value === "string" ? value : value?.getText() ?? "";
}

type EntryMeta = { tags: string[]; favorite: boolean; expiresAt?: Date; custom: CustomField[] };

// Shared by getEntries (read) and updateEntry (no-op check), so both agree on what
// "custom" means: every native field that is not one of the standard KeePass names.
function readEntryMeta(e: kdbxweb.KdbxEntry): EntryMeta {
  const tags = e.tags ?? [];
  const favorite = tags.some((t) => t.toLowerCase() === FAVORITE_TAG);
  const expiresAt = e.times.expires && e.times.expiryTime ? e.times.expiryTime : undefined;
  const custom: CustomField[] = [];
  for (const [name, value] of e.fields) {
    if (RESERVED_FIELDS.has(name)) continue;
    const isProtected = value instanceof ProtectedValue;
    custom.push({ name, value: isProtected ? value.getText() : String(value), protected: isProtected });
  }
  return { tags, favorite, expiresAt, custom };
}

// The favourite tag is a derived member of the tag list: strip it out, then re-add it
// (always last) if favorite is set, so callers never need to track its position.
function foldFavoriteTag(tags: string[], favorite: boolean): string[] {
  const userTags = tags.filter((t) => t.toLowerCase() !== FAVORITE_TAG);
  return favorite ? [...userTags, FAVORITE_TAG] : userTags;
}

// Writes tags (favourite folded in/out), expiry and custom fields onto a native entry.
function writeEntryMeta(e: kdbxweb.KdbxEntry, meta: Pick<VaultEntry, "tags" | "favorite" | "expiresAt" | "custom">): void {
  e.tags = foldFavoriteTag(meta.tags, meta.favorite);
  e.times.expires = !!meta.expiresAt;
  // KeePassXC always writes an ExpiryTime element, even with Expires=False; an empty
  // element there is what an unset expiry looks like to it. Never null the field out,
  // only the flag.
  e.times.expiryTime = meta.expiresAt ?? e.times.expiryTime ?? new Date();
  const keep = new Set(meta.custom.map((f) => f.name));
  for (const name of [...e.fields.keys()]) {
    if (!RESERVED_FIELDS.has(name) && !keep.has(name)) e.fields.delete(name);
  }
  for (const field of meta.custom) {
    e.fields.set(field.name, field.protected ? ProtectedValue.fromString(field.value) : field.value);
  }
}

function customFieldsEqual(a: CustomField[], b: CustomField[]): boolean {
  return a.length === b.length && a.every((f, i) => f.name === b[i].name && f.value === b[i].value && f.protected === b[i].protected);
}

// Order and case of a stored tag list are not meaningful to the user; only membership is.
// A KeePassXC-written "Favorite,work" must compare equal to a re-typed "work" plus the
// Favourite checkbox, or every foreign entry gets rewritten the first time it is touched.
function sameTagSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((t, i) => t === sortedB[i]);
}

export class KeePassVault {
  private db: kdbxweb.Kdbx;
  private credentials: kdbxweb.Credentials;

  private constructor(db: kdbxweb.Kdbx, credentials: kdbxweb.Credentials) {
    this.db = db;
    this.credentials = credentials;
  }

  // The credential is the vault key written as hexadecimal text, not the raw bytes.
  // Both facts matter: it is what KyAuth uses, so either client opens the other's vault,
  // and it is something a person can type into KeePassXC — which raw bytes are not, so a
  // binary-keyed vault has no offline recovery path at all.
  private static credentialFor(vaultKey: Uint8Array): kdbxweb.Credentials {
    return new Credentials(ProtectedValue.fromString(bytesToHex(vaultKey)));
  }

  // Create a new blank KDBX v4 vault encrypted with the random 256-bit vaultKey
  public static async createNew(vaultKey: Uint8Array, vaultName = "KyVault Vault"): Promise<KeePassVault> {
    const cred = KeePassVault.credentialFor(vaultKey);
    const db = Kdbx.create(cred, vaultName);

    // Argon2d with kotpass's Ver4x defaults, so our vaults and KyAuth's are the same kind
    // of file. The parameters are set explicitly because kdbxweb's Argon2 defaults are far
    // weaker (1 MiB, t=2, p=1) than kotpass's.
    db.header.setKdf(Consts.KdfId.Argon2d);
    const kdf = db.header.kdfParameters!;
    kdf.set("M", VarDictionary.ValueType.UInt64, Int64.from(KOTPASS_ARGON2.memoryBytes));
    kdf.set("I", VarDictionary.ValueType.UInt64, Int64.from(KOTPASS_ARGON2.iterations));
    kdf.set("P", VarDictionary.ValueType.UInt32, KOTPASS_ARGON2.parallelism);

    // Create standard default folders
    const root = db.getDefaultGroup();
    db.createGroup(root, "General");
    db.createGroup(root, "Personal");
    db.createGroup(root, "Work");
    db.createGroup(root, "Finance");

    return new KeePassVault(db, cred);
  }

  // Older web clients wrote binary-key credentials. Read those after a hex-key mismatch,
  // then use the portable hex credential on the next explicit save/export.
  public static async open(buffer: ArrayBuffer, vaultKey: Uint8Array): Promise<KeePassVault> {
    const cred = KeePassVault.credentialFor(vaultKey);
    try {
      return new KeePassVault(await Kdbx.load(buffer, cred), cred);
    } catch (err) {
      if (!(err instanceof KdbxError) || err.code !== Consts.ErrorCodes.InvalidKey) throw err;
      const legacy = new Credentials(ProtectedValue.fromBinary(vaultKey.slice().buffer));
      const db = await Kdbx.load(buffer, legacy);
      db.credentials = cred;
      return new KeePassVault(db, cred);
    }
  }

  // Open a file written by another client with a plain password (optionally a key
  // file), for the "import a KeePass file" flow. Never used for this app's own vault.
  public static async openForeign(buffer: ArrayBuffer, password: string, keyFile?: ArrayBuffer): Promise<KeePassVault> {
    const credentials = new Credentials(ProtectedValue.fromString(password), keyFile);
    const db = await Kdbx.load(buffer, credentials);
    return new KeePassVault(db, credentials);
  }

  // Copy the full native entry, including history, binaries and unknown fields.
  // A new UUID avoids replacing a newer edit or reviving a current tombstone, unless
  // keepUuid is set (only ever called after the caller has checked the UUID is free).
  public recoverEntryCopy(source: KeePassVault, uuid: string, options?: { keepUuid?: boolean; into?: kdbxweb.KdbxGroup }): string {
    const entry = source.findEntry(uuid);
    if (!entry?.parentGroup || source.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Select a live entry from the conflict.");
    }
    const destination = options?.into ?? this.db.getDefaultGroup();
    if (this.recycledGroupIds().has(destination.uuid.toString())) throw new Error("No live vault folder is available.");
    // kdbxweb imports icons by UUID. Preserve current icons when another client reused
    // the UUID with different data; give the recovered copy its own icon identity.
    const existingIcons = new Map(this.db.meta.customIcons);
    const copy = this.db.importEntry(entry, destination, source.db);
    const importedIcons = new Map<string, kdbxweb.KdbxUuid>();
    for (const item of [copy, ...copy.history]) {
      const iconId = item.customIcon?.toString();
      if (!iconId || !existingIcons.has(iconId)) continue;
      const icon = source.db.meta.customIcons.get(iconId);
      if (!icon) continue;
      let newId = importedIcons.get(iconId);
      if (!newId) {
        newId = KdbxUuid.random();
        importedIcons.set(iconId, newId);
        this.db.meta.customIcons.set(newId.toString(), icon);
      }
      item.customIcon = newId;
    }
    for (const [id, icon] of existingIcons) this.db.meta.customIcons.set(id, icon);
    if (options?.keepUuid) {
      copy.uuid = entry.uuid;
    } else {
      const title = `${entryFieldText(entry, "Title") || "Untitled"} (recovered)`;
      copy.fields.set("Title", entry.fields.get("Title") instanceof ProtectedValue ? ProtectedValue.fromString(title) : title);
    }
    return copy.uuid.toString();
  }

  // Copy a foreign vault's live tree (recycled entries/groups excluded) into an existing
  // same-named top-level folder, reusing it across repeat imports, or under a new one
  // named after the source root; targetGroupUuid picks the destination explicitly.
  // Existing UUIDs win for entries: a clashing entry is skipped rather than overwritten.
  // A group UUID that already exists live is not skipped: import recurses into it, so
  // entries added to a previously imported folder are picked up on a repeat import.
  public importFrom(source: KeePassVault, targetGroupUuid?: string): ImportReport {
    const report: ImportReport = { entries: 0, groups: 0, skippedEntries: 0, skippedGroups: 0, attachments: 0 };
    const srcRoot = source.db.getDefaultGroup();
    const rootName = folderName(srcRoot.name || "Imported");
    const recycled = source.recycledGroupIds();

    // Validate the whole source tree before mutating anything: a bad name discovered
    // halfway through would otherwise leave a half-imported tree with no onChanged().
    const validateNames = (g: kdbxweb.KdbxGroup) => {
      for (const child of g.groups) {
        if (recycled.has(child.uuid.toString())) continue;
        folderName(child.name || "Folder");
        validateNames(child);
      }
    };
    validateNames(srcRoot);

    const targetRecycled = this.recycledGroupIds();
    if (targetGroupUuid && (targetRecycled.has(targetGroupUuid) || !this.findGroup(targetGroupUuid))) {
      throw new Error("No live vault folder is available.");
    }

    const root = this.db.getDefaultGroup();
    // Never match the target's own recycle bin: it can share a name with a foreign root.
    const existingRoot = root.groups.find((g) => !targetRecycled.has(g.uuid.toString()) && (g.name || "") === rootName);
    const parent = (targetGroupUuid && this.findGroup(targetGroupUuid)) || existingRoot || this.db.createGroup(root, rootName);
    const copyGroup = (from: kdbxweb.KdbxGroup, into: kdbxweb.KdbxGroup) => {
      for (const child of from.groups) {
        const id = child.uuid.toString();
        if (recycled.has(id)) continue;
        const existing = this.findGroup(id);
        if (existing) {
          if (targetRecycled.has(id)) { report.skippedGroups++; continue; }
          copyGroup(child, existing);
          continue;
        }
        const made = this.db.createGroup(into, folderName(child.name || "Folder"));
        made.uuid = child.uuid;
        report.groups++;
        copyGroup(child, made);
      }
      for (const entry of from.entries) {
        const id = entry.uuid.toString();
        if (this.findEntry(id)) { report.skippedEntries++; continue; }
        const uuid = this.recoverEntryCopy(source, id, { keepUuid: true, into });
        report.entries++;
        report.attachments += this.getAttachments(uuid).length;
      }
    };
    copyGroup(srcRoot, parent);
    return report;
  }

  // Export/Save the vault back into encrypted KDBX v4 ArrayBuffer
  public async exportBinary(): Promise<ArrayBuffer> {
    // Keep binaries referenced by live/recycled entries or their retained history.
    this.db.cleanup({ binaries: true });
    return this.db.save();
  }

  // List all Groups
  public getGroups(): VaultGroup[] {
    const groups: VaultGroup[] = [];
    
    const traverse = (g: kdbxweb.KdbxGroup) => {
      groups.push(groupView(g));
      for (const child of g.groups) traverse(child);
    };

    traverse(this.db.getDefaultGroup());
    return groups;
  }

  // List all Entries across all groups (or filter by group)
  public getEntries(groupUuid?: string): VaultEntry[] {
    const entries: VaultEntry[] = [];
    const all = this.db.getDefaultGroup().allEntries();

    for (const e of all) {
      const gUuid = e.parentGroup?.uuid.toString() || "";
      if (groupUuid && gUuid !== groupUuid && groupUuid !== "all") {
        continue;
      }

      const title = entryFieldText(e, "Title");
      const username = entryFieldText(e, "UserName");
      const password = entryFieldText(e, "Password");
      const url = entryFieldText(e, "URL");
      const notes = entryFieldText(e, "Notes");
      const otp = entryFieldText(e, "otp") || entryFieldText(e, "TOTP");
      const { tags, favorite, expiresAt, custom } = readEntryMeta(e);

      entries.push({
        uuid: e.uuid.toString(),
        title,
        username,
        password,
        url,
        notes,
        totpSeed: otp,
        groupUuid: gUuid,
        updatedAt: e.times.lastModTime || new Date(),
        tags,
        favorite,
        expiresAt,
        custom,
      });
    }

    return entries;
  }

  private recycledGroupIds(): Set<string> {
    const recycleBin = this.db.meta.recycleBinUuid ? this.db.getGroup(this.db.meta.recycleBinUuid) : undefined;
    return new Set(recycleBin ? [...recycleBin.allGroups()].map(group => group.uuid.toString()) : []);
  }

  public getLiveEntries(): VaultEntry[] {
    const recycled = this.recycledGroupIds();
    return this.getEntries().filter(entry => !recycled.has(entry.groupUuid));
  }

  public getRecycledEntries(): VaultEntry[] {
    const recycled = this.recycledGroupIds();
    return this.getEntries().filter(entry => recycled.has(entry.groupUuid));
  }

  public getLiveGroups(): VaultGroup[] {
    const recycled = this.recycledGroupIds();
    return this.getGroups().filter(group => !recycled.has(group.uuid));
  }

  public getEntryHistory(uuid: string) {
    return (this.findEntry(uuid)?.history ?? []).map((entry, index) => ({
      index, updatedAt: entry.times.lastModTime,
    })).reverse();
  }

  public getAttachments(uuid: string) {
    return [...(this.findEntry(uuid)?.binaries ?? [])].map(([name, binary]) => {
      const value = "hash" in binary ? binary.value : binary;
      return { name, sizeBytes: value.byteLength };
    });
  }

  private attachmentUsage() {
    const hashes = new Set<string>();
    let bytes = 0;
    for (const entry of this.db.getDefaultGroup().allEntries()) {
      for (const version of [entry, ...entry.history]) {
        for (const binary of version.binaries.values()) {
          if ("hash" in binary) {
            if (!hashes.has(binary.hash)) bytes += binary.value.byteLength;
            hashes.add(binary.hash);
          } else {
            // Imported inline binaries are base64-encoded separately in each version.
            bytes += Math.ceil(binary.byteLength / 3) * 4;
          }
        }
      }
    }
    return { bytes, hashes };
  }

  public get attachmentBytes(): number { return this.attachmentUsage().bytes; }

  public hasAttachmentHistory(uuid: string): boolean {
    return this.findEntry(uuid)?.history.some(version => version.binaries.size > 0) ?? false;
  }

  public clearAttachmentHistory(uuid: string): boolean {
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Choose an entry in the live vault.");
    }
    if (!this.hasAttachmentHistory(uuid)) return false;
    for (const version of entry.history) version.binaries.clear();
    entry.times.update();
    return true;
  }

  public getAttachment(uuid: string, name: string): ArrayBuffer {
    const binary = this.findEntry(uuid)?.binaries.get(name);
    if (!binary) throw new Error("This attachment is no longer available.");
    const value = "hash" in binary ? binary.value : binary;
    return value instanceof ProtectedValue ? value.getBinary().slice().buffer : value.slice(0);
  }

  public async addAttachment(uuid: string, name: string, data: ArrayBuffer, signal: AbortSignal): Promise<void> {
    if (!name.trim() || /[\u0000-\u001f\u007f]/.test(name)) throw new Error("Choose a file with a valid name.");
    if (data.byteLength > MAX_ATTACHMENT_BYTES) throw new Error("Attachments must be 10 MiB or smaller.");
    signal.throwIfAborted();
    // Hash outside the live database so lock/navigation cannot leave a late mutation.
    const binary = await new KdbxBinaries().add(data.slice(0));
    signal.throwIfAborted();
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Choose an entry in the live vault.");
    }
    if (entry.binaries.has(name)) throw new Error("An attachment with this name already exists. Rename the file before adding it.");
    const usage = this.attachmentUsage();
    // Check after hashing, immediately before mutation, including concurrent additions.
    // A checkpoint duplicates imported inline binaries, while hashed binaries are shared.
    const inlineCheckpointBytes = this.entryHistoryEnabled ? [...entry.binaries.values()].reduce((sum, value) =>
      sum + ("hash" in value ? 0 : Math.ceil(value.byteLength / 3) * 4), 0) : 0;
    if (usage.bytes + inlineCheckpointBytes + (usage.hashes.has(binary.hash) ? 0 : binary.value.byteLength) > MAX_VAULT_ATTACHMENT_BYTES) {
      throw new Error("The vault's 40 MiB attachment budget includes retained history and recycled entries. Remove files and their saved copies, or clear attachment history, before adding more. The total upload limit is 50 MiB.");
    }
    this.pushEntryHistory(entry);
    this.db.binaries.addWithHash(binary);
    entry.binaries.set(name, binary);
    entry.times.update();
  }

  public removeAttachment(uuid: string, name: string, removeFromHistory = false): boolean {
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Choose an entry in the live vault.");
    }
    if (!entry.binaries.has(name)) return false;
    this.pushEntryHistory(entry);
    entry.binaries.delete(name);
    if (removeFromHistory) for (const version of entry.history) version.binaries.delete(name);
    entry.times.update();
    // History and other entries may still reference these bytes.
    return true;
  }

  public getEntryHistoryVersion(uuid: string, index: number) {
    const entry = Number.isSafeInteger(index) ? this.findEntry(uuid)?.history[index] : undefined;
    if (!entry) throw new Error("This entry version is no longer available.");
    return {
      fields: [...entry.fields].map(([name, value]) => ({
        name,
        value: typeof value === "string" ? value : value.getText(),
        protected: value instanceof ProtectedValue || /^(password|otp|totp)$/i.test(name),
      })),
      attachments: [...entry.binaries.keys()],
    };
  }

  public get entryHistoryEnabled(): boolean {
    return this.db.meta.historyMaxItems !== 0 && this.db.meta.historyMaxSize !== 0;
  }

  private pushEntryHistory(entry: kdbxweb.KdbxEntry): void {
    if (!this.entryHistoryEnabled) return;
    entry.pushHistory();
    const snapshot = entry.history[entry.history.length - 1];
    // kdbxweb's copyFrom (also used by pushHistory) omits these native properties.
    if (snapshot) {
      snapshot.customData = structuredClone(entry.customData);
      snapshot.qualityCheck = entry.qualityCheck;
      snapshot.previousParentGroup = entry.previousParentGroup;
    }
    const limit = this.db.meta.historyMaxItems ?? 10;
    // ponytail: match kdbxweb's count-based history rules; byte-budget pruning needs
    // native historyMaxSize support before we can enforce it without guessing sizes.
    if (limit >= 0 && entry.history.length > limit) entry.removeHistory(0, entry.history.length - limit);
  }

  public restoreEntryVersion(uuid: string, index: number): void {
    const entry = this.findEntry(uuid);
    if (!entry?.parentGroup || this.recycledGroupIds().has(entry.parentGroup.uuid.toString())) {
      throw new Error("Restore the entry to the live vault before restoring a version.");
    }
    const version = Number.isSafeInteger(index) ? entry.history[index] : undefined;
    if (!version) throw new Error("This entry version is no longer available.");
    if (!this.entryHistoryEnabled) throw new Error("Entry history is disabled for this vault; the current version cannot be preserved.");
    const identity = entry.uuid;
    const locationChanged = entry.times.locationChanged;
    const previousParentGroup = entry.previousParentGroup;
    // Capture the version before pruning; the selected version may be the oldest.
    this.pushEntryHistory(entry);
    entry.copyFrom(version);
    entry.customData = structuredClone(version.customData);
    entry.qualityCheck = version.qualityCheck;
    entry.uuid = identity;
    entry.previousParentGroup = previousParentGroup;
    entry.times.locationChanged = locationChanged;
    entry.times.update();
  }

  public restoreEntry(uuid: string): void {
    const entry = this.findEntry(uuid);
    const recycled = this.recycledGroupIds();
    if (!entry?.parentGroup || !recycled.has(entry.parentGroup.uuid.toString())) {
      throw new Error("This entry is not in the recycle bin.");
    }
    const destination = this.db.getDefaultGroup();
    if (recycled.has(destination.uuid.toString())) throw new Error("No live vault folder is available.");
    this.db.move(entry, destination);
    entry.times.update();
  }

  // Create a new entry in a group
  public createEntry(entry: Omit<VaultEntry, "uuid" | "updatedAt" | "tags" | "favorite" | "custom" | "expiresAt"> &
    Partial<Pick<VaultEntry, "tags" | "favorite" | "custom" | "expiresAt">>): VaultEntry {
    let targetGroup = this.db.getDefaultGroup();
    if (entry.groupUuid) {
      const found = this.findGroup(entry.groupUuid);
      if (found) targetGroup = found;
    }

    const tags = entry.tags ?? [];
    const favorite = entry.favorite ?? false;
    const custom = entry.custom ?? [];
    const expiresAt = entry.expiresAt;

    const e = this.db.createEntry(targetGroup);
    e.fields.set("Title", entry.title);
    e.fields.set("UserName", entry.username);
    e.fields.set("Password", ProtectedValue.fromString(entry.password));
    e.fields.set("URL", entry.url);
    e.fields.set("Notes", entry.notes);
    if (entry.totpSeed) {
      e.fields.set("otp", entry.totpSeed);
    }
    writeEntryMeta(e, { tags, favorite, expiresAt, custom });

    return {
      uuid: e.uuid.toString(),
      title: entry.title,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      notes: entry.notes,
      totpSeed: entry.totpSeed,
      groupUuid: targetGroup.uuid.toString(),
      updatedAt: new Date(),
      tags: foldFavoriteTag(tags, favorite),
      favorite,
      expiresAt,
      custom,
    };
  }

  // Update an existing entry
  public updateEntry(entry: VaultEntry): boolean {
    const e = this.findEntry(entry.uuid);
    if (!e) return false;

    const currentMeta = readEntryMeta(e);
    if (entryFieldText(e, "Title") === entry.title && entryFieldText(e, "UserName") === entry.username &&
        entryFieldText(e, "Password") === entry.password && entryFieldText(e, "URL") === entry.url &&
        entryFieldText(e, "Notes") === entry.notes &&
        (entryFieldText(e, "otp") || entryFieldText(e, "TOTP")) === (entry.totpSeed || "") &&
        (!entry.groupUuid || e.parentGroup?.uuid.toString() === entry.groupUuid) &&
        currentMeta.favorite === entry.favorite &&
        sameTagSet(foldFavoriteTag(currentMeta.tags, false), foldFavoriteTag(entry.tags, false)) &&
        currentMeta.expiresAt?.getTime() === entry.expiresAt?.getTime() &&
        customFieldsEqual(currentMeta.custom, entry.custom)) return false;
    this.pushEntryHistory(e);

    const setField = (name: string, value: string) => e.fields.set(name,
      name === "Password" || e.fields.get(name) instanceof ProtectedValue ? ProtectedValue.fromString(value) : value);
    setField("Title", entry.title);
    setField("UserName", entry.username);
    setField("Password", entry.password);
    setField("URL", entry.url);
    setField("Notes", entry.notes);
    if (entry.totpSeed) {
      setField(e.fields.has("otp") || !e.fields.has("TOTP") ? "otp" : "TOTP", entry.totpSeed);
    } else {
      e.fields.delete("otp");
      e.fields.delete("TOTP");
    }
    writeEntryMeta(e, entry);

    if (entry.groupUuid && e.parentGroup?.uuid.toString() !== entry.groupUuid) {
      const targetGroup = this.findGroup(entry.groupUuid);
      if (targetGroup) {
        this.db.move(e, targetGroup);
      }
    }

    e.times.update();
    return true;
  }

  public get recyclingEnabled(): boolean {
    return this.db.meta.recycleBinEnabled !== false;
  }

  // Delete an entry
  public deleteEntry(uuid: string): void {
    const e = this.findEntry(uuid);
    if (e) {
      // Preserve the imported file’s explicit retention policy.
      if (e.parentGroup && this.recycledGroupIds().has(e.parentGroup.uuid.toString())) return;
      if (this.recyclingEnabled) this.db.createRecycleBin();
      this.db.remove(e);
    }
  }

  // Also used to construct imported/recycled trees; UI parents come from getLiveGroups().
  public createGroup(name: string, parentUuid?: string): VaultGroup {
    const validName = folderName(name);
    const parent = parentUuid ? this.findGroup(parentUuid) : this.db.getDefaultGroup();
    if (!parent) throw new Error("This folder is no longer available.");
    return groupView(this.db.createGroup(parent, validName));
  }

  public renameGroup(uuid: string, name: string): boolean {
    const validName = folderName(name);
    const group = this.findGroup(uuid);
    if (!group || this.recycledGroupIds().has(uuid)) throw new Error("Choose a folder in the live vault.");
    if (group.name === validName) return false;
    group.name = validName;
    group.times.update();
    return true;
  }

  private assertMovableGroup(uuid: string): kdbxweb.KdbxGroup {
    const group = this.findGroup(uuid);
    if (!group) throw new Error("This folder is no longer available.");
    if (group === this.db.getDefaultGroup()) throw new Error("The root folder cannot be changed.");
    if (this.recycledGroupIds().has(uuid)) throw new Error("Choose a folder in the live vault.");
    return group;
  }

  // Recycling keeps the folder tree intact inside the bin, so Restore works per entry.
  public deleteGroup(uuid: string): number {
    const group = this.assertMovableGroup(uuid);
    const count = [...group.allEntries()].length;
    if (this.recyclingEnabled) this.db.createRecycleBin();
    this.db.remove(group);
    return count;
  }

  public moveGroup(uuid: string, newParentUuid: string): boolean {
    const group = this.assertMovableGroup(uuid);
    const target = this.findGroup(newParentUuid);
    if (!target || this.recycledGroupIds().has(newParentUuid)) throw new Error("Choose a live folder to move into.");
    for (let p: kdbxweb.KdbxGroup | undefined = target; p; p = p.parentGroup) {
      if (p === group) throw new Error("A folder cannot be moved inside itself.");
    }
    if (group.parentGroup === target) return false;
    this.db.move(group, target);
    group.times.update();
    return true;
  }

  private findEntry(uuid: string): kdbxweb.KdbxEntry | undefined {
    for (const e of this.db.getDefaultGroup().allEntries()) {
      if (e.uuid.toString() === uuid) {
        return e;
      }
    }
    return undefined;
  }

  private findGroup(uuid: string): kdbxweb.KdbxGroup | undefined {
    const search = (g: kdbxweb.KdbxGroup): kdbxweb.KdbxGroup | undefined => {
      if (g.uuid.toString() === uuid) return g;
      for (const child of g.groups) {
        const res = search(child);
        if (res) return res;
      }
      return undefined;
    };
    return search(this.db.getDefaultGroup());
  }
}
