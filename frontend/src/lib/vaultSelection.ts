import { KeePassVault } from "./kdbx";
import { getBinary, getJSON } from "./api";
import { openSharedKey } from "./sharedKey";
import { loadCrypto } from "./userKey";
import { canOpen, sharedBase, type SharedVaultSummary } from "./sharedVaults";
import { PERSONAL_BASE, uploadVault } from "./vaultSave";
import type { DraftScope } from "./lockedDraft";

export type Selected = { kind: "personal" } | { kind: "shared"; id: string };
export const personal: Selected = { kind: "personal" };
export const selectionScope = (s: Selected): DraftScope => (s.kind === "personal" ? "personal" : (s.id as DraftScope));
export const selectionBase = (s: Selected) => (s.kind === "personal" ? PERSONAL_BASE : sharedBase(s.id));
export const sameSelection = (a: Selected, b: Selected) => a.kind === b.kind && (a.kind === "personal" || a.id === (b as { id: string }).id);

export function resolveSelection(routeShared: string | undefined, vaults: SharedVaultSummary[]): { selected: Selected; notice: string | null } {
  if (!routeShared) return { selected: personal, notice: null };
  const row = vaults.find((v) => v.id === routeShared);
  if (!row) return { selected: personal, notice: "You are not a member of that shared vault." };
  if (!canOpen(row)) {
    const why = row.state === "invited" ? "You have not accepted the invitation to" : "Your key for";
    return { selected: personal, notice: `${why} “${row.name}” ${row.state === "invited" ? "yet." : "needs to be re-sealed by an owner."}` };
  }
  return { selected: { kind: "shared", id: row.id }, notice: null };
}

export const CRYPTO_UNAVAILABLE = "The encryption code could not be loaded, so this vault could not be opened. Reload the page and try again.";
export const RESEAL_NEEDED = "Your copy of the key cannot be opened; ask an owner to re-seal it.";

export type OpenDeps = {
  // Awaited before the unseal so a lazy chunk that 404'd after a deploy is not reported as a
  // key that needs re-sealing — the same separation adoptUserKey makes for the personal key.
  loadCrypto: () => Promise<void>;
  openKey: (seed: Uint8Array, sealedKey: string) => Promise<Uint8Array>;
  fetchMetadata: (base: string) => Promise<{ version: number }>;
  fetchKdbx: (base: string, signal?: AbortSignal) => Promise<ArrayBuffer>;
  openVault: (bytes: ArrayBuffer, key: Uint8Array) => Promise<KeePassVault>;
  createVault: (key: Uint8Array, name: string) => Promise<KeePassVault>;
  upload: (binary: ArrayBuffer, version: number, base: string, keyEpoch: number) => Promise<number>;
};

export const defaultOpenDeps: OpenDeps = {
  loadCrypto,
  openKey: openSharedKey,
  fetchMetadata: (base) => getJSON<{ version: number }>(`${base}/metadata`),
  fetchKdbx: (base, signal) => getBinary(`${base}/kdbx`, signal ?? new AbortController().signal),
  openVault: (bytes, key) => KeePassVault.open(bytes, key),
  createVault: (key, name) => KeePassVault.createNew(key, name),
  upload: (binary, version, base, keyEpoch) => uploadVault(binary, version, undefined, undefined, undefined, false, undefined, base, keyEpoch),
};

// keyEpoch is the vault's, not the row's: it is what every later write must claim.
export type OpenedShared = { vault: KeePassVault; key: Uint8Array; version: number; readOnly: boolean; keyEpoch: number };

export async function openShared(row: SharedVaultSummary, seed: Uint8Array, deps: OpenDeps = defaultOpenDeps): Promise<OpenedShared> {
  try {
    await deps.loadCrypto();
  } catch {
    throw new Error(CRYPTO_UNAVAILABLE);
  }
  let key: Uint8Array;
  try {
    key = await deps.openKey(seed, row.myKey.sealedKey);
  } catch {
    throw new Error(RESEAL_NEEDED);
  }
  const base = sharedBase(row.id);
  const meta = await deps.fetchMetadata(base);
  const readOnly = row.role === "reader";
  if (!meta.version) {
    if (readOnly) throw new Error("This vault is empty; an owner or editor must add the first entry.");
    const vault = await deps.createVault(key, row.name);
    const version = await deps.upload(await vault.exportBinary(), 0, base, row.keyEpoch);
    return { vault, key, version, readOnly, keyEpoch: row.keyEpoch };
  }
  const vault = await deps.openVault(await deps.fetchKdbx(base), key);
  return { vault, key, version: meta.version, readOnly, keyEpoch: row.keyEpoch };
}
