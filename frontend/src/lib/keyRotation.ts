import { HttpError } from "./api";
import type { KeePassVault } from "./kdbx";
import { generateVaultMasterKey, wrapVaultKey } from "./vaultCrypto";
import { uploadVault } from "./vaultSave";

// In memory only: the live vault now saves under the new key. The caller must send the
// binary and both envelopes in ONE upload, and call vault.rekey(oldKey) if that fails.
export async function rotateVaultKey(vault: KeePassVault, password: string, paperCode: string) {
  const key = generateVaultMasterKey();
  vault.rekey(key);
  const binary = await vault.exportBinary();
  const [passwordEnvelope, recoveryEnvelope] = await Promise.all([wrapVaultKey(key, password), wrapVaultKey(key, paperCode)]);
  return { key, binary, passwordEnvelope, recoveryEnvelope };
}

// The server records this upload's version as the new key epoch and refuses rollback to
// anything older, so no client can restore a snapshot the new key cannot open.
export function uploadRotatedVault(binary: ArrayBuffer, version: number, passwordEnvelope: string, recoveryEnvelope: string): Promise<number> {
  return uploadVault(binary, version, passwordEnvelope, recoveryEnvelope, undefined, true);
}

type RotationIO = {
  // POST /api/vault/upload with If-Match: "version"; returns the new version.
  upload: (binary: ArrayBuffer, passwordEnvelope: string, recoveryEnvelope: string) => Promise<number>;
  metadata: () => Promise<{ version?: unknown; passwordEnvelope?: string; recoveryEnvelope?: string }>;
};

// The upload's answer was lost and the server could not be asked. The caller must lock
// and let the next unlock read whichever key the stored envelopes hold.
export class RotationUnconfirmedError extends Error {
  constructor() {
    super("Could not confirm whether the new vault key reached the server.");
    this.name = "RotationUnconfirmedError";
  }
}

// SaveVault writes the KDBX and both envelopes under one lock, so the server holds either
// the old triple or the new one. A server answer (HttpError) means nothing was written. A
// lost response is ambiguous: our envelopes are unique (random salt and IV), so finding
// them stored at exactly version + 1 proves the rotation landed and nothing saved on top.
// Our envelopes at a later version mean another tab saved since; locking lets the next
// unlock read that save instead of this tab overwriting it.
export async function rotateAndUpload(vault: KeePassVault, oldKey: Uint8Array, password: string, paperCode: string, version: number, io: RotationIO) {
  let rotated: Awaited<ReturnType<typeof rotateVaultKey>> | undefined;
  try {
    rotated = await rotateVaultKey(vault, password, paperCode);
    const saved = await io.upload(rotated.binary, rotated.passwordEnvelope, rotated.recoveryEnvelope);
    return { key: rotated.key, version: saved, passwordEnvelope: rotated.passwordEnvelope };
  } catch (err) {
    let unconfirmed = false;
    if (rotated && !(err instanceof HttpError)) {
      const meta = await io.metadata().catch(() => undefined);
      const ours = !!meta && meta.passwordEnvelope === rotated.passwordEnvelope && meta.recoveryEnvelope === rotated.recoveryEnvelope;
      if (ours && meta.version === version + 1) return { key: rotated.key, version: version + 1, passwordEnvelope: rotated.passwordEnvelope };
      unconfirmed = !meta || ours;
    }
    vault.rekey(oldKey);
    throw unconfirmed ? new RotationUnconfirmedError() : err;
  }
}

// Best effort: every device is attempted, 404 means already gone. Returns the ids still paired.
export async function revokeDevices(ids: string[], revoke: (id: string) => Promise<unknown>): Promise<string[]> {
  const results = await Promise.all(ids.map((id) => revoke(id).then(
    () => true,
    (err) => err instanceof HttpError && err.status === 404,
  )));
  return ids.filter((_, i) => !results[i]);
}
