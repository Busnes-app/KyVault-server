import { HttpError } from "./api";
import type { KeePassVault } from "./kdbx";
import { generateVaultMasterKey, wrapVaultKey } from "./vaultCrypto";

// In memory only: the live vault now saves under the new key. The caller must send the
// binary and both envelopes in ONE upload, and call vault.rekey(oldKey) if that fails.
export async function rotateVaultKey(vault: KeePassVault, password: string, paperCode: string) {
  const key = generateVaultMasterKey();
  vault.rekey(key);
  const binary = await vault.exportBinary();
  const [passwordEnvelope, recoveryEnvelope] = await Promise.all([wrapVaultKey(key, password), wrapVaultKey(key, paperCode)]);
  return { key, binary, passwordEnvelope, recoveryEnvelope };
}

type RotationIO = {
  // POST /api/vault/upload with If-Match; returns the new version.
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
// them stored proves the rotation landed. Otherwise the old key comes back.
export async function rotateAndUpload(vault: KeePassVault, oldKey: Uint8Array, password: string, paperCode: string, io: RotationIO) {
  let rotated: Awaited<ReturnType<typeof rotateVaultKey>> | undefined;
  try {
    rotated = await rotateVaultKey(vault, password, paperCode);
    return { key: rotated.key, version: await io.upload(rotated.binary, rotated.passwordEnvelope, rotated.recoveryEnvelope) };
  } catch (err) {
    let unconfirmed = false;
    if (rotated && !(err instanceof HttpError)) {
      const meta = await io.metadata().catch(() => undefined);
      if (meta && typeof meta.version === "number" && meta.passwordEnvelope === rotated.passwordEnvelope && meta.recoveryEnvelope === rotated.recoveryEnvelope) {
        return { key: rotated.key, version: meta.version };
      }
      unconfirmed = !meta;
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
