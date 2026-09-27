import { seal, open, b64 } from "./userKey";

export const SHARED_KEY_INFO = "kyvault/shared-vault-key/1";
export const SHARED_KEY_BYTES = 32;
export const SEALED_KEY_BYTES = 1168;

export function newSharedKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SHARED_KEY_BYTES));
}

export async function sealSharedKey(publicKey: Uint8Array, key: Uint8Array): Promise<string> {
  if (key.length !== SHARED_KEY_BYTES) throw new Error(`shared vault key must be ${SHARED_KEY_BYTES} bytes`);
  const sealed = await seal(publicKey, SHARED_KEY_INFO, key);
  if (sealed.length !== SEALED_KEY_BYTES) throw new Error(`sealed key is ${sealed.length} bytes, expected ${SEALED_KEY_BYTES}`);
  return b64.encode(sealed);
}

export async function openSharedKey(seed: Uint8Array, sealedKey: string): Promise<Uint8Array> {
  const blob = b64.decode(sealedKey);
  if (blob.length !== SEALED_KEY_BYTES) throw new Error("sealed key has the wrong length");
  const key = await open(seed, SHARED_KEY_INFO, blob);
  if (key.length !== SHARED_KEY_BYTES) throw new Error("opened key has the wrong length");
  return key;
}
