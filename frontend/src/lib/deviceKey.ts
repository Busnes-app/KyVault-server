// The cached vault key is encrypted at rest under a per-browser AES-GCM key that
// WebCrypto refuses to export. A copy of the IndexedDB files alone no longer yields the
// vault key; a script running on this origin still can, which is what the CSP is for.
export type SealedKey = { iv: Uint8Array; ciphertext: Uint8Array };

export function newWrappingKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function sealKeyHex(wrapping: CryptoKey, keyHex: string): Promise<SealedKey> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(keyHex);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, wrapping, plain as BufferSource),
  );
  plain.fill(0);
  return { iv, ciphertext };
}

export async function openKeyHex(wrapping: CryptoKey, sealed: SealedKey): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: sealed.iv as BufferSource },
    wrapping,
    sealed.ciphertext as BufferSource,
  );
  return new TextDecoder().decode(plain);
}
