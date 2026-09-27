// A user's X-Wing (ML-KEM-768 + X25519) key pair. The seed is the whole secret; it is
// wrapped under the raw vault key and stored with the envelopes. Sealing is HPKE
// (RFC 9180) with HKDF-SHA256 and AES-256-GCM, byte-compatible with Go crypto/hpke's
// hpke.Seal(pk, HKDFSHA256(), AES256GCM(), info, pt) as ky-primitives capsules use.

export const USER_KEY_ALG = "xwing";
export const PUBLIC_KEY_BYTES = 1216;
export const SEED_BYTES = 32;

export type UserKeyRecord = {
  alg: "xwing";
  publicKey: string;
  wrappedSeed: string;
  createdAt: string;
  previous?: { publicKey: string; replacedAt: string }[];
};

export const b64 = {
  encode: (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)),
  decode: (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0)),
};

// The ~64 KB KEM and HPKE code loads only when a key is first needed.
let suitePromise: Promise<import("@hpke/core").CipherSuite> | null = null;
function suite() {
  suitePromise ??= (async () => {
    const [{ CipherSuite, HkdfSha256, Aes256Gcm }, { XWing }] = await Promise.all([import("@hpke/core"), import("@hpke/hybridkem-x-wing")]);
    return new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
  })().catch((err) => { suitePromise = null; throw err; });
  return suitePromise;
}

// importKey("raw") is X-Wing's own seed expansion, which is what Go's NewPrivateKey(seed)
// does. deriveKeyPair applies HPKE's labelled derivation on top and yields a different key.
async function privateKey(seed: Uint8Array) {
  if (seed.length !== SEED_BYTES) throw new Error("user key seed must be 32 bytes");
  return (await suite()).kem.importKey("raw", seed as unknown as ArrayBuffer, false);
}

// generateKeyPairDerand(seed) is hpke-js's X-Wing expansion from the 32-byte seed and
// matches Go's NewPrivateKey(seed) (verified against the interop fixture).
export async function publicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== SEED_BYTES) throw new Error("user key seed must be 32 bytes");
  const s = await suite();
  const kp = await (s.kem as unknown as { generateKeyPairDerand(sk: Uint8Array): Promise<CryptoKeyPair> }).generateKeyPairDerand(seed);
  return new Uint8Array(await s.kem.serializePublicKey(kp.publicKey));
}

export async function generateUserKey(): Promise<{ seed: Uint8Array; publicKey: Uint8Array }> {
  const seed = crypto.getRandomValues(new Uint8Array(SEED_BYTES));
  return { seed, publicKey: await publicKeyFromSeed(seed) };
}

export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey as BufferSource));
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase().slice(0, 20);
  return hex.match(/.{4}/g)!.join(" ");
}

const aad = (userId: string) => new TextEncoder().encode(`kyvault-user-key:${userId}`);

async function gcmKey(vaultKey: Uint8Array, usage: KeyUsage) {
  return crypto.subtle.importKey("raw", vaultKey as BufferSource, "AES-GCM", false, [usage]);
}

export async function wrapSeed(seed: Uint8Array, vaultKey: Uint8Array, userId: string): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(userId) }, await gcmKey(vaultKey, "encrypt"), seed as BufferSource));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv); out.set(ct, iv.length);
  return out;
}

export async function unwrapSeed(wrapped: Uint8Array, vaultKey: Uint8Array, userId: string): Promise<Uint8Array> {
  if (wrapped.length !== 12 + SEED_BYTES + 16) throw new Error("wrapped seed has the wrong length");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: wrapped.slice(0, 12) as BufferSource, additionalData: aad(userId) }, await gcmKey(vaultKey, "decrypt"), wrapped.slice(12) as BufferSource);
  return new Uint8Array(pt);
}

// HPKE single-shot. Output is enc || ciphertext, which is what Go's hpke.Seal returns.
export async function seal(publicKey: Uint8Array, info: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const s = await suite();
  const recipientPublicKey = await s.kem.importKey("raw", publicKey as unknown as ArrayBuffer, true);
  const ctx = await s.createSenderContext({ recipientPublicKey, info: new TextEncoder().encode(info) });
  const ct = new Uint8Array(await ctx.seal(plaintext));
  const enc = new Uint8Array(ctx.enc);
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc); out.set(ct, enc.length);
  return out;
}

export async function open(seed: Uint8Array, info: string, sealed: Uint8Array): Promise<Uint8Array> {
  const s = await suite();
  const encSize = s.kem.encSize;
  if (sealed.length <= encSize) throw new Error("sealed blob too short");
  const ctx = await s.createRecipientContext({ recipientKey: await privateKey(seed), enc: sealed.slice(0, encSize), info: new TextEncoder().encode(info) });
  return new Uint8Array(await ctx.open(sealed.slice(encSize)));
}
