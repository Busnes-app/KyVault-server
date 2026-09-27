import { generateUserKey, publicKeyFromSeed, wrapSeed, unwrapSeed, b64, USER_KEY_ALG, type UserKeyRecord } from "./userKey";

export type UserKeyState =
  | { kind: "none" }
  | { kind: "ready"; seed: Uint8Array; publicKey: Uint8Array; record: UserKeyRecord }
  | { kind: "mismatch"; record: UserKeyRecord; reason: string };

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// The published public key must be the one the wrapped seed derives; anything else means
// the record was tampered with or wrapped under a key this tab does not hold.
export async function adoptUserKey(record: UserKeyRecord | undefined, vaultKey: Uint8Array, userId: string): Promise<UserKeyState> {
  if (!record) return { kind: "none" };
  let seed: Uint8Array;
  try {
    seed = await unwrapSeed(b64.decode(record.wrappedSeed), vaultKey, userId);
  } catch {
    return { kind: "mismatch", record, reason: "The stored private key could not be opened with this vault key." };
  }
  const publicKey = await publicKeyFromSeed(seed);
  if (!same(publicKey, b64.decode(record.publicKey))) {
    return { kind: "mismatch", record, reason: "Your published public key does not match your private key." };
  }
  return { kind: "ready", seed, publicKey, record };
}

export async function newUserKeyRecord(vaultKey: Uint8Array, userId: string) {
  const { seed, publicKey } = await generateUserKey();
  const record: UserKeyRecord = {
    alg: USER_KEY_ALG,
    publicKey: b64.encode(publicKey),
    wrappedSeed: b64.encode(await wrapSeed(seed, vaultKey, userId)),
    createdAt: new Date().toISOString(),
  };
  return { seed, publicKey, record };
}

// Rotation re-wraps the same seed; the public key is unchanged so nobody re-pins.
export async function rewrapUserKey(state: UserKeyState, newVaultKey: Uint8Array, userId: string): Promise<UserKeyRecord | undefined> {
  if (state.kind !== "ready") return undefined;
  const { previous: _p, ...rest } = state.record;
  return { ...rest, wrappedSeed: b64.encode(await wrapSeed(state.seed, newVaultKey, userId)) };
}

export const userKeyHeader = (record: UserKeyRecord) => btoa(JSON.stringify(record));
