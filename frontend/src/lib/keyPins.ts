import type { KeePassVault } from "./kdbx";
import { getJSON, HttpError } from "./api";
import { fingerprint, b64 } from "./userKey";

// Trust on first use. A pin lives in the user's own encrypted vault so it follows them to
// every device; the server's copy of a public key is never trusted on its own.
export type PublishedKey = { userId: string; publicKey: Uint8Array; fingerprint: string; createdAt: string; previous: { publicKey: string; replacedAt: string }[] };
export type Pin = { fingerprint: string; publicKey: string; pinnedAt: string };
export type Lookup =
  | { state: "unknown"; published: PublishedKey | null }
  | { state: "pinned"; published: PublishedKey; pin: Pin }
  | { state: "changed"; published: PublishedKey; pin: Pin };

export const pinKeyFor = (userId: string) => `kyvault.pin.${userId}`;

export function readPin(vault: KeePassVault, userId: string): Pin | null {
  const raw = vault.getCustomData(pinKeyFor(userId));
  if (!raw) return null;
  try {
    const p = JSON.parse(raw);
    if (typeof p?.fingerprint === "string" && typeof p?.publicKey === "string" && typeof p?.pinnedAt === "string") return p;
  } catch {}
  return null;
}

export async function fetchPublishedKey(userId: string): Promise<PublishedKey | null> {
  try {
    const r = await getJSON<{ userId: string; publicKey: string; fingerprint: string; createdAt: string; previous: PublishedKey["previous"] }>(`/api/users/${encodeURIComponent(userId)}/key`);
    const publicKey = b64.decode(r.publicKey);
    // Recompute rather than trust the server's fingerprint.
    return { userId: r.userId, publicKey, fingerprint: await fingerprint(publicKey), createdAt: r.createdAt, previous: r.previous ?? [] };
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) return null;
    throw err;
  }
}

export async function lookupKey(vault: KeePassVault, userId: string, fetchKey: (userId: string) => Promise<PublishedKey | null> = fetchPublishedKey): Promise<Lookup> {
  const published = await fetchKey(userId);
  const pin = readPin(vault, userId);
  if (!published || !pin) return { state: "unknown", published };
  return pin.publicKey === b64.encode(published.publicKey) ? { state: "pinned", published, pin } : { state: "changed", published, pin };
}

export async function pinKey(vault: KeePassVault, userId: string, publicKey: Uint8Array, onChanged: () => void): Promise<Pin> {
  const pin: Pin = { fingerprint: await fingerprint(publicKey), publicKey: b64.encode(publicKey), pinnedAt: new Date().toISOString() };
  vault.setCustomData(pinKeyFor(userId), JSON.stringify(pin));
  onChanged();
  return pin;
}
