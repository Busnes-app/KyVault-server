import type { VaultEntry } from "./kdbx";

export const FAVORITE_TAG = "favorite";
export const RESERVED_FIELDS = new Set(["Title", "UserName", "Password", "URL", "Notes", "otp", "TOTP"]);
export const MAX_TAG_LENGTH = 32;

export function parseTags(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/[,;]/)) {
    const tag = raw.trim().slice(0, MAX_TAG_LENGTH);
    const key = tag.toLowerCase();
    if (!tag || seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

export function isExpired(entry: Pick<VaultEntry, "expiresAt">, now = new Date()): boolean {
  return !!entry.expiresAt && entry.expiresAt.getTime() <= now.getTime();
}

export function expiresWithin(entry: Pick<VaultEntry, "expiresAt">, days: number, now = new Date()): boolean {
  return !!entry.expiresAt && entry.expiresAt.getTime() > now.getTime() && entry.expiresAt.getTime() <= now.getTime() + days * 86_400_000;
}

export type SortKey = "title" | "modified" | "expiry";
export function sortEntries<T extends Pick<VaultEntry, "title" | "updatedAt" | "expiresAt">>(entries: T[], key: SortKey): T[] {
  const copy = [...entries];
  if (key === "title") copy.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
  if (key === "modified") copy.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
  if (key === "expiry") copy.sort((a, b) => (a.expiresAt?.getTime() ?? Infinity) - (b.expiresAt?.getTime() ?? Infinity));
  return copy;
}

export function entryMatches(entry: VaultEntry, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const hay = [entry.title, entry.username, entry.url, entry.notes, ...entry.tags,
    ...entry.custom.flatMap((f) => (f.protected ? [f.name] : [f.name, f.value]))];
  return hay.some((s) => s.toLowerCase().includes(q));
}
