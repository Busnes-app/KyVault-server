import type { VaultEntry } from "../../../frontend/src/lib/kdbx";
import { sameSite } from "./domain";

// Never the password or seed: this crosses into the popup, which holds no vault key.
export type EntryView = Pick<VaultEntry, "uuid" | "title" | "username" | "url"> & {
  hasPassword: boolean;
  hasTotp: boolean;
  reused: number;
};

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function tier(entry: EntryView, tabHost: string | undefined): 0 | 1 | 2 {
  if (!tabHost) return 2;
  const host = hostOf(entry.url);
  if (!host) return 2;
  if (host === tabHost) return 0;
  if (sameSite(host, tabHost)) return 1;
  return 2;
}

// Without a query: exact host first, then same registrable domain, nothing else.
// With a query: `matches` decides what stays in (defaults to title+URL substring; the
// background passes entryMatches so tags and custom fields are searchable too), and
// site matches still sort first. Each tier sorts by title.
export function rankEntries(
  entries: EntryView[],
  tabHost: string | undefined,
  query: string,
  matches: (entry: EntryView, query: string) => boolean = (e, q) => (e.title + " " + e.url).toLowerCase().includes(q),
): EntryView[] {
  const q = query.trim().toLowerCase();
  const kept = q ? entries.filter((e) => matches(e, q)) : entries.filter((e) => tier(e, tabHost) < 2);
  return kept
    .map((entry) => ({ entry, tier: tier(entry, tabHost) }))
    .sort((a, b) => a.tier - b.tier || a.entry.title.localeCompare(b.entry.title))
    .map((x) => x.entry);
}
