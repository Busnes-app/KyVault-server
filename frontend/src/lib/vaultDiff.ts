import type { VaultEntry } from "./kdbx";
import { comparisonFields } from "./conflictComparison";

export type DiffRow = { uuid: string; title: string };
export type VaultDiff = {
  added: DiffRow[];
  removed: DiffRow[];
  changed: Array<DiffRow & { fields: string[] }>;
  counts: { live: number; other: number };
};

// Titles and field labels only: the result never carries a field value.
// "added" is in `other` only, "removed" is in `live` only.
export function diffVaults(live: VaultEntry[], other: VaultEntry[]): VaultDiff {
  const liveById = new Map(live.map((e) => [e.uuid, e]));
  const otherIds = new Set(other.map((e) => e.uuid));
  const row = (e: VaultEntry): DiffRow => ({ uuid: e.uuid, title: e.title });
  const changed = other.flatMap((e) => {
    const l = liveById.get(e.uuid);
    if (!l) return [];
    const fields = comparisonFields.filter(([k]) => (e[k] || "") !== (l[k] || "")).map(([, label]) => label as string);
    return fields.length ? [{ ...row(e), fields }] : [];
  });
  return {
    added: other.filter((e) => !liveById.has(e.uuid)).map(row),
    removed: live.filter((e) => !otherIds.has(e.uuid)).map(row),
    changed,
    counts: { live: live.length, other: other.length },
  };
}
