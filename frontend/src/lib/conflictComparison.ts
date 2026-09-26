import type { VaultEntry } from "./kdbx";

export const comparisonFields = [
  ["title", "Title"], ["username", "Username"], ["password", "Password"],
  ["url", "Website"], ["notes", "Notes"], ["totpSeed", "TOTP"],
] as const;

// UUID comparison follows the shared entry identity; names and passwords are not identities.
export function compareConflictEntries(current: VaultEntry[], conflict: VaultEntry[]) {
  const byId = new Map(current.map(entry => [entry.uuid, entry]));
  const conflictIds = new Set(conflict.map(entry => entry.uuid));
  return [
    ...conflict.map(entry => {
      const existing = byId.get(entry.uuid);
      const changedFields = comparisonFields.filter(([key]) => (entry[key] || "") !== (existing?.[key] || ""));
      return { entry, current: existing, changedFields, side: "conflict" as const };
    }),
    // Entries the conflict lacks: shown so the comparison reads both ways, never recovered.
    ...current.filter(entry => !conflictIds.has(entry.uuid))
      .map(entry => ({ entry, current: entry as VaultEntry | undefined, changedFields: [] as typeof comparisonFields[number][], side: "current" as const })),
  ];
}
