import { MAX_VAULT_BYTES } from "./kdbx";

export type ImportReport = { entries: number; groups: number; skippedEntries: number; skippedGroups: number; attachments: number };

export async function readKdbxFile(file: File): Promise<ArrayBuffer> {
  if (file.size > MAX_VAULT_BYTES) throw new Error("This file is larger than the 50 MiB vault limit.");
  return file.arrayBuffer();
}

export function describeImport(r: ImportReport): string {
  const parts = [`${r.entries} entr${r.entries === 1 ? "y" : "ies"} and ${r.groups} folder${r.groups === 1 ? "" : "s"} imported`];
  if (r.attachments) parts.push(`${r.attachments} attachment${r.attachments === 1 ? "" : "s"}`);
  if (r.skippedEntries || r.skippedGroups) parts.push(`${r.skippedEntries + r.skippedGroups} already present and left unchanged`);
  return parts.join(", ") + ".";
}
