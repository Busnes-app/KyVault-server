import type { CustomField, KeePassVault, VaultEntry } from "./kdbx";

export type NewEntryDraft = { groupUuid: string };
export type EntryFields = {
  title: string; username: string; password: string; url: string; notes: string; totpSeed: string;
  tags?: string[]; favorite?: boolean; expiresAt?: Date; custom?: CustomField[];
};

// The vault is not touched until the user applies the first edit, so Cancel leaves
// no entry and no save revision behind.
export function createFromDraft(vault: KeePassVault, draft: NewEntryDraft, fields: EntryFields): VaultEntry {
  return vault.createEntry({ ...fields, totpSeed: fields.totpSeed || undefined, groupUuid: draft.groupUuid, title: fields.title || "Untitled" });
}
