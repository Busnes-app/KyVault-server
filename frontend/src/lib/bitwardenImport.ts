import type { ImportedEntryPreview } from "./csvImport";

// Bitwarden `items[].type`: 1 login, 2 secure note, 3 card, 4 identity.
const TYPE_LOGIN = 1;
const TYPE_NOTE = 2;
const TYPE_CARD = 3;
const TYPE_IDENTITY = 4;

export function parseBitwardenJson(
  text: string
): { entries: ImportedEntryPreview[]; skipped: { notes: number; cards: number; identities: number } } {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("This is not a Bitwarden export.");
  }
  if (!data || !Array.isArray(data.items)) throw new Error("This is not a Bitwarden export.");
  if (data.encrypted === true) {
    throw new Error("This Bitwarden export is encrypted. Export it unencrypted and import that file.");
  }

  const folderNames = new Map<string, string>();
  if (Array.isArray(data.folders)) {
    for (const folder of data.folders) {
      if (folder?.id) folderNames.set(folder.id, folder.name ?? "");
    }
  }

  const entries: ImportedEntryPreview[] = [];
  const skipped = { notes: 0, cards: 0, identities: 0 };

  for (const item of data.items) {
    switch (item?.type) {
      case TYPE_LOGIN: {
        const login = item.login ?? {};
        entries.push({
          id: crypto.randomUUID(),
          title: item.name ?? "",
          username: login.username ?? "",
          password: login.password ?? "",
          url: login.uris?.[0]?.uri ?? "",
          notes: item.notes ?? "",
          totpSeed: login.totp ?? "",
          folder: (item.folderId && folderNames.get(item.folderId)) || "",
          selected: true,
        });
        break;
      }
      case TYPE_NOTE:
        skipped.notes++;
        break;
      case TYPE_CARD:
        skipped.cards++;
        break;
      case TYPE_IDENTITY:
        skipped.identities++;
        break;
      default:
        break;
    }
  }

  return { entries, skipped };
}
