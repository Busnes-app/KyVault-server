import type { ImportedEntryPreview } from "./csvImport";

// Bitwarden `items[].type`: 1 login, 2 secure note, 3 card, 4 identity.
const TYPE_LOGIN = 1;
const TYPE_NOTE = 2;
const TYPE_CARD = 3;
const TYPE_IDENTITY = 4;

// Every field below crosses a trust boundary (a file the user chose): a non-string value
// such as `name: 42` must not reach the preview, where search and duplicate detection
// assume strings.
const str = (v: unknown): string => (typeof v === "string" ? v : "");

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

export function parseBitwardenJson(
  text: string
): { entries: ImportedEntryPreview[]; skipped: { notes: number; cards: number; identities: number } } {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("This is not a Bitwarden export.");
  }
  if (!isRecord(data) || !Array.isArray(data.items)) throw new Error("This is not a Bitwarden export.");
  if (data.encrypted === true) {
    throw new Error("This Bitwarden export is encrypted. Export it unencrypted and import that file.");
  }

  const folderNames = new Map<string, string>();
  if (Array.isArray(data.folders)) {
    for (const folder of data.folders) {
      if (isRecord(folder) && typeof folder.id === "string") folderNames.set(folder.id, str(folder.name));
    }
  }

  const entries: ImportedEntryPreview[] = [];
  const skipped = { notes: 0, cards: 0, identities: 0 };

  for (const item of data.items) {
    if (!isRecord(item)) continue;
    switch (item.type) {
      case TYPE_LOGIN: {
        const login = isRecord(item.login) ? item.login : {};
        const uris = Array.isArray(login.uris) ? login.uris : [];
        const firstUri = isRecord(uris[0]) ? uris[0] : {};
        const folderId = typeof item.folderId === "string" ? item.folderId : undefined;
        entries.push({
          id: crypto.randomUUID(),
          title: str(item.name),
          username: str(login.username),
          password: str(login.password),
          url: str(firstUri.uri),
          notes: str(item.notes),
          totpSeed: str(login.totp),
          folder: (folderId && folderNames.get(folderId)) || "",
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
