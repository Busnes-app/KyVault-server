import type { VaultEntry } from "./kdbx";

const HEADER = ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Tags", "Expires", "Last Modified"];
const cell = (v: string) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

// KeePassXC's first six columns in its order, plus Tags/Expires/Last Modified. Every
// value is plaintext: callers must warn before exporting.
export function exportCsv(entries: VaultEntry[], groupsByUuid: Map<string, string>): string {
  const lines = [HEADER.join(",")];
  for (const e of entries) {
    lines.push(
      [
        groupsByUuid.get(e.groupUuid) ?? "",
        e.title,
        e.username,
        e.password,
        e.url,
        e.notes,
        e.totpSeed ?? "",
        e.tags.join(";"),
        e.expiresAt?.toISOString() ?? "",
        e.updatedAt.toISOString(),
      ]
        .map(cell)
        .join(",")
    );
  }
  return lines.join("\r\n") + "\r\n";
}
