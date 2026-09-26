import { test } from "node:test";
import assert from "node:assert/strict";
import { exportCsv } from "./csvExport";
import { parseCsvRecords } from "./csvImport";

test("export is RFC 4180 and round-trips through the parser", () => {
  const entries = [{ uuid: "1", title: 'Say "hi"', username: "a,b", password: "p\nq", url: "", notes: "", groupUuid: "g", updatedAt: new Date("2026-01-02T03:04:05Z"), tags: ["x", "y"], favorite: false, custom: [], expiresAt: new Date("2027-01-01T00:00:00Z") }];
  const csv = exportCsv(entries as never, new Map([["g", "Root/Sub"]]));
  assert.ok(csv.startsWith("Group,Title,Username,Password,URL,Notes,TOTP,Tags,Expires,Last Modified\r\n"));
  const rows = parseCsvRecords(csv);
  assert.deepEqual(rows[1], ["Root/Sub", 'Say "hi"', "a,b", "p\nq", "", "", "", "x;y", "2027-01-01T00:00:00.000Z", "2026-01-02T03:04:05.000Z"]);
});
