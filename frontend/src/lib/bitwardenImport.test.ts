import { test } from "node:test";
import assert from "node:assert/strict";
import { parseBitwardenJson } from "./bitwardenImport";

test("bitwarden logins import with folder and totp; other types are counted", () => {
  const json = JSON.stringify({ encrypted: false, folders: [{ id: "f1", name: "Work" }], items: [
    { type: 1, name: "GitHub", folderId: "f1", notes: "n", login: { username: "me", password: "pw", totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://github.com" }] } },
    { type: 2, name: "Secure note", secureNote: {} },
    { type: 3, name: "Card", card: {} },
    { type: 1, name: "No folder", login: { username: "", password: "x" } },
  ] });
  const { entries, skipped } = parseBitwardenJson(json);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries[0], { id: entries[0].id, title: "GitHub", username: "me", password: "pw", url: "https://github.com", notes: "n", totpSeed: "JBSWY3DPEHPK3PXP", folder: "Work", selected: true });
  assert.equal(entries[1].folder, "");
  assert.deepEqual(skipped, { notes: 1, cards: 1, identities: 0 });
  assert.throws(() => parseBitwardenJson(JSON.stringify({ encrypted: true, items: [] })), /encrypted/i);
  assert.throws(() => parseBitwardenJson("nope"), /not a Bitwarden/i);
});
