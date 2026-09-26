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

test("non-string and null fields are coerced to empty strings, not thrown", () => {
  const json = JSON.stringify({ items: [
    { type: 1, name: 42, notes: null, login: { username: null, password: { x: 1 }, totp: 7, uris: [{ uri: null }] } },
  ] });
  const { entries } = parseBitwardenJson(json);
  assert.deepEqual(entries, [{ id: entries[0].id, title: "", username: "", password: "", url: "", notes: "", totpSeed: "", folder: "", selected: true }]);
});
