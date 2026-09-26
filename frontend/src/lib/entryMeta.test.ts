import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { parseTags, hasReservedTag, isExpired, expiresWithin, sortEntries, entryMatches, FAVORITE_TAG } from "./entryMeta";
import * as kdbxweb from "kdbxweb";

const { Kdbx, Credentials, ProtectedValue } = (kdbxweb as { default?: typeof kdbxweb }).default ?? kdbxweb;
const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

test("tags parse, dedupe and cap", () => {
  assert.deepEqual(parseTags(" work, Work ;home,, "), ["work", "home"]);
  assert.deepEqual(parseTags("x".repeat(40)), ["x".repeat(32)]);
});

test("the favorite tag is reserved and dropped from typed tags", () => {
  assert.deepEqual(parseTags("Home, Favorite"), ["Home"]);
  assert.equal(hasReservedTag("Home, Favorite"), true);
  assert.equal(hasReservedTag("Home, Work"), false);
});

test("metadata round-trips through an encrypted export", async () => {
  const key = new Uint8Array(32).fill(5);
  const vault = await KeePassVault.createNew(key);
  const root = vault.getLiveGroups()[0].uuid;
  // KDBX4 stores expiry as whole seconds (binary date encoding); floor to match round-trip precision.
  const past = new Date(Math.floor((Date.now() - 86_400_000) / 1000) * 1000);
  const e = vault.createEntry({ title: "Bank", username: "u", password: "p", url: "", notes: "", groupUuid: root,
    tags: ["finance"], favorite: true, expiresAt: past, custom: [{ name: "PIN", value: "1234", protected: true }, { name: "Branch", value: "Main", protected: false }] });
  const reopened = await KeePassVault.open(await vault.exportBinary(), key);
  const back = reopened.getEntries().find((x) => x.uuid === e.uuid)!;
  assert.deepEqual(back.tags, ["finance", FAVORITE_TAG]);
  assert.equal(back.favorite, true);
  assert.equal(back.expiresAt?.getTime(), past.getTime());
  assert.equal(isExpired(back), true);
  assert.deepEqual(back.custom, [{ name: "PIN", value: "1234", protected: true }, { name: "Branch", value: "Main", protected: false }]);
  assert.equal(reopened.updateEntry({ ...back }), false, "no-op update creates no revision");
  assert.equal(reopened.updateEntry({ ...back, favorite: false, expiresAt: undefined }), true);
  const again = reopened.getEntries().find((x) => x.uuid === e.uuid)!;
  assert.deepEqual(again.tags, ["finance"]);
  assert.equal(again.expiresAt, undefined);

  // Clearing an expiry must leave Expires=False with a real ExpiryTime element, matching
  // what KeePassXC writes. An empty <ExpiryTime/> (kdbxweb's rendering of undefined) is
  // not read the same by every client.
  const raw = await Kdbx.load(await reopened.exportBinary(), new Credentials(ProtectedValue.fromString(bytesToHex(key))));
  const nativeEntry = [...raw.getDefaultGroup().allEntries()].find((x) => x.uuid.toString() === e.uuid)!;
  assert.equal(nativeEntry.times.expires, false);
  assert.ok(nativeEntry.times.expiryTime instanceof Date);
});

test("sorting, expiry windows and search", () => {
  const base = { username: "", password: "", url: "", notes: "", groupUuid: "g", favorite: false, custom: [], tags: [] as string[] };
  const soon = new Date(Date.now() + 3 * 86_400_000);
  const entries = [
    { ...base, uuid: "1", title: "beta", updatedAt: new Date(1), expiresAt: undefined },
    { ...base, uuid: "2", title: "Alpha", updatedAt: new Date(3), expiresAt: soon, tags: ["Shopping"] },
    { ...base, uuid: "3", title: "gamma", updatedAt: new Date(2), expiresAt: undefined, custom: [{ name: "Member ID", value: "42", protected: false }, { name: "Secret", value: "hidden", protected: true }] },
  ];
  assert.deepEqual(sortEntries(entries, "title").map((e) => e.uuid), ["2", "1", "3"]);
  assert.deepEqual(sortEntries(entries, "modified").map((e) => e.uuid), ["2", "3", "1"]);
  assert.deepEqual(sortEntries(entries, "expiry").map((e) => e.uuid), ["2", "1", "3"]);
  assert.equal(expiresWithin(entries[1], 7), true);
  assert.equal(expiresWithin(entries[1], 1), false);
  assert.equal(entryMatches(entries[1], "shop"), true);
  assert.equal(entryMatches(entries[2], "member"), true);
  assert.equal(entryMatches(entries[2], "42"), true);
  assert.equal(entryMatches(entries[2], "hidden"), false, "protected custom values are never searched");
});
