import { test } from "node:test";
import assert from "node:assert/strict";
import { rankEntries, type EntryView } from "./rank";

const e = (uuid: string, title: string, url: string, username = "u"): EntryView => ({ uuid, title, url, username, hasPassword: true, hasTotp: false, reused: 0 });
const all = [e("a", "Zulu mail", "https://mail.example.com"), e("b", "Example", "https://www.example.com/login"), e("c", "Other", "https://other.test"), e("d", "Alpha exact", "https://www.example.com"), e("e", "Broken", "not a url")];

test("exact host first, then same site, nothing else without a query", () => {
  assert.deepEqual(rankEntries(all, "www.example.com", "").map((x) => x.uuid), ["d", "b", "a"]);
  assert.deepEqual(rankEntries(all, undefined, "").map((x) => x.uuid), []);
});

test("a query searches everything and keeps site matches on top", () => {
  assert.deepEqual(rankEntries(all, "www.example.com", "e").map((x) => x.uuid), ["d", "b", "a", "e", "c"]);
  assert.deepEqual(rankEntries(all, undefined, "alpha").map((x) => x.uuid), ["d"]);
  assert.deepEqual(rankEntries(all, "www.example.com", "zzz").map((x) => x.uuid), []);
});
