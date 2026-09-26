import { test } from "node:test";
import assert from "node:assert/strict";
import { KeePassVault } from "./kdbx";
import { passwordWeakness, buildHealthReport, sha1Hex, hibpPrefix, hibpSuffix, parseRangeResponse, checkBreached } from "./health";

test("weakness heuristic", () => {
  assert.equal(passwordWeakness(""), "empty");
  assert.equal(passwordWeakness("short1!A"), "shorter than 12 characters");
  assert.equal(passwordWeakness("aaaaaaaaaaaaaaaa"), "repeats one character");
  assert.equal(passwordWeakness("abcdefghijklmnop"), "only one kind of character");
  assert.equal(passwordWeakness("abcdefgh1234"), "fewer than 16 characters with two kinds");
  assert.equal(passwordWeakness("abcdefgh12345678"), null);
  assert.equal(passwordWeakness("correct-horse-battery-staple"), null);
});

test("report lists weak, reused, expired and expiring by uuid and title only", async () => {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(4));
  const root = vault.getLiveGroups()[0].uuid;
  const base = { username: "", url: "", notes: "", groupUuid: root, tags: [], favorite: false, custom: [] };
  const a = vault.createEntry({ ...base, title: "A", password: "same-password-1" });
  const b = vault.createEntry({ ...base, title: "B", password: "same-password-1" });
  const c = vault.createEntry({ ...base, title: "C", password: "short", expiresAt: new Date(Date.now() - 1000) });
  const d = vault.createEntry({ ...base, title: "D", password: "long enough and mixed 9", expiresAt: new Date(Date.now() + 5 * 86_400_000) });
  const r = buildHealthReport(vault);
  assert.deepEqual(r.reused.map((x) => x.uuid).sort(), [a.uuid, b.uuid].sort());
  assert.deepEqual(r.weak.map((x) => x.uuid), [c.uuid]);
  assert.deepEqual(r.expired.map((x) => x.uuid), [c.uuid]);
  assert.deepEqual(r.expiring.map((x) => x.uuid), [d.uuid]);
  assert.equal(JSON.stringify(r).includes("same-password-1"), false);
});

test("hibp prefix and range parsing", async () => {
  const hash = await sha1Hex("password");
  assert.equal(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assert.equal(hibpPrefix(hash), "5BAA6");
  assert.equal(hibpSuffix(hash), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
  const body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n00000000000000000000000000000000000:0\r\n";
  assert.equal(parseRangeResponse(body, hibpSuffix(hash)), 12345);
  assert.equal(parseRangeResponse(body, "00000000000000000000000000000000000"), 0);
  assert.equal(parseRangeResponse(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
});

test("checkBreached sends only the prefix and never the password", async () => {
  const urls: string[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    urls.push(url);
    assert.equal((init.headers as Record<string, string>)["Add-Padding"], "true");
    assert.equal(init.credentials, "omit");
    return new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\n");
  }) as unknown as typeof fetch;
  const out = await checkBreached(new Map([["password", ["u1", "u2"]], ["unique-and-safe-xyz", ["u3"]]]), new AbortController().signal, fetchFn);
  assert.deepEqual(urls, ["https://api.pwnedpasswords.com/range/5BAA6", `https://api.pwnedpasswords.com/range/${hibpPrefix(await sha1Hex("unique-and-safe-xyz"))}`]);
  // Only the 5-char prefix may appear after /range/; the domain itself contains
  // "password" (pwnedpasswords.com), so checking the whole URL would false-positive.
  assert.ok(urls.every((u) => !u.split("/range/")[1]?.toLowerCase().includes("password")));
  assert.deepEqual([...out.entries()], [["u1", 7], ["u2", 7]]);
});
