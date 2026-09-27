import { test } from "node:test";
import assert from "node:assert/strict";
import { isInsecureUrl, twoFactorDomainFor, buildWatchtowerReport, runBreachCheck, scoreReport, CATEGORIES, type ReportDeps, type StrengthCache } from "./watchtower";
import { KeePassVault } from "./kdbx";
import { loadStrengthChecker } from "./passwordStrength";

test("insecure URL table", () => {
  const flagged = ["http://example.com", "HTTP://Example.COM/login", "http://example.com./", "http://8.8.8.8", "http://[2001:db8::1]"];
  const clean = [
    "https://example.com", "http://localhost:8080", "http://app.localhost", "http://nas.local",
    "http://10.0.0.5", "http://172.16.4.1", "http://172.31.255.1", "http://192.168.1.1", "http://127.0.0.1",
    "http://169.254.1.1", "http://[::1]", "http://[fe80::1]", "http://[fd00::1]", "http://[::ffff:192.168.1.1]",
    "example.com", "", "not a url", "ftp://example.com", "javascript:alert(1)",
    "http://nas:5000", "http://router.lan", "http://pve.home.arpa", "http://grafana.internal", "http://100.100.1.1",
  ];
  for (const u of flagged) assert.equal(isInsecureUrl(u), true, u);
  for (const u of clean) assert.equal(isInsecureUrl(u), false, u);
  assert.equal(isInsecureUrl("http://172.32.0.1"), true);
  assert.equal(isInsecureUrl("http://100.128.0.1"), true);
});

test("2FA domain match on label boundaries", () => {
  const domains = new Set(["github.com", "amazon.co.uk"]);
  assert.equal(twoFactorDomainFor("https://github.com/login", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://login.github.com", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://GitHub.com./", domains), "github.com");
  assert.equal(twoFactorDomainFor("github.com", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://www.amazon.co.uk", domains), "amazon.co.uk");
  assert.equal(twoFactorDomainFor("https://github.com.evil.example", domains), null);
  assert.equal(twoFactorDomainFor("https://notgithub.com", domains), null);
  assert.equal(twoFactorDomainFor("", domains), null);
  assert.equal(twoFactorDomainFor("::::", domains), null);
  assert.equal(twoFactorDomainFor("github.com:443/login", domains), "github.com");
});

const tick = () => new Promise((r) => setTimeout(r, 5));

async function fixture() {
  const vault = await KeePassVault.createNew(new Uint8Array(32).fill(9));
  const groupUuid = vault.getLiveGroups()[0].uuid;
  const add = (title: string, password: string, extra: Partial<{ url: string; totpSeed: string; expiresAt: Date }> = {}) =>
    vault.createEntry({ title, password, username: "", url: "", notes: "", groupUuid, ...extra });
  return { vault, add };
}

async function deps(over: Partial<ReportDeps> = {}): Promise<ReportDeps> {
  return {
    strength: await loadStrengthChecker(),
    twoFactorDomains: new Set(["github.com"]),
    breached: null,
    cache: new Map(),
    signal: new AbortController().signal,
    ...over,
  };
}

test("each category is detected and recycled entries are ignored", async () => {
  const { vault, add } = await fixture();
  const strong = "correct-horse-battery-staple-91";
  const reusedA = add("Reused A", "another-long-unique-phrase-7");
  const reusedB = add("Reused B", "another-long-unique-phrase-7");
  const weak = add("Weak", "Password1234!");
  const empty = add("Empty", "");
  const http = add("Http", strong + "a", { url: "http://shop.example" });
  const no2fa = add("GitHub", strong + "b", { url: "https://github.com" });
  add("GitHub with TOTP", strong + "c", { url: "https://github.com", totpSeed: "JBSWY3DPEHPK3PXP" });
  const expired = add("Expired", strong + "d", { expiresAt: new Date(Date.now() - 1000) });
  const expiring = add("Expiring", strong + "e", { expiresAt: new Date(Date.now() + 5 * 86_400_000) });
  const recycled = add("Recycled", "Password1234!", { url: "http://shop.example" });
  vault.deleteEntry(recycled.uuid);

  const r = await buildWatchtowerReport(vault, await deps());
  const ids = (c: (typeof CATEGORIES)[number]) => r.categories[c].map((f) => f.uuid).sort();
  assert.deepEqual(ids("reused"), [reusedA.uuid, reusedB.uuid].sort());
  assert.deepEqual(ids("weak"), [weak.uuid, empty.uuid].sort());
  assert.deepEqual(ids("insecureUrl"), [http.uuid]);
  assert.deepEqual(ids("missing2fa"), [no2fa.uuid]);
  assert.deepEqual(ids("expired"), [expired.uuid]);
  assert.deepEqual(ids("expiring"), [expiring.uuid]);
  assert.deepEqual(ids("breached"), []);
  assert.equal(r.breachChecked, false);
  assert.equal(r.categories.weak.find((f) => f.uuid === empty.uuid)?.detail, "empty");
});

test("serialised report contains no secret", async () => {
  const { vault, add } = await fixture();
  add("A", "Password1234!", { totpSeed: "JBSWY3DPEHPK3PXP" });
  add("B", "Password1234!");
  const e = add("C", "hunter2-hunter2");
  vault.updateEntry({ ...e, custom: [{ name: "PIN", value: "secret-pin-4242", protected: true }] });
  const json = JSON.stringify(await buildWatchtowerReport(vault, await deps()));
  for (const secret of ["Password1234!", "JBSWY3DPEHPK3PXP", "hunter2-hunter2", "secret-pin-4242"]) {
    assert.equal(json.includes(secret), false, secret);
  }
});

test("score arithmetic", () => {
  const empty = Object.fromEntries(CATEGORIES.map((c) => [c, []])) as unknown as Parameters<typeof scoreReport>[0];
  const f = { uuid: "u", title: "t", detail: "d" };
  assert.equal(scoreReport(empty, 0), null);
  assert.equal(scoreReport(empty, 10), 100);
  assert.equal(scoreReport({ ...empty, weak: [f] }, 10), 95);              // 2 / 40
  assert.equal(scoreReport({ ...empty, breached: [f], reused: [f, f] }, 10), 75); // 10 / 40
  assert.equal(scoreReport({ ...empty, expiring: [f, f, f] }, 3), 100);
  assert.equal(scoreReport({ ...empty, breached: [f, f], reused: [f, f] }, 1), 0); // clamped
});

test("empty vault scores null", async () => {
  const { vault, add } = await fixture();
  const e = add("Gone", "x");
  vault.deleteEntry(e.uuid);
  const r = await buildWatchtowerReport(vault, await deps());
  assert.equal(r.score, null);
});

test("strength cache rescoring only edited entries", async () => {
  const { vault, add } = await fixture();
  const a = add("A", "Password1234!");
  add("B", "correct-horse-battery-staple-91");
  const real = await loadStrengthChecker();
  const seen: string[] = [];
  const strength = (p: string) => { seen.push(p); return real(p); };
  const cache: StrengthCache = new Map();
  await buildWatchtowerReport(vault, await deps({ strength, cache }));
  assert.equal(seen.length, 2);
  await tick();
  vault.updateEntry({ ...a, password: "another-long-unique-phrase-7" });
  seen.length = 0;
  const r = await buildWatchtowerReport(vault, await deps({ strength, cache }));
  assert.deepEqual(seen, ["another-long-unique-phrase-7"]);
  assert.equal(r.categories.weak.length, 0);
});

test("breach results apply only while the entry is unchanged", async () => {
  const { vault, add } = await fixture();
  const a = add("A", "password");
  add("B", "unique-and-safe-xyz-123");
  const fetchFn = (async () => new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\n")) as unknown as typeof fetch;
  const progress: number[] = [];
  const breached = await runBreachCheck(vault, new AbortController().signal, (done) => progress.push(done), fetchFn);
  assert.deepEqual(progress, [0, 1, 2]);
  let r = await buildWatchtowerReport(vault, await deps({ breached }));
  assert.equal(r.breachChecked, true);
  assert.deepEqual(r.categories.breached.map((f) => [f.uuid, f.detail]), [[a.uuid, "seen 7 times"]]);
  await tick();
  vault.updateEntry({ ...a, password: "now-a-different-long-phrase" }); // edited entry drops a stale breach
  r = await buildWatchtowerReport(vault, await deps({ breached }));
  assert.equal(r.categories.breached.length, 0);
});

test("aborted signal stops the build", async () => {
  const { vault, add } = await fixture();
  for (let i = 0; i < 5; i++) add(`E${i}`, `pw-${i}`);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(buildWatchtowerReport(vault, await deps({ signal: controller.signal })), { name: "AbortError" });
});
