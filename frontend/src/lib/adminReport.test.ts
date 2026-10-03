import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encryptSummary,
  decryptSummary,
  keyDigest,
  encodeSummary,
  decodeSummary,
  aggregateReports,
  projectReport,
  type Summary,
  type ReportConfig,
} from "./adminReport";
import { b64, generateUserKey } from "./userKey";
import { buildWatchtowerReport, CATEGORIES } from "./watchtower";
import { loadStrengthChecker } from "./passwordStrength";
import { KeePassVault } from "./kdbx";
const summary: Summary = {
  schema: "kyvault/admin-summary/1",
  algorithm: "watchtower/1",
  computedAt: "2026-10-03T12:00:00.000Z",
  liveEntries: 0,
  score: null,
  breachStatus: "not-run",
  counts: {
    breached: null,
    reused: 0,
    weak: 0,
    insecureUrl: 0,
    missing2fa: 0,
    expired: 0,
    expiring: 0,
  },
};
function padded(text: string) {
  const raw = new TextEncoder().encode(text),
    bytes = new Uint8Array(2048);
  new DataView(bytes.buffer).setUint16(0, raw.length);
  bytes.set(raw, 2);
  return bytes;
}
test("summary codec rejects duplicate/unknown fields, invalid counts, scores, dates, padding and lengths", () => {
  assert.deepEqual(decodeSummary(encodeSummary(summary)), summary);
  const json = JSON.stringify(summary);
  for (const value of [
    json.replace('"schema":', '"secret":"password","schema":'),
    json.replace('"score":null', '"score":null,"score":null'),
    json.replace('"weak":0', '"weak":-1'),
    json.replace('"weak":0', '"weak":1'),
    json.replace('"breached":null', '"breached":0'),
    json.replace('"score":null', '"score":100'),
    json.replace("2026-10-03", "2026-02-30"),
    json.replace('"liveEntries":0', '"liveEntries":1.5'),
  ])
    assert.throws(() => decodeSummary(padded(value)));
  const bytes = encodeSummary(summary);
  bytes[2047] = 1;
  assert.throws(() => decodeSummary(bytes));
  assert.throws(() => decodeSummary(bytes.slice(1)));
});
test("real vault count projection, HPKE roundtrip and every context boundary", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32)),
    recipient = await generateUserKey(),
    other = await generateUserKey();
  try {
    const vault = await KeePassVault.createNew(key),
      groupUuid = vault.getLiveGroups()[0].uuid;
    const e = vault.createEntry({
      title: "secret title 5632",
      username: "private user",
      password: "Password1234!",
      url: "https://private.example",
      notes: "secret note",
      totpSeed: "JBSWY3DPEHPK3PXP",
      groupUuid,
    });
    const snapshot = await KeePassVault.open(await vault.exportBinary(), key);
    const report = await buildWatchtowerReport(snapshot, {
      strength: await loadStrengthChecker(),
      twoFactorDomains: new Set(),
      cache: new Map(),
      breached: null,
      signal: new AbortController().signal,
    });
    const projected = projectReport(report, 1),
      json = JSON.stringify(projected);
    for (const secret of [
      e.uuid,
      e.title,
      e.username,
      e.password,
      e.url,
      e.notes,
      e.totpSeed!,
    ])
      assert.equal(json.includes(secret), false);
    assert.equal(projected.counts.weak, 1);
    assert.equal(projected.counts.breached, null);
    const config: ReportConfig = {
      instanceId: "11".repeat(16),
      generation: "22".repeat(16),
      enabled: true,
      recipientId: "admin",
      publicKey: b64.encode(recipient.publicKey),
      keyDigest: await keyDigest(recipient.publicKey),
    };
    const record = await encryptSummary(projected, config, "user", 1);
    assert.equal(b64.decode(record.sealed!).length, 3184);
    assert.deepEqual(
      await decryptSummary(record, config, recipient.seed),
      projected,
    );
    await assert.rejects(decryptSummary(record, config, other.seed));
    for (const field of [
      "instanceId",
      "generation",
      "sourceId",
      "version",
      "reportId",
      "recipientId",
      "keyDigest",
    ] as const) {
      const altered = {
        ...record,
        [field]:
          field === "version"
            ? 2
            : field === "sourceId"
              ? "other"
              : field === "recipientId"
                ? "other"
                : "00".repeat(field === "keyDigest" ? 32 : 16),
      };
      await assert.rejects(decryptSummary(altered, config, recipient.seed));
    }
    const bytes = b64.decode(record.sealed!);
    bytes[bytes.length - 1] ^= 1;
    await assert.rejects(
      decryptSummary(
        { ...record, sealed: b64.encode(bytes) },
        config,
        recipient.seed,
      ),
    );
    assert.notEqual(
      (await encryptSummary(projected, config, "user", 1)).sealed,
      record.sealed,
    );
    const aggregate = aggregateReports([
      { status: "current", summary: projected },
      { status: "stale-version", summary: projected },
      { status: "not-submitted" },
    ]);
    assert.equal(aggregate.current, 1);
    assert.equal(aggregate.missing, 2);
    assert.equal(aggregate.breachChecked, 0);
    assert.equal(aggregate.liveEntries, 1);
  } finally {
    key.fill(0);
    recipient.seed.fill(0);
    other.seed.fill(0);
  }
});
