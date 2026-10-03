// Design experiment only, not a runtime codec. Run from frontend:
// npx --no-install tsx scripts/check-admin-report-design.ts
import assert from "node:assert/strict";
import { KeePassVault } from "../src/lib/kdbx";
import { buildWatchtowerReport, CATEGORIES } from "../src/lib/watchtower";
import { loadStrengthChecker } from "../src/lib/passwordStrength";
import { generateUserKey, seal, open } from "../src/lib/userKey";

const vaultKey = crypto.getRandomValues(new Uint8Array(32));
const recipient = await generateUserKey(), stranger = await generateUserKey();
let plaintext: Uint8Array | undefined, decrypted: Uint8Array | undefined;
try {
  const vault = await KeePassVault.createNew(vaultKey);
  const groupUuid = vault.getLiveGroups()[0].uuid;
  const markers = ["Confidential title 39204", "private-user-28402", "Password1234!", "JBSWY3DPEHPK3PXP", "https://private.example/unique-5823", "Secret note 23510"];
  const entry = vault.createEntry({ title: markers[0], username: markers[1], password: markers[2], totpSeed: markers[3], url: markers[4], notes: markers[5], groupUuid });
  vault.createEntry({ title: "Other secret title", username: "other", password: markers[2], url: "", notes: "", groupUuid });
  const snapshot = await KeePassVault.open(await vault.exportBinary(), vaultKey);
  const report = await buildWatchtowerReport(snapshot, {
    strength: await loadStrengthChecker(), twoFactorDomains: new Set<string>(),
    breached: null, cache: new Map(), signal: new AbortController().signal,
  });
  const summary = {
    schema: "kyvault/admin-summary/1", algorithm: "watchtower/1", computedAt: new Date().toISOString(),
    liveEntries: snapshot.getLiveEntries().length, score: report.score, breachStatus: "not-run",
    counts: {
      breached: null, reused: report.categories.reused.length, weak: report.categories.weak.length,
      insecureUrl: report.categories.insecureUrl.length, missing2fa: report.categories.missing2fa.length,
      expired: report.categories.expired.length, expiring: report.categories.expiring.length,
    },
  };
  assert.equal(summary.counts.reused, 2);
  assert.equal(summary.counts.weak, 2);
  assert.equal(summary.liveEntries, 2);
  assert.equal(summary.score, 0);
  assert.equal(summary.counts.breached, null);
  assert.deepEqual(Object.keys(summary.counts).sort(), [...CATEGORIES].sort());
  const encoded = new TextEncoder().encode(JSON.stringify(summary));
  for (const value of [...markers, entry.uuid, "Other secret title"]) assert.equal(new TextDecoder().decode(encoded).includes(value), false, value);
  assert.deepEqual(Object.keys(summary).sort(), ["schema", "algorithm", "computedAt", "liveEntries", "score", "breachStatus", "counts"].sort());
  assert(encoded.length <= 2046);
  plaintext = new Uint8Array(2048);
  new DataView(plaintext.buffer).setUint16(0, encoded.length);
  plaintext.set(encoded, 2);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(recipient.publicKey)));
  const digestHex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  const context = ["kyvault/admin-report/1", "11".repeat(16), "22".repeat(16), "source-u1", "personal", "5", "33".repeat(16), "recipient-u2", digestHex];
  const info = JSON.stringify(context), sealed = await seal(recipient.publicKey, info, plaintext);
  assert.equal(sealed.length, 3184);
  assert.notDeepEqual(await seal(recipient.publicKey, info, plaintext), sealed);
  decrypted = await open(recipient.seed, info, sealed);
  assert.deepEqual(decrypted, plaintext);
  const size = new DataView(decrypted.buffer, decrypted.byteOffset).getUint16(0);
  assert(decrypted.slice(2 + size).every((b) => b === 0));
  assert.deepEqual(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decrypted.slice(2, 2 + size))), summary);
  await assert.rejects(open(stranger.seed, info, sealed));
  for (let i = 0; i < context.length; i++) {
    const changed = [...context]; changed[i] += "x";
    await assert.rejects(open(recipient.seed, JSON.stringify(changed), sealed));
  }
  const tampered = sealed.slice(); tampered[tampered.length - 1] ^= 1;
  await assert.rejects(open(recipient.seed, info, tampered));
  console.log("PASS: real KDBX/Watchtower counts; no entry data; fixed 3184-byte randomized X-Wing seal; round-trip; wrong recipient, every context field and tampering refused.");
} finally {
  vaultKey.fill(0); recipient.seed.fill(0); stranger.seed.fill(0);
  plaintext?.fill(0); decrypted?.fill(0);
}
