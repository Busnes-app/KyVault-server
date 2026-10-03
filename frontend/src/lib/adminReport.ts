import { b64, seal, open, PUBLIC_KEY_BYTES } from "./userKey";
import {
  CATEGORIES,
  scoreCounts,
  type Category,
  type WatchtowerReport,
} from "./watchtower";

export const REPORT_BYTES = 3184;
export type ReportConfig = {
  instanceId: string;
  generation: string;
  enabled: boolean;
  recipientId?: string;
  recipientName?: string;
  publicKey?: string;
  keyDigest?: string;
};
export type ReportRecord = {
  instanceId: string;
  generation: string;
  sourceId: string;
  version: number;
  reportId: string;
  recipientId: string;
  keyDigest: string;
  sealed?: string;
  receivedAt?: string;
};
export type Summary = {
  schema: "kyvault/admin-summary/1";
  algorithm: "watchtower/1";
  computedAt: string;
  liveEntries: number;
  score: number | null;
  breachStatus: "not-run" | "complete";
  counts: Record<Category, number | null>;
};
export type CoverageRow = {
  userId: string;
  username: string;
  status: string;
  record?: ReportRecord;
};
export type ReportPage = {
  config: ReportConfig;
  rows: CoverageRow[];
  next: string;
};
const encoder = new TextEncoder(),
  decoder = new TextDecoder("utf-8", { fatal: true });
const hex = (s: unknown, n: number): s is string =>
  typeof s === "string" && new RegExp(`^[0-9a-f]{${n}}$`).test(s);
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const invalid = () => new Error("Unreadable or unsupported report.");
export async function keyDigest(publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== PUBLIC_KEY_BYTES) throw invalid();
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(publicKey)),
    ),
  ]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
export function context(r: ReportRecord): string {
  if (
    !hex(r.instanceId, 32) ||
    !hex(r.generation, 32) ||
    !hex(r.reportId, 32) ||
    !hex(r.keyDigest, 64) ||
    !Number.isSafeInteger(r.version) ||
    r.version < 1 ||
    [r.sourceId, r.recipientId].some(
      (id) => typeof id !== "string" || !id || encoder.encode(id).length > 128,
    )
  )
    throw invalid();
  return JSON.stringify([
    "kyvault/admin-report/1",
    r.instanceId,
    r.generation,
    r.sourceId,
    "personal",
    String(r.version),
    r.reportId,
    r.recipientId,
    r.keyDigest,
  ]);
}
export function projectReport(
  report: WatchtowerReport,
  liveEntries: number,
): Summary {
  const counts = Object.fromEntries(
    CATEGORIES.map((c) => [
      c,
      c === "breached" && !report.breachChecked
        ? null
        : report.categories[c].length,
    ]),
  ) as Record<Category, number | null>;
  return {
    schema: "kyvault/admin-summary/1",
    algorithm: "watchtower/1",
    computedAt: new Date().toISOString(),
    liveEntries,
    score: report.score,
    breachStatus: report.breachChecked ? "complete" : "not-run",
    counts,
  };
}
function validate(raw: unknown): Summary {
  if (
    !object(raw) ||
    raw.schema !== "kyvault/admin-summary/1" ||
    raw.algorithm !== "watchtower/1" ||
    typeof raw.computedAt !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(raw.computedAt) ||
    !Number.isFinite(Date.parse(raw.computedAt)) ||
    new Date(raw.computedAt).toISOString() !== raw.computedAt ||
    typeof raw.liveEntries !== "number" ||
    !Number.isSafeInteger(raw.liveEntries) ||
    raw.liveEntries < 0 ||
    !object(raw.counts) ||
    (raw.breachStatus !== "not-run" && raw.breachStatus !== "complete")
  )
    throw invalid();
  const counts = {} as Record<Category, number | null>,
    numeric = {} as Record<Category, number>;
  for (const c of CATEGORIES) {
    const n = raw.counts[c];
    if (c === "breached" && raw.breachStatus === "not-run") {
      if (n !== null) throw invalid();
      counts[c] = null;
      numeric[c] = 0;
    } else {
      if (
        typeof n !== "number" ||
        !Number.isSafeInteger(n) ||
        n < 0 ||
        n > raw.liveEntries
      )
        throw invalid();
      counts[c] = n;
      numeric[c] = n;
    }
  }
  if (raw.score !== scoreCounts(numeric, raw.liveEntries)) throw invalid();
  return {
    schema: raw.schema,
    algorithm: raw.algorithm,
    computedAt: raw.computedAt,
    liveEntries: raw.liveEntries,
    score: raw.score as number | null,
    breachStatus: raw.breachStatus,
    counts,
  };
}
export function encodeSummary(summary: Summary): Uint8Array {
  const clean = validate(summary);
  if (JSON.stringify(summary) !== JSON.stringify(clean)) throw invalid();
  const bytes = encoder.encode(JSON.stringify(clean));
  if (bytes.length > 2046) throw invalid();
  const out = new Uint8Array(2048);
  new DataView(out.buffer).setUint16(0, bytes.length);
  out.set(bytes, 2);
  bytes.fill(0);
  return out;
}
export function decodeSummary(bytes: Uint8Array): Summary {
  if (bytes.length !== 2048) throw invalid();
  const n = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getUint16(0);
  if (n < 2 || n > 2046 || !bytes.subarray(2 + n).every((b) => b === 0))
    throw invalid();
  const json = decoder.decode(bytes.subarray(2, 2 + n));
  const summary = validate(JSON.parse(json));
  // Canonical JSON is required: duplicate/unknown keys and alternate encodings fail.
  if (JSON.stringify(summary) !== json) throw invalid();
  return summary;
}
export async function encryptSummary(
  summary: Summary,
  config: ReportConfig,
  sourceId: string,
  version: number,
): Promise<ReportRecord> {
  if (
    !config.enabled ||
    !config.recipientId ||
    !config.keyDigest ||
    !config.publicKey
  )
    throw new Error("Reporting is disabled.");
  const pk = b64.decode(config.publicKey);
  if ((await keyDigest(pk)) !== config.keyDigest) throw invalid();
  const r: ReportRecord = {
    instanceId: config.instanceId,
    generation: config.generation,
    sourceId,
    version,
    reportId: [...crypto.getRandomValues(new Uint8Array(16))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    recipientId: config.recipientId,
    keyDigest: config.keyDigest,
  };
  const pt = encodeSummary(summary);
  try {
    const blob = await seal(pk, context(r), pt);
    if (blob.length !== REPORT_BYTES) throw invalid();
    return { ...r, sealed: b64.encode(blob) };
  } finally {
    pt.fill(0);
  }
}
export async function decryptSummary(
  r: ReportRecord,
  config: ReportConfig,
  seed: Uint8Array,
): Promise<Summary> {
  if (
    !config.enabled ||
    r.instanceId !== config.instanceId ||
    r.generation !== config.generation ||
    r.recipientId !== config.recipientId ||
    r.keyDigest !== config.keyDigest ||
    !r.sealed
  )
    throw invalid();
  const blob = b64.decode(r.sealed);
  if (blob.length !== REPORT_BYTES || b64.encode(blob) !== r.sealed)
    throw invalid();
  const pt = await open(seed, context(r), blob);
  try {
    return decodeSummary(pt);
  } finally {
    pt.fill(0);
  }
}
export function aggregateReports(
  rows: { summary?: Summary; status: string }[],
) {
  const current = rows
    .filter((r) => r.status === "current" && r.summary)
    .map((r) => r.summary!);
  const counts = Object.fromEntries(
    CATEGORIES.map((c) => [
      c,
      current.reduce((n, r) => n + (r.counts[c] ?? 0), 0),
    ]),
  ) as Record<Category, number>;
  return {
    current: current.length,
    missing: rows.length - current.length,
    liveEntries: current.reduce((n, r) => n + r.liveEntries, 0),
    breachChecked: current.filter((r) => r.breachStatus === "complete").length,
    counts,
  };
}
