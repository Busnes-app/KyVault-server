import type { KeePassVault } from "./kdbx";
import { findReusedPasswords } from "./passwordReuse";
import { isExpired, expiresWithin } from "./entryMeta";

export const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";

export type HealthReport = {
  weak: Array<{ uuid: string; title: string; reason: string }>;
  reused: Array<{ uuid: string; title: string; count: number }>;
  expired: Array<{ uuid: string; title: string }>;
  expiring: Array<{ uuid: string; title: string }>;
};

// Length/class heuristic only, deliberately not zxcvbn. Passwords never leave this function.
export function passwordWeakness(password: string): string | null {
  if (password === "") return "empty";
  if (password.length < 12) return "shorter than 12 characters";
  if (/^(.)\1*$/.test(password)) return "repeats one character";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes === 1) return "only one kind of character";
  if (classes === 2 && password.length < 16) return "fewer than 16 characters with two kinds";
  return null;
}

export function buildHealthReport(vault: KeePassVault, now = new Date()): HealthReport {
  const reusedCounts = findReusedPasswords(vault);
  const report: HealthReport = { weak: [], reused: [], expired: [], expiring: [] };
  for (const entry of vault.getLiveEntries()) {
    const reason = passwordWeakness(entry.password);
    if (reason) report.weak.push({ uuid: entry.uuid, title: entry.title, reason });
    const count = reusedCounts.get(entry.uuid);
    if (count) report.reused.push({ uuid: entry.uuid, title: entry.title, count });
    if (isExpired(entry, now)) report.expired.push({ uuid: entry.uuid, title: entry.title });
    else if (expiresWithin(entry, 30, now)) report.expiring.push({ uuid: entry.uuid, title: entry.title });
  }
  return report;
}

export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export const hibpPrefix = (hashHex: string): string => hashHex.slice(0, 5);
export const hibpSuffix = (hashHex: string): string => hashHex.slice(5);

export function parseRangeResponse(body: string, suffix: string): number {
  const want = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [s, n] = line.split(":");
    if (s?.toUpperCase() === want) return Number.parseInt(n ?? "0", 10) || 0;
  }
  return 0;
}

// One request per distinct password, sequential, opt-in per caller. Only the 5-char
// SHA-1 prefix leaves the browser; the password and its remaining hash never do.
export async function checkBreached(
  passwords: Map<string, string[]>,
  signal: AbortSignal,
  fetchFn: typeof fetch = fetch,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const [password, uuids] of passwords) {
    const hash = await sha1Hex(password);
    const res = await fetchFn(HIBP_RANGE_URL + hibpPrefix(hash), {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      signal,
    });
    if (!res.ok) throw new Error(`HIBP range request failed: ${res.status}`);
    const count = parseRangeResponse(await res.text(), hibpSuffix(hash));
    if (count > 0) for (const uuid of uuids) out.set(uuid, count);
  }
  return out;
}
