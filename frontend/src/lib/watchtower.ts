import type { KeePassVault, VaultEntry } from "./kdbx";
import type { StrengthChecker } from "./passwordStrength";
import { findReusedPasswords } from "./passwordReuse";
import { isExpired, expiresWithin } from "./entryMeta";
import { checkBreached } from "./hibp";

function parseUrl(raw: string): URL | null {
  try { return new URL(raw.trim()); } catch { return null; }
}

const bareHost = (url: URL) => url.hostname.toLowerCase().replace(/\.$/, "");

function isLocalIPv4([a, b]: number[]): boolean {
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

// Addresses arrive normalised by URL: IPv4-mapped IPv6 becomes ::ffff:c0a8:101.
function isLocalIPv6(addr: string): boolean {
  if (addr === "::1") return true;
  const mapped = addr.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const hi = parseInt(mapped[1], 16), lo = parseInt(mapped[2], 16);
    return isLocalIPv4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
  }
  const first = parseInt(addr.split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

function isLocalHost(host: string): boolean {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host.endsWith(".lan") || host.endsWith(".home.arpa") || host.endsWith(".internal")) return true;
  if (host.startsWith("[")) return isLocalIPv6(host.slice(1, -1));
  const v4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = v4.slice(1).map(Number);
    if (a === 100 && b >= 64 && b <= 127) return true;
    return isLocalIPv4(v4.slice(1).map(Number));
  }
  // Bare hostnames (no dot) are homelab devices, e.g. "nas" reached via mDNS or /etc/hosts.
  return !host.includes(".");
}

// http:// to a public host. LAN devices (routers, NAS) often have no HTTPS and are not flagged.
export function isInsecureUrl(raw: string): boolean {
  const url = parseUrl(raw);
  return url !== null && url.protocol === "http:" && !isLocalHost(bareHost(url));
}

// KeePass URLs are often stored without a scheme; assume https for the host lookup only.
export function twoFactorDomainFor(raw: string, domains: ReadonlySet<string>): string | null {
  const text = raw.trim();
  const url = parseUrl(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  if (!url || !url.hostname) return null;
  for (let d = bareHost(url); d.includes("."); d = d.slice(d.indexOf(".") + 1)) {
    if (domains.has(d)) return d;
  }
  return null;
}

export const CATEGORIES = ["breached", "reused", "weak", "insecureUrl", "missing2fa", "expired", "expiring"] as const;
export type Category = (typeof CATEGORIES)[number];
export type Finding = { uuid: string; title: string; detail: string };
export type WatchtowerReport = { score: number | null; breachChecked: boolean; categories: Record<Category, Finding[]> };

const WEIGHTS: Record<Category, number> = { breached: 4, reused: 3, weak: 2, insecureUrl: 1, missing2fa: 1, expired: 1, expiring: 0 };

// Keyed by entry uuid and stamped with its updatedAt, so an edit invalidates the result.
export type BreachResults = Map<string, { count: number; updatedAt: number }>;
export type StrengthCache = Map<string, { updatedAt: number; weak: string | null }>;

export type ReportDeps = {
  strength: StrengthChecker;
  twoFactorDomains: ReadonlySet<string>;
  breached: BreachResults | null;
  cache: StrengthCache;
  signal: AbortSignal;
  now?: Date;
};

export function scoreCounts(counts: Record<Category, number>, liveEntries: number): number | null {
  if (liveEntries === 0) return null;
  const penalty = CATEGORIES.reduce((sum, c) => sum + WEIGHTS[c] * counts[c], 0);
  return Math.round(100 * (1 - Math.min(1, penalty / (liveEntries * 4))));
}
export function scoreReport(categories: Record<Category, Finding[]>, liveEntries: number): number | null {
  return scoreCounts(Object.fromEntries(CATEGORIES.map(c => [c, categories[c].length])) as Record<Category, number>, liveEntries);
}

function weakness(entry: VaultEntry, updatedAt: number, deps: ReportDeps): string | null {
  const hit = deps.cache.get(entry.uuid);
  if (hit && hit.updatedAt === updatedAt) return hit.weak;
  let weak: string | null = null;
  if (entry.password === "") weak = "empty";
  else {
    const r = deps.strength(entry.password);
    if (r.score <= 2) weak = r.warning || "easy to guess";
  }
  deps.cache.set(entry.uuid, { updatedAt, weak });
  return weak;
}

// Yield to the UI every ~10 ms so a large vault never freezes the page.
export async function buildWatchtowerReport(vault: KeePassVault, deps: ReportDeps): Promise<WatchtowerReport> {
  deps.signal.throwIfAborted();
  const now = deps.now ?? new Date();
  const entries = vault.getLiveEntries();
  const reused = findReusedPasswords(vault);
  const categories = Object.fromEntries(CATEGORIES.map((c) => [c, []])) as unknown as Record<Category, Finding[]>;
  let sliceStart = performance.now();
  for (const entry of entries) {
    if (performance.now() - sliceStart > 10) {
      await new Promise((r) => setTimeout(r, 0));
      deps.signal.throwIfAborted();
      sliceStart = performance.now();
    }
    const add = (c: Category, detail: string) => categories[c].push({ uuid: entry.uuid, title: entry.title, detail });
    const updatedAt = entry.updatedAt.getTime();
    const breach = deps.breached?.get(entry.uuid);
    if (breach && breach.updatedAt === updatedAt) add("breached", `seen ${breach.count.toLocaleString()} times`);
    const count = reused.get(entry.uuid);
    if (count) add("reused", `used ${count} times`);
    const weak = weakness(entry, updatedAt, deps);
    if (weak) add("weak", weak);
    if (isInsecureUrl(entry.url)) add("insecureUrl", "uses http://");
    if (!entry.totpSeed) {
      const domain = twoFactorDomainFor(entry.url, deps.twoFactorDomains);
      if (domain) add("missing2fa", `${domain} supports TOTP`);
    }
    if (isExpired(entry, now)) add("expired", "expired");
    else if (expiresWithin(entry, 30, now)) add("expiring", "expires within 30 days");
  }
  return { score: scoreReport(categories, entries.length), breachChecked: deps.breached !== null, categories };
}

// One HIBP range request per distinct password; results stamped with each entry's updatedAt.
export async function runBreachCheck(
  vault: KeePassVault,
  signal: AbortSignal,
  onProgress: (done: number, total: number) => void,
  fetchFn: typeof fetch = fetch,
): Promise<BreachResults> {
  const byPassword = new Map<string, string[]>();
  const stamps = new Map<string, number>();
  for (const e of vault.getLiveEntries()) {
    if (e.password === "") continue;
    stamps.set(e.uuid, e.updatedAt.getTime());
    const uuids = byPassword.get(e.password);
    if (uuids) uuids.push(e.uuid);
    else byPassword.set(e.password, [e.uuid]);
  }
  let done = 0;
  onProgress(0, byPassword.size);
  const tracked: typeof fetch = async (...args) => {
    const res = await fetchFn(...args);
    onProgress(++done, byPassword.size);
    return res;
  };
  const hits = await checkBreached(byPassword, signal, tracked);
  return new Map([...hits].map(([uuid, count]) => [uuid, { count, updatedAt: stamps.get(uuid)! }]));
}
