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
  if (host.startsWith("[")) return isLocalIPv6(host.slice(1, -1));
  const v4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  return v4 ? isLocalIPv4(v4.slice(1).map(Number)) : false;
}

// http:// to a public host. LAN devices (routers, NAS) often have no HTTPS and are not flagged.
export function isInsecureUrl(raw: string): boolean {
  const url = parseUrl(raw);
  return url !== null && url.protocol === "http:" && !isLocalHost(bareHost(url));
}

// KeePass URLs are often stored without a scheme; assume https for the host lookup only.
export function twoFactorDomainFor(raw: string, domains: ReadonlySet<string>): string | null {
  const text = raw.trim();
  const url = parseUrl(/^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`);
  if (!url || !url.hostname) return null;
  for (let d = bareHost(url); d.includes("."); d = d.slice(d.indexOf(".") + 1)) {
    if (domains.has(d)) return d;
  }
  return null;
}
