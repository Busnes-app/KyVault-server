// Registrable-domain heuristic for RANKING popup entries by site. It never authorizes a
// fill: see mayFill. ponytail: this is a suffix heuristic, not the Public Suffix List; a
// site under an unlisted multi-label suffix (example.github.io) ranks its neighbours as
// matches. Upgrade path: vendor the PSL's ICANN and PRIVATE sections as a generated
// module like effWordlist.ts when ranking quality shows it matters.
const SECOND_LEVEL = new Set(
  "co.uk org.uk gov.uk ac.uk me.uk co.jp ne.jp or.jp ac.jp com.au net.au org.au edu.au co.nz org.nz com.br net.br co.za org.za com.mx com.ar com.tr com.sg com.hk co.kr co.in co.id com.my com.ph".split(
    " ",
  ),
);

export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || /^\d+(\.\d+){3}$/.test(host)) return host;
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const take = SECOND_LEVEL.has(labels.slice(-2).join(".")) ? 3 : 2;
  return labels.slice(-take).join(".");
}

export function sameSite(a: string, b: string): boolean {
  return registrableDomain(a) === registrableDomain(b);
}

// mayFill decides whether a login saved for entryHost may be filled into a page at
// pageHost: the hosts must be the same, nothing else. No suffix guessing, and no
// subdomain inheritance either: a service that hosts user sites under its own domain
// (tenant.neocities.org) must not hand the service login to a tenant page. Tenants under
// a shared suffix (victim.github.io and evil.github.io) never authorize each other.
// ponytail: an entry can name only one host; per-entry extra hosts are the upgrade path.
export function mayFill(entryHost: string, pageHost: string): boolean {
  const entry = entryHost.toLowerCase().replace(/\.$/, "");
  const page = pageHost.toLowerCase().replace(/\.$/, "");
  return entry !== "" && page === entry;
}
