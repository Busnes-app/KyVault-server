// Registrable-domain heuristic for ranking popup entries by site.
// ponytail: this is a suffix heuristic, not the Public Suffix List; a site under an
// unlisted multi-label suffix (example.github.io) ranks its neighbours as matches.
// Upgrade path: vendor the PSL's ICANN section as a generated module like effWordlist.ts
// when a report shows it matters.
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
