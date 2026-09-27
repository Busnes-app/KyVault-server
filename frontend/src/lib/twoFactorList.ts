const DOMAIN = /^[a-z0-9.-]+\.[a-z]{2,}$/;

// Parses 2fa.directory v3 totp.json: an array of [name, { domain, "additional-domains"? }].
export function extractDomains(json: unknown): string[] {
  if (!Array.isArray(json)) throw new Error("2fa.directory feed: expected an array");
  const out = new Set<string>();
  for (const item of json) {
    const info = Array.isArray(item) ? item[1] : undefined;
    if (!info || typeof info.domain !== "string") throw new Error("2fa.directory feed: entry without a domain");
    const extra: unknown[] = Array.isArray(info["additional-domains"]) ? info["additional-domains"] : [];
    for (const raw of [info.domain, ...extra]) {
      if (typeof raw !== "string") continue;
      const d = raw.trim().toLowerCase().replace(/\.$/, "");
      if (DOMAIN.test(d)) out.add(d);
    }
  }
  return [...out].sort();
}

export function renderDomainsModule(domains: string[], fetchedOn: string): string {
  return `// Sites supporting TOTP, from 2fa.directory (MIT, https://github.com/2factorauth/twofactorauth).
// Fetched ${fetchedOn} from https://api.2fa.directory/v3/totp.json by scripts/update-2fa-list.ts; do not edit by hand.
export const TWO_FACTOR_DOMAINS: readonly string[] = ${JSON.stringify(domains)};
`;
}
