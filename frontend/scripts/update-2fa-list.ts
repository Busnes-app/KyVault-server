import { writeFileSync } from "node:fs";
import { extractDomains, renderDomainsModule } from "../src/lib/twoFactorList.ts";

const res = await fetch("https://api.2fa.directory/v3/totp.json");
if (!res.ok) throw new Error(`2fa.directory: HTTP ${res.status}`);
const domains = extractDomains(await res.json());
const out = new URL("../src/lib/twoFactorDomains.ts", import.meta.url);
writeFileSync(out, renderDomainsModule(domains, new Date().toISOString().slice(0, 10)));
console.log(`wrote ${domains.length} domains to ${out.pathname}`);
