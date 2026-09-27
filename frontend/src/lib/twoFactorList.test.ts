import { test } from "node:test";
import assert from "node:assert/strict";
import { extractDomains, renderDomainsModule } from "./twoFactorList";
import { TWO_FACTOR_DOMAINS } from "./twoFactorDomains";

const fixture = [
  ["GitHub", { domain: "GitHub.com", tfa: ["totp", "u2f"], "additional-domains": ["github.io"] }],
  ["Dupe", { domain: "github.com", tfa: ["totp"] }],
  ["Amazon", { domain: "amazon.com", tfa: ["totp"] }],
];

test("extractDomains lowercases, dedupes, sorts and includes additional domains", () => {
  assert.deepEqual(extractDomains(fixture), ["amazon.com", "github.com", "github.io"]);
});

test("extractDomains rejects a changed feed shape loudly", () => {
  assert.throws(() => extractDomains({}), /array/);
  assert.throws(() => extractDomains([["x", { tfa: ["totp"] }]]), /domain/);
});

test("rendered module names its source and exports the list", () => {
  const src = renderDomainsModule(["a.com"], "2026-09-26");
  assert.match(src, /2fa\.directory/);
  assert.match(src, /MIT/);
  assert.match(src, /export const TWO_FACTOR_DOMAINS: readonly string\[\] = \["a\.com"\];/);
});

test("committed list is sorted, lowercase and non-trivial", () => {
  assert.ok(TWO_FACTOR_DOMAINS.length > 1000);
  assert.ok(TWO_FACTOR_DOMAINS.includes("github.com"));
  assert.deepEqual([...TWO_FACTOR_DOMAINS].sort(), TWO_FACTOR_DOMAINS);
  assert.ok(TWO_FACTOR_DOMAINS.every((d) => d === d.toLowerCase()));
});
