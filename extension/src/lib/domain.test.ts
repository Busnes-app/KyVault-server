import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain, sameSite, mayFill } from "./domain";

test("last two labels, or three under a listed second-level suffix", () => {
  assert.equal(registrableDomain("login.accounts.example.com"), "example.com");
  assert.equal(registrableDomain("Example.COM."), "example.com");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("shop.example.com.au"), "example.com.au");
  assert.equal(registrableDomain("localhost"), "localhost");
  assert.equal(registrableDomain("10.0.0.5"), "10.0.0.5");
  assert.equal(registrableDomain("[::1]"), "[::1]");
});

test("sameSite is registrable-domain equality", () => {
  assert.equal(sameSite("id.example.com", "www.example.com"), true);
  assert.equal(sameSite("example.com", "example.co"), false);
  assert.equal(sameSite("evil-example.com", "example.com"), false);
});

test("mayFill is exact host equality: no shared-suffix neighbours, no tenant subdomains", () => {
  assert.equal(mayFill("example.com", "example.com"), true);
  assert.equal(mayFill("EXAMPLE.com", "Example.COM."), true);
  // A service that hosts user sites under its domain: the tenant must not get the login.
  assert.equal(mayFill("neocities.org", "evil.neocities.org"), false);
  assert.equal(mayFill("example.com", "mail.example.com"), false);
  // Private suffix: two tenants that sameSite treats as one site.
  assert.equal(sameSite("victim.github.io", "evil.github.io"), true);
  assert.equal(mayFill("victim.github.io", "evil.github.io"), false);
  // A public suffix the heuristic does not list: two registrants.
  assert.equal(mayFill("bank.co.zw", "evil.co.zw"), false);
  assert.equal(mayFill("login.example.com", "example.com"), false);
  assert.equal(mayFill("example.com", "notexample.com"), false);
  assert.equal(mayFill("", "example.com"), false);
});
