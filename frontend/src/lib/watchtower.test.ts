import { test } from "node:test";
import assert from "node:assert/strict";
import { isInsecureUrl, twoFactorDomainFor } from "./watchtower";

test("insecure URL table", () => {
  const flagged = ["http://example.com", "HTTP://Example.COM/login", "http://example.com./", "http://8.8.8.8", "http://[2001:db8::1]"];
  const clean = [
    "https://example.com", "http://localhost:8080", "http://app.localhost", "http://nas.local",
    "http://10.0.0.5", "http://172.16.4.1", "http://172.31.255.1", "http://192.168.1.1", "http://127.0.0.1",
    "http://169.254.1.1", "http://[::1]", "http://[fe80::1]", "http://[fd00::1]", "http://[::ffff:192.168.1.1]",
    "example.com", "", "not a url", "ftp://example.com", "javascript:alert(1)",
  ];
  for (const u of flagged) assert.equal(isInsecureUrl(u), true, u);
  for (const u of clean) assert.equal(isInsecureUrl(u), false, u);
  assert.equal(isInsecureUrl("http://172.32.0.1"), true);
});

test("2FA domain match on label boundaries", () => {
  const domains = new Set(["github.com", "amazon.co.uk"]);
  assert.equal(twoFactorDomainFor("https://github.com/login", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://login.github.com", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://GitHub.com./", domains), "github.com");
  assert.equal(twoFactorDomainFor("github.com", domains), "github.com");
  assert.equal(twoFactorDomainFor("https://www.amazon.co.uk", domains), "amazon.co.uk");
  assert.equal(twoFactorDomainFor("https://github.com.evil.example", domains), null);
  assert.equal(twoFactorDomainFor("https://notgithub.com", domains), null);
  assert.equal(twoFactorDomainFor("", domains), null);
  assert.equal(twoFactorDomainFor("::::", domains), null);
});
