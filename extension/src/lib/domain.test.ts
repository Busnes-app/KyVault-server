import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain, sameSite } from "./domain";

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
