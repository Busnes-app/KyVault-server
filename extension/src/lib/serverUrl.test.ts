import { test } from "node:test";
import assert from "node:assert/strict";
import { parseServerOrigin } from "./serverUrl";

test("accepts https origins and drops the path", () => {
  assert.equal(parseServerOrigin("https://vault.example.com/login?x=1"), "https://vault.example.com");
  assert.equal(parseServerOrigin(" https://vault.example.com:8443 "), "https://vault.example.com:8443");
});

test("refuses http, credentials in the URL, and junk", () => {
  for (const bad of ["http://vault.example.com", "https://user:pw@vault.example.com", "vault.example.com", "", "ftp://x", "https://"]) {
    assert.throws(() => parseServerOrigin(bad), /https:\/\/host/, bad);
  }
});
