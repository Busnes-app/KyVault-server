import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRoute, formatRoute } from "./route";

test("routes round-trip and unknown input falls back to the vault", () => {
  assert.deepEqual(parseRoute(""), { tab: "vault" });
  assert.deepEqual(parseRoute("#/"), { tab: "vault" });
  assert.deepEqual(parseRoute("#/vault/abc-123"), { tab: "vault", entry: "abc-123" });
  assert.deepEqual(parseRoute("#/security"), { tab: "security" });
  assert.deepEqual(parseRoute("#/admin/audit"), { tab: "admin", admin: "audit" });
  assert.deepEqual(parseRoute("#/admin"), { tab: "admin", admin: "sso" });
  assert.deepEqual(parseRoute("#/admin/nope"), { tab: "admin", admin: "sso" });
  assert.deepEqual(parseRoute("#/bogus"), { tab: "vault" });
  assert.deepEqual(parseRoute("#/watchtower"), { tab: "watchtower" });
  assert.equal(formatRoute({ tab: "watchtower" }), "#/watchtower");
  assert.equal(formatRoute({ tab: "vault" }), "#/vault");
  assert.equal(formatRoute({ tab: "vault", entry: "abc" }), "#/vault/abc");
  assert.equal(formatRoute({ tab: "admin", admin: "users" }), "#/admin/users");
  assert.equal(formatRoute(parseRoute("#/vault/x%20y")), "#/vault/x%20y");
});

test("shared vault routes", () => {
  assert.deepEqual(parseRoute("#/shared/sv_abcdefghijklmnopqrstuv"), { tab: "vault", shared: "sv_abcdefghijklmnopqrstuv" });
  assert.deepEqual(parseRoute("#/shared/sv_abcdefghijklmnopqrstuv/e%201"), { tab: "vault", shared: "sv_abcdefghijklmnopqrstuv", entry: "e 1" });
  assert.deepEqual(parseRoute("#/shared/../x"), { tab: "vault" });
  assert.deepEqual(parseRoute("#/shared/u-1"), { tab: "vault" });
  assert.equal(formatRoute({ tab: "vault", shared: "sv_abcdefghijklmnopqrstuv" }), "#/shared/sv_abcdefghijklmnopqrstuv");
  assert.equal(formatRoute({ tab: "vault", shared: "sv_abcdefghijklmnopqrstuv", entry: "e 1" }), "#/shared/sv_abcdefghijklmnopqrstuv/e%201");
  assert.deepEqual(parseRoute("#/admin/shared"), { tab: "admin", admin: "shared" });
  assert.equal(formatRoute({ tab: "admin", admin: "shared" }), "#/admin/shared");
});
