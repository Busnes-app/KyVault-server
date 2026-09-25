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
  assert.equal(formatRoute({ tab: "vault" }), "#/vault");
  assert.equal(formatRoute({ tab: "vault", entry: "abc" }), "#/vault/abc");
  assert.equal(formatRoute({ tab: "admin", admin: "users" }), "#/admin/users");
  assert.equal(formatRoute(parseRoute("#/vault/x%20y")), "#/vault/x%20y");
});
