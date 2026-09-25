import { test } from "node:test";
import assert from "node:assert/strict";
import { explainSsoError } from "./ssoError";

test("known codes explain themselves", () => {
  assert.equal(explainSsoError("not_linked"), "Your KySignOn identity is not linked to a KyVault account. Ask your administrator to provision it.");
});

test("prototype-key codes resolve to undefined, not inherited values", () => {
  assert.equal(explainSsoError("__proto__"), undefined);
  assert.equal(explainSsoError("constructor"), undefined);
  assert.equal(explainSsoError("toString"), undefined);
});

test("absent codes resolve to undefined", () => {
  assert.equal(explainSsoError(null), undefined);
  assert.equal(explainSsoError(""), undefined);
});
