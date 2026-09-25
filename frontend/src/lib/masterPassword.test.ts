import { test } from "node:test";
import assert from "node:assert/strict";
import { checkMasterPassword, MIN_MASTER_PASSWORD_LENGTH } from "./masterPassword";

test("master password floor", () => {
  assert.equal(MIN_MASTER_PASSWORD_LENGTH, 12);
  assert.match(checkMasterPassword("short") ?? "", /12/);
  assert.match(checkMasterPassword("            ") ?? "", /space/);
  assert.equal(checkMasterPassword("correct horse battery"), null);
});
