import { test } from "node:test";
import assert from "node:assert/strict";
import { unlockMode, checkCreatePassword } from "./unlockMode";

test("a vault with no version is created, anything else is unlocked", () => {
  assert.equal(unlockMode(undefined), "create");
  assert.equal(unlockMode(0), "create");
  assert.equal(unlockMode(1), "unlock");
});

test("create checks length then match", () => {
  assert.match(checkCreatePassword("short", "short") ?? "", /12/);
  assert.equal(checkCreatePassword("correct horse battery", "correct horse batter"), "The passwords do not match.");
  assert.equal(checkCreatePassword("correct horse battery", "correct horse battery"), null);
});
