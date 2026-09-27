import { test } from "node:test";
import assert from "node:assert/strict";
import { loadStrengthChecker } from "./passwordStrength";

test("zxcvbn flags common patterns and passes passphrases", async () => {
  const check = await loadStrengthChecker();
  for (const weak of ["Password1234!", "qwertyuiop123", "p@ssw0rd2024", "Jennifer1985"]) {
    assert.ok(check(weak).score <= 2, weak);
  }
  for (const strong of ["correct-horse-battery-staple", "Xk9#mQ2$vL7!pR4w"]) {
    assert.ok(check(strong).score >= 3, strong);
  }
  assert.equal(check("").score, 0);
  assert.equal(typeof check("Password1234!").warning, "string");
});

test("loader is memoised", async () => {
  assert.equal(await loadStrengthChecker(), await loadStrengthChecker());
});
