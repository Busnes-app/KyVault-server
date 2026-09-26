import { test } from "node:test";
import assert from "node:assert/strict";
import { isLocked, lockDeadline } from "./lock";

test("deadline is minutes from now and a missing or past deadline is locked", () => {
  const now = 1_800_000_000_000;
  assert.equal(lockDeadline(now, 5), now + 300_000);
  assert.equal(isLocked(undefined, now), true);
  assert.equal(isLocked(now + 1, now), false);
  assert.equal(isLocked(now, now), true);
  // a clock set backwards must not extend the session
  assert.equal(isLocked(now + 3_600_000, now - 86_400_000), true);
});

test("with the chosen window, a small backwards clock jump also locks", () => {
  const now = 1_800_000_000_000;
  const lockAt = lockDeadline(now, 5);
  assert.equal(isLocked(lockAt, now, 5), false);
  assert.equal(isLocked(lockAt, now - 30_000, 5), false); // within a minute of slack
  assert.equal(isLocked(lockAt, now - 10 * 60_000, 5), true);
});
