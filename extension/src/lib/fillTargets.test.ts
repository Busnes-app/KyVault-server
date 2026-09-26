import { test } from "node:test";
import assert from "node:assert/strict";
import { chooseTargets, type Candidate } from "./fillTargets";

const c = (index: number, type: string, o: Partial<Candidate> = {}): Candidate => ({ index, type, visible: true, focused: false, autocomplete: "", ...o });

test("first visible password field and the nearest preceding text field", () => {
  const fields = [c(0, "search"), c(1, "email"), c(2, "text", { visible: false }), c(3, "password"), c(4, "password")];
  assert.deepEqual(chooseTargets(fields), { password: 3, username: 1 });
});

test("a focused password field wins over an earlier one", () => {
  const fields = [c(0, "text"), c(1, "password"), c(2, "text"), c(3, "password", { focused: true })];
  assert.deepEqual(chooseTargets(fields), { password: 3, username: 2 });
});

test("autocomplete=username is preferred even when not nearest", () => {
  const fields = [c(0, "text", { autocomplete: "username" }), c(1, "text"), c(2, "password")];
  assert.deepEqual(chooseTargets(fields), { password: 2, username: 0 });
});

test("hidden password fields and pages without one", () => {
  assert.equal(chooseTargets([c(0, "text"), c(1, "password", { visible: false })]), undefined);
  assert.deepEqual(chooseTargets([c(0, "password")]), { password: 0, username: undefined });
});

test("a focused but hidden password field is not a target", () => {
  const fields = [c(0, "text"), c(1, "password", { visible: false, focused: true }), c(2, "password")];
  assert.deepEqual(chooseTargets(fields), { password: 2, username: 0 });
});
