import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePassword, loadGeneratorOptions, DEFAULT_GENERATOR } from "./generatePassword";

test("every selected class appears at least once", () => {
  for (let i = 0; i < 200; i++) {
    const p = generatePassword({ length: 8, upper: true, lower: true, numbers: true, symbols: true });
    assert.equal(p.length, 8);
    assert.match(p, /[A-Z]/); assert.match(p, /[a-z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
  }
});

test("unselected classes never appear and bad options throw", () => {
  const p = generatePassword({ length: 32, upper: false, lower: true, numbers: false, symbols: false });
  assert.match(p, /^[a-z]{32}$/);
  assert.throws(() => generatePassword({ length: 12, upper: false, lower: false, numbers: false, symbols: false }), /at least one/);
  assert.throws(() => generatePassword({ length: 7, upper: true, lower: true, numbers: true, symbols: true }), /between 8 and 128/);
});

test("stubbed zero randomness is deterministic and terminates", () => {
  const zeros = (a: Uint32Array) => { a.fill(0); return a; };
  const p = generatePassword({ length: 8, upper: true, lower: true, numbers: true, symbols: true }, zeros);
  assert.equal(p.length, 8);
  assert.equal(p, "a0!AAAAA");
});

test("excludeLookalikes filters O0Il1| from every set", () => {
  for (let i = 0; i < 50; i++) {
    const p = generatePassword({ length: 40, upper: true, lower: true, numbers: true, symbols: false, excludeLookalikes: true });
    assert.doesNotMatch(p, /[O0Il1|]/);
  }
});

test("a tampered non-boolean flag and non-number length fall back to defaults", () => {
  const storage = { getItem: () => JSON.stringify({ upper: "no", length: "20" }) };
  const loaded = loadGeneratorOptions(storage);
  assert.equal(loaded.upper, DEFAULT_GENERATOR.upper);
  assert.equal(loaded.length, DEFAULT_GENERATOR.length);
});
