import { test } from "node:test";
import assert from "node:assert/strict";
import { EFF_WORDS } from "./effWordlist";
import { generatePassphrase, passphraseEntropyBits, loadPassphraseOptions, DEFAULT_PASSPHRASE } from "./passphrase";

test("the bundled list is the EFF long list", () => {
  assert.equal(EFF_WORDS.length, 7776);
  assert.equal(new Set(EFF_WORDS).size, 7776);
  assert.ok(EFF_WORDS.every((w) => /^[a-z-]+$/.test(w) && w.length <= 9));
  assert.equal(EFF_WORDS[0], "abacus");
});

test("passphrases use the list, the separator and capitalisation", () => {
  const p = generatePassphrase({ words: 5, separator: " ", capitalize: true });
  const parts = p.split(" ");
  assert.equal(parts.length, 5);
  for (const w of parts) assert.ok(EFF_WORDS.includes(w.toLowerCase()) && /^[A-Z]/.test(w), w);
  assert.throws(() => generatePassphrase({ words: 3, separator: "-", capitalize: false }), /between 4 and 10/);
  assert.throws(() => generatePassphrase({ words: 11, separator: "-", capitalize: false }), /between 4 and 10/);
  const zeros = (a: Uint32Array) => { a.fill(0); };
  assert.equal(generatePassphrase({ words: 4, separator: ".", capitalize: false }, zeros), "abacus.abacus.abacus.abacus");
});

test("entropy is log2 of the space", () => {
  assert.ok(Math.abs(passphraseEntropyBits({ words: 6, separator: "-", capitalize: true }) - 77.55) < 0.01);
  assert.equal(loadPassphraseOptions({ getItem: () => JSON.stringify({ words: 99, separator: 5 }) }), DEFAULT_PASSPHRASE);
});
