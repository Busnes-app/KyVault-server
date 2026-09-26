import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Script, createContext } from "node:vm";
import { build } from "vite";
import { checkFillFrame } from "../lib/fillFrame.fixture";

// Builds the content script with the real config and runs the artifact the way
// scripting.executeScript({files}) does: as a classic script whose completion value
// is the result.
test("content/fill.js is one self-contained IIFE that returns the probe and leaks no globals", async () => {
  const outDir = mkdtempSync(join(tmpdir(), "kyvault-content-"));
  try {
    await build({ configFile: "vite.content.config.ts", logLevel: "silent", build: { outDir, emptyOutDir: true } });
    const code = readFileSync(join(outDir, "content/fill.js"), "utf8");
    assert.ok(code.trim().length > 0);
    assert.doesNotMatch(code, /\bimport\b|\bexport\b/);
    assert.match(code.trim(), /^\(function\b|^\(\(\)\s*=>|^\(\(\)=>|^"use strict";\s*\(/);

    const inputs = [
      { type: "email", autocomplete: "username", getClientRects: () => [1] },
      { type: "password", autocomplete: "current-password", getClientRects: () => [1] },
    ];
    const context = createContext({
      location: { origin: "https://example.com" },
      document: { querySelectorAll: () => inputs, activeElement: null },
      getComputedStyle: () => ({ visibility: "visible" }),
    });
    const before = Object.keys(context).sort();
    const result = new Script(code).runInContext(context);
    assert.deepEqual(JSON.parse(JSON.stringify(result)), { origin: "https://example.com", count: 2, targets: { password: 1, username: 0 } });
    assert.deepEqual(Object.keys(context).sort(), before);
    // Twice in the same frame is fine: nothing is declared at the top level.
    new Script(code).runInContext(context);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

// scripting.executeScript({func}) serialises fillFrame from the shipped background
// bundle, so run that minified text, not the source, in the same fake DOM.
test("the fillFrame serialised from the built background bundle is self-contained", async () => {
  const outDir = mkdtempSync(join(tmpdir(), "kyvault-background-"));
  try {
    await build({ configFile: "vite.config.ts", logLevel: "silent", build: { outDir, emptyOutDir: true } });
    const code = readFileSync(join(outDir, "background.js"), "utf8");
    const at = code.indexOf("HTMLInputElement.prototype");
    assert.ok(at > 0 && code.indexOf("HTMLInputElement.prototype", at + 1) === -1);
    const start = code.lastIndexOf("function", at);
    let depth = 0;
    let end = code.indexOf("{", start);
    do {
      if (code[end] === "{") depth++;
      if (code[end] === "}") depth--;
      end++;
    } while (depth > 0);
    checkFillFrame(code.slice(start, end));
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});
