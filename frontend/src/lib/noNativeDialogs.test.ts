import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const NATIVE_DIALOG_CALL = /(?<!dialogs\.)\b(confirm|prompt|alert)\(/;

function tsxFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...tsxFiles(path));
    else if (entry.name.endsWith(".tsx")) found.push(path);
  }
  return found;
}

// Dialog.tsx/DialogHost.tsx are the only sanctioned modal; window.confirm/prompt/alert
// block the tab and cannot be styled, queued or tested. Calls on `dialogs.` are allowed.
test("no native confirm, prompt or alert calls in frontend/src", () => {
  const offenders: string[] = [];
  for (const file of tsxFiles(srcDir)) {
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, index) => {
      if (NATIVE_DIALOG_CALL.test(line)) offenders.push(`${file}:${index + 1}`);
    });
  }
  assert.deepEqual(offenders, [], `native dialog call(s) found:\n${offenders.join("\n")}`);
});
