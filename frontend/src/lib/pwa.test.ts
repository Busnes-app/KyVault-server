import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("manifest is valid, icons exist and index.html references it", () => {
  const manifest = JSON.parse(readFileSync(join(root, "public", "manifest.webmanifest"), "utf8"));
  assert.equal(manifest.name, "KyVault");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.start_url, "/");
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2);
  for (const icon of manifest.icons) {
    assert.ok(existsSync(join(root, "public", icon.src.replace(/^\//, ""))), icon.src);
    assert.match(icon.sizes, /^\d+x\d+$/);
    assert.equal(icon.type, "image/png");
  }
  assert.ok(manifest.icons.some((i: { sizes: string }) => Number(i.sizes.split("x")[0]) >= 512));
  const html = readFileSync(join(root, "index.html"), "utf8");
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest"/);
  assert.match(html, /<meta name="theme-color" content="#f8f6f0" media="\(prefers-color-scheme: light\)"/);
  assert.match(html, /<meta name="theme-color" content="#182326" media="\(prefers-color-scheme: dark\)"/);
  assert.ok(!html.includes("serviceWorker"));
});
