// Copies the shared build/ output into dist/chrome and dist/firefox, writing
// each browser's own manifest.json from the single source in src/manifest.ts.
import { rmSync, cpSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { chromeManifest, firefoxManifest } from "../src/manifest.ts";

rmSync("dist", { recursive: true, force: true });

for (const [browser, manifest] of [
  ["chrome", chromeManifest()],
  ["firefox", firefoxManifest()],
]) {
  const dest = `dist/${browser}`;
  cpSync("build", dest, { recursive: true });
  // public/ holds only icons/; Vite copies nothing named manifest.json, but
  // guard against a stray one so the generated manifest is never shadowed.
  const stray = `${dest}/manifest.json`;
  if (existsSync(stray)) unlinkSync(stray);
  writeFileSync(stray, JSON.stringify(manifest, null, 2));

  if (browser === "firefox") {
    // Firefox has no Offscreen API (background.ts already gates every call
    // behind `typeof ext.offscreen`); shipping the unused offscreen.js is
    // what makes web-ext lint flag offscreen.closeDocument as UNSUPPORTED_API.
    for (const file of ["offscreen.js", "offscreen.html"]) {
      const path = `${dest}/${file}`;
      if (existsSync(path)) unlinkSync(path);
    }
  }
}
