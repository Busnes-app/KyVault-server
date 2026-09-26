import { test } from "node:test";
import assert from "node:assert/strict";
import { chromeManifest, firefoxManifest } from "./manifest";

for (const [name, manifest] of [["chrome", chromeManifest()], ["firefox", firefoxManifest()]] as const) {
  test(`${name} manifest is MV3 with the minimum permission set`, () => {
    assert.equal(manifest.manifest_version, 3);
    assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
    assert.deepEqual(manifest.optional_host_permissions, ["https://*/*"]);
    assert.equal("host_permissions" in manifest, false);
    const perms = [...manifest.permissions].sort();
    const expected =
      name === "chrome"
        ? ["activeTab", "alarms", "clipboardWrite", "offscreen", "scripting", "storage"]
        : ["activeTab", "alarms", "clipboardWrite", "scripting", "storage"];
    assert.deepEqual(perms, expected);
    assert.equal("content_scripts" in manifest, false);
    assert.match(manifest.content_security_policy.extension_pages, /'wasm-unsafe-eval'/);
    assert.doesNotMatch(manifest.content_security_policy.extension_pages, /'unsafe-eval'|'unsafe-inline'|http/);
    assert.equal(manifest.background.type, "module");
    assert.equal(JSON.parse(JSON.stringify(manifest)).name, "KyVault");
  });
}

test("chrome background is a service worker only; firefox background is scripts only", () => {
  // Chrome MV3 only understands service_worker; Firefox ignores it and warns
  // (BACKGROUND_SERVICE_WORKER_IGNORED), so each browser gets only its own key.
  const chrome = chromeManifest();
  assert.equal(chrome.background.service_worker, "background.js");
  // Pinned floors: changing either changes which browsers the extension claims to support.
  assert.equal(chrome.minimum_chrome_version, "120");
  assert.equal("scripts" in chrome.background, false);
  const ff = firefoxManifest();
  assert.deepEqual(ff.background.scripts, ["background.js"]);
  assert.equal("service_worker" in ff.background, false);
  assert.equal(ff.browser_specific_settings.gecko.id, "kyvault@busnes.app");
  assert.equal(ff.browser_specific_settings.gecko.strict_min_version, "128.0");
  assert.deepEqual(ff.browser_specific_settings.gecko.data_collection_permissions, { required: ["none"] });
});
