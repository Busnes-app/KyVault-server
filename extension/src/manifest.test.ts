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
    const expected = name === "chrome" ? ["activeTab", "alarms", "offscreen", "scripting", "storage"] : ["activeTab", "alarms", "scripting", "storage"];
    assert.deepEqual(perms, expected);
    assert.equal("content_scripts" in manifest, false);
    assert.match(manifest.content_security_policy.extension_pages, /'wasm-unsafe-eval'/);
    assert.doesNotMatch(manifest.content_security_policy.extension_pages, /'unsafe-eval'|'unsafe-inline'|http/);
    assert.equal(manifest.background.service_worker, "background.js");
    assert.equal(manifest.background.type, "module");
    assert.equal(JSON.parse(JSON.stringify(manifest)).name, "KyVault");
  });
}

test("chrome has no background.scripts; firefox has scripts and a gecko id", () => {
  assert.equal("scripts" in chromeManifest().background, false);
  const ff = firefoxManifest();
  assert.deepEqual(ff.background.scripts, ["background.js"]);
  assert.equal(ff.browser_specific_settings.gecko.id, "kyvault@busnes.app");
  assert.deepEqual(ff.browser_specific_settings.gecko.data_collection_permissions, { required: ["none"] });
});
