import { version } from "../package.json";

const shared = {
  manifest_version: 3,
  name: "KyVault",
  version,
  description: "Fill logins from your KyVault vault. Zero knowledge: the server never sees your passwords.",
  icons: { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" },
  action: { default_popup: "popup.html", default_title: "KyVault" },
  options_ui: { page: "options.html", open_in_tab: true },
  permissions: ["storage", "alarms", "activeTab", "scripting"],
  optional_host_permissions: ["https://*/*"],
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'" },
} as const;

export function chromeManifest() {
  return {
    ...shared,
    permissions: [...shared.permissions, "offscreen"],
    background: { service_worker: "background.js", type: "module" },
    minimum_chrome_version: "120",
  };
}

export function firefoxManifest() {
  return {
    ...shared,
    background: { scripts: ["background.js"], service_worker: "background.js", type: "module" },
    browser_specific_settings: {
      gecko: { id: "kyvault@busnes.app", strict_min_version: "128.0", data_collection_permissions: { required: ["none"] } },
    },
  };
}
