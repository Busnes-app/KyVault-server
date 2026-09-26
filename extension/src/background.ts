// The background worker is the single owner of the session and (from Task 3)
// the open vault. Task 2 wires the pairing/unpairing signals the options
// page sends over runtime.sendMessage; it never logs the pairing code or token.
import { ext } from "./ext";
import type { Request, Response, StatusResponse } from "./messages";
import { loadSettings, clearSettings } from "./lib/settings";

ext.runtime.onMessage.addListener((message: Request, _sender, sendResponse) => {
  handle(message).then(sendResponse);
  return true; // keep the channel open for the async response
});

async function handle(message: Request): Promise<Response> {
  switch (message.type) {
    case "paired":
      await ext.storage.session.clear();
      return { type: "ok" };
    case "unpair":
      await unpair();
      return { type: "ok" };
    case "status":
      return { type: "status", status: await status() };
    default:
      return { type: "ok" };
  }
}

async function status(): Promise<StatusResponse> {
  const settings = await loadSettings();
  return {
    paired: Boolean(settings.serverOrigin && settings.sessionToken),
    unlocked: false,
    serverOrigin: settings.serverOrigin,
    deviceName: settings.deviceName,
  };
}

async function unpair(): Promise<void> {
  const settings = await loadSettings();
  if (settings.serverOrigin && settings.sessionToken && settings.deviceId) {
    try {
      await fetch(`${settings.serverOrigin}/api/devices/${settings.deviceId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${settings.sessionToken}` },
        credentials: "omit",
        redirect: "error",
      });
    } catch {
      // Best effort: the device stays listed in Security -> Devices if this fails.
    }
  }
  await clearSettings();
  await ext.storage.session.clear();
  if (settings.serverOrigin) {
    await ext.permissions.remove({ origins: [`${settings.serverOrigin}/*`] });
  }
}
