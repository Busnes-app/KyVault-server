// The background worker is the single owner of the session and the open vault.
// It never logs the pairing code, the token, the password or the key.
import { ext } from "./ext";
import type { Request, Response, StatusResponse } from "./messages";
import { loadSettings, clearSettings, forgetSession } from "./lib/settings";
import { RevokedError } from "./lib/session";
import { createVaultState, LockedError, LOCK_ALARM } from "./lib/vaultState";

const state = createVaultState({
  settings: loadSettings,
  forget: forgetSession,
  fetch: (url, init) => fetch(url, init),
  session: {
    get: (keys) => ext.storage.session.get(keys),
    set: (items) => ext.storage.session.set(items),
    clear: () => ext.storage.session.clear(),
  },
  alarms: {
    create: (name, info) => ext.alarms.create(name, info),
    clear: (name) => ext.alarms.clear(name),
  },
});

ext.runtime.onMessage.addListener((message: Request, sender, sendResponse) => {
  // Only this extension's own pages (popup, options); injected scripts run on the
  // page's URL and get nothing.
  if (sender.id !== ext.runtime.id || !sender.url?.startsWith(ext.runtime.getURL(""))) return false;
  handle(message).then(sendResponse, (err: unknown) =>
    sendResponse({
      type: "error",
      message: err instanceof Error ? err.message : String(err),
      revoked: err instanceof RevokedError,
      locked: err instanceof LockedError,
    } satisfies Response),
  );
  return true; // keep the channel open for the async response
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) void state.lock();
});

// Session storage is already empty after a browser restart; this is belt and braces.
ext.runtime.onStartup.addListener(() => void state.lock());

async function handle(message: Request): Promise<Response> {
  // Every message checks the deadline by the clock, so a missed alarm cannot extend it.
  const vault = await state.status();
  switch (message.type) {
    case "paired":
      await state.lock();
      return { type: "ok" };
    case "unpair":
      await unpair();
      return { type: "ok" };
    case "status":
      return { type: "status", status: await status(vault) };
    case "unlock":
      await state.unlock(message.password);
      return { type: "ok" };
    case "ensure":
      await state.ensure();
      return { type: "ok" };
    case "lock":
      await state.lock();
      return { type: "ok" };
    default:
      return { type: "ok" };
  }
}

async function status(vault: { unlocked: boolean; lockAt?: number }): Promise<StatusResponse> {
  const settings = await loadSettings();
  return {
    paired: Boolean(settings.serverOrigin && settings.sessionToken),
    unlocked: vault.unlocked,
    lockAt: vault.lockAt,
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
  await state.lock();
  if (settings.serverOrigin) {
    await ext.permissions.remove({ origins: [`${settings.serverOrigin}/*`] });
  }
}
