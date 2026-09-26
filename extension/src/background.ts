// The background worker is the single owner of the session and the open vault.
// It never logs the pairing code, the token, the password or the key.
import { hostPattern } from "./lib/pairing";
import { ext } from "./ext";
import type { Request, Response, StatusResponse } from "./messages";
import { loadSettings, clearSettings, forgetSession, saveSettings } from "./lib/settings";
import { parseAutoLockMinutes } from "../../frontend/src/lib/autoLock";
import { RevokedError, serverFetch } from "./lib/session";
import { createVaultState, LockedError, LOCK_ALARM } from "./lib/vaultState";
import { fillFrame, fillTab } from "./lib/fillTab";
import { clearClipboard as clearWithOffscreen, OFFSCREEN_CLEAR } from "./lib/clipboardClear";
import { SECRET_CLIPBOARD_MS } from "../../frontend/src/lib/clipboard";

const CLIPBOARD_ALARM = "clipboard";

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
  if (alarm.name === CLIPBOARD_ALARM) void clearClipboard();
});

// Session storage is already empty after a browser restart; this is belt and braces.
ext.runtime.onStartup.addListener(() => void state.lock());

async function handle(message: Request): Promise<Response> {
  // Every message checks the deadline by the clock, so a missed alarm cannot extend it.
  const vault = await state.status();
  // The popup opens with status, then entries: a revoked device is noticed before either
  // answers, even though both work from memory.
  if (vault.unlocked && (message.type === "status" || message.type === "entries")) await state.checkDevice();
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
    case "entries": {
      const url = await activeTabUrl();
      const host = url?.hostname;
      const tabOrigin = url && /^https?:$/.test(url.protocol) ? url.origin : undefined;
      return { type: "entries", tabHost: host, tabOrigin, entries: await state.listEntries(message.query, host) };
    }
    case "copy":
      return { type: "secret", value: await state.secret(message.uuid, message.field) };
    case "fill":
      return { type: "filled", ...(await fill(message.uuid)) };
    case "saveLogin":
      await state.saveLogin(message.login);
      return { type: "ok" };
    case "setAutoLock":
      // status() above checked the deadline under the old window; save, then re-arm.
      await saveSettings({ autoLockMinutes: parseAutoLockMinutes(message.minutes) });
      if (vault.unlocked) await state.rearm();
      return { type: "ok" };
    case "copied":
      // Blind clear: the background never reads the value back, only when it copied it.
      await ext.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + SECRET_CLIPBOARD_MS });
      return { type: "ok" };
    default:
      return { type: "ok" };
  }
}

// The URL of the active tab, readable through the activeTab permission because opening
// the popup counts as invoking the action. Falls back to "no site" ranking when unset.
async function activeTabUrl(): Promise<URL | undefined> {
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.url) return undefined;
  try {
    return new URL(tab.url);
  } catch {
    return undefined;
  }
}

// Click-only fill into the active tab; fillTab owns the same-site and per-frame rules.
async function fill(uuid: string): Promise<{ username: boolean }> {
  const login = await state.login(uuid);
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
  const tabId = tab?.id;
  if (tabId === undefined) throw new Error("KyVault fills only on web pages.");
  return fillTab(
    {
      tabUrl: tab.url,
      probe: () => ext.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content/fill.js"] }),
      fill: async (frameId, args) =>
        (await ext.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, func: fillFrame, args }))[0]?.result,
    },
    login,
  );
}

// Chrome only (see lib/clipboardClear.ts). Firefox has no offscreen API, so the clear
// there happens only while the popup stays open (its own copyText timer).
async function clearClipboard(): Promise<void> {
  const offscreen = ext.offscreen;
  if (typeof offscreen === "undefined") return;
  await clearWithOffscreen({
    hasDocument: () => offscreen.hasDocument(),
    createDocument: () =>
      offscreen.createDocument({
        url: "offscreen.html",
        reasons: ["CLIPBOARD"],
        justification: "Clear a copied password after 30 seconds",
      }),
    closeDocument: () => offscreen.closeDocument(),
    clear: async () => {
      await ext.runtime.sendMessage({ type: OFFSCREEN_CLEAR });
    },
  });
}

async function status(vault: { unlocked: boolean; lockAt?: number }): Promise<StatusResponse> {
  const settings = await loadSettings();
  return {
    paired: Boolean(settings.serverOrigin && settings.sessionToken),
    unlocked: vault.unlocked,
    lockAt: vault.lockAt,
    serverOrigin: settings.serverOrigin,
    deviceName: settings.deviceName,
    autoLockMinutes: settings.autoLockMinutes,
  };
}

async function unpair(): Promise<void> {
  const settings = await loadSettings();
  if (settings.deviceId) {
    try {
      // serverFetch's origin check and request options; a 401 here changes nothing, since
      // the pairing keys are cleared below either way.
      await serverFetch(
        { settings: async () => settings, forget: async () => {}, fetch: (url, init) => fetch(url, init), timeoutMs: 15_000 },
        `/api/devices/${encodeURIComponent(settings.deviceId)}`,
        { method: "DELETE" },
      );
    } catch {
      // Best effort: the device stays listed in Security, then Devices, if this fails.
    }
  }
  await clearSettings();
  await state.lock();
  if (settings.serverOrigin) {
    await ext.permissions.remove({ origins: [hostPattern(settings.serverOrigin)] });
  }
}
