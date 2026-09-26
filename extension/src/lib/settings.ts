import { parseAutoLockMinutes, type AutoLockMinutes } from "../../../frontend/src/lib/autoLock";
import { ext } from "../ext";

export type Settings = {
  serverOrigin?: string;
  sessionToken?: string;
  deviceId?: string;
  deviceName?: string;
  autoLockMinutes: AutoLockMinutes;
};

const KEYS = ["serverOrigin", "sessionToken", "deviceId", "deviceName", "autoLockMinutes"] as const;
const PAIR_KEYS = ["serverOrigin", "sessionToken", "deviceId", "deviceName"] as const;

// Nothing else is ever written to storage.local; see extension/AGENTS.md.
export async function loadSettings(): Promise<Settings> {
  const raw = await ext.storage.local.get(KEYS as unknown as string[]);
  return {
    serverOrigin: typeof raw.serverOrigin === "string" ? raw.serverOrigin : undefined,
    sessionToken: typeof raw.sessionToken === "string" ? raw.sessionToken : undefined,
    deviceId: typeof raw.deviceId === "string" ? raw.deviceId : undefined,
    deviceName: typeof raw.deviceName === "string" ? raw.deviceName : undefined,
    autoLockMinutes: parseAutoLockMinutes(raw.autoLockMinutes),
  };
}

export async function saveSettings(patch: Partial<Settings>): Promise<void> {
  await ext.storage.local.set(patch);
}

// Unpairing keeps the autoLockMinutes preference; it is a browser setting, not
// a fact about the paired server.
export async function clearSettings(): Promise<void> {
  await ext.storage.local.remove(PAIR_KEYS as unknown as string[]);
}

// A 401 means the server revoked this device. Keep serverOrigin and deviceName so
// pairing again is one field.
export async function forgetSession(): Promise<void> {
  await ext.storage.local.remove(["sessionToken", "deviceId"]);
}
