export type PairIO = { requestHost: (pattern: string) => Promise<boolean>; fetch: (url: string, init: RequestInit) => Promise<Response> };

// A bare `fetch` stored on an object runs with this = that object, which the browser
// refuses ("Illegal invocation"); the arrow calls it unbound.
export function browserPairIO(requestHost: PairIO["requestHost"], fetchImpl: typeof fetch = fetch): PairIO {
  return { requestHost, fetch: (url, init) => fetchImpl(url, init) };
}

// extension/AGENTS.md documents the storage.local allowlist this feeds.
const MAX_DEVICE_NAME_RUNES = 64;

// Matches the server's own device rename rule (internal/api/device_handlers.go):
// 1 to 64 code points, no control characters.
function validateDeviceName(name: string): string {
  const trimmed = name.trim();
  if (trimmed.length === 0 || Array.from(trimmed).length > MAX_DEVICE_NAME_RUNES || /\p{Cc}/u.test(trimmed)) {
    throw new Error(`Device name must be 1 to ${MAX_DEVICE_NAME_RUNES} characters, with no control characters.`);
  }
  return trimmed;
}

export async function pair(io: PairIO, origin: string, codeOrPin: string, deviceName: string) {
  const name = validateDeviceName(deviceName);
  if (!(await io.requestHost(origin + "/*"))) {
    throw new Error("KyVault needs access to that server to pair. Allow it and try again.");
  }
  let res: Response;
  try {
    res = await io.fetch(origin + "/api/devices/pairing/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
      body: JSON.stringify({ codeOrPin: codeOrPin.trim(), deviceName: name, platform: "extension" }),
    });
  } catch {
    throw new Error(`Could not reach ${origin}. Check the address and your connection.`);
  }
  if (res.status === 400) throw new Error("The pairing code was wrong or has expired. Generate a new one in KyVault and try again.");
  if (res.status === 401) throw new Error("The account is inactive or signed out. Sign in to KyVault and start pairing again.");
  if (res.status === 429) throw new Error("Too many attempts. Wait a minute and try again.");
  if (!res.ok) throw new Error(`The server answered ${res.status}. Check the address and try again.`);
  const body = (await res.json()) as { deviceId?: unknown; sessionToken?: unknown };
  if (typeof body.deviceId !== "string" || !body.deviceId || typeof body.sessionToken !== "string" || !body.sessionToken) {
    throw new Error("The server did not return a session. Try pairing again.");
  }
  return { deviceId: body.deviceId, sessionToken: body.sessionToken };
}
