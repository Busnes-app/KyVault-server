export type PairIO = { requestHost: (pattern: string) => Promise<boolean>; fetch: (url: string, init: RequestInit) => Promise<Response> };

// The background worker calls this; it never holds the token itself. See
// extension/AGENTS.md for the storage.local allowlist.
export async function pair(io: PairIO, origin: string, codeOrPin: string, deviceName: string) {
  if (!(await io.requestHost(origin + "/*"))) {
    throw new Error("KyVault needs access to that server to pair. Allow it and try again.");
  }
  const res = await io.fetch(origin + "/api/devices/pairing/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "omit",
    redirect: "error",
    cache: "no-store",
    body: JSON.stringify({ codeOrPin: codeOrPin.trim(), deviceName: deviceName.trim(), platform: "extension" }),
  });
  if (res.status === 400) throw new Error((await res.text()).trim() || "The pairing code was not accepted.");
  if (res.status === 401) throw new Error("The account is inactive or signed out. Sign in to KyVault and start pairing again.");
  if (!res.ok) throw new Error(`The server answered ${res.status}. Check the address and try again.`);
  const body = (await res.json()) as { deviceId?: unknown; sessionToken?: unknown };
  if (typeof body.deviceId !== "string" || !body.deviceId || typeof body.sessionToken !== "string" || !body.sessionToken) {
    throw new Error("The server did not return a session. Try pairing again.");
  }
  return { deviceId: body.deviceId, sessionToken: body.sessionToken };
}
