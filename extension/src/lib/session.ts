import type { Settings } from "./settings";
import { parseServerOrigin } from "./serverUrl";

export class RevokedError extends Error {
  constructor() {
    super("This device was revoked. Pair again from the KyVault options page.");
    this.name = "RevokedError";
  }
}

export type SessionIO = {
  settings: () => Promise<Settings>;
  // Deletes sessionToken and deviceId; keeps serverOrigin and deviceName for re-pairing.
  forget: () => Promise<void>;
  fetch: (url: string, init: RequestInit) => Promise<Response>;
  timeoutMs?: number;
};

const NOT_PAIRED = "Pair this extension with your KyVault server first.";

// The only way the extension talks to the server. Never logs the token.
export async function serverFetch(io: SessionIO, path: string, init: RequestInit): Promise<Response> {
  const { serverOrigin, sessionToken } = await io.settings();
  if (!serverOrigin || !sessionToken) throw new Error(NOT_PAIRED);
  let origin: string;
  try {
    origin = parseServerOrigin(serverOrigin);
  } catch {
    throw new Error(NOT_PAIRED);
  }
  if (origin !== serverOrigin) throw new Error(NOT_PAIRED);

  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${sessionToken}`);
  let res: Response;
  try {
    res = await io.fetch(origin + path, {
      ...init,
      headers,
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(io.timeoutMs ?? 120_000),
    });
  } catch (err) {
    throw timedOut(err) ?? new Error(`Could not reach ${origin}. Check your connection and try again.`);
  }
  if (res.status === 401) {
    await io.forget();
    throw new RevokedError();
  }
  return res;
}

function timedOut(err: unknown): Error | undefined {
  if (err instanceof DOMException && err.name === "TimeoutError") {
    return new Error("The server did not answer in time. Check your connection and try again.");
  }
  return undefined;
}

// The timeout signal covers the body too; a stalled or dropped download gets a sentence.
export async function readBody(res: Response): Promise<ArrayBuffer> {
  try {
    return await res.arrayBuffer();
  } catch (err) {
    throw timedOut(err) ?? new Error("The download was interrupted. Check your connection and try again.");
  }
}
