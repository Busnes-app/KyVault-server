// The extension's only write: a version-checked raw KDBX upload.
import { serverFetch, type SessionIO } from "./session";

export class ConflictError extends Error {
  constructor() {
    super("The vault changed elsewhere. Unlock again to refresh.");
    this.name = "ConflictError";
  }
}

// 409 means another client saved first; the server keeps these bytes as a conflict.
// The caller locks and re-downloads; it never retries with the newer version.
export async function uploadVault(io: SessionIO, binary: ArrayBuffer, version: number, deviceId: string): Promise<number> {
  const res = await serverFetch(io, "/api/vault/upload", {
    method: "POST",
    body: binary,
    headers: { "Content-Type": "application/octet-stream", "If-Match": `"${version}"`, "X-Device-ID": deviceId },
  });
  if (res.status === 409) throw new ConflictError();
  if (res.status === 413) throw new Error("The vault is over the 50 MiB upload limit.");
  if (!res.ok) throw new Error(`The server answered ${res.status}. Try again later.`);
  let v: unknown;
  try {
    v = ((await res.json()) as { metadata?: { version?: unknown } } | null)?.metadata?.version;
  } catch {
    // refused below
  }
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= version) throw new Error("The server did not confirm the saved vault version.");
  return v;
}
