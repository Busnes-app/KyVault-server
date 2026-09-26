// Dev-only stand-in for the Go API so the UI can run without KySignOn. Never built.
import type { Plugin } from "vite";
import { createHash } from "node:crypto";

type Store = {
  version: number; bytes: Buffer | null; passwordEnvelope?: string; recoveryEnvelope?: string;
  history: Array<{ id: string; version: number; sizeBytes: number; checksum: string; timestamp: string }>;
  devices: Array<{ id: string; name: string; platform: string; lastSeenAt: string; lastIp: string }>;
};

export function mockApi(): Plugin {
  const store: Store = { version: 0, bytes: null, history: [], devices: [
    { id: "dev-1", name: "Pixel 9", platform: "android", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.7" },
  ] };
  const user = { id: "u-1", username: "mock-admin", role: "admin", active: true, ssoSub: "sub-mock" };
  const json = (res: import("node:http").ServerResponse, status: number, body: unknown) => {
    res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(body));
  };
  const readBody = (req: import("node:http").IncomingMessage) => new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []; req.on("data", (c) => chunks.push(c)); req.on("end", () => resolve(Buffer.concat(chunks)));
  });
  const metadata = () => ({ version: store.version, checksum: store.bytes ? createHash("sha256").update(store.bytes).digest("hex") : "",
    sizeBytes: store.bytes?.length ?? 0, passwordEnvelope: store.passwordEnvelope, recoveryEnvelope: store.recoveryEnvelope });

  return { name: "kyvault-mock-api", configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const p = url.pathname; const m = req.method ?? "GET";
      if (!p.startsWith("/api/")) return next();
      res.setHeader("Set-Cookie", "csrf_token=mock-csrf; Path=/");
      if (p === "/api/auth/me") return json(res, 200, { authenticated: true, user });
      if (p === "/api/auth/sso-config") return json(res, 200, { enabled: true, issuerUrl: "https://signon.mock" });
      if (p === "/api/auth/logout") return json(res, 200, { ok: true });
      if (p === "/api/vault/metadata") return json(res, 200, metadata());
      if (p === "/api/vault/kdbx") {
        if (!store.bytes) return json(res, 404, { error: "vault does not exist yet" });
        res.setHeader("Content-Type", "application/x-keepass2"); res.setHeader("ETag", `"${store.version}"`); return res.end(store.bytes);
      }
      if (p === "/api/vault/upload" && m === "POST") {
        const expected = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
        if (expected !== store.version) return json(res, 409, { error: "conflict", currentVersion: store.version, expectedVersion: expected, conflictId: "c-1" });
        store.bytes = await readBody(req); store.version++;
        const env = req.headers["x-password-envelope"]; if (typeof env === "string" && env) store.passwordEnvelope = env;
        const rec = req.headers["x-recovery-envelope"]; if (typeof rec === "string" && rec) store.recoveryEnvelope = rec;
        const meta = metadata();
        store.history.unshift({ id: `h-${store.version}`, version: store.version, sizeBytes: meta.sizeBytes, checksum: meta.checksum, timestamp: new Date().toISOString() });
        return json(res, 200, { ok: true, metadata: meta });
      }
      if (p === "/api/vault/envelopes" && m === "PUT") {
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        if (body.passwordEnvelope) store.passwordEnvelope = body.passwordEnvelope;
        if (body.recoveryEnvelope) store.recoveryEnvelope = body.recoveryEnvelope;
        return json(res, 200, { ok: true });
      }
      if (p === "/api/vault/history") return json(res, 200, store.history);
      if (p === "/api/vault/conflicts") return json(res, 200, []);
      if (p === "/api/devices" && m === "GET") return json(res, 200, store.devices);
      if (p.startsWith("/api/devices/") && m === "DELETE") { store.devices = store.devices.filter((d) => `/api/devices/${d.id}` !== p); return json(res, 200, { ok: true }); }
      if (p === "/api/devices/pairing/start") return json(res, 200, { pin: "483920", secret: "mock-secret", expiresAt: new Date(Date.now() + 90_000).toISOString() });
      if (p === "/api/admin/users") return json(res, 200, [user, { id: "u-2", username: "dana", role: "user", active: true, ssoSub: "sub-dana" }]);
      if (p === "/api/admin/sso" && m === "GET") return json(res, 200, { enabled: true, issuerUrl: "https://signon.mock", clientId: "kyvault", autoProvision: true, clientSecretSet: true });
      if (p === "/api/admin/sso" && m === "PUT") return json(res, 200, { ok: true });
      if (p === "/api/admin/provisioning") return json(res, 200, { configured: false, basePath: "/scim/v2" });
      if (p === "/api/audit/verify") return json(res, 200, { valid: true, writeFailures: 0, error: "" });
      if (p === "/api/audit") return json(res, 200, [{ index: 1, timestamp: new Date().toISOString(), action: "auth.sso_login", userId: "u-1", deviceId: "", ipAddress: "127.0.0.1", details: "signed in via SSO", hash: "abc123def456abc123def456" }]);
      if (p === "/api/backup/status") return json(res, 200, { paired: false, keyHealthy: false, backupDir: "", allowPrivate: false, intervalSec: 0, localCopies: [] });
      if (p.startsWith("/api/admin/users/")) return json(res, 200, { ok: true });
      return json(res, 404, { error: `mock: no handler for ${m} ${p}` });
    });
  } };
}
