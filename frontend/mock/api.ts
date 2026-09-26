// Dev-only stand-in for the Go API so the UI can run without KySignOn. Never built.
import type { Plugin } from "vite";
import { createHash } from "node:crypto";

type Store = {
  version: number; keyEpochSince: number; bytes: Buffer | null; passwordEnvelope?: string; recoveryEnvelope?: string;
  history: Array<{ id: string; version: number; sizeBytes: number; checksum: string; timestamp: string; bytes: Buffer }>;
  conflicts: Array<{ id: string; expectedVersion: number; deviceId: string; sizeBytes: number; timestamp: string; bytes: Buffer }>;
  devices: Array<{ id: string; name: string; platform: string; lastSeenAt: string; lastIp: string; current: boolean }>;
};

export function mockApi(): Plugin {
  const store: Store = { version: 0, keyEpochSince: 0, bytes: null, history: [], conflicts: [], devices: [
    { id: "dev-1", name: "Pixel 9", platform: "android", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.7", current: false },
    { id: "dev-2", name: "Firefox extension", platform: "browser", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.8", current: false },
  ] };
  const user = { id: "u-1", username: "mock-admin", role: "admin", active: true, ssoSub: "sub-mock" };
  const json = (res: import("node:http").ServerResponse, status: number, body: unknown) => {
    res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(body));
  };
  const readBody = (req: import("node:http").IncomingMessage) => new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []; req.on("data", (c) => chunks.push(c)); req.on("end", () => resolve(Buffer.concat(chunks)));
  });
  // Like the Go store: archive the outgoing copy as a snapshot before replacing it.
  const archive = (suffix = "") => {
    if (!store.bytes) return;
    const meta = metadata();
    store.history.unshift({ id: `${Date.now()}_v${store.version}${suffix}`, version: store.version, sizeBytes: meta.sizeBytes,
      checksum: meta.checksum, timestamp: new Date().toISOString(), bytes: store.bytes });
  };
  const listed = <T extends { bytes: Buffer }>(items: T[]) => items.map(({ bytes: _bytes, ...rest }) => rest);
  const binary = (res: import("node:http").ServerResponse, bytes: Buffer) => {
    res.setHeader("Content-Type", "application/x-keepass2"); res.setHeader("Cache-Control", "no-store"); res.end(bytes);
  };
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
        const body = await readBody(req);
        if (expected !== store.version) {
          const id = `${Date.now()}_web_exp${expected}`;
          store.conflicts.unshift({ id, expectedVersion: expected, deviceId: "web", sizeBytes: body.length, timestamp: new Date().toISOString(), bytes: body });
          return json(res, 409, { error: "conflict", currentVersion: store.version, expectedVersion: expected, conflictId: id });
        }
        const rotated = req.headers["x-vault-key-rotated"] === "1";
        if (rotated && !(req.headers["x-password-envelope"] && req.headers["x-recovery-envelope"])) return json(res, 400, { error: "a key rotation must carry both new envelopes" });
        archive();
        store.bytes = body; store.version++;
        if (rotated) { store.keyEpochSince = store.version; store.devices = []; }
        const env = req.headers["x-password-envelope"]; if (typeof env === "string" && env) store.passwordEnvelope = env;
        const rec = req.headers["x-recovery-envelope"]; if (typeof rec === "string" && rec) store.recoveryEnvelope = rec;
        return json(res, 200, { ok: true, metadata: metadata() });
      }
      if (p === "/api/vault/envelopes" && m === "PUT") {
        const expected = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
        if (expected !== store.version) return json(res, 409, { error: "The vault changed on the server since this key was checked. Reload the vault and try again." });
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        if (body.passwordEnvelope) store.passwordEnvelope = body.passwordEnvelope;
        if (body.recoveryEnvelope) store.recoveryEnvelope = body.recoveryEnvelope;
        return json(res, 200, { ok: true });
      }
      if (p === "/api/vault/history") return json(res, 200, listed(store.history).map((h) => ({ ...h, staleKey: h.version < store.keyEpochSince })));
      if (p === "/api/vault/conflicts") return json(res, 200, listed(store.conflicts));
      const snapshot = store.history.find((h) => p.startsWith(`/api/vault/history/${h.id}`));
      if (snapshot && p === `/api/vault/history/${snapshot.id}` && m === "GET") return binary(res, snapshot.bytes);
      if (snapshot && p === `/api/vault/history/${snapshot.id}/restore` && m === "POST") {
        if (snapshot.version < store.keyEpochSince) return json(res, 409, { error: "This snapshot was saved under a previous vault key. The current key cannot open it, so it cannot be rolled back to." });
        archive("_before_rollback"); store.bytes = snapshot.bytes; store.version++;
        return json(res, 200, { ok: true, metadata: metadata() });
      }
      const conflict = store.conflicts.find((c) => p === `/api/vault/conflicts/${c.id}`);
      if (conflict && m === "GET") return binary(res, conflict.bytes);
      if (conflict && m === "DELETE") { store.conflicts = store.conflicts.filter((c) => c !== conflict); return json(res, 200, { ok: true }); }
      if (p === "/api/devices" && m === "GET") return json(res, 200, store.devices);
      if (p.startsWith("/api/devices/") && m === "DELETE") { store.devices = store.devices.filter((d) => `/api/devices/${d.id}` !== p); return json(res, 200, { ok: true }); }
      if (p.startsWith("/api/devices/") && m === "PATCH") {
        const id = p.slice("/api/devices/".length);
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        const name = String(body.name ?? "").trim();
        if (!name || name.length > 64) return json(res, 400, { error: "invalid device name" });
        const device = store.devices.find((d) => d.id === id);
        if (!device) return json(res, 404, { error: "device not found" });
        device.name = name;
        return json(res, 200, device);
      }
      if (p === "/api/devices/pairing/start") return json(res, 200, { pin: "483920", secret: "mock-secret", expiresAt: new Date(Date.now() + 90_000).toISOString() });
      if (p === "/api/devices/pairing/redeem" && m === "POST") {
        const id = `dev-${store.devices.length + 1}`;
        store.devices.push({ id, name: "New device", platform: "mock", lastSeenAt: new Date().toISOString(), lastIp: "127.0.0.1", current: false });
        return json(res, 200, { ok: true, deviceId: id, sessionToken: "mock-token", user: { id: user.id } });
      }
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
