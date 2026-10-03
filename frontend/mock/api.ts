// Dev-only stand-in for the Go API so the UI can run without KySignOn. Never built.
import type { Plugin } from "vite";
import { keyDigest, type ReportConfig, type ReportRecord } from "../src/lib/adminReport";
import { createHash, randomBytes, randomUUID } from "node:crypto";

type VaultData = {
  version: number; bytes: Buffer | null;
  history: Array<{ id: string; version: number; sizeBytes: number; checksum: string; timestamp: string; bytes: Buffer }>;
  conflicts: Array<{ id: string; expectedVersion: number; deviceId: string; sizeBytes: number; timestamp: string; bytes: Buffer }>;
};

type Store = VaultData & {
  keyEpochSince: number; passwordEnvelope?: string; recoveryEnvelope?: string;
  devices: Array<{ id: string; name: string; platform: string; lastSeenAt: string; lastIp: string; current: boolean }>;
  userKey: undefined | Record<string, unknown>;
};

type Role = "owner" | "editor" | "reader";
type MemberState = "invited" | "active" | "stale" | "suspended";
type SharedMember = {
  userId: string; role: Role; state: MemberState; sealedKey: string; sealedBy: string; sealedByFingerprint: string;
  keyFingerprint: string; keyEpoch: number; addedAt: string; acceptedAt?: string;
};
type Pending = { since: string; userId: string; reason: "removed" | "left" | "declined" };
type SharedVault = VaultData & { id: string; name: string; createdBy: string; createdAt: string; keyEpoch: number;
  rotationPending?: Pending; members: SharedMember[] };

export function mockApi(): Plugin {
  let reporting: ReportConfig = {instanceId: [...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,"0")).join(""), generation: [...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,"0")).join(""), enabled:false};
  const reports = new Map<string,ReportRecord>();
  const endedSessions = new Set<string>();
  const sessions = () => {
    const now = Date.now();
    const rows = [
      { id: "browser-current", kind: "browser", ip: "192.0.2.10", issuedAt: new Date(now - 3_600_000).toISOString(), authenticatedAt: new Date(now - 3_600_000).toISOString(), expiresAt: new Date(now + 82_800_000).toISOString(), current: true },
      { id: "browser-other", kind: "browser", ip: "198.51.100.7", issuedAt: new Date(now - 7_200_000).toISOString(), authenticatedAt: new Date(now - 7_200_000).toISOString(), expiresAt: new Date(now + 79_200_000).toISOString(), current: false },
      ...store.devices.map((d) => ({ id: `device-${d.id}`, kind: "device", deviceId: d.id, deviceName: d.name, ip: d.lastIp, issuedAt: d.lastSeenAt, expiresAt: new Date(now + 89 * 86_400_000).toISOString(), current: false })),
    ];
    return rows.filter((r) => !endedSessions.has(r.id));
  };
  const store: Store = { version: 0, keyEpochSince: 0, bytes: null, history: [], conflicts: [], userKey: undefined, devices: [
    { id: "dev-1", name: "Pixel 9", platform: "android", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.7", current: false },
    { id: "dev-2", name: "Firefox extension", platform: "browser", lastSeenAt: new Date().toISOString(), lastIp: "10.0.0.8", current: false },
  ] };
  // Device bearer tokens issued by redeem; a token dies with its device. Requests without
  // a bearer header are the web app's cookie session and pass as before.
  const tokens = new Map<string, string>();
  let deviceCount = store.devices.length;
  const user = { id: "u-1", username: "mock-admin", role: "admin", active: true, ssoSub: "sub-mock" };
  const json = (res: import("node:http").ServerResponse, status: number, body: unknown) => {
    res.statusCode = status; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(body));
  };
  const readBody = (req: import("node:http").IncomingMessage) => new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = []; req.on("data", (c) => chunks.push(c)); req.on("end", () => resolve(Buffer.concat(chunks)));
  });
  // Like the Go store: archive the outgoing copy as a snapshot before replacing it.
  const archive = (d: VaultData = store, suffix = "") => {
    if (!d.bytes) return;
    const meta = metaOf(d);
    d.history.unshift({ id: `${Date.now()}_v${d.version}${suffix}`, version: d.version, sizeBytes: meta.sizeBytes,
      checksum: meta.checksum, timestamp: new Date().toISOString(), bytes: d.bytes });
  };
  const listed = <T extends { bytes: Buffer }>(items: T[]) => items.map(({ bytes: _bytes, ...rest }) => rest);
  const binary = (res: import("node:http").ServerResponse, bytes: Buffer) => {
    res.setHeader("Content-Type", "application/x-keepass2"); res.setHeader("Cache-Control", "no-store"); res.end(bytes);
  };
  const metaOf = (d: VaultData) => ({ version: d.version, checksum: d.bytes ? createHash("sha256").update(d.bytes).digest("hex") : "",
    sizeBytes: d.bytes?.length ?? 0 });
  const metadata = () => ({ ...metaOf(store), passwordEnvelope: store.passwordEnvelope, recoveryEnvelope: store.recoveryEnvelope, userKey: store.userKey });

  // Plain-text errors, like the Go server's http.Error: the UI branches on the body text
  // (a 403 body starting "re-authenticate" is the one error with a link on screen).
  const fail = (res: import("node:http").ServerResponse, status: number, text: string) => {
    res.statusCode = status; res.setHeader("Content-Type", "text/plain; charset=utf-8"); res.end(text);
  };

  // ---- Shared vaults -------------------------------------------------------
  // Dana (u-2) gets a real X-Wing key pair at startup, so sealing a shared vault key to her
  // published key in the browser is real HPKE rather than a stub.
  const fingerprintOf = (publicKey: Buffer) =>
    createHash("sha256").update(publicKey).digest("hex").toUpperCase().slice(0, 20).match(/.{4}/g)!.join(" ");
  const hpke = (async () => {
    const [{ CipherSuite, HkdfSha256, Aes256Gcm }, { XWing }] = await Promise.all([import("@hpke/core"), import("@hpke/hybridkem-x-wing")]);
    return new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
  })();
  const dana = (async () => {
    const suite = await hpke;
    const pair = await suite.kem.generateKeyPair();
    const publicKey = Buffer.from(new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)));
    return { publicKey: publicKey.toString("base64"), fingerprint: fingerprintOf(publicKey), createdAt: new Date().toISOString() };
  })();
  const ab = (b: Buffer) => b.buffer.slice(b.byteOffset, b.byteOffset + b.length) as ArrayBuffer;
  // Duplicates frontend/src/lib/userKey.ts seal() and sharedKey.ts SHARED_KEY_INFO by hand, so
  // the mock can seal a shared vault key the browser really opens. It drifts if either changes.
  const sealTo = async (publicKeyB64: string, key: Buffer): Promise<string> => {
    const suite = await hpke;
    const recipientPublicKey = await suite.kem.importKey("raw", ab(Buffer.from(publicKeyB64, "base64")), true);
    const ctx = await suite.createSenderContext({ recipientPublicKey, info: new TextEncoder().encode("kyvault/shared-vault-key/1") });
    const ct = new Uint8Array(await ctx.seal(ab(key)));
    return Buffer.concat([Buffer.from(new Uint8Array(ctx.enc)), Buffer.from(ct)]).toString("base64");
  };
  const others: Record<string, string> = { "u-2": "dana", "u-3": "erin" };
  const usernameOf = (id: string) => (id === user.id ? user.username : others[id] ?? id);
  const publishedKey = async (userId: string): Promise<{ publicKey: string; fingerprint: string; createdAt: string } | null> => {
    if (userId === "u-2") return await dana;
    if (userId !== user.id || !store.userKey) return null;
    const publicKey = String(store.userKey.publicKey ?? "");
    if (!publicKey) return null;
    return { publicKey, fingerprint: fingerprintOf(Buffer.from(publicKey, "base64")), createdAt: String(store.userKey.createdAt ?? new Date().toISOString()) };
  };

  const emptyData = (): VaultData => ({ version: 0, bytes: null, history: [], conflicts: [] });
  const sid = (label: string) => `sv_${label.padEnd(22, "0").slice(0, 22)}`;
  // An invitation's sealed key is never opened by the UI, so filler of the right length stands in.
  const filler = Buffer.alloc(1168, 7).toString("base64");
  const sharedVaults: SharedVault[] = [];
  const sharedSettings = { createRestrictedToAdmins: false };
  let seeded = false;
  // Two invitations from dana: one whose invitation fingerprint is her published key (so the
  // Accept dialog reads unknown, then pinned once her key is pinned), one sealed by a key she
  // no longer publishes (so it reads "changed" — the invitation drift).
  const seedShared = async () => {
    await seedOwned();
    if (seeded) return;
    seeded = true;
    const d = await dana;
    const now = new Date().toISOString();
    const invitation = (label: string, name: string, sealedByFingerprint: string): SharedVault => ({
      ...emptyData(), id: sid(label), name, createdBy: "u-2", createdAt: now, keyEpoch: 1,
      members: [
        { userId: "u-2", role: "owner", state: "active", sealedKey: filler, sealedBy: "u-2", sealedByFingerprint: d.fingerprint, keyFingerprint: d.fingerprint, keyEpoch: 1, addedAt: now, acceptedAt: now },
        { userId: user.id, role: "editor", state: "invited", sealedKey: filler, sealedBy: "u-2", sealedByFingerprint, keyFingerprint: "", keyEpoch: 1, addedAt: now },
      ],
    });
    sharedVaults.push(invitation("household", "Household", d.fingerprint));
    sharedVaults.push(invitation("legal", "Legal", "0000 1111 2222 3333 4444"));
  };
  // The one vault the mock user owns, and the only one they can rotate: its key is really
  // sealed to their published user key, so it can be seeded only once the browser has
  // published one — hence the retry rather than a flag set up front. Its pending flag is
  // already set and erin publishes no key, so the rotation banner and the left-behind report
  // are both reachable without removing anyone first.
  let ownedSeeded = false;
  const seedOwned = async () => {
    if (ownedSeeded) return;
    const mine = await publishedKey(user.id);
    if (!mine) return;
    ownedSeeded = true;
    const d = await dana;
    const now = new Date().toISOString();
    const key = randomBytes(32);
    const member = (userId: string, role: Role, sealedKey: string, keyFingerprint: string): SharedMember => ({
      userId, role, state: "active", sealedKey, sealedBy: user.id, sealedByFingerprint: mine.fingerprint,
      keyFingerprint, keyEpoch: 1, addedAt: now, acceptedAt: now,
    });
    sharedVaults.push({
      ...emptyData(), id: sid("team"), name: "Team", createdBy: user.id, createdAt: now, keyEpoch: 1,
      rotationPending: { since: new Date(Date.now() - 3_600_000).toISOString(), userId: "u-4", reason: "removed" },
      members: [
        member(user.id, "owner", await sealTo(mine.publicKey, key), mine.fingerprint),
        member("u-2", "editor", filler, d.fingerprint),
        member("u-3", "reader", filler, "0000 1111 2222 3333 4444"),
      ],
    });
  };
  // Every departure flags a pending rotation, as shared.Store.Remove does: the row is gone,
  // but the copy of the vault key it held is not, and only a rotation retires that.
  const depart = (v: SharedVault, row: SharedMember, reason: Pending["reason"]) => {
    v.members = v.members.filter((x) => x !== row);
    v.rotationPending = { since: new Date().toISOString(), userId: row.userId, reason };
  };
  const memberView = (m: SharedMember) => ({ userId: m.userId, username: usernameOf(m.userId), role: m.role, state: m.state,
    keyFingerprint: m.keyFingerprint, keyEpoch: m.keyEpoch, addedAt: m.addedAt, acceptedAt: m.acceptedAt });
  const activeOwners = (v: SharedVault) => v.members.filter((x) => x.role === "owner" && x.state === "active");

  // The nine vault data routes, served from whichever store the caller reached them through.
  const vaultData = async (d: VaultData, sub: string, m: string, req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, canWrite: boolean, keyEpoch: number): Promise<boolean> => {
    const readOnly = () => { fail(res, 403, "this shared vault is read-only for you"); return true; };
    // withSharedWrite's epoch gate, by hand: a write must claim the vault's current key epoch,
    // or it is ciphertext under a key the vault has retired. A missing header is NaN, so stale.
    const wrongEpoch = () => {
      const claimed = Number(req.headers["x-shared-key-epoch"]);
      if (claimed === keyEpoch) return false;
      // Two refusals, as the server has: a client that said nothing is not a rotation.
      fail(res, 409, Number.isInteger(claimed)
        ? "the shared vault key was rotated; reload the vault"
        : "this write did not say which shared vault key it was made under; reload the vault");
      return true;
    };
    if (sub === "/metadata" && m === "GET") { json(res, 200, metaOf(d)); return true; }
    if (sub === "/kdbx" && m === "GET") {
      if (!d.bytes) { json(res, 404, { error: "vault does not exist yet" }); return true; }
      res.setHeader("ETag", `"${d.version}"`); res.setHeader("X-Vault-Version", String(d.version));
      binary(res, d.bytes); return true;
    }
    if (sub === "/upload" && m === "POST") {
      if (!canWrite) return readOnly();
      if (wrongEpoch()) return true;
      const expected = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
      const body = await readBody(req);
      if (expected !== d.version) {
        const id = `${Date.now()}_web_exp${expected}`;
        d.conflicts.unshift({ id, expectedVersion: expected, deviceId: "web", sizeBytes: body.length, timestamp: new Date().toISOString(), bytes: body });
        json(res, 409, { error: "conflict", currentVersion: d.version, expectedVersion: expected, conflictId: id });
        return true;
      }
      archive(d);
      d.bytes = body; d.version++;
      json(res, 200, { ok: true, metadata: metaOf(d) });
      return true;
    }
    if (sub === "/history" && m === "GET") { json(res, 200, listed(d.history)); return true; }
    if (sub === "/conflicts" && m === "GET") { json(res, 200, listed(d.conflicts)); return true; }
    const snap = /^\/history\/([^/]+?)(\/restore)?$/.exec(sub);
    if (snap) {
      const row = d.history.find((h) => h.id === decodeURIComponent(snap[1]));
      if (!row) { json(res, 404, { error: "not found" }); return true; }
      if (!snap[2] && m === "GET") { binary(res, row.bytes); return true; }
      if (snap[2] && m === "POST") {
        if (!canWrite) return readOnly();
        if (wrongEpoch()) return true;
        archive(d, "_before_rollback"); d.bytes = row.bytes; d.version++;
        json(res, 200, { ok: true, metadata: metaOf(d) });
        return true;
      }
    }
    const conf = /^\/conflicts\/([^/]+)$/.exec(sub);
    if (conf) {
      const row = d.conflicts.find((c) => c.id === decodeURIComponent(conf[1]));
      if (!row) { json(res, 404, { error: "not found" }); return true; }
      if (m === "GET") { binary(res, row.bytes); return true; }
      if (m === "DELETE") {
        if (!canWrite) return readOnly();
        if (wrongEpoch()) return true;
        d.conflicts = d.conflicts.filter((c) => c !== row);
        json(res, 200, { ok: true });
        return true;
      }
    }
    return false;
  };

  return { name: "kyvault-mock-api", configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const p = url.pathname; const m = req.method ?? "GET";
      if (!p.startsWith("/api/")) return next();
      res.setHeader("Set-Cookie", "csrf_token=mock-csrf; Path=/");
      const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
      if (bearer !== undefined && !store.devices.some((d) => d.id === tokens.get(bearer))) return json(res, 401, { error: "unauthorized" });
      if(p.startsWith("/api/reporting/")||p.startsWith("/api/admin/reporting")) {
        if(bearer!==undefined)return json(res,403,{error:"this action needs a browser session"});
        res.setHeader("Cache-Control","no-store");
        if(reporting.enabled&&reporting.publicKey!==store.userKey?.publicKey){reporting={instanceId:reporting.instanceId,generation:[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,"0")).join(""),enabled:false};reports.clear()}
        if(p==="/api/reporting/config"&&m==="GET")return json(res,200,reporting);
        if(p==="/api/admin/reporting/config"&&m==="PUT") {
          const b=JSON.parse((await readBody(req)).toString());
          if(b.generation!==reporting.generation)return json(res,409,{error:"report settings changed"});
          if(b.enabled) {
            if(b.recipientId!==user.id||typeof store.userKey?.publicKey!=="string")return json(res,400,{error:"recipient needs a published admin key"});
            const digest=await keyDigest(new Uint8Array(Buffer.from(store.userKey.publicKey,"base64")));
            if(digest!==b.keyDigest)return json(res,400,{error:"recipient key changed"});
            reporting={instanceId:reporting.instanceId,generation:[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,"0")).join(""),enabled:true,recipientId:user.id,recipientName:user.username,publicKey:store.userKey.publicKey,keyDigest:digest};
          }else reporting={instanceId:reporting.instanceId,generation:[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,"0")).join(""),enabled:false};
          reports.clear();return json(res,200,reporting);
        }
        if(p==="/api/reporting/report"&&m==="PUT") {
          const b=JSON.parse((await readBody(req)).toString());
          if(!reporting.enabled||b.generation!==reporting.generation||b.version!==store.version||b.sourceId!==user.id||b.keyDigest!==reporting.keyDigest)return json(res,409,{error:"report settings or vault changed; refresh and share again"});
          reports.set(user.id,{...b,receivedAt:new Date().toISOString()});return json(res,200,{ok:true});
        }
        if(p==="/api/reporting/report"&&m==="DELETE"){reports.delete(user.id);return json(res,200,{ok:true})}
        if(p==="/api/admin/reporting"&&m==="GET") {
          const r=reports.get(user.id),status=!store.version?"no-vault":!r?"not-submitted":r.version!==store.version?"stale-version":"current";
          const record=r?{...r,sealed:status==="current"?r.sealed:undefined}:undefined;
          return json(res,200,{config:reporting,rows:[{userId:user.id,username:user.username,status,record},{userId:"u-2",username:"dana",status:"not-submitted"}],next:""});
        }
      }
      if (p === "/api/auth/me") return json(res, 200, { authenticated: true, user });
      if (p === "/api/auth/sso-config") return json(res, 200, { enabled: true, issuerUrl: "https://signon.mock" });
      if (p === "/api/auth/logout") return json(res, 200, { ok: true });
      if (p === "/api/auth/sessions" && m === "GET") return json(res, 200, sessions());
      if (p.startsWith("/api/auth/sessions/") && m === "DELETE") {
        const id = p.slice("/api/auth/sessions/".length);
        if (id === "browser-current") return json(res, 400, { error: "use logout to end the current session" });
        endedSessions.add(id);
        store.devices = store.devices.filter((d) => `device-${d.id}` !== id);
        return json(res, 200, { ok: true });
      }
      if (p === "/api/vault/metadata") return json(res, 200, metadata());
      if (p === "/api/vault/kdbx") {
        if (!store.bytes) return json(res, 404, { error: "vault does not exist yet" });
        res.setHeader("Content-Type", "application/x-keepass2"); res.setHeader("ETag", `"${store.version}"`);
        res.setHeader("X-Vault-Version", String(store.version)); return res.end(store.bytes);
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
        if (rotated && store.userKey && !req.headers["x-user-key"]) return json(res, 400, { error: "a key rotation must carry the re-wrapped user key" });
        if (rotated && req.headers["x-user-key"]) {
          const decoded = JSON.parse(Buffer.from(String(req.headers["x-user-key"]), "base64").toString());
          if (!store.userKey) return json(res, 400, { error: "a key rotation must not publish a new user key" });
          if (decoded.publicKey !== store.userKey.publicKey) return json(res, 400, { error: "a key rotation must not change the public key" });
        }
        archive();
        store.bytes = body; store.version++;
        if (rotated) { store.keyEpochSince = store.version; store.devices = []; }
        const env = req.headers["x-password-envelope"]; if (typeof env === "string" && env) store.passwordEnvelope = env;
        const rec = req.headers["x-recovery-envelope"]; if (typeof rec === "string" && rec) store.recoveryEnvelope = rec;
        if (rotated && req.headers["x-user-key"]) {
          const decoded = JSON.parse(Buffer.from(String(req.headers["x-user-key"]), "base64").toString());
          store.userKey = { ...decoded, previous: store.userKey?.previous ?? [] };
        }
        return json(res, 200, { ok: true, metadata: metadata() });
      }
      if (p === "/api/vault/user-key" && m === "PUT") {
        const expected = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
        if (store.version === 0 || expected !== store.version) return json(res, 409, { error: "conflict" });
        if (req.headers["if-none-match"] === "*" && store.userKey) return json(res, 409, { error: "conflict" });
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        const prev = store.userKey && store.userKey.publicKey !== body.publicKey
          ? [...((store.userKey.previous as unknown[]) ?? []), { publicKey: store.userKey.publicKey, replacedAt: new Date().toISOString() }].slice(-5)
          : (store.userKey?.previous ?? []);
        store.userKey = { ...body, previous: prev };
        return json(res, 200, { ok: true, fingerprint: "MOCK FPRT" });
      }
      const keyMatch = p.match(/^\/api\/users\/([^/]+)\/key$/);
      if (keyMatch && m === "GET") {
        const id = decodeURIComponent(keyMatch[1]);
        const pub = await publishedKey(id);
        if (!pub) return json(res, 404, { error: "not found" });
        return json(res, 200, { userId: id, publicKey: pub.publicKey, fingerprint: pub.fingerprint, createdAt: pub.createdAt,
          previous: id === user.id ? store.userKey?.previous ?? [] : [] });
      }
      if (p === "/api/users/lookup" && m === "GET") {
        const name = (url.searchParams.get("username") ?? "").trim();
        for (const id of [user.id, "u-2"]) {
          if (usernameOf(id) !== name) continue;
          const pub = await publishedKey(id);
          if (pub) return json(res, 200, { userId: id, username: name, fingerprint: pub.fingerprint });
        }
        return fail(res, 404, "not found");
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
        archive(store, "_before_rollback"); store.bytes = snapshot.bytes; store.version++;
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
        const id = `dev-${++deviceCount}`; // never reused, so a revoked token stays dead
        store.devices.push({ id, name: "New device", platform: "mock", lastSeenAt: new Date().toISOString(), lastIp: "127.0.0.1", current: false });
        const sessionToken = `mock-token-${randomUUID()}`;
        tokens.set(sessionToken, id);
        return json(res, 200, { ok: true, deviceId: id, sessionToken, user: { id: user.id } });
      }
      // ---- /api/shared: the status codes the UI branches on (404 not a member, 403 a reader
      // write, 409 the last owner, 400 a fingerprint that moved under the form).
      if (p === "/api/shared" || p.startsWith("/api/shared/")) {
        await seedShared();
        if (p === "/api/shared" && m === "GET") {
          return json(res, 200, sharedVaults.flatMap((v) => {
            const me = v.members.find((x) => x.userId === user.id);
            if (!me) return [];
            return [{
              id: v.id, name: v.name, role: me.role, state: me.state, keyEpoch: v.keyEpoch,
              // Active owners only, as the server does: the flag names a departed member, and
              // an invitation discloses nothing about the membership before it is accepted.
              ...(me.role === "owner" && me.state === "active" ? { rotationPending: v.rotationPending } : {}),
              myKey: { sealedKey: me.sealedKey, keyFingerprint: me.keyFingerprint, keyEpoch: me.keyEpoch, sealedBy: me.sealedBy, sealedByFingerprint: me.sealedByFingerprint },
              ...(me.state === "invited" ? { invitedBy: { userId: me.sealedBy, username: usernameOf(me.sealedBy), fingerprint: me.sealedByFingerprint } } : {}),
            }];
          }));
        }
        if (p === "/api/shared" && m === "POST") {
          const body = JSON.parse((await readBody(req)).toString() || "{}");
          if (sharedSettings.createRestrictedToAdmins && user.role !== "admin") return fail(res, 403, "an administrator has restricted shared vault creation to administrators");
          const mine = await publishedKey(user.id);
          if (!mine) return fail(res, 404, "publish a user key before creating a shared vault");
          if (body.keyFingerprint !== mine.fingerprint) return fail(res, 400, "keyFingerprint does not match your current user key");
          const now = new Date().toISOString();
          const v: SharedVault = {
            ...emptyData(), id: sid(randomUUID().replace(/-/g, "")), name: String(body.name ?? ""), createdBy: user.id, createdAt: now, keyEpoch: 1,
            members: [{ userId: user.id, role: "owner", state: "active", sealedKey: String(body.sealedKey ?? ""), sealedBy: user.id, sealedByFingerprint: mine.fingerprint, keyFingerprint: mine.fingerprint, keyEpoch: 1, addedAt: now, acceptedAt: now }],
          };
          sharedVaults.push(v);
          return json(res, 201, { id: v.id });
        }
        const rest = p.slice("/api/shared/".length);
        const cut = rest.indexOf("/");
        const vaultId = decodeURIComponent(cut === -1 ? rest : rest.slice(0, cut));
        const sub = cut === -1 ? "" : rest.slice(cut);
        const v = sharedVaults.find((x) => x.id === vaultId);
        const me = v?.members.find((x) => x.userId === user.id);
        // Not a member, or no such vault: the same 404, so a non-member learns nothing.
        if (!v || !me) return fail(res, 404, "not found");
        const owner = me.role === "owner" && me.state === "active";
        const unaccepted = me.state === "invited" || (me.state === "stale" && !me.acceptedAt);

        if (sub === "/accept" && m === "POST") {
          if (me.state !== "invited") return fail(res, 409, "member is not in the required state");
          if (activeOwners(v).length === 0) return fail(res, 409, "member is not in the required state: the vault has no owner");
          me.state = "active"; me.acceptedAt = new Date().toISOString();
          return json(res, 200, { ok: true });
        }
        if (sub === "/decline" && m === "POST") {
          if (!unaccepted) return fail(res, 409, "only an invitation can be declined");
          depart(v, me, "declined");
          return json(res, 200, { ok: true });
        }
        if (sub === "" && m === "GET") {
          if (unaccepted) return fail(res, 404, "not found");
          return json(res, 200, { id: v.id, name: v.name, createdBy: v.createdBy, createdAt: v.createdAt, keyEpoch: v.keyEpoch,
            rotationPending: v.rotationPending, members: v.members.map(memberView) });
        }
        if (sub === "" && m === "PATCH") {
          if (!owner) return fail(res, 403, "only an owner can rename a shared vault");
          const body = JSON.parse((await readBody(req)).toString() || "{}");
          const name = String(body.name ?? "").trim();
          if (!name || name.length > 64) return fail(res, 400, "invalid shared vault input: name");
          v.name = name;
          return json(res, 200, { ok: true });
        }
        if (sub === "" && m === "DELETE") {
          if (!owner) return fail(res, 403, "only an owner can delete a shared vault");
          sharedVaults.splice(sharedVaults.indexOf(v), 1);
          return json(res, 200, { ok: true });
        }
        // An invitation reveals nothing but its own row: no members, no data.
        if (unaccepted || me.state === "suspended") return fail(res, 403, "forbidden");

        const members = /^\/members(?:\/([^/]+))?$/.exec(sub);
        if (members) {
          const targetId = members[1] ? decodeURIComponent(members[1]) : "";
          if (!targetId && m === "POST") {
            if (!owner) return fail(res, 403, "only an owner can add members");
            const body = JSON.parse((await readBody(req)).toString() || "{}");
            const target = await publishedKey(String(body.userId ?? ""));
            if (!target) return fail(res, 404, "user not found");
            if (v.members.some((x) => x.userId === body.userId)) return fail(res, 409, "already a member");
            if (body.keyFingerprint !== target.fingerprint) return fail(res, 400, "keyFingerprint does not match that user's current key");
            const mine = await publishedKey(user.id);
            const now = new Date().toISOString();
            v.members.push({ userId: String(body.userId), role: body.role as Role, state: "invited", sealedKey: String(body.sealedKey ?? ""),
              sealedBy: user.id, sealedByFingerprint: mine?.fingerprint ?? "", keyFingerprint: String(body.keyFingerprint), keyEpoch: v.keyEpoch, addedAt: now });
            return json(res, 200, { ok: true });
          }
          const row = v.members.find((x) => x.userId === targetId);
          if (m === "PUT") {
            if (!row) return fail(res, 404, "not found");
            const body = JSON.parse((await readBody(req)).toString() || "{}");
            const selfReseal = targetId === user.id && me.state === "stale" && body.role === undefined;
            if (!owner && !selfReseal) return fail(res, 403, "only an owner can change members");
            if (body.sealedKey || body.keyFingerprint) {
              if (!body.sealedKey || !body.keyFingerprint) return fail(res, 400, "sealedKey and keyFingerprint come together");
              const target = await publishedKey(targetId);
              if (!target) return fail(res, 404, "that user has not published a key yet");
              if (body.keyFingerprint !== target.fingerprint) return fail(res, 400, "keyFingerprint does not match that user's current key");
              const mine = await publishedKey(user.id);
              row.sealedKey = String(body.sealedKey); row.keyFingerprint = String(body.keyFingerprint);
              row.sealedBy = user.id; row.sealedByFingerprint = mine?.fingerprint ?? ""; row.keyEpoch = v.keyEpoch;
              if (row.state === "stale") row.state = row.acceptedAt ? "active" : "invited";
            }
            if (body.role !== undefined) {
              if (row.role === "owner" && body.role !== "owner" && row.state === "active" && activeOwners(v).length === 1) return fail(res, 409, "a shared vault keeps at least one active owner");
              row.role = body.role as Role;
            }
            return json(res, 200, { ok: true });
          }
          if (m === "DELETE") {
            if (!row) return fail(res, 404, "not found");
            if (targetId !== user.id && !owner) return fail(res, 403, "only an owner can remove members");
            if (row.role === "owner" && row.state === "active" && activeOwners(v).length === 1) return fail(res, 409, "a shared vault keeps at least one active owner");
            depart(v, row, targetId !== user.id ? "removed" : row.state === "invited" ? "declined" : "left");
            return json(res, 200, { ok: true });
          }
        }
        // The transitions of internal/api/shared_rotate.go and shared.Store.Rotate, by hand,
        // so they can drift: two parts in order, every sealed copy checked against that user's
        // current published key, the epoch and version proved, then the named members re-sealed,
        // the rest left stale and the retired key's history and conflicts dropped. The real
        // route also demands CSRF and a fresh sign-in, which the mock has no notion of.
        if (sub === "/rotate" && m === "POST") {
          if (!owner) return fail(res, 403, "only an owner can rotate a shared vault key");
          const body = await readBody(req);
          const form = await new Response(ab(body), { headers: { "content-type": String(req.headers["content-type"] ?? "") } }).formData().catch(() => null);
          const parts = form ? [...form.keys()] : [];
          if (!form || parts.length !== 2 || parts[0] !== "kdbx" || parts[1] !== "keys") return fail(res, 400, `rotate takes exactly two parts, "kdbx" then "keys"`);
          const kdbx = Buffer.from(new Uint8Array(await (form.get("kdbx") as Blob).arrayBuffer()));
          const keys = JSON.parse(String(form.get("keys")));
          const sealed = (keys.sealed ?? []) as Array<{ userId: string; sealedKey: string; keyFingerprint: string }>;
          if (!kdbx.length) return fail(res, 400, "empty vault payload");
          if (!sealed.length) return fail(res, 400, "a rotation must seal the new key for at least the caller");
          for (const sf of sealed) {
            if (!v.members.some((x) => x.userId === sf.userId)) return fail(res, 400, `invalid shared vault input: ${sf.userId} is not a member`);
            const target = await publishedKey(sf.userId);
            if (!target || target.fingerprint !== sf.keyFingerprint) return fail(res, 400, "keyFingerprint does not match that user's current key");
          }
          const named = new Set(sealed.map((s) => s.userId));
          if (!named.has(user.id)) return fail(res, 400, "a rotation must seal the new key for the caller's own row");
          const want = Number((req.headers["if-match"] ?? '"0"').toString().replace(/"/g, ""));
          if (keys.epoch !== v.keyEpoch || want !== v.version) return fail(res, 409, "the shared vault changed; reload it and rotate again");
          const next = v.keyEpoch + 1;
          const actorFingerprint = me.keyFingerprint; // read before the loop overwrites my own row
          for (const sf of sealed) {
            const row = v.members.find((x) => x.userId === sf.userId)!;
            row.sealedKey = sf.sealedKey; row.keyFingerprint = sf.keyFingerprint;
            row.sealedBy = user.id; row.sealedByFingerprint = actorFingerprint; row.keyEpoch = next;
            if (row.state !== "suspended") row.state = row.acceptedAt ? "active" : "invited";
          }
          for (const row of v.members) if (!named.has(row.userId) && row.state !== "suspended") row.state = "stale";
          v.keyEpoch = next; v.rotationPending = undefined;
          v.bytes = kdbx; v.version++;
          v.history = []; v.conflicts = [];
          return json(res, 200, { ok: true, metadata: metaOf(v), keyEpoch: next, historyCleared: true, epochMarked: true,
            leftBehind: v.members.filter((x) => x.keyEpoch !== next).map((x) => x.userId).sort() });
        }
        if (await vaultData(v, sub, m, req, res, me.role !== "reader", v.keyEpoch)) return;
        return fail(res, 404, `mock: no handler for ${m} ${p}`);
      }
      if (p === "/api/admin/shared" && m === "GET") {
        await seedShared();
        return json(res, 200, sharedVaults.map((v) => ({ id: v.id, name: v.name, createdBy: v.createdBy, createdAt: v.createdAt,
          keyEpoch: v.keyEpoch, ownerless: activeOwners(v).length === 0, rotationPending: v.rotationPending,
          members: v.members.map(memberView) })));
      }
      if (p === "/api/admin/shared/settings" && m === "GET") return json(res, 200, sharedSettings);
      if (p === "/api/admin/shared/settings" && m === "PUT") {
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        sharedSettings.createRestrictedToAdmins = !!body.createRestrictedToAdmins;
        return json(res, 200, { ok: true });
      }
      const adminShared = /^\/api\/admin\/shared\/([^/]+)(?:\/members\/([^/]+))?$/.exec(p);
      if (adminShared && m === "DELETE") {
        await seedShared();
        const v = sharedVaults.find((x) => x.id === decodeURIComponent(adminShared[1]));
        if (!v) return fail(res, 404, "not found");
        // One deliberately gated action, so the fresh-session refusal and its "Sign in again"
        // link can be exercised: the real server needs a recent KySignOn sign-in here.
        if (!adminShared[2]) return fail(res, 403, "re-authenticate to continue: this action needs a recent sign-in");
        const targetId = decodeURIComponent(adminShared[2]);
        const row = v.members.find((x) => x.userId === targetId);
        if (!row) return fail(res, 404, "not found");
        depart(v, row, "removed");
        return json(res, 200, { ok: true });
      }
      // Dev-only, no server counterpart: the UI cannot demote its own user, so a reader's
      // read-only vault is otherwise unreachable in the mock.
      if (p === "/api/mock/role" && m === "POST") {
        await seedShared();
        const body = JSON.parse((await readBody(req)).toString() || "{}");
        const row = sharedVaults.find((x) => x.id === body.vaultId)?.members.find((x) => x.userId === (body.userId ?? user.id));
        if (!row) return fail(res, 404, "not found");
        row.role = body.role as Role;
        return json(res, 200, { ok: true });
      }
      if (p === "/api/admin/users") return json(res, 200, [user, { id: "u-2", username: "dana", role: "user", active: true, ssoSub: "sub-dana" },
        { id: "u-3", username: "erin", role: "user", active: true, ssoSub: "sub-erin" }]);
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
