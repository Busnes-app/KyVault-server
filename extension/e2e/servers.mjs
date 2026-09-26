// Local fixtures for the e2e suites: the frontend mock API (5200), a TLS proxy in front of it
// (5443, the "server" the extension pairs with) and an https test site (5444). Port 5199 is
// never used. Nothing here is started by CI.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, "../../frontend");
export const MOCK_PORT = 5200;
export const SERVER_PORT = 5443;
export const SITE_PORT = 5444;
export const SERVER_ORIGIN = `https://localhost:${SERVER_PORT}`;
export const MOCK_ORIGIN = `http://localhost:${MOCK_PORT}`;
export const SITE = `https://127.0.0.1:${SITE_PORT}`;
// Same port, different host: a cross-site frame that a localhost or 127.0.0.1 grant cannot cover.
export const CROSS_SITE = `https://[::1]:${SITE_PORT}`;
// The mock redeems any PIN; the proxy refuses every other one with the real server's 400.
export const PIN = "483920";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Self-signed for localhost, 127.0.0.1 and ::1; generated once into the gitignored .certs/.
function certificate() {
  const dir = path.join(here, ".certs");
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  if (!fs.existsSync(key) || !fs.existsSync(cert)) {
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "30",
      "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"], { stdio: "ignore" });
  }
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function portInUse(port, host) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host });
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
  });
}

// Refuse to run over someone else's server rather than kill it.
async function assertFree(port) {
  for (const host of ["127.0.0.1", "::1"]) {
    if (await portInUse(port, host)) throw new Error(`Port ${port} is already in use on ${host}. Stop whatever holds it and rerun.`);
  }
}

async function startMock(log) {
  const vite = path.join(frontend, "node_modules/.bin/vite");
  if (!fs.existsSync(vite)) throw new Error("frontend/node_modules is missing. Run `npm ci` in frontend/ first.");
  const child = spawn(vite, ["--port", String(MOCK_PORT), "--strictPort"], {
    cwd: frontend, env: { ...process.env, KYVAULT_MOCK_API: "1" }, detached: true, stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => log(`mock: ${d}`.trim()));
  child.stderr.on("data", (d) => log(`mock: ${d}`.trim()));
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error(`The mock exited with ${child.exitCode}.`);
    try {
      if ((await fetch(`${MOCK_ORIGIN}/api/vault/metadata`)).ok) return child;
    } catch {
      // not up yet
    }
    await sleep(250);
  }
  throw new Error("The mock did not answer within 30 seconds.");
}

function stopMock(child) {
  if (child.exitCode !== null) return;
  try {
    process.kill(-child.pid, "SIGTERM"); // the whole process group, vite included
  } catch {
    // already gone
  }
}

// The test pages. Each records input/change events and counts submits (always prevented).
const recorder = `<script>
window.log = []; window.submitted = 0;
for (const el of document.querySelectorAll("input")) for (const t of ["input", "change"]) el.addEventListener(t, (e) => window.log.push(t + ":" + el.name + ":" + e.bubbles));
for (const f of document.querySelectorAll("form")) f.addEventListener("submit", (e) => { e.preventDefault(); window.submitted++; });
</script>`;
const loginForm = (title) => `<!doctype html><title>${title}</title><h1>${title}</h1>
<form action="/never" method="post"><input name="username" type="text" autocomplete="username">
<input name="password" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>${recorder}`;
// React decides whether onChange fires by comparing the DOM value with a tracker that an
// instance-level value setter updates. A fill through the instance setter is invisible to
// the app; only the prototype setter plus a bubbling input event updates window.state.
const reactForm = `<!doctype html><title>React form</title><h1>React form</h1><div id="app"></div><script>
window.log = []; window.submitted = 0; window.state = { username: "", password: "" };
const app = document.getElementById("app");
const form = document.createElement("form");
const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
for (const [name, type] of [["username", "text"], ["password", "password"]]) {
  const el = document.createElement("input"); el.name = name; el.type = type;
  let tracked = "";
  Object.defineProperty(el, "value", { configurable: true, get() { return proto.get.call(this); }, set(v) { tracked = String(v); proto.set.call(this, v); } });
  for (const t of ["input", "change"]) app.addEventListener(t, (e) => {
    if (e.target !== el) return;
    window.log.push(t + ":" + name + ":" + e.bubbles);
    const current = proto.get.call(el);
    if (current !== tracked) { tracked = current; window.state[name] = current; window.log.push("onChange:" + name); }
  });
  form.append(el);
}
const button = document.createElement("button"); button.type = "submit"; button.textContent = "Sign in"; form.append(button);
form.addEventListener("submit", (e) => { e.preventDefault(); window.submitted++; });
app.append(form);
</script>`;
const pages = {
  "/": "<!doctype html><title>Test site</title><h1>Test site</h1>",
  "/plain.html": loginForm("Plain login"),
  "/react.html": reactForm,
  "/inner.html": loginForm("Inner login"),
  "/frame-same.html": `<!doctype html><title>Same-site frame</title><iframe src="${SITE}/inner.html" width="600" height="300"></iframe>`,
  "/frame-cross.html": `<!doctype html><title>Cross-site frame</title><iframe src="${CROSS_SITE}/inner.html" width="600" height="300"></iframe>`,
};

export async function startServers({ log = () => {} } = {}) {
  for (const port of [MOCK_PORT, SERVER_PORT, SITE_PORT]) await assertFree(port);
  const tls = certificate();
  const mock = await startMock(log);
  let killNextUpload = false;
  let proxies = [];

  const proxy = (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      log(`proxy ${req.method} ${req.url} bearer=${Boolean(req.headers.authorization)} if-match=${req.headers["if-match"] ?? "-"}`);
      if (killNextUpload && req.method === "POST" && req.url === "/api/vault/upload") {
        // The server dies mid-save: no answer, no stored bytes, back after a few seconds.
        killNextUpload = false;
        req.socket.destroy();
        closeProxy();
        setTimeout(() => openProxy().catch((e) => log(`proxy restart failed: ${e}`)), 5000);
        return;
      }
      if (req.method === "POST" && req.url === "/api/devices/pairing/redeem") {
        let pin = "";
        try { pin = JSON.parse(body.toString()).codeOrPin; } catch { /* malformed counts as wrong */ }
        if (pin !== PIN) { res.writeHead(400, { "Content-Type": "text/plain" }); return res.end("invalid or expired pairing code\n"); }
      }
      const upstream = http.request({ host: "localhost", port: MOCK_PORT, method: req.method, path: req.url,
        headers: { ...req.headers, host: `localhost:${MOCK_PORT}` } }, (up) => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
      upstream.on("error", (e) => { res.writeHead(502); res.end(String(e)); });
      upstream.end(body);
    });
  };
  const listen = (handler, port, host) => new Promise((resolve, reject) => {
    const server = https.createServer(tls, handler);
    server.once("error", reject);
    server.listen(port, host, () => resolve(server));
  });
  async function openProxy() {
    if (proxies.length) return;
    proxies = await Promise.all(["127.0.0.1", "::1"].map((h) => listen(proxy, SERVER_PORT, h)));
  }
  function closeProxy() {
    for (const s of proxies) { s.close(); s.closeAllConnections(); }
    proxies = [];
  }
  await openProxy();

  const site = (req, res) => {
    const page = pages[new URL(req.url, SITE).pathname];
    if (!page) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(page);
  };
  const sites = await Promise.all(["127.0.0.1", "::1"].map((h) => listen(site, SITE_PORT, h)));

  return {
    killNextUpload: () => { killNextUpload = true; },
    proxyUp: () => proxies.length > 0,
    async stop() {
      closeProxy();
      for (const s of sites) { s.close(); s.closeAllConnections(); }
      stopMock(mock);
    },
  };
}
