// Firefox e2e against LibreWolf over WebDriver BiDi (puppeteer-core). `web-ext run` cannot
// attach to LibreWolf, so dist/firefox is installed through BiDi as a temporary add-on.
// Covers pairing, unlock, list, fill and save; the popup is opened and driven from the
// browser's chrome scope (browserAction.triggerAction, then a frame script in the popup).
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";
import { EMPTY_FORM, ENTRIES, MASTER_PASSWORD, formState, item, notRunItem, printSummary, seedVault, serverVersion, sleep, waitFor } from "./helpers.mjs";
import { CROSS_SITE, PIN, SERVER_ORIGIN, SITE, startServers } from "./servers.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(here, "../dist/firefox");
const BROWSER = process.env.KYVAULT_E2E_FIREFOX ?? "/usr/bin/librewolf";
const ADDON_ID = "kyvault@busnes.app";
const UUID = "6b1f0e36-8c3f-4b5a-9d7e-0000000e2e00";
const BASE = `moz-extension://${UUID}/`;
const HOST_PATTERN = "https://localhost/*";

const missing = !fs.existsSync(BROWSER) ? `${BROWSER} not found (set KYVAULT_E2E_FIREFOX to a Firefox or LibreWolf binary).`
  : !fs.existsSync(path.join(DIST, "manifest.json")) ? "dist/firefox is missing. Run `npm run build` first." : undefined;

printSummary("Firefox e2e");

if (missing) notRunItem("Firefox suite", missing);
else suite();

// A frame script carrying `fn` itself: the popup's CSP blocks Function() inside it, but not
// a frame script's own code. `content` is the popup window.
const frameScript = (id, fn, args) => `(async () => {
  try {
    const value = await (${fn})(content, content.document, ${JSON.stringify(args)});
    sendAsyncMessage("e2e:result", { id: ${id}, value: JSON.stringify(value) });
  } catch (e) { sendAsyncMessage("e2e:result", { id: ${id}, error: String(e) }); }
})();`;

function suite() {
  let servers;
  let browser;
  let profile;
  let options;
  let tab;

  before(async () => {
    servers = await startServers();
    profile = fs.mkdtempSync(path.join(os.tmpdir(), "kyvault-e2e-firefox-"));
    browser = await puppeteer.launch({
      browser: "firefox",
      executablePath: BROWSER,
      headless: !process.env.KYVAULT_E2E_HEADFUL,
      acceptInsecureCerts: true,
      userDataDir: profile,
      args: ["--remote-allow-system-access"],
      extraPrefsFirefox: {
        "extensions.webextensions.uuids": JSON.stringify({ [ADDON_ID]: UUID }),
        "network.stricttransportsecurity.preloadlist": false,
      },
    });
    await browser.installExtension(DIST);
    await seedVault(await browser.newPage());
  });

  after(async () => {
    await browser?.close().catch(() => {});
    await servers?.stop();
    if (profile) fs.rmSync(profile, { recursive: true, force: true });
  });

  // Evaluates an async function body in the browser window's chrome scope.
  async function chrome(body) {
    const tree = await browser.connection.send("browsingContext.getTree", { "moz:scope": "chrome" });
    const context = tree.result.contexts[0].context;
    const r = await browser.connection.send("script.evaluate", {
      expression: `(async () => { ${body} })().then((v) => JSON.stringify(v))`, target: { context }, awaitPromise: true,
    });
    if (r.result.type === "exception") throw new Error(JSON.stringify(r.result.exceptionDetails.text ?? r.result.exceptionDetails));
    const value = r.result.result.value;
    return value === undefined ? undefined : JSON.parse(value);
  }

  const extension = `WebExtensionPolicy.getByID(${JSON.stringify(ADDON_ID)}).extension`;
  const parent = `ChromeUtils.importESModule("resource://gre/modules/ExtensionParent.sys.mjs").ExtensionParent`;

  async function closePopup() {
    await chrome(`const { ViewPopup } = ChromeUtils.importESModule("resource:///modules/ExtensionPopups.sys.mjs");
      const p = ViewPopup.for(${extension}, window); if (p) p.closePopup(); return Boolean(p);`);
  }

  // The toolbar click: grants activeTab on the selected tab and opens the popup.
  async function openPopup() {
    await closePopup();
    await tab.bringToFront();
    await chrome(`${parent}.apiManager.global.browserActionFor(${extension}).triggerAction(window); return 1;`);
    await waitFor(() => popup(async (win, doc) => doc.readyState === "complete" && Boolean(doc.querySelector("#root > *"))).catch(() => false),
      { timeout: 15_000, what: "the popup" });
  }

  // Runs `fn(content, doc, args)` in the open popup and returns its JSON-able result.
  async function popup(fn, args = null) {
    const id = Math.floor(Math.random() * 2 ** 31);
    const r = await chrome(`
      const browserEl = document.querySelector("browser.webextension-popup-browser");
      if (!browserEl) return { error: "no popup open" };
      const mm = browserEl.messageManager;
      return await new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ error: "timeout" }), 60000);
        mm.addMessageListener("e2e:result", function listener(m) {
          if (m.data.id !== ${id}) return;
          mm.removeMessageListener("e2e:result", listener); clearTimeout(timer); resolve(m.data);
        });
        mm.loadFrameScript("data:application/javascript," + encodeURIComponent(${JSON.stringify(frameScript(id, fn.toString(), args))}), false);
      });`);
    if (r.error) throw new Error(r.error);
    return r.value === undefined ? undefined : JSON.parse(r.value);
  }

  const popupText = () => popup((win, doc) => doc.getElementById("root").innerText);
  const titles = () => popup((win, doc) => [...doc.querySelectorAll(".entry-row .entry-heading p:first-child")].map((p) => p.textContent));
  const status = () => popup((win, doc) => [...doc.querySelectorAll("[role=status]")].map((s) => s.textContent).join(" ").trim());
  const search = async (query) => {
    await popup((win, doc, q) => { const s = doc.querySelector("input[type=search]"); s.value = q; s.dispatchEvent(new win.Event("input")); }, query);
    await sleep(700);
    return titles();
  };
  const unlock = (password) => popup((win, doc, pw) => { doc.querySelector("#password").value = pw; doc.querySelector("form button[type=submit]").click(); }, password);
  const clickRowButton = (title, label) => popup((win, doc, [t, l]) => {
    const row = [...doc.querySelectorAll(".entry-row")].find((r) => r.querySelector("p").textContent === t);
    const button = [...row.querySelectorAll("button")].find((b) => b.textContent === l);
    if (button.disabled) return { disabled: true, title: button.title };
    button.click();
    return { disabled: false };
  }, [title, label]);

  const storage = () => options.evaluate(async () => ({ local: await browser.storage.local.get(null), session: await browser.storage.session.get(null) }));
  const optionsText = () => options.evaluate(() => document.getElementById("root").innerText);

  async function fillPairingForm(pin) {
    const [server, code] = await options.$$("#root input");
    await server.evaluate((el) => { el.value = ""; });
    await server.type(SERVER_ORIGIN);
    await code.evaluate((el) => { el.value = ""; });
    await code.type(pin);
    await options.click("xpath/.//button[normalize-space()='Pair']");
  }

  // BiDi never reports a moz-extension:// navigation as finished, so goto() times out on a
  // page that did load; the selector wait is the real check.
  async function openExtensionPage(page, file) {
    await page.goto(`${BASE}${file}`, { timeout: 5000 }).catch((e) => { if (e.name !== "TimeoutError") throw e; });
    await page.waitForSelector("#root button");
  }

  const hostGranted = async () => (await options.evaluate(() => browser.permissions.getAll())).origins.includes(HOST_PATTERN);

  item("F2 options: permission https://localhost/*, wrong PIN sentence, real PIN pairs", async ({ note }) => {
    options = await browser.newPage();
    await openExtensionPage(options, "options.html");
    await options.evaluate(() => {
      window.permissionRequests = [];
      const original = browser.permissions.request.bind(browser.permissions);
      browser.permissions.request = (arg) => { window.permissionRequests.push(JSON.stringify(arg)); return original(arg); };
    });
    await fillPairingForm("000000");
    await sleep(2500);
    // Accept the permission doorhanger the way its Allow button does.
    const accepted = await chrome(`const n = PopupNotifications.panel.firstElementChild?.notification;
      if (!n) return false; n.mainAction.callback({ checkboxChecked: false, source: "button" }); PopupNotifications.remove(n); return true;`);
    await sleep(1500);
    if (!(await hostGranted())) {
      await chrome(`const { ExtensionPermissions } = ChromeUtils.importESModule("resource://gre/modules/ExtensionPermissions.sys.mjs");
        await ExtensionPermissions.add(${JSON.stringify(ADDON_ID)}, { origins: [${JSON.stringify(HOST_PATTERN)}], permissions: [] }, ${extension}); return 1;`);
      note(`doorhanger ${accepted ? "found but its Allow action did not grant" : "not found"}; host granted through ExtensionPermissions`);
      await openExtensionPage(options, "options.html");
      await fillPairingForm("000000");
    } else {
      note("permission doorhanger shown and accepted through its Allow action (chrome scope)");
    }
    const requests = await options.evaluate(() => window.permissionRequests ?? []);
    if (requests.length) assert.equal(requests[0], JSON.stringify({ origins: [HOST_PATTERN] }));
    await waitFor(async () => (await optionsText()).includes("The pairing code was wrong or has expired."), { what: "the wrong-PIN sentence" });
    await fillPairingForm(PIN);
    await waitFor(async () => (await optionsText()).startsWith(`Paired with ${SERVER_ORIGIN} as Browser extension.`), { what: "the paired view" });
    const granted = (await options.evaluate(() => browser.permissions.getAll())).origins;
    assert.deepEqual(granted, [HOST_PATTERN]);
    const { local, session } = await storage();
    assert.ok(local.sessionToken);
    assert.deepEqual(session, {});
    assert.ok(!(await options.content()).includes(local.sessionToken));
    note(`requested ${requests[0] ?? "(not recorded)"}; wrong-PIN sentence shown; paired; origins ${JSON.stringify(granted)}; token not in the page`);
  });

  item("F3 popup: wrong password, then unlock keeps the key in storage.session only", async ({ note }) => {
    tab = await browser.newPage();
    await tab.goto(`${SITE}/plain.html`);
    await openPopup();
    await waitFor(() => popup((win, doc) => Boolean(doc.querySelector("#password"))), { what: "the unlock form" });
    await unlock("wrong password here");
    await waitFor(async () => (await status()) === "That password did not unlock the vault. Check it and try again.", { timeout: 30_000, what: "the wrong-password sentence" });
    assert.deepEqual((await storage()).session, {});
    await unlock(MASTER_PASSWORD);
    await waitFor(() => popup((win, doc) => Boolean(doc.querySelector(".entries"))), { timeout: 30_000, what: "the entry list" });
    const { local, session } = await storage();
    assert.match(session.keyHex, /^[0-9a-f]{64}$/);
    assert.ok(!JSON.stringify(local).includes(session.keyHex));
    note(`storage.session keys ${Object.keys(session).sort().join(",")}; storage.local has no key`);
  });

  item("F4 entries for the active tab's host rank first; search works", async ({ note }) => {
    await openPopup();
    assert.deepEqual(await titles(), ["Carol test site", "Test site login"]);
    assert.deepEqual(await search("login"), ["Carol test site", "Test site login", "Mock server login"]);
    assert.deepEqual(await search("zeta"), ["Zeta example"]);
    note("site entries only without a query; site entries first with one");
  });

  item("F7 fill: plain, React-style and same-site frame; cross-site frame and other host refused", async ({ note }) => {
    const alice = ENTRIES[0];
    const top = () => tab.mainFrame();
    const child = () => tab.frames().find((f) => f !== tab.mainFrame());
    async function fillOn(page, frameOf) {
      await tab.goto(`${SITE}/${page}`);
      await waitFor(async () => frameOf()?.url().endsWith(".html") && (await frameOf().$("input[name=password]")), { what: `the form in ${page}` });
      await openPopup();
      await sleep(800);
      const afterOpen = await formState(frameOf());
      await clickRowButton("Test site login", "Fill");
      const said = await waitFor(() => status(), { what: "the fill status" });
      await sleep(300);
      return { afterOpen, said, result: await formState(frameOf()) };
    }
    const strip = (s) => ({ ...s, reactState: undefined });
    for (const [page, frameOf] of [["plain.html", top], ["react.html", top], ["frame-same.html", child]]) {
      const r = await fillOn(page, frameOf);
      assert.deepEqual(strip(r.afterOpen), strip(EMPTY_FORM), `${page}: opening the popup changed the form`);
      assert.equal(r.said, "Filled.");
      assert.equal(r.result.username, alice.username);
      assert.equal(r.result.passwordLength, alice.password.length);
      assert.equal(r.result.submitted, 0);
      if (r.result.reactState) assert.deepEqual(r.result.reactState, { username: alice.username, passwordLength: alice.password.length });
    }
    note("plain, React-style (state updated) and same-site frame filled, no submit");
    const cross = await fillOn("frame-cross.html", child);
    assert.equal(child().url(), `${CROSS_SITE}/inner.html`);
    assert.notEqual(cross.said, "Filled.");
    assert.deepEqual(strip(cross.result), strip(EMPTY_FORM));
    note(`cross-site frame not filled ("${cross.said}")`);
    await tab.goto(`${SITE}/plain.html`);
    await openPopup();
    await search("bob");
    const other = await clickRowButton("Mock server login", "Fill");
    assert.deepEqual(other, { disabled: true, title: "This login is for localhost, not this page." });
    note(`other host: Fill disabled ("${other.title}")`);
  });

  item("F8 save login: version advances and the entry is listed", async ({ note }) => {
    const v0 = await serverVersion();
    await openPopup();
    await popup((win, doc) => {
      doc.querySelector("details").open = true;
      doc.querySelector("#save-title").value = "Saved from Firefox";
      doc.querySelector("#save-username").value = "wolf";
      doc.querySelector("#save-password").value = "Wolf-Pass-5444!";
      doc.querySelector("details form").requestSubmit();
    });
    await waitFor(async () => (await popup((win, doc) => doc.querySelector("form [role=status]").textContent)) === "Saved to the vault.", { timeout: 30_000, what: "the save" });
    assert.equal(await serverVersion(), v0 + 1);
    assert.ok((await titles()).includes("Saved from Firefox"));
    note(`version ${v0} -> ${v0 + 1}, listed`);
    await closePopup();
  });

  for (const [name, why] of [
    ["F1 manifest warnings", "`npm run lint` (web-ext lint) covers the Firefox manifest"],
    ["F5 clipboard clear", "Firefox has no offscreen API; the clear runs only while the popup is open (README)"],
    ["F6 TOTP", "covered in Chromium; the generator is shared code"],
    ["F9 revoke", "Chromium only in this suite"],
    ["F10 idle lock", "Chromium only in this suite"],
    ["F11 console errors", "Chromium only in this suite"],
  ]) notRunItem(name, why);
}
