// Chromium e2e: the built dist/chrome in Playwright's Chromium, driven by puppeteer-core over
// the pipe transport, which is what exposes Extensions.triggerAction (a real toolbar click, so
// the popup gets activeTab exactly as a user's click grants it). Local only; see README.md.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";
import {
  EMPTY_FORM, ENTRIES, MASTER_PASSWORD, TOTP_SEED, editEntryInWebApp, formState, item, mockDevices, notRunItem,
  printSummary, reloadWebApp, revokeExtensionDevice, rfc6238SelfCheck, seedVault, serverVersion, sleep, totp, waitFor,
} from "./helpers.mjs";
import { CROSS_SITE, MOCK_ORIGIN, PIN, SERVER_ORIGIN, SITE, startServers } from "./servers.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(here, "../dist/chrome");
const HOST_PATTERN = "https://localhost/*";
const MESSAGES = {
  wrongPin: "The pairing code was wrong or has expired. Generate a new one in KyVault and try again.",
  paired: `Paired with ${SERVER_ORIGIN} as Browser extension.`,
  wrongPassword: "That password did not unlock the vault. Check it and try again.",
  conflict: "The vault changed elsewhere. Unlock again to refresh, then add the login again.",
  unconfirmed: `Could not reach ${SERVER_ORIGIN}. Check your connection and try again. KyVault could not confirm the save. Check the list above before adding it again.`,
  revoked: "This device was revoked. Pair again from the KyVault options page.",
};

function findChrome() {
  if (process.env.KYVAULT_E2E_CHROME) return process.env.KYVAULT_E2E_CHROME;
  const cache = path.join(os.homedir(), ".cache/ms-playwright");
  const builds = fs.existsSync(cache) ? fs.readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)) : [];
  builds.sort((a, b) => Number(b.split("-")[1]) - Number(a.split("-")[1]));
  for (const b of builds) {
    const exe = path.join(cache, b, "chrome-linux64/chrome");
    if (fs.existsSync(exe)) return exe;
  }
  return undefined;
}

const chrome = findChrome();
const missing = !chrome ? "Playwright's Chromium was not found (set KYVAULT_E2E_CHROME or run `npx playwright install chromium`)."
  : !fs.existsSync(path.join(DIST, "manifest.json")) ? "dist/chrome is missing. Run `npm run build` first." : undefined;

printSummary("Chromium e2e");

if (missing) {
  notRunItem("Chromium suite", missing);
} else {
  suite();
}

function suite() {
  const serverLog = [];
  const consoleLog = [];
  const watched = new Set(); // extension documents and workers with console capture attached
  const attached = new WeakSet();
  const markWatched = (target) => {
    if (attached.has(target) && target.url().startsWith("chrome-extension://")) watched.add(new URL(target.url()).pathname);
  };
  let servers;
  let browser;
  let profile;
  let extId;
  let extensionsPage; // chrome://extensions, for developerPrivate
  let web; // the KyVault web app
  let options;
  let tab; // the test-site tab the popup acts on

  before(async () => {
    servers = await startServers({ log: (line) => serverLog.push(line) });
    profile = fs.mkdtempSync(path.join(os.tmpdir(), "kyvault-e2e-chromium-"));
    browser = await puppeteer.launch({
      executablePath: chrome,
      headless: true,
      pipe: true,
      enableExtensions: true,
      userDataDir: profile,
      args: ["--headless=new", `--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`,
        "--ignore-certificate-errors", "--enable-unsafe-extension-debugging"],
    });
    browser.on("targetcreated", captureConsole);
    browser.on("targetchanged", markWatched);
    for (const target of browser.targets()) await captureConsole(target);
    const worker = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().startsWith("chrome-extension://"));
    extId = new URL(worker.url()).host;

    extensionsPage = await browser.newPage();
    await extensionsPage.goto("chrome://extensions");
    await extensionsPage.evaluate(async (id) => {
      await chrome.developerPrivate.updateProfileConfiguration({ inDeveloperMode: true });
      await chrome.developerPrivate.updateExtensionConfiguration({ extensionId: id, errorCollection: true });
    }, extId);

    web = await browser.newPage();
    await seedVault(web);
  });

  after(async () => {
    await browser?.close().catch(() => {});
    await servers?.stop();
    if (profile) fs.rmSync(profile, { recursive: true, force: true });
    if (process.env.KYVAULT_E2E_VERBOSE) process.stdout.write(serverLog.join("\n") + "\n");
  });

  async function captureConsole(target) {
    if (!["page", "service_worker", "background_page", "other"].includes(target.type())) return;
    try {
      const session = await target.createCDPSession();
      const push = (level, text) => consoleLog.push({ url: target.url(), type: target.type(), level, text });
      session.on("Runtime.consoleAPICalled", (e) => push(e.type, e.args.map((a) => a.value ?? a.description ?? a.type).join(" ")));
      session.on("Runtime.exceptionThrown", (e) => push("exception", e.exceptionDetails.exception?.description ?? e.exceptionDetails.text));
      session.on("Log.entryAdded", (e) => push(`log-${e.entry.level}`, `${e.entry.text} ${e.entry.url ?? ""}`));
      await session.send("Runtime.enable");
      await session.send("Log.enable");
      attached.add(target);
      markWatched(target); // popups and offscreen documents often get their URL only later
    } catch {
      // a target that closed before we attached
    }
  }

  // Evaluates in the extension's service worker, waking it through an extension page if idle.
  async function sw(fn, ...args) {
    const isWorker = (t) => t.type() === "service_worker" && t.url().startsWith(`chrome-extension://${extId}/`);
    let target = browser.targets().find(isWorker);
    if (!target) {
      const page = await browser.newPage();
      await page.goto(`chrome-extension://${extId}/options.html`);
      target = await browser.waitForTarget(isWorker);
      await page.close();
    }
    return (await target.worker()).evaluate(fn, ...args);
  }

  const storage = () => sw(async () => ({ local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) }));

  // The toolbar click on `page`'s tab: grants activeTab and opens the action popup.
  async function openPopup(page = tab) {
    await page.bringToFront();
    await page.triggerExtensionAction((await browser.extensions()).get(extId));
    const target = await browser.waitForTarget((t) => t.url() === `chrome-extension://${extId}/popup.html`, { timeout: 10_000 });
    const popup = await target.asPage();
    await popup.waitForSelector("#root > *");
    return popup;
  }

  const popupText = (popup) => popup.evaluate(() => document.getElementById("root").innerText);
  const titles = (popup) => popup.$$eval(".entry-row .entry-heading p:first-child", (ps) => ps.map((p) => p.textContent));
  const statusText = (popup, selector = "[role=status]") => popup.evaluate((s) => [...document.querySelectorAll(s)].map((n) => n.textContent).join(" ").trim(), selector);

  async function rowButton(popup, title, label) {
    const [row] = await popup.$$(`xpath/.//div[contains(@class,'entry-row')][.//p[normalize-space()='${title}']]`);
    assert.ok(row, `no row for "${title}"`);
    const [button] = await row.$$(`xpath/.//button[normalize-space()='${label}']`);
    assert.ok(button, `no "${label}" button for "${title}"`);
    return button;
  }

  async function search(popup, query) {
    await popup.$eval("input[type=search]", (el, q) => { el.value = q; el.dispatchEvent(new Event("input")); }, query);
    await sleep(600); // past the popup's 150 ms debounce and the round trip
    return titles(popup);
  }

  async function unlock(popup, password) {
    await popup.type("#password", password);
    await popup.click("xpath/.//button[normalize-space()='Unlock']");
  }

  // Records every chrome.permissions.request call the options page makes, and its outcome.
  const hookPermissionRequests = (page) => page.evaluate(() => {
    window.permissionRequests = [];
    const original = chrome.permissions.request.bind(chrome.permissions);
    chrome.permissions.request = (arg) => {
      const record = { arg: JSON.stringify(arg), result: "pending" };
      window.permissionRequests.push(record);
      const p = original(arg);
      p.then((r) => { record.result = r; }, (e) => { record.result = `error: ${e.message}`; });
      return p;
    };
  });

  async function fillPairingForm(pin) {
    const [server, code] = await options.$$("#root input");
    await server.evaluate((el) => { el.value = ""; });
    await server.type(SERVER_ORIGIN);
    await code.evaluate((el) => { el.value = ""; });
    await code.type(pin);
    await options.click("xpath/.//button[normalize-space()='Pair']");
  }

  const optionsText = () => options.evaluate(() => document.getElementById("root").innerText);

  async function openOptions() {
    if (!options) options = await browser.newPage();
    await options.bringToFront();
    await options.goto(`chrome-extension://${extId}/options.html`);
    await options.waitForSelector("#root button");
  }

  async function pairWithRealPin() {
    await openOptions();
    await hookPermissionRequests(options);
    await fillPairingForm(PIN);
    await waitFor(async () => (await optionsText()).startsWith(MESSAGES.paired), { what: "the paired view" });
  }

  async function unlockFromPopup() {
    const popup = await openPopup();
    await unlock(popup, MASTER_PASSWORD);
    await popup.waitForSelector(".entries", { timeout: 30_000 });
    return popup;
  }

  // ---- 1

  item("1 loads without manifest warnings; icons 16/32/48/128 present", async ({ note }) => {
    const info = await extensionsPage.evaluate((id) => chrome.developerPrivate.getExtensionInfo(id), extId);
    assert.equal(info.state, "ENABLED");
    assert.deepEqual(info.manifestErrors, []);
    assert.deepEqual(info.installWarnings, []);
    const manifest = JSON.parse(fs.readFileSync(path.join(DIST, "manifest.json"), "utf8"));
    for (const size of [16, 32, 48, 128]) {
      assert.equal(manifest.icons[size], `icons/${size}.png`);
      const png = fs.readFileSync(path.join(DIST, "icons", `${size}.png`));
      assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [size, size], `icons/${size}.png dimensions`);
      assert.ok(png.equals(fs.readFileSync(path.resolve(here, "../public/icons", `${size}.png`))), `icons/${size}.png differs from public/icons`);
    }
    note(`state ENABLED, manifestErrors [], installWarnings []; icons 16/32/48/128 at their sizes and equal to public/icons`);
  });

  // ---- 2

  item("2 options: wrong PIN sentence, real PIN pairs, permission https://localhost/*, token never shown", async ({ note }) => {
    await openOptions();
    await hookPermissionRequests(options);
    const before = await storage();
    assert.deepEqual(before.session, {});
    // Headless: the prompt opens and nothing can accept it. The requested pattern is still recorded.
    await fillPairingForm("000000");
    await sleep(3000);
    const [first] = await options.evaluate(() => window.permissionRequests);
    assert.equal(first.arg, JSON.stringify({ origins: [HOST_PATTERN] }));
    note(`request ${first.arg} left ${first.result} by the headless prompt`);

    // chrome://extensions Site access grants the host, as a user can; request then resolves at once.
    await extensionsPage.evaluate(async (id, pattern) => {
      await chrome.developerPrivate.updateExtensionConfiguration({ extensionId: id, hostAccess: "ON_SPECIFIC_SITES" });
      await chrome.developerPrivate.addHostPermission(id, pattern);
    }, extId, HOST_PATTERN);

    await openOptions();
    await hookPermissionRequests(options);
    await fillPairingForm("000000");
    await waitFor(async () => (await optionsText()).includes(MESSAGES.wrongPin), { what: "the wrong-PIN sentence" });
    note(`wrong PIN: "${MESSAGES.wrongPin}"`);

    await fillPairingForm(PIN);
    await waitFor(async () => (await optionsText()).startsWith(MESSAGES.paired), { what: "the paired view" });
    note(`"${MESSAGES.paired}"`);

    const requests = await options.evaluate(() => window.permissionRequests);
    assert.ok(requests.every((r) => r.arg === JSON.stringify({ origins: [HOST_PATTERN] }) && r.result === true), JSON.stringify(requests));
    const granted = await sw(() => chrome.permissions.getAll());
    assert.deepEqual(granted.origins, [HOST_PATTERN]);
    note(`permissions.getAll().origins = ${JSON.stringify(granted.origins)}`);

    const { local, session } = await storage();
    assert.equal(local.serverOrigin, SERVER_ORIGIN);
    assert.equal(local.deviceName, "Browser extension");
    assert.ok(local.sessionToken, "storage.local has no sessionToken");
    assert.deepEqual(Object.keys(local).sort(), ["autoLockMinutes", "deviceId", "deviceName", "serverOrigin", "sessionToken"]);
    assert.deepEqual(session, {});
    assert.ok(!(await options.content()).includes(local.sessionToken), "the token is in the options page");
    note(`storage.local keys ${Object.keys(local).sort().join(",")}; storage.session {}; token not in the page`);
  });

  notRunItem("2b the host permission prompt accepted by a click",
    "headless Chromium shows the prompt but nothing can click it; item 2 grants the host through chrome://extensions Site access instead");

  // ---- 3

  item("3 popup: wrong password stores nothing; unlock keeps the key in storage.session only", async ({ note }) => {
    tab = await browser.newPage();
    await tab.goto(`${SITE}/plain.html`);
    const popup = await openPopup();
    const localBefore = (await storage()).local;
    await unlock(popup, "wrong password here");
    await waitFor(async () => (await statusText(popup)) === MESSAGES.wrongPassword, { timeout: 30_000, what: "the wrong-password sentence" });
    const afterWrong = await storage();
    assert.deepEqual(afterWrong.session, {});
    assert.deepEqual(afterWrong.local, localBefore);
    note(`wrong password: "${MESSAGES.wrongPassword}", storage.session {}`);

    await unlock(popup, MASTER_PASSWORD);
    await popup.waitForSelector(".entries", { timeout: 30_000 });
    const { local, session } = await storage();
    for (const key of ["keyHex", "envelope", "lockAt"]) assert.ok(key in session, `storage.session lacks ${key}`);
    assert.match(session.keyHex, /^[0-9a-f]{64}$/);
    assert.ok(!("keyHex" in local) && !JSON.stringify(local).includes(session.keyHex), "the key reached storage.local");
    note(`storage.session keys ${Object.keys(session).sort().join(",")}; storage.local has no key`);
    await popup.close();
  });

  // ---- 4

  item("4 entries for the active tab's host rank first; search works", async ({ note }) => {
    const popup = await openPopup();
    const siteOnly = await titles(popup);
    assert.deepEqual(siteOnly, ["Carol test site", "Test site login"]);
    const login = await search(popup, "login");
    assert.deepEqual(login, ["Carol test site", "Test site login", "Mock server login"]);
    assert.deepEqual(await search(popup, "zeta"), ["Zeta example"]);
    assert.deepEqual(await search(popup, "bob"), ["Mock server login"]);
    assert.deepEqual(await search(popup, "no-such-entry"), []);
    note(`no query ${JSON.stringify(siteOnly)}; "login" ${JSON.stringify(login)}; "zeta", "bob" and a miss as expected`);
    await popup.close();
  });

  // ---- 5

  item("5 copy password: two consecutive copies each clear after 30 s and close the offscreen document", async ({ note }) => {
    const offscreenDocuments = () => sw(async () => (await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] })).length);
    for (const title of ["Test site login", "Carol test site"]) {
      const expected = ENTRIES.find((e) => e.title === title).password;
      // Record the worker's clear round trip: the offscreen document replies {cleared}.
      await sw(() => {
        globalThis.e2eClears = [];
        if (globalThis.e2eWrapped) return;
        globalThis.e2eWrapped = true;
        const send = chrome.runtime.sendMessage.bind(chrome.runtime);
        chrome.runtime.sendMessage = (...args) => {
          const p = send(...args);
          if (args[0]?.type === "offscreenClear") p.then((reply) => globalThis.e2eClears.push({ at: Date.now(), reply }), (e) => globalThis.e2eClears.push({ at: Date.now(), error: String(e) }));
          return p;
        };
      });
      const popup = await openPopup();
      await popup.evaluate(() => {
        window.e2eWrites = [];
        const write = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = (text) => { window.e2eWrites.push(text); return write(text); };
      });
      const copiedAt = Date.now();
      await (await rowButton(popup, title, "Copy password")).click();
      await waitFor(async () => (await statusText(popup)) === "Copied. Clears in 30 seconds.", { what: "the copy toast" });
      assert.deepEqual(await popup.evaluate(() => window.e2eWrites), [expected], "the popup did not write the entry's password");
      await popup.close(); // the clear must not depend on the popup
      const [clear] = await waitFor(() => sw(() => globalThis.e2eClears.length ? globalThis.e2eClears : undefined), { timeout: 45_000, interval: 1000, what: "the clipboard clear" });
      assert.deepEqual(clear.reply, { cleared: true }, JSON.stringify(clear));
      const seconds = (clear.at - copiedAt) / 1000;
      assert.ok(seconds >= 29 && seconds <= 40, `cleared after ${seconds} s`);
      await waitFor(async () => (await offscreenDocuments()) === 0, { timeout: 5000, what: "the offscreen document to close" });
      note(`${title}: wrote the password, offscreen replied {cleared:true} after ${seconds.toFixed(1)} s, no offscreen document left`);
    }
  });

  notRunItem("5b clipboard contents read back as a single space",
    "headless Chromium's clipboard is a no-op store (a page's own writeText then readText returns \"\"); item 5 checks the written value and the offscreen clear's reply instead");

  // ---- 6

  item("6 TOTP matches an independent RFC 6238 computation", async ({ note }) => {
    assert.ok(rfc6238SelfCheck(), "the reference TOTP fails RFC 6238 Appendix B");
    const popup = await openPopup();
    await popup.evaluate(() => {
      window.e2eWrites = [];
      const write = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = (text) => { window.e2eWrites.push(text); return write(text); };
    });
    const before = Date.now();
    await (await rowButton(popup, "Test site login", "Copy TOTP")).click();
    const [code] = await waitFor(() => popup.evaluate(() => (window.e2eWrites.length ? window.e2eWrites : undefined)), { what: "the TOTP copy" });
    const expected = [totp(TOTP_SEED, before), totp(TOTP_SEED, Date.now())];
    assert.ok(expected.includes(code), `copied ${code}, expected ${expected.join(" or ")}`);
    note(`copied ${code}; reference ${expected[0]}`);
    await popup.close();
  });

  // ---- 7

  item("7 fill: plain, React-style and same-site frame filled on click only; cross-site frame and other host refused", async ({ note }) => {
    const alice = ENTRIES[0];
    const filled = { username: alice.username, passwordLength: alice.password.length, submitted: 0,
      log: ["input:username:true", "change:username:true", "input:password:true", "change:password:true"] };

    async function fillOn(page, frameOf) {
      await tab.goto(`${SITE}/${page}`);
      const frame = await waitFor(async () => frameOf(), { what: `the frame in ${page}` });
      await frame.waitForSelector("input[name=password]");
      const popup = await openPopup();
      await sleep(1000);
      const afterOpen = await formState(frameOf());
      await (await rowButton(popup, "Test site login", "Fill")).click();
      const status = await waitFor(async () => statusText(popup), { what: "the fill status" });
      await sleep(300);
      const result = await formState(frameOf());
      await popup.close();
      return { afterOpen, status, result };
    }
    const top = () => tab.mainFrame();
    const child = () => tab.frames().find((f) => f !== tab.mainFrame());

    const plain = await fillOn("plain.html", top);
    assert.deepEqual({ ...plain.afterOpen, reactState: undefined }, { ...EMPTY_FORM, reactState: undefined }, "opening the popup changed the form");
    assert.equal(plain.status, "Filled.");
    assert.deepEqual({ ...plain.result, reactState: undefined }, { ...filled, reactState: undefined });
    note("plain: filled, bubbling input/change, no submit; opening the popup changed nothing");

    const react = await fillOn("react.html", top);
    assert.equal(react.afterOpen.reactState.username, "");
    assert.equal(react.status, "Filled.");
    assert.deepEqual(react.result.reactState, { username: alice.username, passwordLength: alice.password.length });
    assert.ok(react.result.log.includes("onChange:username") && react.result.log.includes("onChange:password"), JSON.stringify(react.result.log));
    assert.equal(react.result.submitted, 0);
    note("React-style: value tracker saw the change, state updated, no submit");

    const same = await fillOn("frame-same.html", child);
    assert.equal(child().url(), `${SITE}/inner.html`);
    assert.deepEqual({ ...same.afterOpen, reactState: undefined }, { ...EMPTY_FORM, reactState: undefined });
    assert.equal(same.status, "Filled.");
    assert.deepEqual({ ...same.result, reactState: undefined }, { ...filled, reactState: undefined });
    note("same-site frame: filled, no submit");

    const cross = await fillOn("frame-cross.html", child);
    assert.equal(child().url(), `${CROSS_SITE}/inner.html`);
    assert.notEqual(cross.status, "Filled.");
    assert.deepEqual({ ...cross.result, reactState: undefined }, { ...EMPTY_FORM, reactState: undefined });
    note(`cross-site frame (${CROSS_SITE}): not filled, popup said "${cross.status}"`);

    await tab.goto(`${SITE}/plain.html`);
    const popup = await openPopup();
    await search(popup, "bob");
    const other = await (await rowButton(popup, "Mock server login", "Fill")).evaluate((b) => ({ disabled: b.disabled, title: b.title }));
    assert.deepEqual(other, { disabled: true, title: "This login is for localhost, not this page." });
    // The background refuses it too, whatever the popup shows.
    const direct = await popup.evaluate(async () => {
      const { entries } = await chrome.runtime.sendMessage({ type: "entries", query: "bob" });
      return chrome.runtime.sendMessage({ type: "fill", uuid: entries[0].uuid });
    });
    assert.equal(direct.type, "error");
    assert.equal(direct.message, "This login is for localhost, not 127.0.0.1.");
    assert.deepEqual({ ...(await formState(top())), reactState: undefined }, { ...EMPTY_FORM, reactState: undefined });
    note(`other host: Fill disabled ("${other.title}"); a direct fill message is refused: "${direct.message}"`);
    await popup.close();
  });

  // ---- 8

  item("8 save login: version advances; 409 locks; a lost answer keeps the typed values", async ({ note }) => {
    async function saveFromPopup(popup, title, username, password) {
      await popup.click("summary");
      await popup.$eval("#save-title", (el) => { el.value = ""; });
      await popup.type("#save-title", title);
      await popup.type("#save-username", username);
      await popup.type("#save-password", password);
      await popup.click("xpath/.//button[normalize-space()='Save login']");
    }
    const formStatus = (popup) => statusText(popup, "form [role=status]");

    const v0 = await serverVersion();
    let popup = await openPopup();
    await saveFromPopup(popup, "Saved from extension", "dave", "Dave-Pass-5444!");
    await waitFor(async () => (await formStatus(popup)) === "Saved to the vault.", { timeout: 30_000, what: "the save" });
    assert.equal(await serverVersion(), v0 + 1);
    assert.ok((await titles(popup)).includes("Saved from extension"));
    await popup.close();
    assert.ok((await reloadWebApp(web)).includes("Saved from extension"), "the web app does not list the saved login");
    note(`saved: version ${v0} -> ${v0 + 1}, listed in the popup and the web app`);

    await editEntryInWebApp(web, "Zeta example", "-edited");
    const moved = await serverVersion();
    popup = await openPopup();
    await saveFromPopup(popup, "Should conflict", "erin", "Erin-Pass-5444!");
    await waitFor(async () => (await statusText(popup)) === MESSAGES.conflict, { timeout: 30_000, what: "the conflict lock" });
    assert.ok(await popup.$("#password"), "the popup did not lock");
    assert.deepEqual((await storage()).session, {});
    assert.equal(await serverVersion(), moved);
    const conflicts = await (await fetch(`${MOCK_ORIGIN}/api/vault/conflicts`)).json();
    assert.equal(conflicts[0].expectedVersion, moved - 1);
    note(`after the web app moved the server to v${moved}: "${MESSAGES.conflict}", storage.session {}, conflict preserved`);

    await unlock(popup, MASTER_PASSWORD);
    await popup.waitForSelector(".entries", { timeout: 30_000 });
    servers.killNextUpload();
    await saveFromPopup(popup, "Killed mid save", "frank", "Frank-Pass-5444!");
    await waitFor(async () => (await formStatus(popup)) === MESSAGES.unconfirmed, { timeout: 30_000, what: "the unconfirmed-save sentence" });
    const kept = await popup.evaluate(() => ({
      title: document.getElementById("save-title").value, username: document.getElementById("save-username").value,
      passwordLength: document.getElementById("save-password").value.length,
    }));
    assert.deepEqual(kept, { title: "Killed mid save", username: "frank", passwordLength: 16 });
    assert.equal(await serverVersion(), moved);
    await popup.close();
    await waitFor(() => servers.proxyUp(), { timeout: 15_000, what: "the proxy to return" });
    popup = await openPopup();
    assert.ok(!(await search(popup, "Killed")).length, "a phantom entry is listed after the failed save");
    await popup.close();
    note(`proxy killed mid-upload: typed values kept, "${MESSAGES.unconfirmed}", version stayed ${moved}, no phantom entry`);
  });

  // ---- 9

  item("9 revoked device: lists for up to 60 s, then the revoked sentence and the token is gone", async ({ note }) => {
    const contact = (await storage()).session.lastServerContact;
    await web.bringToFront();
    await revokeExtensionDevice(web);
    assert.ok(!(await mockDevices()).includes((await storage()).local.deviceId), "the mock still lists the device");

    // Well inside the window: the popup works from memory and has not asked the server yet.
    await sleep(Math.max(0, contact + 30_000 - Date.now()));
    let popup = await openPopup();
    const early = Math.round((Date.now() - contact) / 1000);
    assert.ok(early < 60, `the check ran ${early} s after the last contact`);
    assert.ok((await titles(popup)).length > 0, "the popup stopped listing within 60 s");
    note(`${early} s after the last server contact (device already revoked) the popup still lists`);
    await popup.close();

    await sleep(Math.max(0, contact + 62_000 - Date.now()));
    popup = await openPopup();
    await waitFor(async () => (await popupText(popup)).startsWith(MESSAGES.revoked), { timeout: 15_000, what: "the revoked sentence" });
    const { local, session } = await storage();
    assert.ok(!("sessionToken" in local) && !("deviceId" in local), JSON.stringify(Object.keys(local)));
    assert.deepEqual(session, {});
    note(`${Math.round((Date.now() - contact) / 1000)} s after the last contact: "${MESSAGES.revoked}"; sessionToken and deviceId gone, storage.session {}`);
    await popup.close();
  });

  // ---- 10

  item("10 idle lock at 1 minute: no immediate lock, then the password is asked and storage.session is empty", async ({ note }) => {
    await pairWithRealPin();
    await (await unlockFromPopup()).close();
    await options.bringToFront();
    await options.select("select", "1");
    await waitFor(async () => (await statusText(options)) === "Saved.", { what: "the Saved. notice" });
    const setAt = Date.now();
    const armed = await sw(async () => {
      const s = await chrome.storage.session.get(null);
      const alarm = await chrome.alarms.get("lock");
      return { keyHex: Boolean(s.keyHex), lockIn: (s.lockAt - Date.now()) / 1000, alarmIn: alarm ? (alarm.scheduledTime - Date.now()) / 1000 : null };
    });
    assert.ok(armed.keyHex, "the vault locked at once");
    assert.ok(armed.lockIn > 50 && armed.lockIn <= 61, `lockAt ${armed.lockIn} s ahead`);
    assert.ok(armed.alarmIn > 50 && armed.alarmIn <= 61, `lock alarm ${armed.alarmIn} s ahead`);
    note(`"Saved.", still unlocked, lock due in ${Math.round(armed.lockIn)} s`);

    await sleep(setAt + 70_000 - Date.now());
    assert.deepEqual((await storage()).session, {});
    const popup = await openPopup();
    assert.ok(await popup.$("#password"), `popup shows: ${await popupText(popup)}`);
    note("after 70 s storage.session was {} before the popup opened, and the popup asks for the master password");
    await popup.close();
  });

  // ---- 11

  item("11 no console errors from the service worker, popup, options or offscreen pages", async ({ note }) => {
    const info = await extensionsPage.evaluate((id) => chrome.developerPrivate.getExtensionInfo(id), extId);
    const own = consoleLog.filter((l) => l.url.startsWith(`chrome-extension://${extId}/`));
    const errors = own.filter((l) => /error|exception|assert/.test(l.level))
      // The two deliberate wrong-PIN redeems in item 2 log their 400 as a network error.
      .filter((l) => !(l.level === "log-error" && l.text.includes("status of 400") && l.text.includes("/api/devices/pairing/redeem")));
    assert.deepEqual(info.runtimeErrors.map((e) => `${e.contextUrl}: ${e.message}`), []);
    assert.deepEqual(errors.map((e) => `${e.type} ${e.url}: ${e.text}`), []);
    for (const page of ["/background.js", "/popup.html", "/options.html", "/offscreen.html"]) assert.ok(watched.has(page), `console capture never attached to ${page}`);
    note(`developerPrivate runtimeErrors []; no console errors or exceptions from ${[...watched].sort().join(", ")}`);
  });
}

