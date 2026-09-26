// Shared pieces of the e2e suites: fixtures, the web app steps, the site checks, TOTP and the
// PASS / FAIL / NOT RUN summary.
import { createHmac } from "node:crypto";
import { after, test } from "node:test";
import { MOCK_ORIGIN, SERVER_ORIGIN, SITE } from "./servers.mjs";

export const MASTER_PASSWORD = "correct horse battery staple";
export const TOTP_SEED = "JBSWY3DPEHPK3PXP";
// Two entries for the test site (so ranking has a tier), one for the paired server's host
// (a different host from the test site), one unrelated.
export const ENTRIES = [
  { title: "Test site login", username: "alice", password: "Alice-Pass-5444!", url: SITE, totp: TOTP_SEED },
  { title: "Carol test site", username: "carol", password: "Carol-Pass-5444!", url: `${SITE}/login` },
  { title: "Mock server login", username: "bob", password: "Bob-Pass-5443!", url: SERVER_ORIGIN },
  { title: "Zeta example", username: "zed", password: "Zed-Pass-org!", url: "https://example.org" },
];

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function waitFor(check, { timeout = 15_000, interval = 200, what = "condition" } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error(`Timed out waiting for ${what}.`);
    await sleep(interval);
  }
}

export async function serverVersion() {
  return (await (await fetch(`${MOCK_ORIGIN}/api/vault/metadata`)).json()).version;
}

export async function mockDevices() {
  return (await (await fetch(`${MOCK_ORIGIN}/api/devices`)).json()).map((d) => d.id);
}

// RFC 6238, HMAC-SHA1, 6 digits, 30 s: an implementation independent of the extension's.
export function totp(base32, at = Date.now(), digits = 6) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  return hotp(key, Math.floor(at / 30_000), digits);
}

function hotp(key, counter, digits) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 10 ** digits).padStart(digits, "0");
}

// RFC 6238 Appendix B, SHA-1 at T=59: proves the reference implementation before it judges.
export const rfc6238SelfCheck = () => hotp(Buffer.from("12345678901234567890"), 1, 8) === "94287082";

// ---- web app (the real frontend served by the mock)

const byLabel = (page, label) => page.$(`xpath/.//label[normalize-space()='${label}']/following::input[1]`);

async function clickButton(page, text) {
  const button = await waitFor(async () => (await page.$$(`xpath/.//button[normalize-space()='${text}']`))[0], { what: `button "${text}"` });
  await button.click();
}

async function typeInto(page, label, value) {
  const input = await waitFor(() => byLabel(page, label), { what: `field "${label}"` });
  await input.evaluate((el) => el.focus());
  await input.type(value);
}

// Creates the vault through the web app and adds ENTRIES through its entry editor.
export async function seedVault(page) {
  await page.setViewport({ width: 1400, height: 1000 });
  await page.goto(`${MOCK_ORIGIN}/`, { waitUntil: "load" });
  await waitFor(() => page.$$("input[type=password]").then((l) => l.length >= 2), { what: "the create-vault form" });
  for (const input of await page.$$("input[type=password]")) await input.type(MASTER_PASSWORD);
  await clickButton(page, "Create vault");
  await waitFor(() => page.$("button[title='Add Entry']"), { timeout: 30_000, what: "the unlocked vault" });
  for (const entry of ENTRIES) {
    const before = await serverVersion();
    await (await page.$("button[title='Add Entry']")).click();
    await typeInto(page, "Title", entry.title);
    await typeInto(page, "Username / Email", entry.username);
    await typeInto(page, "Password", entry.password);
    await typeInto(page, "Website URL", entry.url);
    if (entry.totp) await typeInto(page, "Two-Factor Authentication (TOTP Key / URI)", entry.totp);
    const [apply] = await page.$$("xpath/.//button[contains(., 'Apply Edits')]");
    await apply.click();
    await waitFor(async () => (await serverVersion()) > before, { timeout: 20_000, what: `autosave of "${entry.title}"` });
  }
}

// Reloads the web app, unlocking it if it asks; resolves with the page text.
export async function reloadWebApp(page) {
  await page.bringToFront(); // headless freezes background tabs; evaluations would time out
  await page.goto(`${MOCK_ORIGIN}/`, { waitUntil: "load" });
  const state = await waitFor(async () => {
    if (await page.$("button[title='Add Entry']")) return "open";
    if (await page.$("dialog[open] input[type=password]")) return "locked";
    return undefined;
  }, { timeout: 20_000, what: "the web app" });
  if (state === "locked") {
    await (await page.$("dialog[open] input[type=password]")).type(MASTER_PASSWORD);
    await (await page.$("xpath/.//dialog[@open]//button[@type='submit' and normalize-space()='Unlock']")).click();
    await waitFor(() => page.$("button[title='Add Entry']"), { timeout: 30_000, what: "the web app to unlock" });
  }
  return page.evaluate(() => document.body.innerText);
}

// Appends text to one entry's username and applies it: moves the server version by one.
export async function editEntryInWebApp(page, title, suffix) {
  await page.bringToFront();
  const before = await serverVersion();
  const [row] = await page.$$(`xpath/.//*[normalize-space()='${title}']`);
  await row.click();
  await clickButton(page, "Edit");
  await typeInto(page, "Username / Email", suffix);
  const [apply] = await page.$$("xpath/.//button[contains(., 'Apply Edits')]");
  await apply.click();
  await waitFor(async () => (await serverVersion()) > before, { timeout: 20_000, what: "the web app save" });
}

// Revokes the device the mock calls "New device" (the extension) from Security.
export async function revokeExtensionDevice(page) {
  await page.bringToFront();
  await (await page.$("button[aria-label='Security']")).click();
  const clicked = await waitFor(() => page.evaluate(() => {
    for (const button of document.querySelectorAll("button[title='Revoke device']")) {
      let row = button.parentElement;
      while (row && !row.innerText.includes("New device")) row = row.parentElement;
      if (row && !row.innerText.includes("Pixel 9")) { button.click(); return true; }
    }
    return false;
  }), { what: "the extension's Revoke button" });
  if (!clicked) throw new Error("No revoke button for the extension device.");
  // Every device row has a "Revoke" button too; confirm inside the dialog.
  const confirm = await waitFor(async () => (await page.$$("xpath/.//dialog[@open]//button[normalize-space()='Revoke']"))[0], { what: "the revoke confirmation" });
  await confirm.click();
  await waitFor(() => page.evaluate(() => /Device "New device" revoked\./.test(document.body.innerText)), { what: "the revoke notice" });
}

// ---- test site

// Field values (password length only), recorded events and submit count of a frame.
export function formState(frame) {
  return frame.evaluate(() => {
    const value = (name) => document.querySelector(`input[name=${name}]`)?.value ?? "";
    return {
      username: value("username"),
      passwordLength: value("password").length,
      log: window.log,
      submitted: window.submitted,
      reactState: window.state ? { username: window.state.username, passwordLength: window.state.password.length } : undefined,
    };
  });
}

export const EMPTY_FORM = { username: "", passwordLength: 0, log: [], submitted: 0 };

// ---- reporting

const results = [];

// One checklist item. `fn` gets `note(text)` for evidence and `notRun(reason)` to mark it
// NOT RUN (it returns, so the caller stops). A thrown error is a FAIL.
export function item(name, fn) {
  test(name, async (t) => {
    const notes = [];
    const note = (text) => { notes.push(text); t.diagnostic(text); };
    let skipped;
    const notRun = (reason) => { skipped = reason; };
    try {
      await fn({ note, notRun });
    } catch (err) {
      results.push({ name, status: "FAIL", detail: err.message.split("\n").slice(0, 6).join(" | ") });
      throw err;
    }
    if (skipped) {
      results.push({ name, status: "NOT RUN", detail: skipped });
      t.skip(skipped);
      return;
    }
    results.push({ name, status: "PASS", detail: notes.join("; ") });
  });
}

// Headless limits are reported as their own NOT RUN rows, never folded into a PASS.
export function notRunItem(name, reason) {
  test(name, (t) => {
    results.push({ name, status: "NOT RUN", detail: reason });
    t.skip(reason);
  });
}

export function printSummary(title) {
  after(() => {
    const lines = [``, `${title}`, ...results.map((r) => `${r.status.padEnd(7)} ${r.name}${r.detail ? ` -- ${r.detail}` : ""}`)];
    process.stdout.write(lines.join("\n") + "\n");
  });
}
