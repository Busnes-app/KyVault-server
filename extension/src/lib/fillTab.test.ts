import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { fillFrame, fillTab, type FillArgs, type FillIO } from "./fillTab";

const login = { url: "https://example.com/login", username: "alice", password: "hunter2" };
const probe = (frameId: number, origin: string, targets: unknown = { password: 1, username: 0 }, count = 2) => ({
  frameId,
  result: { origin, count, targets },
});

function io(tabUrl: string | undefined, frames: unknown[], answer: unknown = true) {
  const sent: { frameId: number; args: FillArgs }[] = [];
  let probed = 0;
  const fake: FillIO = {
    tabUrl,
    probe: async () => { probed++; return frames as Awaited<ReturnType<FillIO["probe"]>>; },
    fill: async (frameId, args) => { sent.push({ frameId, args }); return answer; },
  };
  return { fake, sent, probed: () => probed };
}

test("fills the top frame of a same-site tab", async () => {
  const { fake, sent } = io("https://example.com/login", [probe(0, "https://example.com")]);
  assert.deepEqual(await fillTab(fake, login), { username: true });
  assert.deepEqual(sent, [{ frameId: 0, args: ["https://example.com", 2, 1, 0, "alice", "hunter2"] }]);
});

test("refuses an entry for another site before injecting anything", async () => {
  const { fake, sent, probed } = io("https://evil.test/", [probe(0, "https://evil.test")]);
  await assert.rejects(fillTab(fake, login), /^Error: This login is for example\.com, not evil\.test\.$/);
  assert.equal(probed(), 0);
  assert.equal(sent.length, 0);
});

test("refuses tabs that are not web pages", async () => {
  for (const url of [undefined, "chrome://settings", "file:///etc/passwd", "about:blank", "data:text/html,x"]) {
    const { fake, sent, probed } = io(url, [probe(0, "https://example.com")]);
    await assert.rejects(fillTab(fake, login), /KyVault fills only on web pages\./);
    assert.equal(probed() + sent.length, 0);
  }
});

test("refuses an entry without a website address", async () => {
  const { fake, probed } = io("https://example.com/", [probe(0, "https://example.com")]);
  await assert.rejects(fillTab(fake, { ...login, url: "example.com" }), /no website address/);
  assert.equal(probed(), 0);
});

test("an https login is never filled into an http page or frame", async () => {
  const tab = io("http://example.com/", [probe(0, "http://example.com")]);
  await assert.rejects(fillTab(tab.fake, login), /only over HTTPS/);
  assert.equal(tab.probed(), 0);
  const frame = io("https://example.com/", [probe(0, "https://example.com", null), probe(3, "http://login.example.com")]);
  await assert.rejects(fillTab(frame.fake, login), /No login form on this page\./);
  assert.equal(frame.sent.length, 0);
});

test("credentials go to a same-site frame only, never to a cross-site one", async () => {
  const frames = [
    probe(0, "https://example.com", null),
    probe(4, "https://evil.test"),
    probe(5, "null"),
    { frameId: 6, result: null },
    probe(7, "https://login.example.com"),
  ];
  const { fake, sent } = io("https://example.com/", frames);
  assert.deepEqual(await fillTab(fake, login), { username: true });
  assert.deepEqual(sent.map((s) => s.frameId), [7]);
});

test("a page with only a cross-site login form reports no form", async () => {
  const { fake, sent } = io("https://example.com/", [probe(0, "https://example.com", null), probe(4, "https://evil.test")]);
  await assert.rejects(fillTab(fake, login), /^Error: No login form on this page\.$/);
  assert.equal(sent.length, 0);
});

test("the top frame wins over a same-site iframe", async () => {
  const { fake, sent } = io("https://example.com/", [probe(7, "https://login.example.com"), probe(0, "https://example.com")]);
  await fillTab(fake, login);
  assert.deepEqual(sent.map((s) => s.frameId), [0]);
});

test("an empty username leaves the username field alone", async () => {
  const { fake, sent } = io("https://example.com/", [probe(0, "https://example.com")]);
  assert.deepEqual(await fillTab(fake, { ...login, username: "" }), { username: false });
  assert.equal(sent[0].args[3], -1);
});

test("pages that refuse injection and pages that changed get a sentence", async () => {
  const refused: FillIO = { tabUrl: "https://example.com/", probe: async () => { throw new Error("Cannot access"); }, fill: async () => true };
  await assert.rejects(fillTab(refused, login), /^Error: KyVault cannot fill on this page\.$/);
  const changed = io("https://example.com/", [probe(0, "https://example.com")], false);
  await assert.rejects(fillTab(changed.fake, login), /The page changed before filling\. Try again\./);
});

// A fake DOM just big enough for fillFrame; run through toString the way
// scripting.executeScript serializes `func`, so a closure over module scope fails here.
function page(origin: string, types: string[]) {
  const events: string[] = [];
  class HTMLInputElement {
    type: string;
    _value = "";
    constructor(type: string) { this.type = type; }
    focus() { events.push(`focus:${this.type}`); }
    dispatchEvent(e: { type: string; bubbles: boolean }) { events.push(`${e.type}:${this.type}:${e.bubbles}`); return true; }
    // A page overriding the instance setter must not see the value.
    set value(_v: string) { events.push("instance-setter"); }
  }
  Object.defineProperty(HTMLInputElement.prototype, "value", {
    set(this: HTMLInputElement, v: string) { this._value = v; },
    get(this: HTMLInputElement) { return this._value; },
    configurable: true,
  });
  const inputs = types.map((t) => new HTMLInputElement(t));
  class Event { type: string; bubbles: boolean; constructor(type: string, init?: { bubbles?: boolean }) { this.type = type; this.bubbles = Boolean(init?.bubbles); } }
  const context = { location: { origin }, document: { querySelectorAll: () => inputs }, HTMLInputElement, Event };
  return { context, inputs, events };
}

function run(context: object, args: FillArgs): unknown {
  return runInNewContext(`(${fillFrame.toString()})(...args)`, { ...context, args });
}

test("fillFrame sets values through the native setter and dispatches bubbling events", () => {
  const { context, inputs, events } = page("https://example.com", ["email", "password"]);
  assert.equal(run(context, ["https://example.com", 2, 1, 0, "alice", "hunter2"]), true);
  assert.equal(inputs[0]._value, "alice");
  assert.equal(inputs[1]._value, "hunter2");
  assert.deepEqual(events, [
    "focus:email", "input:email:true", "change:email:true",
    "focus:password", "input:password:true", "change:password:true",
  ]);
  assert.deepEqual(Object.keys(context).sort(), ["Event", "HTMLInputElement", "document", "location"]);
});

test("fillFrame refuses a navigated frame or a changed form without touching it", () => {
  for (const [origin, types, args] of [
    ["https://evil.test", ["email", "password"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["email", "password", "text"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["email", "text"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["password", "password"], ["https://example.com", 2, 1, 0, "a", "p"]],
  ] as [string, string[], FillArgs][]) {
    const { context, inputs, events } = page(origin, types);
    assert.equal(run(context, args), false);
    assert.deepEqual(events, []);
    assert.ok(inputs.every((i) => i._value === ""));
  }
});
