// Shared by fillTab.test.ts (source) and content/fill.test.ts (built bundle).
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import type { FillArgs } from "./fillTab";

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

function run(source: string, context: object, args: FillArgs): unknown {
  return runInNewContext(`(${source})(...args)`, { ...context, args });
}

// Both the source function and the one serialised in the built background bundle run this.
export function checkFillFrame(source: string): void {
  {
    const { context, inputs, events } = page("https://example.com", ["email", "password"]);
    assert.equal(run(source, context, ["https://example.com", 2, 1, 0, "alice", "hunter2"]), true);
    assert.equal(inputs[0]._value, "alice");
    assert.equal(inputs[1]._value, "hunter2");
    assert.deepEqual(events, [
      "focus:email", "input:email:true", "change:email:true",
      "focus:password", "input:password:true", "change:password:true",
    ]);
    assert.deepEqual(Object.keys(context).sort(), ["Event", "HTMLInputElement", "document", "location"]);
  }
  for (const [origin, types, args] of [
    ["https://evil.test", ["email", "password"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["email", "password", "text"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["email", "text"], ["https://example.com", 2, 1, 0, "a", "p"]],
    ["https://example.com", ["password", "password"], ["https://example.com", 2, 1, 0, "a", "p"]],
  ] as [string, string[], FillArgs][]) {
    const { context, inputs, events } = page(origin, types);
    assert.equal(run(source, context, args), false);
    assert.deepEqual(events, []);
    assert.ok(inputs.every((i) => i._value === ""));
  }
}
