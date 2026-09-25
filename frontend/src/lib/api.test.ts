import { test } from "node:test";
import assert from "node:assert/strict";
import { getJSON, HttpError } from "./api";

test("a 401 dispatches kyvault:unauthorized except for the session probe", async (t) => {
  const events: string[] = [];
  Object.defineProperty(globalThis, "window", { configurable: true, value: { dispatchEvent: (e: Event) => { events.push(e.type); return true; } } });
  Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
  t.after(() => { Reflect.deleteProperty(globalThis, "window"); Reflect.deleteProperty(globalThis, "document"); });
  t.mock.method(globalThis, "fetch", async () => new Response("unauthorized", { status: 401 }));
  await assert.rejects(getJSON("/api/vault/metadata"), HttpError);
  await assert.rejects(getJSON("/api/auth/me"), HttpError);
  assert.deepEqual(events, ["kyvault:unauthorized"]);
});
