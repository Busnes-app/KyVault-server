import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { PinStatus } from "../lib/sharedFlows";
import { MemberKey, selfView, type KeyView } from "./SharedMembersDialog";

const FP = "F77C 6D33 8E2B 552B 6C5B";
const published = (bytes: number[]): PinStatus => ({ state: "unknown", fingerprint: FP, publicKey: new Uint8Array(bytes) });
const render = (username: string, view: KeyView) => renderToStaticMarkup(createElement(MemberKey, { username, view }));

test("my own row says the key is mine, and a mismatch on it is a problem", () => {
  const held = new Uint8Array([1, 2, 3]);
  const mine = render("mock-admin", selfView(published([1, 2, 3]), held));
  assert.match(mine, /Your key/);
  assert.doesNotMatch(mine, /not verified/);
  assert.doesNotMatch(mine, /--warning/, "my own key must never wear the unverified warning");
  assert.match(mine, /F77C 6D33/);

  // The server publishes a key this browser does not hold: that is worth the danger colour.
  const wrong = render("mock-admin", selfView(published([9, 9, 9]), held));
  assert.match(wrong, /Not the key this browser holds/);
  assert.match(wrong, /--danger/);
});

test("another member's unpinned key still carries the warning", () => {
  const other = render("dana", { key: published([4, 5, 6]) });
  assert.match(other, /Key not verified/);
  assert.match(other, /--warning/);

  const pinned = render("dana", { key: { ...published([4, 5, 6]), state: "pinned" } });
  assert.match(pinned, /Key pinned/);
  assert.match(pinned, /--success/);

  const changed = render("dana", { key: { ...published([4, 5, 6]), state: "changed" } });
  assert.match(changed, /Key changed since you pinned it/);
  assert.match(changed, /--danger/);

  assert.match(render("dana", { problem: "No published key" }), /No published key/);
});
