import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { PinStatus } from "../lib/sharedFlows";
import { MemberKey, VaultActions, selfView, sealBlocked, type KeyView } from "./SharedMembersDialog";

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

const gate = { keyReady: true, open: true, unsaved: false };
const actions = (over: Partial<Parameters<typeof VaultActions>[0]> = {}) =>
  renderToStaticMarkup(createElement(VaultActions, {
    isOwner: true, myState: "active", banner: null, gate, busy: false,
    onRename: () => {}, onDelete: () => {}, onLeave: () => {}, onRotate: () => {}, ...over,
  }));

test("only an owner is offered the rotation, and everyone can leave", () => {
  const owner = actions();
  assert.match(owner, /Rotate key/);
  assert.match(owner, /Rename…/);
  assert.match(owner, /Delete vault…/);
  assert.match(owner, /Leave vault…/);

  for (const role of [{ isOwner: false }, { isOwner: false, myState: "active" as const }]) {
    const other = actions(role);
    assert.doesNotMatch(other, /Rotate key/, "a reader or editor must never see the rotation");
    assert.doesNotMatch(other, /Delete vault…/);
    assert.match(other, /Leave vault…/);
  }

  // A rotation that left this row behind makes it stale; getting out must still be possible.
  for (const myState of ["active", "invited", "stale", "suspended"] as const) {
    assert.match(actions({ myState }), /Leave vault…/);
  }
});

test("a rotation nobody can run yet is disabled and says why", () => {
  // A stale owner holds the retired key: the server would refuse the rotation anyway.
  assert.match(actions({ myState: "stale" }), /active owner/);
  assert.match(actions({ gate: { ...gate, unsaved: true } }), /unsaved edits/);
  assert.match(actions({ gate: { ...gate, open: false } }), /Open this vault/);
  assert.match(actions({ gate: { ...gate, keyReady: false } }), /user key/);
  assert.doesNotMatch(actions(), /disabled/, "nothing in the way, nothing disabled");
  assert.match(actions({ busy: true }), /disabled/);
});

test("the rotation-pending banner is an owner's alone", () => {
  const banner = "u-9 was removed on Sunday. Their copy of the key still opens anything this vault saved before a rotation.";
  assert.match(actions({ banner }), /u-9 was removed on Sunday/);
  assert.doesNotMatch(actions({ banner, isOwner: false }), /u-9 was removed/, "a member who cannot rotate is not told to");
});

test("a member with no key to seal to is told that, not that the key is unchecked", () => {
  assert.match(sealBlocked(undefined)!, /has not been checked yet/);
  assert.match(sealBlocked({ problem: "No published key" })!, /No published key/);
  assert.doesNotMatch(sealBlocked({ problem: "No published key" })!, /checked yet/);
  assert.match(sealBlocked({ problem: "Could not check this key" })!, /Could not check this key/);
  assert.match(sealBlocked({ key: published([]) })!, /no key to seal to/i);
  assert.equal(sealBlocked({ key: published([1, 2, 3]) }), null);

  // Someone else's changed pin is re-pinned from Security; my own row has no pin to re-pin,
  // so it must not be sent there — the key this browser holds is what moved.
  const other = sealBlocked({ key: { ...published([1, 2, 3]), state: "changed" } })!;
  assert.match(other, /Known keys/);
  const own = sealBlocked(selfView(published([9, 9, 9]), new Uint8Array([1, 2, 3])))!;
  assert.doesNotMatch(own, /Known keys/);
  assert.match(own, /this browser holds/);
});
