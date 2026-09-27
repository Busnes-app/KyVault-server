import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { HttpError } from "../lib/api";
import { type AdminSharedVault } from "../lib/sharedVaults";
import { ErrorLine, VaultRow, rowBusy, saveRestricted } from "./AdminShared";

const vault = (over: Partial<AdminSharedVault> = {}): AdminSharedVault => ({
  id: "sv_abcdefghijklmnopqrstuv", name: "Finance", createdBy: "u-1", createdAt: "2026-09-27T10:00:00Z",
  keyEpoch: 1, ownerless: false,
  members: [
    { userId: "u-1", username: "mock-admin", role: "owner", state: "active" },
    { userId: "u-2", username: "dana", role: "reader", state: "invited" },
  ],
  ...over,
});

test("a refused settings PUT puts the server's value back and says why", async () => {
  const refused = await saveRestricted(false, true, async () => {
    throw new HttpError(403, "re-authenticate to continue: this action needs a recent sign-in");
  });
  assert.equal(refused.restricted, false, "the checkbox must not keep the value the server rejected");
  assert.match(refused.error, /^re-authenticate to continue/);

  const failed = await saveRestricted(true, false, async () => { throw new Error("network down"); });
  assert.equal(failed.restricted, true);
  assert.equal(failed.error, "network down");

  let sent: unknown = null;
  const ok = await saveRestricted(false, true, async (s) => { sent = s; });
  assert.deepEqual(sent, { createRestrictedToAdmins: true });
  assert.deepEqual(ok, { restricted: true, error: "" });
});

test("only a fresh-session refusal offers a way back in", () => {
  const gated = renderToStaticMarkup(createElement(ErrorLine, { text: "re-authenticate to continue: this action needs a recent sign-in" }));
  assert.match(gated, /role="alert"/);
  assert.match(gated, /href="\/api\/auth\/oidc\/login\?reauth=true"/);
  assert.match(gated, /Sign in again/);

  const other = renderToStaticMarkup(createElement(ErrorLine, { text: "only an owner can delete a shared vault" }));
  assert.match(other, /role="alert"/);
  assert.doesNotMatch(other, /reauth=true/);
});

test("a running action marks its own row busy and no other", () => {
  assert.equal(rowBusy("sv_abcdefghijklmnopqrstuv", "sv_abcdefghijklmnopqrstuv"), true);
  assert.equal(rowBusy("sv_abcdefghijklmnopqrstuv:u-2", "sv_abcdefghijklmnopqrstuv"), true, "a member removal belongs to its vault's row");
  assert.equal(rowBusy("sv_abcdefghijklmnopqrstuv:u-2", "sv_zzzzzzzzzzzzzzzzzzzzzz"), false);
  assert.equal(rowBusy("sv_abcdefghijklmnopqrstuv", "sv_abcdefghijklmnopqrstuvWXYZ"), false, "an id prefix is not the same vault");
  assert.equal(rowBusy(null, "sv_abcdefghijklmnopqrstuv"), false);
});

test("a busy row disables its destructive controls; an expanded row lists members", () => {
  const props = { vault: vault(), expanded: true, onToggle: () => {}, onDelete: () => {}, onRemoveMember: () => {} };
  const busy = renderToStaticMarkup(createElement(VaultRow, { ...props, busy: true }));
  assert.equal(busy.match(/<button[^>]*disabled/g)?.length, 3, "delete vault and both member removals");
  assert.match(busy, /dana/);

  const idle = renderToStaticMarkup(createElement(VaultRow, { ...props, busy: false }));
  assert.equal(idle.match(/<button[^>]*disabled/g), null);

  const collapsed = renderToStaticMarkup(createElement(VaultRow, { ...props, expanded: false }));
  assert.doesNotMatch(collapsed, /dana/, "a collapsed row does not render its members");
  assert.match(renderToStaticMarkup(createElement(VaultRow, { ...props, vault: vault({ ownerless: true }) })), /Ownerless/);
});
