import { test } from "node:test";
import assert from "node:assert/strict";
import { switchTo, lostAccess, restorePlan, applyRotation, type SwitchDeps } from "./appSelection";
import { personal } from "./vaultSelection";

const ID = "sv_abcdefghijklmnopqrstuv";
const row: any = { id: ID, name: "Finance", role: "editor", state: "active", keyEpoch: 1, myKey: { sealedKey: "AAAA", keyFingerprint: "", keyEpoch: 1, sealedBy: "u-1", sealedByFingerprint: "" } };
const vaultA: any = { name: "personal" }; const vaultB: any = { name: "shared" };

function deps(over: Partial<SwitchDeps> = {}) {
  const log: string[] = [];
  let gen = 1;
  const d: SwitchDeps = {
    confirmDiscard: async () => true,
    closeQueue: () => { log.push("close"); },
    openShared: async () => { log.push("openShared"); return { vault: vaultB, key: new Uint8Array(32), version: 3, readOnly: false }; },
    openPersonal: async () => { log.push("openPersonal"); return { vault: vaultA, key: new Uint8Array(32), version: 9 }; },
    apply: (next) => { log.push(`apply:${next.selected.kind}:${(next.vault as any).name}:${next.queue.getSnapshot().version}`); },
    notify: (t) => { log.push(`notify:${t}`); },
    generation: () => gen,
    ...over,
  };
  return { d, log, bump: () => { gen++; } };
}

test("switching closes the old queue before opening the new one", async () => {
  const { d, log } = deps();
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), true);
  assert.deepEqual(log, ["close", "openShared", `apply:shared:shared:3`]);
});

test("declining the discard confirm aborts before anything closes", async () => {
  const { d, log } = deps({ confirmDiscard: async () => false });
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), false);
  assert.deepEqual(log, []);
});

test("a lock during the open is not applied", async () => {
  const h = deps();
  const key = new Uint8Array(32).fill(7);
  h.d.openShared = async () => { h.bump(); return { vault: vaultB, key, version: 3, readOnly: false }; };
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, h.d), false);
  assert.ok(!h.log.some((l) => l.startsWith("apply")));
  assert.ok(key.every((b) => b === 0), "a shared key opened for a stale generation is zeroed");
});

test("save 404 on a shared vault falls back to personal", () => {
  const sel = { kind: "shared", id: ID } as const;
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 404 } as any), true);
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 403 } as any), true);
  assert.equal(lostAccess(sel, { kind: "error", version: 3, message: "x", status: 409 } as any), false);
  assert.equal(lostAccess(personal, { kind: "error", version: 3, message: "x", status: 404 } as any), false);
});

test("an open failure notifies and falls back to the personal vault", async () => {
  const { d, log } = deps({ openShared: async () => { throw new Error("Your copy of the key cannot be opened; ask an owner to re-seal it."); } });
  assert.equal(await switchTo({ kind: "shared", id: ID }, row, d), false);
  assert.deepEqual(log, ["close", "notify:Your copy of the key cannot be opened; ask an owner to re-seal it.", "openPersonal", "apply:personal:personal:9"]);
});

test("a missing row falls back to the personal vault", async () => {
  const { d, log } = deps();
  assert.equal(await switchTo({ kind: "shared", id: ID }, undefined, d), false);
  assert.deepEqual(log, ["close", "notify:That shared vault is no longer available.", "openPersonal", "apply:personal:personal:9"]);
});

test("route restore after unlock", () => {
  const invited = { ...row, state: "invited" };
  // Waits until the list has loaded and the user key is ready.
  assert.deepEqual(restorePlan(ID, null, "ready", false), { action: "wait" });
  assert.deepEqual(restorePlan(ID, [row], null, false), { action: "wait" });
  // Nothing to restore, or already done this generation.
  assert.deepEqual(restorePlan(undefined, null, null, false), { action: "none" });
  assert.deepEqual(restorePlan(ID, [row], "ready", true), { action: "none" });
  assert.deepEqual(restorePlan(ID, [row], "ready", false), { action: "switch", id: ID });
  assert.deepEqual(restorePlan(ID, [], "ready", false), { action: "notice", text: "You are not a member of that shared vault." });
  assert.equal(restorePlan(ID, [invited], "ready", false).action, "notice");
  // A user key that settled without being usable never opens anything: say so instead of waiting.
  const noKey = { action: "notice", text: "Your user key is not available, so the shared vault could not be opened. Showing My vault." };
  for (const kind of ["none", "mismatch", "unavailable"] as const) assert.deepEqual(restorePlan(ID, [row], kind, false), noKey);
  assert.deepEqual(restorePlan(ID, null, "unavailable", false), noKey);
});

test("a finished rotation only replaces the live vault if nothing switched meanwhile", () => {
  const started: any = {}; const other: any = {};
  assert.equal(applyRotation(personal, started, started), true);
  assert.equal(applyRotation(personal, started, null), true, "the switch closed the queue but has not applied yet: still personal");
  assert.equal(applyRotation({ kind: "shared", id: ID }, started, other), false);
  assert.equal(applyRotation({ kind: "shared", id: ID }, started, null), false);
  assert.equal(applyRotation(personal, started, other), false, "a newer personal queue (reopen) wins");
});
