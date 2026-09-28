import { newSharedKey, sealSharedKey, openSharedKey } from "./sharedKey";
import type { Member, Pending, SharedApi } from "./sharedVaults";
import { REPIN_FIRST, type PinStatus } from "./sharedFlows";
import { formatWhen } from "./format";

export type KeyView = { key: PinStatus } | { problem: string };
export type Seal = { userId: string; publicKey: Uint8Array; pin: PinStatus };
export type LeftBehind = { userId: string; username: string; reason: string };
export type RotationPlan = { seal: Seal[]; leftBehind: LeftBehind[] };

const CHANGED = "their key changed since you pinned it";
const UNCHECKED = "Could not check this key";
// A user with no published key reads as `unknown` with an empty publicKey, so "unknown" alone
// is not permission to seal. The same rule guards every caller of sharedFlows.sealFor (NO_KEY),
// deliberately in two places: without it here, pinning-as-we-use would write a pin for zero
// bytes and leave that member reading "changed" until the owner forgets the pin by hand.
const NO_KEY = "No published key";

// planRotation decides who gets a copy of the next key. A member whose published key no
// longer matches the owner's pin is left behind rather than blocking the rotation: this is
// the action that locks out someone who was removed, and an unrelated trust question must
// not hold it up. They stay stale until an owner verifies the new key and re-seals them.
// My own row is sealed unconditionally from the key this tab holds — the server refuses a
// rotation that does not name the caller, and a pin of my own key is never written.
export function planRotation(members: Member[], views: Record<string, KeyView>,
                             me: { id: string; publicKey: Uint8Array; fingerprint: string }): RotationPlan {
  const seal: Seal[] = [{ userId: me.id, publicKey: me.publicKey, pin: { state: "pinned", fingerprint: me.fingerprint, publicKey: me.publicKey } }];
  const leftBehind: LeftBehind[] = [];
  for (const m of members) {
    if (m.userId === me.id) continue;
    const v = views[m.userId];
    if (!v || "problem" in v) {
      leftBehind.push({ userId: m.userId, username: m.username, reason: v ? v.problem : UNCHECKED });
      continue;
    }
    if (v.key.state === "changed" || !v.key.publicKey.length) {
      leftBehind.push({ userId: m.userId, username: m.username, reason: v.key.publicKey.length ? CHANGED : NO_KEY });
      continue;
    }
    seal.push({ userId: m.userId, publicKey: v.key.publicKey, pin: v.key });
  }
  return { seal, leftBehind };
}

export type RotateDeps = {
  // metadata answers the one question a lost rotation response leaves open: which version
  // the vault is on now, which is what the caller's save queue has to claim next.
  api: Pick<SharedApi, "rotate" | "list" | "metadata">;
  pinUnknown: (userId: string, publicKey: Uint8Array) => Promise<void>;
  reEncrypt: (key: Uint8Array) => Promise<ArrayBuffer>;   // exports the open vault under a new key
  seal?: typeof sealSharedKey;
  openKey?: typeof openSharedKey;
  seed: Uint8Array;
};
export type RotationOutcome = { key: Uint8Array; keyEpoch: number; version: number; leftBehind: LeftBehind[]; historyCleared: boolean };

export async function rotateSharedVault(id: string, epoch: number, version: number,
                                        plan: RotationPlan, deps: RotateDeps): Promise<RotationOutcome> {
  const seal = deps.seal ?? sealSharedKey;
  // planRotation leaves a changed pin behind; refused here too, where the sealing happens, and
  // before the loop so the refusal is total: a pin written for one member and then a throw is
  // the worst of both. Same rule, and same reason, as sharedFlows.sealFor.
  if (plan.seal.some((s) => s.pin.state === "changed")) throw new Error(REPIN_FIRST);
  // And the other half of planRotation's rule, for the same reason: pinning zero bytes would
  // leave that member reading "changed" in every later verdict until the owner forgot the pin.
  if (plan.seal.some((s) => !s.publicKey.length)) throw new Error(`${NO_KEY}: there is nothing to seal to.`);
  const key = newSharedKey();
  const sealed: { userId: string; sealedKey: string; keyFingerprint: string }[] = [];
  for (const s of plan.seal) {
    // Trust on first use, as invite does: an unpinned key is pinned as it is used.
    if (s.pin.state === "unknown") await deps.pinUnknown(s.userId, s.publicKey);
    sealed.push({ userId: s.userId, sealedKey: await seal(s.publicKey, key), keyFingerprint: s.pin.fingerprint });
  }
  const kdbx = await deps.reEncrypt(key);
  try {
    const res = await deps.api.rotate(id, kdbx, epoch, version, sealed);
    return { key, keyEpoch: res.keyEpoch, version: res.metadata.version, leftBehind: plan.leftBehind, historyCleared: res.historyCleared };
  } catch (err) {
    // A rotation whose response was lost still re-keyed the vault, and every sealed copy
    // committed with it, this tab's included — a reload recovers the vault either way. Checking
    // the server spares the owner an error about a rotation that succeeded; it is not what
    // keeps the vault openable, so nothing here may be treated as a durability guarantee.
    let landed: { keyEpoch: number; version: number } | null;
    try {
      landed = await rotationLanded(id, key, deps);
    } catch {
      // The check failed too: nothing is known, and the rotation's own error is the honest one.
      throw err;
    }
    if (!landed) throw err;
    // The response is gone, so the plan's list is the only one there is and the history clear
    // is unknown — reported as not done, which asks for a rotation that was harmless anyway.
    return { key, keyEpoch: landed.keyEpoch, version: landed.version, leftBehind: plan.leftBehind, historyCleared: false };
  }
}

// Whether the vault is now sealed to `expected` for me. A list that fails throws: it says
// nothing about the rotation, and answering "did not land" would report a rotation that may
// well have committed as a failure.
export async function rotationLanded(id: string, expected: Uint8Array, deps: RotateDeps): Promise<{ keyEpoch: number; version: number } | null> {
  const open = deps.openKey ?? openSharedKey;
  const row = (await deps.api.list()).find((v) => v.id === id);
  if (!row) return null;
  const mine = await open(deps.seed, row.myKey.sealedKey).catch(() => null);
  if (!mine) return null;
  const same = mine.length === expected.length && mine.every((b, i) => b === expected[i]);
  if (!same) return null;
  // The response that carried the version is gone; a metadata read that fails throws for the
  // same reason a failed list does — the caller keeps the key the server last accepted.
  return { keyEpoch: row.keyEpoch, version: (await deps.api.metadata(id)).version };
}

// Why the Rotate button refuses, or null when it may run, most fundamental reason first.
export type RotateGate = { activeOwner: boolean; keyReady: boolean; open: boolean; unsaved: boolean };
export function rotateBlocked(g: RotateGate): string | null {
  if (!g.activeOwner) return "Only an active owner of this vault can rotate its key.";
  if (!g.keyReady) return "Your user key is not ready, so no new copies of the key can be sealed.";
  if (!g.open) return "Open this vault before rotating its key.";
  if (g.unsaved) return "Save or discard your unsaved edits first.";
  return null;
}

const REASON: Record<Pending["reason"], string> = { removed: "was removed", left: "left", declined: "declined the invitation" };

// The member the flag names has usually been deleted from the record, so their id is all
// there is to call them by.
export const pendingName = (p: Pending, members: { userId: string; username: string }[]): string =>
  members.find((m) => m.userId === p.userId)?.username ?? p.userId;

export const rotationBanner = (p: Pending, members: { userId: string; username: string }[]): string =>
  `${pendingName(p, members)} ${REASON[p.reason]} on ${formatWhen(p.since)}. ` +
  "Their copy of the key still opens anything this vault saved before a rotation. " +
  "Rotating re-keys the vault for everyone who remains.";

// What the owner is told afterwards: how many copies of the new key exist, who holds none,
// and — because the server only audits it — whether the retired-key snapshots really went.
export function rotationReport(sealed: number, o: Pick<RotationOutcome, "leftBehind" | "historyCleared">): string {
  const parts = [`Rotated. ${sealed} member${sealed === 1 ? " has" : "s have"} the new key.`];
  if (o.leftBehind.length) {
    parts.push(`${o.leftBehind.map((l) => `${l.username} (${l.reason})`).join(", ")} did not get a copy.`,
      "Verify their key and re-seal them from this dialog.");
  }
  if (!o.historyCleared) {
    parts.push("This vault's old version history and preserved conflicts could not be deleted, so they are still on the server under the retired key. Rotate again to clear them.");
  }
  return parts.join(" ");
}
