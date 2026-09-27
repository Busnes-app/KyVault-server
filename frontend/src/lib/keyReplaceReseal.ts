import { toErrorMessage } from "./api";
import { openSharedKey, sealSharedKey } from "./sharedKey";
import { canOpen, type SharedApi, type SharedVaultSummary } from "./sharedVaults";

// Replacing the user key retires the key every shared vault key is sealed to, so each one
// must be opened with the old key first and re-sealed to the new one afterwards. A key the
// old key cannot open is already lost; the user hears that before anything is replaced.
export type HeldKey = { id: string; name: string; key: Uint8Array };
export type Unopenable = { id: string; name: string; soleOwner: boolean };
export type ReplacePlan = { held: HeldKey[]; unopenable: Unopenable[] };
export type SealIdentity = { id: string; publicKey: Uint8Array; fingerprint: string };
export type ResealFailure = { id: string; name: string; error: string };
// What a re-seal still owes: the failures to show, the keys they need, and who to seal to.
export type ResealPending = { failed: ResealFailure[]; held: HeldKey[]; me: SealIdentity };

export type PlanApi = Pick<SharedApi, "list" | "get">;

export const REPLACE_KEY_MESSAGE = "Anyone who has verified your current key will be asked to verify the new one. Do this if you believe your private key was exposed.";

// A vault with no other active owner has nobody left who can re-share it: replacing the key
// loses its contents. An unreadable member list is counted that way too — the warning must
// not be softened by a failed request.
async function isSoleOwner(v: SharedVaultSummary, api: PlanApi): Promise<boolean> {
  if (v.role !== "owner") return false;
  try {
    const detail = await api.get(v.id);
    return detail.members.filter((m) => m.role === "owner" && m.state === "active").length <= 1;
  } catch {
    return true;
  }
}

// The list is fetched here, never taken from a cache: a page that opened before the first
// GET /api/shared, or after one failed, holds an empty list, and planning from that would
// replace the key while quietly stranding every vault. A list failure rejects instead.
// A null seed is a key this tab cannot use at all (a mismatched record): every vault is
// beyond reach, and the warning is the only notice the user gets before replacing it.
export async function planReplace(seed: Uint8Array | null, api: PlanApi, openKey: typeof openSharedKey = openSharedKey): Promise<ReplacePlan> {
  const vaults = await api.list();
  const held: HeldKey[] = [];
  const unopenable: Unopenable[] = [];
  for (const v of vaults) {
    // Invited, stale and suspended rows are not openable with any key today, so replacing
    // this one takes nothing from them.
    if (!canOpen(v)) continue;
    const key = seed ? await openKey(seed, v.myKey.sealedKey).catch(() => null) : null;
    if (key) held.push({ id: v.id, name: v.name, key });
    else unopenable.push({ id: v.id, name: v.name, soleOwner: await isSoleOwner(v, api) });
  }
  return { held, unopenable };
}

export function replaceWarning(plan: ReplacePlan): string | null {
  if (plan.unopenable.length === 0) return null;
  const names = plan.unopenable
    .map((v) => `"${v.name}"${v.soleOwner ? " (you are its only owner, so its contents will be lost)" : ""}`)
    .join("; ");
  const one = plan.unopenable.length === 1;
  return `Your current key cannot open ${one ? "this shared vault" : "these shared vaults"}: ${names}. Replacing your key does not recover ${one ? "it" : "them"}: where another owner remains, ask them to share the vault with you again.`;
}

// Never throws: a vault left unreachable has to be named on screen with a way to retry, not
// swallowed by a rejected promise half way through the list.
export async function resealHeld(held: HeldKey[], me: SealIdentity, api: SharedApi, seal: typeof sealSharedKey = sealSharedKey): Promise<{ failed: ResealFailure[] }> {
  const failed: ResealFailure[] = [];
  for (const h of held) {
    try {
      await api.updateMember(h.id, me.id, { sealedKey: await seal(me.publicKey, h.key), keyFingerprint: me.fingerprint });
    } catch (err) {
      failed.push({ id: h.id, name: h.name, error: toErrorMessage(err, "Could not re-seal this vault to your new key.") });
    }
  }
  return { failed };
}

export function zeroKeys(held: HeldKey[]): void {
  for (const h of held) h.key.fill(0);
}

export type ReplaceSteps = {
  api: SharedApi;
  // The seed about to be retired, or null when this tab holds no usable key.
  seed: Uint8Array | null;
  // Proves the master password; returns the vault version it holds for, or null if refused.
  prove: () => Promise<number | null>;
  confirm: (message: string) => Promise<boolean>;
  // Creates and publishes the new key; returns who the vaults must be sealed to.
  publish: (version: number) => Promise<SealIdentity>;
  openKey?: typeof openSharedKey;
  seal?: typeof sealSharedKey;
};

// The order is the safety property: plan (and so the warning) before the proof, the confirm
// before the publish, the re-seal after it. Anything the caller is not handed is zeroed,
// whichever way this ends.
export async function runKeyReplace(steps: ReplaceSteps): Promise<{ replaced: boolean; pending: ResealPending | null }> {
  const plan = await planReplace(steps.seed, steps.api, steps.openKey);
  let keep: ResealPending | null = null;
  try {
    const version = await steps.prove();
    if (version === null) return { replaced: false, pending: null };
    if (!await steps.confirm([REPLACE_KEY_MESSAGE, replaceWarning(plan)].filter(Boolean).join("\n\n"))) {
      return { replaced: false, pending: null };
    }
    const me = await steps.publish(version);
    const { failed } = await resealHeld(plan.held, me, steps.api, steps.seal);
    if (failed.length) keep = { failed, held: plan.held.filter((h) => failed.some((f) => f.id === h.id)), me };
    return { replaced: true, pending: keep };
  } finally {
    zeroKeys(plan.held.filter((h) => !keep?.held.includes(h)));
  }
}

// A retry of the failed subset only, from the keys the caller still holds. The caller's own
// state setter zeroes what it drops, so nothing is wiped here.
export async function retryPending(pending: ResealPending, api: SharedApi, seal: typeof sealSharedKey = sealSharedKey): Promise<ResealPending | null> {
  const { failed } = await resealHeld(pending.held, pending.me, api, seal);
  if (!failed.length) return null;
  return { ...pending, failed, held: pending.held.filter((h) => failed.some((f) => f.id === h.id)) };
}
