import { toErrorMessage } from "./api";
import { openSharedKey, sealSharedKey } from "./sharedKey";
import { canOpen, sharedApi, type SharedApi, type SharedVaultDetail, type SharedVaultSummary } from "./sharedVaults";

// Replacing the user key retires the key every shared vault key is sealed to, so each one
// must be opened with the old key first and re-sealed to the new one afterwards. A key the
// old key cannot open is already lost; the user hears that before anything is replaced.
export type HeldKey = { id: string; name: string; key: Uint8Array };
export type Unopenable = { id: string; name: string; soleOwner: boolean };
export type ReplacePlan = { held: HeldKey[]; unopenable: Unopenable[] };
export type SealIdentity = { id: string; publicKey: Uint8Array; fingerprint: string };
export type ResealFailure = { id: string; name: string; error: string };

// A vault with no other active owner has nobody left who can re-share it: replacing the key
// loses its contents. An unreadable member list is counted that way too — the warning must
// not be softened by a failed request.
async function isSoleOwner(v: SharedVaultSummary, getDetail: (id: string) => Promise<SharedVaultDetail>): Promise<boolean> {
  if (v.role !== "owner") return false;
  try {
    const detail = await getDetail(v.id);
    return detail.members.filter((m) => m.role === "owner" && m.state === "active").length <= 1;
  } catch {
    return true;
  }
}

// A null seed is a key this tab cannot use at all (a mismatched record): every vault is
// beyond reach, and the warning is the only notice the user gets before replacing it.
export async function planReplace(
  vaults: SharedVaultSummary[],
  seed: Uint8Array | null,
  openKey: typeof openSharedKey = openSharedKey,
  getDetail: (id: string) => Promise<SharedVaultDetail> = sharedApi.get,
): Promise<ReplacePlan> {
  const held: HeldKey[] = [];
  const unopenable: Unopenable[] = [];
  for (const v of vaults) {
    if (!canOpen(v)) continue;
    const key = seed ? await openKey(seed, v.myKey.sealedKey).catch(() => null) : null;
    if (key) held.push({ id: v.id, name: v.name, key });
    else unopenable.push({ id: v.id, name: v.name, soleOwner: await isSoleOwner(v, getDetail) });
  }
  return { held, unopenable };
}

export function replaceWarning(plan: ReplacePlan): string | null {
  if (plan.unopenable.length === 0) return null;
  const names = plan.unopenable
    .map((v) => `"${v.name}"${v.soleOwner ? " (you are its only owner, so its contents will be lost)" : ""}`)
    .join("; ");
  const one = plan.unopenable.length === 1;
  return `Your current key cannot open ${names}. Replacing your key does not recover ${one ? "it" : "them"}: where another owner remains, ask them to share the vault with you again.`;
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
