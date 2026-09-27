import type { KeePassVault } from "./kdbx";
import type { Lookup } from "./keyPins";
import { newSharedKey, sealSharedKey } from "./sharedKey";
import type { LookupResult, Role, SharedApi, SharedVaultSummary } from "./sharedVaults";

// The flows every shared-vault dialog runs, with the API, the pin store and my own key
// injected so they are testable without a browser and without the network.
export type PinStatus = {
  state: "pinned" | "unknown" | "changed";
  fingerprint: string;
  publicKey: Uint8Array;
  // Why a "changed" state was reached: the pin no longer matches the published key, or the
  // key that signed an invitation is not the key this user publishes now.
  drift?: "pin" | "invitation";
};

export type FlowDeps = {
  api: SharedApi;
  pinVault: KeePassVault;
  onPinChanged: () => void;
  lookupKey: (vault: KeePassVault, userId: string) => Promise<Lookup>;
  pinKey: (vault: KeePassVault, userId: string, publicKey: Uint8Array, onChanged: () => void) => Promise<unknown>;
  me: { id: string; publicKey: Uint8Array; fingerprint: string };
};

export const REPIN_FIRST = "This user's key changed since you pinned it. Re-pin it from Security → Known keys first.";
const NO_KEY = "That user has no published key.";
export const REPIN_CONFIRM = "Their key changed since you pinned it. Confirm re-pinning it before accepting.";

export async function createSharedVault(name: string, deps: FlowDeps): Promise<{ id: string; key: Uint8Array }> {
  const key = newSharedKey();
  const sealedKey = await sealSharedKey(deps.me.publicKey, key);
  const { id } = await deps.api.create(name, sealedKey, deps.me.fingerprint);
  return { id, key };
}

const statusOf = (l: Lookup): PinStatus => ({
  state: l.state,
  fingerprint: l.published?.fingerprint ?? "",
  publicKey: l.published?.publicKey ?? new Uint8Array(),
  ...(l.state === "changed" ? { drift: "pin" as const } : {}),
});

export async function resolveInvitee(username: string, deps: FlowDeps): Promise<{ user: LookupResult; pin: PinStatus } | null> {
  const user = await deps.api.lookupUser(username);
  if (!user) return null;
  const pin = statusOf(await deps.lookupKey(deps.pinVault, user.userId));
  if (!pin.publicKey.length) throw new Error(NO_KEY);
  return { user, pin };
}

// Trust on first use: an unpinned key is pinned as it is used, a changed one never is.
async function sealFor(userId: string, pin: PinStatus, sharedKey: Uint8Array, deps: FlowDeps): Promise<{ sealedKey: string; keyFingerprint: string }> {
  if (pin.state === "changed") throw new Error(REPIN_FIRST);
  if (pin.state === "unknown") await deps.pinKey(deps.pinVault, userId, pin.publicKey, deps.onPinChanged);
  return { sealedKey: await sealSharedKey(pin.publicKey, sharedKey), keyFingerprint: pin.fingerprint };
}

export async function inviteMember(vaultId: string, invitee: { user: LookupResult; pin: PinStatus }, role: Role, sharedKey: Uint8Array, deps: FlowDeps): Promise<void> {
  const s = await sealFor(invitee.user.userId, invitee.pin, sharedKey, deps);
  await deps.api.invite(vaultId, invitee.user.userId, role, s.sealedKey, s.keyFingerprint);
}

// `shown` is the verdict the caller put on screen, not a fresh lookup: the key sealed here
// has to be the one whose fingerprint the user was looking at when they clicked.
export async function resealMember(vaultId: string, userId: string, shown: PinStatus, sharedKey: Uint8Array, deps: FlowDeps): Promise<void> {
  // My own key needs no pin: I hold it.
  const pin: PinStatus = userId === deps.me.id
    ? { state: "pinned", fingerprint: deps.me.fingerprint, publicKey: deps.me.publicKey }
    : shown;
  if (!pin.publicKey.length) throw new Error(NO_KEY);
  const s = await sealFor(userId, pin, sharedKey, deps);
  await deps.api.updateMember(vaultId, userId, s);
}

// What the Accept dialog shows about the person who invited me. The server is trusted for
// who is in a vault, never for whose key that is: the fingerprint on screen is the one the
// user compares out of band.
export async function inviterStatus(row: SharedVaultSummary, deps: FlowDeps): Promise<PinStatus> {
  const by = row.invitedBy;
  const unknown: PinStatus = { state: "unknown", fingerprint: by?.fingerprint ?? "", publicKey: new Uint8Array() };
  if (!by) return unknown;
  const status = statusOf(await deps.lookupKey(deps.pinVault, by.userId));
  if (!status.publicKey.length) return unknown;
  if (status.state !== "changed" && by.fingerprint && by.fingerprint !== status.fingerprint) {
    return { ...status, state: "changed", drift: "invitation" };
  }
  return status;
}

// Replacing a pin is a decision, so it lives here with the same weight as the refusal in
// sealFor: the dialog may only pass repinConfirmed once its second confirm resolved true.
export async function acceptInvitation(row: SharedVaultSummary, status: PinStatus, deps: FlowDeps, opts: { repinConfirmed?: boolean } = {}): Promise<void> {
  if (status.state === "changed" && !opts.repinConfirmed) throw new Error(REPIN_CONFIRM);
  const userId = row.invitedBy?.userId;
  if (userId && status.state !== "pinned" && status.publicKey.length > 0) {
    await deps.pinKey(deps.pinVault, userId, status.publicKey, deps.onPinChanged);
  }
  await deps.api.accept(row.id);
}
