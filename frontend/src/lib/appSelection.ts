import { VaultSaveQueue, type SaveState } from "./vaultSave";
import { resolveSelection, selectionBase, type Selected, type OpenedShared } from "./vaultSelection";
import type { SharedVaultSummary } from "./sharedVaults";
import type { KeePassVault } from "./kdbx";
import type { UserKeyState } from "./userKeyState";

export type OpenedPersonal = { vault: KeePassVault; key: Uint8Array; version: number; passwordEnvelope?: string };

export type SwitchDeps = {
  confirmDiscard: () => Promise<boolean>;
  closeQueue: () => void;
  openShared: (row: SharedVaultSummary) => Promise<OpenedShared>;
  openPersonal: () => Promise<OpenedPersonal>;
  apply: (next: { selected: Selected; vault: KeePassVault; key: Uint8Array; queue: VaultSaveQueue; readOnly: boolean }) => void;
  notify: (text: string) => void;
  generation: () => number;
};

export const lostAccess = (selected: Selected, state: SaveState): boolean =>
  selected.kind === "shared" && state.kind === "error" && (state.status === 403 || state.status === 404);

// A shared write refused because the key was rotated elsewhere: this copy is sealed under a
// retired key, so there is nothing to overwrite with and the vault has to be re-opened. Every
// other 409 is an ordinary version conflict and keeps the overwrite/reload choice.
export const rotatedElsewhere = (selected: Selected, state: SaveState): boolean =>
  selected.kind === "shared" && state.kind === "error" && state.status === 409 &&
  /was rotated/.test(state.message);

// What the tab offers before a rotation elsewhere forces it to re-open the vault. The refused
// save is itself the proof there are unsaved edits, and they can never be uploaded — they are
// sealed under a retired key and the server is right to refuse them — but this tab still holds
// that key and the open database, so a download hands the user a KDBX they can open. Losing
// them is destructive, so it is never done without an answer to this question.
export const ROTATED_QUESTION = {
  title: "This vault's key was rotated elsewhere",
  message: "Your unsaved edits can no longer be saved: they are encrypted with the key that was just retired. " +
    "You can download a copy of this vault as it stands, then re-open it with the new key.",
  label: "Unsaved edits",
  options: [
    { value: "download", label: "Download a copy, then re-open the vault" },
    { value: "discard", label: "Re-open the vault and lose them" },
  ],
  confirmLabel: "Continue",
};

// The answer, decided: a dismissed question (Escape, or a lock cancelling it) does neither, so
// the edits stay on screen and the refusal banner stays with them.
export const rotatedPlan = (answer: string | null): { download: boolean; reopen: boolean } =>
  ({ download: answer === "download", reopen: answer !== null });

export type RestorePlan = { action: "wait" } | { action: "none" } | { action: "switch"; id: string } | { action: "notice"; text: string };

// Which vault an unlocked tab should reopen from its #/shared/<id> route.
// userKey is null until the unlock has settled it; any other kind than "ready" is final.
export function restorePlan(routeShared: string | undefined, vaults: SharedVaultSummary[] | null, userKey: UserKeyState["kind"] | null, done: boolean): RestorePlan {
  if (done || !routeShared) return { action: "none" };
  if (userKey !== null && userKey !== "ready") return { action: "notice", text: "Your user key is not available, so the shared vault could not be opened. Showing My vault." };
  if (!vaults || !userKey) return { action: "wait" };
  const { selected, notice } = resolveSelection(routeShared, vaults);
  if (notice) return { action: "notice", text: notice };
  return selected.kind === "shared" ? { action: "switch", id: selected.id } : { action: "none" };
}

// One vault at a time: the old queue closes before the next vault opens, a lock during the
// open wins, and any failure lands on the personal vault rather than on no vault.
export async function switchTo(target: Selected, row: SharedVaultSummary | undefined, deps: SwitchDeps): Promise<boolean> {
  if (!(await deps.confirmDiscard())) return false;
  const gen = deps.generation();
  deps.closeQueue();
  try {
    if (target.kind === "shared") {
      if (!row) throw new Error("That shared vault is no longer available.");
      const o = await deps.openShared(row);
      if (deps.generation() !== gen) { o.key.fill(0); return false; }
      deps.apply({ selected: target, vault: o.vault, key: o.key, queue: new VaultSaveQueue(o.vault, o.version, undefined, selectionBase(target), o.keyEpoch), readOnly: o.readOnly });
      return true;
    }
    const p = await deps.openPersonal();
    if (deps.generation() !== gen) return false;
    deps.apply({ selected: target, vault: p.vault, key: p.key, queue: new VaultSaveQueue(p.vault, p.version, p.passwordEnvelope), readOnly: false });
    return true;
  } catch (err) {
    deps.notify(err instanceof Error ? err.message : String(err));
    if (deps.generation() !== gen) return false;
    const p = await deps.openPersonal();
    if (deps.generation() !== gen) return false;
    deps.apply({ selected: { kind: "personal" }, vault: p.vault, key: p.key, queue: new VaultSaveQueue(p.vault, p.version, p.passwordEnvelope), readOnly: false });
    return false;
  }
}

// A rotation that finishes after a switch must not put the personal vault back on screen:
// only the personal selection, with the queue rotation started on (or none yet), takes it.
export const applyRotation = <Q>(selected: Selected, started: Q, current: Q | null): boolean =>
  selected.kind === "personal" && (current === null || current === started);

// What goes on screen when a locked checkpoint was recovered for a vault this user may only
// read: nothing of it. A reader's edits can never be uploaded, so the server copy opens and
// the checkpoint is left unread — settle never runs, so a session that can save it still
// has it — because the notice says the server copy and that has to be true.
export type OpenedDraft<V, E> = {
  vault: V;
  version: number;
  dirty: boolean;
  entry: E | null;
  recovered: boolean;
  settle: (current: () => boolean) => Promise<boolean>;
};

export const READ_ONLY_DRAFT = "This vault is read-only for you, so the recovered local edits cannot be applied. Showing the server copy.";

export function resolveDraft<V, E>(server: { vault: V; version: number }, draft: OpenedDraft<V, E>, readOnly: boolean, notices: string[]): OpenedDraft<V, E> {
  if (!draft.recovered || !readOnly) return draft;
  notices.unshift(READ_ONLY_DRAFT);
  return { vault: server.vault, version: server.version, dirty: false, entry: null, recovered: false, settle: async () => true };
}
