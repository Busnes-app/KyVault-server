import { HttpError, requestJSON, toErrorMessage } from "./api";
import type { KeePassVault } from "./kdbx";

export type SaveState =
  | { kind: "saved"; version: number }
  | { kind: "saving"; version: number }
  | { kind: "error"; version: number; message: string; conflict?: boolean; status?: number };

export const PERSONAL_BASE = "/api/vault";

// What the save banner may offer. A retired-epoch 409 can only be answered by the server's
// copy: `save()` is a no-op for it, so a Retry button there would do nothing at all.
export const saveAction = (state: SaveState): "overwrite" | "reload" | "retry" | null =>
  state.kind !== "error" ? null : state.conflict ? "overwrite" : state.status === 409 ? "reload" : "retry";

// The server's two epoch refusals: the key was rotated under this tab, or the write never said
// which key it used at all (a tab left open across a deploy, or a client that sends no epoch
// header). Both share their status code with a version conflict and mean the opposite of one:
// this copy cannot be the basis of an overwrite, and the only answer is to re-open the vault.
export const ROTATION_REFUSAL = /was rotated|did not say which shared vault key/;

// A shared write the server refused for either of those reasons. Overwriting is the one thing
// that must not happen; callers re-open the vault.
export const isRotationRefusal = (err: unknown): boolean =>
  err instanceof HttpError && err.status === 409 && ROTATION_REFUSAL.test(err.message);

export async function uploadVault(binary: ArrayBuffer, version: number, passwordEnvelope?: string, recoveryEnvelope?: string, signal?: AbortSignal, keyRotated = false, userKeyHeader?: string, basePath = PERSONAL_BASE, keyEpoch?: number): Promise<number> {
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "If-Match": `"${version}"`,
  };
  // Every shared write proves which key epoch it sealed its ciphertext under; a personal
  // vault has no epoch, and sending one there would be a header the server never reads.
  if (basePath !== PERSONAL_BASE && keyEpoch !== undefined) headers["X-Shared-Key-Epoch"] = String(keyEpoch);
  if (keyRotated) headers["X-Vault-Key-Rotated"] = "1";
  if (passwordEnvelope) headers["X-Password-Envelope"] = passwordEnvelope;
  if (recoveryEnvelope) headers["X-Recovery-Envelope"] = recoveryEnvelope;
  if (userKeyHeader) headers["X-User-Key"] = userKeyHeader;
  const data = await requestJSON<unknown>(`${basePath}/upload`, { method: "POST", headers, body: binary, signal });
  if (typeof data !== "object" || data === null || !("metadata" in data) ||
      typeof data.metadata !== "object" || data.metadata === null || !("version" in data.metadata) ||
      typeof data.metadata.version !== "number" || !Number.isSafeInteger(data.metadata.version) || data.metadata.version <= version) {
    throw new Error("The server did not confirm the saved vault version.");
  }
  return data.metadata.version;
}

// Security actions may proceed in every save state; only the user's refusal cancels them.
export async function canDiscardVault(state: SaveState, hasDraft: boolean, confirmDiscard: () => Promise<boolean>): Promise<boolean> {
  return (!hasDraft && state.kind === "saved") || confirmDiscard();
}

// One queue per unlocked vault; a successful upload only acknowledges its starting revision.
export class VaultSaveQueue {
  private revision = 0;
  private savedRevision = 0;
  private running = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private controller = new AbortController();
  private listeners = new Set<() => void>();
  private state: SaveState;
  private exporting: Promise<unknown> = Promise.resolve();
  private onlineRetry: (() => void) | undefined;

  // passwordEnvelope is the one this vault was unlocked against: a different stored one
  // means another session rotated the key, and this copy must not overwrite the server's.
  constructor(private vault: KeePassVault | null, version: number, private passwordEnvelope?: string, private basePath = PERSONAL_BASE, private epoch?: number) {
    this.state = { kind: "saved", version };
  }

  // The epoch this queue's ciphertext is sealed under; undefined for the personal vault.
  get keyEpoch(): number | undefined { return this.epoch; }
  // A rotation this tab committed re-keyed the vault; later saves belong to the new epoch.
  setKeyEpoch = (epoch: number): void => { this.epoch = epoch; };

  // Downloads, uploads and key rotation share the same mutable KDBX serializer.
  exclusive = <T>(run: (vault: KeePassVault) => Promise<T>): Promise<T> => {
    const vault = this.vault;
    const result = this.exporting.then(() => {
      if (!vault) throw new Error("Vault is locked.");
      return run(vault);
    });
    this.exporting = result.catch(() => {});
    return result;
  };
  exportBinary = (): Promise<ArrayBuffer> => this.exclusive((vault) => vault.exportBinary());

  recoverUnsaved = (): void => {
    this.revision++;
    this.publish({ kind: "error", version: this.state.version, message: "Recovered unsaved edits. Review and retry saving, or download this copy before reloading." });
  };

  getSnapshot = (): SaveState => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private publish(state: SaveState) {
    this.state = state;
    this.listeners.forEach((listener) => listener());
  }

  // Explicitly discarding cancels debounce, aborts transport, and prevents later revisions
  // from uploading after a new unlock/session. A request already accepted cannot be undone.
  discard = (): void => {
    clearTimeout(this.timer);
    this.clearOnlineRetry();
    this.controller.abort();
    this.vault = null;
    this.listeners.clear();
  };

  changed = (): void => {
    if (this.controller.signal.aborted) return;
    this.revision++;
    // Failed uploads stop automatic retries, including conflicts. Retry is explicit.
    if (this.state.kind === "error" || this.running) return;
    clearTimeout(this.timer);
    this.publish({ kind: "saving", version: this.state.version });
    this.timer = setTimeout(() => { void this.save(); }, 1500);
  };

  save = async (options: { overwrite?: boolean } = {}): Promise<void> => {
    clearTimeout(this.timer);
    this.clearOnlineRetry();
    if (this.controller.signal.aborted || this.running || this.revision === this.savedRevision) return;
    if (this.state.kind === "error" && this.state.conflict && !options.overwrite) return;
    // A 409 that is not a version conflict is the retired-epoch refusal: this copy is sealed
    // under a key the server no longer accepts, so no retry and no overwrite can land it.
    if (this.state.kind === "error" && !this.state.conflict && this.state.status === 409) return;
    this.running = true;
    this.publish({ kind: "saving", version: this.state.version });
    try {
      if (options.overwrite) {
        // The server's copy stays in version history; ours becomes the head.
        const meta = await requestJSON<{ version?: unknown; passwordEnvelope?: string }>(`${this.basePath}/metadata`, { method: "GET", signal: this.controller.signal });
        if (typeof meta.version !== "number" || !Number.isSafeInteger(meta.version)) throw new Error("The server did not report its vault version.");
        // Shared metadata has no envelope; the rotation guard only applies to the personal vault.
        if (this.basePath === PERSONAL_BASE && meta.passwordEnvelope !== this.passwordEnvelope) throw new Error("The vault key was rotated in another session. Download this copy, then lock and unlock with your master password.");
        this.state = { ...this.state, version: meta.version };
      }
      while (this.savedRevision < this.revision) {
        const revision = this.revision;
        const binary = await this.exportBinary();
        if (this.controller.signal.aborted) return;
        const version = await uploadVault(binary, this.state.version, undefined, undefined, this.controller.signal, false, undefined, this.basePath, this.epoch);
        if (this.controller.signal.aborted) return;
        this.savedRevision = revision;
        this.publish({ kind: this.savedRevision === this.revision ? "saved" : "saving", version });
      }
    } catch (err) {
      if (this.controller.signal.aborted) return;
      const rotated = isRotationRefusal(err);
      const conflict = err instanceof HttpError && err.status === 409 && !rotated;
      // A 409 of either kind is answered by the user, never by a retry when the link returns.
      if (!(err instanceof HttpError && err.status === 409) && typeof window !== "undefined") {
        this.onlineRetry = () => { this.clearOnlineRetry(); void this.save(); };
        window.addEventListener("online", this.onlineRetry);
      }
      this.publish({ kind: "error", version: this.state.version, conflict, status: err instanceof HttpError ? err.status : undefined, message: conflict
        ? "A newer vault exists on the server. Overwrite it with this copy (the server copy stays in Version History) or reload the server copy and lose these edits."
        // The server's words, so appSelection.rotatedElsewhere can act on them.
        : toErrorMessage(err, "Unable to save vault. Your edits are still here.") });
    } finally {
      this.running = false;
    }
  };

  private clearOnlineRetry() {
    if (this.onlineRetry && typeof window !== "undefined") window.removeEventListener("online", this.onlineRetry);
    this.onlineRetry = undefined;
  }
}
