import { ConflictComparison } from "./ConflictComparison";
import { KeePassVault, isWrongVaultKey } from "../lib/kdbx";
import { useState, useEffect, useRef } from "react";
import { getBinary, getJSON, postJSON, deleteJSON, toErrorMessage } from "../lib/api";
import { diffVaults, type DiffRow, type VaultDiff } from "../lib/vaultDiff";
import { RotateCcw, AlertTriangle, Trash2, CheckCircle2, Eye, EyeOff } from "lucide-react";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";

type HistoryEntry = {
  id: string;
  version: number;
  sizeBytes: number;
  checksum: string;
  timestamp: string;
};

type ConflictEntry = {
  id: string;
  expectedVersion: number;
  deviceId: string;
  sizeBytes: number;
  timestamp: string;
};

// Snapshot previews exist only in this component's state; closing or locking unmounts it.
type Preview =
  | { kind: "loading" }
  | { kind: "ready"; diff: VaultDiff; folders: { now: number; snapshot: number } }
  | { kind: "oldKey" }
  | { kind: "error" };

const folderCount = (vault: KeePassVault) => vault.getLiveGroups().length - 1; // excludes the root
const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
const countsSentence = (p: Extract<Preview, { kind: "ready" }>) =>
  `The snapshot has ${count(p.diff.counts.other, "entry", "entries")} and ${count(p.folders.snapshot, "folder", "folders")}. ` +
  `The vault has ${count(p.diff.counts.live, "entry", "entries")} and ${count(p.folders.now, "folder", "folders")} now.`;
const OLD_KEY_REASON = "Saved under a previous vault key. The current key cannot open it, so rolling back to it would leave a vault nobody can unlock.";

type Props = {
  snapshot?: { vault: KeePassVault; vaultKey: Uint8Array };
  recovery?: { vault: KeePassVault; vaultKey: Uint8Array; onRecovered: (uuid: string) => void };
  allowRollback: boolean;
  onClose: () => void;
  onRestored: () => void;
  onNotice: (text: string) => void;
};

export function HistoryModal({ onClose, onRestored, onNotice, recovery, snapshot, allowRollback }: Props) {
  const dialogs = useDialogs();
  const [comparisonId, setComparisonId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"history" | "conflicts">("history");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [conflicts, setConflicts] = useState<ConflictEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [previews, setPreviews] = useState<Record<string, Preview>>({});
  const [openPreview, setOpenPreview] = useState<string | null>(null);
  const aborts = useRef(new Set<AbortController>());

  // Previews are bound to the key that opened them; a new key or unmount drops them.
  useEffect(() => {
    setPreviews({});
    setOpenPreview(null);
    const pending = aborts.current;
    return () => { for (const c of pending) c.abort(); pending.clear(); };
  }, [snapshot?.vaultKey]);

  const loadPreview = async (id: string): Promise<Preview> => {
    if (!snapshot) return { kind: "error" };
    const controller = new AbortController();
    aborts.current.add(controller);
    setPreviews((prev) => ({ ...prev, [id]: { kind: "loading" } }));
    let result: Preview;
    try {
      const bytes = await getBinary(`/api/vault/history/${encodeURIComponent(id)}`, controller.signal);
      const opened = await KeePassVault.open(bytes, snapshot.vaultKey);
      result = {
        kind: "ready",
        diff: diffVaults(snapshot.vault.getLiveEntries(), opened.getLiveEntries()),
        folders: { now: folderCount(snapshot.vault), snapshot: folderCount(opened) },
      };
    } catch (err) {
      result = isWrongVaultKey(err) ? { kind: "oldKey" } : { kind: "error" };
    } finally {
      aborts.current.delete(controller);
    }
    if (!controller.signal.aborted) setPreviews((prev) => ({ ...prev, [id]: result }));
    return result;
  };

  const togglePreview = (id: string) => {
    if (openPreview === id) { setOpenPreview(null); return; }
    setOpenPreview(id);
    const current = previews[id];
    if (!current || current.kind === "error") void loadPreview(id);
  };

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [histData, confData] = await Promise.all([
        getJSON<HistoryEntry[]>("/api/vault/history"),
        getJSON<ConflictEntry[]>("/api/vault/conflicts"),
      ]);
      setHistory(histData || []);
      setConflicts(confData || []);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load history"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const restoreSnapshot = async (id: string) => {
    if (!allowRollback || busyId !== null) return;
    // While unlocked, only a snapshot the current key opens can be rolled back to.
    let preview = previews[id];
    if (snapshot && preview?.kind !== "ready") {
      setBusyId(id);
      setOpenPreview(id);
      preview = await loadPreview(id);
      setBusyId(null);
      if (preview.kind !== "ready") return;
    }
    if (!await dialogs.confirm({
      title: "Roll back the vault?",
      message: preview?.kind === "ready"
        ? `${countsSentence(preview)} Roll back to this snapshot? The current version will be archived.`
        : `Roll back to snapshot ${id}? The current version will be archived.`,
      confirmLabel: "Roll back",
      danger: true,
    })) return;
    setBusyId(id);
    setMessage("");
    setError("");
    try {
      await postJSON(`/api/vault/history/${id}/restore`, {});
      onNotice("Vault restored to the selected version.");
      onRestored();
    } catch (err) {
      setError(toErrorMessage(err, "Failed to restore snapshot"));
    } finally {
      setBusyId(null);
    }
  };

  const discardConflict = async (id: string) => {
    if (!allowRollback || busyId !== null) return;
    if (!await dialogs.confirm({
      title: "Discard this conflict?",
      message: "Discard this conflict upload?",
      confirmLabel: "Discard",
      danger: true,
    })) return;
    setBusyId(id);
    setMessage("");
    setError("");
    try {
      await deleteJSON(`/api/vault/conflicts/${id}`);
      setConflicts((prev) => prev.filter((c) => c.id !== id));
      setMessage("Conflict upload removed.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to discard conflict"));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <Dialog title="Vault Version History & Rollback" onClose={onClose} size="lg">
        <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--line)", marginBottom: "1.5rem" }}>
          <button
            className={`nav-link-btn ${activeTab === "history" ? "active" : ""}`}
            onClick={() => { setComparisonId(null); setActiveTab("history"); setMessage(""); setError(""); }}
          >
            Snapshots ({history.length})
          </button>
          <button
            className={`nav-link-btn ${activeTab === "conflicts" ? "active" : ""}`}
            onClick={() => { setComparisonId(null); setActiveTab("conflicts"); setMessage(""); setError(""); }}
          >
            Preserved Conflicts ({conflicts.length})
          </button>
        </div>

        {activeTab === "history" ? (
          <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>
            Keeps up to 100 snapshots spread across the server’s retention period (90 days by default). Closely spaced snapshots are thinned as you save or roll back.
          </p>
        ) : null}

        {message ? (
          <p style={{ color: "var(--accent)", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <CheckCircle2 size={16} /> {message}
          </p>
        ) : null}
        {error ? (
          <p style={{ color: "var(--danger)", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.6rem" }}>
            {error}
            <button className="btn btn-quiet btn-sm" onClick={loadData}>
              Retry
            </button>
          </p>
        ) : null}

        {comparisonId && recovery ? (
          <ConflictComparison key={comparisonId} conflictId={comparisonId} current={recovery.vault} vaultKey={recovery.vaultKey}
            onRecovered={recovery.onRecovered} onBack={() => setComparisonId(null)} />
        ) : loading ? (
          <p style={{ color: "var(--ink-muted)" }}>Loading {activeTab === "history" ? "snapshots" : "conflicts"}…</p>
        ) : activeTab === "history" ? (
          history.length === 0 ? (
            <p style={{ color: "var(--ink-muted)" }}>No past version snapshots found.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {history.map((h) => {
                const preview = previews[h.id];
                const refused = snapshot && (preview?.kind === "oldKey" || preview?.kind === "error");
                const rollbackReason = !allowRollback ? "Save or discard your unsaved edits first."
                  : preview?.kind === "oldKey" ? OLD_KEY_REASON
                  : preview?.kind === "error" ? "This snapshot could not be opened with the current vault key."
                  : undefined;
                return (
                <div
                  key={h.id}
                  style={{
                    background: "var(--bg)",
                    border: "1px solid var(--line)",
                    borderRadius: "6px",
                    padding: "0.75rem 1rem",
                  }}
                >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", flexWrap: "wrap" }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                      Version {h.version || h.id}
                    </div>
                    <div style={{ color: "var(--ink-muted)", fontSize: "0.8rem", marginTop: "0.2rem" }}>
                      {new Date(h.timestamp).toLocaleString()} • {(h.sizeBytes / 1024).toFixed(1)} KB • Checksum:{" "}
                      <code className="font-mono">{h.checksum.slice(0, 8)}</code>
                    </div>
                    {preview?.kind === "oldKey" ? (
                      <div style={{ color: "var(--warning)", fontSize: "0.8rem", marginTop: "0.2rem" }}>Saved under a previous vault key</div>
                    ) : null}
                  </div>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    <button
                      className="btn btn-quiet btn-sm"
                      disabled={!snapshot}
                      aria-expanded={openPreview === h.id}
                      title={!snapshot ? "Unlock the vault to preview a snapshot." : undefined}
                      onClick={() => togglePreview(h.id)}
                    >
                      {openPreview === h.id ? <EyeOff size={14} /> : <Eye size={14} />} Preview
                    </button>
                    <button
                      className="btn btn-secondary btn-sm"
                      disabled={busyId !== null || !allowRollback || refused}
                      title={rollbackReason}
                      onClick={() => restoreSnapshot(h.id)}
                    >
                      <RotateCcw size={14} /> Rollback
                    </button>
                  </div>
                </div>
                {openPreview === h.id && preview ? <SnapshotPreview preview={preview} /> : null}
                </div>
                );
              })}
            </div>
          )
        ) : conflicts.length === 0 ? (
          <p style={{ color: "var(--ink-muted)" }}>No pending conflicting saves detected.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <p style={{ color: "var(--warning)", fontSize: "0.85rem", marginBottom: "0.5rem" }}>
              <AlertTriangle size={14} style={{ display: "inline", verticalAlign: "middle" }} /> The following uploads were rejected because another client saved changes in the meantime:
            </p>
            {conflicts.map((c) => (
              <div
                key={c.id}
                style={{
                  background: "var(--bg)",
                  border: "1px solid rgba(245, 158, 11, 0.3)",
                  borderRadius: "6px",
                  padding: "0.75rem 1rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: "0.95rem", color: "var(--warning)" }}>
                    Conflict from {c.deviceId || "Unknown Device"}
                  </div>
                  <div style={{ color: "var(--ink-muted)", fontSize: "0.8rem", marginTop: "0.2rem" }}>
                    {new Date(c.timestamp).toLocaleString()} • Target Version: {c.expectedVersion}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                <button className="btn btn-secondary btn-sm" disabled={busyId !== null || !recovery}
                  title={!recovery ? "Unlock the vault to compare entries" : undefined}
                  onClick={() => setComparisonId(c.id)}>Compare & Recover</button>
                <button
                  className="btn btn-danger btn-sm"
                  disabled={busyId !== null || !allowRollback}
                  title={!allowRollback ? "Save or discard your unsaved edits first." : undefined}
                  onClick={() => discardConflict(c.id)}
                >
                  <Trash2 size={14} /> Discard
                </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "1.5rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
    </Dialog>
  );
}

function SnapshotPreview({ preview }: { preview: Preview }) {
  if (preview.kind === "loading") return <p role="status" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>Opening the snapshot in this browser…</p>;
  if (preview.kind === "oldKey") return <p role="alert" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>{OLD_KEY_REASON}</p>;
  if (preview.kind === "error") return <p role="alert" style={{ fontSize: "0.85rem", marginTop: "0.75rem" }}>This snapshot could not be downloaded or opened. Rollback to it is unavailable. Choose Preview again to retry.</p>;
  const { added, removed, changed } = preview.diff;
  const list = (label: string, rows: Array<DiffRow & { fields?: string[] }>) => (
    <div style={{ marginTop: "0.5rem" }}>
      <div style={{ fontWeight: 600, fontSize: "0.85rem" }}>{label} ({rows.length})</div>
      {rows.length ? (
        <ul style={{ margin: "0.25rem 0 0", paddingLeft: "1.25rem", fontSize: "0.85rem", maxHeight: "8rem", overflowY: "auto", overflowWrap: "anywhere" }}>
          {rows.map((r) => <li key={r.uuid}>{r.title || "Untitled"}{r.fields ? `: ${r.fields.join(", ")}` : ""}</li>)}
        </ul>
      ) : <div style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>None</div>}
    </div>
  );
  return (
    <section aria-label="Snapshot preview" style={{ borderTop: "1px solid var(--line)", marginTop: "0.75rem", paddingTop: "0.5rem" }}>
      <p style={{ fontSize: "0.85rem", margin: 0 }}>{countsSentence(preview)} Only titles and field names are shown.</p>
      {list("Entries in the snapshot only", added)}
      {list("Entries now only", removed)}
      {list("Changed", changed)}
    </section>
  );
}
