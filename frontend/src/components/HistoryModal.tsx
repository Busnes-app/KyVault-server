import { ConflictComparison } from "./ConflictComparison";
import type { KeePassVault } from "../lib/kdbx";
import React, { useState, useEffect } from "react";
import { getJSON, postJSON, deleteJSON, toErrorMessage } from "../lib/api";
import { RotateCcw, AlertTriangle, Trash2, CheckCircle2 } from "lucide-react";
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

type Props = {
  recovery?: { vault: KeePassVault; vaultKey: Uint8Array; onRecovered: (uuid: string) => void };
  allowRollback: boolean;
  onClose: () => void;
  onRestored: () => void;
};

export function HistoryModal({ onClose, onRestored, recovery, allowRollback }: Props) {
  const dialogs = useDialogs();
  const [comparisonId, setComparisonId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"history" | "conflicts">("history");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [conflicts, setConflicts] = useState<ConflictEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

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
    if (!await dialogs.confirm({
      title: "Roll back the vault?",
      message: `Roll back to snapshot ${id}? Current changes will be archived.`,
      confirmLabel: "Roll back",
      danger: true,
    })) return;
    setBusyId(id);
    setMessage("");
    setError("");
    try {
      await postJSON(`/api/vault/history/${id}/restore`, {});
      setMessage("Vault successfully restored.");
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
              {history.map((h) => (
                <div
                  key={h.id}
                  style={{
                    background: "var(--bg)",
                    border: "1px solid var(--line)",
                    borderRadius: "6px",
                    padding: "0.75rem 1rem",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                      Version {h.version || h.id}
                    </div>
                    <div style={{ color: "var(--ink-muted)", fontSize: "0.8rem", marginTop: "0.2rem" }}>
                      {new Date(h.timestamp).toLocaleString()} • {(h.sizeBytes / 1024).toFixed(1)} KB • Checksum:{" "}
                      <code className="font-mono">{h.checksum.slice(0, 8)}</code>
                    </div>
                  </div>
                  <button
                    className="btn btn-secondary btn-sm"
                    disabled={busyId !== null || !allowRollback}
                    onClick={() => restoreSnapshot(h.id)}
                  >
                    <RotateCcw size={14} /> Rollback
                  </button>
                </div>
              ))}
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
