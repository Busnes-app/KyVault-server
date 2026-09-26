import { useEffect, useState } from "react";
import { getBinary } from "../lib/api";
import { KeePassVault, isWrongVaultKey } from "../lib/kdbx";
import { compareConflictEntries, comparisonFields } from "../lib/conflictComparison";

type LoadState = { kind: "loading" } | { kind: "error"; oldKey: boolean } | { kind: "ready"; vault: KeePassVault };
type Props = {
  conflictId: string;
  current: KeePassVault;
  vaultKey: Uint8Array;
  onRecovered: (uuid: string) => void;
  onBack: () => void;
};

export function ConflictComparison({ conflictId, current, vaultKey, onRecovered, onBack }: Props) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [selectedId, setSelectedId] = useState("");
  const [reveal, setReveal] = useState(false);
  const [recovered, setRecovered] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void (async () => {
      try {
        const bytes = await getBinary(`/api/vault/conflicts/${encodeURIComponent(conflictId)}`, controller.signal);
        if (!active) return;
        const vault = await KeePassVault.open(bytes, vaultKey);
        if (active) {
          setState({ kind: "ready", vault });
          setSelectedId(vault.getLiveEntries()[0]?.uuid ?? "");
        }
      } catch (err) {
        if (active) setState({ kind: "error", oldKey: isWrongVaultKey(err) });
      }
    })();
    return () => { active = false; controller.abort(); };
  }, [conflictId, vaultKey]);

  const rows = state.kind === "ready" ? compareConflictEntries(current.getLiveEntries(), state.vault.getLiveEntries()) : [];
  const selected = rows.find(row => row.entry.uuid === selectedId);
  const recover = () => {
    if (state.kind !== "ready" || !selected || selected.side !== "conflict" || recovered.has(selectedId)) return;
    try {
      const uuid = current.recoverEntryCopy(state.vault, selectedId, { preferOriginalGroup: true });
      const original = current.getEntries().find(entry => entry.uuid === uuid)?.groupUuid === selected.entry.groupUuid;
      setRecovered(previous => new Set(previous).add(selectedId));
      onRecovered(uuid);
      setMessage(`Recovered a copy into ${original ? "its original folder" : "the top-level folder"}. Close this window to check autosave status. The conflict is still preserved.`);
    } catch {
      setMessage("Unable to recover this entry. The preserved conflict has not been deleted.");
    }
  };

  return <section aria-label="Conflict comparison">
    <button className="btn btn-secondary btn-sm" onClick={onBack}>Back to conflicts</button>
    <p>Compare live entries by their KeePass ID with the open vault. Passwords stay in this browser.</p>
    <p style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
      Only the six fields below are compared. Folders, attachments, other fields and history are not compared.
      Recovery copies the complete entry with a new ID into its original folder when that folder still exists, otherwise into the top-level folder. It never replaces a current entry.
    </p>
    {state.kind === "loading" ? <p role="status">Opening encrypted conflict…</p> : null}
    {state.kind === "error" ? <p role="alert">{state.oldKey
      ? "This conflict was saved under a previous vault key. The current key cannot open it. Your vault has not changed."
      : "Could not open this conflict with the current vault key. It may be unavailable or damaged. Your vault has not changed."}</p> : null}
    {state.kind === "ready" && rows.length === 0 ? <p>No live entries in this conflict or your vault.</p> : null}
    <div style={{ maxHeight: "12rem", overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
      {(["conflict", "current"] as const).map(side => {
        const group = rows.filter(row => row.side === side);
        if (!group.length) return null;
        return <div key={side} style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
          <div style={{ fontWeight: 600, fontSize: "0.85rem" }}>{side === "conflict" ? "In the preserved conflict" : "Only in your vault"}</div>
          {group.map(row => <button key={row.entry.uuid} className={`btn ${selectedId === row.entry.uuid ? "btn-primary" : "btn-secondary"}`}
            onClick={() => { setSelectedId(row.entry.uuid); setReveal(false); }}>
            {row.entry.title || "Untitled"}: {side === "current" ? "Not in the conflict" : !row.current ? "Not in live vault" : row.changedFields.length ? "Changed fields" : "Same shown fields"}
            {recovered.has(row.entry.uuid) ? " (copy recovered)" : ""}
          </button>)}
        </div>;
      })}
    </div>
    {selected ? <>
      <label style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}>
        <input type="checkbox" checked={reveal} onChange={event => setReveal(event.target.checked)} /> Reveal passwords and TOTP keys
      </label>
      <table style={{ width: "100%", tableLayout: "fixed", overflowWrap: "anywhere" }}>
        <thead><tr><th scope="col">Field</th><th scope="col">Open vault</th><th scope="col">Preserved conflict</th></tr></thead>
        <tbody>{comparisonFields.map(([key, label]) => <tr key={key}>
          <th scope="row">{label}{selected.changedFields.some(([changed]) => changed === key) ? " (changed)" : ""}</th>
          {[selected.current, selected.side === "conflict" ? selected.entry : undefined].map((entry, index) => <td key={index} style={{ whiteSpace: "pre-wrap", padding: "0.5rem" }}>
            {!entry ? (index === 0 ? "Not in live vault" : "Not in the conflict") : (key === "password" || key === "totpSeed") && !reveal && entry[key] ? "••••••••" : entry[key] || "—"}
          </td>)}
        </tr>)}</tbody>
      </table>
      {selected.side === "conflict"
        ? <button className="btn btn-primary" disabled={recovered.has(selectedId)} onClick={recover}>Recover as copy</button>
        : null}
    </> : null}
    {message ? <p role="status">{message}</p> : null}
  </section>;
}
