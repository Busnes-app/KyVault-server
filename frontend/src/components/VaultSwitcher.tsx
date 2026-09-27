import { canOpen, stateLabel, type SharedVaultSummary } from "../lib/sharedVaults";
import type { Selected } from "../lib/vaultSelection";

type Props = {
  selected: Selected;
  vaults: SharedVaultSummary[];
  onSelect: (s: Selected) => void;
  onCreate: () => void;
  onAccept: (row: SharedVaultSummary) => void;
  onDecline: (row: SharedVaultSummary) => void;
  onMembers: () => void;
  canCreate: boolean;
  busy: boolean;
  error?: string;
};

export function VaultSwitcher({ selected, vaults, onSelect, onCreate, onAccept, onDecline, onMembers, canCreate, busy, error }: Props) {
  const invitations = vaults.filter((v) => v.state === "invited");
  const value = selected.kind === "personal" ? "personal" : selected.id;
  // Whose key sealed my copy of the selected vault's key: the server only reports it for
  // my own row, so it belongs here rather than in the members list.
  const sealedBy = selected.kind === "shared" ? vaults.find((v) => v.id === selected.id)?.myKey?.sealedByFingerprint : undefined;
  return (
    <div className="vault-switcher" style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center", padding: "0.5rem 0.75rem", borderBottom: "1px solid var(--line)" }}>
      <select id="vault-switcher" className="select" aria-label="Vault" value={value} disabled={busy}
        title={sealedBy ? `Your copy of this vault key was sealed by key ${sealedBy}` : undefined}
        onChange={(e) => onSelect(e.target.value === "personal" ? { kind: "personal" } : { kind: "shared", id: e.target.value })}>
        <option value="personal">My vault</option>
        {vaults.filter((v) => v.state !== "invited").map((v) => (
          <option key={v.id} value={v.id} disabled={!canOpen(v)}>{v.name}{stateLabel(v) ? ` — ${stateLabel(v)}` : ""}</option>
        ))}
      </select>
      {selected.kind === "shared" ? <button type="button" className="btn btn-quiet btn-sm" onClick={onMembers} disabled={busy}>Members</button> : null}
      <button type="button" className="btn btn-quiet btn-sm" onClick={onCreate} disabled={!canCreate || busy} title={canCreate ? undefined : "Your user key is not ready yet."}>New shared vault…</button>
      {invitations.map((v) => (
        <span key={v.id} className="badge badge-cyan" style={{ display: "inline-flex", gap: "0.25rem", alignItems: "center" }}>
          Invitation: {v.name}
          <button type="button" className="btn btn-quiet btn-sm" onClick={() => onAccept(v)} disabled={busy}>Accept</button>
          <button type="button" className="btn btn-quiet btn-sm" onClick={() => onDecline(v)} disabled={busy}>Decline</button>
        </span>
      ))}
      {error ? <span role="alert" style={{ color: "var(--danger)", fontSize: "0.8rem" }}>{error}</span> : null}
    </div>
  );
}
