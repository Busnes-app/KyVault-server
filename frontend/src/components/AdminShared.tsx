import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { toErrorMessage } from "../lib/api";
import { adminSharedApi, type AdminSharedVault } from "../lib/sharedVaults";
import { formatWhen } from "../lib/format";
import { useDialogs } from "./DialogHost";

type Member = AdminSharedVault["members"][number];

// A fresh-session refusal is the one error with a way out on screen.
function ErrorLine({ text }: { text: string }) {
  return (
    <p role="alert" style={{ color: "var(--danger)" }}>
      {text}
      {text.startsWith("re-authenticate") ? <> <a href="/api/auth/oidc/login?reauth=true">Sign in again</a></> : null}
    </p>
  );
}

const stateBadgeClass = (state: Member["state"]) =>
  state === "active" ? "badge badge-green" : state === "invited" ? "badge badge-cyan" : "badge badge-warning";

function MemberRow({ vault, member, busy, onRemove }: { vault: AdminSharedVault; member: Member; busy: boolean; onRemove: () => void }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", padding: "0.5rem 0", borderTop: "1px solid var(--line)", flexWrap: "wrap" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
        <span>{member.username}</span>
        <span className="badge">{member.role}</span>
        <span className={stateBadgeClass(member.state)}>{member.state}</span>
      </div>
      <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={onRemove}>
        Remove
      </button>
    </div>
  );
}

function VaultRow({ vault, expanded, busy, onToggle, onDelete, onRemoveMember }: {
  vault: AdminSharedVault;
  expanded: boolean;
  busy: boolean;
  onToggle: () => void;
  onDelete: () => void;
  onRemoveMember: (member: Member) => void;
}) {
  return (
    <div style={{ background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px", padding: "0.75rem 1.25rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", flexWrap: "wrap" }}>
        <button type="button" className="btn btn-quiet btn-sm" aria-expanded={expanded} onClick={onToggle}
          style={{ display: "flex", alignItems: "center", gap: "0.4rem", padding: 0 }}>
          {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <span style={{ fontWeight: 600 }}>{vault.name}</span>
          {vault.ownerless ? <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>Ownerless</span> : null}
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", fontSize: "0.85rem", color: "var(--ink-muted)", flexWrap: "wrap" }}>
          <span>Created by {vault.createdBy}</span>
          <span>{formatWhen(vault.createdAt)}</span>
          <span>{vault.members.length} member{vault.members.length === 1 ? "" : "s"}</span>
          <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={onDelete}>
            Delete vault
          </button>
        </div>
      </div>
      {expanded ? (
        <div style={{ marginTop: "0.5rem" }}>
          {vault.members.map((m) => (
            <MemberRow key={m.userId} vault={vault} member={m} busy={busy} onRemove={() => onRemoveMember(m)} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function AdminShared() {
  const dialogs = useDialogs();
  const [vaults, setVaults] = useState<AdminSharedVault[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [listError, setListError] = useState("");
  const [restricted, setRestricted] = useState<boolean | null>(null);
  const [settingsError, setSettingsError] = useState("");
  const [actionError, setActionError] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadList = useCallback(async () => {
    try {
      const list = await adminSharedApi.list();
      setVaults(list);
      setLoaded(true);
      setListError("");
    } catch (err) {
      setListError(toErrorMessage(err, "Could not load shared vaults."));
    }
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const s = await adminSharedApi.settings();
        if (live) setRestricted(s.createRestrictedToAdmins);
      } catch (err) {
        if (live) setSettingsError(toErrorMessage(err, "Could not load shared vault settings."));
      }
    })();
    return () => { live = false; };
  }, []);

  const toggleRestricted = async (checked: boolean) => {
    const prev = restricted;
    setRestricted(checked);
    setSettingsError("");
    try {
      await adminSharedApi.saveSettings({ createRestrictedToAdmins: checked });
    } catch (err) {
      setRestricted(prev);
      setSettingsError(toErrorMessage(err, "Could not save shared vault settings."));
    }
  };

  const deleteVault = async (v: AdminSharedVault) => {
    if (!await dialogs.confirm({
      title: "Delete vault?",
      message: `Delete “${v.name}”? Members lose access. The server keeps it for the retention window; recovery is a host operation.`,
      confirmLabel: "Delete vault",
      danger: true,
    })) return;
    setBusyId(v.id);
    setActionError("");
    try {
      await adminSharedApi.remove(v.id);
      await loadList();
    } catch (err) {
      setActionError(toErrorMessage(err, `Could not delete “${v.name}”.`));
    } finally {
      setBusyId(null);
    }
  };

  const removeMember = async (v: AdminSharedVault, m: Member) => {
    if (!await dialogs.confirm({
      title: "Remove member?",
      message: `Remove ${m.username} from “${v.name}”? They lose access now; their copy of the key is only invalidated by a key rotation.`,
      confirmLabel: "Remove",
      danger: true,
    })) return;
    const key = `${v.id}:${m.userId}`;
    setBusyId(key);
    setActionError("");
    try {
      await adminSharedApi.removeMember(v.id, m.userId);
      await loadList();
    } catch (err) {
      setActionError(toErrorMessage(err, `Could not remove ${m.username}.`));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div>
      <div className="field-card" style={{ marginBottom: "1.5rem" }}>
        <h3 style={{ marginTop: 0 }}>Shared vault settings</h3>
        {settingsError ? <ErrorLine text={settingsError} /> : null}
        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: restricted === null ? "default" : "pointer", fontSize: "0.9rem" }}>
          <input
            type="checkbox"
            checked={restricted ?? false}
            disabled={restricted === null}
            onChange={(e) => void toggleRestricted(e.target.checked)}
          />
          Only admins may create shared vaults
        </label>
      </div>

      {listError ? <ErrorLine text={listError} /> : null}
      {actionError ? <ErrorLine text={actionError} /> : null}

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {vaults.map((v) => (
          <VaultRow
            key={v.id}
            vault={v}
            expanded={!!expanded[v.id]}
            busy={busyId === v.id || busyId?.startsWith(`${v.id}:`) === true}
            onToggle={() => setExpanded((prev) => ({ ...prev, [v.id]: !prev[v.id] }))}
            onDelete={() => void deleteVault(v)}
            onRemoveMember={(m) => void removeMember(v, m)}
          />
        ))}
      </div>
      {loaded && vaults.length === 0 ? <p style={{ color: "var(--ink-muted)" }}>No shared vaults yet.</p> : null}
    </div>
  );
}
