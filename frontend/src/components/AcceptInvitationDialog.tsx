import { useEffect, useState } from "react";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";
import { toErrorMessage } from "../lib/api";
import { acceptInvitation, inviterStatus, type FlowDeps, type PinStatus } from "../lib/sharedFlows";
import type { SharedVaultSummary } from "../lib/sharedVaults";

type Props = { row: SharedVaultSummary; deps: FlowDeps; onDone: (accepted: boolean) => void };

// Joining a shared vault is the moment the user decides whose key to trust, so the
// inviter's fingerprint is on screen before Accept is reachable.
export function AcceptInvitationDialog({ row, deps, onDone }: Props) {
  const dialogs = useDialogs();
  const [status, setStatus] = useState<PinStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const who = row.invitedBy?.username ?? "them";

  useEffect(() => {
    let live = true;
    inviterStatus(row, deps).then(
      (s) => { if (live) setStatus(s); },
      (err) => { if (live) setError(toErrorMessage(err, "Could not check the inviter's key.")); },
    );
    return () => { live = false; };
  }, [row.id]);

  const accept = async () => {
    if (!status || busy) return;
    setError("");
    let repinConfirmed = false;
    if (status.state === "changed") {
      repinConfirmed = await dialogs.confirm({
        title: "Re-pin this key?",
        message: "You are about to trust a new key for this user. Only do this after verifying the fingerprint with them.",
        danger: true,
        confirmLabel: "Re-pin and accept",
      });
      if (!repinConfirmed) return;
    }
    setBusy(true);
    try {
      await acceptInvitation(row, status, deps, { repinConfirmed });
      onDone(true);
    } catch (err) {
      setError(toErrorMessage(err, "Could not accept the invitation."));
      setBusy(false);
    }
  };

  const decline = async () => {
    if (busy) return;
    setError("");
    setBusy(true);
    try {
      await deps.api.decline(row.id);
      onDone(false);
    } catch (err) {
      setError(toErrorMessage(err, "Could not decline the invitation."));
      setBusy(false);
    }
  };

  return (
    <Dialog title={`Join “${row.name}”?`} onClose={() => onDone(false)}>
      <p>Invited by <strong>{who}</strong> as <strong>{row.role}</strong>.</p>
      <p style={{ marginBottom: "0.25rem" }}>Their key fingerprint:</p>
      <code className="font-mono" style={{ fontSize: "1.05rem", overflowWrap: "anywhere" }} aria-label="Inviter key fingerprint">{status ? status.fingerprint || "—" : "Checking…"}</code>
      {status?.state === "pinned" ? <p style={{ color: "var(--success)" }}>Matches the key you pinned.</p> : null}
      {status?.state === "unknown" ? (
        <p role="alert" style={{ color: "var(--warning)" }}>Not verified. Verify with {who} before you rely on this vault.</p>
      ) : null}
      {status?.state === "changed" ? (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {status.drift === "invitation"
            ? `Their key changed since this invitation was sent. Verify with ${who} before you rely on this vault.`
            : `Their key changed since you pinned it. Verify with ${who} before you rely on this vault.`}
        </p>
      ) : null}
      <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>KyVault trusts the server for who is in a vault, never for its contents.</p>
      {error ? (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {error}
          {error.startsWith("re-authenticate") ? <> <a href="/api/auth/oidc/login?reauth=true">Sign in again</a></> : null}
        </p>
      ) : null}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1rem" }}>
        <button type="button" className="btn btn-secondary" onClick={() => void decline()} disabled={busy}>Decline</button>
        <button type="button" className="btn btn-primary" onClick={() => void accept()} disabled={busy || !status}>Accept</button>
      </div>
    </Dialog>
  );
}
