import { useEffect, useState } from "react";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";
import { toErrorMessage } from "../lib/api";
import { inviteMember, resealMember, resolveInvitee, REPIN_FIRST, type FlowDeps, type PinStatus } from "../lib/sharedFlows";
import { sharedNameError, type LookupResult, type Member, type Role, type SharedVaultDetail } from "../lib/sharedVaults";
import { ErrorLine } from "./ErrorLine";
import { Users } from "lucide-react";

type Props = {
  vaultId: string;
  myId: string;
  myRole: Role;
  sharedKey: Uint8Array | null;
  deps: FlowDeps;
  onChanged: () => void;
  onLeftOrDeleted: () => void;
  onClose: () => void;
};

const ROLES: Role[] = ["owner", "editor", "reader"];

// What a member row knows about that member's published key. A row without a verdict must
// not show m.keyFingerprint in its place: for a stale row that is the key they no longer hold.
// `mine` is my own row: a pin for yourself is never written, so the pin states do not apply —
// the key this browser holds is the comparison, and only a mismatch is a warning.
export type KeyView = { key: PinStatus; mine?: boolean } | { problem: string };

const sameKey = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

// My own row: the published key either is the one this tab holds or it is a problem worth
// the danger colour. It is never "not verified" — that label has to keep meaning something.
export const selfView = (key: PinStatus, mine: Uint8Array): KeyView =>
  ({ key: { ...key, state: sameKey(key.publicKey, mine) ? "pinned" : "changed" }, mine: true });

const pinLabel = (p: PinStatus, mine?: boolean) =>
  mine ? (p.state === "pinned" ? "Your key" : "Not the key this browser holds")
    : p.state === "pinned" ? "Key pinned" : p.state === "unknown" ? "Key not verified" : "Key changed since you pinned it";
const pinColor = (p: PinStatus) =>
  p.state === "pinned" ? "var(--success)" : p.state === "unknown" ? "var(--warning)" : "var(--danger)";

export function MemberKey({ username, view }: { username: string; view: KeyView | undefined }) {
  if (!view) return <span>Checking…</span>;
  if ("problem" in view) return <span style={{ color: "var(--warning)" }}>{view.problem}</span>;
  return (
    <>
      <code className="font-mono" style={{ overflowWrap: "anywhere" }} aria-label={`${username} key fingerprint`}>{view.key.fingerprint}</code>
      <span style={{ color: pinColor(view.key) }}>{pinLabel(view.key, view.mine)}</span>
    </>
  );
}

export function SharedMembersDialog({ vaultId, myId, myRole, sharedKey, deps, onChanged, onLeftOrDeleted, onClose }: Props) {
  const dialogs = useDialogs();
  const [detail, setDetail] = useState<SharedVaultDetail | null>(null);
  const [keys, setKeys] = useState<Record<string, KeyView>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // The loaded record is authoritative about my own role; the summary row may be a minute old.
  const isOwner = (detail?.members.find((m) => m.userId === myId)?.role ?? myRole) === "owner";

  const [username, setUsername] = useState("");
  const [invitee, setInvitee] = useState<{ user: LookupResult; pin: PinStatus } | null>(null);
  const [role, setRole] = useState<Role>("reader");
  const [inviteError, setInviteError] = useState("");

  const load = async () => {
    const d = await deps.api.get(vaultId);
    setDetail(d);
    // One published-key read per member: the pin verdict is what makes the fingerprint
    // on screen worth anything, so a read that failed says so instead of showing a key.
    const found = await Promise.all(d.members.map(async (m): Promise<[string, KeyView]> => {
      try {
        const l = await deps.lookupKey(deps.pinVault, m.userId);
        if (!l.published) return [m.userId, { problem: "No published key" }];
        const key: PinStatus = { state: l.state, fingerprint: l.published.fingerprint, publicKey: l.published.publicKey };
        // My own row is checked against the key this tab holds, never against a pin.
        if (m.userId === myId) return [m.userId, selfView(key, deps.me.publicKey)];
        return [m.userId, { key }];
      } catch {
        return [m.userId, { problem: "Could not check this key" }];
      }
    }));
    setKeys(Object.fromEntries(found));
  };

  useEffect(() => {
    let live = true;
    void (async () => {
      try { await load(); } catch (err) { if (live) setError(toErrorMessage(err, "Could not load this vault's members.")); }
    })();
    return () => { live = false; };
  }, [vaultId]);

  // Every action is the same shape: run it, tell App, then re-read the server's answer.
  const run = async (what: () => Promise<void>, fallback: string, after?: () => void) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await what();
      onChanged();
      if (after) { after(); return; }
      await load();
    } catch (err) {
      setError(toErrorMessage(err, fallback));
      // A refusal usually means the server moved under us (a role, a key, a membership):
      // re-read so the screen shows what it refused against.
      try { await load(); } catch { /* the first error is the one worth showing */ }
    } finally {
      setBusy(false);
    }
  };

  const rename = async () => {
    const name = await dialogs.prompt({
      title: "Rename shared vault",
      label: "Name",
      defaultValue: detail?.name ?? "",
      validate: sharedNameError,
    });
    if (name === null) return;
    await run(() => deps.api.rename(vaultId, name.trim()), "Could not rename this vault.");
  };

  const remove = async () => {
    if (!(await dialogs.confirm({
      title: `Delete “${detail?.name ?? ""}”?`,
      message: "Every member loses access and the vault's contents are deleted. This cannot be undone.",
      danger: true,
      confirmLabel: "Delete vault",
    }))) return;
    await run(() => deps.api.remove(vaultId), "Could not delete this vault.", onLeftOrDeleted);
  };

  const leave = async () => {
    if (!(await dialogs.confirm({
      title: "Leave this vault?",
      message: "You will lose access to this vault until an owner invites you again.",
      danger: true,
      confirmLabel: "Leave",
    }))) return;
    await run(() => deps.api.removeMember(vaultId, myId), "Could not leave this vault.", onLeftOrDeleted);
  };

  const removeMember = async (m: Member) => {
    if (!(await dialogs.confirm({
      title: `Remove ${m.username}?`,
      message: "They lose access immediately. Their copy of the vault key is only invalidated by rotating it, which is not built yet.",
      danger: true,
      confirmLabel: "Remove",
    }))) return;
    await run(() => deps.api.removeMember(vaultId, m.userId), `Could not remove ${m.username}.`);
  };

  const changeRole = (m: Member, next: Role) => void run(() => deps.api.updateMember(vaultId, m.userId, { role: next }), `Could not change ${m.username}'s role.`);

  // The key sealed is the one whose fingerprint this row is showing, not a fresh lookup.
  const reseal = (m: Member) => void run(async () => {
    if (!sharedKey) throw new Error("Open this vault before re-sealing a member's key.");
    const view = keys[m.userId];
    if (!view || !("key" in view)) throw new Error("This member's key has not been checked yet; reopen this dialog and try again.");
    await resealMember(vaultId, m.userId, view.key, sharedKey, deps);
  }, `Could not re-seal ${m.username}'s key.`);

  const lookup = async () => {
    setInviteError("");
    setInvitee(null);
    if (!username.trim()) return;
    setBusy(true);
    try {
      const found = await resolveInvitee(username.trim(), deps);
      if (!found) setInviteError("No active user with a published key by that name.");
      else setInvitee(found);
    } catch (err) {
      setInviteError(toErrorMessage(err, "Could not look up that user."));
    } finally {
      setBusy(false);
    }
  };

  const invite = async () => {
    if (!invitee || busy) return;
    setInviteError("");
    if (!sharedKey) { setInviteError("Open this vault before inviting members."); return; }
    setBusy(true);
    try {
      await inviteMember(vaultId, invitee, role, sharedKey, deps);
      setInvitee(null);
      setUsername("");
      setRole("reader");
      onChanged();
      await load();
    } catch (err) {
      const text = toErrorMessage(err, "Could not invite that user.");
      // The server refused the fingerprint we sealed to: their key moved under us, so the
      // only safe next step is a fresh lookup the user can compare again.
      if (text.includes("keyFingerprint")) {
        setInviteError("That user's key changed while this form was open. Check the new fingerprint and invite again.");
        try { setInvitee(await resolveInvitee(invitee.user.username, deps)); } catch { setInvitee(null); }
      } else {
        setInviteError(text);
      }
    } finally {
      setBusy(false);
    }
  };

  const changed = invitee?.pin.state === "changed";
  const changedPin = (userId: string) => {
    const v = keys[userId];
    return !!v && "key" in v && v.key.state === "changed";
  };

  return (
    <Dialog title={detail ? `Members of “${detail.name}”` : "Members"} onClose={onClose} size="lg">
      {error ? <ErrorLine text={error} /> : null}
      {!detail ? <p style={{ color: "var(--ink-muted)" }}>Loading…</p> : (
        <>
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "1rem" }}>
            {isOwner ? <button type="button" className="btn btn-secondary btn-sm" onClick={() => void rename()} disabled={busy}>Rename…</button> : null}
            {isOwner ? <button type="button" className="btn btn-danger btn-sm" onClick={() => void remove()} disabled={busy}>Delete vault…</button> : null}
            <button type="button" className="btn btn-quiet btn-sm" onClick={() => void leave()} disabled={busy}>Leave vault…</button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {detail.members.map((m) => (
              <div key={m.userId} style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "6px", padding: "0.75rem 1rem", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                    {m.username}
                    {m.userId === myId ? <span className="badge badge-cyan">You</span> : null}
                    <span className={m.state === "active" ? "badge badge-green" : m.state === "invited" ? "badge badge-cyan" : "badge badge-warning"}>{m.state}</span>
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.2rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    <MemberKey username={m.username} view={keys[m.userId]} />
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                  {isOwner ? (
                    <select className="select" aria-label={`${m.username} role`} value={m.role} disabled={busy || m.userId === myId}
                      title={m.userId === myId ? "Another owner has to change your own role." : undefined}
                      onChange={(e) => changeRole(m, e.target.value as Role)}>
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  ) : <span style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>{m.role}</span>}
                  {isOwner && m.state === "stale" ? (
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => reseal(m)}
                      disabled={busy || !sharedKey || changedPin(m.userId)}
                      title={changedPin(m.userId) ? REPIN_FIRST : !sharedKey ? "Open this vault first." : undefined}>Re-seal key</button>
                  ) : null}
                  {isOwner && m.userId !== myId ? (
                    <button type="button" className="btn btn-danger btn-sm" onClick={() => void removeMember(m)} disabled={busy}>Remove</button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>

          {isOwner ? (
            <section style={{ marginTop: "1.5rem", borderTop: "1px solid var(--line)", paddingTop: "1rem" }}>
              <h4 style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginTop: 0 }}><Users size={16} /> Invite someone</h4>
              <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "flex-end" }}>
                <div className="input-group" style={{ marginBottom: 0 }}>
                  <label className="input-label" htmlFor="shared-invite-username">KyVault username</label>
                  <input id="shared-invite-username" className="input" value={username} autoComplete="off"
                    onChange={(e) => { setUsername(e.target.value); setInvitee(null); setInviteError(""); }} />
                </div>
                <button type="button" className="btn btn-secondary" onClick={() => void lookup()} disabled={busy || !username.trim()}>Look up</button>
              </div>
              {invitee ? (
                <div style={{ marginTop: "0.75rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
                    <strong>{invitee.user.username}</strong>
                    <code className="font-mono" style={{ overflowWrap: "anywhere" }} aria-label="Invitee key fingerprint">{invitee.pin.fingerprint}</code>
                    <span style={{ color: pinColor(invitee.pin) }}>{pinLabel(invitee.pin)}</span>
                  </div>
                  <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", margin: 0 }}>
                    Compare this fingerprint with {invitee.user.username} out of band before you invite them.
                  </p>
                  <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}>
                    <div className="input-group" style={{ marginBottom: 0 }}>
                      <label className="input-label" htmlFor="shared-invite-role">Role</label>
                      <select id="shared-invite-role" className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                        {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </div>
                    <button type="button" className="btn btn-primary" onClick={() => void invite()} disabled={busy || changed || !sharedKey}
                      title={changed ? REPIN_FIRST : !sharedKey ? "Open this vault first." : undefined}>Invite</button>
                  </div>
                  {changed ? <p role="alert" style={{ color: "var(--danger)", margin: 0 }}>{REPIN_FIRST}</p> : null}
                </div>
              ) : null}
              {inviteError ? <ErrorLine text={inviteError} /> : null}
            </section>
          ) : null}
        </>
      )}
    </Dialog>
  );
}
