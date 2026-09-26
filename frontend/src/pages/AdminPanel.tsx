import React, { useState, useEffect, FormEvent } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../lib/api";
import { Users, Shield, ScrollText, CheckCircle2, AlertCircle, ShieldCheck, ArchiveRestore, Copy, Check } from "lucide-react";
import { AdminBackup } from "../components/AdminBackup";
import { formatWhen } from "../lib/format";
import { useDialogs } from "../components/DialogHost";
import { copyText } from "../lib/clipboard";
import type { Route } from "../lib/route";

type User = {
  id: string;
  username: string;
  role: "admin" | "user";
  active: boolean;
  ssoSub?: string;
};

type SSOSettings = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  autoProvision: boolean;
  clientSecretSet?: boolean;
};

type AuditEntry = {
  index: number;
  timestamp: string;
  action: string;
  userId: string;
  deviceId: string;
  ipAddress: string;
  details: string;
  hash: string;
};

type AuditVerify = { valid: boolean; writeFailures: number; error: string };

export function AdminPanel({ currentUserId, route, navigate }: { currentUserId: string; route: Route; navigate: (next: Route) => void }) {
  const dialogs = useDialogs();
  const activeTab = route.admin ?? "sso";
  const [usersList, setUsersList] = useState<User[]>([]);
  const [usersLoaded, setUsersLoaded] = useState(false);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [auditDone, setAuditDone] = useState(false);
  const [provisioning, setProvisioning] = useState<{ configured: boolean; basePath: string } | null>(null);
  const [auditVerify, setAuditVerify] = useState<AuditVerify | "loading" | "unavailable">("loading");

  const [ssoSettings, setSsoSettings] = useState<SSOSettings | null>(null);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [roleError, setRoleError] = useState("");
  const [scimCopied, setScimCopied] = useState(false);
  const [redirectCopied, setRedirectCopied] = useState(false);

  const loadData = async () => {
    const [u, s, a, p] = await Promise.allSettled([
      getJSON<User[]>("/api/admin/users"),
      getJSON<SSOSettings>("/api/admin/sso"),
      getJSON<AuditEntry[]>("/api/audit?limit=50"),
      getJSON<{ configured: boolean; basePath: string }>("/api/admin/provisioning"),
    ]);
    if (u.status === "fulfilled") { setUsersList(u.value || []); setUsersLoaded(true); }
    if (s.status === "fulfilled") setSsoSettings(s.value);
    if (a.status === "fulfilled") { setAuditLogs(a.value || []); setAuditDone((a.value || []).length < 50); }
    if (p.status === "fulfilled") setProvisioning(p.value);
    const failed = [u, s, a, p].filter((r): r is PromiseRejectedResult => r.status === "rejected");
    if (failed.length) setError(toErrorMessage(failed[0].reason, "Some admin data could not be loaded"));
  };

  useEffect(() => {
    loadData();
  }, []);

  // Verification is a full chain walk; only pay for it while the tab is open.
  useEffect(() => {
    if (activeTab !== "audit") return;
    let cancelled = false;
    setAuditVerify("loading");
    getJSON<AuditVerify>("/api/audit/verify")
      .then((v) => { if (!cancelled) setAuditVerify(v); })
      .catch(() => { if (!cancelled) setAuditVerify("unavailable"); });
    return () => { cancelled = true; };
  }, [activeTab]);

  const loadOlderAudit = async () => {
    const last = auditLogs[auditLogs.length - 1];
    if (!last) return;
    try {
      const older = await getJSON<AuditEntry[]>(`/api/audit?limit=50&before=${last.index}`);
      setAuditLogs((prev) => [...prev, ...older]);
      if (older.length < 50) setAuditDone(true);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load older audit entries"));
    }
  };

  const handleRoleChange = async (u: User, role: "admin" | "user") => {
    if (role === u.role) return;
    if (!await dialogs.confirm({
      title: "Change role?",
      message: `Make ${u.username} ${role === "admin" ? "an admin" : "a user"}?`,
      confirmLabel: "Change",
    })) return;

    setRoleError("");
    try {
      await putJSON(`/api/admin/users/${u.id}/role`, { role });
      setUsersList((prev) => prev.map((item) => (item.id === u.id ? { ...item, role } : item)));
    } catch (err) {
      setRoleError(toErrorMessage(err, "Failed to change role"));
    }
  };

  const handleSaveSSO = async (e: FormEvent) => {
    e.preventDefault();
    if (!ssoSettings) return;
    setBusy(true);
    setMessage("");
    setError("");

    try {
      await putJSON("/api/admin/sso", { ...ssoSettings, enabled: true });
      setSsoSettings({ ...ssoSettings, clientSecret: "", clientSecretSet: true });
      setMessage("SSO settings saved.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to save SSO settings"));
    } finally {
      setBusy(false);
    }
  };

  const applyKySignOnPreset = () => {
    setSsoSettings((prev) => ({
      ...(prev ?? { enabled: true, issuerUrl: "", clientId: "", autoProvision: true }),
      enabled: true,
      issuerUrl: "https://auth.urlxl.com",
      clientId: "kyvaults",
      autoProvision: true,
    }));
  };

  const handleToggleDeactivate = async (u: User) => {
    const action = u.active ? "deactivate" : "reactivate";
    if (!await dialogs.confirm({
      title: action === "deactivate" ? "Deactivate user?" : "Reactivate user?",
      message: `${action === "deactivate" ? "Deactivate" : "Reactivate"} user "${u.username}"?`,
      confirmLabel: action === "deactivate" ? "Deactivate" : "Reactivate",
      danger: action === "deactivate",
    })) return;

    try {
      await postJSON(`/api/admin/users/${u.id}/${action}`, {});
      setUsersList((prev) =>
        prev.map((item) => (item.id === u.id ? { ...item, active: !u.active } : item))
      );
      setMessage(`User ${action}d.`);
    } catch (err) {
      setError(toErrorMessage(err, `Failed to ${action} user`));
    }
  };

  return (
    <div className="settings-page" style={{ maxWidth: "1000px" }}>
      <div style={{ marginBottom: "2rem" }}>
        <h2>System Administration</h2>
        <p style={{ color: "var(--ink-muted)" }}>
          Manage instance settings, Single Sign-On, user accounts, and audit trails.
        </p>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", borderBottom: "1px solid var(--line)", marginBottom: "2rem" }}>
        <button
          className={`nav-link-btn ${activeTab === "sso" ? "active" : ""}`}
          onClick={() => navigate({ tab: "admin", admin: "sso" })}
        >
          <Shield size={16} /> Single Sign-On (SSO)
        </button>
        <button
          className={`nav-link-btn ${activeTab === "users" ? "active" : ""}`}
          onClick={() => navigate({ tab: "admin", admin: "users" })}
        >
          <Users size={16} /> User Directory{usersLoaded ? ` (${usersList.length})` : ""}
        </button>
        <button
          className={`nav-link-btn ${activeTab === "audit" ? "active" : ""}`}
          onClick={() => navigate({ tab: "admin", admin: "audit" })}
        >
          <ScrollText size={16} /> Tamper-Evident Audit Log
        </button>
        <button
          className={`nav-link-btn ${activeTab === "backup" ? "active" : ""}`}
          onClick={() => navigate({ tab: "admin", admin: "backup" })}
        >
          <ArchiveRestore size={16} /> Backup &amp; Recovery
        </button>
      </div>

      {message ? (
        <div
          style={{
            background: "var(--success-soft)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            color: "var(--success)",
            padding: "0.75rem 1rem",
            borderRadius: "6px",
            marginBottom: "1.5rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <CheckCircle2 size={16} /> {message}
        </div>
      ) : null}

      {error ? (
        <div
          style={{
            background: "var(--danger-soft)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            color: "var(--danger)",
            padding: "0.75rem 1rem",
            borderRadius: "6px",
            marginBottom: "1.5rem",
          }}
        >
          {error}
        </div>
      ) : null}

      {activeTab === "sso" ? (
        <div className="field-card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
            <div>
              <h3 style={{ margin: "0 0 0.25rem 0" }}>OIDC Provider Configuration</h3>
              <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", margin: 0 }}>
                Configure KySignOn, Authentik, Keycloak, or any OpenID Connect IdP.
              </p>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={applyKySignOnPreset}>
              + KySignOn Preset
            </button>
          </div>

          <label className="input-group">
            <span className="input-label">Redirect URI to register with KySignOn</span>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <input className="input font-mono" readOnly value={`${window.location.origin}/api/auth/oidc/callback`} />
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={async () => {
                  if (await copyText(`${window.location.origin}/api/auth/oidc/callback`)) {
                    setRedirectCopied(true);
                    setTimeout(() => setRedirectCopied(false), 2000);
                  }
                }}
              >
                {redirectCopied ? <Check size={14} color="#10b981" /> : <Copy size={14} />} Copy
              </button>
            </div>
          </label>

          {ssoSettings ? (
            <form onSubmit={handleSaveSSO}>
              <div className="input-group">
                <label className="input-label">Issuer URL</label>
                <input
                  type="url"
                  className="input font-mono"
                  placeholder="https://auth.urlxl.com"
                  value={ssoSettings.issuerUrl}
                  onChange={(e) => setSsoSettings({ ...ssoSettings, issuerUrl: e.target.value })}
                  required
                />
                <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)", marginTop: "0.25rem", display: "block" }}>
                  Must support standard <code>.well-known/openid-configuration</code> auto-discovery.
                </span>
              </div>

              <div className="input-group">
                <label className="input-label">Client ID</label>
                <input
                  type="text"
                  className="input font-mono"
                  placeholder="kyvaults"
                  value={ssoSettings.clientId}
                  onChange={(e) => setSsoSettings({ ...ssoSettings, clientId: e.target.value })}
                  required
                />
              </div>

              <div className="input-group">
                <label className="input-label">Client Secret</label>
                <input
                  type="password"
                  className="input font-mono"
                  autoComplete="off"
                  placeholder={ssoSettings.clientSecretSet ? "Unchanged. Type a new value to replace it." : "Required unless the client uses PKCE only"}
                  value={ssoSettings.clientSecret || ""}
                  onChange={(e) => setSsoSettings({ ...ssoSettings, clientSecret: e.target.value })}
                />
              </div>

              <div className="input-group">
                <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.9rem" }}>
                  <input
                    type="checkbox"
                    checked={ssoSettings.autoProvision}
                    onChange={(e) => setSsoSettings({ ...ssoSettings, autoProvision: e.target.checked })}
                  />
                  Auto-provision new accounts upon successful SSO authentication
                </label>
              </div>

              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? "Saving…" : "Save SSO Settings"}
              </button>
            </form>
          ) : (
            <p>{error ? "SSO settings could not be loaded." : "Loading SSO settings…"}</p>
          )}
        </div>
      ) : activeTab === "users" ? (
        <div>
          <section className="field-card" style={{ marginBottom: "1.5rem" }}>
            <h3>SCIM Provisioning</h3>
            <p>{provisioning?.configured ? "Enabled — provisioning token configured." : "Disabled — set KYVAULT_SCIM_TOKEN and restart to enable."}</p>
            {provisioning ? (
              <label className="input-group">
                <span className="input-label">SCIM base URL</span>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <input className="input font-mono" readOnly value={new URL(provisioning.basePath, window.location.origin).href} />
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={async () => {
                      if (await copyText(new URL(provisioning.basePath, window.location.origin).href)) {
                        setScimCopied(true);
                        setTimeout(() => setScimCopied(false), 2000);
                      }
                    }}
                  >
                    {scimCopied ? <Check size={14} color="#10b981" /> : <Copy size={14} />} Copy
                  </button>
                </div>
              </label>
            ) : null}
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>
              Configure your provisioning client with this URL and the dedicated bearer token.
              Map externalId to the KySignOn user ID (OIDC subject). Sign-in still uses KySignOn.
              Deleting a directory user retains their encrypted vault.
            </p>
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>
              Existing signed KySignOn replication continues at /api/sync/webhook using the kyvault system type.
            </p>
          </section>
          <div style={{ marginBottom: "1.5rem" }}>
            <h3 style={{ margin: 0 }}>Registered User Accounts</h3>
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginTop: "0.4rem", marginBottom: 0 }}>
              Accounts are managed in KySignOn. They appear here when KySignOn replicates them or
              when someone signs in for the first time. Role, deactivate and reactivate below are
              local overrides.
            </p>
          </div>

          {roleError ? (
            <div role="alert" className="field-card" style={{ color: "var(--danger)", marginBottom: "1rem" }}>
              {roleError}
            </div>
          ) : null}

          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {usersList.map((u) => (
              <div
                key={u.id}
                style={{
                  background: "var(--panel)",
                  border: "1px solid var(--line)",
                  borderRadius: "6px",
                  padding: "0.75rem 1.25rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span style={{ fontWeight: 600 }}>{u.username}</span>
                    <span className={`badge ${u.role === "admin" ? "badge-cyan" : "badge-green"}`}>
                      {u.role}
                    </span>
                    {!u.active ? <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>Disabled</span> : null}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
                    ID: <code>{u.id}</code> {u.ssoSub ? `• Linked SSO: ${u.ssoSub}` : ""}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <select
                    className="input font-mono"
                    value={u.role}
                    disabled={u.id === currentUserId}
                    title={u.id === currentUserId ? "You cannot change your own role" : undefined}
                    onChange={(e) => void handleRoleChange(u, e.target.value as "admin" | "user")}
                  >
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleToggleDeactivate(u)}
                    disabled={u.id === currentUserId}
                    title={u.id === currentUserId ? "You cannot deactivate your own account" : undefined}
                  >
                    {u.active ? "Deactivate" : "Reactivate"}
                  </button>
                </div>
              </div>
            ))}
          </div>

        </div>
      ) : activeTab === "backup" ? (
        <AdminBackup />
      ) : (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
              <h3 style={{ margin: 0 }}>Cryptographic Audit Chain</h3>
              {auditVerify === "loading" ? <span className="badge">Checking chain…</span>
               : auditVerify === "unavailable" ? <span className="badge">Could not verify</span>
               : auditVerify.valid && auditVerify.writeFailures === 0 ? <span className="badge badge-green" style={{ display: "flex", alignItems: "center", gap: "0.25rem" }}><ShieldCheck size={12} /> Chain Verified</span>
               : <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }} title={auditVerify.error || undefined}><AlertCircle size={12} /> {auditVerify.valid ? `${auditVerify.writeFailures} audit writes failed` : "Integrity Warning"}</span>}
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {auditLogs.map((log) => (
              <div
                key={log.index}
                style={{
                  background: "var(--bg)",
                  border: "1px solid var(--line)",
                  borderRadius: "6px",
                  padding: "0.75rem 1rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.85rem",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.3rem" }}>
                  <strong style={{ color: "var(--accent)" }}>{log.action}</strong>
                  <span style={{ color: "var(--ink-muted)", fontSize: "0.75rem" }}>
                    {formatWhen(log.timestamp)}
                  </span>
                </div>
                <div style={{ color: "var(--ink-strong)", marginBottom: "0.3rem" }}>
                  {log.details || "—"}
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                  IP: {log.ipAddress} • User: {log.userId || "anon"} • Hash: {(log.hash ?? "").slice(0, 16)}…
                </div>
              </div>
            ))}
          </div>
          {!auditDone && auditLogs.length ? (
            <button className="btn btn-secondary btn-sm" style={{ marginTop: "1rem" }} onClick={() => void loadOlderAudit()}>
              Load older
            </button>
          ) : null}
        </div>
      )}
    </div>
  );
}
