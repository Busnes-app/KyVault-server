import React, { useState, useEffect, FormEvent } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../lib/api";
import { Users, Shield, ScrollText, CheckCircle2, AlertCircle, ShieldCheck, ArchiveRestore } from "lucide-react";
import { AdminBackup } from "../components/AdminBackup";

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

export function AdminPanel({ currentUserId }: { currentUserId: string }) {
  const [activeTab, setActiveTab] = useState<"sso" | "users" | "audit" | "backup">("sso");
  const [usersList, setUsersList] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [provisioning, setProvisioning] = useState<{ configured: boolean; basePath: string } | null>(null);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);

  const [ssoSettings, setSsoSettings] = useState<SSOSettings | null>(null);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadData = async () => {
    const [u, s, a, v, p] = await Promise.allSettled([
      getJSON<User[]>("/api/admin/users"),
      getJSON<SSOSettings>("/api/admin/sso"),
      getJSON<AuditEntry[]>("/api/audit?limit=50"),
      getJSON<{ valid: boolean }>("/api/audit/verify"),
      getJSON<{ configured: boolean; basePath: string }>("/api/admin/provisioning"),
    ]);
    if (u.status === "fulfilled") setUsersList(u.value || []);
    if (s.status === "fulfilled") setSsoSettings(s.value);
    if (a.status === "fulfilled") setAuditLogs(a.value || []);
    if (v.status === "fulfilled") setAuditValid(v.value.valid);
    if (p.status === "fulfilled") setProvisioning(p.value);
    const failed = [u, s, a, v, p].filter((r): r is PromiseRejectedResult => r.status === "rejected");
    if (failed.length) setError(toErrorMessage(failed[0].reason, "Some admin data could not be loaded"));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveSSO = async (e: FormEvent) => {
    e.preventDefault();
    if (!ssoSettings) return;
    setBusy(true);
    setMessage("");
    setError("");

    try {
      await putJSON("/api/admin/sso", { ...ssoSettings, enabled: true });
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
    if (!confirm(`${action === "deactivate" ? "Deactivate" : "Reactivate"} user "${u.username}"?`)) return;

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
          onClick={() => setActiveTab("sso")}
        >
          <Shield size={16} /> Single Sign-On (SSO)
        </button>
        <button
          className={`nav-link-btn ${activeTab === "users" ? "active" : ""}`}
          onClick={() => setActiveTab("users")}
        >
          <Users size={16} /> User Directory ({usersList.length})
        </button>
        <button
          className={`nav-link-btn ${activeTab === "audit" ? "active" : ""}`}
          onClick={() => setActiveTab("audit")}
        >
          <ScrollText size={16} /> Tamper-Evident Audit Log
        </button>
        <button
          className={`nav-link-btn ${activeTab === "backup" ? "active" : ""}`}
          onClick={() => setActiveTab("backup")}
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
            <p>Loading SSO settings…</p>
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
                <input className="input font-mono" readOnly value={new URL(provisioning.basePath, window.location.origin).href} />
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
                <div style={{ display: "flex", gap: "0.5rem" }}>
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
              {auditValid ? (
                <span className="badge badge-green" style={{ display: "flex", alignItems: "center", gap: "0.25rem" }}>
                  <ShieldCheck size={12} /> Chain Verified
                </span>
              ) : (
                <span className="badge" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>
                  <AlertCircle size={12} /> Integrity Warning
                </span>
              )}
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
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                </div>
                <div style={{ color: "var(--ink-strong)", marginBottom: "0.3rem" }}>
                  {log.details || "—"}
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                  IP: {log.ipAddress} • User: {log.userId || "anon"} • Hash: {log.hash.slice(0, 16)}…
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
