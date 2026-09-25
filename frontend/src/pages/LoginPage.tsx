import { ThemeSwitcher } from '../components/ThemeSwitcher';
import React, { useState, useEffect } from "react";
import { getJSON } from "../lib/api";
import { ShieldCheck, Lock, AlertTriangle, Info } from "lucide-react";

// KySignOn is the only way in. There is no local password to type here, because the
// master password is not a credential: it unwraps the vault key in your browser, after a
// KySignOn session already exists. That second step lives in the unlock dialog.

type SsoState = "loading" | "ready" | "disabled" | "unreachable";

const ERRORS: Record<string, string> = {
  not_linked: "Your KySignOn identity is not linked to a KyVault account. Ask your administrator to provision it.",
  deactivated: "This account is deactivated. Ask your administrator to reactivate it.",
  signed_out: "KySignOn signed you out. Sign in again.",
};

export function LoginPage({ notice }: { notice?: string }) {
  const [sso, setSso] = useState<SsoState>("loading");
  const ssoError = ERRORS[new URLSearchParams(window.location.search).get("sso_error") ?? ""];

  const load = () => {
    setSso("loading");
    getJSON<{ enabled: boolean }>("/api/auth/sso-config")
      .then((res) => setSso(res.enabled ? "ready" : "disabled"))
      .catch(() => setSso("unreachable"));
  };

  useEffect(load, []);

  return (
    <div className="auth-container">
      <div className="auth-box">
        <div className="auth-theme"><ThemeSwitcher /></div>
        <div className="auth-header">
          <img src="/logo.png" alt="KyVault" />
          <h1>KyVault</h1>
          <p>Zero-Knowledge KeePass Vault &amp; Sync</p>
        </div>

        {ssoError ? (
          <div
            style={{
              background: "var(--danger-soft)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
              display: "flex",
              gap: "0.6rem",
              alignItems: "flex-start",
            }}
          >
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
            <span>{ssoError}</span>
          </div>
        ) : notice ? (
          <div
            style={{
              background: "var(--panel)",
              border: "1px solid var(--line)",
              color: "var(--ink)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
              display: "flex",
              gap: "0.6rem",
              alignItems: "flex-start",
            }}
          >
            <Info size={18} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
            <span>{notice}</span>
          </div>
        ) : null}

        {sso === "disabled" ? (
          <div
            style={{
              background: "var(--danger-soft)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
              display: "flex",
              gap: "0.6rem",
              alignItems: "flex-start",
            }}
          >
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
            <span>
              KySignOn is unavailable, so sign-in is unavailable. Your passwords are not lost — any
              copy of your vault opens in a standard KeePass client. Ask your administrator to check
              the identity provider.
            </span>
          </div>
        ) : null}

        {sso === "unreachable" ? (
          <div
            style={{
              background: "var(--danger-soft)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              padding: "0.75rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              marginBottom: "1.25rem",
              display: "flex",
              flexDirection: "column",
              gap: "0.6rem",
            }}
          >
            <div style={{ display: "flex", gap: "0.6rem", alignItems: "flex-start" }}>
              <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
              <span>
                KyVault's server could not be reached. Your passwords are not lost; any copy of your
                vault opens in a standard KeePass client.
              </span>
            </div>
            <button type="button" className="btn btn-secondary" onClick={load}>
              Retry
            </button>
          </div>
        ) : null}

        {/* A link with aria-disabled still navigates and still takes focus, so when
            KySignOn is unavailable this becomes a real disabled button instead: the click
            goes nowhere, the control leaves the tab order, and what a screen reader
            announces matches what the control actually does. */}
        {sso === "ready" ? (
          <a
            href="/api/auth/oidc/login"
            className="btn btn-primary"
            style={{ width: "100%", marginBottom: "1.25rem" }}
          >
            <ShieldCheck size={18} /> Sign in with KySignOn
          </a>
        ) : (
          <button
            type="button"
            className="btn btn-primary"
            style={{ width: "100%", marginBottom: "1.25rem" }}
            disabled
          >
            <ShieldCheck size={18} /> {sso === "loading" ? "Checking sign-in…" : "Sign in with KySignOn"}
          </button>
        )}

        <div
          style={{
            borderTop: "1px solid var(--line)",
            paddingTop: "1rem",
            color: "var(--ink-muted)",
            fontSize: "0.8rem",
            display: "flex",
            gap: "0.6rem",
            alignItems: "flex-start",
          }}
        >
          <Lock size={16} style={{ flexShrink: 0, marginTop: "0.1rem" }} />
          <span>
            Signing in proves who you are to KySignOn. Your vault is unlocked separately, with a
            master password this server never receives.
          </span>
        </div>
      </div>
    </div>
  );
}
