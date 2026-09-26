import React, { useState, useEffect, useRef, useCallback, FormEvent } from "react";
import { getJSON, putJSON, patchJSON, deleteJSON, toErrorMessage, HttpError } from "../lib/api";
import { wrapVaultKey, bytesToHex, verifyMasterPassword } from "../lib/vaultCrypto";
import { checkMasterPassword, MIN_MASTER_PASSWORD_LENGTH } from "../lib/masterPassword";
import { KeyRound, Shield, FileText, Smartphone, Trash2, CheckCircle2, QrCode, Download, RefreshCw } from "lucide-react";
import { DevicePairingModal } from "../components/DevicePairingModal";
import { useDialogs } from "../components/DialogHost";

import { AUTO_LOCK_MINUTES, parseAutoLockMinutes, type AutoLockMinutes } from "../lib/autoLock";
import { formatWhen } from "../lib/format";
import { copyText, SECRET_CLIPBOARD_MS } from "../lib/clipboard";
import { groupHex, useHideAfter } from "../lib/secretDisplay";
import { generatePaperCode } from "../lib/paperCode";
import { revokeDevices } from "../lib/keyRotation";

// Type-it-back comparison ignores formatting, not case or characters.
function normalizeCode(value: string): string {
  return value.toUpperCase().replace(/[-\s]/g, "");
}

type Device = {
  id: string;
  name: string;
  platform: string;
  lastSeenAt: string;
  lastIp: string;
  current?: boolean;
};

type Props = {
  user: any;
  vaultKey: Uint8Array;
  onUserUpdated: () => void;
  autoLockMinutes: AutoLockMinutes;
  onAutoLockChange: (minutes: AutoLockMinutes) => void;
  onForgetDevice?: () => void;
  canRotate: boolean;
  onExport: () => Promise<void>;
  onRotateKey: (password: string, paperCode: string) => Promise<void>;
};

export function SecuritySettings({ user, vaultKey, onUserUpdated, onForgetDevice, autoLockMinutes, onAutoLockChange, canRotate, onExport, onRotateKey }: Props) {
  const dialogs = useDialogs();
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [devices, setDevices] = useState<Device[]>([]);
  const [paperCode, setPaperCode] = useState<string | null>(null);
  const [ssoConfig, setSsoConfig] = useState<{ enabled: boolean; issuerUrl: string } | null>(null);
  const [showPairing, setShowPairing] = useState(false);
  const [showVaultKey, setShowVaultKey] = useState(false);
  const [vaultKeyCopied, setVaultKeyCopied] = useState(false);
  const [paperCodeCopied, setPaperCodeCopied] = useState(false);
  const [paperConfirmInput, setPaperConfirmInput] = useState("");
  const [paperConfirmed, setPaperConfirmed] = useState(false);
  const [printTarget, setPrintTarget] = useState<"key" | "paper" | null>(null);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [unrevoked, setUnrevoked] = useState<Device[]>([]);

  const hideVaultKey = useCallback(() => setShowVaultKey(false), []);
  const hidePaperCode = useCallback(() => setPaperCode(null), []);
  useHideAfter(60_000, showVaultKey, hideVaultKey);
  useHideAfter(120_000, paperCode !== null, hidePaperCode);

  // Only one secret block should carry the print-only class at a time; render with the
  // class applied first, then print, so a single block never depends on stacking order.
  useEffect(() => {
    if (!printTarget) return;
    const done = () => setPrintTarget(null);
    window.addEventListener("afterprint", done, { once: true });
    window.print();
    return () => window.removeEventListener("afterprint", done);
  }, [printTarget]);

  // A lock cancels pending dialogs (App.tsx closeVault), but these handlers hold the
  // vault key in closure across awaits; a stale resume must not act on an unmounted page.
  const alive = useRef(true);
  useEffect(() => {
    // StrictMode mounts, cleans up, and mounts again on the same instance; re-arm on
    // every mount so the replay does not leave the guard permanently tripped.
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const loadDevices = async () => {
    try {
      const list = await getJSON<Device[]>("/api/devices");
      setDevices(list || []);
    } catch (err) {
      setError(toErrorMessage(err, "Could not load paired devices."));
    }
  };

  useEffect(() => {
    loadDevices();
    getJSON<{ enabled: boolean; issuerUrl: string }>("/api/auth/sso-config")
      .then((cfg) => setSsoConfig(cfg))
      .catch(() => {});
  }, []);

  // Every action below either changes what protects the vault key or shows it.
  // Prove the current master password first; it never leaves the browser.
  const proveCurrentPassword = async (): Promise<boolean> => {
    const meta = await getJSON<{ passwordEnvelope?: string; recoveryEnvelope?: string }>("/api/vault/metadata");
    if (!meta.passwordEnvelope && !meta.recoveryEnvelope) {
      setError("No master password or paper code envelope is stored for this vault.");
      return false;
    }
    if (meta.passwordEnvelope && (await verifyMasterPassword(meta.passwordEnvelope, currentPassword, vaultKey))) {
      return true;
    }
    if (meta.recoveryEnvelope && (await verifyMasterPassword(meta.recoveryEnvelope, currentPassword, vaultKey))) {
      return true;
    }
    setError("The current master password or paper code is incorrect.");
    return false;
  };

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    const problem = checkMasterPassword(newPassword);
    if (problem) { setError(problem); return; }
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match");
      return;
    }
    setBusy(true);
    setMessage("");
    setError("");

    try {
      if (!(await proveCurrentPassword())) return;
      if (!alive.current) return;

      // Changing the master password is entirely a re-wrap of the vault key envelope.
      // There is no password on the server to update: it never had one, and the new
      // password is not sent anywhere — only the envelope it encrypts is.
      const newEnvelope = await wrapVaultKey(vaultKey, newPassword);
      if (!alive.current) return;

      await putJSON("/api/vault/envelopes", {
        passwordEnvelope: newEnvelope,
      });
      if (!alive.current) return;

      setMessage("Master password changed and vault key re-wrapped.");
      setNewPassword("");
      setConfirmPassword("");
      setCurrentPassword("");
      onUserUpdated();
    } catch (err) {
      setError(toErrorMessage(err, "Failed to change password"));
    } finally {
      setBusy(false);
    }
  };

  const handleGeneratePaperRecovery = async () => {
    if (!await dialogs.confirm({
      title: "Generate a new paper code?",
      message: "Generating a new paper recovery code will invalidate any previous paper backup. Proceed?",
      confirmLabel: "Generate",
    })) return;
    if (!alive.current) return;
    setBusy(true);
    setMessage("");
    setError("");

    try {
      if (!(await proveCurrentPassword())) return;
      if (!alive.current) return;

      // Clear any shown code first (and its confirmation) so the hide timer re-arms even
      // when regenerating while a code is already visible: the awaits below give React a
      // render in between, so `paperCode !== null` genuinely flips false, then true again.
      setPaperCode(null);
      setPaperConfirmInput("");
      setPaperConfirmed(false);
      setPaperCodeCopied(false);

      const code = generatePaperCode();

      // The recovery code wraps the vault key and nothing else. It used to also be hashed
      // onto the user record so it could start a session; that made it a second way to
      // authenticate, which SSO-only does not allow. It unlocks the vault, not the site.
      const recoveryEnv = await wrapVaultKey(vaultKey, code);
      if (!alive.current) return;

      await putJSON("/api/vault/envelopes", {
        recoveryEnvelope: recoveryEnv,
      });
      if (!alive.current) return;

      setPaperCode(code);
      setMessage("Paper recovery backup generated. Print or write this down.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to generate paper recovery code"));
    } finally {
      setBusy(false);
    }
  };

  // The vault key in the form KeePassXC will accept. A downloaded .kdbx is encrypted with
  // exactly this string, so without it the "open your vault in any KeePass client" fallback
  // is not actually available to anyone.
  const handleRevealVaultKey = async () => {
    if (showVaultKey) {
      setShowVaultKey(false);
      return;
    }
    if (!await dialogs.confirm({
      title: "Show the vault key?",
      message: "Your vault key unlocks everything, on any device, forever. Unlike your master " +
      "password, it cannot be changed without re-encrypting the vault. Only reveal it if you " +
      "are printing it for offline recovery, and nobody can see your screen.",
      confirmLabel: "Show",
    })) return;
    if (!alive.current) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      if (!(await proveCurrentPassword())) return;
      if (!alive.current) return;
      setVaultKeyCopied(false);
      setShowVaultKey(true);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to verify the current master password"));
    } finally {
      setBusy(false);
    }
  };

  // Devices hold the retired key, which opens nothing current, so a failure here is a
  // cleanup gap rather than a security gap. Runs even if the page unmounted meanwhile.
  const revokeAll = async (list: Device[]) => {
    const failed = await revokeDevices(list.map((d) => d.id), (id) => deleteJSON(`/api/devices/${id}`));
    const left = list.filter((d) => failed.includes(d.id));
    if (!alive.current) return;
    setUnrevoked(left);
    setDevices((prev) => prev.filter((d) => !list.some((x) => x.id === d.id) || failed.includes(d.id)));
  };

  const handleRotateKey = async () => {
    if (!canRotate) return;
    if (!await dialogs.confirm({
      title: "Rotate the vault key?",
      message: "All paired devices and extensions will be signed out and need pairing again. " +
        "Snapshots and preserved conflicts from before now cannot be opened with the new key, so download the vault first if you may need them. " +
        "The download opens only with the offline vault key shown below; reveal and save it first. " +
        "Your master password does not change. A new paper recovery code will be shown once; the old one stops working.",
      confirmLabel: "Rotate",
      danger: true,
    })) return;
    if (!alive.current) return;
    setBusy(true);
    setMessage("");
    setError("");
    setUnrevoked([]);
    try {
      if (!(await proveCurrentPassword())) return;
      if (!alive.current) return;
      setPaperCode(null);
      setPaperConfirmInput("");
      setPaperConfirmed(false);
      setPaperCodeCopied(false);
      setShowVaultKey(false);
      const code = generatePaperCode();
      await onRotateKey(currentPassword, code);
      // The server now holds the new key. Revoke before touching page state: a lock
      // mid-rotation unmounts this page but the devices still need signing out.
      const list = await getJSON<Device[]>("/api/devices").catch(() => devices);
      const revoked = revokeAll(list || []);
      if (alive.current) {
        setCurrentPassword("");
        setPaperCode(code);
        setMessage("Vault key rotated. Save the new paper code shown under Paper Recovery Code; the old one no longer works.");
      }
      await revoked;
    } catch (err) {
      if (!alive.current) return;
      setError(err instanceof HttpError && err.status === 409
        ? "Another device saved the vault first, so nothing changed. Reload the vault and try again."
        : `Could not rotate the vault key, so nothing changed on the server. ${toErrorMessage(err, "")}`.trim());
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const handleRevokeDevice = async (id: string, name: string) => {
    if (revoking) return;
    if (!await dialogs.confirm({
      title: "Revoke device?",
      message: `Revoke access for device "${name}"?`,
      confirmLabel: "Revoke",
      danger: true,
    })) return;
    setRevoking(id);
    setError("");
    setMessage("");
    try {
      await deleteJSON(`/api/devices/${id}`);
      setDevices((prev) => prev.filter((d) => d.id !== id));
      setMessage(`Device "${name}" revoked.`);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to revoke device"));
    } finally {
      setRevoking(null);
    }
  };

  const handleRenameDevice = async (device: Device) => {
    const name = await dialogs.prompt({
      title: "Rename device",
      label: "Name",
      defaultValue: device.name,
      validate: (v) => (v.trim() ? (v.trim().length > 64 ? "Use at most 64 characters." : null) : "Enter a name."),
    });
    if (name === null) return;
    setError("");
    setMessage("");
    try {
      const updated = await patchJSON<Device>(`/api/devices/${device.id}`, { name: name.trim() });
      setDevices((prev) => prev.map((d) => (d.id === device.id ? updated : d)));
    } catch (err) {
      setError(toErrorMessage(err, "Failed to rename device"));
    }
  };

  const handleRevokeAllOthers = async () => {
    if (revoking) return;
    if (!await dialogs.confirm({
      title: "Revoke every other device?",
      message: "Each paired app and extension except this one is signed out and must pair again. Your vault data is not changed.",
      confirmLabel: "Revoke all",
      danger: true,
    })) return;
    const others = devices.filter((d) => !d.current);
    setError("");
    setMessage("");
    try {
      const failed = await revokeDevices(others.map((d) => d.id), (id) => deleteJSON(`/api/devices/${id}`));
      setDevices((prev) => prev.filter((d) => d.current || failed.includes(d.id)));
      setMessage(failed.length ? "Some devices could not be signed out. Try again." : "Every other device has been signed out.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to revoke other devices"));
    }
  };

  return (
    <div className="settings-page" style={{ maxWidth: "800px" }}>
      <div style={{ marginBottom: "2rem" }}>
        <h2>Security & Key Management</h2>
      <section className="card" style={{ marginTop: "1.5rem", marginBottom: "1.5rem", padding: "1.5rem" }}>
        <h3>Automatic vault lock</h3>
        <p>Lock after inactivity, including time while this tab or computer is asleep. Unsaved vault edits are kept in an encrypted local recovery copy.</p>
        <label className="input-label" htmlFor="auto-lock">Lock after</label>
        <select id="auto-lock" className="input" value={autoLockMinutes} onChange={event => onAutoLockChange(parseAutoLockMinutes(event.target.value))}>
          {AUTO_LOCK_MINUTES.map(minutes => <option key={minutes} value={minutes}>{minutes} minute{minutes === 1 ? "" : "s"}</option>)}
        </select>
        <p>Applies to this browser. Unlock with your master password or paper recovery key after locking.</p>
      </section>

        <p style={{ color: "var(--ink-muted)" }}>
          Manage your zero-knowledge key custody, master password, paper recovery, and paired devices.
        </p>
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

      {/* 1. Master Password Change */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <KeyRound size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Change Master Password</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Your master password is not a login credential — KySignOn handles signing in. It is the
          secret that decrypts your vault key, here in the browser. Changing it re-wraps that key
          envelope client-side; the password itself is never sent, and the KDBX vault is not
          re-encrypted.
        </p>

        <div className="input-group">
          <label className="input-label" htmlFor="current-master-password">Current Master Password or Paper Code</label>
          <input id="current-master-password" type="password" className="input" autoComplete="current-password"
            value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
          <p style={{ fontSize: "0.8rem", color: "var(--ink-muted)" }}>Needed to change the password, generate a paper code, rotate the vault key or show the vault key. Checked in this browser only.</p>
        </div>

        <form onSubmit={handleChangePassword}>
          <div className="input-group">
            <label htmlFor="new-master-password" className="input-label">New Master Password</label>
            <input
              id="new-master-password"
              type="password"
              className="input"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              minLength={MIN_MASTER_PASSWORD_LENGTH}
              required
            />
          </div>
          <div className="input-group">
            <label htmlFor="confirm-master-password" className="input-label">Confirm New Password</label>
            <input
              id="confirm-master-password"
              type="password"
              className="input"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              minLength={MIN_MASTER_PASSWORD_LENGTH}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={busy || !newPassword || !currentPassword}>
            {busy ? "Updating…" : "Update Master Password"}
          </button>
        </form>
      </section>

      {/* 2. Paper Recovery Code */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <FileText size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Paper Recovery Code</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Print or store this paper key in a safe. If you ever forget your master password, this code unlocks your vault key envelope.
        </p>

        {paperCode ? (
          <div
            className={printTarget === "paper" ? "print-only-secret" : undefined}
            style={{
              background: "var(--bg)",
              border: "1px solid var(--accent)",
              borderRadius: "8px",
              padding: "1.25rem",
              marginBottom: "1.25rem",
              textAlign: "center",
            }}
          >
            <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginBottom: "0.5rem" }}>
              YOUR EMERGENCY PAPER BACKUP KEY
            </div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, letterSpacing: "0.1em", color: "var(--accent)" }} className="font-mono">
              {paperCode}
            </div>
            <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1rem" }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={async () => {
                  const copied = await copyText(paperCode, { clearAfterMs: SECRET_CLIPBOARD_MS });
                  if (copied) { setPaperCodeCopied(true); setTimeout(() => setPaperCodeCopied(false), 2000); }
                }}
              >
                {paperCodeCopied ? <CheckCircle2 size={14} /> : null} Copy
              </button>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPrintTarget("paper")}>
                Print
              </button>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--ink-muted)", marginTop: "0.5rem" }}>
              Cleared from the clipboard after 30 seconds when the browser allows it.
            </p>

            <div style={{ marginTop: "1.25rem", textAlign: "left" }}>
              <label className="input-label" htmlFor="paper-code-confirm">Type the code to confirm you saved it</label>
              <input
                id="paper-code-confirm"
                type="text"
                className="input"
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                value={paperConfirmInput}
                onChange={(e) => setPaperConfirmInput(e.target.value)}
              />
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.5rem" }}>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={normalizeCode(paperConfirmInput) !== normalizeCode(paperCode)}
                  onClick={() => { setPaperConfirmed(true); setPaperCode(null); }}
                >
                  Done
                </button>
                {!paperConfirmed ? <span style={{ fontSize: "0.8rem", color: "var(--ink-muted)" }}>Not confirmed yet.</span> : null}
              </div>
            </div>
          </div>
        ) : null}

        <button className="btn btn-secondary" onClick={handleGeneratePaperRecovery} disabled={busy || !currentPassword}>
          Generate Printable Paper Key
        </button>
      </section>

      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <RefreshCw size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Rotate Vault Key</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          Replaces the vault key with a new random one and re-encrypts the vault. Your master password stays
          the same. Every paired device and extension is signed out, and snapshots and preserved conflicts
          from before the rotation can no longer be opened here. A new paper code is shown once afterwards;
          if this tab closes before you save it, your master password still unlocks the vault and you can
          generate another code. The download opens only with the offline vault key shown below; reveal and
          save it first.
        </p>
        {unrevoked.length > 0 ? (
          <div role="alert" style={{ marginBottom: "1rem", fontSize: "0.85rem" }}>
            <p style={{ margin: "0 0 0.5rem" }}>These devices could not be signed out yet: {unrevoked.map((d) => d.name).join(", ")}.</p>
            <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void revokeAll(unrevoked)}>
              Retry revoking
            </button>
          </div>
        ) : null}
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn btn-secondary" onClick={() => void onExport()} disabled={busy}>
            <Download size={14} /> Download vault first
          </button>
          <button type="button" className="btn btn-danger" onClick={handleRotateKey}
            disabled={busy || !currentPassword || !canRotate}
            title={canRotate ? undefined : "Save or discard your unsaved edits first."}>
            Rotate key
          </button>
        </div>
        {!canRotate ? <p style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.5rem" }}>Save or discard your unsaved edits first.</p> : null}
      </section>

      {/* Offline recovery: the key that opens a downloaded vault in any KeePass client */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <Download size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>Offline Vault Key</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
          If KySignOn is ever unavailable you can still reach your passwords: download your vault
          and open it in KeePass, KeePassXC or KeePassDX. The file's password is the key below —
          type or paste it exactly. Keep a printed copy somewhere safe, because this server cannot
          show it to you while it is down.
        </p>

        {showVaultKey ? (
          <div
            className={printTarget === "key" ? "print-only-secret" : undefined}
            style={{
              background: "var(--bg)",
              border: "1px solid var(--accent)",
              borderRadius: "8px",
              padding: "1.25rem",
              marginBottom: "1.25rem",
              textAlign: "center",
            }}
          >
            <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginBottom: "0.5rem" }}>
              VAULT KEY — THE PASSWORD FOR YOUR DOWNLOADED .KDBX
            </div>
            <div
              className="font-mono"
              style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--accent)", wordBreak: "break-all" }}
            >
              {groupHex(bytesToHex(vaultKey))}
            </div>
            <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1rem" }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={async () => {
                  const copied = await copyText(bytesToHex(vaultKey), { clearAfterMs: SECRET_CLIPBOARD_MS });
                  if (copied) { setVaultKeyCopied(true); setTimeout(() => setVaultKeyCopied(false), 2000); }
                }}
              >
                {vaultKeyCopied ? <CheckCircle2 size={14} /> : null} Copy
              </button>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPrintTarget("key")}>
                Print
              </button>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--ink-muted)", marginTop: "0.5rem" }}>
              Cleared from the clipboard after 30 seconds when the browser allows it.
            </p>
          </div>
        ) : null}

        <button className="btn btn-secondary" onClick={handleRevealVaultKey} disabled={busy || (!showVaultKey && !currentPassword)}>
          {showVaultKey ? "Hide Vault Key" : "Show Vault Key"}
        </button>
      </section>

      {/* 3. Single Sign-On */}
      {ssoConfig?.enabled ? (
        <section className="field-card" style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
            <Shield size={20} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>Single Sign-On (KySignOn / OIDC)</h3>
          </div>

          <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
            KySignOn is your only way in to KyVault, so this identity cannot be unlinked —
            doing so would lock you out for good. Accounts are managed in KySignOn.
          </p>
          <div
            style={{
              background: "var(--accent-soft)",
              border: "1px solid rgba(77, 238, 234, 0.3)",
              borderRadius: "6px",
              padding: "0.75rem 1rem",
            }}
          >
            <strong style={{ color: "var(--accent)" }}>KySignOn Identity</strong>
            <div style={{ fontSize: "0.85rem", color: "var(--ink-muted)", marginTop: "0.25rem" }}>
              Username: <code>{user.ssoUsername || user.username}</code>{" "}
              {user.ssoEmail ? `(${user.ssoEmail})` : ""}
              <br />
              Subject: <code>{user.ssoSub || "—"}</code>
            </div>
          </div>
        </section>
      ) : null}

      {/* Local Device Vault & 1-Click SSO */}
      <section className="field-card" style={{ marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <KeyRound size={20} color="var(--accent)" />
          <h3 style={{ margin: 0 }}>This Device & 1-Click SSO</h3>
        </div>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
          The vault key is kept in this browser, encrypted under a key the browser will not export. Forget This Device removes it.
        </p>

        {onForgetDevice && (
          <button className="btn btn-danger btn-sm" onClick={onForgetDevice}>
            Forget This Device & Sign Out
          </button>
        )}
      </section>

      {/* 4. Paired Devices */}
      <section className="field-card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Smartphone size={20} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>Paired Devices & Extensions</h3>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            {devices.some((d) => !d.current) ? (
              <button className="btn btn-danger btn-sm" onClick={handleRevokeAllOthers} disabled={revoking !== null}>
                Revoke all others
              </button>
            ) : null}
            <button className="btn btn-primary btn-sm" onClick={() => setShowPairing(true)}>
              <QrCode size={14} /> Pair New Device
            </button>
          </div>
        </div>

        {devices.length === 0 ? (
          <p style={{ color: "var(--ink-muted)", fontSize: "0.9rem" }}>No paired mobile apps or browser extensions.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {devices.map((d) => (
              <div
                key={d.id}
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
                  <div style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    {d.name}
                    {d.current ? <span className="badge badge-cyan">This device</span> : null}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.2rem" }}>
                    {d.platform} • Last active: {formatWhen(d.lastSeenAt)} ({d.lastIp || "—"})
                  </div>
                </div>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleRenameDevice(d)}
                    title="Rename device"
                  >
                    Rename
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => handleRevokeDevice(d.id, d.name)}
                    title="Revoke device"
                    disabled={revoking !== null}
                  >
                    <Trash2 size={14} /> Revoke
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {showPairing ? (
        <DevicePairingModal
          onClose={() => { setShowPairing(false); loadDevices(); }}
          onPaired={() => setMessage("Device paired.")}
        />
      ) : null}
    </div>
  );
}
