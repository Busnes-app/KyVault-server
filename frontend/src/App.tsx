import { ThemeSwitcher } from './components/ThemeSwitcher';
import React, { useState, useEffect, useSyncExternalStore, useRef, useCallback } from "react";
import { getJSON, postJSON, putJSON, toErrorMessage, HttpError } from "./lib/api";
import { VaultSaveQueue, uploadVault, canDiscardVault, type SaveState } from "./lib/vaultSave";
import { IdleDeadline, cachedKeyExpired, loadAutoLockMinutes, storeAutoLockMinutes, type AutoLockMinutes } from "./lib/autoLock";
import { sealDraft, openDraft, draftPointer, draftStore, readDraft, removeDraft, pruneDrafts, type EntryDraft, type LockedDraft } from "./lib/lockedDraft";
import { KeePassVault, isWrongVaultKey } from "./lib/kdbx";
import { downloadBlob } from "./lib/download";
import { rotateAndUpload, RotationUnconfirmedError, uploadRotatedVault } from "./lib/keyRotation";
import {
  generateVaultMasterKey,
  wrapVaultKey,
  unwrapVaultKeyFromEnvelopes,
  bytesToHex,
  hexToBytes,
} from "./lib/vaultCrypto";
import { checkMasterPassword } from "./lib/masterPassword";
import { unlockMode, checkCreatePassword } from "./lib/unlockMode";
import { getDeviceVaultKey, storeDeviceVaultKey, clearDeviceVaultKey } from "./lib/storage";
import { cacheDeviceKey } from "./lib/deviceKeyCache";
import { useRoute, type Route } from "./lib/route";
import { LoginPage } from "./pages/LoginPage";
import { VaultPage } from "./pages/VaultPage";
import { SecuritySettings } from "./pages/SecuritySettings";
import { AdminPanel } from "./pages/AdminPanel";
import { HistoryModal } from "./components/HistoryModal";
import { Dialog } from "./components/Dialog";
import { useDialogs } from "./components/DialogHost";
import { Shield, KeyRound, Settings, LogOut, Lock, CheckCircle2, History, RotateCcw } from "lucide-react";
import "./styles/styles.css";
import "./ky-ui/tokens.css";
import "./ky-ui/navigation.css";

type User = {
  id: string;
  username: string;
  role: "admin" | "user";
  active: boolean;
  ssoSub?: string;
  ssoUsername?: string;
  ssoEmail?: string;
};

type VaultMetadata = {
  version: number;
  checksum: string;
  sizeBytes: number;
  passwordEnvelope?: string;
  recoveryEnvelope?: string;
};

const idleSave: SaveState = { kind: "saved", version: 0 };
const noSubscribe = () => () => {};
const idleSnapshot = () => idleSave;

export function App() {
  const dialogs = useDialogs();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [route, navigate] = useRoute();
  const navTab = route.tab;
  const lastVault = useRef<Route>({ tab: "vault" });
  useEffect(() => {
    if (route.tab === "vault") lastVault.current = route;
  }, [route]);

  // Vault state
  const [vault, setVault] = useState<KeePassVault | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [saveQueue, setSaveQueue] = useState<VaultSaveQueue | null>(null);
  const saveState = useSyncExternalStore(saveQueue?.subscribe ?? noSubscribe, saveQueue?.getSnapshot ?? idleSnapshot);
  const [hasDraft, setHasDraft] = useState(false);
  const draft = useRef<EntryDraft | null>(null);
  const [initialDraft, setInitialDraft] = useState<EntryDraft | null>(null);
  const onDraftChange = useCallback((value: EntryDraft | null) => { draft.current = value; setHasDraft(value !== null); }, []);
  const [autoLockMinutes, setAutoLockMinutes] = useState(loadAutoLockMinutes);
  const unlockGeneration = useRef(0);
  const checkpoint = useRef<Promise<void>>(Promise.resolve());
  const memoryDraft = useRef<LockedDraft | undefined>(undefined);
  const [lockNotice, setLockNotice] = useState("");
  const restoreNotice = useRef("");
  const [sessionNotice, setSessionNotice] = useState("");
  const recoveryId = (u: User): string | undefined => {
    try { return draftPointer(sessionStorage, u.id); } catch { return undefined; }
  };
  const [recoveryPending, setRecoveryPending] = useState(false);
  const unsaved = recoveryPending || hasDraft || saveState.kind !== "saved";

  useEffect(() => {
    if (!unsaved) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unsaved]);

  const confirmDiscardVault = () => canDiscardVault(saveState, hasDraft, () =>
    dialogs.confirm({
      title: "Discard unsaved edits?",
      message: "Some edits are unsaved or still saving. Continue and discard unsaved edits? An upload already accepted by the server cannot be undone.",
      confirmLabel: "Discard",
      danger: true,
    }));

  // Replacing or closing a vault must never leave a timer/old upload able to save later.
  useEffect(() => () => { saveQueue?.discard(); }, [saveQueue]);

  // SSO unlock modal state
  const [meta, setMeta] = useState<VaultMetadata | null>(null);
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [lockedReason, setLockedReason] = useState<"new" | "locked" | null>(null);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockConfirm, setUnlockConfirm] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const mode = meta ? unlockMode(meta.version) : "unlock";

  // Check auth on load
  const checkAuth = async () => {
    try {
      const res = await getJSON<{ authenticated: boolean; user?: User }>("/api/auth/me");
      if (res.authenticated && res.user) {
        setUser(res.user);
        setSessionNotice("");
        await initVault(res.user);
      } else {
        setUser(null);
        setVault(null);
        setVaultKey(null);
        setSaveQueue(null);
        setHasDraft(false);
      }
    } catch {
      setUser(null);
      setVault(null);
      setVaultKey(null);
      setSaveQueue(null);
      setHasDraft(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (!loading && user && route.tab === "admin" && user.role !== "admin") navigate({ tab: "vault" });
  }, [loading, route.tab, user?.role]);

  useEffect(() => {
    if (!user) return;
    const ended = () => { closeVault(); setUser(null); setSessionNotice("Your session ended. Sign in again."); };
    window.addEventListener("kyvault:unauthorized", ended);
    return () => window.removeEventListener("kyvault:unauthorized", ended);
  }, [user?.id]);

  const initVault = async (u: User, masterPassword?: string) => {
    const generation = ++unlockGeneration.current;
    const current = () => generation === unlockGeneration.current;
    const notices: string[] = [];
    try {
      await checkpoint.current;
      if (!current()) return;
      const meta = await getJSON<VaultMetadata>("/api/vault/metadata");
      if (!current()) return;
      setMeta(meta);

      // Case 1: Brand new vault (version 0)
      if (!meta.version || meta.version === 0) {
        if (!masterPassword) {
          setLockedReason("new");
          return;
        }

        const problem = checkMasterPassword(masterPassword);
        if (problem) throw new Error(problem);

        const key = generateVaultMasterKey();

        const newVault = await KeePassVault.createNew(key, `${u.username}'s Vault`);

        // Export and save initial version 1
        const binary = await newVault.exportBinary();
        const pwEnvelope = await wrapVaultKey(key, masterPassword);

        const version = await uploadVault(binary, 0, pwEnvelope);
        if (!current()) return;
        setMeta({ ...meta, version, passwordEnvelope: pwEnvelope });
        const cached = await cacheDeviceKey({ store: () => storeDeviceVaultKey(u.username, bytesToHex(key)), clear: () => clearDeviceVaultKey(u.username), stillCurrent: current });
        if (cached === "failed") notices.push("Could not cache the device key; you may need your master password again.");
        if (!current()) return;
        try { sessionStorage.removeItem(`kyvault.locked:${u.id}`); localStorage.removeItem(`kyvault.locked:${u.id}`); } catch {}
        setSaveQueue(new VaultSaveQueue(newVault, version, pwEnvelope));
        setVaultKey(key);
        setVault(newVault);
        setLockedReason(null);
        setShowUnlockModal(false);
        setLockNotice(["Vault created. Generate a paper recovery code from Security so a forgotten password does not lock you out.", ...notices].join(" "));
        return;
      }

      // Case 2: Existing vault on server
      let key: Uint8Array | null = null;
      if (masterPassword) {
        key = await unwrapVaultKeyFromEnvelopes([meta.passwordEnvelope, meta.recoveryEnvelope], masterPassword);
      } else {
        // The trusted-key deadline survives refreshing or closing every tab.
        try {
          const last = sessionStorage.getItem(`kyvault.activity:${u.id}`) ?? localStorage.getItem(`kyvault.activity:${u.id}`);
          if (sessionStorage.getItem(`kyvault.locked:${u.id}`) || localStorage.getItem(`kyvault.locked:${u.id}`) ||
              cachedKeyExpired(last, autoLockMinutes * 60000)) {
            setLockedReason("locked");
            await clearDeviceVaultKey(u.username).catch(() => {});
            return;
          }
        } catch { setLockedReason("locked"); return; }
        // Check for cached key on this trusted device
        const cachedHex = await getDeviceVaultKey(u.username).catch(() => undefined);
        if (cachedHex) {
          key = hexToBytes(cachedHex);
        } else {
          setLockedReason("locked");
          return;
        }
      }

      if (!current()) return;

      // Download encrypted KDBX
      const kdbxRes = await fetch("/api/vault/kdbx", { credentials: "same-origin" });
      if (!kdbxRes.ok) throw new Error("Failed to download encrypted vault");
      const kdbxBytes = await kdbxRes.arrayBuffer();

      // Open zero-knowledge vault client-side
      const id = recoveryId(u);
      const local = memoryDraft.current ? { kind: "available", draft: memoryDraft.current } : await readDraft(id);
      const stored = "draft" in local ? local.draft : undefined;
      if (local.kind === "unavailable") notices.push("Opened the server copy. Could not read the local recovery copy; retry unlocking when browser storage is available to recover local edits.");
      let recovered: Awaited<ReturnType<typeof openDraft>> | undefined;
      if (stored) {
        try {
          recovered = await openDraft(stored, key, u.id);
        } catch {
          notices.push("Opened the server copy. The local recovery copy could not be read and was discarded.");
          if (!await removeDraft(id)) notices.push("Could not remove the unreadable recovery copy from browser storage.");
        }
      }
      const loadedVault = await KeePassVault.open(recovered?.binary ?? kdbxBytes, key);
      if (!current()) return;
      if (!masterPassword) {
        try {
          const last = sessionStorage.getItem(`kyvault.activity:${u.id}`) ?? localStorage.getItem(`kyvault.activity:${u.id}`);
          if (localStorage.getItem(`kyvault.locked:${u.id}`) || cachedKeyExpired(last, autoLockMinutes * 60000)) {
            setLockedReason("locked");
            await clearDeviceVaultKey(u.username).catch(() => {});
            return;
          }
        } catch { setLockedReason("locked"); return; }
      }
      if (masterPassword) {
        const cached = await cacheDeviceKey({ store: () => storeDeviceVaultKey(u.username, bytesToHex(key)), clear: () => clearDeviceVaultKey(u.username), stillCurrent: current });
        if (cached === "failed") notices.push("Could not cache the device key; you may need your master password again.");
        if (!current()) return;
      }
      if (recovered) {
        memoryDraft.current = stored;
        setRecoveryPending(true);
        if (!await removeDraft(id)) notices.push("Recovered local edits, but could not remove the old encrypted recovery copy from browser storage.");
      }
      if (local.kind === "available") {
        try {
          sessionStorage.removeItem(`kyvault.draft:${u.id}`);
          sessionStorage.removeItem(`kypassword.draft:${u.id}`);
        } catch {}
      }
      if (!current()) return;
      memoryDraft.current = undefined;
      setRecoveryPending(local.kind === "unavailable");
      const queue = new VaultSaveQueue(loadedVault, recovered?.metadata.version ?? meta.version, meta.passwordEnvelope);
      if (recovered?.metadata.dirty) queue.recoverUnsaved();
      setInitialDraft(recovered?.metadata.entry ?? null);
      setSaveQueue(queue);
      setVaultKey(key);
      setVault(loadedVault);
      if (recovered) notices.unshift("Recovered local edits. Review them before saving.");
      setLockNotice(notices.join(" "));
      if (masterPassword) { try { sessionStorage.removeItem(`kyvault.locked:${u.id}`); localStorage.removeItem(`kyvault.locked:${u.id}`); } catch {} }
      void pruneDrafts(u.id, id);
      setLockedReason(null);
      setShowUnlockModal(false);
    } catch (err) {
      if (!current()) return;
      console.error("Vault init error:", err);
      // A cached key that no longer opens the vault was retired by a rotation elsewhere.
      if (!masterPassword && isWrongVaultKey(err)) {
        await clearDeviceVaultKey(u.username).catch(() => {});
        if (!current()) return;
        setUnlockError("The vault key changed on another device. Enter your master password or paper code.");
      } else {
        setUnlockError(toErrorMessage(err, "Failed to unlock vault"));
      }
      setLockedReason(meta ? (meta.version ? "locked" : "new") : "locked");
    }
  };

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setUnlockError("");

    if (mode === "create") {
      const problem = checkCreatePassword(unlockPassword, unlockConfirm);
      if (problem) { setUnlockError(problem); return; }
    }

    setUnlocking(true);
    try {
      await initVault(user, unlockPassword);
      setUnlockPassword("");
      setUnlockConfirm("");
    } catch (err) {
      setUnlockError(toErrorMessage(err, "Incorrect password or recovery key"));
    } finally {
      setUnlocking(false);
    }
  };

  const handleExportKdbx = async () => {
    if (!saveQueue || saveState.kind === "saving") return;
    const binary = await saveQueue.exportBinary();
    downloadBlob(new Blob([binary], { type: "application/x-keepass2" }), `${user?.username || "vault"}.kdbx`);
  };

  // Key rotation. Runs inside the queue's serializer so no download or autosave can export
  // while the live vault holds a key the server has not accepted yet.
  const rotateKey = async (password: string, paperCode: string): Promise<void> => {
    const queue = saveQueue, oldKey = vaultKey, u = user, generation = unlockGeneration.current;
    if (!vault || !queue || !oldKey || !u) throw new Error("Unlock the vault first.");
    let rotated: { key: Uint8Array; version: number; passwordEnvelope: string };
    try {
      rotated = await queue.exclusive((live) => {
        if (queue.getSnapshot().kind !== "saved") throw new Error("Save or discard your unsaved edits first.");
        const version = queue.getSnapshot().version;
        return rotateAndUpload(live, oldKey, password, paperCode, version, {
          upload: (binary, pw, rec) => uploadRotatedVault(binary, version, pw, rec),
          metadata: () => getJSON("/api/vault/metadata"),
        });
      });
    } catch (err) {
      if (err instanceof RotationUnconfirmedError) {
        closeVault();
        await clearDeviceVaultKey(u.username).catch(() => {});
        setLockNotice("Could not confirm whether the new vault key reached the server, so the vault is locked. Unlock with your master password, then generate a new paper code from Security.");
      }
      throw err;
    }
    queue.discard();
    const recache = clearDeviceVaultKey(u.username);
    if (generation !== unlockGeneration.current) {
      // Locked while the upload was in flight: the rotation stands, this tab keeps nothing.
      await recache.catch(() => {});
      setLockNotice("The vault key was rotated while the vault locked. Unlock with your master password, then generate a new paper code from Security.");
      return;
    }
    setVaultKey(rotated.key);
    setSaveQueue(new VaultSaveQueue(vault, rotated.version, rotated.passwordEnvelope));
    // Forget This Device or a lock can land while this write is pending; the helper
    // undoes a write that lost that race so the forgotten device keeps nothing.
    const cached = await recache.then(() => cacheDeviceKey({
      store: () => storeDeviceVaultKey(u.username, bytesToHex(rotated.key)),
      clear: () => clearDeviceVaultKey(u.username),
      stillCurrent: () => generation === unlockGeneration.current,
    }), () => "failed" as const);
    if (cached === "failed") setLockNotice("Could not cache the new device key; you may need your master password again.");
  };

  const closeVault = () => {
    // A question asked before the lock must not be answerable after it: the handler
    // that asked still holds the vault key in its closure.
    dialogs.cancelAll();
    unlockGeneration.current++;
    if (user) {
      try { sessionStorage.setItem(`kyvault.locked:${user.id}`, "1"); } catch {}
      try { localStorage.setItem(`kyvault.locked:${user.id}`, "1"); } catch {}
    }
    saveQueue?.discard();
    draft.current = null;
    setInitialDraft(null);
    setSaveQueue(null);
    setHasDraft(false);
    setVault(null);
    setVaultKey(null);
    setUnlockPassword("");
    setUnlockConfirm("");
    setShowUnlockModal(false);
    setShowHistoryModal(false);
    setLockedReason(meta?.version ? "locked" : "new");
  };

  const autoLock = useRef(() => {});
  autoLock.current = () => {
    if (!vault || !vaultKey || !saveQueue || !user) return;
    const u = user;
    const key = vaultKey;
    const metadata = { version: saveQueue.getSnapshot().version, dirty: saveQueue.getSnapshot().kind !== "saved", entry: draft.current };
    const binary = metadata.dirty || metadata.entry ? saveQueue.exportBinary() : null;
    // Duplicating a browser tab copies sessionStorage. Allocate on each lock so those
    // tabs cannot overwrite one another's subsequent recovery snapshots.
    const id = `${u.id}:${crypto.randomUUID()}`;
    let durableReference = true;
    if (binary) {
      try { sessionStorage.setItem(`kyvault.draft:${u.id}`, id); }
      catch { durableReference = false; }
    }
    // Capture the serializer before discarding; no subsequent network save can run.
    autoLock.current = () => {};
    setRecoveryPending(!!binary);
    closeVault();
    setLockNotice(binary ? "Vault locked. Securing your unsaved edits…" : "Vault locked after inactivity.");
    const removeCachedKey = clearDeviceVaultKey(u.username).catch(() => { setLockNotice("Vault locked. Could not remove the cached device key; keep this tab locked until browser storage is available."); });
    checkpoint.current = (async () => {
      try {
        if (binary) {
          memoryDraft.current = await sealDraft(await binary, metadata, key, u.id);
          await draftStore(id, "put", memoryDraft.current);
          setRecoveryPending(!durableReference);
          setLockNotice(durableReference
            ? "Vault locked. Your unsaved edits are encrypted on this device; unlock this tab to recover them."
            : "Vault locked. Keep this tab open and unlock to recover your edits; the browser could not save the recovery reference.");
        } else {
          memoryDraft.current = undefined;
        }
      } catch {
        setLockNotice(memoryDraft.current
          ? "Vault locked. Recovery storage failed; keep this tab open and unlock to recover your edits."
          : "Vault locked, but the recovery copy failed. Unsaved edits could not be preserved.");
      } finally { await removeCachedKey; }
    })();
  };

  useEffect(() => {
    if (!vault || !user) return;
    const deadline = new IdleDeadline(autoLockMinutes * 60000);
    const record = () => {
      const now = String(Date.now());
      try { sessionStorage.setItem(`kyvault.activity:${user.id}`, now); } catch {}
      try { localStorage.setItem(`kyvault.activity:${user.id}`, now); } catch {}
    };
    record();
    const check = () => { if (deadline.expired()) autoLock.current(); };
    const activity = (event: Event) => {
      if (deadline.activity()) record();
      else { event.preventDefault(); event.stopImmediatePropagation(); autoLock.current(); }
    };
    const events = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"] as const;
    events.forEach(event => window.addEventListener(event, activity, { capture: true }));
    window.addEventListener("focus", check);
    document.addEventListener("visibilitychange", check);
    const timer = window.setInterval(check, 1000);
    return () => {
      clearInterval(timer);
      events.forEach(event => window.removeEventListener(event, activity, true));
      window.removeEventListener("focus", check);
      document.removeEventListener("visibilitychange", check);
    };
  }, [vault, user?.id, autoLockMinutes]);

  const changeAutoLock = (minutes: AutoLockMinutes) => {
    setAutoLockMinutes(minutes);
    try { storeAutoLockMinutes(minutes); } catch { void dialogs.notify({ title: "Setting not saved", message: "The timeout applies to this tab, but browser storage could not save the preference." }); }
  };

  const logout = async () => {
    closeVault();
    // Clear the visible vault before waiting on a possibly stalled network request.
    try {
      await postJSON("/api/auth/logout", {});
    } catch (err) {
      // A 401 here means the server session was already gone; treat it as signed out.
      if (!(err instanceof HttpError) || err.status !== 401) throw err;
    }
    setUser(null);
  };

  const handleLogout = async () => {
    if (!await confirmDiscardVault()) return;
    try { await logout(); } catch { await dialogs.notify({ title: "Sign-out did not reach the server", message: "Vault locked locally, but server logout failed. Retry signing out when the connection returns." }); }
  };

  const handleForgetDevice = async () => {
    if (!await confirmDiscardVault()) return;
    const username = user?.username;
    closeVault();
    // Neither storage failure nor a stalled logout may prevent the other action starting.
    const results = await Promise.allSettled([
      username ? clearDeviceVaultKey(username) : Promise.resolve(),
      checkpoint.current.then(async () => {
        memoryDraft.current = undefined;
        const id = user ? recoveryId(user) : undefined;
        if (id) await draftStore(id, "delete");
        if (user) {
          try {
            sessionStorage.removeItem(`kyvault.draft:${user.id}`);
            sessionStorage.removeItem(`kypassword.draft:${user.id}`);
          } catch {}
        }
      }),
      logout(),
    ]);
    if (results[0].status === "rejected") await dialogs.notify({ title: "Could not complete that", message: "Could not forget this device. Clear this site's browser data to remove its saved vault key." });
    if (results[1].status === "rejected") await dialogs.notify({ title: "Could not complete that", message: "Could not remove the local recovery copy. Clear this site’s browser data." });
    if (results[2].status === "rejected") await dialogs.notify({ title: "Sign-out did not reach the server", message: "Vault locked locally, but server logout failed." });
  };

  const handleLockVault = async () => {
    if (!await confirmDiscardVault()) return;
    closeVault();
    setShowUnlockModal(true);
  };

  const closeUnlockModal = () => {
    if (unlocking) return;
    setShowUnlockModal(false);
    setLockedReason(null);
  };

  if (loading) {
    return (
      <div className="auth-container">
        <p style={{ color: "var(--accent)" }}>Loading KyVault…</p>
      </div>
    );
  }

  if (!user) {
    return <LoginPage notice={sessionNotice} />;
  }

  return (
    <div className="app-container">
      {/* Navbar */}
      <header className="app-nav">
        <a href="/" className="nav-brand">
          <img src="/logo.png" alt="KyVault" />
          <span>KyVault</span>
        </a>

        <ThemeSwitcher />
        <div className="nav-links">
          <button
            className={`ky-nav-item nav-link-btn ${navTab === "vault" ? "active" : ""}`}
            aria-current={navTab === "vault" ? "page" : undefined}
            aria-label="Vault"
            onClick={() => navigate(lastVault.current)}
          >
            <Shield size={16} /> <span>Vault</span>
          </button>
          <button
            className={`ky-nav-item nav-link-btn ${navTab === "security" ? "active" : ""}`}
            aria-current={navTab === "security" ? "page" : undefined}
            aria-label="Security"
            onClick={() => navigate({ tab: "security" })}
          >
            <KeyRound size={16} /> <span>Security</span>
          </button>
          {user.role === "admin" ? (
            <button
              className={`ky-nav-item nav-link-btn ${navTab === "admin" ? "active" : ""}`}
              aria-current={navTab === "admin" ? "page" : undefined}
              aria-label="Admin"
              onClick={() => navigate({ tab: "admin", admin: "sso" })}
            >
              <Settings size={16} /> <span>Admin</span>
            </button>
          ) : null}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <span className="nav-user-name" style={{ fontSize: "0.85rem", color: "var(--ink-muted)" }}>
            {user.username}
          </span>
          <button className="btn btn-quiet btn-sm" onClick={handleLockVault} title="Lock Vault">
            <Lock size={16} /> Lock
          </button>
          <button className="btn btn-quiet btn-sm" onClick={handleLogout} title="Log Out" aria-label="Log out">
            <LogOut size={16} /> <span className="nav-icon-label">Log out</span>
          </button>
        </div>
      </header>

      {lockNotice ? (
        <p role="status" style={{ padding: "0.75rem", margin: 0, display: "flex", gap: "0.75rem", alignItems: "center" }}>
          <span>{lockNotice}</span>
          {lockNotice.startsWith("Vault created.") ? (
            <button className="btn btn-quiet btn-sm" onClick={() => navigate({ tab: "security" })}>Go to Security</button>
          ) : null}
        </p>
      ) : null}

      {/* Keep the editor mounted across tabs so drafts and save status survive navigation. */}
      {vault && vaultKey && saveQueue ? (
        <VaultPage
          vault={vault}
          vaultKey={vaultKey}
          vaultVersion={saveState.version}
          saveState={saveState}
          onChanged={saveQueue.changed}
          onSave={saveQueue.save}
          onDraftChange={onDraftChange}
          initialDraft={initialDraft}
          hidden={navTab !== "vault"}
          onExport={handleExportKdbx}
          onReload={() => initVault(user)}
          route={route}
          navigate={navigate}
        />
      ) : null}
      {navTab === "admin" && user.role === "admin" ? (
        <AdminPanel currentUserId={user.id} route={route} navigate={navigate} />
      ) : vault ? (
        navTab === "security" ? <SecuritySettings
          user={user}
          vaultKey={vaultKey!}
          autoLockMinutes={autoLockMinutes}
          onAutoLockChange={changeAutoLock}
          onUserUpdated={async () => { if (await confirmDiscardVault()) void checkAuth(); }}
          onForgetDevice={handleForgetDevice}
          canRotate={!unsaved}
          onExport={handleExportKdbx}
          onRotateKey={rotateKey}
        /> : null
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ textAlign: "center", maxWidth: "440px", padding: "2rem" }}>
            <Lock size={48} color="var(--accent)" style={{ marginBottom: "1rem" }} />
            <h2>{mode === "create" ? "Set up your vault" : "Vault is Locked"}</h2>
            <p style={{ color: "var(--ink-muted)", marginBottom: "1.5rem" }}>
              {mode === "create"
                ? "Choose a master password to create your encrypted vault. It stays in your browser and is never sent to the server."
                : "Enter your master password or paper recovery code to unlock your encrypted KeePass vault."}
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <button className="btn btn-primary" onClick={() => setShowUnlockModal(true)}>
                <Lock size={16} /> {mode === "create" ? "Create master password" : "Unlock Vault"}
              </button>
              {mode === "create" ? null : (
                <button className="btn btn-secondary" onClick={() => setShowHistoryModal(true)}>
                  <RotateCcw size={16} /> Version History & Rollback
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Unlock/create modal: auto-opens on the vault tab when locked; explicit opens work on any tab */}
      {showUnlockModal || (lockedReason && navTab === "vault") ? (
        <Dialog title={mode === "create" ? "Create your master password" : "Unlock KeePass Vault"} onClose={closeUnlockModal}>
            <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.25rem" }}>
              {mode === "create"
                ? "This password encrypts your vault key in your browser. It is never sent to the server, so nobody can reset it for you. Use at least 12 characters; a short sentence works well."
                : "You are signed in. KySignOn has proved who you are. Unlocking is separate: your master password decrypts the vault here in your browser, and is never sent to the server. Enter it once to trust this device for 1-click unlock."}
            </p>

            {unlockError ? (
              <div
                style={{
                  background: "var(--danger-soft)",
                  color: "var(--danger)",
                  padding: "0.75rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  marginBottom: "1rem",
                }}
              >
                {unlockError}
              </div>
            ) : null}

            <form onSubmit={handleUnlockSubmit}>
              {mode === "create" ? (
                <>
                  <div className="input-group">
                    <label className="input-label">Master password</label>
                    <input
                      type="password"
                      className="input font-mono"
                      autoComplete="new-password"
                      value={unlockPassword}
                      onChange={(e) => setUnlockPassword(e.target.value)}
                      required
                      data-autofocus
                    />
                  </div>
                  <div className="input-group">
                    <label className="input-label">Confirm master password</label>
                    <input
                      type="password"
                      className="input font-mono"
                      autoComplete="new-password"
                      value={unlockConfirm}
                      onChange={(e) => setUnlockConfirm(e.target.value)}
                      required
                    />
                  </div>
                </>
              ) : (
                <div className="input-group">
                  <label className="input-label">Master Password or Paper Recovery Key</label>
                  <input
                    type="password"
                    className="input font-mono"
                    placeholder="•••••••••••• or KYPASS-XXXX-..."
                    autoComplete="current-password"
                    value={unlockPassword}
                    onChange={(e) => setUnlockPassword(e.target.value)}
                    required
                    data-autofocus
                  />
                </div>
              )}

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "1rem" }}>
                {mode === "unlock" ? (
                  <button
                    type="button"
                    className="btn btn-quiet btn-sm"
                    onClick={() => {
                      closeUnlockModal();
                      setShowHistoryModal(true);
                    }}
                  >
                    <RotateCcw size={14} /> Rollback / History
                  </button>
                ) : <span />}
                <div style={{ display: "flex", gap: "0.75rem" }}>
                  <button type="button" className="btn btn-secondary" onClick={closeUnlockModal} disabled={unlocking}>
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={unlocking || !unlockPassword || (mode === "create" && !unlockConfirm)}>
                    {unlocking ? (mode === "create" ? "Creating…" : "Unlocking…") : mode === "create" ? "Create vault" : "Unlock"}
                  </button>
                </div>
              </div>
            </form>
        </Dialog>
      ) : null}

      {/* History & Rollback Modal */}
      {showHistoryModal ? (
        <HistoryModal
          allowRollback={!vault && !saveQueue}
          onClose={() => setShowHistoryModal(false)}
          onNotice={(text) => { restoreNotice.current = text; }}
          onRestored={async () => {
            setShowHistoryModal(false);
            if (user) {
              // initVault owns lockNotice on its success paths, so the rollback
              // text is merged in after it settles rather than passed straight through.
              try {
                await initVault(user);
                setLockNotice((prev) => [restoreNotice.current, prev].filter(Boolean).join(" "));
              } finally {
                restoreNotice.current = "";
              }
            }
          }}
        />
      ) : null}
    </div>
  );
}
