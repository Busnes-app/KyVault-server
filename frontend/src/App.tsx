import { ThemeSwitcher } from './components/ThemeSwitcher';
import React, { useState, useEffect, useSyncExternalStore, useRef, useCallback, useMemo } from "react";
import { getBinary, getJSON, postJSON, putJSON, requestJSON, toErrorMessage, HttpError } from "./lib/api";
import { VaultSaveQueue, uploadVault, canDiscardVault, PERSONAL_BASE, type SaveState } from "./lib/vaultSave";
import { IdleDeadline, cachedKeyExpired, loadAutoLockMinutes, storeAutoLockMinutes, type AutoLockMinutes } from "./lib/autoLock";
import { sealDraft, openDraft, openDraftCompat, draftPointer, draftStore, readDraft, removeDraft, pruneDrafts, draftAccount, draftId, type DraftScope, type EntryDraft, type LockedDraft } from "./lib/lockedDraft";
import { KeePassVault, isWrongVaultKey } from "./lib/kdbx";
import { downloadBlob } from "./lib/download";
import { rotateAndUpload, RotationUnconfirmedError, uploadRotatedVault } from "./lib/keyRotation";
import { adoptUserKey, newUserKeyRecord, type UserKeyState } from "./lib/userKeyState";
import { fingerprint, type UserKeyRecord } from "./lib/userKey";
import { lookupKey, pinKey } from "./lib/keyPins";
import { createSharedVault, type FlowDeps } from "./lib/sharedFlows";
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
import { personal, selectionScope, selectionBase, sameSelection, resolveSelection, openShared, type Selected } from "./lib/vaultSelection";
import { switchTo, lostAccess, restorePlan, applyRotation, type OpenedPersonal } from "./lib/appSelection";
import { useSharedVaults, sharedApi, type SharedVaultSummary } from "./lib/sharedVaults";
import { VaultSwitcher } from "./components/VaultSwitcher";
import { AcceptInvitationDialog } from "./components/AcceptInvitationDialog";
import { SharedMembersDialog } from "./components/SharedMembersDialog";
import { LoginPage } from "./pages/LoginPage";
import { VaultPage } from "./pages/VaultPage";
import { WatchtowerPage } from "./pages/WatchtowerPage";
import { SecuritySettings } from "./pages/SecuritySettings";
import { AdminPanel } from "./pages/AdminPanel";
import { HistoryModal } from "./components/HistoryModal";
import { Dialog } from "./components/Dialog";
import { useDialogs } from "./components/DialogHost";
import { Shield, ShieldCheck, KeyRound, Settings, LogOut, Lock, CheckCircle2, History, RotateCcw } from "lucide-react";
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
  userKey?: UserKeyRecord;
};

const idleSave: SaveState = { kind: "saved", version: 0 };
// Personal pointers keep their original key; shared scopes add the vault id.
const pointerOwner = (userId: string, scope: DraftScope) => (scope === "personal" ? userId : `${userId}:${scope}`);
// Every draft pointer this tab holds for userId, personal and shared.
const draftPointerKeys = (userId: string): string[] => {
  const keys: string[] = [];
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k && [`kyvault.draft:${userId}`, `kypassword.draft:${userId}`].some((prefix) => k === prefix || k.startsWith(`${prefix}:`))) keys.push(k);
    }
  } catch {}
  return keys;
};
type PendingOpen = { dirty: boolean; entry: EntryDraft | null; recovered: boolean; notices: string[]; settle: (current: () => boolean) => Promise<boolean> };
const noSubscribe = () => () => {};
const idleSnapshot = () => idleSave;

export function App() {
  const dialogs = useDialogs();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [route, navigate] = useRoute();
  const routeRef = useRef(route);
  routeRef.current = route;
  const navTab = route.tab;
  const lastVault = useRef<Route>({ tab: "vault" });
  useEffect(() => {
    if (route.tab === "vault") lastVault.current = route;
  }, [route]);

  // Vault state
  const [vault, setVault] = useState<KeePassVault | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [userKey, setUserKey] = useState<UserKeyState | null>(null);
  const [saveQueue, setSaveQueue] = useState<VaultSaveQueue | null>(null);
  const saveState = useSyncExternalStore(saveQueue?.subscribe ?? noSubscribe, saveQueue?.getSnapshot ?? idleSnapshot);
  const [hasDraft, setHasDraft] = useState(false);
  const draft = useRef<EntryDraft | null>(null);
  const [initialDraft, setInitialDraft] = useState<EntryDraft | null>(null);
  const onDraftChange = useCallback((value: EntryDraft | null) => { draft.current = value; setHasDraft(value !== null); }, []);
  const [autoLockMinutes, setAutoLockMinutes] = useState(loadAutoLockMinutes);
  const unlockGeneration = useRef(0);
  const checkpoint = useRef<Promise<void>>(Promise.resolve());
  const memoryDraft = useRef(new Map<DraftScope, LockedDraft>());
  const [lockNotice, setLockNotice] = useState("");
  const restoreNotice = useRef("");
  const [sessionNotice, setSessionNotice] = useState("");
  const recoveryId = (u: User, scope: DraftScope = "personal"): string | undefined => {
    try { return draftPointer(sessionStorage, pointerOwner(u.id, scope)); } catch { return undefined; }
  };
  const [recoveryPending, setRecoveryPending] = useState(false);
  const unsaved = recoveryPending || hasDraft || saveState.kind !== "saved";

  // One selected vault at a time. The personal vault and key stay in memory while a shared
  // vault is selected; the shared key lives only in sharedKeyRef and is zeroed on leave.
  const [selected, setSelected] = useState<Selected>(personal);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const queueRef = useRef(saveQueue);
  queueRef.current = saveQueue;
  const [readOnly, setReadOnly] = useState(false);
  const [switching, setSwitching] = useState(false);
  const switchingRef = useRef(false);
  const [rotating, setRotating] = useState(false);
  const rotatingRef = useRef(false);
  const personalRef = useRef<(OpenedPersonal & { stale?: boolean }) | null>(null);
  const sharedKeyRef = useRef<Uint8Array | null>(null);
  const pendingOpen = useRef<PendingOpen | null>(null);
  const restored = useRef(-1);
  const pinChain = useRef<Promise<void>>(Promise.resolve());
  const shared = useSharedVaults(!!vault && !!user);
  const [acceptRow, setAcceptRow] = useState<SharedVaultSummary | null>(null);
  const [showMembers, setShowMembers] = useState(false);
  // My own fingerprint: the server checks it against my published key on every seal.
  const [myFingerprint, setMyFingerprint] = useState("");
  useEffect(() => {
    if (userKey?.kind !== "ready") { setMyFingerprint(""); return; }
    let live = true;
    void fingerprint(userKey.publicKey).then((f) => { if (live) setMyFingerprint(f); });
    return () => { live = false; };
  }, [userKey]);
  const resetSelection = () => {
    sharedKeyRef.current?.fill(0);
    sharedKeyRef.current = null;
    pendingOpen.current = null;
    setSelected(personal);
    setReadOnly(false);
  };

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
        setUserKey(null);
        setSaveQueue(null);
        setHasDraft(false);
      }
    } catch {
      setUser(null);
      setVault(null);
      setVaultKey(null);
      setUserKey(null);
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
    if (!loading && user && route.tab === "admin" && user.role !== "admin") navigate(lastVault.current);
  }, [loading, route.tab, user?.role]);

  useEffect(() => {
    if (!user) return;
    const ended = () => { closeVault(); setUser(null); setSessionNotice("Your session ended. Sign in again."); };
    window.addEventListener("kyvault:unauthorized", ended);
    return () => window.removeEventListener("kyvault:unauthorized", ended);
  }, [user?.id]);

  // Runs after unlock, never blocks it. A missing record is generated and published
  // create-only (If-None-Match: *) against the vault version the tab holds; a 409 means
  // another tab won the race to publish first, so this tab re-reads metadata and adopts
  // whatever that tab wrote instead of overwriting it.
  const settleUserKey = async (u: User, key: Uint8Array, record: UserKeyRecord | undefined, version: number, generation: number) => {
    try {
      const state = await adoptUserKey(record, key, u.id);
      if (generation !== unlockGeneration.current) return;
      if (state.kind !== "none") { setUserKey(state); return; }
      try {
        const made = await newUserKeyRecord(key, u.id);
        await requestJSON("/api/vault/user-key", { method: "PUT", headers: { "If-Match": `"${version}"`, "If-None-Match": "*", "Content-Type": "application/json" }, body: JSON.stringify(made.record) });
        if (generation !== unlockGeneration.current) return;
        setUserKey({ kind: "ready", seed: made.seed, publicKey: made.publicKey, record: made.record });
        setMeta((m) => (m ? { ...m, userKey: made.record } : m));
      } catch (err) {
        if (generation !== unlockGeneration.current) return;
        if (err instanceof HttpError && err.status === 409) {
          try {
            const latest = await getJSON<VaultMetadata>("/api/vault/metadata");
            if (generation !== unlockGeneration.current) return;
            const adopted = await adoptUserKey(latest.userKey, key, u.id);
            if (generation !== unlockGeneration.current) return;
            setUserKey(adopted);
            setMeta(latest);
            return;
          } catch (err2) {
            if (generation !== unlockGeneration.current) return;
            console.warn("user key adopt after conflict failed:", err2);
          }
        }
        setUserKey({ kind: "none" });
        console.warn("user key publish deferred:", err);
      }
    } catch (err) {
      if (generation !== unlockGeneration.current) return;
      setUserKey({ kind: "unavailable", reason: toErrorMessage(err, "Your key could not be loaded.") });
      console.warn("user key settle failed:", err);
    }
  };

  // Opens scope's vault from this tab's locked checkpoint when one exists, else from the server
  // copy. settle() retires the checkpoint once the caller has applied the vault; it returns
  // false when a lock landed first, leaving the in-memory copy for the next unlock.
  const restoreDraft = async (u: User, scope: DraftScope, server: ArrayBuffer | KeePassVault, key: Uint8Array, version: number, notices: string[]) => {
    const id = recoveryId(u, scope);
    const inMemory = memoryDraft.current.get(scope);
    const local = inMemory ? { kind: "available" as const, draft: inMemory } : await readDraft(id);
    const stored = local.kind === "available" ? local.draft : undefined;
    if (local.kind === "unavailable") notices.push("Opened the server copy. Could not read the local recovery copy; retry unlocking when browser storage is available to recover local edits.");
    let recovered: Awaited<ReturnType<typeof openDraft>> | undefined;
    if (stored) {
      try {
        recovered = scope === "personal" ? await openDraftCompat(stored, key, u.id) : await openDraft(stored, key, draftAccount(u.id, scope));
      } catch {
        notices.push("Opened the server copy. The local recovery copy could not be read and was discarded.");
        if (!await removeDraft(id)) notices.push("Could not remove the unreadable recovery copy from browser storage.");
      }
    }
    const opened = recovered ? await KeePassVault.open(recovered.binary, key)
      : server instanceof KeePassVault ? server : await KeePassVault.open(server, key);
    const settle = async (current: () => boolean): Promise<boolean> => {
      if (recovered && stored) {
        memoryDraft.current.set(scope, stored);
        setRecoveryPending(true);
        if (!await removeDraft(id)) notices.push("Recovered local edits, but could not remove the old encrypted recovery copy from browser storage.");
      }
      if (local.kind === "available") {
        try {
          sessionStorage.removeItem(`kyvault.draft:${pointerOwner(u.id, scope)}`);
          sessionStorage.removeItem(`kypassword.draft:${pointerOwner(u.id, scope)}`);
        } catch {}
      }
      if (!current()) return false;
      memoryDraft.current.delete(scope);
      setRecoveryPending(local.kind === "unavailable");
      return true;
    };
    return { id, vault: opened, version: recovered?.metadata.version ?? version, dirty: !!recovered?.metadata.dirty, entry: recovered?.metadata.entry ?? null, recovered: !!recovered, settle };
  };

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
        void settleUserKey(u, key, undefined, version, generation);
        setVault(newVault);
        personalRef.current = { vault: newVault, key, version, passwordEnvelope: pwEnvelope };
        resetSelection();
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
      const restoredDraft = await restoreDraft(u, "personal", kdbxBytes, key, meta.version, notices);
      const loadedVault = restoredDraft.vault;
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
      if (!await restoredDraft.settle(current)) return;
      const queue = new VaultSaveQueue(loadedVault, restoredDraft.version, meta.passwordEnvelope);
      if (restoredDraft.dirty) queue.recoverUnsaved();
      setInitialDraft(restoredDraft.entry);
      setSaveQueue(queue);
      setVaultKey(key);
      void settleUserKey(u, key, meta.userKey, restoredDraft.version, generation);
      setVault(loadedVault);
      personalRef.current = { vault: loadedVault, key, version: restoredDraft.version, passwordEnvelope: meta.passwordEnvelope };
      resetSelection();
      if (restoredDraft.recovered) notices.unshift("Recovered local edits. Review them before saving.");
      setLockNotice(notices.join(" "));
      if (masterPassword) { try { sessionStorage.removeItem(`kyvault.locked:${u.id}`); localStorage.removeItem(`kyvault.locked:${u.id}`); } catch {} }
      void pruneDrafts(u.id, restoredDraft.id);
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
    const name = selected.kind === "shared" ? shared.vaults.find((v) => v.id === selected.id)?.name || "shared-vault" : user?.username || "vault";
    downloadBlob(new Blob([binary], { type: "application/x-keepass2" }), `${name}.kdbx`);
  };

  // Key rotation. Runs inside the queue's serializer so no download or autosave can export
  // while the live vault holds a key the server has not accepted yet.
  const rotateKey = async (password: string, paperCode: string): Promise<void> => {
    const queue = saveQueue, oldKey = vaultKey, u = user, generation = unlockGeneration.current;
    if (!vault || !queue || !oldKey || !u) throw new Error("Unlock the vault first.");
    if (selected.kind !== "personal") throw new Error("Switch to My vault to rotate the vault key.");
    let rotated: { key: Uint8Array; version: number; passwordEnvelope: string; userKeyRecord?: UserKeyRecord };
    rotatingRef.current = true;
    setRotating(true);
    try {
      rotated = await queue.exclusive((live) => {
        if (queue.getSnapshot().kind !== "saved") throw new Error("Save or discard your unsaved edits first.");
        const version = queue.getSnapshot().version;
        return rotateAndUpload(live, oldKey, password, paperCode, version, {
          upload: (binary, pw, rec, ukr) => uploadRotatedVault(binary, version, pw, rec, ukr),
          metadata: () => getJSON("/api/vault/metadata"),
        }, userKey ?? { kind: "none" }, u.id);
      });
    } catch (err) {
      if (err instanceof RotationUnconfirmedError) {
        closeVault();
        await clearDeviceVaultKey(u.username).catch(() => {});
        setLockNotice("Could not confirm whether the new vault key reached the server, so the vault is locked. Unlock with your master password, then generate a new paper code from Security.");
      }
      throw err;
    } finally {
      rotatingRef.current = false;
      setRotating(false);
    }
    queue.discard();
    const recache = clearDeviceVaultKey(u.username);
    if (generation !== unlockGeneration.current) {
      // Locked while the upload was in flight: the rotation stands, this tab keeps nothing.
      await recache.catch(() => {});
      setLockNotice("The vault key was rotated while the vault locked. Unlock with your master password, then generate a new paper code from Security.");
      return;
    }
    if (rotated.userKeyRecord && userKey?.kind === "ready") setUserKey({ ...userKey, record: rotated.userKeyRecord });
    personalRef.current = { vault, key: rotated.key, version: rotated.version, passwordEnvelope: rotated.passwordEnvelope };
    // A switch that closed this queue owns the screen; the personal copy above is what it reopens.
    if (applyRotation(selectedRef.current, queue, queueRef.current)) {
      setVaultKey(rotated.key);
      setSaveQueue(new VaultSaveQueue(vault, rotated.version, rotated.passwordEnvelope));
    }
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
    setUserKey(null);
    setUnlockPassword("");
    setUnlockConfirm("");
    setShowUnlockModal(false);
    setShowHistoryModal(false);
    setAcceptRow(null);
    setShowMembers(false);
    resetSelection();
    personalRef.current = null;
    switchingRef.current = false;
    setSwitching(false);
    setLockedReason(meta?.version ? "locked" : "new");
  };

  // Reopens the retained personal vault. After its unsaved edits were discarded, or the
  // server copy moved on under a pin upload, the in-memory copy is stale: fetch the server's.
  const openPersonal = async (): Promise<OpenedPersonal> => {
    await pinChain.current;
    const p = personalRef.current;
    if (!p) throw new Error("Vault is locked.");
    if (!p.stale) return p;
    const meta = await getJSON<VaultMetadata>("/api/vault/metadata");
    const fresh = { vault: await KeePassVault.open(await getBinary("/api/vault/kdbx"), p.key), key: p.key, version: meta.version, passwordEnvelope: meta.passwordEnvelope };
    if (personalRef.current === p) personalRef.current = fresh;
    return fresh;
  };

  // Pins live in the personal vault. While it is selected its queue saves them; otherwise
  // they upload on their own chain against the retained personal version.
  const savePersonalPins = useCallback((): Promise<void> => {
    if (selectedRef.current.kind === "personal") { queueRef.current?.changed(); return Promise.resolve(); }
    const run = pinChain.current.then(async () => {
      const p = personalRef.current;
      if (!p) return;
      if (p.stale) { setLockNotice("Your personal vault has discarded edits in this tab; the pin was not saved. Switch to My vault and try again."); return; }
      try {
        p.version = await uploadVault(await p.vault.exportBinary(), p.version, undefined, undefined, undefined, false, undefined, PERSONAL_BASE);
      } catch (err) {
        if (err instanceof HttpError && err.status === 409) {
          p.stale = true;
          setLockNotice("Your personal vault changed on the server; the pin was not saved. Switch to My vault and try again.");
        } else {
          setLockNotice(toErrorMessage(err, "Could not save the pin."));
        }
      }
    });
    pinChain.current = run.catch(() => {});
    return run;
  }, []);

  // The shared-vault flows take their world as an argument. Recomputing it whenever the
  // user key, the personal vault object or the pin saver changes is what stops a dialog
  // capturing a key from a previous unlock.
  const pinVault = personalRef.current?.vault;
  const flowDeps = useMemo<FlowDeps | null>(() => {
    if (!user || !pinVault || userKey?.kind !== "ready" || !myFingerprint) return null;
    return {
      api: sharedApi,
      pinVault,
      onPinChanged: () => { void savePersonalPins(); },
      lookupKey: (v, id) => lookupKey(v, id),
      pinKey,
      me: { id: user.id, publicKey: userKey.publicKey, seed: userKey.seed, fingerprint: myFingerprint },
    };
  }, [user, pinVault, userKey, myFingerprint, savePersonalPins]);

  const switchVault = async (target: Selected, row?: SharedVaultSummary, opts: { force?: boolean } = {}): Promise<boolean> => {
    const u = user;
    if (!u || !personalRef.current || switchingRef.current || rotatingRef.current) return false;
    switchingRef.current = true;
    setSwitching(true);
    const from = selected, queue = saveQueue, discarding = saveState.kind !== "saved" || hasDraft;
    const generation = unlockGeneration.current;
    let applied = false;
    try {
      const ok = await switchTo(target, row, {
        confirmDiscard: opts.force ? async () => true : confirmDiscardVault,
        closeQueue: () => {
          const p = personalRef.current;
          if (from.kind === "personal" && p) {
            if (queue) p.version = queue.getSnapshot().version;
            if (discarding) p.stale = true;
          }
          queue?.discard();
          setSaveQueue(null);
        },
        openShared: async (r) => {
          if (userKey?.kind !== "ready") throw new Error("Your user key is not available; reload and unlock again.");
          const o = await openShared(r, userKey.seed);
          const notices: string[] = [];
          const d = await restoreDraft(u, selectionScope({ kind: "shared", id: r.id }), o.vault, o.key, o.version, notices);
          pendingOpen.current = { dirty: d.dirty, entry: d.entry, recovered: d.recovered, notices, settle: d.settle };
          return { ...o, vault: d.vault, version: d.version };
        },
        openPersonal,
        apply: (n) => {
          applied = true;
          if (sharedKeyRef.current !== n.key) sharedKeyRef.current?.fill(0);
          sharedKeyRef.current = n.selected.kind === "shared" ? n.key : null;
          const pending = n.selected.kind === "shared" ? pendingOpen.current : null;
          pendingOpen.current = null;
          // A reader's recovered edits could never upload; keep the server copy and say so.
          const blocked = !!pending?.recovered && n.readOnly;
          if (pending?.dirty && !blocked) n.queue.recoverUnsaved();
          if (blocked) pending!.notices.unshift("This vault is read-only for you, so the recovered local edits cannot be applied. Showing the server copy.");
          draft.current = null;
          setHasDraft(false);
          setInitialDraft(blocked ? null : pending?.entry ?? null);
          setSelected(n.selected);
          setVault(n.vault);
          setVaultKey(n.key);
          setSaveQueue(n.queue);
          setReadOnly(n.readOnly);
          const id = n.selected.kind === "shared" ? n.selected.id : undefined;
          const next: Route = { tab: "vault", shared: id, entry: sameSelection(n.selected, from) ? routeRef.current.entry : undefined };
          lastVault.current = next;
          // A switch forced from another tab (lost access) does not pull the user off it.
          if (routeRef.current.tab === "vault") navigate(next);
          if (pending) {
            const current = () => generation === unlockGeneration.current;
            void pending.settle(current).then(() => {
              const text = [pending.recovered && !blocked ? "Recovered local edits. Review them before saving." : "", ...pending.notices].filter(Boolean).join(" ");
              if (text && current()) setLockNotice(text);
            });
          }
        },
        notify: (text) => { if (generation === unlockGeneration.current) setLockNotice(text); },
        generation: () => unlockGeneration.current,
      });
      // Declined: put the route back on the vault that is still open.
      if (!applied && generation === unlockGeneration.current && routeRef.current.tab === "vault") {
        navigate({ tab: "vault", shared: from.kind === "shared" ? from.id : undefined, entry: routeRef.current.entry });
      }
      return ok;
    } catch (err) {
      // Not even the personal vault reopened (its key was rotated elsewhere, or the network
      // is gone): locking is the only state left that holds no half-open vault.
      if (generation === unlockGeneration.current) {
        closeVault();
        setLockNotice(`${toErrorMessage(err, "Could not reopen your vault.")} Unlock again.`);
      }
      return false;
    } finally {
      if (generation === unlockGeneration.current) {
        switchingRef.current = false;
        setSwitching(false);
      }
    }
  };

  const sharedRow = (id: string) => shared.vaults.find((v) => v.id === id);

  // Create, then select from the list the server just gave us: the sealed copy of the key
  // that opens the new vault only exists in that row.
  const createShared = async () => {
    if (!flowDeps) return;
    const name = await dialogs.prompt({
      title: "New shared vault",
      label: "Name",
      validate: (v) => (v.trim().length >= 1 && v.trim().length <= 64 && !/[\p{Cc}\p{Cf}]/u.test(v) ? null : "1 to 64 characters, no control characters"),
    });
    if (name === null) return;
    try {
      const made = await createSharedVault(name.trim(), flowDeps);
      made.key.fill(0);
      const rows = await shared.refresh();
      await switchVault({ kind: "shared", id: made.id }, rows.find((r) => r.id === made.id));
    } catch (err) {
      setLockNotice(toErrorMessage(err, "Could not create the shared vault."));
    }
  };

  const declineShared = async (row: SharedVaultSummary) => {
    if (!(await dialogs.confirm({ title: `Decline “${row.name}”?`, message: "The invitation is removed. An owner can invite you again.", danger: true, confirmLabel: "Decline" }))) return;
    try { await sharedApi.decline(row.id); } catch (err) { setLockNotice(toErrorMessage(err, "Could not decline the invitation.")); }
    void shared.refresh();
  };

  const invitationSettled = async (row: SharedVaultSummary, accepted: boolean) => {
    setAcceptRow(null);
    const rows = await shared.refresh();
    if (accepted) await switchVault({ kind: "shared", id: row.id }, rows.find((r) => r.id === row.id));
  };

  // Route restore: once per unlock, reopen the #/shared/<id> the tab was on, after the list
  // has loaded and the user key that opens it is ready.
  useEffect(() => {
    if (!vault || switchingRef.current) return;
    const generation = unlockGeneration.current;
    const plan = restorePlan(route.shared, shared.loaded ? shared.vaults : null, userKey?.kind ?? null, restored.current === generation);
    if (plan.action === "wait") return;
    restored.current = generation;
    if (plan.action === "switch" && !sameSelection(selected, { kind: "shared", id: plan.id })) void switchVault({ kind: "shared", id: plan.id }, sharedRow(plan.id));
    else if (plan.action === "notice") { setLockNotice(plan.text); navigate({ tab: "vault" }); }
  }, [vault, shared.loaded, shared.vaults, userKey?.kind]);

  // Route follow: after the restore, a vault-tab route naming another vault switches to it.
  useEffect(() => {
    if (!vault || restored.current !== unlockGeneration.current || switchingRef.current || route.tab !== "vault") return;
    const current = selected.kind === "shared" ? selected.id : undefined;
    if (route.shared === current) return;
    const { selected: next, notice } = resolveSelection(route.shared, shared.vaults);
    if (notice) { setLockNotice(notice); navigate({ tab: "vault", shared: current }); return; }
    void switchVault(next, next.kind === "shared" ? sharedRow(next.id) : undefined);
  }, [route.tab, route.shared]);

  // A 403/404 on save means membership or role changed under us. The edits cannot be saved
  // anywhere, so there is nothing to confirm: go home and say so.
  useEffect(() => {
    if (selected.kind !== "shared" || !lostAccess(selected, saveState)) return;
    const name = sharedRow(selected.id)?.name ?? "that shared vault";
    void switchVault(personal, undefined, { force: true }).then((ok) => {
      if (ok) setLockNotice(`You no longer have write access to “${name}”; switched to My vault. Unsaved edits in that vault could not be saved.`);
      void shared.refresh();
    });
  }, [saveState, selected]);

  const autoLock = useRef(() => {});
  autoLock.current = () => {
    // A switch in flight has no queue: its discard was already confirmed, so lock with no
    // checkpoint. The open's continuation fails its generation check and zeroes its key.
    if (vault && user && !saveQueue) {
      const u = user;
      autoLock.current = () => {};
      closeVault();
      setLockNotice("Vault locked after inactivity.");
      void clearDeviceVaultKey(u.username).catch(() => { setLockNotice("Vault locked. Could not remove the cached device key; keep this tab locked until browser storage is available."); });
      return;
    }
    if (!vault || !vaultKey || !saveQueue || !user) return;
    const u = user;
    const scope = selectionScope(selected);
    // A copy: closeVault zeroes a shared key before the seal below runs.
    const key = new Uint8Array(vaultKey);
    const metadata = { version: saveQueue.getSnapshot().version, dirty: saveQueue.getSnapshot().kind !== "saved", entry: draft.current };
    const binary = metadata.dirty || metadata.entry ? saveQueue.exportBinary() : null;
    // Duplicating a browser tab copies sessionStorage. Allocate on each lock so those
    // tabs cannot overwrite one another's subsequent recovery snapshots.
    const id = draftId(u.id, scope);
    let durableReference = true;
    if (binary) {
      try { sessionStorage.setItem(`kyvault.draft:${pointerOwner(u.id, scope)}`, id); }
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
          const sealed = await sealDraft(await binary, metadata, key, draftAccount(u.id, scope));
          memoryDraft.current.set(scope, sealed);
          await draftStore(id, "put", sealed);
          setRecoveryPending(!durableReference);
          setLockNotice(durableReference
            ? "Vault locked. Your unsaved edits are encrypted on this device; unlock this tab to recover them."
            : "Vault locked. Keep this tab open and unlock to recover your edits; the browser could not save the recovery reference.");
        } else {
          memoryDraft.current.delete(scope);
        }
      } catch {
        setLockNotice(memoryDraft.current.has(scope)
          ? "Vault locked. Recovery storage failed; keep this tab open and unlock to recover your edits."
          : "Vault locked, but the recovery copy failed. Unsaved edits could not be preserved.");
      } finally { key.fill(0); await removeCachedKey; }
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
        memoryDraft.current.clear();
        const keys = user ? draftPointerKeys(user.id) : [];
        for (const k of keys) {
          let id: string | null = null;
          try { id = sessionStorage.getItem(k); } catch {}
          if (id) await draftStore(id, "delete");
        }
        try { for (const k of keys) sessionStorage.removeItem(k); } catch {}
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
            className={`ky-nav-item nav-link-btn ${navTab === "watchtower" ? "active" : ""}`}
            aria-current={navTab === "watchtower" ? "page" : undefined}
            aria-label="Watchtower"
            onClick={() => navigate({ tab: "watchtower" })}
          >
            <ShieldCheck size={16} /> <span>Watchtower</span>
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
        <>
          <VaultPage
            key={`vault:${selectionScope(selected)}`}
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
            onReload={async () => {
              // A shared vault reloads by reopening it from the server; initVault is personal-only.
              if (selected.kind === "shared") await switchVault(selected, sharedRow(selected.id), { force: true });
              else await initVault(user);
            }}
            route={route}
            navigate={navigate}
            basePath={selectionBase(selected)}
            readOnly={readOnly}
            header={<VaultSwitcher
              selected={selected}
              vaults={shared.vaults}
              onSelect={(s) => void switchVault(s, s.kind === "shared" ? sharedRow(s.id) : undefined)}
              onCreate={() => void createShared()}
              onAccept={(row) => setAcceptRow(row)}
              onDecline={(row) => void declineShared(row)}
              onMembers={() => setShowMembers(true)}
              canCreate={!!flowDeps}
              busy={switching || rotating}
              error={shared.error}
            />}
          />
          <WatchtowerPage key={`watchtower:${selectionScope(selected)}`} vault={vault} hidden={navTab !== "watchtower"} userId={user.id}
            onOpenEntry={(uuid) => navigate({ tab: "vault", shared: selected.kind === "shared" ? selected.id : undefined, entry: uuid })} />
        </>
      ) : vault && navTab === "vault" ? (
        <p role="status" style={{ padding: "2rem", textAlign: "center", color: "var(--ink-muted)" }}>Opening vault…</p>
      ) : null}
      {navTab === "admin" && user.role === "admin" ? (
        <AdminPanel currentUserId={user.id} route={route} navigate={navigate} />
      ) : vault ? (
        navTab === "security" ? <SecuritySettings
          user={user}
          vaultKey={personalRef.current?.key ?? vaultKey!}
          personalOnly={selected.kind === "personal"}
          autoLockMinutes={autoLockMinutes}
          onAutoLockChange={changeAutoLock}
          onUserUpdated={async () => { if (await confirmDiscardVault()) void checkAuth(); }}
          onForgetDevice={handleForgetDevice}
          canRotate={!unsaved && !switching}
          onExport={handleExportKdbx}
          onRotateKey={rotateKey}
          userKey={userKey}
          unlockGeneration={() => unlockGeneration.current}
          onUserKeyReplaced={(s: UserKeyState, generation: number) => { if (generation === unlockGeneration.current) setUserKey(s); }}
          pinVault={pinVault ?? null}
          onPinsChanged={() => { void savePersonalPins(); }}
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

      {acceptRow && flowDeps ? (
        <AcceptInvitationDialog key={acceptRow.id} row={acceptRow} deps={flowDeps} onDone={(accepted) => void invitationSettled(acceptRow, accepted)} />
      ) : null}

      {showMembers && flowDeps && selected.kind === "shared" ? (
        <SharedMembersDialog
          key={selected.id}
          vaultId={selected.id}
          myId={user.id}
          myRole={sharedRow(selected.id)?.role ?? "reader"}
          sharedKey={sharedKeyRef.current}
          deps={flowDeps}
          onChanged={() => { void shared.refresh(); }}
          onLeftOrDeleted={() => {
            setShowMembers(false);
            void switchVault(personal, undefined, { force: true }).then(() => { void shared.refresh(); });
          }}
          onClose={() => setShowMembers(false)}
        />
      ) : null}

      {/* History & Rollback Modal */}
      {showHistoryModal ? (
        <HistoryModal
          key={selectionScope(selected)}
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
