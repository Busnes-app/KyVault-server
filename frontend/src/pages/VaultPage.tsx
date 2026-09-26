import React, { useState, useEffect, useMemo, useRef } from "react";
import { KeePassVault, VaultEntry, VaultGroup, CustomField } from "../lib/kdbx";
import { readKdbxFile, describeImport } from "../lib/kdbxImport";
import type { EntryDraft } from "../lib/lockedDraft";
import type { SaveState } from "../lib/vaultSave";
import { createFromDraft, type NewEntryDraft } from "../lib/newEntryDraft";
import { findReusedPasswords } from "../lib/passwordReuse";
import { parseTags, hasReservedTag, sortEntries, entryMatches, isExpired, expiresWithin, RESERVED_FIELDS, type SortKey } from "../lib/entryMeta";
import { generateTOTP } from "../lib/totp";
import { safeHref } from "../lib/safeHref";
import { copyText, SECRET_CLIPBOARD_MS } from "../lib/clipboard";
import { PasswordGenerator } from "../components/PasswordGenerator";
import { DevicePairingModal } from "../components/DevicePairingModal";
import { HistoryModal } from "../components/HistoryModal";
import { EntryHistoryModal } from "../components/EntryHistoryModal";
import { EntryAttachments } from "../components/EntryAttachments";
import { CsvImportModal } from "../components/CsvImportModal";
import { exportCsv } from "../lib/csvExport";
import { downloadBlob } from "../lib/download";
import { useDialogs } from "../components/DialogHost";
import type { Route } from "../lib/route";
import { useMediaQuery, NARROW } from "../lib/useMediaQuery";
import {
  Folder,
  Plus,
  Search,
  Key,
  Copy,
  Eye,
  EyeOff,
  ExternalLink,
  Trash2,
  Save,
  Download,
  History,
  QrCode,
  Check,
  Clock,
  Shield,
  RefreshCw,
  FileSpreadsheet,
  Upload,
  CheckCircle2,
  AlertCircle,
  ChevronLeft,
  Star,
  X,
} from "lucide-react";

type Props = {
  vault: KeePassVault;
  vaultKey: Uint8Array;
  vaultVersion: number;
  saveState: SaveState;
  onChanged: () => void;
  onDraftChange: (draft: EntryDraft | null) => void;
  initialDraft?: EntryDraft | null;
  hidden: boolean;
  onSave: (options?: { overwrite?: boolean }) => Promise<void>;
  onExport: () => void;
  onReload: () => Promise<void>;
  route: Route;
  navigate: (next: Route) => void;
};

export function VaultPage({ vault, vaultKey, vaultVersion, onSave, onExport, onReload, saveState, onChanged, onDraftChange, hidden, initialDraft, route, navigate }: Props) {
  const dialogs = useDialogs();
  const narrow = useMediaQuery(NARROW);
  const [pane, setPane] = useState<"folders" | "list" | "detail">(initialDraft ? "detail" : "list");
  const [groups, setGroups] = useState<VaultGroup[]>([]);
  const [selectedGroupUuid, setSelectedGroupUuid] = useState<string>("all");
  const [recycledIds, setRecycledIds] = useState<Set<string>>(new Set());
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [selectedEntryUuid, setSelectedEntryUuid] = useState<string | null>(initialDraft?.uuid ?? null);
  const [newDraft, setNewDraft] = useState<NewEntryDraft | null>(null);
  const pendingDraft = useRef(initialDraft);
  const importFileInputRef = useRef<HTMLInputElement>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showReusedPasswords, setShowReusedPasswords] = useState(false);
  const [showFavorites, setShowFavorites] = useState(false);
  const [showExpiring, setShowExpiring] = useState(false);
  const [reusedPasswords, setReusedPasswords] = useState<Map<string, number>>(new Map());
  const [sortKey, setSortKey] = useState<SortKey>(() => {
    const stored = localStorage.getItem("kyvault.sort");
    return stored === "modified" || stored === "expiry" ? stored : "title";
  });

  // Editor State
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState("");
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [editTotp, setEditTotp] = useState("");
  const [editGroupUuid, setEditGroupUuid] = useState("");
  const [editTags, setEditTags] = useState("");
  const [editFavorite, setEditFavorite] = useState(false);
  const [editExpires, setEditExpires] = useState("");
  const [editCustom, setEditCustom] = useState<CustomField[]>([]);
  const [revealedCustom, setRevealedCustom] = useState<Set<number>>(new Set());
  const reservedCustomFieldName = editCustom.find((f) => RESERVED_FIELDS.has(f.name.trim()))?.name;
  const tagsHasReservedWord = hasReservedTag(editTags);

  // UI Modals & Helpers
  const [showGenerator, setShowGenerator] = useState(false);
  const [showPairing, setShowPairing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showEntryHistory, setShowEntryHistory] = useState(false);
  const [showCsvImport, setShowCsvImport] = useState(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [revealPassword, setRevealPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const saving = saveState.kind === "saving";

  // TOTP live state
  const [totpCode, setTotpCode] = useState<string | null>(null);
  const [totpRemaining, setTotpRemaining] = useState<number>(30);

  const refreshVaultData = () => {
    const grps = vault.getLiveGroups();
    const ents = vault.getEntries();
    setGroups(grps);
    setEntries(ents);
    setRecycledIds(new Set(vault.getRecycledEntries().map(entry => entry.uuid)));
    setReusedPasswords(findReusedPasswords(vault));
    if (!selectedEntryUuid) {
      setSelectedEntryUuid(vault.getLiveEntries()[0]?.uuid ?? null);
    }
  };

  useEffect(() => {
    refreshVaultData();
  }, [vault]);

  const selectedEntry = useMemo(() => {
    return entries.find((e) => e.uuid === selectedEntryUuid) || null;
  }, [entries, selectedEntryUuid]);

  // The expiry date input holds a calendar date (YYYY-MM-DD); it is stored/compared as
  // midnight UTC on that date, not the browser's local midnight.
  const entryExpiresString = (entry: VaultEntry) => entry.expiresAt ? entry.expiresAt.toISOString().slice(0, 10) : "";
  const entryTagsString = (entry: VaultEntry) => entry.tags.filter((t) => t.toLowerCase() !== "favorite").join(", ");
  const customFieldsEqual = (a: CustomField[], b: CustomField[]) =>
    a.length === b.length && a.every((f, i) => f.name === b[i].name && f.value === b[i].value && f.protected === b[i].protected);

  const draftDirty = isEditing && (
    newDraft
      ? Boolean(editTitle || editUsername || editPassword || editUrl || editNotes || editTotp || editGroupUuid !== newDraft.groupUuid ||
          editTags || editFavorite || editExpires || editCustom.length > 0)
      : selectedEntry !== null && (
          editTitle !== selectedEntry.title || editUsername !== selectedEntry.username ||
          editPassword !== selectedEntry.password || editUrl !== selectedEntry.url ||
          editNotes !== selectedEntry.notes || editTotp !== (selectedEntry.totpSeed || "") ||
          editGroupUuid !== selectedEntry.groupUuid ||
          editTags !== entryTagsString(selectedEntry) || editFavorite !== selectedEntry.favorite ||
          editExpires !== entryExpiresString(selectedEntry) || !customFieldsEqual(editCustom, selectedEntry.custom)
        )
  );
  // A never-applied new entry has no uuid, so the auto-lock checkpoint (which is keyed by
  // uuid) can't hold it; its fields are lost on auto-lock, which is accepted since nothing
  // was created yet. draftDirty stays true so canChangeEntry still asks before discarding it.
  useEffect(() => { onDraftChange(draftDirty && selectedEntryUuid ? {
    uuid: selectedEntryUuid, title: editTitle, username: editUsername, password: editPassword,
    url: editUrl, notes: editNotes, totpSeed: editTotp, groupUuid: editGroupUuid,
    tags: parseTags(editTags), favorite: editFavorite, expiresAt: editExpires || null, custom: editCustom,
  } : null); }, [draftDirty, selectedEntryUuid, editTitle, editUsername, editPassword, editUrl, editNotes, editTotp, editGroupUuid,
    editTags, editFavorite, editExpires, editCustom, onDraftChange]);
  const canChangeEntry = async () => !draftDirty || await dialogs.confirm({
    title: "Discard unsaved edits?",
    message: "Discard unapplied entry edits?",
    confirmLabel: "Discard",
    danger: true,
  });

  // The editor stays mounted across tabs, so ignore route changes while another tab is active.
  useEffect(() => {
    if (newDraft) return; // draft has no route entry; do not let this effect close it
    if (route.tab !== "vault" || route.entry === selectedEntryUuid) return;
    if (route.entry && !entries.some((e) => e.uuid === route.entry)) return;
    if (route.entry && recycledIds.has(route.entry)) { navigate({ tab: "vault" }); return; }
    (async () => {
      if (await canChangeEntry()) {
        setIsEditing(false);
        setSelectedEntryUuid(route.entry ?? null);
        setPane(route.entry ? "detail" : "list");
      } else {
        navigate({ tab: "vault", entry: selectedEntryUuid ?? undefined });
      }
    })();
  }, [route.tab, route.entry, entries, recycledIds, selectedEntryUuid, newDraft]);

  // Load selected entry into editor
  const loadEditor = () => {
    if (selectedEntry) {
      const recovered = pendingDraft.current;
      setRevealedCustom(new Set());
      if (recovered?.uuid === selectedEntry.uuid) {
        pendingDraft.current = null;
        setEditTitle(recovered.title); setEditUsername(recovered.username); setEditPassword(recovered.password);
        setEditUrl(recovered.url); setEditNotes(recovered.notes); setEditTotp(recovered.totpSeed);
        setEditGroupUuid(recovered.groupUuid);
        setEditTags(recovered.tags.filter((t) => t.toLowerCase() !== "favorite").join(", "));
        setEditFavorite(recovered.favorite);
        setEditExpires(recovered.expiresAt ? recovered.expiresAt.slice(0, 10) : "");
        setEditCustom(recovered.custom);
        setIsEditing(true); setRevealPassword(false);
        return;
      }
      setEditTitle(selectedEntry.title);
      setEditUsername(selectedEntry.username);
      setEditPassword(selectedEntry.password);
      setEditUrl(selectedEntry.url);
      setEditNotes(selectedEntry.notes);
      setEditTotp(selectedEntry.totpSeed || "");
      setEditGroupUuid(selectedEntry.groupUuid);
      setEditTags(entryTagsString(selectedEntry));
      setEditFavorite(selectedEntry.favorite);
      setEditExpires(entryExpiresString(selectedEntry));
      setEditCustom(selectedEntry.custom);
      setRevealPassword(false);
    }
  };
  useEffect(loadEditor, [vault, selectedEntry?.uuid]);
  useEffect(() => { if (hidden) setShowEntryHistory(false); }, [hidden]);

  // Live TOTP ticker
  useEffect(() => {
    if (!selectedEntry?.totpSeed) {
      setTotpCode(null);
      return;
    }

    let active = true;
    const update = async () => {
      if (!selectedEntry.totpSeed) return;
      const res = await generateTOTP(selectedEntry.totpSeed);
      if (active) {
        setTotpCode(res.code);
        setTotpRemaining(res.secondsRemaining);
      }
    };

    update();
    const interval = setInterval(update, 1000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [selectedEntry?.totpSeed]);

  const copyToClipboard = async (text: string, field: string) => {
    const secret = field === "pass" || field === "totp";
    const ok = await copyText(text, secret ? { clearAfterMs: SECRET_CLIPBOARD_MS } : {});
    setCopiedField(ok ? field : null);
    if (!ok) setImportError("Could not copy. Your browser blocked clipboard access.");
    if (ok) setTimeout(() => setCopiedField(null), 2000);
  };

  // The chosen calendar date is stored/compared as midnight UTC on that date, not the
  // browser's local midnight, so it round-trips to the same "YYYY-MM-DD" everywhere.
  const parseExpires = (value: string): Date | undefined => value ? new Date(value + "T00:00:00Z") : undefined;

  const handleSaveEntry = () => {
    if (reservedCustomFieldName) return;
    if (newDraft) {
      const entry = createFromDraft(vault, { groupUuid: editGroupUuid }, {
        title: editTitle, username: editUsername, password: editPassword,
        url: editUrl, notes: editNotes, totpSeed: editTotp,
        tags: parseTags(editTags), favorite: editFavorite, expiresAt: parseExpires(editExpires), custom: editCustom,
      });
      onChanged();
      refreshVaultData();
      setNewDraft(null);
      setIsEditing(false);
      setSelectedEntryUuid(entry.uuid);
      navigate({ tab: "vault", entry: entry.uuid });
      return;
    }
    if (!selectedEntryUuid) return;
    const changed = vault.updateEntry({
      uuid: selectedEntryUuid,
      title: editTitle,
      username: editUsername,
      password: editPassword,
      url: editUrl,
      notes: editNotes,
      totpSeed: editTotp,
      groupUuid: editGroupUuid,
      updatedAt: new Date(),
      tags: parseTags(editTags),
      favorite: editFavorite,
      expiresAt: parseExpires(editExpires),
      custom: editCustom,
    });
    if (changed) onChanged();
    setIsEditing(false);
    refreshVaultData();
  };

  const handleCancelEdit = () => {
    if (newDraft) {
      setNewDraft(null);
      setIsEditing(false);
      setPane("list");
      return;
    }
    loadEditor();
    setIsEditing(false);
  };

  // The vault stays untouched until Apply creates the entry, so Cancel leaves no entry
  // and no save revision behind.
  const handleCreateNewEntry = async () => {
    if (!await canChangeEntry()) return;
    const groupUuid = selectedGroupUuid === "all" || selectedGroupUuid === "recycle" ? groups[0]?.uuid || "" : selectedGroupUuid;
    if (selectedGroupUuid === "recycle") setSelectedGroupUuid("all");
    setSelectedEntryUuid(null);
    setNewDraft({ groupUuid });
    navigate({ tab: "vault" });
    setPane("detail");
    setEditTitle(""); setEditUsername(""); setEditPassword(""); setEditUrl(""); setEditNotes(""); setEditTotp("");
    setEditGroupUuid(groupUuid);
    setEditTags(""); setEditFavorite(false); setEditExpires(""); setEditCustom([]);
    setRevealPassword(false);
    setIsEditing(true);
  };

  const handleDeleteEntry = async () => {
    if (!selectedEntryUuid) return;
    const permanent = !vault.recyclingEnabled;
    const message = permanent ? "Recycling is disabled for this vault. Permanently delete this entry from the current vault? Existing snapshots and backups may still contain it." :
      "Move this entry to the Recycle Bin?";
    const ok = await dialogs.confirm({
      title: permanent ? "Delete permanently?" : "Move to Recycle Bin?",
      message,
      confirmLabel: permanent ? "Delete" : "Move",
      danger: permanent,
    });
    if (!ok) return;
    vault.deleteEntry(selectedEntryUuid);
    onChanged();
    setSelectedEntryUuid(null);
    navigate({ tab: "vault", entry: undefined });
    setPane("list");
    refreshVaultData();
  };

  const handleRestoreEntry = async () => {
    if (!selectedEntryUuid) return;
    try {
      vault.restoreEntry(selectedEntryUuid);
      onChanged();
      refreshVaultData();
      setSelectedGroupUuid("all");
      clearSmartViews();
    } catch (error) {
      await dialogs.notify({ title: "Entry not restored", message: error instanceof Error ? error.message : "Unable to restore entry." });
    }
  };

  // Folders drive the selection: switching folders clears an open entry (or draft) that
  // does not belong to the newly chosen folder, so the detail pane never shows a stale entry.
  const selectFolder = async (uuid: string) => {
    if (!await canChangeEntry()) return;
    setIsEditing(false);
    setNewDraft(null);
    const inFolder = selectedEntry ? (
      uuid === "recycle" ? recycledIds.has(selectedEntry.uuid) :
      uuid === "all" ? !recycledIds.has(selectedEntry.uuid) :
      !recycledIds.has(selectedEntry.uuid) && selectedEntry.groupUuid === uuid
    ) : true;
    if (!inFolder) {
      setSelectedEntryUuid(null);
      navigate({ tab: "vault", entry: undefined });
    }
    setSelectedGroupUuid(uuid);
    if (uuid === "recycle") clearSmartViews();
    setPane("list");
  };

  const selectedFolder = groups.find(group => group.uuid === selectedGroupUuid);
  const handleCreateGroup = async () => {
    const name = await dialogs.prompt({
      title: "New folder",
      label: selectedFolder ? `New subfolder in "${selectedFolder.path}"` : "New folder name",
      validate: (v) => v.trim() ? null : "Enter a folder name.",
    });
    if (name === null) return;
    try {
      vault.createGroup(name, selectedFolder?.uuid);
      onChanged();
      refreshVaultData();
    } catch (error) {
      await dialogs.notify({ title: "Folder not created", message: error instanceof Error ? error.message : "Unable to create folder." });
    }
  };

  const handleRenameGroup = async () => {
    if (!selectedFolder) return;
    const name = await dialogs.prompt({
      title: "Rename folder",
      label: "Folder name",
      defaultValue: selectedFolder.name,
      validate: (v) => v.trim() ? null : "Enter a folder name.",
    });
    if (name === null) return;
    try {
      if (vault.renameGroup(selectedFolder.uuid, name)) {
        onChanged();
        refreshVaultData();
      }
    } catch (error) {
      await dialogs.notify({ title: "Folder not renamed", message: error instanceof Error ? error.message : "Unable to rename folder." });
    }
  };

  // Folder names may contain "/", so descendants must be found by walking parentUuid
  // links rather than matching on rendered path strings.
  const isDescendant = (uuid: string, ancestor: string): boolean => {
    const byId = new Map(groups.map((g) => [g.uuid, g]));
    for (let cur = byId.get(uuid); cur; cur = cur.parentUuid ? byId.get(cur.parentUuid) : undefined) {
      if (cur.uuid === ancestor) return true;
    }
    return false;
  };

  const handleMoveGroup = async () => {
    if (!selectedFolder) return;
    const root = groups[0];
    const options = [
      { value: root.uuid, label: root.name },
      ...groups.filter((g) => g.uuid !== root.uuid && g.uuid !== selectedFolder.uuid &&
        !isDescendant(g.uuid, selectedFolder.uuid)).map((g) => ({ value: g.uuid, label: g.path })),
    ];
    const target = await dialogs.choose({
      title: "Move folder",
      label: "Move into",
      options,
      defaultValue: selectedFolder.parentUuid,
    });
    if (target === null) return;
    try {
      if (vault.moveGroup(selectedFolder.uuid, target)) {
        onChanged();
        refreshVaultData();
      }
    } catch (error) {
      await dialogs.notify({ title: "Folder not moved", message: error instanceof Error ? error.message : "Unable to move folder." });
    }
  };

  const handleDeleteGroup = async () => {
    if (!selectedFolder) return;
    const subtreeIds = new Set(groups.filter((g) => g.uuid === selectedFolder.uuid ||
      isDescendant(g.uuid, selectedFolder.uuid)).map((g) => g.uuid));
    const count = entries.filter((e) => !recycledIds.has(e.uuid) && subtreeIds.has(e.groupUuid)).length;
    const recycling = vault.recyclingEnabled;
    const ok = await dialogs.confirm({
      title: recycling ? "Move folder to Recycle Bin?" : "Delete folder permanently?",
      message: `"${selectedFolder.name}" and its ${count} entries ${recycling ? "move to the Recycle Bin" :
        "are removed from the current vault. Existing snapshots and backups may still contain them"}.`,
      confirmLabel: recycling ? "Move" : "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      vault.deleteGroup(selectedFolder.uuid);
      if (selectedEntry && subtreeIds.has(selectedEntry.groupUuid)) {
        setSelectedEntryUuid(null);
        navigate({ tab: "vault", entry: undefined });
      }
      setSelectedGroupUuid("all");
      onChanged();
      refreshVaultData();
    } catch (error) {
      await dialogs.notify({ title: "Folder not deleted", message: error instanceof Error ? error.message : "Unable to delete folder." });
    }
  };

  const handleImportKeePassFile = async (file: File) => {
    let buffer: ArrayBuffer;
    try {
      buffer = await readKdbxFile(file);
    } catch (error) {
      await dialogs.notify({ title: "File not imported", message: error instanceof Error ? error.message : "Unable to read this file." });
      return;
    }
    const password = await dialogs.prompt({
      title: "Open the KeePass file",
      label: "Its master password",
      secret: true,
      validate: (v) => v ? null : "Enter the master password.",
    });
    if (password === null) return;
    let foreign: KeePassVault;
    try {
      foreign = await KeePassVault.openForeign(buffer, password);
    } catch {
      await dialogs.notify({ title: "File not imported", message: "Could not open this file. Check the password; key files are not supported yet." });
      return;
    }
    const target = await dialogs.choose({
      title: "Import into",
      label: "Add under",
      options: [{ value: "", label: "New folder named after the file" }, ...groups.map((g) => ({ value: g.uuid, label: g.path }))],
      defaultValue: "",
    });
    if (target === null) return;
    try {
      const report = vault.importFrom(foreign, target || undefined);
      onChanged();
      refreshVaultData();
      setImportError(null);
      setImportMessage(describeImport(report));
    } catch (error) {
      await dialogs.notify({ title: "File not imported", message: error instanceof Error ? error.message : "Unable to import this file." });
    }
  };

  const handleExportCsv = async () => {
    const ok = await dialogs.confirm({
      title: "Export passwords as plain text?",
      message: "The CSV contains every password and TOTP secret unencrypted. Save it only to a device you control and delete it when you are done.",
      confirmLabel: "Export",
      danger: true,
    });
    if (!ok) return;
    const pathMap = new Map(vault.getLiveGroups().map((g) => [g.uuid, g.path]));
    downloadBlob(new Blob([exportCsv(vault.getLiveEntries(), pathMap)], { type: "text/csv" }), "vault-export.csv");
  };

  const filteredEntries = useMemo(() => {
    const smartFiltered = entries.filter((e) => {
      const matchesGroup =
        selectedGroupUuid === "recycle" ? recycledIds.has(e.uuid) :
        !recycledIds.has(e.uuid) && (
          showReusedPasswords ? reusedPasswords.has(e.uuid) :
          showFavorites ? e.favorite :
          showExpiring ? expiresWithin(e, 7) :
          selectedGroupUuid === "all" || e.groupUuid === selectedGroupUuid);
      const matchesSearch = entryMatches(e, searchQuery);
      return matchesGroup && matchesSearch;
    });
    return sortEntries(smartFiltered, sortKey);
  }, [entries, selectedGroupUuid, searchQuery, showReusedPasswords, showFavorites, showExpiring, reusedPasswords, recycledIds, sortKey]);

  const selectSmartView = (view: "reused" | "favorites" | "expiring", checked: boolean) => {
    setShowReusedPasswords(view === "reused" && checked);
    setShowFavorites(view === "favorites" && checked);
    setShowExpiring(view === "expiring" && checked);
  };
  const clearSmartViews = () => { setShowReusedPasswords(false); setShowFavorites(false); setShowExpiring(false); };

  const changeSortKey = (key: SortKey) => {
    setSortKey(key);
    localStorage.setItem("kyvault.sort", key);
  };

  return (
    <div className={`vault-layout${narrow ? " vault-layout--narrow" : ""}`} data-pane={pane} style={hidden ? { display: "none" } : undefined}>
      {/* 1. Sidebar Folders */}
      <aside className="vault-sidebar">
        <div className="sidebar-header">
          <span style={{ fontWeight: 600, fontSize: "0.85rem", textTransform: "uppercase", color: "var(--ink)" }}>
            Folders
          </span>
          <div style={{ display: "flex", gap: "0.25rem" }}>
            <button type="button" className="btn btn-quiet btn-sm" onClick={handleCreateGroup}
              title={selectedFolder ? "Add Subfolder" : "Add Folder"} aria-label={selectedFolder ? "Add Subfolder" : "Add Folder"}>
              <Plus size={16} />
            </button>
            <button type="button" className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Close folders"
              onClick={() => setPane("list")}>
              <ChevronLeft size={16} />
            </button>
          </div>
        </div>

        <button type="button"
          className={`group-item ${selectedGroupUuid === "all" ? "active" : ""}`}
          aria-pressed={selectedGroupUuid === "all"}
          onClick={() => void selectFolder("all")}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Shield size={16} />
            <span>All Items</span>
          </div>
          <span className="font-mono" style={{ fontSize: "0.75rem" }}>
            {entries.length - recycledIds.size}
          </span>
        </button>

        <button type="button" className={`group-item ${selectedGroupUuid === "recycle" ? "active" : ""}`}
          aria-pressed={selectedGroupUuid === "recycle"}
          onClick={() => void selectFolder("recycle")}>
          <span style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}><Trash2 size={16} /> Recycle Bin</span>
          <span>{recycledIds.size}</span>
        </button>

        {selectedFolder ? (
          <div style={{ display: "flex", gap: "0.25rem" }}>
            <button type="button" className="btn btn-quiet btn-sm" onClick={handleRenameGroup}>Rename Folder</button>
            <button type="button" className="btn btn-quiet btn-sm" onClick={handleMoveGroup}>Move Folder</button>
            <button type="button" className="btn btn-quiet btn-sm" onClick={handleDeleteGroup}>Delete Folder</button>
          </div>
        ) : null}

        {groups.map((g) => (
          <button type="button"
            key={g.uuid}
            className={`group-item ${selectedGroupUuid === g.uuid ? "active" : ""}`}
            title={g.path}
            aria-label={g.path} aria-pressed={selectedGroupUuid === g.uuid}
            style={{ paddingLeft: `${1 + Math.min(g.depth, 6) * 0.75}rem` }}
            onClick={() => void selectFolder(g.uuid)}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Folder size={16} />
              <span style={{ overflowWrap: "anywhere", textAlign: "left" }}>{g.name}</span>
            </div>
            <span className="font-mono" style={{ fontSize: "0.75rem" }}>
              {entries.filter((e) => e.groupUuid === g.uuid).length}
            </span>
          </button>
        ))}

        <div style={{ marginTop: "auto", padding: "1rem", borderTop: "1px solid var(--line)" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <button className="btn btn-primary btn-sm" onClick={() => setShowCsvImport(true)}>
              <FileSpreadsheet size={14} /> Import CSV Passwords
            </button>
            <input ref={importFileInputRef} type="file" accept=".kdbx" style={{ display: "none" }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (file) void handleImportKeePassFile(file);
              }} />
            <button className="btn btn-secondary btn-sm" onClick={() => importFileInputRef.current?.click()}>
              <Upload size={14} /> Import KeePass file
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowPairing(true)}>
              <QrCode size={14} /> Pair Extension / Mobile
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowHistory(true)} disabled={saveState.kind !== "saved" || draftDirty}>
              <History size={14} /> Version History (v{vaultVersion})
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onExport} disabled={saving}>
              <Download size={14} /> Download .kdbx
            </button>
            <button className="btn btn-secondary btn-sm" onClick={() => void handleExportCsv()}>
              <FileSpreadsheet size={14} /> Export CSV
            </button>
          </div>
        </div>
      </aside>

      {/* 2. Middle List Pane */}
      <section className="vault-list-pane">
        <div className="list-search-bar">
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
            <button type="button" className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Folders"
              onClick={() => setPane("folders")}>
              <Folder size={16} />
            </button>
            <div style={{ position: "relative", flex: 1 }}>
              <Search
                size={16}
                color="var(--ink-muted)"
                style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)" }}
              />
              <input
                type="text"
                className="input"
                style={{ paddingLeft: "2.2rem" }}
                placeholder="Search passwords…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button className="btn btn-primary" onClick={handleCreateNewEntry} title="Add Entry">
              <Plus size={16} />
            </button>
          </div>

          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.5rem" }}>
            <label className="input-label" htmlFor="vault-sort" style={{ margin: 0 }}>Sort</label>
            <select id="vault-sort" className="select" value={sortKey} onChange={(e) => changeSortKey(e.target.value as SortKey)}>
              <option value="title">Title</option>
              <option value="modified">Last modified</option>
              <option value="expiry">Expiry</option>
            </select>
          </div>

          <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input type="checkbox" disabled={selectedGroupUuid === "recycle"} checked={showReusedPasswords}
              onChange={(event) => selectSmartView("reused", event.target.checked)} />
            Reused passwords ({reusedPasswords.size})
          </label>
          <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input type="checkbox" disabled={selectedGroupUuid === "recycle"} checked={showFavorites}
              onChange={(event) => selectSmartView("favorites", event.target.checked)} />
            Favourites ({entries.filter((e) => e.favorite && !recycledIds.has(e.uuid)).length})
          </label>
          <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input type="checkbox" disabled={selectedGroupUuid === "recycle"} checked={showExpiring}
              onChange={(event) => selectSmartView("expiring", event.target.checked)} />
            Expiring ({entries.filter((e) => !recycledIds.has(e.uuid) && expiresWithin(e, 7)).length})
          </label>
          {selectedGroupUuid === "recycle" ? <p style={{ fontSize: "0.8rem", color: "var(--ink-muted)" }}>
            Deleted entries are kept here. Restore returns an entry to the vault’s top-level folder.
          </p> : null}
          {showReusedPasswords ? (
            <p style={{ fontSize: "0.8rem", color: "var(--ink-muted)" }}>
              Across all live folders. Checked only in this browser after Apply Edits.
              Change each affected account’s password on its website, then update the vault.
            </p>
          ) : null}

          {importMessage ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                background: "var(--success-soft)",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                padding: "0.5rem 0.75rem",
                borderRadius: "6px",
                fontSize: "0.8rem",
                marginBottom: "0.5rem",
                color: "var(--success)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <CheckCircle2 size={14} />
                <span>{importMessage}</span>
              </div>
              <button
                className="btn btn-quiet btn-sm"
                style={{ padding: "0.1rem 0.3rem" }}
                onClick={() => setImportMessage(null)}
              >
                ✕
              </button>
            </div>
          ) : null}

          {importError ? (
            <div
              role="alert"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                background: "var(--danger-soft)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                padding: "0.5rem 0.75rem",
                borderRadius: "6px",
                fontSize: "0.8rem",
                marginBottom: "0.5rem",
                color: "var(--danger)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <AlertCircle size={14} />
                <span>{importError}</span>
              </div>
              <button
                className="btn btn-quiet btn-sm"
                style={{ padding: "0.1rem 0.3rem" }}
                onClick={() => setImportError(null)}
              >
                ✕
              </button>
            </div>
          ) : null}

          <div role={saveState.kind === "error" ? "alert" : "status"} style={{ padding: "0.5rem", fontSize: "0.85rem" }}>
            {saveState.kind === "error" ? (
              <>
                <p style={{ color: "var(--danger)" }}>Unsaved edits: {saveState.message}</p>
                {saveState.conflict ? (
                  <>
                    <button className="btn btn-danger btn-sm" onClick={() => void onSave({ overwrite: true })}>Overwrite server copy</button>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={async () => { if (await dialogs.confirm({ title: "Reload server copy?", message: "Discard the unsaved edits in this tab and reload the server copy?", confirmLabel: "Reload", danger: true })) void onReload(); }}
                    >
                      Reload server copy
                    </button>
                  </>
                ) : (
                  <button className="btn btn-primary btn-sm" onClick={() => void onSave()}>Retry Save</button>
                )}
              </>
            ) : <span>{saving ? "Saving…" : draftDirty ? "Applied changes saved" : "All changes saved"}</span>}
            {draftDirty ? <p>Entry edits have not been applied.</p> : null}
          </div>
        </div>

        <ul className="entry-list">
          {filteredEntries.length === 0 ? (
            <li style={{ padding: "2.5rem 1rem", textAlign: "center", color: "var(--ink-muted)", fontSize: "0.9rem" }}>
              <p style={{ marginBottom: "1rem" }}>{showReusedPasswords ? "No reused passwords match this search." : "No entries found."}</p>
              <button
                className="btn btn-secondary btn-sm"
                style={{ margin: "0 auto" }}
                onClick={() => setShowCsvImport(true)}
              >
                <FileSpreadsheet size={14} /> Import from CSV
              </button>
            </li>
          ) : (
            filteredEntries.map((e) => (
              <li
                key={e.uuid}
                className={`entry-item ${selectedEntryUuid === e.uuid ? "active" : ""}`}
                onClick={async () => { if (await canChangeEntry()) { setIsEditing(false); setNewDraft(null); setSelectedEntryUuid(e.uuid); navigate({ tab: "vault", entry: e.uuid }); setPane("detail"); } }}
              >
                <div className="entry-title">
                  {e.favorite ? <Star size={14} fill="var(--warning)" color="var(--warning)" aria-label="Favourite" /> : null}
                  <span>{e.title || "Untitled"}</span>
                  {reusedPasswords.has(e.uuid) ? <span className="badge badge-cyan">Shared by {reusedPasswords.get(e.uuid)} entries</span> : null}
                  {e.totpSeed ? <span className="badge badge-cyan">2FA</span> : null}
                  {isExpired(e) ? <span className="badge badge-danger">Expired</span> :
                    expiresWithin(e, 7) ? <span className="badge badge-warning">Expires soon</span> : null}
                </div>
                <div className="entry-subtitle">
                  {e.username || (e.url ? e.url.replace(/^https?:\/\//, "") : "No username")}
                </div>
                {e.tags.filter((t) => t.toLowerCase() !== "favorite").length > 0 ? (
                  <div className="tag-chips">
                    {e.tags.filter((t) => t.toLowerCase() !== "favorite").slice(0, 3).map((t) => (
                      <span key={t} className="tag-chip">{t}</span>
                    ))}
                  </div>
                ) : null}
              </li>
            ))
          )}
        </ul>
      </section>

      {/* 3. Detail & Editor Pane */}
      <main className="vault-detail-pane">
        {selectedEntry || newDraft ? (
          <div>
            <div className="detail-header">
              <button type="button" className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Back to list"
                onClick={() => setPane("list")}>
                <ChevronLeft size={16} />
              </button>
              <div>
                <h2 style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  {!isEditing && selectedEntry?.favorite ? <Star size={18} fill="var(--warning)" color="var(--warning)" aria-label="Favourite" /> : null}
                  {newDraft ? "New entry" : isEditing ? "Edit Entry" : selectedEntry!.title || "Untitled"}
                </h2>
                {selectedEntry ? <span style={{ color: "var(--ink-muted)", fontSize: "0.8rem" }}>
                  Last modified: {new Date(selectedEntry.updatedAt).toLocaleString()}
                </span> : null}
                {!isEditing && selectedEntry && isExpired(selectedEntry) ? <span className="badge badge-danger" style={{ marginLeft: "0.5rem" }}>Expired</span> :
                  !isEditing && selectedEntry && expiresWithin(selectedEntry, 7) ? <span className="badge badge-warning" style={{ marginLeft: "0.5rem" }}>Expires soon</span> : null}
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                {!isEditing && selectedEntry ? <button className="btn btn-secondary" onClick={() => setShowEntryHistory(true)}>
                  <History size={16} /> Entry History
                </button> : null}
                {selectedEntry && recycledIds.has(selectedEntry.uuid) ? (
                  <button className="btn btn-primary" onClick={handleRestoreEntry}>Restore to vault</button>
                ) : isEditing ? (
                  <>
                    <button className="btn btn-secondary" onClick={handleCancelEdit}>
                      Cancel
                    </button>
                    <button className="btn btn-primary" onClick={handleSaveEntry} disabled={!!reservedCustomFieldName}>
                      <Save size={16} /> Apply Edits
                    </button>
                  </>
                ) : (
                  <>
                    <button className="btn btn-secondary" onClick={() => { loadEditor(); setIsEditing(true); }}>
                      Edit
                    </button>
                    <button className="btn btn-danger btn-sm" onClick={handleDeleteEntry} title="Delete">
                      <Trash2 size={16} />
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Title & Group */}
            <div className="field-card">
              <div className="input-group" style={{ marginBottom: isEditing ? "1rem" : 0 }}>
                <label className="input-label">Title</label>
                {isEditing ? (
                  <input
                    type="text"
                    className="input"
                    value={editTitle}
                    onChange={(e) => setEditTitle(e.target.value)}
                  />
                ) : (
                  <div style={{ fontSize: "1.1rem", fontWeight: 600 }}>{selectedEntry!.title}</div>
                )}
              </div>

              {isEditing ? (
                <div className="input-group" style={{ marginBottom: 0 }}>
                  <label className="input-label">Folder</label>
                  <select
                    className="select"
                    value={editGroupUuid}
                    onChange={(e) => setEditGroupUuid(e.target.value)}
                  >
                    {groups.map((g) => (
                      <option key={g.uuid} value={g.uuid}>
                        {g.path}
                      </option>
                    ))}
                  </select>
                </div>
              ) : null}
            </div>

            {/* Username Field */}
            <div className="field-card">
              <label className="input-label">Username / Email</label>
              {isEditing ? (
                <input
                  type="text"
                  className="input font-mono"
                  value={editUsername}
                  onChange={(e) => setEditUsername(e.target.value)}
                />
              ) : (
                <div className="field-row">
                  <span className="font-mono">{selectedEntry!.username || "—"}</span>
                  {selectedEntry!.username ? (
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => copyToClipboard(selectedEntry!.username, "user")}
                      title="Copy Username"
                    >
                      {copiedField === "user" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                    </button>
                  ) : null}
                </div>
              )}
            </div>

            {/* Password Field */}
            <div className="field-card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
                <label className="input-label" style={{ margin: 0 }}>Password</label>
                {isEditing ? (
                  <button
                    type="button"
                    className="btn btn-quiet btn-sm"
                    onClick={() => setShowGenerator(true)}
                  >
                    <Key size={14} /> Generate
                  </button>
                ) : null}
              </div>

              {isEditing ? (
                <div style={{ position: "relative" }}>
                  <input
                    type={revealPassword ? "text" : "password"}
                    className="input font-mono"
                    value={editPassword}
                    onChange={(e) => setEditPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn btn-quiet btn-sm"
                    style={{ position: "absolute", right: "0.5rem", top: "50%", transform: "translateY(-50%)" }}
                    onClick={() => setRevealPassword(!revealPassword)}
                  >
                    {revealPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              ) : (
                <div className="field-row">
                  <span className="font-mono">
                    {revealPassword ? selectedEntry!.password : "••••••••••••••••"}
                  </span>
                  <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => setRevealPassword(!revealPassword)}
                      title="Toggle visibility"
                    >
                      {revealPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                    <button
                      className="btn btn-quiet btn-sm"
                      onClick={() => copyToClipboard(selectedEntry!.password, "pass")}
                      title="Copy Password"
                    >
                      {copiedField === "pass" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                    </button>
                    {copiedField === "pass" ? (
                      <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                        Cleared from the clipboard after 30 seconds when the browser allows it.
                      </span>
                    ) : null}
                  </div>
                </div>
              )}
            </div>

            {/* TOTP 2FA Authenticator */}
            {(selectedEntry?.totpSeed || isEditing) ? (
              <div className="field-card">
                <label className="input-label">Two-Factor Authentication (TOTP Key / URI)</label>
                {isEditing ? (
                  <input
                    type="text"
                    className="input font-mono"
                    placeholder="otpauth://totp/App:user?secret=JBSWY3DPEHPK3PXP"
                    value={editTotp}
                    onChange={(e) => setEditTotp(e.target.value)}
                  />
                ) : totpCode ? (
                  <div className="totp-box">
                    <div>
                      <div className="totp-code">{totpCode}</div>
                      <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                        Auto-updates every 30s
                      </span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                      <div className="totp-timer">{totpRemaining}</div>
                      <button
                        className="btn btn-quiet btn-sm"
                        onClick={() => copyToClipboard(totpCode, "totp")}
                        title="Copy OTP Code"
                      >
                        {copiedField === "totp" ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
                      </button>
                    </div>
                    {copiedField === "totp" ? (
                      <span style={{ fontSize: "0.75rem", color: "var(--ink-muted)" }}>
                        Cleared from the clipboard after 30 seconds when the browser allows it.
                      </span>
                    ) : null}
                  </div>
                ) : (
                  <span style={{ color: "var(--ink-muted)" }}>—</span>
                )}
              </div>
            ) : null}

            {/* Website URL */}
            <div className="field-card">
              <label className="input-label">Website URL</label>
              {isEditing ? (
                <input
                  type="url"
                  className="input font-mono"
                  placeholder="https://example.com"
                  value={editUrl}
                  onChange={(e) => setEditUrl(e.target.value)}
                />
              ) : (
                <div className="field-row">
                  <span className="font-mono">{selectedEntry!.url || "—"}</span>
                  {selectedEntry!.url ? (
                    <div style={{ display: "flex", gap: "0.4rem" }}>
                      {(() => {
                        const href = safeHref(selectedEntry!.url);
                        return href ? (
                          <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn btn-quiet btn-sm"
                            title="Open in new tab"
                          >
                            <ExternalLink size={14} />
                          </a>
                        ) : null;
                      })()}
                      <button
                        className="btn btn-quiet btn-sm"
                        onClick={() => copyToClipboard(selectedEntry!.url, "url")}
                      >
                        {copiedField === "url" ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                      </button>
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            {/* Notes */}
            <div className="field-card">
              <label className="input-label">Notes</label>
              {isEditing ? (
                <textarea
                  className="textarea font-mono"
                  rows={5}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                />
              ) : (
                <div style={{ whiteSpace: "pre-wrap", color: "var(--ink-strong)", fontSize: "0.9rem" }}>
                  {selectedEntry!.notes || <span style={{ color: "var(--ink-muted)" }}>No notes attached.</span>}
                </div>
              )}
            </div>
            {/* Tags */}
            <div className="field-card">
              <label className="input-label">Tags</label>
              {isEditing ? (
                <>
                  <input
                    type="text"
                    className="input"
                    placeholder="work, personal"
                    value={editTags}
                    onChange={(e) => setEditTags(e.target.value)}
                  />
                  {tagsHasReservedWord ? <p role="alert" style={{ color: "var(--danger)", fontSize: "0.8rem" }}>
                    The tag favorite is reserved; use the Favourite checkbox.
                  </p> : null}
                </>
              ) : (
                <div className="tag-chips">
                  {selectedEntry!.tags.filter((t) => t.toLowerCase() !== "favorite").length > 0 ? (
                    selectedEntry!.tags.filter((t) => t.toLowerCase() !== "favorite").map((t) => (
                      <span key={t} className="tag-chip">{t}</span>
                    ))
                  ) : <span style={{ color: "var(--ink-muted)" }}>No tags.</span>}
                </div>
              )}
            </div>

            {/* Favourite */}
            {isEditing ? (
              <div className="field-card">
                <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <input type="checkbox" checked={editFavorite} onChange={(e) => setEditFavorite(e.target.checked)} />
                  Favourite
                </label>
              </div>
            ) : null}

            {/* Expiry */}
            <div className="field-card">
              <label className="input-label">Expires</label>
              {isEditing ? (
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <input
                    type="date"
                    className="input"
                    style={{ flex: 1 }}
                    value={editExpires}
                    onChange={(e) => setEditExpires(e.target.value)}
                  />
                  {editExpires ? (
                    <button type="button" className="btn btn-quiet btn-sm" onClick={() => setEditExpires("")}>
                      <X size={14} /> Clear
                    </button>
                  ) : null}
                </div>
              ) : (
                <span className="font-mono">
                  {selectedEntry!.expiresAt ? selectedEntry!.expiresAt.toISOString().slice(0, 10) : "No expiry"}
                </span>
              )}
            </div>

            {/* Custom fields */}
            <div className="field-card">
              <label className="input-label">Custom fields</label>
              {isEditing ? (
                <>
                  {editCustom.map((field, index) => (
                    <div key={index} style={{ display: "flex", gap: "0.4rem", alignItems: "center", marginBottom: "0.4rem" }}>
                      <input
                        type="text"
                        className="input"
                        style={{ flex: 1 }}
                        placeholder="Name"
                        value={field.name}
                        onChange={(e) => {
                          const name = e.target.value;
                          setEditCustom(editCustom.map((f, i) => (i === index ? { ...f, name } : f)));
                        }}
                      />
                      <input
                        type={field.protected ? "password" : "text"}
                        className="input"
                        style={{ flex: 1 }}
                        placeholder="Value"
                        value={field.value}
                        onChange={(e) => setEditCustom(editCustom.map((f, i) => (i === index ? { ...f, value: e.target.value } : f)))}
                      />
                      <label style={{ display: "flex", gap: "0.3rem", alignItems: "center", fontSize: "0.8rem", whiteSpace: "nowrap" }}>
                        <input type="checkbox" checked={field.protected}
                          onChange={(e) => setEditCustom(editCustom.map((f, i) => (i === index ? { ...f, protected: e.target.checked } : f)))} />
                        Protected
                      </label>
                      <button type="button" className="btn btn-quiet btn-sm" aria-label="Remove field"
                        onClick={() => setEditCustom(editCustom.filter((_, i) => i !== index))}>
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                  {reservedCustomFieldName ? <p role="alert" style={{ color: "var(--danger)", fontSize: "0.8rem" }}>"{reservedCustomFieldName}" is a reserved field name.</p> : null}
                  <button type="button" className="btn btn-secondary btn-sm"
                    onClick={() => setEditCustom([...editCustom, { name: "", value: "", protected: false }])}>
                    <Plus size={14} /> Add field
                  </button>
                </>
              ) : selectedEntry!.custom.length > 0 ? (
                selectedEntry!.custom.map((field, index) => (
                  <div key={index} className="field-row">
                    <span className="font-mono">
                      {field.name}: {field.protected && !revealedCustom.has(index) ? "••••••••" : field.value}
                    </span>
                    {field.protected ? (
                      <button className="btn btn-quiet btn-sm" title="Toggle visibility"
                        onClick={() => setRevealedCustom((prev) => {
                          const next = new Set(prev);
                          if (next.has(index)) next.delete(index); else next.add(index);
                          return next;
                        })}>
                        {revealedCustom.has(index) ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    ) : null}
                  </div>
                ))
              ) : (
                <span style={{ color: "var(--ink-muted)" }}>No custom fields.</span>
              )}
            </div>

            {!isEditing && selectedEntry && !hidden ? <EntryAttachments key={selectedEntry.uuid} vault={vault}
              entryUuid={selectedEntry.uuid} readOnly={recycledIds.has(selectedEntry.uuid)}
              onChanged={() => { onChanged(); refreshVaultData(); }} /> : null}
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "4rem 0", color: "var(--ink-muted)" }}>
            <button type="button" className="btn btn-quiet btn-sm vault-only-narrow" aria-label="Back to list"
              onClick={() => setPane("list")} style={{ marginBottom: "1rem" }}>
              <ChevronLeft size={16} />
            </button>
            <Key size={48} style={{ opacity: 0.2, marginBottom: "1rem" }} />
            <p>Select an entry to view details, or create a new password.</p>
          </div>
        )}
      </main>

      {/* Modals */}
      {showEntryHistory && selectedEntry && !hidden ? <EntryHistoryModal
        key={selectedEntry.uuid}
        vault={vault}
        entryUuid={selectedEntry.uuid}
        allowRestore={!recycledIds.has(selectedEntry.uuid)}
        onClose={() => setShowEntryHistory(false)}
        onRestored={() => {
          onChanged();
          setShowEntryHistory(false);
          setRevealPassword(false);
          refreshVaultData();
        }}
      /> : null}

      {showGenerator ? (
        <PasswordGenerator
          currentValue={editPassword}
          onSelect={(pw) => {
            setEditPassword(pw);
            setRevealPassword(true);
          }}
          onClose={() => setShowGenerator(false)}
        />
      ) : null}

      {showPairing ? (
        <DevicePairingModal
          onClose={() => setShowPairing(false)}
          onPaired={() => setImportMessage("Device paired.")}
        />
      ) : null}

      {showCsvImport ? (
        <CsvImportModal
          vault={vault}
          groups={groups}
          onClose={() => setShowCsvImport(false)}
          onImportComplete={(count, createdFolders, skipped) => {
            if (count > 0) onChanged();
            refreshVaultData();
            setImportError(null);
            const folderText =
              createdFolders.length > 0
                ? ` (${createdFolders.length} folder${createdFolders.length === 1 ? "" : "s"} created)`
                : "";
            setImportMessage(`Imported ${count} password${count === 1 ? "" : "s"}${folderText}. ${skipped} duplicate${skipped === 1 ? "" : "s"} skipped.${count > 0 ? " Changes are saved automatically." : ""}`);
          }}
          onImportFailed={(message) => {
            onChanged();
            refreshVaultData();
            setImportMessage(null);
            setImportError(`Import stopped: ${message} Entries added before the failure are kept and saved automatically.`);
          }}
        />
      ) : null}

      {showHistory ? (
        <HistoryModal
          allowRollback={saveState.kind === "saved" && !draftDirty}
          recovery={{ vault, vaultKey, onRecovered: (uuid) => {
            onChanged();
            refreshVaultData();
            setSelectedGroupUuid("all");
            clearSmartViews();
            setSelectedEntryUuid(uuid);
            navigate({ tab: "vault", entry: uuid });
            setPane("detail");
          } }}
          onClose={() => setShowHistory(false)}
          onNotice={setImportMessage}
          onRestored={async () => {
            setShowHistory(false);
            await onReload();
          }}
        />
      ) : null}
    </div>
  );
}
