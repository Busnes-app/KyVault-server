import { useCallback, useEffect, useState } from "react";
import { getJSON, postJSON, putJSON, patchJSON, deleteJSON, HttpError, toErrorMessage } from "./api";

export type Role = "owner" | "editor" | "reader";
export type MemberState = "invited" | "active" | "stale" | "suspended";
export type MyKey = { sealedKey: string; keyFingerprint: string; keyEpoch: number; sealedBy: string; sealedByFingerprint: string };
export type SharedVaultSummary = { id: string; name: string; role: Role; state: MemberState; keyEpoch: number; myKey: MyKey; invitedBy?: { userId: string; username: string; fingerprint: string } };
export type Member = { userId: string; username: string; role: Role; state: MemberState; keyFingerprint: string; keyEpoch: number; addedAt: string; acceptedAt?: string };
export type SharedVaultDetail = { id: string; name: string; createdBy: string; createdAt: string; keyEpoch: number; members: Member[] };
export type LookupResult = { userId: string; username: string; fingerprint: string };

export const SHARED_ID = /^sv_[A-Za-z0-9_-]{22}$/;
export const sharedBase = (id: string) => `/api/shared/${encodeURIComponent(id)}`;

// The server's rule for a shared vault name, in the shape every prompt's validate() wants.
export const sharedNameError = (v: string) =>
  v.trim().length >= 1 && v.trim().length <= 64 && !/[\p{Cc}\p{Cf}]/u.test(v) ? null : "1 to 64 characters, no control characters";

export const sharedApi = {
  list: () => getJSON<SharedVaultSummary[]>("/api/shared"),
  get: (id: string) => getJSON<SharedVaultDetail>(sharedBase(id)),
  create: (name: string, sealedKey: string, keyFingerprint: string) => postJSON<{ id: string }>("/api/shared", { name, sealedKey, keyFingerprint }),
  rename: async (id: string, name: string) => { await patchJSON(sharedBase(id), { name }); },
  remove: async (id: string) => { await deleteJSON(sharedBase(id)); },
  invite: async (id: string, userId: string, role: Role, sealedKey: string, keyFingerprint: string) => { await postJSON(`${sharedBase(id)}/members`, { userId, role, sealedKey, keyFingerprint }); },
  updateMember: async (id: string, userId: string, patch: { role?: Role; sealedKey?: string; keyFingerprint?: string }) => { await putJSON(`${sharedBase(id)}/members/${encodeURIComponent(userId)}`, patch); },
  removeMember: async (id: string, userId: string) => { await deleteJSON(`${sharedBase(id)}/members/${encodeURIComponent(userId)}`); },
  accept: async (id: string) => { await postJSON(`${sharedBase(id)}/accept`, {}); },
  decline: async (id: string) => { await postJSON(`${sharedBase(id)}/decline`, {}); },
  lookupUser: async (username: string): Promise<LookupResult | null> => {
    try {
      return await getJSON<LookupResult>(`/api/users/lookup?username=${encodeURIComponent(username)}`);
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) return null;
      throw err;
    }
  },
  metadata: (id: string) => getJSON<{ version: number }>(`${sharedBase(id)}/metadata`),
};
export type SharedApi = typeof sharedApi;

export type AdminSharedVault = {
  id: string;
  name: string;
  createdBy: string;
  createdAt: string;
  keyEpoch: number;
  ownerless: boolean;
  members: { userId: string; username: string; role: Role; state: MemberState }[];
};

export const adminSharedApi = {
  list: () => getJSON<AdminSharedVault[]>("/api/admin/shared"),
  remove: async (id: string) => { await deleteJSON(`/api/admin/shared/${encodeURIComponent(id)}`); },
  removeMember: async (id: string, userId: string) => { await deleteJSON(`/api/admin/shared/${encodeURIComponent(id)}/members/${encodeURIComponent(userId)}`); },
  settings: () => getJSON<{ createRestrictedToAdmins: boolean }>("/api/admin/shared/settings"),
  saveSettings: async (s: { createRestrictedToAdmins: boolean }) => { await putJSON("/api/admin/shared/settings", s); },
};

export const canOpen = (v: SharedVaultSummary) => v.state === "active";

export function stateLabel(v: SharedVaultSummary): string | null {
  if (v.state === "invited") return "Invitation";
  if (v.state === "stale") return "Key changed";
  if (v.role === "reader") return "Read-only";
  return null;
}

const REFRESH_MS = 60_000;

// Loads the caller's shared vaults after unlock and keeps them fresh while the tab is visible.
export function useSharedVaults(enabled: boolean, api: SharedApi = sharedApi) {
  const [vaults, setVaults] = useState<SharedVaultSummary[]>([]);
  const [error, setError] = useState("");
  // False until the first successful list, so a route restore never mistakes "not loaded" for "not a member".
  const [loaded, setLoaded] = useState(false);
  const refresh = useCallback(async (): Promise<SharedVaultSummary[]> => {
    if (!enabled) return [];
    try {
      const list = await api.list();
      setVaults(list);
      setLoaded(true);
      setError("");
      return list;
    } catch (err) {
      setError(toErrorMessage(err, "Could not load shared vaults."));
      return [];
    }
  }, [enabled, api]);
  useEffect(() => {
    if (!enabled) { setVaults([]); setLoaded(false); setError(""); return; }
    void refresh();
    const tick = () => { if (document.visibilityState === "visible") void refresh(); };
    const timer = setInterval(tick, REFRESH_MS);
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", tick); };
  }, [enabled, refresh]);
  return { vaults, loaded, refresh, error };
}
