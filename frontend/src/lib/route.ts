import { useCallback, useSyncExternalStore } from "react";

export type AdminTab = "sso" | "users" | "audit" | "backup";
export type Route = { tab: "vault" | "security" | "admin"; admin?: AdminTab; entry?: string };
const ADMIN_TABS: AdminTab[] = ["sso", "users", "audit", "backup"];

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "security") return { tab: "security" };
  if (parts[0] === "admin") return { tab: "admin", admin: ADMIN_TABS.includes(parts[1] as AdminTab) ? (parts[1] as AdminTab) : "sso" };
  if (parts[0] === "vault" && parts[1]) return { tab: "vault", entry: decodeURIComponent(parts[1]) };
  return { tab: "vault" };
}

export function formatRoute(route: Route): string {
  if (route.tab === "security") return "#/security";
  if (route.tab === "admin") return `#/admin/${route.admin ?? "sso"}`;
  return route.entry ? `#/vault/${encodeURIComponent(route.entry)}` : "#/vault";
}

const subscribe = (listener: () => void) => { window.addEventListener("hashchange", listener); return () => window.removeEventListener("hashchange", listener); };
const read = () => window.location.hash;

export function useRoute(): [Route, (next: Route) => void] {
  const hash = useSyncExternalStore(subscribe, read, () => "");
  const navigate = useCallback((next: Route) => { const target = formatRoute(next); if (window.location.hash !== target) window.location.hash = target; }, []);
  return [parseRoute(hash), navigate];
}
