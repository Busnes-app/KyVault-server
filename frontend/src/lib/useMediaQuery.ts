import { useSyncExternalStore } from "react";

export function useMediaQuery(query: string): boolean {
  const subscribe = (listener: () => void) => {
    const mql = window.matchMedia(query);
    mql.addEventListener("change", listener);
    return () => mql.removeEventListener("change", listener);
  };
  return useSyncExternalStore(subscribe, () => window.matchMedia(query).matches, () => false);
}

export const NARROW = "(max-width: 900px)";
export const PHONE = "(max-width: 600px)";
