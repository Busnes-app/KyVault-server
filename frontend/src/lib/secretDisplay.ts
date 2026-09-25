import { useEffect } from "react";

export function groupHex(hex: string, size = 8): string {
  return hex.match(new RegExp(`.{1,${size}}`, "g"))?.join(" ") ?? "";
}

// A revealed secret hides itself: after a timeout, and as soon as the tab is hidden.
export function useHideAfter(ms: number, visible: boolean, hide: () => void): void {
  useEffect(() => {
    if (!visible) return;
    const timer = setTimeout(hide, ms);
    const onVisibility = () => { if (document.visibilityState === "hidden") hide(); };
    document.addEventListener("visibilitychange", onVisibility);
    return () => { clearTimeout(timer); document.removeEventListener("visibilitychange", onVisibility); };
  }, [visible, ms, hide]);
}
