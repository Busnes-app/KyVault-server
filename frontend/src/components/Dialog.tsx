import { useEffect, useId, useRef, type ReactNode } from "react";

type Props = { title: string; onClose: () => void; size?: "md" | "lg"; children: ReactNode; closeLabel?: string; className?: string };

// Every modal in the app. Native <dialog> gives focus trapping, Escape and a backdrop for
// free; clicking the backdrop is deliberately not a close, so typed state is never lost.
export function Dialog({ title, onClose, size = "md", children, closeLabel = "Close", className }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  // Set while this component is unmounting its own dialog, so the native "close" event
  // that firing element.close() produces does not call onClose a second time.
  const closingRef = useRef(false);
  useEffect(() => {
    const element = ref.current;
    const opener = document.activeElement as HTMLElement | null;
    // StrictMode mounts, cleans up, and mounts again on the same instance; clear the
    // guard on every mount so a real native close is not ignored after the replay.
    closingRef.current = false;
    element?.showModal();
    const autofocusTarget = element?.querySelector<HTMLElement>("[data-autofocus]")
      ?? element?.querySelector<HTMLElement>("input, textarea, select");
    autofocusTarget?.focus();
    return () => {
      closingRef.current = true;
      if (element?.open) element.close();
      opener?.focus?.();
    };
  }, []);
  return (
    <dialog ref={ref} className={`modal-card dialog-${size}${className ? ` ${className}` : ""}`} aria-labelledby={titleId}
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      // Chrome can close a <dialog> natively (e.g. a rapid double Escape) without the
      // cancel handler above running. The native "close" event always fires, so it is
      // the reliable place to keep the owner's state in sync with the element. close()
      // queues its "close" event rather than firing it synchronously, so a StrictMode
      // remount's showModal() can reopen the element before the prior cleanup's queued
      // event arrives; a close event on an element that is open again is that stale
      // replay, so it is ignored.
      onClose={(event) => { if (!closingRef.current && !event.currentTarget.open) onClose(); }}>
      <div className="modal-header">
        <h3 id={titleId}>{title}</h3>
        <button type="button" className="btn btn-quiet btn-sm" aria-label={closeLabel} onClick={onClose}>✕</button>
      </div>
      {children}
    </dialog>
  );
}
