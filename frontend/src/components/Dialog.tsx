import { useEffect, useId, useRef, type ReactNode } from "react";

type Props = { title: string; onClose: () => void; size?: "md" | "lg"; children: ReactNode; closeLabel?: string };

// Every modal in the app. Native <dialog> gives focus trapping, Escape and a backdrop for
// free; clicking the backdrop is deliberately not a close, so typed state is never lost.
export function Dialog({ title, onClose, size = "md", children, closeLabel = "Close" }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const element = ref.current;
    const opener = document.activeElement as HTMLElement | null;
    element?.showModal();
    return () => { element?.close(); opener?.focus?.(); };
  }, []);
  return (
    <dialog ref={ref} className={`modal-card dialog-${size}`} aria-labelledby={titleId}
      onCancel={(event) => { event.preventDefault(); onClose(); }}>
      <div className="modal-header">
        <h3 id={titleId}>{title}</h3>
        <button type="button" className="btn btn-quiet btn-sm" aria-label={closeLabel} onClick={onClose}>✕</button>
      </div>
      {children}
    </dialog>
  );
}
