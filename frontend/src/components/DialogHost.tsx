import { createContext, useContext, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { DialogQueue, type DialogRequest } from "../lib/dialogQueue";
import { Dialog } from "./Dialog";

type Api = {
  confirm: (opts: Omit<DialogRequest, "kind">) => Promise<boolean>;
  prompt: (opts: Omit<DialogRequest, "kind">) => Promise<string | null>;
  notify: (opts: Omit<DialogRequest, "kind">) => Promise<void>;
  choose: (opts: Omit<DialogRequest, "kind">) => Promise<string | null>;
  cancelAll: () => void;
};

const Context = createContext<Api | null>(null);

export function useDialogs(): Api {
  const api = useContext(Context);
  if (!api) throw new Error("useDialogs needs a DialogHost above it");
  return api;
}

export function DialogHost({ children }: { children: ReactNode }) {
  const [queue] = useState(() => new DialogQueue());
  const current = useSyncExternalStore(queue.subscribe, () => queue.current());
  const api = useMemo<Api>(() => ({
    confirm: (opts) => queue.ask<boolean>({ ...opts, kind: "confirm" }),
    prompt: (opts) => queue.ask<string | null>({ ...opts, kind: "prompt" }),
    notify: (opts) => queue.ask<void>({ ...opts, kind: "notify" }),
    choose: (opts) => queue.ask<string | null>({ ...opts, kind: "choose" }),
    cancelAll: () => queue.cancelAll(),
  }), [queue]);
  return (
    <Context.Provider value={api}>
      {children}
      {current ? <QuestionDialog key={queue.currentId()} request={current} settle={(v) => queue.settle(v)} /> : null}
    </Context.Provider>
  );
}

function QuestionDialog({ request, settle }: { request: DialogRequest; settle: (value: unknown) => void }) {
  const [value, setValue] = useState(request.defaultValue ?? (request.kind === "choose" ? request.options?.[0]?.value ?? "" : ""));
  const [problem, setProblem] = useState<string | null>(null);
  const cancelValue = request.kind === "confirm" ? false : request.kind === "prompt" || request.kind === "choose" ? null : undefined;
  const submit = () => {
    if (request.kind === "prompt") {
      const message = request.validate?.(value) ?? null;
      if (message) { setProblem(message); return; }
      settle(value);
    } else if (request.kind === "choose") settle(value);
    else settle(request.kind === "confirm" ? true : undefined);
  };
  return (
    <Dialog title={request.title} onClose={() => settle(cancelValue)}>
      {request.message ? <p style={{ color: "var(--ink-muted)", whiteSpace: "pre-wrap" }}>{request.message}</p> : null}
      <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
        {request.kind === "prompt" ? (
          <div className="input-group">
            <label className="input-label" htmlFor="dialog-input">{request.label ?? request.title}</label>
            <input id="dialog-input" className="input" data-autofocus value={value}
              type={request.secret ? "password" : "text"} {...(request.secret ? { autoComplete: "off" } : {})}
              onChange={(e) => { setValue(e.target.value); setProblem(null); }} />
            {problem ? <p role="alert" style={{ color: "var(--danger)" }}>{problem}</p> : null}
          </div>
        ) : null}
        {request.kind === "choose" ? (
          <div className="input-group">
            <label className="input-label" htmlFor="dialog-select">{request.label ?? request.title}</label>
            <select id="dialog-select" className="select" data-autofocus value={value}
              onChange={(e) => setValue(e.target.value)}>
              {request.options?.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </div>
        ) : null}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1rem" }}>
          {request.kind !== "notify" ? (
            <button type="button" className="btn btn-secondary" onClick={() => settle(cancelValue)}>{request.cancelLabel ?? "Cancel"}</button>
          ) : null}
          <button type="submit" className={`btn ${request.danger ? "btn-danger" : "btn-primary"}`} {...(request.kind !== "prompt" ? { "data-autofocus": true } : {})}>
            {request.confirmLabel ?? (request.kind === "notify" ? "OK" : "Continue")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
