import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { KeePassVault } from "../lib/kdbx";
import { buildHealthReport, checkBreached } from "../lib/health";
import { toErrorMessage } from "../lib/api";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";

type Props = { vault: KeePassVault; onOpenEntry: (uuid: string) => void; onClose: () => void };

export function HealthReport({ vault, onOpenEntry, onClose }: Props) {
  const dialogs = useDialogs();
  const report = useMemo(() => buildHealthReport(vault), [vault]);
  const [breached, setBreached] = useState<Map<string, number> | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Auto-lock unmounts this component without calling onClose; abort whatever request is
  // in flight so the sequential loop stops hashing/sending and never sets state after unmount.
  useEffect(() => () => { abortRef.current?.abort(); }, []);

  const open = (uuid: string) => { onOpenEntry(uuid); onClose(); };

  const runCheck = async () => {
    const controller = new AbortController();
    abortRef.current = controller;
    const confirmed = await dialogs.confirm({
      title: "Check passwords against Have I Been Pwned?",
      message: "For each distinct password, the first five characters of its SHA-1 hash are sent to api.pwnedpasswords.com. The password, the rest of the hash, your entries and your account never leave this browser. Results are kept in memory until you lock the vault.",
      confirmLabel: "Check",
    });
    if (controller.signal.aborted) return;
    if (!confirmed) return;
    setBreached(null);
    setError(null);
    const byPassword = new Map<string, string[]>();
    for (const entry of vault.getLiveEntries()) {
      if (entry.password === "") continue;
      const uuids = byPassword.get(entry.password);
      if (uuids) uuids.push(entry.uuid);
      else byPassword.set(entry.password, [entry.uuid]);
    }
    const total = byPassword.size;
    let done = 0;
    setProgress({ done: 0, total });
    // checkBreached runs sequentially; wrap each distinct password to report progress.
    const tracked = new Map<string, string[]>();
    for (const [password, uuids] of byPassword) tracked.set(password, uuids);
    try {
      const trackFetch: typeof fetch = async (...args) => {
        const res = await fetch(...args);
        done += 1;
        setProgress({ done, total });
        return res;
      };
      const result = await checkBreached(tracked, controller.signal, trackFetch);
      if (controller.signal.aborted) return;
      setBreached(result);
    } catch (err) {
      if (controller.signal.aborted) return;
      setError(toErrorMessage(err, "Have I Been Pwned check failed."));
    } finally {
      if (!controller.signal.aborted) setProgress(null);
      if (abortRef.current === controller) abortRef.current = null;
    }
  };

  const close = () => { abortRef.current?.abort(); onClose(); };

  return (
    <Dialog title="Vault Health" size="lg" onClose={close}>
      <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
        <Section title="Weak passwords" count={report.weak.length}>
          {report.weak.map((e) => (
            <Row key={e.uuid} onOpen={() => open(e.uuid)} title={e.title} detail={e.reason} />
          ))}
        </Section>
        <Section title="Reused passwords" count={report.reused.length}>
          {report.reused.map((e) => (
            <Row key={e.uuid} onOpen={() => open(e.uuid)} title={e.title} detail={`used ${e.count} times`} />
          ))}
        </Section>
        <Section title="Expired" count={report.expired.length}>
          {report.expired.map((e) => (
            <Row key={e.uuid} onOpen={() => open(e.uuid)} title={e.title} detail="expired" />
          ))}
        </Section>
        <Section title="Expiring within 30 days" count={report.expiring.length}>
          {report.expiring.map((e) => (
            <Row key={e.uuid} onOpen={() => open(e.uuid)} title={e.title} detail="expiring soon" />
          ))}
        </Section>
        <Section title="Breached passwords" count={breached?.size ?? 0}>
          {breached === null ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => void runCheck()} disabled={!!progress}>
                {progress ? `Checking ${progress.done} of ${progress.total}` : "Check against Have I Been Pwned"}
              </button>
              {error ? (
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span style={{ color: "var(--danger)" }}>{error}</span>
                  <button type="button" className="btn btn-quiet btn-sm" onClick={() => void runCheck()}>Retry</button>
                </div>
              ) : null}
            </div>
          ) : (
            <>
              {[...breached].map(([uuid, count]) => {
                const title = vault.getLiveEntries().find((e) => e.uuid === uuid)?.title ?? uuid;
                return <Row key={uuid} onOpen={() => open(uuid)} title={title} detail={`seen ${count.toLocaleString()} times`} />;
              })}
              <button type="button" className="btn btn-quiet btn-sm" onClick={() => void runCheck()}>Check again</button>
            </>
          )}
        </Section>
      </div>
    </Dialog>
  );
}

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <div>
      <h4 style={{ margin: "0 0 0.5rem" }}>{title} <span className="font-mono" style={{ color: "var(--ink-muted)" }}>({count})</span></h4>
      {count === 0 && title !== "Breached passwords" ? (
        <p style={{ color: "var(--ink-muted)", margin: 0 }}>None.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>{children}</div>
      )}
    </div>
  );
}

function Row({ title, detail, onOpen }: { title: string; detail: string; onOpen: () => void }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
      <button type="button" className="btn btn-quiet btn-sm" style={{ justifyContent: "flex-start" }} onClick={onOpen}>{title}</button>
      <span style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>{detail}</span>
    </div>
  );
}
