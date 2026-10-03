import { useEffect, useRef, useState } from "react";
import type { KeePassVault } from "../lib/kdbx";
import { buildWatchtowerReport, runBreachCheck, CATEGORIES, CATEGORY_LABELS, type BreachResults, type Category, type StrengthCache, type WatchtowerReport } from "../lib/watchtower";
import { loadStrengthChecker, type StrengthChecker } from "../lib/passwordStrength";
import { HIBP_DISCLOSURE } from "../lib/hibp";
import { toErrorMessage } from "../lib/api";
import { ShareAdminReport, type ReportSharing } from "../components/ShareAdminReport";
import { useDialogs } from "../components/DialogHost";

const autoBreachKey = (userId: string) => `kyvault.watchtower.autoBreach:${userId}`;

const SEVERITY: Record<Category, string> = {
  breached: "var(--danger)", reused: "var(--danger)", weak: "var(--warning)", insecureUrl: "var(--warning)",
  missing2fa: "var(--warning)", expired: "var(--warning)", expiring: "var(--ink-muted)",
};

type Props = { vault: KeePassVault; hidden: boolean; userId: string; sharing?: ReportSharing; onOpenEntry: (uuid: string) => void };
type Deps = { strength: StrengthChecker; twoFactorDomains: ReadonlySet<string> };

function verdict(score: number | null): string {
  if (score === null) return "No entries yet.";
  if (score >= 90) return "Excellent.";
  if (score >= 70) return "Good, with a few things to fix.";
  if (score >= 40) return "Needs attention.";
  return "At risk.";
}

function readAutoBreach(userId: string): boolean {
  try { return localStorage.getItem(autoBreachKey(userId)) === "1"; } catch { return false; }
}

// Stays mounted while unlocked so the cache and breach results last the session; lock unmounts it.
export function WatchtowerPage({ vault, hidden, userId, onOpenEntry, sharing }: Props) {
  const dialogs = useDialogs();
  const [deps, setDeps] = useState<Deps | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<WatchtowerReport | null>(null);
  const [selected, setSelected] = useState<Category>("breached");
  const [breached, setBreached] = useState<BreachResults | null>(null);
  const [checkedVersion, setCheckedVersion] = useState<number | null>(null);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [autoBreach, setAutoBreach] = useState(() => readAutoBreach(userId));
  const cache = useRef<StrengthCache>(new Map());
  const breachAbort = useRef<AbortController | null>(null);
  const autoRan = useRef(false);

  // StrictMode runs this cleanup once on mount in dev; re-arm the auto check so it is not lost.
  useEffect(() => () => { breachAbort.current?.abort(); autoRan.current = false; }, []);

  useEffect(() => {
    if (hidden || deps) return;
    let live = true;
    setError(null);
    Promise.all([loadStrengthChecker(), import("../lib/twoFactorDomains")])
      .then(([strength, m]) => { if (live) setDeps({ strength, twoFactorDomains: new Set(m.TWO_FACTOR_DOMAINS) }); })
      .catch((err) => { if (live) setError(toErrorMessage(err, "Could not load the password checker.")); });
    return () => { live = false; };
  }, [hidden, deps, attempt]);

  // VaultPage mutates the vault in place, so rebuild whenever the tab is shown.
  useEffect(() => {
    if (hidden || !deps) return;
    const controller = new AbortController();
    buildWatchtowerReport(vault, { ...deps, breached, cache: cache.current, signal: controller.signal })
      .then((r) => { if (controller.signal.aborted) return; setError(null); setReport(r); })
      .catch((err) => { if (!controller.signal.aborted) setError(toErrorMessage(err, "Could not build the report.")); });
    return () => controller.abort();
  }, [hidden, deps, vault, breached]);

  const runCheck = async () => {
    breachAbort.current?.abort();
    const controller = new AbortController();
    const sourceVersion = sharing?.queue.getSnapshot();
    breachAbort.current = controller;
    setBreachError(null);
    try {
      const result = await runBreachCheck(vault, controller.signal, (done, total) => setProgress({ done, total }));
      setBreached(result);
      const after = sharing?.queue.getSnapshot();
      setCheckedVersion(sourceVersion?.kind === "saved" && after?.kind === "saved" && after.version === sourceVersion.version ? after.version : null);
      setCheckedAt(new Date());
    } catch (err) {
      if (!controller.signal.aborted) setBreachError(toErrorMessage(err, "Have I Been Pwned check failed."));
    } finally {
      if (breachAbort.current === controller) { breachAbort.current = null; setProgress(null); }
    }
  };

  const confirmCheck = (auto: boolean) => dialogs.confirm({
    title: "Check passwords against Have I Been Pwned?",
    message: auto ? `${HIBP_DISCLOSURE} This runs the first time you open Watchtower after each unlock, in this browser.` : HIBP_DISCLOSURE,
    confirmLabel: auto ? "Turn on" : "Check",
  });

  const manualCheck = async () => { if (await confirmCheck(false)) await runCheck(); };

  const toggleAuto = async (on: boolean) => {
    if (on && !(await confirmCheck(true))) return;
    try { localStorage.setItem(autoBreachKey(userId), on ? "1" : "0"); } catch {}
    setAutoBreach(on);
    autoRan.current = true;
    if (on && !breached && !breachAbort.current) void runCheck();
  };

  useEffect(() => {
    if (hidden || !autoBreach || autoRan.current) return;
    autoRan.current = true;
    void runCheck();
  }, [hidden, autoBreach]);

  if (hidden) return null;

  const status = progress ? `Checking breaches: ${progress.done} of ${progress.total}`
    : checkedAt ? `Breaches checked at ${checkedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "Breach check not run; the score leaves breaches out.";
  const findings = report?.categories[selected] ?? [];

  return (
    <div className="settings-page" style={{ maxWidth: "960px" }}>
      <section className="field-card watchtower-header">
        <div>
          <div className="watchtower-score font-mono" role="status" aria-label="Vault score">{report?.score ?? "–"}</div>
          <p style={{ margin: 0 }}>{report ? verdict(report.score) : "Checking your vault…"}</p>
          <p style={{ margin: 0, color: "var(--ink-muted)", fontSize: "0.85rem" }}>{status}</p>
          {breachError ? <p role="alert" style={{ margin: 0, color: "var(--danger)" }}>{breachError}</p> : null}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", alignItems: "flex-end" }}>
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => void manualCheck()} disabled={!!progress}>
            {checkedAt ? "Check breaches again" : "Check breaches"}
          </button>
          <label style={{ fontSize: "0.85rem", display: "flex", gap: "0.4rem", alignItems: "center" }}>
            <input type="checkbox" checked={autoBreach} onChange={(e) => void toggleAuto(e.target.checked)} />
            Check automatically when I open Watchtower
          </label>
        </div>
      </section>

      {sharing && <ShareAdminReport {...sharing} breachResults={breached} breachVersion={checkedVersion} />}

      {error ? (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {error} <button type="button" className="btn btn-quiet btn-sm" onClick={() => { setDeps(null); setAttempt((n) => n + 1); }}>Retry</button>
        </p>
      ) : report ? (
        <>
          <div className="watchtower-grid">
            {CATEGORIES.map((c) => {
              const count = report.categories[c].length;
              return (
                <button key={c} type="button" className={`watchtower-card${selected === c ? " active" : ""}`}
                  aria-pressed={selected === c} onClick={() => setSelected(c)}>
                  <span className="font-mono watchtower-count" style={{ color: count ? SEVERITY[c] : "var(--ink-muted)" }}>
                    {c === "breached" && !report.breachChecked ? "?" : count}
                  </span>
                  <span>{CATEGORY_LABELS[c]}</span>
                </button>
              );
            })}
          </div>
          <section className="field-card" aria-label={CATEGORY_LABELS[selected]}>
            <h3 style={{ marginTop: 0 }}>{CATEGORY_LABELS[selected]}</h3>
            {selected === "breached" && !report.breachChecked ? (
              <p style={{ color: "var(--ink-muted)", margin: 0 }}>Not checked yet.</p>
            ) : findings.length === 0 ? (
              <p style={{ color: "var(--ink-muted)", margin: 0 }}>None.</p>
            ) : findings.map((f) => (
              <div key={f.uuid} className="field-row watchtower-row">
                <button type="button" className="btn btn-quiet btn-sm" onClick={() => onOpenEntry(f.uuid)}>{f.title || "(untitled)"}</button>
                <span style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>{f.detail}</span>
              </div>
            ))}
          </section>
        </>
      ) : null}
    </div>
  );
}
