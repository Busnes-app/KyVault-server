import { useEffect, useRef, useState } from "react";
import { getJSON, putJSON, toErrorMessage } from "../lib/api";
import { fetchPublishedKey } from "../lib/keyPins";
import { b64, fingerprint } from "../lib/userKey";
import type { UserKeyState } from "../lib/userKeyState";
import {
  aggregateReports,
  decryptSummary,
  keyDigest,
  type Summary,
  type CoverageRow,
  type ReportPage,
  type ReportConfig,
} from "../lib/adminReport";
import { CATEGORIES } from "../lib/watchtower";
import { useDialogs } from "./DialogHost";

type User = { id: string; username: string; active: boolean; role: string };
type Row = CoverageRow & { summary?: Summary };
export function AdminReporting({
  userId,
  userKey,
  users,
}: {
  userId: string;
  userKey: UserKeyState | null;
  users: User[];
}) {
  const dialogs = useDialogs();
  const [config, setConfig] = useState<ReportConfig | null>(null),
    [rows, setRows] = useState<Row[]>([]),
    [next, setNext] = useState("");
  const [recipient, setRecipient] = useState(userId),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const sequence = useRef(0);
  const liveKey = useRef(userKey);
  liveKey.current = userKey;
  const rowsKey = useRef<UserKeyState | null>(null);
  const load = async (after = "") => {
    const seq = ++sequence.current,
      key = userKey;
    setBusy(true);
    setError("");
    if (!after) setRows([]);
    try {
      const page = await getJSON<ReportPage>(
        `/api/admin/reporting?limit=100${after ? `&after=${encodeURIComponent(after)}` : ""}`,
      );
      if (seq !== sequence.current) return;
      const canDecrypt =
        key?.kind === "ready" &&
        page.config.recipientId === userId &&
        (await keyDigest(key.publicKey)) === page.config.keyDigest;
      const out: Row[] = [];
      for (const row of page.rows) {
        if (seq !== sequence.current || liveKey.current !== key) return;
        const result: Row = { ...row };
        if (
          row.status === "current" &&
          row.record?.sealed &&
          canDecrypt &&
          key?.kind === "ready"
        ) {
          try {
            result.summary = await decryptSummary(
              row.record,
              page.config,
              key.seed,
            );
          } catch {
            result.status = "unreadable";
          }
        }
        out.push(result);
      }
      // Config changed between pagination requests: reset rather than mix generations.
      const latest = await getJSON<ReportConfig>("/api/reporting/config");
      if (seq !== sequence.current || liveKey.current !== key) return;
      if (latest.generation !== page.config.generation) {
        setRows([]);
        setNext("");
        setConfig(latest);
        throw new Error("Reporting settings changed. Refresh the report.");
      }
      rowsKey.current = key;
      setConfig(page.config);
      setNext(page.next);
      setRows((old) =>
        after && config?.generation === page.config.generation
          ? [...old, ...out]
          : out,
      );
    } catch (err) {
      if (seq === sequence.current) setError(toErrorMessage(err));
    } finally {
      if (seq === sequence.current) setBusy(false);
    }
  };
  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 60_000);
    const focus = () => void load();
    window.addEventListener("focus", focus);
    return () => {
      sequence.current++;
      clearInterval(id);
      window.removeEventListener("focus", focus);
      setRows([]);
    };
  }, [userKey]);
  const configure = async (enabled: boolean) => {
    if (!config) return;
    setBusy(true);
    setError("");
    sequence.current++;
    setRows([]);
    try {
      let digest = "",
        fp = "";
      if (enabled) {
        const key = await fetchPublishedKey(recipient);
        if (!key)
          throw new Error(
            "That administrator must unlock their personal vault and publish a user key first.",
          );
        digest = await keyDigest(key.publicKey);
        fp = await fingerprint(key.publicKey);
        if (
          recipient === userId &&
          userKey?.kind === "ready" &&
          b64.encode(userKey.publicKey) !== b64.encode(key.publicKey)
        )
          throw new Error(
            "The directory key is not the key this browser holds.",
          );
      }
      const name = users.find((u) => u.id === recipient)?.username ?? recipient;
      if (
        !(await dialogs.confirm({
          title: enabled ? "Enable encrypted reporting?" : "Disable reporting?",
          message: enabled
            ? `Only ${name} (${fp}) can decrypt reports using their personal vault key. Users choose whether to share. Changing the recipient deletes cached reports; downloaded copies cannot be recalled.`
            : "Delete cached reports and stop accepting new submissions? Downloaded copies cannot be recalled.",
          confirmLabel: enabled ? "Enable reporting" : "Disable reporting",
        }))
      )
        return;
      await putJSON("/api/admin/reporting/config", {
        generation: config.generation,
        enabled,
        recipientId: enabled ? recipient : "",
        keyDigest: digest,
      });
      await load();
    } catch (err) {
      setError(toErrorMessage(err));
      await load();
    } finally {
      setBusy(false);
    }
  };
  const canSee =
    userKey?.kind === "ready" &&
    rowsKey.current === userKey &&
    config?.recipientId === userId;
  const totals = aggregateReports(canSee ? rows : []);
  return (
    <section className="field-card">
      <h2>Personal vault reports</h2>
      <p>
        Client-reported counts, encrypted for one designated administrator.
        Shared vaults are excluded. Missing reports do not mean a vault is safe.
      </p>
      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          alignItems: "end",
          flexWrap: "wrap",
        }}
      >
        <label>
          Recipient administrator
          <select
            className="input"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            disabled={busy}
          >
            {users
              .filter((u) => u.active && u.role === "admin")
              .map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username}
                </option>
              ))}
          </select>
        </label>
        <button
          className="btn btn-secondary"
          disabled={busy || !config}
          onClick={() => void configure(true)}
        >
          Enable / change recipient
        </button>
        <button
          className="btn btn-quiet"
          disabled={busy || !config?.enabled}
          onClick={() => void configure(false)}
        >
          Disable reporting
        </button>
        <button
          className="btn btn-quiet"
          disabled={busy}
          onClick={() => void load()}
        >
          Refresh
        </button>
      </div>
      <p>
        {config?.enabled
          ? `Recipient: ${config.recipientName}.`
          : "Reporting is disabled."}{" "}
        {!canSee &&
          config?.enabled &&
          (config.recipientId === userId
            ? "Unlock your personal vault to decrypt counts."
            : "You can see coverage; only the designated recipient can decrypt counts.")}
      </p>
      {error && (
        <p role="alert">
          {error} <a href="/api/auth/oidc/login?reauth=true">Sign in again</a>
        </p>
      )}
      <p>
        {rows.length} active users loaded{next ? " (more available)" : ""};{" "}
        {rows.filter((r) => r.status === "current").length} current submissions.
        Freshness requires the current vault version and receipt within 24
        hours.
      </p>
      {canSee && (
        <>
          <p>
            {totals.current} current reports decrypted; {totals.missing} loaded
            users without valid counts. {totals.liveEntries} live entries
            covered. Breaches checked in {totals.breachChecked} of{" "}
            {totals.current} reports.
          </p>
          <div className="watchtower-grid">
            {CATEGORIES.map((c) => (
              <div className="watchtower-card" key={c}>
                <strong className="font-mono">
                  {c === "breached" && totals.breachChecked === 0
                    ? "Not checked"
                    : totals.counts[c]}
                </strong>
                <span>{c}</span>
              </div>
            ))}
          </div>
          <p>
            Category counts overlap. Breach totals cover checked reports only;
            no overall server score is calculated.
          </p>
        </>
      )}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%" }}>
          <thead>
            <tr>
              <th scope="col">User</th>
              <th scope="col">Coverage</th>
              <th scope="col">Entries</th>
              <th scope="col">Score</th>
              <th scope="col">Breaches</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.userId}>
                <td>{r.username}</td>
                <td>{r.status}</td>
                <td>{canSee ? (r.summary?.liveEntries ?? "—") : "—"}</td>
                <td>{canSee ? (r.summary?.score ?? "—") : "—"}</td>
                <td>
                  {canSee && r.summary
                    ? r.summary.breachStatus === "complete"
                      ? r.summary.counts.breached
                      : "Not checked"
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {next && (
        <button
          className="btn btn-secondary"
          disabled={busy}
          onClick={() => void load(next)}
        >
          Load more users
        </button>
      )}
      {busy && <p role="status">Loading…</p>}
    </section>
  );
}
