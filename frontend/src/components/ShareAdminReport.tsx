import { useEffect, useRef, useState } from "react";
import { KeePassVault } from "../lib/kdbx";
import type { VaultSaveQueue } from "../lib/vaultSave";
import { getJSON, requestJSON, deleteJSON, toErrorMessage } from "../lib/api";
import { readPin, pinKey } from "../lib/keyPins";
import { b64, fingerprint } from "../lib/userKey";
import {
  encryptSummary,
  projectReport,
  type ReportConfig,
} from "../lib/adminReport";
import { buildWatchtowerReport, type BreachResults } from "../lib/watchtower";
import { loadStrengthChecker } from "../lib/passwordStrength";
import { useDialogs } from "./DialogHost";

export type ReportSharing = {
  vault: KeePassVault;
  vaultKey: Uint8Array;
  queue: VaultSaveQueue;
  userId: string;
  enabled: boolean;
  breachResults?: BreachResults | null;
  breachVersion?: number | null;
  isCurrent: () => boolean;
};
export function ShareAdminReport(props: ReportSharing) {
  const dialogs = useDialogs(),
    latest = useRef(props);
  latest.current = props;
  const [busy, setBusy] = useState(false),
    [message, setMessage] = useState("");
  const task = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      task.current?.abort();
    },
    [],
  );
  const share = async () => {
    const p = latest.current,
      controller = new AbortController();
    task.current = controller;
    setBusy(true);
    setMessage("");
    const current = () => {
      controller.signal.throwIfAborted();
      if (
        !p.isCurrent() ||
        !latest.current.enabled ||
        p.queue.getSnapshot().kind !== "saved"
      )
        throw new Error("Save your edits and share again.");
    };
    let key: Uint8Array | undefined;
    try {
      current();
      const cfg = await getJSON<ReportConfig>("/api/reporting/config");
      current();
      if (!cfg.enabled || !cfg.publicKey || !cfg.recipientId)
        throw new Error("An administrator has not enabled reporting.");
      const pk = b64.decode(cfg.publicKey),
        fp = await fingerprint(pk);
      current();
      const pin = readPin(p.vault, cfg.recipientId);
      if (pin && pin.publicKey !== cfg.publicKey)
        throw new Error(
          "The recipient's key changed. Resolve it in Security → Known keys before sharing.",
        );
      if (
        !(await dialogs.confirm({
          title: "Share personal vault counts?",
          message: `Share category counts and your vault's score with ${cfg.recipientName} (${fp})? They can infer information from small vaults and successive reports. Entry details and password matching tokens are excluded. ${pin ? "This key matches your pin." : "Compare this fingerprint with the recipient outside KyVault before relying on it."} Downloaded reports cannot be recalled. A breach result is included only if its completed check matches the saved revision.`,
          confirmLabel: "Share counts",
        }))
      )
        return;
      current();
      if (!pin) {
        await pinKey(p.vault, cfg.recipientId, pk, () => p.queue.changed());
        await p.queue.save();
        controller.signal.throwIfAborted();
      }
      if (!p.isCurrent() || p.queue.getSnapshot().kind !== "saved")
        throw new Error(
          "The pin or edits could not be saved. Save or reload your vault first.",
        );
      const version = p.queue.getSnapshot().version;
      key = new Uint8Array(p.vaultKey);
      const binary = await p.queue.exportBinary();
      current();
      const snapshot = await KeePassVault.open(binary, key);
      current();
      const [strength, { TWO_FACTOR_DOMAINS }] = await Promise.all([
        loadStrengthChecker(),
        import("../lib/twoFactorDomains"),
      ]);
      current();
      const report = await buildWatchtowerReport(snapshot, {
        strength,
        twoFactorDomains: new Set(TWO_FACTOR_DOMAINS),
        breached:
          p.breachVersion === version ? (p.breachResults ?? null) : null,
        cache: new Map(),
        signal: controller.signal,
      });
      current();
      const rec = await encryptSummary(
        projectReport(report, snapshot.getLiveEntries().length),
        cfg,
        p.userId,
        version,
      );
      current();
      if (p.queue.getSnapshot().version !== version)
        throw new Error(
          "Your vault changed while building the report. Share again.",
        );
      await requestJSON("/api/reporting/report", {
        method: "PUT",
        body: JSON.stringify(rec),
        headers: { "If-Match": `"${version}"` },
        signal: controller.signal,
      });
      current();
      setMessage(
        report.breachChecked
          ? "Encrypted counts shared, including the completed breach check."
          : "Encrypted counts shared. Breaches were not checked for this revision.",
      );
    } catch (err) {
      if (!controller.signal.aborted)
        setMessage(toErrorMessage(err, "Could not share the report."));
    } finally {
      key?.fill(0);
      if (task.current === controller) {
        task.current = null;
        setBusy(false);
      }
    }
  };
  const withdraw = async () => {
    setBusy(true);
    try {
      if (
        await dialogs.confirm({
          title: "Withdraw your report?",
          message:
            "Delete your cached report. Copies already downloaded by the recipient remain readable.",
          confirmLabel: "Withdraw",
        })
      ) {
        await deleteJSON("/api/reporting/report");
        setMessage("Cached report withdrawn.");
      }
    } catch (err) {
      setMessage(toErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="field-card" aria-label="Share admin report">
      <h3>Share security counts</h3>
      <p>
        Share an encrypted summary of this personal vault with the designated
        administrator. Sharing is voluntary.
      </p>
      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
        <button
          className="btn btn-secondary"
          disabled={busy || !props.enabled}
          onClick={() => void share()}
        >
          {busy ? "Working…" : "Share counts with admin"}
        </button>
        <button
          className="btn btn-quiet"
          disabled={busy}
          onClick={() => void withdraw()}
        >
          Withdraw cached report
        </button>
      </div>
      {!props.enabled && (
        <p>
          Switch to your personal vault and save or apply your edits before
          sharing.
        </p>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
