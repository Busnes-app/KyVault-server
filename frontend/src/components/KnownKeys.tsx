import { useEffect, useState } from "react";
import { useDialogs } from "./DialogHost";
import { toErrorMessage } from "../lib/api";
import { formatWhen } from "../lib/format";
import type { KeePassVault } from "../lib/kdbx";
import { lookupKey, pinKey, pinKeyFor, readPin, type Pin } from "../lib/keyPins";
import { KeyRound } from "lucide-react";

type Props = { vault: KeePassVault; onChanged: () => void };

type Row = { userId: string; pin: Pin };

// The keys this user has decided to trust. They live in the vault, so they follow the user
// to every device; the server's copy of a public key is never trusted on its own.
export function KnownKeys({ vault, onChanged }: Props) {
  const dialogs = useDialogs();
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reload = () => {
    const found: Row[] = [];
    for (const key of vault.customDataKeys(pinKeyFor(""))) {
      const userId = key.slice(pinKeyFor("").length);
      const pin = readPin(vault, userId);
      if (pin) found.push({ userId, pin });
    }
    setRows(found);
  };

  useEffect(reload, [vault]);

  const forget = async (row: Row) => {
    if (!(await dialogs.confirm({
      title: "Forget this key?",
      message: `You will be asked to verify ${row.userId}'s key again the next time you share with them.`,
      danger: true,
      confirmLabel: "Forget",
    }))) return;
    vault.setCustomData(pinKeyFor(row.userId), undefined);
    onChanged();
    reload();
  };

  const repin = async (row: Row) => {
    setError("");
    setBusy(true);
    try {
      // The same verdict sealing uses: the pinned key's bytes, not its fingerprint.
      const found = await lookupKey(vault, row.userId);
      if (!found.published) { await dialogs.notify({ title: "No published key", message: "That user has no published key right now, so there is nothing to pin." }); return; }
      const published = found.published;
      if (found.state === "pinned") {
        await dialogs.notify({ title: "Key unchanged", message: "The published key still matches the one you pinned." });
        return;
      }
      if (!(await dialogs.confirm({
        title: "Re-pin this key?",
        message: `Pinned: ${row.pin.fingerprint}\nPublished now: ${published.fingerprint}\n\nYou are about to trust a new key for this user. Only do this after verifying the new fingerprint with them.`,
        danger: true,
        confirmLabel: "Re-pin",
      }))) return;
      await pinKey(vault, row.userId, published.publicKey, onChanged);
      reload();
    } catch (err) {
      setError(toErrorMessage(err, "Could not read that user's published key."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="field-card" style={{ marginBottom: "2rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
        <KeyRound size={20} color="var(--accent)" />
        <h3 style={{ margin: 0 }}>Known keys</h3>
      </div>
      <p style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
        The keys you have pinned for other users. Sharing with someone whose key has changed is refused until you re-pin it, which you should only do after comparing the new fingerprint with them.
      </p>
      {error ? <p role="alert" style={{ color: "var(--danger)" }}>{error}</p> : null}
      {rows.length === 0 ? (
        <p style={{ color: "var(--ink-muted)", margin: 0 }}>No keys pinned yet. Inviting someone to a shared vault, or accepting an invitation, pins theirs.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          {rows.map((row) => (
            <div key={row.userId} style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "6px", padding: "0.75rem 1rem", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap" }}>
              <div>
                <code className="font-mono" style={{ overflowWrap: "anywhere" }} aria-label={`Pinned fingerprint for ${row.userId}`}>{row.pin.fingerprint}</code>
                <div style={{ fontSize: "0.8rem", color: "var(--ink-muted)", marginTop: "0.2rem" }}>{row.userId} • Pinned {formatWhen(row.pin.pinnedAt)}</div>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => void repin(row)} disabled={busy}>Re-pin…</button>
                <button type="button" className="btn btn-danger btn-sm" onClick={() => void forget(row)} disabled={busy}>Forget</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
