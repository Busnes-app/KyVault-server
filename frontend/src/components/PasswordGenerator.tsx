import React, { useState, useEffect } from "react";
import { Copy, RefreshCw, Check } from "lucide-react";
import { copyText, SECRET_CLIPBOARD_MS } from "../lib/clipboard";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";
import { generatePassword, loadGeneratorOptions, saveGeneratorOptions, type GeneratorOptions } from "../lib/generatePassword";

type Props = {
  onSelect: (password: string) => void;
  onClose: () => void;
  currentValue: string;
};

export function PasswordGenerator({ onSelect, onClose, currentValue }: Props) {
  const dialogs = useDialogs();
  const [options, setOptions] = useState<GeneratorOptions>(() => loadGeneratorOptions());
  const [generated, setGenerated] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const update = (patch: Partial<GeneratorOptions>) => {
    const next = { ...options, ...patch };
    setOptions(next);
    saveGeneratorOptions(next);
  };

  const regenerate = () => {
    try {
      setGenerated(generatePassword(options));
      setError(null);
    } catch (err) {
      setGenerated("");
      setError(err instanceof Error ? err.message : "Could not generate a password.");
    }
    setCopied(false);
  };

  useEffect(regenerate, [options.length, options.upper, options.lower, options.numbers, options.symbols, options.excludeLookalikes]);

  const copy = async () => {
    if (!generated) return;
    const ok = await copyText(generated, { clearAfterMs: SECRET_CLIPBOARD_MS });
    setCopied(ok);
    if (ok) setTimeout(() => setCopied(false), 2000);
  };

  const use = async () => {
    if (!generated) return;
    if (currentValue) {
      const confirmed = await dialogs.confirm({
        title: "Replace the current password?",
        message: "The current password will be replaced in the editor. Apply Edits keeps the previous one in entry history.",
        confirmLabel: "Replace",
      });
      if (!confirmed) return;
    }
    onSelect(generated);
    onClose();
  };

  return (
    <Dialog title="Password Generator" onClose={onClose}>
        <div
          style={{
            background: "var(--bg)",
            border: "1px solid var(--accent)",
            padding: "1rem",
            borderRadius: "8px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "1.5rem",
          }}
        >
          <span
            className="font-mono"
            role={error ? "alert" : undefined}
            style={{
              fontSize: "1.1rem",
              wordBreak: "break-all",
              color: error ? "var(--danger)" : "var(--accent)",
              letterSpacing: "0.05em",
            }}
          >
            {error ?? generated}
          </span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn btn-quiet btn-sm" onClick={regenerate} title="Regenerate">
              <RefreshCw size={16} />
            </button>
            <button className="btn btn-quiet btn-sm" onClick={copy} title="Copy" disabled={!generated}>
              {copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
            </button>
          </div>
        </div>

        <div className="input-group">
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <label className="input-label" htmlFor="generator-length">Length</label>
            <input
              id="generator-length"
              type="number"
              min={8}
              max={128}
              className="input"
              style={{ width: "5rem", textAlign: "right" }}
              value={options.length}
              onChange={(e) => {
                const n = parseInt(e.target.value, 10);
                if (Number.isInteger(n)) update({ length: Math.min(128, Math.max(8, n)) });
              }}
            />
          </div>
          <input
            type="range"
            min="8"
            max="128"
            value={options.length}
            onChange={(e) => update({ length: parseInt(e.target.value, 10) })}
            style={{ width: "100%", accentColor: "var(--accent)" }}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "0.75rem" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={options.upper} onChange={(e) => update({ upper: e.target.checked })} />
            Uppercase (A-Z)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={options.lower} onChange={(e) => update({ lower: e.target.checked })} />
            Lowercase (a-z)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={options.numbers} onChange={(e) => update({ numbers: e.target.checked })} />
            Numbers (0-9)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={options.symbols} onChange={(e) => update({ symbols: e.target.checked })} />
            Special Characters (!@#$)
          </label>
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
          <input type="checkbox" checked={options.excludeLookalikes ?? false} onChange={(e) => update({ excludeLookalikes: e.target.checked })} />
          Exclude look-alike characters (O, 0, I, l, 1, |)
        </label>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={use} disabled={!generated}>
            Use Password
          </button>
        </div>
    </Dialog>
  );
}
