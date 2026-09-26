import React, { useState, useEffect } from "react";
import { Copy, RefreshCw, Check } from "lucide-react";
import { copyText, SECRET_CLIPBOARD_MS } from "../lib/clipboard";
import { Dialog } from "./Dialog";
import { useDialogs } from "./DialogHost";
import { generatePassword, loadGeneratorOptions, saveGeneratorOptions, passwordEntropyBits, type GeneratorOptions } from "../lib/generatePassword";
import { generatePassphrase, loadPassphraseOptions, savePassphraseOptions, passphraseEntropyBits, type PassphraseOptions } from "../lib/passphrase";

type Props = {
  onSelect: (password: string) => void;
  onClose: () => void;
  currentValue: string;
};

type Mode = "characters" | "passphrase";
const MODE_KEY = "kyvault.generator.mode";
function loadMode(): Mode {
  const raw = localStorage.getItem(MODE_KEY);
  return raw === "characters" || raw === "passphrase" ? raw : "characters";
}
const SEPARATORS: Array<{ value: string; label: string }> = [
  { value: "-", label: "Hyphen" },
  { value: " ", label: "Space" },
  { value: ".", label: "Period" },
  { value: "", label: "None" },
];

export function PasswordGenerator({ onSelect, onClose, currentValue }: Props) {
  const dialogs = useDialogs();
  const [mode, setMode] = useState<Mode>(loadMode);
  const [options, setOptions] = useState<GeneratorOptions>(() => loadGeneratorOptions());
  const [phraseOptions, setPhraseOptions] = useState<PassphraseOptions>(() => loadPassphraseOptions());
  const [generated, setGenerated] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [lengthText, setLengthText] = useState(() => String(options.length));

  const update = (patch: Partial<GeneratorOptions>) => {
    const next = { ...options, ...patch };
    setOptions(next);
    saveGeneratorOptions(next);
  };

  const updatePhrase = (patch: Partial<PassphraseOptions>) => {
    const next = { ...phraseOptions, ...patch };
    setPhraseOptions(next);
    savePassphraseOptions(next);
  };

  const changeMode = (next: Mode) => {
    setMode(next);
    localStorage.setItem(MODE_KEY, next);
  };

  const regenerate = () => {
    try {
      setGenerated(mode === "characters" ? generatePassword(options) : generatePassphrase(phraseOptions));
      setError(null);
    } catch (err) {
      setGenerated("");
      setError(err instanceof Error ? err.message : "Could not generate a password.");
    }
    setCopied(false);
  };

  useEffect(regenerate, [mode, options.length, options.upper, options.lower, options.numbers, options.symbols, options.excludeLookalikes, phraseOptions.words, phraseOptions.separator, phraseOptions.capitalize]);

  const bits = mode === "characters" ? passwordEntropyBits(options) : passphraseEntropyBits(phraseOptions);

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
        <div className="input-group" style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
          <button
            type="button"
            className={mode === "characters" ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
            style={{ flex: 1 }}
            onClick={() => changeMode("characters")}
          >
            Characters
          </button>
          <button
            type="button"
            className={mode === "passphrase" ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
            style={{ flex: 1 }}
            onClick={() => changeMode("passphrase")}
          >
            Passphrase
          </button>
        </div>

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
              wordBreak: mode === "passphrase" ? "break-word" : "break-all",
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

        <div style={{ marginBottom: "1rem" }}>
          <meter min={0} max={128} low={50} high={80} optimum={100} value={bits} style={{ width: "100%" }} />
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            About {Math.round(bits)} bits of entropy{mode === "passphrase" ? " from the EFF long wordlist" : ""}.
          </div>
        </div>

        {mode === "characters" ? (
          <>
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
                  value={lengthText}
                  onChange={(e) => {
                    const text = e.target.value;
                    setLengthText(text);
                    const n = parseInt(text, 10);
                    if (Number.isInteger(n) && n >= 8 && n <= 128) update({ length: n });
                  }}
                  onBlur={() => {
                    const n = parseInt(lengthText, 10);
                    const clamped = Number.isInteger(n) ? Math.min(128, Math.max(8, n)) : options.length;
                    setLengthText(String(clamped));
                    if (clamped !== options.length) update({ length: clamped });
                  }}
                />
              </div>
              <input
                type="range"
                min="8"
                max="128"
                value={options.length}
                onChange={(e) => {
                  const n = parseInt(e.target.value, 10);
                  update({ length: n });
                  setLengthText(String(n));
                }}
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
          </>
        ) : (
          <>
            <div className="input-group">
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                <label className="input-label" htmlFor="generator-words">Words</label>
                <input
                  id="generator-words"
                  type="number"
                  min={4}
                  max={10}
                  className="input"
                  style={{ width: "5rem", textAlign: "right" }}
                  value={phraseOptions.words}
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (Number.isInteger(n) && n >= 4 && n <= 10) updatePhrase({ words: n });
                  }}
                />
              </div>
              <input
                type="range"
                min="4"
                max="10"
                value={phraseOptions.words}
                onChange={(e) => updatePhrase({ words: parseInt(e.target.value, 10) })}
                style={{ width: "100%", accentColor: "var(--accent)" }}
              />
            </div>

            <div className="input-group" style={{ marginBottom: "0.75rem" }}>
              <label className="input-label" htmlFor="generator-separator">Separator</label>
              <select
                id="generator-separator"
                className="input"
                value={phraseOptions.separator}
                onChange={(e) => updatePhrase({ separator: e.target.value })}
              >
                {SEPARATORS.map((s) => (
                  <option key={s.label} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>

            <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
              <input type="checkbox" checked={phraseOptions.capitalize} onChange={(e) => updatePhrase({ capitalize: e.target.checked })} />
              Capitalise each word
            </label>
          </>
        )}

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
