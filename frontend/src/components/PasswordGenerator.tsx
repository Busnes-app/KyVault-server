import React, { useState, useEffect } from "react";
import { Copy, RefreshCw, Check } from "lucide-react";
import { copyText, SECRET_CLIPBOARD_MS } from "../lib/clipboard";
import { Dialog } from "./Dialog";

type Props = {
  onSelect: (password: string) => void;
  onClose: () => void;
};

export function PasswordGenerator({ onSelect, onClose }: Props) {
  const [length, setLength] = useState(20);
  const [useUpper, setUseUpper] = useState(true);
  const [useLower, setUseLower] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);

  const generate = () => {
    let chars = "";
    if (useLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (useUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useNumbers) chars += "0123456789";
    if (useSymbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
    setGenerated(result);
    setCopied(false);
  };

  useEffect(() => {
    generate();
  }, [length, useUpper, useLower, useNumbers, useSymbols]);

  const copy = async () => {
    const ok = await copyText(generated, { clearAfterMs: SECRET_CLIPBOARD_MS });
    setCopied(ok);
    if (ok) setTimeout(() => setCopied(false), 2000);
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
            style={{
              fontSize: "1.1rem",
              wordBreak: "break-all",
              color: "var(--accent)",
              letterSpacing: "0.05em",
            }}
          >
            {generated}
          </span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn btn-quiet btn-sm" onClick={generate} title="Regenerate">
              <RefreshCw size={16} />
            </button>
            <button className="btn btn-quiet btn-sm" onClick={copy} title="Copy">
              {copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
            </button>
          </div>
        </div>

        <div className="input-group">
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <label className="input-label">Length</label>
            <span className="font-mono">{length}</span>
          </div>
          <input
            type="range"
            min="10"
            max="64"
            value={length}
            onChange={(e) => setLength(parseInt(e.target.value, 10))}
            style={{ width: "100%", accentColor: "var(--accent)" }}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "1.5rem" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={useUpper} onChange={(e) => setUseUpper(e.target.checked)} />
            Uppercase (A-Z)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={useLower} onChange={(e) => setUseLower(e.target.checked)} />
            Lowercase (a-z)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={useNumbers} onChange={(e) => setUseNumbers(e.target.checked)} />
            Numbers (0-9)
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.85rem" }}>
            <input type="checkbox" checked={useSymbols} onChange={(e) => setUseSymbols(e.target.checked)} />
            Special Characters (!@#$)
          </label>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={() => {
              onSelect(generated);
              onClose();
            }}
          >
            Use Password
          </button>
        </div>
    </Dialog>
  );
}
