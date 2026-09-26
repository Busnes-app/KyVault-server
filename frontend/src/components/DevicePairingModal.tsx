import React, { useState, useEffect, useRef } from "react";
import QRCode from "qrcode";
import { getJSON, postJSON, toErrorMessage } from "../lib/api";
import { Smartphone, Laptop, Check, Copy } from "lucide-react";
import { copyText } from "../lib/clipboard";
import { Dialog } from "./Dialog";

type Props = {
  onClose: () => void;
  onPaired?: () => void;
};

const DEVICE_POLL_MS = 3000;

export function DevicePairingModal({ onClose, onPaired }: Props) {
  const [pin, setPin] = useState("");
  const [qrUrl, setQrUrl] = useState("");
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const fetchPairingCode = async () => {
    try {
      setError("");
      setPin("");
      setQrUrl("");
      setExpiresAt(null);
      const res = await postJSON<{ pin: string; secret: string; expiresAt: string }>("/api/devices/pairing/start", {});
      setPin(res.pin);
      // The server value drives expiry, but a client clock ahead of the server must not
      // read the code as already expired; the client clock is not trusted beyond 90s either.
      const server = new Date(res.expiresAt).getTime();
      setExpiresAt(Number.isNaN(server) ? Date.now() + 90_000 : Math.min(server, Date.now() + 90_000));

      const qrPayload = JSON.stringify({
        server: window.location.origin,
        secret: res.secret,
        pin: res.pin,
      });

      const qr = await QRCode.toDataURL(qrPayload, {
        errorCorrectionLevel: "M",
        margin: 2,
        width: 220,
        color: {
          dark: "#111111",
          light: "#ffffff",
        },
      });
      setQrUrl(qr);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to generate pairing code"));
    }
  };

  useEffect(() => {
    fetchPairingCode();
  }, []);

  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const secondsRemaining = expiresAt === null ? null : Math.max(0, Math.ceil((expiresAt - now) / 1000));

  const baselineCount = useRef<number | null>(null);
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      // Timer keeps ticking, but skip the network call while hidden so a backgrounded tab sends no requests.
      if (document.visibilityState === "hidden") return;
      try {
        const devices = await getJSON<unknown[]>("/api/devices");
        if (cancelled) return;
        const count = devices?.length ?? 0;
        if (baselineCount.current === null) {
          baselineCount.current = count;
        } else if (count > baselineCount.current) {
          onPaired?.();
          onClose();
        }
      } catch {
        // Silent: keep polling, a transient failure is not worth surfacing.
      }
    };
    poll();
    const t = setInterval(poll, DEVICE_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const copyPIN = async () => {
    const ok = await copyText(pin);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } else {
      setError("Could not copy the PIN. Your browser blocked clipboard access.");
    }
  };

  return (
    <Dialog title="Pair Device or Extension" onClose={onClose}>
      <div style={{ textAlign: "center" }}>
        <p style={{ color: "var(--ink-muted)", fontSize: "0.9rem", margin: "0 0 1.5rem 0" }}>
          Scan this QR code with the <strong>KyVault Mobile App</strong>, or enter the PIN in your <strong>Browser Extension</strong>.
        </p>

        {error ? (
          <div style={{ padding: "1rem 0" }}>
            <p style={{ color: "var(--danger)" }}>{error}</p>
            <button className="btn btn-primary" onClick={fetchPairingCode}>
              Try again
            </button>
          </div>
        ) : secondsRemaining === null ? (
          <p style={{ color: "var(--ink-muted)" }}>Requesting a pairing code…</p>
        ) : secondsRemaining > 0 ? (
          <div>
            {qrUrl ? (
              <div
                style={{
                  display: "inline-block",
                  padding: "0.5rem",
                  background: "#ffffff",
                  border: "1px solid var(--line)",
                  borderRadius: "8px",
                  marginBottom: "1rem",
                }}
              >
                <img src={qrUrl} alt="Pairing QR Code" style={{ display: "block" }} />
              </div>
            ) : null}

            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "1rem",
                background: "var(--bg)",
                border: "1px solid var(--line)",
                padding: "0.75rem 1.5rem",
                borderRadius: "8px",
                maxWidth: "260px",
                margin: "0 auto 1.5rem auto",
              }}
            >
              <span style={{ fontSize: "1.75rem", fontWeight: 700, letterSpacing: "0.25em", color: "var(--accent)" }} className="font-mono">
                {pin}
              </span>
              <button className="btn btn-quiet btn-sm" onClick={copyPIN} title="Copy PIN">
                {copied ? <Check size={16} color="#10b981" /> : <Copy size={16} />}
              </button>
            </div>

            <div style={{ color: "var(--ink-muted)", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
              Expires in <strong style={{ color: "var(--accent)" }}>{secondsRemaining}s</strong>
            </div>
          </div>
        ) : (
          <div style={{ padding: "2rem 0" }}>
            <p style={{ color: "var(--ink-muted)", marginBottom: "1rem" }}>Pairing PIN expired.</p>
            <button className="btn btn-primary" onClick={fetchPairingCode}>
              Generate New PIN
            </button>
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "center", gap: "0.5rem" }}>
          <button className="btn btn-secondary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </Dialog>
  );
}
