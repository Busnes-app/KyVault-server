import type { ResealPending } from "../lib/keyReplaceReseal";

// Lives in the app shell, not on the Security page: the only copies of these vault keys are
// in the pending, and leaving the page would take them with it. The text says what is true —
// the vault cannot be opened until the re-seal lands, and nobody but another active owner
// can put it back.
export function ResealPanel({ pending, busy, onRetry }: { pending: ResealPending; busy: boolean; onRetry: () => void }) {
  const one = pending.failed.length === 1;
  const reauth = pending.failed.some((f) => f.error.startsWith("re-authenticate"));
  return (
    <div role="alert" style={{ padding: "0.75rem", background: "var(--danger-soft)", borderBottom: "1px solid rgba(239, 68, 68, 0.3)" }}>
      <p style={{ margin: "0 0 0.5rem", color: "var(--danger)" }}>
        Your new key is published, but {one ? "a shared vault is" : `${pending.failed.length} shared vaults are`} still sealed to your old key.
        You cannot open {one ? "it" : "them"} until this re-seal succeeds. Retry it here: the keys it needs are held in this tab only, and are
        lost when you lock, sign out or reload. After that, only another active owner can share {one ? "the vault" : "each vault"} with you again —
        and a vault you own alone cannot be recovered.
      </p>
      <ul style={{ margin: "0 0 0.75rem 1.25rem", padding: 0 }}>
        {pending.failed.map((f) => (
          <li key={f.id}><strong>{f.name}</strong>: {f.error}</li>
        ))}
      </ul>
      {reauth ? (
        <p style={{ margin: "0 0 0.5rem" }}>
          This needs a fresh KySignOn sign-in. Open{" "}
          <a href="/api/auth/oidc/login?reauth=true" target="_blank" rel="noopener noreferrer">sign in again</a>{" "}
          in a new tab — leaving this page would discard the keys — then come back and retry.
        </p>
      ) : null}
      <button className="btn btn-secondary btn-sm" onClick={onRetry} disabled={busy}>{busy ? "Re-sealing…" : "Retry re-seal"}</button>
    </div>
  );
}
