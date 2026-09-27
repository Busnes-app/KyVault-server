// A fresh-session refusal is the one error with a way out on screen.
export function ErrorLine({ text }: { text: string }) {
  return (
    <p role="alert" style={{ color: "var(--danger)" }}>
      {text}
      {text.startsWith("re-authenticate") ? <> <a href="/api/auth/oidc/login?reauth=true">Sign in again</a></> : null}
    </p>
  );
}
