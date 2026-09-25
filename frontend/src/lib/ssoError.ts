// Explains an sso_error query code on the login page. A Map avoids the prototype-key
// lookups a plain object would resolve (__proto__, constructor, toString), which React
// cannot render and which previously white-screened the page.
const ERRORS = new Map<string, string>([
  ["not_linked", "Your KySignOn identity is not linked to a KyVault account. Ask your administrator to provision it."],
  ["deactivated", "This account is deactivated. Ask your administrator to reactivate it."],
  ["signed_out", "KySignOn signed you out. Sign in again."],
]);

export function explainSsoError(code: string | null): string | undefined {
  if (!code) return undefined;
  return ERRORS.get(code);
}
