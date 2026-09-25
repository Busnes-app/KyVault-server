// Entry URLs come from imports and other clients. Only http(s) may become a clickable link.
export function safeHref(raw: string): string | null {
  const text = raw.trim();
  if (!text) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`;
  try {
    const url = new URL(candidate);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
