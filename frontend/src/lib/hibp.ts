export const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";

export const HIBP_DISCLOSURE = "For each distinct password, the first five characters of its SHA-1 hash are sent to api.pwnedpasswords.com. The password, the rest of the hash, your entries and your account never leave this browser. Results are kept in memory until you lock the vault.";

export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export const hibpPrefix = (hashHex: string): string => hashHex.slice(0, 5);
export const hibpSuffix = (hashHex: string): string => hashHex.slice(5);

export function parseRangeResponse(body: string, suffix: string): number {
  const want = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [s, n] = line.split(":");
    if (s?.toUpperCase() === want) return Number.parseInt(n ?? "0", 10) || 0;
  }
  return 0;
}

// One request per distinct password, sequential, opt-in per caller. Only the 5-char
// SHA-1 prefix leaves the browser; the password and its remaining hash never do.
export async function checkBreached(
  passwords: Map<string, string[]>,
  signal: AbortSignal,
  fetchFn: typeof fetch = fetch,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const [password, uuids] of passwords) {
    const hash = await sha1Hex(password);
    const res = await fetchFn(HIBP_RANGE_URL + hibpPrefix(hash), {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      signal,
    });
    if (!res.ok) throw new Error(`HIBP range request failed: ${res.status}`);
    const count = parseRangeResponse(await res.text(), hibpSuffix(hash));
    if (count > 0) for (const uuid of uuids) out.set(uuid, count);
  }
  return out;
}
