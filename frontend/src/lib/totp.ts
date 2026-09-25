// Pure-JS RFC 6238 TOTP generator using Web Crypto API

function base32Decode(input: string): Uint8Array {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = "";
  for (let i = 0; i < clean.length; i++) {
    const val = base32chars.indexOf(clean.charAt(i));
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  return bytes;
}

export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

function parseAlgorithm(value: string | null): TotpAlgorithm | undefined {
  const v = (value ?? "").toUpperCase().replace("-", "");
  return v === "SHA1" ? "SHA-1" : v === "SHA256" ? "SHA-256" : v === "SHA512" ? "SHA-512" : undefined;
}

export async function generateTOTP(secretOrURI: string, timeStep = 30, digits = 6, algorithm: TotpAlgorithm = "SHA-1", nowMs = Date.now()): Promise<{ code: string; secondsRemaining: number }> {
  let secret = secretOrURI.trim();
  if (secret.startsWith("otpauth://")) {
    try {
      const url = new URL(secret);
      const s = url.searchParams.get("secret");
      if (s) secret = s;
      const d = parseInt(url.searchParams.get("digits") ?? "", 10);
      if (d >= 6 && d <= 10) digits = d;
      const p = parseInt(url.searchParams.get("period") ?? "", 10);
      if (p > 0) timeStep = p;
      algorithm = parseAlgorithm(url.searchParams.get("algorithm")) ?? algorithm;
    } catch {
      // Fallback to raw string
    }
  }

  const keyBytes = base32Decode(secret);
  if (keyBytes.length === 0) {
    return { code: "------", secondsRemaining: 30 };
  }

  const epoch = Math.floor(nowMs / 1000);
  const timeCount = Math.floor(epoch / timeStep);
  const secondsRemaining = timeStep - (epoch % timeStep);

  const counterBytes = new Uint8Array(8);
  let temp = timeCount;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = temp & 0xff;
    temp = temp >> 8;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, counterBytes as BufferSource);
  const hmac = new Uint8Array(signature);

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, "0");
  return { code: otp, secondsRemaining };
}
