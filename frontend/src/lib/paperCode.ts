// 16 symbols from a 32-character alphabet (no 0/O, 1/I): 80 bits, KYPASS-XXXX-XXXX-XXXX-XXXX.
// 256 is a multiple of 32, so the modulo is unbiased.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generatePaperCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const raw = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join("");
  return `KYPASS-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}
