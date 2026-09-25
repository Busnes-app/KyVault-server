import { test } from "node:test";
import assert from "node:assert/strict";
import { generateTOTP } from "./totp";

// RFC 4648 base32, only what the test needs to turn the RFC 6238 ASCII seeds into secrets.
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  if (bits.length % 5) out += alphabet[parseInt(bits.slice(-(bits.length % 5)).padEnd(5, "0"), 2)];
  return out;
}
const seed = (n: number) => base32(new TextEncoder().encode("1234567890".repeat(7).slice(0, n)));

// RFC 6238 Appendix B, T = 59 seconds, 8 digits.
test("RFC 6238 vectors for SHA-1, SHA-256 and SHA-512", async () => {
  const at = 59_000;
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&digits=8`, 30, 6, "SHA-1", at)).code, "94287082");
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(32)}&digits=8&algorithm=SHA256`, 30, 6, "SHA-1", at)).code, "46119246");
  assert.equal((await generateTOTP(`otpauth://totp/x?secret=${seed(64)}&digits=8&algorithm=SHA512`, 30, 6, "SHA-1", at)).code, "90693936");
});

test("period and remaining seconds come from the URI", async () => {
  const res = await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&period=60`, 30, 6, "SHA-1", 59_000);
  assert.equal(res.secondsRemaining, 1);
  assert.equal(res.code.length, 6);
});

test("unknown algorithm falls back to SHA-1 and an empty secret yields dashes", async () => {
  const a = await generateTOTP(`otpauth://totp/x?secret=${seed(20)}&algorithm=MD5`, 30, 6, "SHA-1", 59_000);
  const b = await generateTOTP(seed(20), 30, 6, "SHA-1", 59_000);
  assert.equal(a.code, b.code);
  assert.equal((await generateTOTP("", 30, 6, "SHA-1", 59_000)).code, "------");
});
