// The master password is the only thing between a stolen envelope and the vault key
// (see vaultCrypto.ts). Length is the one rule that survives every composition policy.
export const MIN_MASTER_PASSWORD_LENGTH = 12;

export function checkMasterPassword(password: string): string | null {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters. A short sentence works well.`;
  if (password.trim().length === 0) return "A master password cannot be only spaces.";
  return null;
}
