import { EFF_WORDS } from "./effWordlist";

export type PassphraseOptions = { words: number; separator: string; capitalize: boolean };
export const DEFAULT_PASSPHRASE: PassphraseOptions = { words: 6, separator: "-", capitalize: false };
const MIN_WORDS = 4, MAX_WORDS = 10, MAX_SEPARATOR = 3;

export function generatePassphrase(opts: PassphraseOptions, random: (a: Uint32Array<ArrayBuffer>) => void = (a) => { crypto.getRandomValues(a); }): string {
  if (!Number.isInteger(opts.words) || opts.words < MIN_WORDS || opts.words > MAX_WORDS) throw new Error(`Choose between ${MIN_WORDS} and ${MAX_WORDS} words.`);
  const limit = Math.floor(0x100000000 / EFF_WORDS.length) * EFF_WORDS.length;
  const buf = new Uint32Array(1);
  const words: string[] = [];
  while (words.length < opts.words) {
    do { random(buf); } while (buf[0] >= limit);
    const w = EFF_WORDS[buf[0] % EFF_WORDS.length];
    words.push(opts.capitalize ? w[0].toUpperCase() + w.slice(1) : w);
  }
  return words.join(opts.separator);
}

export function passphraseEntropyBits(opts: PassphraseOptions): number {
  return opts.words * Math.log2(EFF_WORDS.length);
}

const KEY = "kyvault.passphrase";
export function loadPassphraseOptions(storage: Pick<Storage, "getItem"> = localStorage): PassphraseOptions {
  try {
    const raw = storage.getItem(KEY);
    if (!raw) return DEFAULT_PASSPHRASE;
    const parsed = JSON.parse(raw) as Partial<Record<keyof PassphraseOptions, unknown>>;
    // Stored values are untrusted (tampered localStorage, stale format): anything outside
    // the valid shape falls back to the shared default object wholesale, matching
    // loadGeneratorOptions' refusal to coerce partial/invalid input.
    const wordsValid = typeof parsed.words === "number" && Number.isInteger(parsed.words) && parsed.words >= MIN_WORDS && parsed.words <= MAX_WORDS;
    const separatorValid = typeof parsed.separator === "string" && parsed.separator.length <= MAX_SEPARATOR;
    const capitalizeValid = typeof parsed.capitalize === "boolean";
    if (!wordsValid || !separatorValid || !capitalizeValid) return DEFAULT_PASSPHRASE;
    return { words: parsed.words as number, separator: parsed.separator as string, capitalize: parsed.capitalize as boolean };
  } catch { return DEFAULT_PASSPHRASE; }
}
export function savePassphraseOptions(opts: PassphraseOptions, storage: Pick<Storage, "setItem"> = localStorage): void {
  try { storage.setItem(KEY, JSON.stringify(opts)); } catch { /* preference only */ }
}
