export type GeneratorOptions = {
  length: number;
  upper: boolean;
  lower: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeLookalikes?: boolean;
};
const SETS = { upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", lower: "abcdefghijklmnopqrstuvwxyz", numbers: "0123456789", symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?" } as const;
const LOOKALIKES = /[O0Il1|]/g;
export const DEFAULT_GENERATOR: GeneratorOptions = { length: 20, upper: true, lower: true, numbers: true, symbols: true, excludeLookalikes: false };

// Rejection sampling keeps every pick uniform; one guaranteed pick per selected class,
// then the rest from the union, then a Fisher-Yates shuffle so the guaranteed picks
// are not always at the front.
export function generatePassword(opts: GeneratorOptions, random: (a: Uint32Array<ArrayBuffer>) => void = (a) => { crypto.getRandomValues(a); }): string {
  if (opts.length < 8 || opts.length > 128 || !Number.isInteger(opts.length)) throw new Error("Length must be between 8 and 128.");
  const setFor = (k: keyof typeof SETS) => (opts.excludeLookalikes ? SETS[k].replace(LOOKALIKES, "") : SETS[k]);
  const classes = (Object.keys(SETS) as Array<keyof typeof SETS>).filter((k) => opts[k] && setFor(k).length > 0);
  if (classes.length === 0) throw new Error("Select at least one character set.");
  const union = classes.map((k) => setFor(k)).join("");
  const uniformBelow = (n: number) => {
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    do { random(buf); } while (buf[0] >= limit);
    return buf[0] % n;
  };
  const pick = (from: string) => from[uniformBelow(from.length)];
  const chars = classes.map((k) => pick(setFor(k)));
  while (chars.length < opts.length) chars.push(pick(union));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = uniformBelow(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

export function passwordEntropyBits(opts: GeneratorOptions): number {
  const setFor = (k: keyof typeof SETS) => (opts.excludeLookalikes ? SETS[k].replace(LOOKALIKES, "") : SETS[k]);
  const classes = (Object.keys(SETS) as Array<keyof typeof SETS>).filter((k) => opts[k] && setFor(k).length > 0);
  if (classes.length === 0) return 0;
  const pool = new Set(classes.flatMap((k) => setFor(k).split(""))).size;
  return opts.length * Math.log2(pool);
}

const KEY = "kyvault.generator";
const BOOL_KEYS = ["upper", "lower", "numbers", "symbols", "excludeLookalikes"] as const;
export function loadGeneratorOptions(storage: Pick<Storage, "getItem"> = localStorage): GeneratorOptions {
  try {
    const raw = storage.getItem(KEY);
    if (!raw) return DEFAULT_GENERATOR;
    const parsed = JSON.parse(raw) as Partial<Record<keyof GeneratorOptions, unknown>>;
    // Stored values are untrusted (tampered localStorage, stale format): a flag that is
    // not strictly a boolean, or a length outside range, falls back to the default rather
    // than being coerced, so e.g. {"upper":"no"} cannot silently flip a class on.
    const length = typeof parsed.length === "number" && Number.isInteger(parsed.length) && parsed.length >= 8 && parsed.length <= 128
      ? parsed.length : DEFAULT_GENERATOR.length;
    const flags = Object.fromEntries(BOOL_KEYS.map((k) => [k, typeof parsed[k] === "boolean" ? parsed[k] : DEFAULT_GENERATOR[k]]));
    return { length, ...flags } as GeneratorOptions;
  } catch { return DEFAULT_GENERATOR; }
}
export function saveGeneratorOptions(opts: GeneratorOptions, storage: Pick<Storage, "setItem"> = localStorage): void {
  try { storage.setItem(KEY, JSON.stringify(opts)); } catch { /* preference only */ }
}
