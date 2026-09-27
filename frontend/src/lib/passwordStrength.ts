export type StrengthResult = { score: 0 | 1 | 2 | 3 | 4; warning: string };
export type StrengthChecker = (password: string) => StrengthResult;

let loading: Promise<StrengthChecker> | null = null;

// Dynamic imports keep ~850 KB gzip of dictionaries out of the entry chunk.
export function loadStrengthChecker(): Promise<StrengthChecker> {
  loading ??= (async () => {
    const [{ ZxcvbnFactory }, common, en] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    // The default of 100 l33t substitutions costs ~18 ms per password; 10 costs ~2.7 ms
    // and scored the same on our probe set.
    const zxcvbn = new ZxcvbnFactory({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary },
      l33tMaxSubstitutions: 10,
    });
    return (password: string): StrengthResult => {
      const r = zxcvbn.check(password);
      return { score: r.score, warning: r.feedback.warning ?? "" };
    };
  })().catch((err) => { loading = null; throw err; });
  return loading;
}
