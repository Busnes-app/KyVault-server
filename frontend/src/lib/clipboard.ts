// Secrets leave the clipboard after a delay. Reading the clipboard back needs a permission
// some browsers refuse; then we only clear if nothing newer was copied through this helper.
// Browsers may refuse the timed clear (no user activation, or the tab is not focused); the
// failure is swallowed, so the clear is best effort.
let generation = 0;

export async function copyText(text: string, options: { clearAfterMs?: number; clipboard?: Clipboard; setTimer?: typeof setTimeout } = {}): Promise<boolean> {
  const clipboard = options.clipboard ?? navigator.clipboard;
  const setTimer = options.setTimer ?? setTimeout;
  try { await clipboard.writeText(text); } catch { return false; }
  const mine = ++generation;
  if (options.clearAfterMs) {
    setTimer(() => { void (async () => {
      let current: string | undefined;
      try { current = await clipboard.readText(); } catch { current = undefined; }
      const stillOurs = current === undefined ? mine === generation : current === text;
      if (stillOurs) { try { await clipboard.writeText(""); } catch { /* nothing to clear */ } }
    })(); }, options.clearAfterMs);
  }
  return true;
}

export const SECRET_CLIPBOARD_MS = 30_000;
