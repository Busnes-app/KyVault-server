// Chrome only. An offscreen document gets chrome.runtime and nothing else, so it
// cannot close itself: the background opens it (or reuses one left open), asks it to
// clear, and closes it, even when the clear fails.
export const OFFSCREEN_CLEAR = "offscreenClear";

export type OffscreenIO = {
  hasDocument: () => Promise<boolean>;
  createDocument: () => Promise<void>;
  closeDocument: () => Promise<void>;
  // Resolves once the offscreen document has overwritten the clipboard.
  clear: () => Promise<void>;
};

export async function clearClipboard(io: OffscreenIO): Promise<void> {
  if (!(await io.hasDocument())) await io.createDocument();
  try {
    await io.clear();
  } finally {
    await io.closeDocument();
  }
}
