// Chrome only. The background worker opens this document 30 seconds after a copy and
// asks it to blind-clear the clipboard: it never reads the clipboard back, only
// overwrites it. The async clipboard API needs a focused document, which an offscreen
// document is not, so this uses execCommand with a hidden textarea instead. An empty
// selection is a no-op for execCommand, hence the single space. The background closes
// the document after the reply; chrome.offscreen does not exist in here.
import { OFFSCREEN_CLEAR } from "./lib/clipboardClear";

chrome.runtime.onMessage.addListener((message: { type?: string }, sender, sendResponse) => {
  if (message?.type !== OFFSCREEN_CLEAR || sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL(""))) return false;
  const textarea = document.createElement("textarea");
  textarea.value = " ";
  document.body.append(textarea);
  try {
    textarea.select();
    sendResponse({ cleared: document.execCommand("copy") });
  } finally {
    textarea.remove();
  }
  return false;
});
