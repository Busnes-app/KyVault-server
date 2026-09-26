// Chrome only. The background worker opens this document 30 seconds after a copy to
// blind-clear the clipboard: it never reads the clipboard back, only overwrites it.
// The async clipboard API needs a focused document, which an offscreen document is
// not, so this uses execCommand with a hidden textarea instead. An empty selection is
// a no-op for execCommand, hence the single space.
const textarea = document.createElement("textarea");
textarea.value = " ";
document.body.append(textarea);
try {
  textarea.select();
  document.execCommand("copy");
} finally {
  // Always close, even if execCommand throws, so a later clear is not skipped by a
  // stale offscreen document that createDocument then refuses to replace.
  textarea.remove();
  void chrome.offscreen.closeDocument();
}
