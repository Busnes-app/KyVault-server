// Chrome only. The background worker opens this document 30 seconds after a copy to
// blind-clear the clipboard: it never reads the clipboard back, only overwrites it.
// The async clipboard API needs a focused document, which an offscreen document is
// not, so this uses execCommand with a hidden textarea instead. An empty selection is
// a no-op for execCommand, hence the single space.
const textarea = document.createElement("textarea");
textarea.value = " ";
document.body.append(textarea);
textarea.select();
document.execCommand("copy");
textarea.remove();
void chrome.offscreen.closeDocument();
