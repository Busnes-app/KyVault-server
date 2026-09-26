import { test } from "node:test";
import assert from "node:assert/strict";
import { clearClipboard, type OffscreenIO } from "./clipboardClear";

function fakes(open = false) {
  const log: string[] = [];
  const io: OffscreenIO = {
    hasDocument: async () => open,
    createDocument: async () => { open = true; log.push("create"); },
    // The document cannot close itself; only the background does.
    closeDocument: async () => { open = false; log.push("close"); },
    clear: async () => { log.push("clear"); },
  };
  return { io, log };
}

test("two consecutive copies both clear the clipboard", async () => {
  const f = fakes();
  await clearClipboard(f.io);
  await clearClipboard(f.io);
  assert.deepEqual(f.log, ["create", "clear", "close", "create", "clear", "close"]);
});

test("a document left open still clears instead of skipping", async () => {
  const f = fakes(true);
  await clearClipboard(f.io);
  assert.deepEqual(f.log, ["clear", "close"]);
});

test("a failed clear still closes the document", async () => {
  const f = fakes();
  f.io.clear = async () => { throw new Error("Receiving end does not exist."); };
  await assert.rejects(clearClipboard(f.io));
  assert.deepEqual(f.log, ["create", "close"]);
});
