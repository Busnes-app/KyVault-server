import { test } from "node:test";
import assert from "node:assert/strict";
import { copyText } from "./clipboard";

function fakeClipboard(opts: { readable: boolean }) {
  let value = "";
  return {
    value: () => value,
    clipboard: {
      writeText: async (t: string) => { value = t; },
      readText: async () => { if (!opts.readable) throw new Error("denied"); return value; },
    } as unknown as Clipboard,
  };
}

test("clears a secret after the delay only if the clipboard still holds it", async () => {
  const timers: Array<() => void> = [];
  const setTimer = ((fn: () => void) => { timers.push(fn); return 0; }) as unknown as typeof setTimeout;
  const fake = fakeClipboard({ readable: true });
  assert.equal(await copyText("hunter2", { clearAfterMs: 30_000, clipboard: fake.clipboard, setTimer }), true);
  await fake.clipboard.writeText("something else");
  timers[0]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "something else");
  await copyText("hunter3", { clearAfterMs: 30_000, clipboard: fake.clipboard, setTimer });
  timers[1]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "");
});

test("without read permission it clears unless a newer copy happened", async () => {
  const timers: Array<() => void> = [];
  const setTimer = ((fn: () => void) => { timers.push(fn); return 0; }) as unknown as typeof setTimeout;
  const fake = fakeClipboard({ readable: false });
  await copyText("one", { clearAfterMs: 1, clipboard: fake.clipboard, setTimer });
  await copyText("two", { clearAfterMs: 1, clipboard: fake.clipboard, setTimer });
  timers[0]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "two");
  timers[1]();
  await new Promise((r) => setImmediate(r));
  assert.equal(fake.value(), "");
});

test("a rejected write reports false", async () => {
  const clipboard = { writeText: async () => { throw new Error("no"); } } as unknown as Clipboard;
  assert.equal(await copyText("x", { clipboard }), false);
});
