import { test } from "node:test";
import assert from "node:assert/strict";
import { DialogQueue } from "./dialogQueue";

test("dialogs are answered in order and one at a time", async () => {
  const q = new DialogQueue();
  const seen: Array<string | null> = [];
  q.subscribe(() => seen.push(q.current()?.title ?? null));
  const a = q.ask<boolean>({ kind: "confirm", title: "A" });
  const b = q.ask<string | null>({ kind: "prompt", title: "B" });
  assert.equal(q.current()?.title, "A");
  q.settle(true);
  assert.equal(await a, true);
  assert.equal(q.current()?.title, "B");
  q.settle("typed");
  assert.equal(await b, "typed");
  assert.equal(q.current(), null);
  assert.deepEqual(seen, ["A", "B", null]);
});

test("settle without a current dialog is a no-op", () => {
  const q = new DialogQueue();
  q.settle(true);
  assert.equal(q.current(), null);
});

test("cancelAll answers every pending question with its cancel value", async () => {
  const q = new DialogQueue();
  const a = q.ask<boolean>({ kind: "confirm", title: "A" });
  const b = q.ask<string | null>({ kind: "prompt", title: "B" });
  const c = q.ask<void>({ kind: "notify", title: "C" });
  q.cancelAll();
  assert.equal(await a, false);
  assert.equal(await b, null);
  assert.equal(await c, undefined);
  assert.equal(q.current(), null);
});
