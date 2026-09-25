import { test } from "node:test";
import assert from "node:assert/strict";
import { safeHref } from "./safeHref";

test("only http(s) links open", () => {
  assert.equal(safeHref("https://example.com/login"), "https://example.com/login");
  assert.equal(safeHref("http://intranet/"), "http://intranet/");
  assert.equal(safeHref("example.com"), "https://example.com/");
  assert.equal(safeHref("javascript:alert(1)"), null);
  assert.equal(safeHref("data:text/html,hi"), null);
  assert.equal(safeHref("file:///etc/passwd"), null);
  assert.equal(safeHref("  "), null);
});
