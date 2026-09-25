import { test } from "node:test";
import assert from "node:assert/strict";
import { groupHex } from "./secretDisplay";

test("hex is grouped for reading and copies back without spaces", () => {
  const hex = "ab".repeat(32);
  const grouped = groupHex(hex);
  assert.equal(grouped.split(" ").length, 8);
  assert.equal(grouped.replace(/ /g, ""), hex);
  assert.equal(groupHex("abc", 2), "ab c");
});
