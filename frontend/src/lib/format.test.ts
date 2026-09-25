import { test } from "node:test";
import assert from "node:assert/strict";
import { formatInterval, formatWhen } from "./format";

test("intervals read as humans say them", () => {
  assert.equal(formatInterval(0), "Off");
  assert.equal(formatInterval(900), "Every 15 minutes");
  assert.equal(formatInterval(3600), "Hourly");
  assert.equal(formatInterval(21600), "Every 6 hours");
  assert.equal(formatInterval(86400), "Daily");
  assert.equal(formatInterval(259200), "Every 3 days");
  assert.equal(formatInterval(Number.NaN), "Unknown");
});

test("timestamps never render Invalid Date", () => {
  assert.equal(formatWhen(undefined), "Unknown");
  assert.equal(formatWhen("not a date"), "Unknown");
  assert.equal(formatWhen("2026-09-25T12:00:00Z"), new Date("2026-09-25T12:00:00Z").toLocaleString());
});
