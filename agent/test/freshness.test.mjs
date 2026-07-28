import { test } from "node:test";
import assert from "node:assert/strict";
import { describeFreshness, STALE_AFTER_SECONDS } from "../lib/freshness.mjs";

const NOW = Date.parse("2026-07-29T12:00:00.000Z");
const now = () => NOW;

test("a recent snapshot reports its age and is not stale", () => {
  const scannedAt = new Date(NOW - 60_000).toISOString();
  assert.deepEqual(describeFreshness(scannedAt, { now }), {
    scannedAt,
    ageSeconds: 60,
    stale: false,
  });
});

test("a snapshot older than the threshold is marked stale", () => {
  const scannedAt = new Date(NOW - (STALE_AFTER_SECONDS + 1) * 1000).toISOString();
  assert.equal(describeFreshness(scannedAt, { now }).stale, true);
});

test("the threshold itself is not yet stale", () => {
  const scannedAt = new Date(NOW - STALE_AFTER_SECONDS * 1000).toISOString();
  const result = describeFreshness(scannedAt, { now });
  assert.equal(result.ageSeconds, STALE_AFTER_SECONDS);
  assert.equal(result.stale, false);
});

test("the staleness threshold is configurable", () => {
  const scannedAt = new Date(NOW - 120_000).toISOString();
  assert.equal(describeFreshness(scannedAt, { now, staleAfterSeconds: 60 }).stale, true);
  assert.equal(describeFreshness(scannedAt, { now, staleAfterSeconds: 300 }).stale, false);
});

test("a missing or unparseable timestamp is stale, not fresh", () => {
  // Failing towards "trust this data" would be the wrong default for an exposure report.
  for (const bad of [undefined, null, "", "not a date"]) {
    const result = describeFreshness(bad, { now });
    assert.equal(result.stale, true);
    assert.equal(result.ageSeconds, null);
  }
});

test("a future timestamp is clamped rather than reported as a negative age", () => {
  const scannedAt = new Date(NOW + 60_000).toISOString();
  const result = describeFreshness(scannedAt, { now });
  assert.equal(result.ageSeconds, 0);
});

test("the timestamp is normalised to ISO form", () => {
  const result = describeFreshness("2026-07-29T11:59:00Z", { now });
  assert.equal(result.scannedAt, "2026-07-29T11:59:00.000Z");
});

test("the default staleness window is a day", () => {
  assert.equal(STALE_AFTER_SECONDS, 86_400);
});
