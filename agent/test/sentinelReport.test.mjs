import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readSentinelReport, EXPECTED_INTERVAL_SECONDS } from "../lib/sentinelReport.mjs";
import { detectorFingerprint } from "../lib/scamHeuristics.mjs";

const NOW = Date.parse("2026-07-30T12:00:00.000Z");
const now = () => NOW;

async function withState(state) {
  const dir = await mkdtemp(join(tmpdir(), "kokosh-sentinel-"));
  const path = join(dir, "sentinel-state.json");
  await writeFile(path, typeof state === "string" ? state : JSON.stringify(state));
  return path;
}

test("reports the age of the last cycle and that it is current", async () => {
  const path = await withState({
    lastRunAt: "2026-07-30T09:00:00.000Z",
    lastScannedBlock: "49311220",
    knownFlaggedTokens: ["0xa", "0xb"],
    alertedApprovals: [],
    detectorFingerprint: detectorFingerprint(),
  });

  const report = await readSentinelReport({ path, now });
  assert.equal(report.ageSeconds, 3 * 3600);
  assert.equal(report.overdue, false);
  assert.equal(report.lastScannedBlock, "49311220");
  assert.equal(report.knownFlaggedTokens, 2);
  assert.equal(report.detector.willRebaseline, false);
});

test("a cycle that has not run in over a day is overdue", async () => {
  // The real incident: the cron died and lastRunAt sat four days back while the log looked
  // like a quiet, healthy stand-down.
  const path = await withState({ lastRunAt: "2026-07-26T09:00:00.000Z", detectorFingerprint: detectorFingerprint() });
  const report = await readSentinelReport({ path, now });

  assert.ok(report.ageSeconds > EXPECTED_INTERVAL_SECONDS);
  assert.equal(report.overdue, true);
});

test("a healthy gap may exceed 24h, because the cron jitters", async () => {
  const path = await withState({ lastRunAt: "2026-07-29T11:00:00.000Z" });
  const report = await readSentinelReport({ path, now });
  assert.equal(report.ageSeconds, 25 * 3600);
  assert.equal(report.overdue, false);
});

test("a missing or unparseable lastRunAt counts as overdue, not as fine", async () => {
  for (const state of [{}, { lastRunAt: "not a date" }, { lastRunAt: 12345 }]) {
    const report = await readSentinelReport({ path: await withState(state), now });
    assert.equal(report.ageSeconds, null);
    assert.equal(report.overdue, true, JSON.stringify(state));
  }
});

test("a state file predating fingerprinting reports that the next cycle re-baselines", async () => {
  const path = await withState({ lastRunAt: "2026-07-30T11:00:00.000Z", knownFlaggedTokens: ["0xa"] });
  const report = await readSentinelReport({ path, now });

  assert.equal(report.detector.baseline, null);
  assert.equal(report.detector.running, detectorFingerprint());
  assert.equal(report.detector.willRebaseline, true);
});

test("pending approval findings are listed in full, since each needs a human with the Ledger", async () => {
  const alerted = ["erc20:0xtoken:0xspender", "permit2:0xtoken:0xspender"];
  const path = await withState({ lastRunAt: "2026-07-30T11:00:00.000Z", alertedApprovals: alerted });
  const report = await readSentinelReport({ path, now });
  assert.deepEqual(report.alertedApprovals, alerted);
});

test("a missing file is null, and a corrupt one is null with a warning", async () => {
  assert.equal(await readSentinelReport({ path: "/nonexistent/sentinel-state.json", now, log: () => {} }), null);

  const warnings = [];
  const path = await withState("{ not json");
  assert.equal(await readSentinelReport({ path, now, log: (m) => warnings.push(m) }), null);
  assert.equal(warnings.length, 1, "a broken deployment must not look like an unseeded one");
});

test("the real state file in the repo parses", async () => {
  // Guards the move into agent/data: a wrong path here would make the endpoint answer "never
  // seeded" forever, which is how the approval report hid for weeks.
  const path = new URL("../data/sentinel-state.json", import.meta.url).pathname;
  const report = await readSentinelReport({ path, now });
  assert.ok(report, "agent/data/sentinel-state.json must be readable");
  assert.ok(report.lastScannedBlock);
});
