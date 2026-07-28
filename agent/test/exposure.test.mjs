import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readExposureReport } from "../lib/exposure.mjs";

async function reportFile(contents) {
  const dir = await mkdtemp(join(tmpdir(), "kokosh-exposure-"));
  const path = join(dir, "approvals-report.json");
  await writeFile(path, contents, "utf8");
  return path;
}

const VALID = JSON.stringify({
  owner: "0x2984Bb4953cfCE2cEc957388BE686D6c38779234",
  scannedAt: "2026-07-29T00:00:00.000Z",
  erc20Live: [{ token: "0x1", symbol: "USDC", spender: "0x2", amount: "1" }],
  permit2Live: [],
});

test("a valid report is returned as parsed JSON", async () => {
  const path = await reportFile(VALID);
  const report = await readExposureReport({ path });
  assert.equal(report.erc20Live.length, 1);
  assert.equal(report.permit2Live.length, 0);
});

test("a missing file is the normal pre-scan state and logs nothing", async () => {
  const logs = [];
  const report = await readExposureReport({ path: "/nonexistent/report.json", log: (m) => logs.push(m) });
  assert.equal(report, null);
  assert.deepEqual(logs, [], "never having run the scanner is not a fault worth warning about");
});

test("malformed JSON is reported rather than swallowed", async () => {
  // Previously indistinguishable from "not scanned yet", so a corrupted report would have
  // left the endpoint claiming that forever.
  const logs = [];
  const path = await reportFile("{ this is not json");
  const report = await readExposureReport({ path, log: (m) => logs.push(m) });

  assert.equal(report, null);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /not valid JSON/);
});

test("a report missing the expected arrays is rejected", async () => {
  // The callers index straight into these; a report without them would throw at request time
  // instead of at read time.
  const logs = [];
  const path = await reportFile(JSON.stringify({ owner: "0x1", scannedAt: "2026-07-29T00:00:00Z" }));
  const report = await readExposureReport({ path, log: (m) => logs.push(m) });

  assert.equal(report, null);
  assert.match(logs[0], /missing erc20Live/);
});

test("a report whose arrays are the wrong type is rejected", async () => {
  const path = await reportFile(JSON.stringify({ erc20Live: "lots", permit2Live: [] }));
  assert.equal(await readExposureReport({ path, log: () => {} }), null);
});

test("an empty but well-formed report is valid, not an error", async () => {
  // Zero live approvals is the state this agent is trying to achieve, so it must not be
  // confused with a broken report.
  const path = await reportFile(JSON.stringify({ erc20Live: [], permit2Live: [] }));
  const report = await readExposureReport({ path, log: () => {} });
  assert.deepEqual(report.erc20Live, []);
});
