import { test } from "node:test";
import assert from "node:assert/strict";
import {
  planIncrementalScan,
  pairsToRecheck,
  partitionLive,
  MissingScanAnchor,
  DEFAULT_OVERLAP_BLOCKS,
} from "../lib/approvalScan.mjs";

const TIP = 49_315_000n;

test("the scan resumes from the anchor, with an overlap below it", () => {
  const plan = planIncrementalScan({ report: { scannedToBlock: "49300000" }, latestBlock: TIP });

  assert.equal(plan.toBlock, TIP);
  assert.equal(plan.fromBlock, 49_300_000n - DEFAULT_OVERLAP_BLOCKS + 1n);
  assert.equal(plan.overlapBlocks, DEFAULT_OVERLAP_BLOCKS);
});

test("the overlap never runs off the start of the chain", () => {
  const plan = planIncrementalScan({ report: { scannedToBlock: 10 }, latestBlock: TIP });
  assert.equal(plan.fromBlock, 0n);
});

test("a report with no anchor is refused rather than guessed at", () => {
  // Reports written before scannedToBlock existed. Starting at 0 silently becomes the
  // 50-minute full walk; starting at the tip skips the wallet's whole history.
  for (const report of [null, {}, { scannedToBlock: null }, { scannedToBlock: "" }]) {
    assert.throws(() => planIncrementalScan({ report, latestBlock: TIP }), MissingScanAnchor);
  }
});

test("an anchor ahead of the tip is refused", () => {
  // Otherwise every future run scans an empty range and reports "nothing new" while looking
  // healthy -- the same failure the sentinel's state validation refuses.
  assert.throws(
    () => planIncrementalScan({ report: { scannedToBlock: TIP + 1000n }, latestBlock: TIP }),
    /ahead of the chain tip/
  );
});

test("a non-integer or negative anchor is refused", () => {
  assert.throws(() => planIncrementalScan({ report: { scannedToBlock: "soon" }, latestBlock: TIP }), /not an integer/);
  assert.throws(() => planIncrementalScan({ report: { scannedToBlock: -5 }, latestBlock: TIP }), /negative/);
});

test("previously-live pairs are re-read even when no new event mentions them", () => {
  // The half that is easy to miss: `transferFrom` decrements a finite allowance and ERC-20 does
  // not require an event, so a grant spent to zero produces no log. Scanning only new events
  // would keep reporting exposure that is already gone.
  const pairs = pairsToRecheck({
    previousLive: [{ kind: "erc20", token: "0xWETH", spender: "0xAave", symbol: "WETH" }],
    discovered: [],
  });

  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].symbol, "WETH", "the recorded symbol survives, saving a symbol() call");
});

test("a pair seen both in the old report and in a new log is re-read once", () => {
  const pairs = pairsToRecheck({
    previousLive: [{ kind: "erc20", token: "0xAbCd", spender: "0xEf01", symbol: "TKN" }],
    discovered: [{ kind: "erc20", token: "0xabcd", spender: "0xef01" }],
  });

  assert.equal(pairs.length, 1, "addresses differ only in case");
  assert.equal(pairs[0].symbol, "TKN");
});

test("erc20 and permit2 grants for the same pair are tracked separately", () => {
  const pairs = pairsToRecheck({
    discovered: [
      { kind: "erc20", token: "0xT", spender: "0xS" },
      { kind: "permit2", token: "0xT", spender: "0xS" },
    ],
  });
  assert.equal(pairs.length, 2, "a Permit2 grant is not the same allowance as a bare approval");
});

test("entries missing a token or spender are skipped rather than re-read as undefined", () => {
  const pairs = pairsToRecheck({ discovered: [{ kind: "erc20", token: "0xT" }, null, { kind: "erc20", spender: "0xS" }] });
  assert.deepEqual(pairs, []);
});

test("only non-zero allowances land in the report", () => {
  const { erc20Live } = partitionLive([
    { kind: "erc20", token: "0xA", spender: "0xB", amount: "0" },
    { kind: "erc20", token: "0xC", spender: "0xD", amount: "5" },
  ]);
  assert.deepEqual(erc20Live.map((a) => a.token), ["0xC"]);
});

test("an expired Permit2 grant is not exposure", () => {
  const now = () => 1_800_000_000_000; // 1.8e9 seconds
  const { permit2Live } = partitionLive(
    [
      { kind: "permit2", token: "0xA", spender: "0xB", amount: "10", expiration: 1_700_000_000 },
      { kind: "permit2", token: "0xC", spender: "0xD", amount: "10", expiration: 1_900_000_000 },
    ],
    { now }
  );

  assert.deepEqual(permit2Live.map((a) => a.token), ["0xC"], "reporting an expired grant inflates hygieneScore's penalty");
});

test("permit2 and erc20 results are separated into the report's two lists", () => {
  const { erc20Live, permit2Live } = partitionLive(
    [
      { kind: "erc20", token: "0xA", spender: "0xB", amount: "1", symbol: "AAA" },
      { kind: "permit2", token: "0xC", spender: "0xD", amount: "2", expiration: 4_000_000_000, symbol: "CCC" },
    ],
    { now: () => 1_800_000_000_000 }
  );

  assert.deepEqual(erc20Live, [{ token: "0xA", symbol: "AAA", spender: "0xB", amount: "1" }]);
  assert.equal(permit2Live[0].expiration, 4_000_000_000);
  assert.equal("expiration" in erc20Live[0], false, "an ERC-20 approval has no expiry to report");
});
