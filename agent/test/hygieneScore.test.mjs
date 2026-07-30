import { test } from "node:test";
import assert from "node:assert/strict";
import { computeHygieneScore, SCORE_VERSION, WEIGHTS, UNLIMITED_THRESHOLD } from "../lib/hygieneScore.mjs";

const MAX_UINT256 = (2n ** 256n - 1n).toString();
const report = (erc20Live = [], permit2Live = []) => ({ erc20Live, permit2Live });
const approval = (amount) => ({ token: "0xtoken", symbol: "TKN", spender: "0xspender", amount });

test("a clean, scanned wallet scores 100", () => {
  const result = computeHygieneScore({ report: report(), flaggedCount: 0 });
  assert.equal(result.hygieneScore, 100);
  assert.equal(result.scoreVersion, SCORE_VERSION);
  assert.equal(result.scoreBreakdown.exposureScanned, true);
});

test("an unlimited approval costs more than a finite one", () => {
  const unlimited = computeHygieneScore({ report: report([approval(MAX_UINT256)]) });
  const finite = computeHygieneScore({ report: report([approval("19999985165190")]) });

  assert.equal(unlimited.hygieneScore, 100 - WEIGHTS.unlimitedApproval);
  assert.equal(finite.hygieneScore, 100 - WEIGHTS.finiteApproval);
  assert.ok(unlimited.hygieneScore < finite.hygieneScore, "the old formula charged both the same");
});

test("the live snapshot's real approval is read as finite", () => {
  // The actual WETH -> Aave v3 Pool allowance this wallet is carrying: ~2e13 wei, about $0.04.
  const result = computeHygieneScore({ report: report([approval("19999985165190")]), flaggedCount: 63 });
  assert.equal(result.scoreBreakdown.finiteApprovals, 1);
  assert.equal(result.scoreBreakdown.unlimitedApprovals, 0);
});

test("airdrop spam is capped instead of pinning the score to zero", () => {
  // 63 flagged collections is the real number for this wallet once NFTs are scanned. Under the
  // old formula (2 points each) that alone was -126 and the score was 0 regardless of exposure.
  const spammed = computeHygieneScore({ report: report(), flaggedCount: 63 });
  const veryspammed = computeHygieneScore({ report: report(), flaggedCount: 6300 });

  assert.equal(spammed.hygieneScore, 100 - WEIGHTS.flaggedTokenCap);
  assert.equal(veryspammed.hygieneScore, spammed.hygieneScore, "spam is capped, not unbounded");
  assert.ok(spammed.hygieneScore > 0, "receiving spam is not a hygiene failure — it cannot be refused");
});

test("one unlimited approval outweighs a wallet full of airdrop spam", () => {
  // The distinction the old formula could not make, and the reason for this module.
  const oneBadApproval = computeHygieneScore({ report: report([approval(MAX_UINT256)]), flaggedCount: 0 });
  const lotsOfSpam = computeHygieneScore({ report: report(), flaggedCount: 63 });
  assert.ok(oneBadApproval.hygieneScore < lotsOfSpam.hygieneScore);
});

test("permit2 grants cost less than bare approvals because they expire", () => {
  const grant = computeHygieneScore({ report: report([], [{ token: "0xt", spender: "0xs", amount: "1", expiration: 1 }]) });
  assert.equal(grant.hygieneScore, 100 - WEIGHTS.permit2Grant);
  assert.ok(WEIGHTS.permit2Grant < WEIGHTS.finiteApproval);
});

test("values just over the unlimited threshold count as unlimited", () => {
  // Routers and wallets spell "unlimited" several ways; an equality test on uint256 max would
  // read 2^160-1 as a modest allowance.
  for (const amount of [UNLIMITED_THRESHOLD, 2n ** 160n - 1n, 2n ** 255n, 2n ** 256n - 1n]) {
    const result = computeHygieneScore({ report: report([approval(amount.toString())]) });
    assert.equal(result.scoreBreakdown.unlimitedApprovals, 1, amount.toString());
  }
});

test("an unparseable amount is treated as unlimited, not as clean", () => {
  const result = computeHygieneScore({ report: report([approval("not-a-number")]) });
  assert.equal(result.scoreBreakdown.unlimitedApprovals, 1);
});

test("no snapshot means no score, not a perfect one", () => {
  // Approvals are the half of this score the owner can act on. Reporting 100 because nothing
  // was scanned is the quiet-confident-failure this agent keeps having to fix.
  const result = computeHygieneScore({ report: null, flaggedCount: 5 });
  assert.equal(result.hygieneScore, null);
  assert.equal(result.scoreBreakdown.exposureScanned, false);
  assert.equal(result.scoreBreakdown.approvalPenalty, null);
  assert.equal(result.scoreBreakdown.flaggedCollections, 5, "what was scanned is still reported");
});

test("the score floors at zero rather than going negative", () => {
  const many = Array.from({ length: 20 }, () => approval(MAX_UINT256));
  assert.equal(computeHygieneScore({ report: report(many), flaggedCount: 100 }).hygieneScore, 0);
});

test("a Permit2 grant that never expires is not scored as though it does", () => {
  // This wallet granted exactly that: WETH to Morpho's GeneralAdapter1, expiration
  // 281474976710655 -- uint48 max, Permit2's "never". The discount for Permit2 grants was
  // justified by "they expire by themselves", which is false for this shape.
  const expiring = computeHygieneScore({
    report: report([], [{ token: "0xT", spender: "0xS", amount: "1", expiration: 1_800_000_000 }]),
  });
  const forever = computeHygieneScore({
    report: report([], [{ token: "0xT", spender: "0xS", amount: "1", expiration: 281474976710655 }]),
  });

  assert.equal(expiring.hygieneScore, 100 - WEIGHTS.permit2Grant);
  assert.equal(forever.hygieneScore, 100 - WEIGHTS.permit2GrantNoExpiry);
  assert.ok(forever.hygieneScore < expiring.hygieneScore);
  assert.equal(forever.scoreBreakdown.permit2GrantsWithoutExpiry, 1);
  assert.equal(expiring.scoreBreakdown.permit2GrantsWithoutExpiry, 0);
});

test("an unexpiring Permit2 grant costs the same as a bare finite approval", () => {
  // It behaves as one: only the amount reaching zero ends it.
  assert.equal(WEIGHTS.permit2GrantNoExpiry, WEIGHTS.finiteApproval);
});
