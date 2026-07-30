// The number /audit sells. It had one job and was getting it wrong.
//
// The old formula was `100 - liveApprovals*5 - flaggedTokens*2`. Once the scan learned to read
// NFTs it saw 63 flagged collections, so the score pinned to 0 and stayed there: a wallet with
// one dust-sized allowance and a pile of airdrop spam scored the same as one with ten unlimited
// approvals to unknown contracts. A metric that cannot distinguish those is not measuring
// hygiene.
//
// Two corrections, both about *agency*:
//
//   1. Scam airdrops are received, not chosen. Nobody can refuse an incoming transfer, so
//      holding 63 of them is evidence the wallet is a target, not that its owner is careless.
//      They cost a few points, capped, instead of dominating the score.
//   2. Allowances are the owner's decision and they are not equal. An unlimited approval is an
//      open-ended claim on the whole balance; a finite one is bounded by construction. The old
//      formula charged both 5 points.
//
// The score is versioned and reports its own arithmetic. A paying caller whose number moves
// needs to be able to tell "my wallet changed" from "the formula changed", and this agent has
// already had to re-seed a baseline once for exactly that confusion.

// 3: unexpiring Permit2 grants no longer get the expiring-grant discount. Bumped because the
// weights changed — the whole point of this field is that a paying caller can tell a formula
// change from a wallet change, and v2 has already been sold.
export const SCORE_VERSION = 3;

// An allowance this large is unlimited in every practical sense: uint256 max is the common
// spelling, but so are 2^255, 2^160-1 and other "big enough that it will never be reached"
// values that wallets and routers use. The threshold is deliberately far above any real
// balance rather than an equality test on one magic constant.
export const UNLIMITED_THRESHOLD = 2n ** 128n;

// Permit2 stores expiry in a uint48; its maximum is the protocol's "never expires". Treated as a
// threshold rather than an equality test for the same reason as the amount above: near-max
// values are the same promise in practice (uint48 max is the year 8,919,586).
export const NEVER_EXPIRES_THRESHOLD = 2 ** 47;

export const WEIGHTS = {
  unlimitedApproval: 25,
  finiteApproval: 8,
  // A Permit2 grant that genuinely expires stops mattering by itself, which is a real
  // structural difference from a bare ERC-20 approval that lives until revoked.
  permit2Grant: 5,
  // ...but only if it expires. Permit2 accepts uint48 max as "never", and this wallet has
  // granted exactly that: WETH to Morpho's GeneralAdapter1 on 2025-10-01, expiration
  // 281474976710655. Nothing but the amount reaching zero was ever going to end it. Scoring
  // that at the expiring-grant discount was wrong, so an unexpiring grant is priced like the
  // bare approval it behaves as.
  permit2GrantNoExpiry: 8,
  perFlaggedToken: 1,
  // Airdrop noise is capped: past a handful of pieces of spam it says nothing further about
  // how this wallet is looked after.
  flaggedTokenCap: 10,
};

const isUnlimited = (amount) => {
  try {
    return BigInt(amount ?? 0) >= UNLIMITED_THRESHOLD;
  } catch {
    // An unparseable amount is treated as unlimited: the safe direction for a number whose
    // purpose is to warn. A malformed report should not read as a clean wallet.
    return true;
  }
};

/**
 * Score a wallet's hygiene from its live exposure and its flagged holdings.
 *
 * `report` is the approval snapshot (null when never scanned), `flaggedCount` the number of
 * suspicious collections. Returns the score plus the breakdown that produced it.
 */
export function computeHygieneScore({ report, flaggedCount = 0 } = {}) {
  const erc20 = report?.erc20Live ?? [];
  const permit2 = report?.permit2Live ?? [];

  const unlimited = erc20.filter((a) => isUnlimited(a.amount)).length;
  const finite = erc20.length - unlimited;

  const permit2NoExpiry = permit2.filter((g) => Number(g.expiration ?? 0) >= NEVER_EXPIRES_THRESHOLD).length;
  const permit2Expiring = permit2.length - permit2NoExpiry;

  const approvalPenalty =
    unlimited * WEIGHTS.unlimitedApproval +
    finite * WEIGHTS.finiteApproval +
    permit2Expiring * WEIGHTS.permit2Grant +
    permit2NoExpiry * WEIGHTS.permit2GrantNoExpiry;
  const airdropPenalty = Math.min(flaggedCount * WEIGHTS.perFlaggedToken, WEIGHTS.flaggedTokenCap);

  return {
    // Null when the approval snapshot is missing. Scoring 100 on "no approvals found" when
    // nothing was scanned would be the agent's own signature failure — answering confidently
    // while not working — and approvals are the half of the score its owner can act on.
    hygieneScore: report ? Math.max(0, 100 - approvalPenalty - airdropPenalty) : null,
    scoreVersion: SCORE_VERSION,
    scoreBreakdown: {
      // Null, not zero, when there is no snapshot: "no approvals found" and "never looked" are
      // different claims, and only one of them deserves a full score.
      unlimitedApprovals: report ? unlimited : null,
      finiteApprovals: report ? finite : null,
      permit2Grants: report ? permit2.length : null,
      permit2GrantsWithoutExpiry: report ? permit2NoExpiry : null,
      flaggedCollections: flaggedCount,
      approvalPenalty: report ? approvalPenalty : null,
      airdropPenalty,
      exposureScanned: Boolean(report),
    },
  };
}
