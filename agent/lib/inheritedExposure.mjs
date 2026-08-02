// Approvals the sentinel structurally cannot see.
//
// The sentinel scans forward from `lastScannedBlock`, which is what makes each cycle cheap: it
// reads the blocks since last time and nothing else. The cost is permanent and easy to miss --
// any allowance that was already live when the baseline was seeded emitted its Approval event
// before the window, so no forward scan will ever encounter it. `alertedApprovals` stays empty
// and would have stayed empty however long the cron ran.
//
// This is not hypothetical. The full rescan on 2026-07-29 found `WETH -> 0xA238Dd80…` still
// live -- the Aave v3 Pool, left from a July 23 borrow/repay whose cleanup revoked two other
// allowances and missed this one. It is in the committed snapshot, it is real exposure, and the
// daily cycle is blind to it.
//
// The two scans are complementary, not redundant: the incremental one catches new exposure, and
// only the full one catches inherited exposure. Saying so in the response is the point. An agent
// that reports "no new findings" while silently not covering half the question is this project's
// characteristic failure, and the fix is to make the boundary visible rather than to pretend the
// cheap scan is the whole story.

/** Same key shape the sentinel records in `alertedApprovals`. */
const keyFor = (kind, token, spender) => `${kind}:${token}:${spender}`.toLowerCase();

/**
 * Which live approvals in the committed snapshot the sentinel's own baseline has never recorded.
 *
 * @param {{erc20Live?: Array<object>, permit2Live?: Array<object>}|null} report
 *   The approval snapshot produced by scripts/scan-approvals.mjs.
 * @param {{alertedApprovals?: string[]}|null} state The sentinel's state file.
 * @returns {{live: number, monitored: number, inherited: Array<object>, inheritedCount: number}|null}
 *   Null when there is no snapshot to reason about -- absence of data, not a finding of zero.
 */
export function describeInheritedExposure(report, state) {
  if (!report) return null;

  const known = new Set((state?.alertedApprovals ?? []).map((entry) => String(entry).toLowerCase()));

  const entries = [
    ...(report.erc20Live ?? []).map((a) => ({ ...a, kind: "erc20" })),
    ...(report.permit2Live ?? []).map((a) => ({ ...a, kind: "permit2" })),
  ];

  const inherited = entries
    .filter((a) => !known.has(keyFor(a.kind, a.token, a.spender)))
    .map(({ kind, token, symbol, spender, amount }) => ({ kind, token, symbol, spender, amount }));

  return {
    live: entries.length,
    monitored: entries.length - inherited.length,
    inheritedCount: inherited.length,
    inherited,
  };
}
