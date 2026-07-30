#!/usr/bin/env node
// Run the scam heuristics over this wallet's real holdings and print what they decide.
//
// Why this exists: the rules in lib/scamHeuristics.mjs are pattern guesses about adversarial
// text, and the only honest way to judge one is against the names actually sitting in the
// wallet. Both of the detector's known bugs -- the exact-ticker impersonation that could never
// fire, and ERC-20-only scanning -- survived because changes were reasoned about in the
// abstract instead of being run against the 274 collections available for free.
//
// The output is deliberately for a human to read, not a pass/fail: a new rule is judged by
// what it newly flags (should be scams) and by what it flags that it should not (Basenames,
// Base Colors, Rai.Finance and friends are all real holdings here). Unit tests then pin the
// specific cases this pass established.
//
// Usage:
//   node scripts/calibrate-heuristics.mjs              # summary + flagged, per standard
//   node scripts/calibrate-heuristics.mjs --unflagged   # also list what was NOT flagged
//   node scripts/calibrate-heuristics.mjs --json        # machine-readable, for diffing runs

import { classifyToken } from "../lib/scamHeuristics.mjs";
import { fetchTokenHoldings, fetchNftHoldings } from "../lib/blockscout.mjs";

const WALLET = process.env.WALLET ?? "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const showUnflagged = process.argv.includes("--unflagged");
const asJson = process.argv.includes("--json");

const label = (t) => `[${t.symbol || "-"}] ${t.name || "(no name)"}`;

async function main() {
  const [tokens, nfts] = await Promise.all([
    fetchTokenHoldings(WALLET, { onTruncated: (n) => console.warn(`WARN erc20 truncated at ${n}`) }),
    fetchNftHoldings(WALLET, { onTruncated: (n) => console.warn(`WARN nft truncated at ${n}`) }),
  ]);

  const classified = [...tokens, ...nfts].map((t) => ({
    standard: t.standard || "ERC-20",
    address: t.address,
    name: t.name,
    symbol: t.symbol,
    ...classifyToken(t),
  }));

  if (asJson) {
    console.log(JSON.stringify({ wallet: WALLET, scannedAt: new Date().toISOString(), classified }, null, 2));
    return;
  }

  const standards = [...new Set(classified.map((c) => c.standard))].sort();
  console.log(`wallet ${WALLET} — ${classified.length} collections across ${standards.length} standards\n`);

  for (const standard of standards) {
    const rows = classified.filter((c) => c.standard === standard);
    const flagged = rows.filter((r) => r.suspicious);
    console.log(`=== ${standard}: ${flagged.length} flagged of ${rows.length}`);
    for (const r of flagged) console.log(`  FLAG ${label(r)}\n       ${r.reasons.join(", ")}`);
    if (showUnflagged) for (const r of rows.filter((x) => !x.suspicious)) console.log(`  ok   ${label(r)}`);
    console.log();
  }

  // Which rules are actually earning their place: a rule that never fires on real data is
  // untested in production regardless of its unit tests, and one that fires on everything is
  // probably matching something other than what it claims to.
  const byReason = {};
  for (const r of classified) for (const reason of r.reasons) byReason[reason] = (byReason[reason] ?? 0) + 1;
  console.log("hits per rule:");
  for (const [reason, count] of Object.entries(byReason).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(count).padStart(4)}  ${reason}`);
  }

  const total = classified.filter((c) => c.suspicious).length;
  console.log(`\ntotal flagged: ${total} of ${classified.length}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
