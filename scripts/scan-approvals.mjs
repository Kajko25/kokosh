#!/usr/bin/env node
// Scans 0x2984 for ERC-20 Approval events and Permit2 allowance grants, then reads back CURRENT
// allowances to report what is actually still live. Public RPC caps eth_getLogs at a
// 10,000-block range, so we chunk + run with bounded concurrency across a small pool of public
// endpoints.
//
// Two modes:
//
//   --full         walk from block 0. ~4,900 windows, about 50 minutes. Needed once to establish
//                  the anchor, and after that only if the report is lost or suspect.
//   --incremental  resume from the report's scannedToBlock (default when the anchor exists).
//                  Minutes, not an hour -- which is the point: /exposure and the paid /audit both
//                  serve this file, and a snapshot nobody can afford to refresh goes stale.
//
// Correctness of the incremental path lives in agent/lib/approvalScan.mjs, with tests. The short
// version: new events find grants made in the gap, and every previously-live pair is re-read
// regardless, because `transferFrom` can spend a finite allowance to zero without emitting
// anything.

import { createPublicClient, http, parseAbiItem, getAddress } from "viem";
import { base } from "viem/chains";
import { writeFileSync, readFileSync } from "node:fs";
import { planIncrementalScan, pairsToRecheck, partitionLive, MissingScanAnchor } from "../agent/lib/approvalScan.mjs";

const OWNER = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const CHUNK = 10_000n;
const CONCURRENCY = 5;

const RPCS = [
  "https://mainnet.base.org",
  "https://base-rpc.publicnode.com",
  "https://base.meowrpc.com",
  "https://1rpc.io/base",
];

const clients = RPCS.map((url) => createPublicClient({ chain: base, transport: http(url) }));

const REPORT_PATH = new URL("../agent/data/approvals-report.json", import.meta.url);

const ERC20_APPROVAL = parseAbiItem("event Approval(address indexed owner, address indexed spender, uint256 value)");
const PERMIT2_APPROVAL = parseAbiItem(
  "event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration)"
);
// Permit2 grants made by signature emit `Permit`, not `Approval`. Scanning only the latter --
// which both modes did until now -- misses every router that takes a permit signature instead of
// an on-chain approve. No occurrence was found for this wallet in the last ~237k blocks, so this
// closes a hole rather than fixing an observed miss.
const PERMIT2_PERMIT = parseAbiItem(
  "event Permit(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration, uint48 nonce)"
);
const ERC20_ALLOWANCE_ABI = parseAbiItem("function allowance(address owner, address spender) view returns (uint256)");
const ERC20_SYMBOL_ABI = parseAbiItem("function symbol() view returns (string)");
const PERMIT2_ALLOWANCE_ABI = parseAbiItem(
  "function allowance(address owner, address token, address spender) view returns (uint160 amount, uint48 expiration, uint48 nonce)"
);

async function withRetry(fnByClient, startIdx, tries = clients.length * 5) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    const client = clients[(startIdx + i) % clients.length];
    try {
      return await fnByClient(client);
    } catch (err) {
      lastErr = err;
      const isRateLimit = /rate limit|429|exceeds defined limit/i.test(err?.details ?? err?.message ?? "");
      const delay = isRateLimit ? 2000 + Math.random() * 2000 : 400 * (i + 1);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

async function runPool(jobs, worker, concurrency) {
  const results = [];
  let next = 0;
  async function runner() {
    while (next < jobs.length) {
      const i = next++;
      results[i] = await worker(jobs[i], i);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, runner));
  return results;
}

async function scanEvent(event, { fromBlock, toBlock, address }) {
  const ranges = [];
  for (let from = fromBlock; from <= toBlock; from += CHUNK) {
    const to = from + CHUNK - 1n > toBlock ? toBlock : from + CHUNK - 1n;
    ranges.push([from, to]);
  }
  console.log(`  scanning ${ranges.length} chunk(s), blocks ${fromBlock}-${toBlock}...`);

  const allLogs = [];
  let done = 0;
  await runPool(
    ranges,
    async ([from, to], i) => {
      const logs = await withRetry(
        (client) => client.getLogs({ address, event, args: { owner: OWNER }, fromBlock: from, toBlock: to }),
        i
      );
      allLogs.push(...logs);
      done++;
      if (done % 200 === 0) console.log(`    ${done}/${ranges.length} chunks done, ${allLogs.length} logs so far`);
    },
    CONCURRENCY
  );
  return allLogs;
}

async function symbolOf(token) {
  try {
    return await withRetry((client) => client.readContract({ address: token, abi: [ERC20_SYMBOL_ABI], functionName: "symbol" }), 0);
  } catch {
    return "???";
  }
}

function readPreviousReport() {
  try {
    return JSON.parse(readFileSync(REPORT_PATH, "utf8"));
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    // A corrupt report must not silently become "no previous state" — that would drop every
    // known-live pair from the re-read set and quietly under-report exposure.
    throw new Error(`existing report at ${REPORT_PATH.pathname} is unreadable: ${err.message}`);
  }
}

/** Read back the current allowance for every pair, whatever put it in the list. */
async function readCurrentAllowances(pairs) {
  const entries = [];
  await runPool(
    pairs,
    async (pair, i) => {
      if (pair.kind === "permit2") {
        const [amount, expiration] = await withRetry(
          (client) =>
            client.readContract({
              address: PERMIT2,
              abi: [PERMIT2_ALLOWANCE_ABI],
              functionName: "allowance",
              args: [OWNER, pair.token, pair.spender],
            }),
          i
        );
        if (amount > 0n) {
          entries.push({ ...pair, symbol: pair.symbol ?? (await symbolOf(pair.token)), amount: amount.toString(), expiration });
        }
        return;
      }

      const amount = await withRetry(
        (client) =>
          client.readContract({ address: pair.token, abi: [ERC20_ALLOWANCE_ABI], functionName: "allowance", args: [OWNER, pair.spender] }),
        i
      );
      if (amount > 0n) entries.push({ ...pair, symbol: pair.symbol ?? (await symbolOf(pair.token)), amount: amount.toString() });
    },
    CONCURRENCY
  );
  return entries;
}

async function discoverPairs({ fromBlock, toBlock }) {
  console.log(`Scanning ERC-20 Approval events for owner ${OWNER}...`);
  const erc20Logs = await scanEvent(ERC20_APPROVAL, { fromBlock, toBlock });
  console.log(`Found ${erc20Logs.length} ERC-20 Approval events.`);

  console.log(`Scanning Permit2 Approval events...`);
  const permit2ApprovalLogs = await scanEvent(PERMIT2_APPROVAL, { fromBlock, toBlock, address: PERMIT2 });
  console.log(`Found ${permit2ApprovalLogs.length} Permit2 Approval events.`);

  console.log(`Scanning Permit2 Permit events (signature-based grants)...`);
  const permit2PermitLogs = await scanEvent(PERMIT2_PERMIT, { fromBlock, toBlock, address: PERMIT2 });
  console.log(`Found ${permit2PermitLogs.length} Permit2 Permit events.`);

  const pairs = [];
  for (const log of erc20Logs) {
    pairs.push({ kind: "erc20", token: getAddress(log.address), spender: getAddress(log.args.spender) });
  }
  for (const log of [...permit2ApprovalLogs, ...permit2PermitLogs]) {
    pairs.push({ kind: "permit2", token: getAddress(log.args.token), spender: getAddress(log.args.spender) });
  }
  return pairs;
}

async function main() {
  const args = process.argv.slice(2);
  const wantsFull = args.includes("--full");
  const previous = readPreviousReport();
  const latest = await clients[0].getBlockNumber();
  // Taken here, next to the block read it describes -- not at the end. A full scan runs for
  // hours, so a timestamp written on completion claims freshness the data does not have: the
  // report covers the chain as of `latest`, which is *now*, and everything after that block is
  // outside the scan whatever the clock says later. /exposure derives `stale` from this field,
  // and an exposure report must not round its own age down.
  const scannedAt = new Date().toISOString();

  let fromBlock = 0n;
  let mode = "full";

  if (!wantsFull) {
    try {
      const plan = planIncrementalScan({ report: previous, latestBlock: latest });
      fromBlock = plan.fromBlock;
      mode = "incremental";
      console.log(
        `Incremental scan: anchor ${plan.anchorBlock}, re-scanning ${plan.overlapBlocks} blocks below it for reorg safety.`
      );
    } catch (err) {
      if (!(err instanceof MissingScanAnchor)) throw err;
      // Falling back rather than failing: the first run after this feature ships has no anchor,
      // and the honest response is to do the expensive thing once and say so.
      console.log(`Falling back to a full scan — ${err.message}`);
    }
  }

  if (mode === "full") console.log("Full scan from block 0 — expect ~50 minutes.");

  const discovered = await discoverPairs({ fromBlock, toBlock: latest });

  // Previously-live pairs are always re-read: a finite allowance can be spent to zero by
  // transferFrom without emitting anything, so events alone would keep reporting dead exposure.
  const previousLive =
    mode === "incremental"
      ? [
          ...(previous?.erc20Live ?? []).map((a) => ({ kind: "erc20", ...a })),
          ...(previous?.permit2Live ?? []).map((a) => ({ kind: "permit2", ...a })),
        ]
      : [];

  const pairs = pairsToRecheck({ previousLive, discovered });
  console.log(`\n${pairs.length} unique (token, spender) pair(s) to re-check` + (previousLive.length ? ` (${previousLive.length} carried from the previous report).` : "."));

  const entries = await readCurrentAllowances(pairs);
  const { erc20Live, permit2Live } = partitionLive(entries);

  const report = {
    owner: OWNER,
    scannedAt,
    scanFinishedAt: new Date().toISOString(),
    // The anchor the next incremental run resumes from. Written only after the re-read
    // succeeded, so a failed run cannot advance it past blocks that were never processed.
    scannedToBlock: latest.toString(),
    scanMode: mode,
    erc20Live,
    permit2Live,
  };
  writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + "\n");

  console.log("\n=== LIVE ERC-20 APPROVALS ===");
  for (const a of erc20Live) console.log(`  ${a.symbol} (${a.token}) -> ${a.spender}: ${a.amount}`);
  console.log("\n=== LIVE PERMIT2 GRANTS ===");
  for (const a of permit2Live) console.log(`  ${a.symbol} (${a.token}) -> ${a.spender}: ${a.amount} exp=${a.expiration}`);
  console.log(`\nTotal live: ${erc20Live.length} ERC-20 approvals, ${permit2Live.length} Permit2 grants.`);
  console.log(`Report written to agent/data/approvals-report.json (${mode} scan, anchor now ${latest}).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
