#!/usr/bin/env node
// Scans 0x2984's full on-chain history for ERC-20 Approval events and Permit2 allowance
// grants, then reads back CURRENT allowances to report what's actually still live.
// Public RPC caps eth_getLogs at a 10,000-block range, so we chunk + run with bounded
// concurrency across a small pool of public endpoints.

import { createPublicClient, http, parseAbiItem, getAddress } from "viem";
import { base } from "viem/chains";
import { writeFileSync } from "node:fs";

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

const ERC20_APPROVAL = parseAbiItem("event Approval(address indexed owner, address indexed spender, uint256 value)");
const PERMIT2_APPROVAL = parseAbiItem(
  "event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration)"
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

async function scanEvent(event, extraArgs = {}) {
  const latest = await clients[0].getBlockNumber();
  const ranges = [];
  for (let from = 0n; from <= latest; from += CHUNK) {
    const to = from + CHUNK - 1n > latest ? latest : from + CHUNK - 1n;
    ranges.push([from, to]);
  }
  console.log(`  scanning ${ranges.length} chunks up to block ${latest}...`);

  const allLogs = [];
  let done = 0;
  await runPool(
    ranges,
    async ([from, to], i) => {
      const logs = await withRetry(
        (client) => client.getLogs({ address: undefined, event, args: { owner: OWNER, ...extraArgs }, fromBlock: from, toBlock: to }),
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

async function main() {
  console.log(`Scanning ERC-20 Approval events for owner ${OWNER}...`);
  const erc20Logs = await scanEvent(ERC20_APPROVAL);
  console.log(`Found ${erc20Logs.length} ERC-20 Approval events.`);

  const erc20Pairs = new Map();
  for (const log of erc20Logs) {
    const token = getAddress(log.address);
    const spender = getAddress(log.args.spender);
    erc20Pairs.set(`${token}:${spender}`, { token, spender });
  }
  console.log(`${erc20Pairs.size} unique (token, spender) pairs to re-check.`);

  const erc20Live = [];
  await runPool(
    [...erc20Pairs.values()],
    async ({ token, spender }, i) => {
      const amount = await withRetry(
        (client) => client.readContract({ address: token, abi: [ERC20_ALLOWANCE_ABI], functionName: "allowance", args: [OWNER, spender] }),
        i
      );
      if (amount > 0n) {
        const symbol = await symbolOf(token);
        erc20Live.push({ token, symbol, spender, amount: amount.toString() });
      }
    },
    CONCURRENCY
  );

  console.log(`\nScanning Permit2 Approval events for owner ${OWNER}...`);
  const permit2Logs = await scanEvent(PERMIT2_APPROVAL);
  console.log(`Found ${permit2Logs.length} Permit2 Approval events.`);

  const permit2Triples = new Map();
  for (const log of permit2Logs) {
    const token = getAddress(log.args.token);
    const spender = getAddress(log.args.spender);
    permit2Triples.set(`${token}:${spender}`, { token, spender });
  }
  console.log(`${permit2Triples.size} unique (token, spender) Permit2 pairs to re-check.`);

  const permit2Live = [];
  await runPool(
    [...permit2Triples.values()],
    async ({ token, spender }, i) => {
      const [amount, expiration] = await withRetry(
        (client) =>
          client.readContract({
            address: PERMIT2,
            abi: [PERMIT2_ALLOWANCE_ABI],
            functionName: "allowance",
            args: [OWNER, token, spender],
          }),
        i
      );
      const nowSec = Math.floor(Date.now() / 1000);
      if (amount > 0n && expiration > nowSec) {
        const symbol = await symbolOf(token);
        permit2Live.push({ token, symbol, spender, amount: amount.toString(), expiration });
      }
    },
    CONCURRENCY
  );

  const report = { owner: OWNER, scannedAt: new Date().toISOString(), erc20Live, permit2Live };
  writeFileSync(new URL("../agent/data/approvals-report.json", import.meta.url), JSON.stringify(report, null, 2));

  console.log("\n=== LIVE ERC-20 APPROVALS ===");
  for (const a of erc20Live) console.log(`  ${a.symbol} (${a.token}) -> ${a.spender}: ${a.amount}`);
  console.log("\n=== LIVE PERMIT2 GRANTS ===");
  for (const a of permit2Live) console.log(`  ${a.symbol} (${a.token}) -> ${a.spender}: ${a.amount} exp=${a.expiration}`);
  console.log(`\nTotal live: ${erc20Live.length} ERC-20 approvals, ${permit2Live.length} Permit2 grants.`);
  console.log("Report written to agent/data/approvals-report.json");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
