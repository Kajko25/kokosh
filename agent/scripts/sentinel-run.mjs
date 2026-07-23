#!/usr/bin/env node
// Kokosh's own autonomous hygiene check: periodically re-scans 0x2984's live approvals and
// token holdings for anything NEW since the last run, and only speaks up (an on-chain EAS
// attestation, signed by courier — the agent wallet, no Ledger needed) when something
// actually changed. No finding, no attestation — this is a real check, not a heartbeat.
//
// Can't auto-revoke: only 0x2984's own Ledger can call approve() on its own allowances, so
// a new live approval is reported, not fixed, here. That's a real constraint of this
// wallet's hardware-signing policy, not an oversight.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createPublicClient, http, parseAbiItem, getAddress, encodeAbiParameters } from "viem";
import { base } from "viem/chains";
import { classifyToken } from "../lib/scamHeuristics.mjs";
import { fetchTokenHoldings } from "../lib/blockscout.mjs";

const execFileAsync = promisify(execFile);
const OWNER = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const COURIER_PASSWORD_FILE = "/home/kajko/.foundry/keystores/courier.password";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const EAS = "0x4200000000000000000000000000000000000021";
const SENTINEL_SCHEMA = "0x3741936182a94f6252130505509e2f0853cb231fcff5d92b41ed2b4397e93032";
const STATE_PATH = new URL("../../docs/sentinel-state.json", import.meta.url);
const RPC = "https://mainnet.base.org";

const client = createPublicClient({ chain: base, transport: http(RPC) });

const ERC20_APPROVAL = parseAbiItem("event Approval(address indexed owner, address indexed spender, uint256 value)");
const PERMIT2_APPROVAL = parseAbiItem(
  "event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration)"
);

function loadState() {
  if (!existsSync(STATE_PATH)) {
    throw new Error("no docs/sentinel-state.json — seed one with a baseline lastScannedBlock/knownFlaggedTokens first");
  }
  return JSON.parse(readFileSync(STATE_PATH, "utf8"));
}

async function scanNewApprovals(fromBlock, toBlock) {
  const [erc20Logs, permit2Logs] = await Promise.all([
    client.getLogs({ event: ERC20_APPROVAL, args: { owner: OWNER }, fromBlock, toBlock }),
    client.getLogs({ event: PERMIT2_APPROVAL, args: { owner: OWNER }, fromBlock, toBlock }),
  ]);

  const pairs = new Map();
  for (const log of erc20Logs) {
    const token = getAddress(log.address);
    const spender = getAddress(log.args.spender);
    pairs.set(`erc20:${token}:${spender}`, { kind: "erc20", token, spender });
  }
  for (const log of permit2Logs) {
    const token = getAddress(log.args.token);
    const spender = getAddress(log.args.spender);
    pairs.set(`permit2:${token}:${spender}`, { kind: "permit2", token, spender });
  }

  const live = [];
  for (const p of pairs.values()) {
    if (p.kind === "erc20") {
      const amount = await client.readContract({
        address: p.token,
        abi: [parseAbiItem("function allowance(address,address) view returns (uint256)")],
        functionName: "allowance",
        args: [OWNER, p.spender],
      });
      if (amount > 0n) live.push({ ...p, amount: amount.toString() });
    } else {
      const [amount, expiration] = await client.readContract({
        address: PERMIT2,
        abi: [parseAbiItem("function allowance(address,address,address) view returns (uint160,uint48,uint48)")],
        functionName: "allowance",
        args: [OWNER, p.token, p.spender],
      });
      if (amount > 0n && expiration > Math.floor(Date.now() / 1000)) {
        live.push({ ...p, amount: amount.toString(), expiration });
      }
    }
  }
  return live;
}

async function attestFinding(newFindings, summary) {
  const checkedAt = Math.floor(Date.now() / 1000);
  const data = encodeAbiParameters(
    [{ type: "address" }, { type: "uint64" }, { type: "uint16" }, { type: "string" }],
    [OWNER, BigInt(checkedAt), newFindings, summary]
  );
  const noExpiration = 0;
  const noRefUid = "0x" + "00".repeat(32);
  const noValue = 0;
  const tuple = `(${SENTINEL_SCHEMA},(${OWNER},${noExpiration},true,${noRefUid},${data},${noValue}))`;
  const { stdout } = await execFileAsync("cast", [
    "send",
    EAS,
    "attest((bytes32,(address,uint64,bool,bytes32,bytes,uint256)))",
    tuple,
    "--rpc-url",
    RPC,
    "--account",
    "courier",
    "--password-file",
    COURIER_PASSWORD_FILE,
  ]);
  return stdout;
}

async function main() {
  const state = loadState();
  const latest = await client.getBlockNumber();
  const fromBlock = BigInt(state.lastScannedBlock) + 1n;

  console.log(`sentinel run @ ${new Date().toISOString()} — scanning blocks ${fromBlock}-${latest}`);

  const findings = [];

  if (fromBlock <= latest) {
    const liveApprovals = await scanNewApprovals(fromBlock, latest);
    const known = new Set(state.alertedApprovals ?? []);
    for (const a of liveApprovals) {
      const key = `${a.kind}:${a.token}:${a.spender}`;
      if (!known.has(key)) {
        findings.push(`new live approval: ${a.token} -> ${a.spender} (${a.kind}, amount ${a.amount})`);
        known.add(key);
      }
    }
    state.alertedApprovals = [...known];
  } else {
    console.log("no new blocks since last run");
  }

  const holdings = await fetchTokenHoldings(OWNER);
  const flaggedNow = new Set(
    holdings.map((t) => ({ ...t, ...classifyToken(t) })).filter((t) => t.suspicious).map((t) => t.address.toLowerCase())
  );
  const knownFlagged = new Set((state.knownFlaggedTokens ?? []).map((a) => a.toLowerCase()));
  for (const addr of flaggedNow) {
    if (!knownFlagged.has(addr)) {
      findings.push(`new suspicious token: ${addr}`);
      knownFlagged.add(addr);
    }
  }
  state.knownFlaggedTokens = [...knownFlagged];
  state.lastScannedBlock = latest.toString();
  state.lastRunAt = new Date().toISOString();

  if (findings.length === 0) {
    console.log("no new findings — standing down, no attestation");
  } else {
    const summary = findings.join("; ").slice(0, 500);
    console.log(`${findings.length} new finding(s): ${summary}`);
    if (findings.some((f) => f.startsWith("new live approval"))) {
      console.log("NOTE: new live approval(s) require a human to revoke via 0x2984's Ledger — the agent cannot sign for the owner's own wallet.");
    }
    const out = await attestFinding(findings.length, summary);
    console.log(out);
  }

  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
