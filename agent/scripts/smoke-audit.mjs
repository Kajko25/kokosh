#!/usr/bin/env node
// Check that the deployed /audit still challenges for the right payment, without paying.
//
// The purchase tests cover the loop against a stubbed facilitator, which by construction cannot
// catch a deploy whose *configuration* drifted: missing CDP keys turn the paid endpoint into a
// 503, ALLOW_UNPAID_AUDIT=1 gives the report away, and a wrong payTo would route real money to
// the wrong address while every test still passed. All three are invisible to a test suite and
// obvious in the challenge itself.
//
// Costs nothing and signs nothing: one unauthenticated GET, exactly what any client's first
// request looks like. It never pays -- a real purchase needs the Ledger and stays manual.
//
// Usage: node scripts/smoke-audit.mjs [url]

import { AGENT_WALLET, AUDIT_NETWORK } from "../lib/x402Seller.mjs";

const URL_UNDER_TEST = process.argv[2] ?? "https://kokosh-agent.vercel.app/audit";
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const EXPECTED_AMOUNT = "10000"; // $0.01 at USDC's six decimals

const failures = [];
const check = (label, actual, expected) => {
  const ok = String(actual).toLowerCase() === String(expected).toLowerCase();
  console.log(`${ok ? "ok  " : "FAIL"}  ${label}: ${actual}${ok ? "" : ` (expected ${expected})`}`);
  if (!ok) failures.push(label);
};

const res = await fetch(URL_UNDER_TEST);
console.log(`GET ${URL_UNDER_TEST} -> ${res.status}`);

// 200 is the loud one: it means the agent is handing out the report it exists to sell.
if (res.status !== 402) {
  console.error(
    res.status === 200
      ? "FAIL  /audit answered 200 without payment — the paid report is being served free"
      : `FAIL  /audit answered ${res.status}, expected a 402 payment challenge`
  );
  process.exit(1);
}

const header = res.headers.get("payment-required");
if (!header) {
  console.error("FAIL  402 carried no payment-required header — a client has nothing to pay against");
  process.exit(1);
}

let accepts;
try {
  accepts = JSON.parse(Buffer.from(header, "base64").toString("utf8")).accepts?.[0];
} catch (err) {
  console.error(`FAIL  payment-required is not base64 JSON: ${err.message}`);
  process.exit(1);
}
if (!accepts) {
  console.error("FAIL  payment-required carried no accepts[] entry");
  process.exit(1);
}

check("scheme", accepts.scheme, "exact");
check("network", accepts.network, AUDIT_NETWORK);
check("payTo", accepts.payTo, AGENT_WALLET);
check("asset", accepts.asset, USDC_BASE);
check("amount", accepts.amount, EXPECTED_AMOUNT);
check("domain name", accepts.extra?.name, "USD Coin");
check("domain version", accepts.extra?.version, "2");

if (failures.length) {
  console.error(`\n${failures.length} mismatch(es): ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nAll payment terms match what this repo charges.");
