#!/usr/bin/env node
// Encodes a shareable Prolink for a small USDC payment request to courier, then round-trips
// it through decodeProlink as a sanity check before printing the URL to actually open.

import { encodeFunctionData, parseUnits } from "viem";
// Real SDK gap: createProlinkUrl is only re-exported from the browser build
// (dist/interface/public-utilities/prolink/index.js), not from index.node.js — importing
// it from '@base-org/account/prolink' in Node throws "does not provide an export named
// createProlinkUrl". Built it inline instead; per the function's own source, the query
// param key is "p", not "prolink" as the reference doc's prose might suggest.
import { encodeProlink, decodeProlink } from "@base-org/account/prolink";

function createProlinkUrl(prolink, url) {
  const link = new URL(url);
  link.searchParams.set("p", prolink);
  return link.toString();
}

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const COURIER = "0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6";
const AMOUNT = "0.02";

const data = encodeFunctionData({
  abi: [{ type: "function", name: "transfer", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] }],
  functionName: "transfer",
  args: [COURIER, parseUnits(AMOUNT, 6)],
});

// Real SDK gap #2: the reference doc's example passes params as a bare object, but the
// installed package's encodeProlink asserts Array.isArray(request.params) and reads
// request.params[0] — params must be array-wrapped, standard JSON-RPC style.
const prolink = await encodeProlink({
  method: "wallet_sendCalls",
  params: [{
    version: "2.0.0",
    chainId: "0x2105",
    calls: [{ to: USDC, data, value: "0x0" }],
  }],
});

const decoded = await decodeProlink(prolink);
console.log("round-trip decode:", JSON.stringify(decoded, null, 2));

const url = createProlinkUrl(prolink, "https://kokosh-agent.vercel.app/prolink.html");
console.log("\nopen this URL in the browser with the passkey Base Account signed in:\n" + url);
