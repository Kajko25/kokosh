#!/usr/bin/env node
// First ERC-4337 UserOperation for 0x2984: a SimpleAccount (EntryPoint v0.7) owned by the
// Ledger, gas paid entirely in USDC via Pimlico's ERC-20 paymaster. The owner "account" is a
// thin viem LocalAccount wrapping `cast wallet sign --ledger` (personal_sign — the same
// EIP-191 flow that works fine on this device, unlike EIP-7702's raw-hash signing).

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createPublicClient, http } from "viem";
import { toAccount } from "viem/accounts";
import { base } from "viem/chains";
import { entryPoint07Address } from "viem/account-abstraction";
import { createSmartAccountClient } from "permissionless";
import { toSimpleSmartAccount } from "permissionless/accounts";
import { createPimlicoClient } from "permissionless/clients/pimlico";
import { prepareUserOperationForErc20Paymaster } from "permissionless/experimental/pimlico";

const execFileAsync = promisify(execFile);
const OWNER = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

async function ledgerPersonalSign(hex) {
  const { stdout } = await execFileAsync("cast", ["wallet", "sign", hex, "--ledger"]);
  return stdout.trim();
}

const ledgerAccount = toAccount({
  address: OWNER,
  async signMessage({ message }) {
    const raw = typeof message === "string" ? message : message.raw;
    return ledgerPersonalSign(raw);
  },
  async signTransaction() {
    throw new Error("not used in this flow");
  },
  async signTypedData() {
    throw new Error("not used in this flow");
  },
});

const publicClient = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });

const pimlicoUrl = `https://api.pimlico.io/v2/${base.id}/rpc?apikey=${process.env.PIMLICO_API_KEY}`;
const pimlicoClient = createPimlicoClient({
  chain: base,
  transport: http(pimlicoUrl),
  entryPoint: { address: entryPoint07Address, version: "0.7" },
});

const account = await toSimpleSmartAccount({
  client: publicClient,
  owner: ledgerAccount,
  entryPoint: { address: entryPoint07Address, version: "0.7" },
});

console.log("Counterfactual SimpleAccount address:", account.address);

if (process.argv[2] === "address-only") {
  process.exit(0);
}

const smartAccountClient = createSmartAccountClient({
  account,
  chain: base,
  bundlerTransport: http(pimlicoUrl),
  paymaster: pimlicoClient,
  userOperation: {
    estimateFeesPerGas: async () => (await pimlicoClient.getUserOperationGasPrice()).fast,
    prepareUserOperation: prepareUserOperationForErc20Paymaster(pimlicoClient),
  },
});

// Waypoint is onlyOwner(0x2984) — calling it FROM the SimpleAccount would revert, since
// msg.sender would be the smart account's own address, not 0x2984. A trivial self-call proves
// the ERC-4337 + USDC-paymaster mechanism without needing any special permissions.
console.log("Sending UserOperation (gas paid in USDC via Pimlico)...");
const hash = await smartAccountClient.sendTransaction({
  calls: [{ to: account.address, value: 0n, data: "0x" }],
  paymasterContext: { token: USDC },
});

console.log("UserOperation hash:", hash);
