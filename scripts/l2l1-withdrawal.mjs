#!/usr/bin/env node
// Base -> Ethereum L1 withdrawal driver (native OP-Stack bridge, fault-proof era) for 0x2984.
// Read-only: reports status, and when ready, prints the exact calldata to submit via
// `cast send <to> <data> --ledger` (0x2984 signs exclusively via Ledger, never a raw key,
// so this never touches viem's wallet-client/private-key path).
//
// Usage:
//   node l2l1-withdrawal.mjs status   <l2TxHash>
//   node l2l1-withdrawal.mjs prove    <l2TxHash>
//   node l2l1-withdrawal.mjs finalize <l2TxHash>

import { createPublicClient, http, formatEther, encodeFunctionData } from "viem";
import { base, mainnet } from "viem/chains";
import { publicActionsL1, publicActionsL2, getWithdrawals } from "viem/op-stack";

// portal2Abi/portalAbi are internal to viem (no public `viem/op-stack/abis` export), so the
// two OptimismPortal function fragments actually needed are declared here directly instead.
const withdrawalTxComponents = [
  { name: "nonce", type: "uint256" },
  { name: "sender", type: "address" },
  { name: "target", type: "address" },
  { name: "value", type: "uint256" },
  { name: "gasLimit", type: "uint256" },
  { name: "data", type: "bytes" },
];

const proveAbi = [{
  type: "function",
  name: "proveWithdrawalTransaction",
  stateMutability: "nonpayable",
  inputs: [
    { name: "_tx", type: "tuple", components: withdrawalTxComponents },
    { name: "_l2OutputIndex", type: "uint256" },
    { name: "_outputRootProof", type: "tuple", components: [
      { name: "version", type: "bytes32" },
      { name: "stateRoot", type: "bytes32" },
      { name: "messagePasserStorageRoot", type: "bytes32" },
      { name: "latestBlockhash", type: "bytes32" },
    ] },
    { name: "_withdrawalProof", type: "bytes[]" },
  ],
  outputs: [],
}];

const finalizeAbi = [{
  type: "function",
  name: "finalizeWithdrawalTransaction",
  stateMutability: "nonpayable",
  inputs: [{ name: "_tx", type: "tuple", components: withdrawalTxComponents }],
  outputs: [],
}];

const [cmd, hash] = process.argv.slice(2);
if (!cmd || !hash) {
  console.error("usage: node l2l1-withdrawal.mjs <status|prove|finalize> <l2TxHash>");
  process.exit(1);
}

const L1_RPC = process.env.L1_RPC ?? "https://ethereum-rpc.publicnode.com";
const l2 = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") }).extend(publicActionsL2());
const l1 = createPublicClient({ chain: mainnet, transport: http(L1_RPC) }).extend(publicActionsL1());

const receipt = await l2.getTransactionReceipt({ hash });
const [withdrawal] = getWithdrawals(receipt);
console.log("withdrawal nonce:", withdrawal.nonce.toString());
console.log("amount:", formatEther(withdrawal.value), "ETH ->", withdrawal.target);

const status = await l1.getWithdrawalStatus({ receipt, targetChain: base });
console.log("status:", status);

if (cmd === "status") process.exit(0);

const portalAddress = base.contracts.portal[mainnet.id].address;
console.log("portal address (L1):", portalAddress);

if (cmd === "prove") {
  if (status !== "ready-to-prove") {
    console.log("not ready to prove yet — run again later");
    process.exit(2);
  }
  const { output } = await l1.waitToProve({ receipt, targetChain: base });
  const args = await l2.buildProveWithdrawal({ output, withdrawal });
  const data = encodeFunctionData({
    abi: proveAbi,
    functionName: "proveWithdrawalTransaction",
    args: [args.withdrawal, args.l2OutputIndex, args.outputRootProof, args.withdrawalProof],
  });
  console.log("\nSubmit with:");
  console.log(`cast send ${portalAddress} ${data} --rpc-url ${L1_RPC} --ledger`);
} else if (cmd === "finalize") {
  if (status !== "ready-to-finalize") {
    console.log("not ready to finalize yet — run again later");
    process.exit(2);
  }
  const data = encodeFunctionData({
    abi: finalizeAbi,
    functionName: "finalizeWithdrawalTransaction",
    args: [withdrawal],
  });
  console.log("\nSubmit with:");
  console.log(`cast send ${portalAddress} ${data} --rpc-url ${L1_RPC} --ledger`);
} else {
  console.error(`unknown command: ${cmd}`);
  process.exit(1);
}
