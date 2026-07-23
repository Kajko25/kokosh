#!/usr/bin/env node
// Manual execution of a Base Account spend permission (the primitive behind
// base.subscription.subscribe()). prepareCharge/prepareRevoke return raw calldata —
// no CDP-managed wallet needed, so we submit it from the courier burner via `cast send`,
// same pattern already used for the EIP-2612 permit and ERC-8004 setAgentWallet flows.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { homedir } from "node:os";
import { join } from "node:path";
import { base } from "@base-org/account";

const execFileAsync = promisify(execFile);
const RPC = "https://mainnet.base.org";
const PASSWORD_FILE = join(homedir(), ".foundry/keystores/courier.password");

async function sendFromCourier(to, data, value = "0x0") {
  const args = ["send", to, data, "--rpc-url", RPC, "--account", "courier", "--password-file", PASSWORD_FILE];
  if (value && value !== "0x0") args.push("--value", value);
  const { stdout } = await execFileAsync("cast", args);
  return stdout;
}

const [, , cmd, id, amount] = process.argv;
if (!cmd || !id) {
  console.error("usage: node spend-permission.mjs <status|charge|revoke> <subscriptionId> [amount|max-remaining-charge]");
  process.exit(1);
}

if (cmd === "status") {
  const status = await base.subscription.getStatus({ id, testnet: false });
  console.log(JSON.stringify(status, null, 2));
} else if (cmd === "charge") {
  const calls = await base.subscription.prepareCharge({ id, amount: amount ?? "max-remaining-charge", testnet: false });
  console.log(`prepared ${calls.length} call(s)`);
  for (const call of calls) {
    console.log(`sending to ${call.to}...`);
    console.log(await sendFromCourier(call.to, call.data, call.value));
  }
} else if (cmd === "revoke") {
  const call = await base.subscription.prepareRevoke({ id, testnet: false });
  console.log(`sending revoke to ${call.to}...`);
  console.log(await sendFromCourier(call.to, call.data, call.value));
} else {
  console.error(`unknown command: ${cmd}`);
  process.exit(1);
}
