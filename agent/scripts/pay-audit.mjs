#!/usr/bin/env node
// Pays Kokosh's own /audit endpoint via x402, signing the USDC transfer authorization
// with the 0x2984 Ledger through `cast wallet sign --data --ledger` (EIP-712, which the
// device supports natively — unlike EIP-7702 raw-hash signing).

import { execFile } from "node:child_process";
import { writeFile, unlink } from "node:fs/promises";
import { promisify } from "node:util";
import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";

const execFileAsync = promisify(execFile);
const OWNER = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const AUDIT_URL = process.argv[2] ?? "https://kokosh-agent.vercel.app/audit";

const ledgerSigner = {
  address: OWNER,
  async signTypedData({ domain, types, primaryType, message }) {
    const typedData = { domain, types: { EIP712Domain: eip712DomainType(domain), ...types }, primaryType, message };
    const tmpFile = `/tmp/kokosh-x402-typed-${Date.now()}.json`;
    await writeFile(tmpFile, JSON.stringify(typedData, (_key, value) => (typeof value === "bigint" ? value.toString() : value)));
    try {
      const { stdout } = await execFileAsync("cast", [
        "wallet",
        "sign",
        "--data",
        "--from-file",
        tmpFile,
        "--ledger",
      ]);
      return stdout.trim();
    } finally {
      await unlink(tmpFile).catch(() => {});
    }
  },
};

function eip712DomainType(domain) {
  const fields = [];
  if (domain.name !== undefined) fields.push({ name: "name", type: "string" });
  if (domain.version !== undefined) fields.push({ name: "version", type: "string" });
  if (domain.chainId !== undefined) fields.push({ name: "chainId", type: "uint256" });
  if (domain.verifyingContract !== undefined) fields.push({ name: "verifyingContract", type: "address" });
  return fields;
}

const client = new x402Client();
registerExactEvmScheme(client, { signer: ledgerSigner });

const fetchWithPay = wrapFetchWithPayment(fetch, client);

console.log(`Requesting ${AUDIT_URL} (expect a Ledger EIP-712 signature prompt)...`);
const res = await fetchWithPay(AUDIT_URL);
console.log("status:", res.status);
console.log(await res.text());
