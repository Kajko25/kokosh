// The 402 → sign → 200 loop, end to end, with no money and no hardware.
//
// This is the flow a paying customer depends on and the one part of the agent that was never
// covered: a real purchase signs with the Ledger-held 0x2984 and spends real USDC, so it can
// only be exercised by hand. Everything except chain settlement is genuine here -- the real
// x402 client, the real EIP-3009 typed data, a real secp256k1 signature -- over a throwaway key
// generated per run, holding nothing, on no chain.
//
// WHO CHECKS WHAT. The agent does not validate payments itself: amount, recipient and signature
// all travel to the facilitator, and its verdict decides whether the audit is served. Probing
// established that directly -- a facilitator stubbed to approve everything will sell an audit
// for a tampered authorization, because nothing upstream of it looks. That is x402 working as
// designed, but it means a stub that always approves cannot test anything about payment safety.
// So the facilitator here *actually verifies*: it recovers the EIP-712 signature and compares
// the authorization against the requirements it was handed. What that leaves under test is
// exactly what belongs to this agent -- that it states the right requirements, and that it
// respects the answer.

import { test } from "node:test";
import express from "express";
import assert from "node:assert/strict";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { verifyTypedData } from "viem";
import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";

import { makeApp } from "../app.mjs";
import { AGENT_WALLET, AUDIT_NETWORK } from "../lib/x402Seller.mjs";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

// The header the payer resubmits with. Not `X-PAYMENT`: that name is x402 v1 and the installed
// v2 client sends `payment-signature`. Asserted in its own test below, because getting this
// wrong is invisible -- an unrecognised header simply reads as an unpaid request.
const PAYMENT_HEADER = "payment-signature";

const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const HOLDINGS = {
  tokens: async () => [{ address: "0xdead", symbol: "OK", name: "Ordinary Token", type: "ERC-20" }],
  nfts: async () => [],
};

/**
 * Behaves like a real facilitator: verifies the signature against EIP-3009 typed data and checks
 * the authorization pays what the requirements demanded, to whom they demanded. Records calls so
 * a test can assert what the agent asked for. Settlement is faked -- that is where money would
 * move, and it is the one thing that must not be real here.
 */
function verifyingFacilitator() {
  const calls = { verify: [], settle: [] };
  return {
    calls,
    async verify(payload, requirements) {
      calls.verify.push({ payload, requirements });
      const auth = payload?.payload?.authorization;
      const signature = payload?.payload?.signature;
      if (!auth || !signature) return { isValid: false, invalidReason: "malformed" };

      const signedByPayer = await verifyTypedData({
        address: auth.from,
        domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC_BASE },
        types: EIP3009_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from: auth.from,
          to: auth.to,
          value: BigInt(auth.value),
          validAfter: BigInt(auth.validAfter),
          validBefore: BigInt(auth.validBefore),
          nonce: auth.nonce,
        },
        signature,
      }).catch(() => false);

      if (!signedByPayer) return { isValid: false, invalidReason: "bad_signature" };
      if (auth.to.toLowerCase() !== requirements.payTo.toLowerCase()) {
        return { isValid: false, invalidReason: "wrong_recipient" };
      }
      if (BigInt(auth.value) < BigInt(requirements.amount)) {
        return { isValid: false, invalidReason: "underpaid" };
      }
      return { isValid: true, payer: auth.from };
    },
    async settle(payload, requirements) {
      calls.settle.push({ payload, requirements });
      return { success: true, transaction: "0x" + "22".repeat(32), network: AUDIT_NETWORK };
    },
    async getSupported() {
      return { kinds: [{ x402Version: 2, scheme: "exact", network: AUDIT_NETWORK }] };
    },
  };
}

function paidApp(facilitatorClient, { captureHeader } = {}) {
  const app = makeApp({
    client: {},
    cdp: { apiKeyId: "test-id", apiKeySecret: "test-secret" },
    holdings: HOLDINGS,
    facilitatorClient,
  });
  if (!captureHeader) return app;

  // Wrapped rather than appended: the payment middleware lives inside makeApp and answers the
  // request itself, so anything mounted after it never runs. The observer has to sit in front.
  const outer = express();
  outer.use((req, _res, next) => {
    if (req.headers[PAYMENT_HEADER]) captureHeader(req.headers[PAYMENT_HEADER]);
    next();
  });
  outer.use(app);
  return outer;
}

/**
 * Dropping connections explicitly is load-bearing, not tidiness: Node's fetch keeps its
 * connections alive, so `close()` alone waits for them and a finished test hangs instead of
 * ending. This repo has been bitten by that before -- a clear failure became a silent 45-second
 * stall with no output.
 */
function closeServer(server) {
  return new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(resolve);
  });
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

/** A fetch that pays, signing with a fresh throwaway key. */
function payingFetch() {
  const account = privateKeyToAccount(generatePrivateKey());
  const client = new x402Client();
  registerExactEvmScheme(client, {
    signer: {
      address: account.address,
      signTypedData: (typedData) => account.signTypedData(typedData),
    },
  });
  return { fetchWithPay: wrapFetchWithPayment(fetch, client), account };
}

/**
 * Buys once honestly and returns the header the real client produced, for tests that then tamper
 * with it.
 *
 * Takes `t` so teardown is registered before anything can throw. Getting that order wrong is how
 * this file first hung: a failed assertion skipped the close, the listening server kept the
 * runner alive, and a clear failure became a silent timeout.
 */
async function capturePaidHeader(facilitator, t) {
  let header = null;
  const app = paidApp(facilitator, { captureHeader: (value) => (header = value) });
  const server = await listen(app);
  t.after(() => closeServer(server));

  const { fetchWithPay } = payingFetch();
  const res = await fetchWithPay(`http://127.0.0.1:${server.address().port}/audit`);
  assert.equal(res.status, 200, "the honest purchase this builds on must succeed");
  assert.ok(header, "the paid request must carry the payment header");
  return { header, port: server.address().port };
}

/** Replays a header with one field of the authorization changed. */
async function resubmit(port, header, mutate) {
  const decoded = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  mutate(decoded);
  return fetch(`http://127.0.0.1:${port}/audit`, {
    headers: { [PAYMENT_HEADER]: Buffer.from(JSON.stringify(decoded)).toString("base64") },
  });
}

test("an unpaid request is challenged with terms naming USDC on Base", async (t) => {
  const server = await listen(paidApp(verifyingFacilitator()));
  t.after(() => closeServer(server));

  const res = await fetch(`http://127.0.0.1:${server.address().port}/audit`);
  assert.equal(res.status, 402);

  const header = res.headers.get("payment-required");
  assert.ok(header, "the challenge must carry payment-required");
  const accepts = JSON.parse(Buffer.from(header, "base64").toString("utf8")).accepts[0];

  assert.equal(accepts.scheme, "exact");
  assert.equal(accepts.network, AUDIT_NETWORK);
  assert.equal(accepts.payTo, AGENT_WALLET);
  assert.equal(accepts.asset.toLowerCase(), USDC_BASE.toLowerCase(), "must charge in native USDC");
  assert.equal(accepts.amount, "10000", "$0.01 at six decimals");
  // The domain the payer will sign under travels in the challenge; a wrong name or version
  // produces a signature no facilitator can verify.
  assert.deepEqual(accepts.extra, { name: "USD Coin", version: "2" });
});

test("paying the challenge returns the audit, and the signature is genuinely the payer's", async (t) => {
  const facilitator = verifyingFacilitator();
  const server = await listen(paidApp(facilitator));
  t.after(() => closeServer(server));

  const { fetchWithPay, account } = payingFetch();
  const res = await fetchWithPay(`http://127.0.0.1:${server.address().port}/audit`);

  assert.equal(res.status, 200, "a paid request must be served");
  const body = await res.json();
  assert.equal(body.wallet, "0x2984Bb4953cfCE2cEc957388BE686D6c38779234");
  assert.ok(body.hygieneScore, "the audit must carry the product it sells");

  assert.equal(facilitator.calls.verify.length, 1, "payment must reach the facilitator exactly once");
  assert.equal(facilitator.calls.settle.length, 1, "a verified payment must settle");

  const { payload, requirements } = facilitator.calls.verify[0];
  const authorization = payload.payload.authorization;

  // What this agent is responsible for: stating the right terms to the facilitator.
  assert.equal(requirements.payTo, AGENT_WALLET);
  assert.equal(requirements.amount, "10000");
  assert.equal(requirements.asset.toLowerCase(), USDC_BASE.toLowerCase());

  assert.equal(authorization.to.toLowerCase(), AGENT_WALLET.toLowerCase(), "paying anyone else is a bug");
  assert.equal(authorization.value, "10000");
  assert.equal(authorization.from.toLowerCase(), account.address.toLowerCase());
});

test("the payer resubmits under payment-signature, not the v1 X-PAYMENT name", async (t) => {
  // Worth pinning: an unrecognised header does not error, it reads as an unpaid request. A
  // client following the wrong name gets 402 forever with nothing to explain why.
  const facilitator = verifyingFacilitator();
  const { header, port } = await capturePaidHeader(facilitator, t);

  const asV1 = await fetch(`http://127.0.0.1:${port}/audit`, { headers: { "X-PAYMENT": header } });
  assert.equal(asV1.status, 402, "the v1 header name must not be mistaken for payment");

  const asV2 = await fetch(`http://127.0.0.1:${port}/audit`, { headers: { [PAYMENT_HEADER]: header } });
  assert.equal(asV2.status, 200, "the v2 header name must be accepted");
});

test("an authorization edited to pay less does not buy an audit", async (t) => {
  const facilitator = verifyingFacilitator();
  const { header, port } = await capturePaidHeader(facilitator, t);

  const res = await resubmit(port, header, (d) => {
    d.payload.authorization.value = "1";
  });

  assert.notEqual(res.status, 200, "underpaying must not be served");
  const lastVerify = facilitator.calls.verify.at(-1);
  assert.equal(lastVerify.requirements.amount, "10000", "the agent must still demand the full price");
});

test("an authorization redirected to another payee does not buy an audit", async (t) => {
  const facilitator = verifyingFacilitator();
  const { header, port } = await capturePaidHeader(facilitator, t);

  const res = await resubmit(port, header, (d) => {
    d.payload.authorization.to = "0x000000000000000000000000000000000000dEaD";
  });

  assert.notEqual(res.status, 200, "a payment addressed elsewhere must not be served");
});

test("a forged signature does not buy an audit", async (t) => {
  const facilitator = verifyingFacilitator();
  const { header, port } = await capturePaidHeader(facilitator, t);

  const res = await resubmit(port, header, (d) => {
    d.payload.signature = "0x" + "00".repeat(65);
  });

  assert.notEqual(res.status, 200, "an unsigned authorization must not be served");
});

test("the agent serves nothing when the facilitator refuses, and settles nothing either", async (t) => {
  const facilitator = verifyingFacilitator();
  facilitator.verify = async () => ({ isValid: false, invalidReason: "test_rejected" });

  const server = await listen(paidApp(facilitator));
  t.after(() => closeServer(server));

  const { fetchWithPay } = payingFetch();
  let status;
  try {
    status = (await fetchWithPay(`http://127.0.0.1:${server.address().port}/audit`)).status;
  } catch {
    // The client throws rather than returning when payment cannot be completed. Either way the
    // assertion below is the one that matters.
    status = 402;
  }

  assert.notEqual(status, 200, "an unverified payment must never be served");
  assert.equal(facilitator.calls.settle.length, 0, "nothing may settle after a failed verify");
});
