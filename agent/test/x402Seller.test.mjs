// The payment terms this agent charges on, and the seam that makes them testable.
//
// These constants are not decoration: the agent card advertises them and the middleware collects
// on them, and the two are only consistent because they read the same exports. A test that
// pinned them by copying the values would drift in exactly the way the sharing exists to
// prevent, so this asserts the identity instead -- card and middleware, same source.

import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";

import { buildAuditPaymentMiddleware, AGENT_WALLET, AUDIT_PRICE, AUDIT_NETWORK } from "../lib/x402Seller.mjs";
import { agentCard } from "../app.mjs";

/** Minimal facilitator: enough shape for the resource server to mount against. */
function stubFacilitator() {
  return {
    async verify() {
      return { isValid: true, payer: "0x0000000000000000000000000000000000000001" };
    },
    async settle() {
      return { success: true, transaction: "0x" + "11".repeat(32), network: AUDIT_NETWORK };
    },
    async getSupported() {
      return { kinds: [{ x402Version: 2, scheme: "exact", network: AUDIT_NETWORK }] };
    },
  };
}

test("the agent card advertises exactly what the middleware charges", () => {
  const card = agentCard({ auditMode: "paid" });
  const terms = card.payment["/audit"];

  assert.equal(terms.payTo, AGENT_WALLET);
  assert.equal(terms.price, AUDIT_PRICE);
  assert.equal(terms.network, AUDIT_NETWORK);
  assert.equal(terms.scheme, "x402");
  assert.equal(terms.protocol, "exact");
});

test("payment terms are the courier burner on Base mainnet", () => {
  // The wallet matters enough to state twice: payments must never require the Ledger-held
  // 0x2984 to be present, and must never be addressed to it either.
  assert.equal(AGENT_WALLET, "0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6");
  assert.equal(AUDIT_NETWORK, "eip155:8453");
  assert.match(AUDIT_PRICE, /^\$\d+\.\d{2}$/);
});

test("an injected facilitator is used instead of building a CDP-backed one", () => {
  // Without the seam this call reaches createFacilitatorConfig with undefined credentials.
  // Building the middleware at all is the assertion: it must not need CDP keys to exist.
  const middleware = buildAuditPaymentMiddleware({ facilitatorClient: stubFacilitator() });
  assert.equal(typeof middleware, "function");
});

test("the middleware mounts and challenges an unpaid request", async (t) => {
  const app = express();
  app.use(buildAuditPaymentMiddleware({ facilitatorClient: stubFacilitator() }));
  app.get("/audit", (req, res) => res.json({ reached: true }));

  const server = app.listen(0);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve) => server.once("listening", resolve));

  const res = await fetch(`http://127.0.0.1:${server.address().port}/audit`);
  assert.equal(res.status, 402, "an unpaid request must be challenged, not served");
  assert.notEqual(await res.text(), '{"reached":true}', "the handler must not run without payment");
});

test("the price is configurable without touching the advertised default", () => {
  const middleware = buildAuditPaymentMiddleware({ facilitatorClient: stubFacilitator(), price: "$1.00" });
  assert.equal(typeof middleware, "function");
  assert.equal(AUDIT_PRICE, "$0.01", "overriding a call must not mutate the advertised term");
});
