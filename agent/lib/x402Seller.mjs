import { createFacilitatorConfig } from "@coinbase/x402";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { x402ResourceServer } from "@x402/core/server";
import { paymentMiddleware } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";

// The courier burner, not the Ledger-held main wallet, so receiving payments never needs
// hardware present. Exported because the agent card advertises these same terms — a card that
// disagreed with what the middleware actually charges would be worse than no card.
export const AGENT_WALLET = "0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6";
export const AUDIT_PRICE = "$0.01";
export const AUDIT_NETWORK = "eip155:8453";

/**
 * `facilitatorClient` is injectable for the same reason `makeApp` takes its viem client rather
 * than constructing one: without a seam, the only way to exercise the payment path is to pay.
 * A real purchase needs the Ledger and real USDC, so the 402 → sign → 200 loop — the part a
 * paying customer actually depends on — had no test at all. Left unset in production, where the
 * CDP-backed HTTP facilitator is built exactly as before.
 */
export function buildAuditPaymentMiddleware({ cdpApiKeyId, cdpApiKeySecret, price = AUDIT_PRICE, facilitatorClient }) {
  const client = facilitatorClient ?? new HTTPFacilitatorClient(createFacilitatorConfig(cdpApiKeyId, cdpApiKeySecret));
  const server = new x402ResourceServer(client).register(AUDIT_NETWORK, new ExactEvmScheme());

  const routes = {
    "/audit": {
      accepts: {
        scheme: "exact",
        payTo: AGENT_WALLET,
        price,
        network: AUDIT_NETWORK,
      },
      description: "Kokosh wallet hygiene audit: live approval exposure + scam-airdrop scan for kajko24.base.eth",
    },
  };

  return paymentMiddleware(routes, server);
}
