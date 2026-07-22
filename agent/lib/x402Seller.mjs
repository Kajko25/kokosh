import { createFacilitatorConfig } from "@coinbase/x402";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { x402ResourceServer } from "@x402/core/server";
import { paymentMiddleware } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";

const AGENT_WALLET = "0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6"; // courier, receives audit payments

export function buildAuditPaymentMiddleware({ cdpApiKeyId, cdpApiKeySecret, price = "$0.01" }) {
  const facilitatorConfig = createFacilitatorConfig(cdpApiKeyId, cdpApiKeySecret);
  const facilitatorClient = new HTTPFacilitatorClient(facilitatorConfig);
  const server = new x402ResourceServer(facilitatorClient).register("eip155:8453", new ExactEvmScheme());

  const routes = {
    "/audit": {
      accepts: {
        scheme: "exact",
        payTo: AGENT_WALLET,
        price,
        network: "eip155:8453",
      },
      description: "Kokosh wallet hygiene audit: live approval exposure + scam-airdrop scan for kajko24.base.eth",
    },
  };

  return paymentMiddleware(routes, server);
}
