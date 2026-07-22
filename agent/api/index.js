import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { makeApp } from "../app.mjs";

const client = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });
const app = makeApp({
  client,
  cdp: { apiKeyId: process.env.CDP_API_KEY_ID, apiKeySecret: process.env.CDP_API_KEY_SECRET },
});

export default app;
