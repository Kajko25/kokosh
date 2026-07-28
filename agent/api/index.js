import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { makeApp, resolveAuditMode } from "../lib/app.mjs";
import { warnOnAuditMode } from "../lib/auditMode.mjs";

const client = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });

const cdp = { apiKeyId: process.env.CDP_API_KEY_ID, apiKeySecret: process.env.CDP_API_KEY_SECRET };
const allowUnpaidAudit = process.env.ALLOW_UNPAID_AUDIT === "1";

warnOnAuditMode(resolveAuditMode({ cdp, allowUnpaidAudit }));

const app = makeApp({ client, cdp, allowUnpaidAudit });

export default app;
