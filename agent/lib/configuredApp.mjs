// Builds the app from environment variables.
//
// Three places need the same wiring — the local server, the Vercel function under api/, and
// app.mjs's own default export (Vercel's Node builder picks app.mjs as the entrypoint because
// it is the root file importing express, and invokes its default export directly). Having one
// factory means those three cannot drift into configuring the agent differently.

import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { warnOnAuditMode } from "./auditMode.mjs";

const RPC = "https://mainnet.base.org";

export function appConfigFromEnv(env = process.env) {
  return {
    cdp: { apiKeyId: env.CDP_API_KEY_ID, apiKeySecret: env.CDP_API_KEY_SECRET },
    allowUnpaidAudit: env.ALLOW_UNPAID_AUDIT === "1",
  };
}

/**
 * `makeApp` is passed in rather than imported, because app.mjs imports this module and
 * importing it back would be circular.
 */
export function buildConfiguredApp(makeApp, { env = process.env, resolveAuditMode } = {}) {
  const config = appConfigFromEnv(env);
  const client = createPublicClient({ chain: base, transport: http(RPC) });

  if (resolveAuditMode) warnOnAuditMode(resolveAuditMode(config));

  return makeApp({ client, ...config });
}
