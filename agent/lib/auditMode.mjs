// Startup reporting for /audit's payment configuration.
//
// Kept out of makeApp so the factory stays side-effect free and silent under test; the
// entry points (server.mjs, api/index.js) call this once so an operator sees the state in
// the deploy log instead of discovering it from a suspiciously popular free endpoint.

const MESSAGES = {
  paid: "/audit: payments enabled (x402, $0.01 USDC on Base).",
  unpaid:
    "/audit: serving FREE — ALLOW_UNPAID_AUDIT=1 is set. Deliberate; unset it to require payment.",
  unavailable:
    "/audit: DISABLED (503) — CDP_API_KEY_ID / CDP_API_KEY_SECRET are missing, so payment cannot " +
    "be collected. Set both to charge for it, or ALLOW_UNPAID_AUDIT=1 to serve it free on purpose.",
};

export function warnOnAuditMode(mode, log = console) {
  const message = MESSAGES[mode];
  if (!message) return;
  if (mode === "paid") log.log(message);
  else log.warn(message);
}
