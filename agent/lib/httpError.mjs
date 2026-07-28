// Consistent error responses.
//
// The route handlers used to answer with `String(err?.message ?? err)`, which hands the
// caller whatever the failing library happened to say — upstream URLs, request bodies, viem's
// multi-line diagnostics. None of it is actionable for a client, and some of it describes
// internals that need not be public. The operator wants that detail; the caller wants a code.

/**
 * Log the real error, return a safe body.
 *
 * `code` is a stable machine-readable string the client can branch on. The human-readable
 * detail goes to the server log, keyed by the same code so the two can be matched up.
 */
export function failure(res, { status, code, error, extra, log = console.error }) {
  log(`[${code}] ${describe(error)}`);
  res.status(status).json({ ...extra, error: code });
}

function describe(error) {
  if (!error) return "no error object";
  // viem attaches a one-line shortMessage that is far more useful than the full dump.
  return String(error.shortMessage ?? error.message ?? error);
}

export { describe as describeErrorForLog };
