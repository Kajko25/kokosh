// Age reporting for the committed approval snapshot.
//
// /exposure and /audit serve data produced by scripts/scan-approvals.mjs, not a live scan.
// The response carried `scannedAt` but nothing said how old that was, so a caller had to
// know the endpoint's implementation to interpret it. A snapshot that silently ages is the
// same class of problem as a monitor that silently stops: it keeps answering confidently
// while drifting away from the truth.

// The scanner is a manual operation, so a day is the point past which the answer should be
// treated as indicative rather than current.
export const STALE_AFTER_SECONDS = 86_400;

export function describeFreshness(scannedAt, { now = () => Date.now(), staleAfterSeconds = STALE_AFTER_SECONDS } = {}) {
  const parsed = Date.parse(scannedAt ?? "");
  if (Number.isNaN(parsed)) {
    return { scannedAt: scannedAt ?? null, ageSeconds: null, stale: true };
  }

  // A snapshot timestamped in the future means a clock problem somewhere; clamp rather than
  // reporting a negative age, and don't call it fresh on the strength of a bad timestamp.
  const ageSeconds = Math.max(0, Math.round((now() - parsed) / 1000));

  return {
    scannedAt: new Date(parsed).toISOString(),
    ageSeconds,
    stale: ageSeconds > staleAfterSeconds,
  };
}
