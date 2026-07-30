// Validation for the sentinel's state file.
//
// The run's scan range comes straight from `lastScannedBlock`. A corrupted or hand-edited
// value does not fail loudly — it quietly changes what gets scanned. Missing entirely, the
// scan would start from block 0 and walk ~5,000 windows; a value ahead of the chain tip makes
// the range empty, so the sentinel reports "no new blocks" forever while looking healthy.
//
// Both are the same failure this agent has already had once: something silently stops working
// and nothing distinguishes it from a quiet, correct run.

export class InvalidSentinelState extends Error {
  constructor(message) {
    super(`sentinel state invalid: ${message}`);
    this.name = "InvalidSentinelState";
  }
}

export function parseSentinelState(raw, { latestBlock } = {}) {
  let parsed;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch (err) {
    throw new InvalidSentinelState(`not valid JSON (${err.message})`);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new InvalidSentinelState("expected a JSON object");
  }

  const { lastScannedBlock } = parsed;
  if (lastScannedBlock === undefined || lastScannedBlock === null) {
    throw new InvalidSentinelState("lastScannedBlock is missing — seed a baseline rather than rescanning from genesis");
  }

  let block;
  try {
    block = BigInt(lastScannedBlock);
  } catch {
    throw new InvalidSentinelState(`lastScannedBlock is not an integer: ${JSON.stringify(lastScannedBlock)}`);
  }
  if (block < 0n) {
    throw new InvalidSentinelState("lastScannedBlock is negative");
  }
  if (latestBlock !== undefined && block > BigInt(latestBlock)) {
    // Otherwise every future run computes an empty range and reports "no new blocks",
    // indistinguishable from a healthy quiet cycle.
    throw new InvalidSentinelState(`lastScannedBlock ${block} is ahead of the chain tip ${latestBlock}`);
  }

  const knownFlaggedTokens = parsed.knownFlaggedTokens ?? [];
  if (!Array.isArray(knownFlaggedTokens)) {
    throw new InvalidSentinelState("knownFlaggedTokens must be an array");
  }
  const alertedApprovals = parsed.alertedApprovals ?? [];
  if (!Array.isArray(alertedApprovals)) {
    throw new InvalidSentinelState("alertedApprovals must be an array");
  }

  // Optional: absent on state files written before the detector was fingerprinted, which
  // planTokenFindings treats as "changed" and re-baselines. A non-string, though, would compare
  // unequal forever and re-baseline every cycle, so the sentinel would never report a token
  // again — silent uselessness, which is this agent's recurring failure mode.
  const { detectorFingerprint } = parsed;
  if (detectorFingerprint !== undefined && typeof detectorFingerprint !== "string") {
    throw new InvalidSentinelState(`detectorFingerprint must be a string, got ${typeof detectorFingerprint}`);
  }

  return { ...parsed, lastScannedBlock: block.toString(), knownFlaggedTokens, alertedApprovals };
}
