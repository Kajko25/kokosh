// Decide which flagged tokens count as *new* — the question that gates an on-chain attestation.
//
// The sentinel's contract with its own state file is: EAS attestations record changes in the
// wallet, git records changes in the detector. Holding those apart is not a nicety. An
// attestation says "as of this timestamp, this exposure appeared", and the wallet's scam
// airdrops mostly arrived months ago; attesting them because a new rule started seeing them
// puts a false date on-chain, permanently, signed by the agent.
//
// This has happened twice — the pagination fix and the bare-domain rule each made the scan see
// tokens it had never seen — and both times it was caught by a human noticing and re-seeding
// the baseline by hand. That is a rule enforced by memory, which is to say not enforced.
//
// So the ruleset's fingerprint travels in the state file. When it differs from the running
// detector's, this cycle re-baselines instead of reporting: every currently flagged token is
// recorded as known, and nothing is attested. The next cycle, on an unchanged detector, reports
// genuinely new tokens normally.

/**
 * @param {object} args
 * @param {string[]} args.knownFlaggedTokens addresses already recorded by earlier cycles
 * @param {{address: string}[]} args.flaggedNow everything the current detector flags
 * @param {string} args.fingerprint the running detector's fingerprint
 * @param {string|undefined} args.stateFingerprint the fingerprint stored in the state file
 * @returns {{findings: string[], knownFlaggedTokens: string[], rebaselined: boolean, reason?: string}}
 */
export function planTokenFindings({ knownFlaggedTokens = [], flaggedNow = [], fingerprint, stateFingerprint } = {}) {
  const known = new Set(knownFlaggedTokens.map((a) => a.toLowerCase()));
  const nowAddresses = flaggedNow.map((t) => t.address?.toLowerCase()).filter(Boolean);

  // A state file predating fingerprinting is treated as a detector change, not as a match. The
  // alternative — assuming the stored baseline was produced by today's rules — is the exact
  // wrong guess, since the feature exists because the rules keep changing.
  if (stateFingerprint !== fingerprint) {
    const merged = new Set([...known, ...nowAddresses]);
    return {
      findings: [],
      knownFlaggedTokens: [...merged],
      rebaselined: true,
      reason: stateFingerprint
        ? `detector fingerprint changed (${stateFingerprint} -> ${fingerprint})`
        : `state file carries no detector fingerprint (now ${fingerprint})`,
    };
  }

  const findings = [];
  for (const address of nowAddresses) {
    if (!known.has(address)) {
      findings.push(`new suspicious token: ${address}`);
      known.add(address);
    }
  }

  return { findings, knownFlaggedTokens: [...known], rebaselined: false };
}
