import { readFile } from "node:fs/promises";
import { detectorFingerprint } from "./scamHeuristics.mjs";

// The daily sentinel cycle has already stopped running once without anyone noticing: the log
// showed a jitter line and then nothing, while the state file's lastRunAt sat four days back.
// It was found by reading project notes, not by any alert, and the reason nothing surfaced it is
// that a stand-down cycle and a dead cron produce the same silence.
//
// This turns the state file into something a monitor can watch from outside: how long since the
// last cycle, whether that exceeds the expected interval, and whether the ruleset that produced
// the baseline is the one running now.

// The cron fires daily with up to 45 minutes of jitter, so a healthy gap can exceed 24h.
export const EXPECTED_INTERVAL_SECONDS = 26 * 3600;

export async function readSentinelReport({ path, now = () => Date.now(), log = console.warn } = {}) {
  let parsed;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    // Same distinction the exposure reader had to learn: a missing file is a wallet whose
    // sentinel was never seeded, while unreadable or malformed content is a broken deployment.
    if (err?.code !== "ENOENT") log(`sentinel state unusable at ${path}: ${err?.message ?? err}`);
    return null;
  }

  const lastRunAt = typeof parsed.lastRunAt === "string" ? parsed.lastRunAt : null;
  const ranAtMs = lastRunAt ? Date.parse(lastRunAt) : NaN;
  const ageSeconds = Number.isNaN(ranAtMs) ? null : Math.max(0, Math.round((now() - ranAtMs) / 1000));

  const running = detectorFingerprint();
  const stored = typeof parsed.detectorFingerprint === "string" ? parsed.detectorFingerprint : null;

  return {
    lastRunAt,
    ageSeconds,
    // Null age counts as overdue: a state file with no usable lastRunAt is not evidence of a
    // recent run, and reporting `false` there would be the reassuring answer, not the true one.
    overdue: ageSeconds === null || ageSeconds > EXPECTED_INTERVAL_SECONDS,
    expectedIntervalSeconds: EXPECTED_INTERVAL_SECONDS,
    lastScannedBlock: parsed.lastScannedBlock ?? null,
    knownFlaggedTokens: Array.isArray(parsed.knownFlaggedTokens) ? parsed.knownFlaggedTokens.length : null,
    // The findings that need a human: 0x2984 signs with a Ledger, so the agent can report a new
    // allowance but never revoke it. Listed in full rather than counted, since each one is an
    // action item.
    alertedApprovals: Array.isArray(parsed.alertedApprovals) ? parsed.alertedApprovals : [],
    detector: {
      running,
      baseline: stored,
      // When these differ the next cycle re-baselines and attests nothing, so a caller reading
      // "0 findings" deserves to know that is why.
      willRebaseline: stored !== running,
    },
  };
}
