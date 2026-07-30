import { test } from "node:test";
import assert from "node:assert/strict";
import { planTokenFindings } from "../lib/tokenFindings.mjs";

const FP = "fb9e99a705d8";
const token = (address) => ({ address });

test("a genuinely new token is reported", () => {
  const plan = planTokenFindings({
    knownFlaggedTokens: ["0xaaa"],
    flaggedNow: [token("0xaaa"), token("0xbbb")],
    fingerprint: FP,
    stateFingerprint: FP,
  });

  assert.deepEqual(plan.findings, ["new suspicious token: 0xbbb"]);
  assert.equal(plan.rebaselined, false);
  assert.deepEqual(plan.knownFlaggedTokens.sort(), ["0xaaa", "0xbbb"]);
});

test("an already-known token is not reported again", () => {
  const plan = planTokenFindings({
    knownFlaggedTokens: ["0xaaa"],
    flaggedNow: [token("0xaaa")],
    fingerprint: FP,
    stateFingerprint: FP,
  });
  assert.deepEqual(plan.findings, []);
});

test("a changed detector re-baselines instead of attesting months-old exposure", () => {
  // The failure this module exists to prevent: a new rule sees 25 tokens that arrived long ago,
  // and attesting them writes a false date on-chain, signed by the agent, permanently.
  const plan = planTokenFindings({
    knownFlaggedTokens: ["0xaaa"],
    flaggedNow: [token("0xaaa"), token("0xbbb"), token("0xccc")],
    fingerprint: FP,
    stateFingerprint: "0000deadbeef",
  });

  assert.deepEqual(plan.findings, [], "nothing is attested on a detector change");
  assert.equal(plan.rebaselined, true);
  assert.deepEqual(plan.knownFlaggedTokens.sort(), ["0xaaa", "0xbbb", "0xccc"]);
  assert.match(plan.reason, /0000deadbeef -> fb9e99a705d8/);
});

test("a state file with no fingerprint is treated as changed, not as matching", () => {
  // Assuming an old baseline was produced by today's rules is the exact wrong guess: the
  // feature exists because the rules keep changing.
  const plan = planTokenFindings({
    knownFlaggedTokens: [],
    flaggedNow: [token("0xaaa")],
    fingerprint: FP,
    stateFingerprint: undefined,
  });

  assert.deepEqual(plan.findings, []);
  assert.equal(plan.rebaselined, true);
  assert.match(plan.reason, /no detector fingerprint/);
});

test("the cycle after a re-baseline reports new tokens normally", () => {
  const first = planTokenFindings({
    knownFlaggedTokens: [],
    flaggedNow: [token("0xaaa")],
    fingerprint: FP,
    stateFingerprint: "old",
  });
  const second = planTokenFindings({
    knownFlaggedTokens: first.knownFlaggedTokens,
    flaggedNow: [token("0xaaa"), token("0xnew")],
    fingerprint: FP,
    stateFingerprint: FP,
  });

  assert.deepEqual(second.findings, ["new suspicious token: 0xnew"]);
  assert.equal(second.rebaselined, false);
});

test("addresses are compared case-insensitively", () => {
  // Blockscout returns checksummed addresses; the state file has held lowercase ones.
  const plan = planTokenFindings({
    knownFlaggedTokens: ["0xAbCd"],
    flaggedNow: [token("0xabcd")],
    fingerprint: FP,
    stateFingerprint: FP,
  });
  assert.deepEqual(plan.findings, []);
});

test("a flagged entry with no address is skipped rather than recorded as undefined", () => {
  const plan = planTokenFindings({
    knownFlaggedTokens: [],
    flaggedNow: [{ name: "no address" }, token("0xaaa")],
    fingerprint: FP,
    stateFingerprint: FP,
  });
  assert.deepEqual(plan.findings, ["new suspicious token: 0xaaa"]);
  assert.deepEqual(plan.knownFlaggedTokens, ["0xaaa"]);
});
