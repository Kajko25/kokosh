import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSentinelState, InvalidSentinelState } from "../lib/sentinelState.mjs";

const LATEST = 49_250_000n;

test("a well-formed state is returned with defaults filled in", () => {
  const state = parseSentinelState(
    JSON.stringify({ lastScannedBlock: "49241986" }),
    { latestBlock: LATEST }
  );
  assert.equal(state.lastScannedBlock, "49241986");
  assert.deepEqual(state.knownFlaggedTokens, []);
  assert.deepEqual(state.alertedApprovals, []);
});

test("existing fields are preserved", () => {
  const state = parseSentinelState(
    { lastScannedBlock: 100, knownFlaggedTokens: ["0xabc"], alertedApprovals: ["erc20:0x1:0x2"], note: "keep me" },
    { latestBlock: LATEST }
  );
  assert.deepEqual(state.knownFlaggedTokens, ["0xabc"]);
  assert.deepEqual(state.alertedApprovals, ["erc20:0x1:0x2"]);
  assert.equal(state.note, "keep me");
});

test("malformed JSON is rejected with the reason", () => {
  assert.throws(() => parseSentinelState("{ nope"), InvalidSentinelState);
});

test("a missing lastScannedBlock is refused rather than defaulting to genesis", () => {
  // Defaulting to 0 would silently start a ~5,000-window walk from block 0 on every run.
  assert.throws(
    () => parseSentinelState(JSON.stringify({ knownFlaggedTokens: [] }), { latestBlock: LATEST }),
    /lastScannedBlock is missing/
  );
});

test("a non-numeric lastScannedBlock is refused", () => {
  assert.throws(() => parseSentinelState({ lastScannedBlock: "not-a-number" }), /not an integer/);
  assert.throws(() => parseSentinelState({ lastScannedBlock: {} }), /not an integer/);
});

test("a negative lastScannedBlock is refused", () => {
  assert.throws(() => parseSentinelState({ lastScannedBlock: -5 }), /negative/);
});

test("a lastScannedBlock ahead of the chain tip is refused", () => {
  // This is the quiet one: the computed range is empty, so the sentinel reports "no new
  // blocks" on every future run and looks perfectly healthy while scanning nothing.
  assert.throws(
    () => parseSentinelState({ lastScannedBlock: LATEST + 1n }, { latestBlock: LATEST }),
    /ahead of the chain tip/
  );
});

test("the tip itself is acceptable", () => {
  const state = parseSentinelState({ lastScannedBlock: LATEST }, { latestBlock: LATEST });
  assert.equal(state.lastScannedBlock, LATEST.toString());
});

test("wrongly typed collections are refused", () => {
  assert.throws(() => parseSentinelState({ lastScannedBlock: 1, knownFlaggedTokens: {} }), /knownFlaggedTokens/);
  assert.throws(() => parseSentinelState({ lastScannedBlock: 1, alertedApprovals: "none" }), /alertedApprovals/);
});

test("the tip check is skipped when no latest block is supplied", () => {
  // Callers that have not yet queried the chain should still be able to validate shape.
  const state = parseSentinelState({ lastScannedBlock: 99_999_999_999n });
  assert.equal(state.lastScannedBlock, "99999999999");
});

test("a detector fingerprint is optional but must be a string when present", () => {
  const base = { lastScannedBlock: "100" };
  assert.equal(parseSentinelState({ ...base }).detectorFingerprint, undefined);
  assert.equal(parseSentinelState({ ...base, detectorFingerprint: "abc123" }).detectorFingerprint, "abc123");

  // A number would compare unequal to the real fingerprint forever, so every cycle would
  // re-baseline and the sentinel would never report a token again -- working, silently useless.
  assert.throws(() => parseSentinelState({ ...base, detectorFingerprint: 12345 }), /detectorFingerprint must be a string/);
});
