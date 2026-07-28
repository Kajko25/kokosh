import { test } from "node:test";
import assert from "node:assert/strict";
import { validateSignInRequest, MAX_MESSAGE_BYTES, MAX_SIGNATURE_BYTES } from "../lib/signInRequest.mjs";

const VALID = {
  address: "0x2984Bb4953cfCE2cEc957388BE686D6c38779234",
  message: "kokosh wants you to sign in.\n\nNonce: abc123",
  signature: "0xdeadbeef",
};

test("a well-formed request passes through unchanged", () => {
  const result = validateSignInRequest(VALID);
  assert.equal(result.ok, true);
  assert.deepEqual(result.value, VALID);
});

test("missing fields are reported before anything else", () => {
  assert.equal(validateSignInRequest({}).error, "missing_fields");
  assert.equal(validateSignInRequest(undefined).error, "missing_fields");
  assert.equal(validateSignInRequest({ ...VALID, address: undefined }).error, "missing_fields");
  assert.equal(validateSignInRequest({ ...VALID, signature: "" }).error, "missing_fields");
});

test("non-string fields are rejected rather than coerced", () => {
  // JSON bodies are attacker-shaped: an object here would otherwise reach String matching
  // and viem.
  assert.equal(validateSignInRequest({ ...VALID, address: { evil: true } }).error, "invalid_field_types");
  assert.equal(validateSignInRequest({ ...VALID, message: 42 }).error, "invalid_field_types");
  assert.equal(validateSignInRequest({ ...VALID, signature: ["0x"] }).error, "invalid_field_types");
});

test("only a real 20-byte hex address is accepted", () => {
  assert.equal(validateSignInRequest({ ...VALID, address: "not-an-address" }).error, "invalid_address");
  assert.equal(validateSignInRequest({ ...VALID, address: "0x1234" }).error, "invalid_address");
  assert.equal(validateSignInRequest({ ...VALID, address: VALID.address + "00" }).error, "invalid_address");
  assert.equal(validateSignInRequest({ ...VALID, address: VALID.address.replace("0x", "") }).error, "invalid_address");
});

test("mixed-case (checksummed) addresses are accepted", () => {
  assert.equal(validateSignInRequest(VALID).ok, true);
  assert.equal(validateSignInRequest({ ...VALID, address: VALID.address.toLowerCase() }).ok, true);
});

test("an oversized message is rejected instead of being scanned", () => {
  const big = { ...VALID, message: "x".repeat(MAX_MESSAGE_BYTES + 1) };
  assert.equal(validateSignInRequest(big).error, "message_too_large");

  const atLimit = { ...VALID, message: "x".repeat(MAX_MESSAGE_BYTES) };
  assert.equal(validateSignInRequest(atLimit).ok, true);
});

test("message size is measured in bytes, not characters", () => {
  // Multi-byte characters must not be a way to smuggle a larger payload past the cap.
  const multibyte = { ...VALID, message: "€".repeat(MAX_MESSAGE_BYTES) };
  assert.equal(validateSignInRequest(multibyte).error, "message_too_large");
});

test("a non-hex or oversized signature is rejected", () => {
  assert.equal(validateSignInRequest({ ...VALID, signature: "zzzz" }).error, "invalid_signature_encoding");
  assert.equal(validateSignInRequest({ ...VALID, signature: "deadbeef" }).error, "invalid_signature_encoding");

  const huge = { ...VALID, signature: "0x" + "a".repeat(MAX_SIGNATURE_BYTES) };
  assert.equal(validateSignInRequest(huge).error, "invalid_signature_encoding");
});

test("the signature cap leaves room for ERC-6492 wrapped signatures", () => {
  // Undeployed smart accounts send a wrapped signature carrying factory calldata; it is by
  // far the largest legitimate payload this endpoint sees.
  assert.ok(MAX_SIGNATURE_BYTES >= 4096);
  const wrapped = { ...VALID, signature: "0x" + "a".repeat(4000) };
  assert.equal(validateSignInRequest(wrapped).ok, true);
});
