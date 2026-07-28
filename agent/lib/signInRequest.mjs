// Shape validation for POST /auth/verify.
//
// The handler previously checked only that the three fields were truthy and handed them
// straight to viem, which meant any string reached an RPC call: a non-address, a multi-kilobyte
// "message" that the nonce regex then had to scan, or a signature of arbitrary size. None of
// that is exploitable on its own, but rejecting it here is cheap and keeps unbounded
// attacker-controlled input away from both the regex and the network.

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;

// A SIWE-style message is a few hundred bytes; ERC-6492 wrapped signatures for undeployed
// smart accounts are the largest legitimate payload here and stay well under 8 KB.
export const MAX_MESSAGE_BYTES = 4096;
export const MAX_SIGNATURE_BYTES = 8192;

export function validateSignInRequest(body) {
  const { address, message, signature } = body ?? {};

  if (!address || !message || !signature) {
    return { ok: false, error: "missing_fields" };
  }
  if (typeof address !== "string" || typeof message !== "string" || typeof signature !== "string") {
    return { ok: false, error: "invalid_field_types" };
  }
  if (!ADDRESS_RE.test(address)) {
    return { ok: false, error: "invalid_address" };
  }
  if (Buffer.byteLength(message, "utf8") > MAX_MESSAGE_BYTES) {
    return { ok: false, error: "message_too_large" };
  }
  if (!HEX_RE.test(signature) || Buffer.byteLength(signature, "utf8") > MAX_SIGNATURE_BYTES) {
    return { ok: false, error: "invalid_signature_encoding" };
  }

  return { ok: true, value: { address, message, signature } };
}
