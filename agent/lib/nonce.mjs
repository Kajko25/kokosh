// Stateless sign-in nonces.
//
// The previous implementation kept issued nonces in an in-process Set. On a serverless
// runtime the verify request routinely lands on a different instance than the one that
// issued the nonce, so a perfectly valid sign-in was rejected as unknown — sign-in worked
// or failed essentially at random, depending on instance routing. The Set also grew without
// bound, since only consumed nonces were ever removed.
//
// A nonce here carries its own expiry and an HMAC over both halves, so any instance holding
// the shared secret can validate it without shared storage. Everything is hex, which keeps
// the value alphanumeric as SIWE requires.
//
//   <random: 16 hex><expiry seconds: 8 hex><hmac: 32 hex>
//
// What this does NOT give you is guaranteed single use: without shared state, two instances
// cannot agree that a nonce was already spent. Replay is bounded by the TTL and, on a single
// instance, blocked outright by the consumed-set in siwb.mjs. Closing the gap completely
// needs a shared store (KV/Redis); this is the honest limit of the stateless approach.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const RANDOM_HEX = 16;
const EXPIRY_HEX = 8;
const MAC_HEX = 32;
export const NONCE_LENGTH = RANDOM_HEX + EXPIRY_HEX + MAC_HEX;

export const DEFAULT_TTL_SECONDS = 300;

function mac(payload, secret) {
  return createHmac("sha256", secret).update(payload).digest("hex").slice(0, MAC_HEX);
}

export function createNonce({
  secret,
  ttlSeconds = DEFAULT_TTL_SECONDS,
  now = () => Date.now(),
  random = () => randomBytes(RANDOM_HEX / 2).toString("hex"),
} = {}) {
  if (!secret) throw new Error("createNonce requires a secret");

  const expiry = Math.floor(now() / 1000) + ttlSeconds;
  const payload = random() + expiry.toString(16).padStart(EXPIRY_HEX, "0");
  return payload + mac(payload, secret);
}

/**
 * Validate a nonce's shape, signature and expiry. Returns {ok:true, expiresAt} or
 * {ok:false, error} — never throws on malformed input, since the value is attacker-supplied.
 */
export function checkNonce(nonce, { secret, now = () => Date.now() } = {}) {
  if (!secret) throw new Error("checkNonce requires a secret");

  if (typeof nonce !== "string" || nonce.length !== NONCE_LENGTH || !/^[0-9a-f]+$/.test(nonce)) {
    return { ok: false, error: "malformed_nonce" };
  }

  const payload = nonce.slice(0, RANDOM_HEX + EXPIRY_HEX);
  const provided = nonce.slice(RANDOM_HEX + EXPIRY_HEX);
  const expected = mac(payload, secret);

  // Both are fixed-length hex of equal size here, so timingSafeEqual is safe to call.
  if (!timingSafeEqual(Buffer.from(provided, "hex"), Buffer.from(expected, "hex"))) {
    return { ok: false, error: "invalid_nonce_signature" };
  }

  const expiry = parseInt(payload.slice(RANDOM_HEX), 16);
  if (Math.floor(now() / 1000) >= expiry) {
    return { ok: false, error: "expired_nonce" };
  }

  return { ok: true, expiresAt: expiry };
}
