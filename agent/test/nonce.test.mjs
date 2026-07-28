import { test } from "node:test";
import assert from "node:assert/strict";
import { createNonce, checkNonce, NONCE_LENGTH, DEFAULT_TTL_SECONDS } from "../lib/nonce.mjs";

const SECRET = "test-secret";
const OTHER_SECRET = "a-different-secret";

test("a freshly issued nonce validates", () => {
  const nonce = createNonce({ secret: SECRET });
  assert.deepEqual(checkNonce(nonce, { secret: SECRET }).ok, true);
});

test("nonces are alphanumeric and fixed length, as SIWE requires", () => {
  const nonce = createNonce({ secret: SECRET });
  assert.equal(nonce.length, NONCE_LENGTH);
  assert.match(nonce, /^[0-9a-f]+$/);
});

test("an instance with the same secret accepts a nonce it never issued", () => {
  // This is the whole point of the change: issue and verify can be different processes.
  const issuedElsewhere = createNonce({ secret: SECRET });
  assert.equal(checkNonce(issuedElsewhere, { secret: SECRET }).ok, true);
});

test("a nonce is rejected under a different secret", () => {
  const nonce = createNonce({ secret: SECRET });
  assert.deepEqual(checkNonce(nonce, { secret: OTHER_SECRET }), {
    ok: false,
    error: "invalid_nonce_signature",
  });
});

test("a tampered payload fails the signature check", () => {
  const nonce = createNonce({ secret: SECRET });
  const flipped = (nonce[0] === "a" ? "b" : "a") + nonce.slice(1);
  assert.equal(checkNonce(flipped, { secret: SECRET }).error, "invalid_nonce_signature");
});

test("extending the expiry without re-signing is rejected", () => {
  // The attack the MAC exists to stop: keep the random half and the MAC, push the expiry out.
  const now = 1_800_000_000_000;
  const nonce = createNonce({ secret: SECRET, ttlSeconds: 60, now: () => now });
  const farFuture = (Math.floor(now / 1000) + 999_999).toString(16).padStart(8, "0");
  const forged = nonce.slice(0, 16) + farFuture + nonce.slice(24);

  assert.equal(checkNonce(forged, { secret: SECRET }).error, "invalid_nonce_signature");
});

test("an expired nonce is rejected", () => {
  const issuedAt = 1_800_000_000_000;
  const nonce = createNonce({ secret: SECRET, ttlSeconds: 300, now: () => issuedAt });

  const justBefore = issuedAt + 299_000;
  const justAfter = issuedAt + 301_000;

  assert.equal(checkNonce(nonce, { secret: SECRET, now: () => justBefore }).ok, true);
  assert.equal(checkNonce(nonce, { secret: SECRET, now: () => justAfter }).error, "expired_nonce");
});

test("expiry is exclusive at the boundary", () => {
  const issuedAt = 1_800_000_000_000;
  const nonce = createNonce({ secret: SECRET, ttlSeconds: 60, now: () => issuedAt });
  const exactly = issuedAt + 60_000;
  assert.equal(checkNonce(nonce, { secret: SECRET, now: () => exactly }).error, "expired_nonce");
});

test("malformed input is rejected without throwing", () => {
  // Attacker-supplied, so every shape has to be survivable.
  for (const bad of ["", "not-hex-at-all", "abc", "z".repeat(NONCE_LENGTH), null, undefined, 42, {}]) {
    assert.equal(checkNonce(bad, { secret: SECRET }).error, "malformed_nonce");
  }
});

test("a nonce of the right length but wrong alphabet is rejected as malformed", () => {
  assert.equal(checkNonce("A".repeat(NONCE_LENGTH), { secret: SECRET }).error, "malformed_nonce");
});

test("two nonces issued in the same second still differ", () => {
  const now = () => 1_800_000_000_000;
  const a = createNonce({ secret: SECRET, now });
  const b = createNonce({ secret: SECRET, now });
  assert.notEqual(a, b, "the random half must vary independently of the clock");
});

test("issuing requires a secret rather than silently signing with nothing", () => {
  assert.throws(() => createNonce({}), /requires a secret/);
  assert.throws(() => checkNonce("x", {}), /requires a secret/);
});

test("the default TTL is short enough to bound cross-instance replay", () => {
  assert.ok(DEFAULT_TTL_SECONDS <= 600, "a long-lived stateless nonce widens the replay window");
});
