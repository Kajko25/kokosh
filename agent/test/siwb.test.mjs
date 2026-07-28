import { test } from "node:test";
import assert from "node:assert/strict";

// siwb.mjs reads its secret once at module load, so the env has to be set before the
// dynamic import below. A fixed secret also proves the module honours SIWB_NONCE_SECRET
// rather than falling back to the per-process one.
process.env.SIWB_NONCE_SECRET = "test-secret-for-siwb";
const { issueNonce, verifySignIn } = await import("../lib/siwb.mjs");

const ADDRESS = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const accept = async () => true;
const reject = async () => false;

function messageWith(nonce) {
  return `kokosh-agent.vercel.app wants you to sign in.\n\nNonce: ${nonce}`;
}

test("a nonce issued by this module verifies", async () => {
  const message = messageWith(issueNonce());
  const result = await verifySignIn({ address: ADDRESS, message, signature: "0x" }, { verifyMessage: accept });
  assert.deepEqual(result, { ok: true, address: ADDRESS });
});

test("replaying a consumed nonce is refused", async () => {
  const message = messageWith(issueNonce());
  const first = await verifySignIn({ address: ADDRESS, message, signature: "0x" }, { verifyMessage: accept });
  const second = await verifySignIn({ address: ADDRESS, message, signature: "0x" }, { verifyMessage: accept });

  assert.equal(first.ok, true);
  assert.deepEqual(second, { ok: false, error: "nonce_already_used" });
});

test("a bad signature does not burn the nonce", async () => {
  // Otherwise anyone could invalidate someone else's in-flight sign-in by submitting
  // garbage against their nonce.
  const message = messageWith(issueNonce());

  const failed = await verifySignIn({ address: ADDRESS, message, signature: "0x" }, { verifyMessage: reject });
  assert.deepEqual(failed, { ok: false, error: "invalid_signature" });

  const retried = await verifySignIn({ address: ADDRESS, message, signature: "0x" }, { verifyMessage: accept });
  assert.equal(retried.ok, true, "the nonce should still be usable after a failed attempt");
});

test("a message with no nonce is rejected", async () => {
  const result = await verifySignIn(
    { address: ADDRESS, message: "no nonce here", signature: "0x" },
    { verifyMessage: accept }
  );
  assert.deepEqual(result, { ok: false, error: "missing_nonce" });
});

test("a nonce this deployment never signed is rejected", async () => {
  // The pre-fix behaviour accepted only nonces held in local memory; the fix must not
  // over-correct into accepting anything shaped like a nonce.
  const forged = "f".repeat(56);
  const result = await verifySignIn(
    { address: ADDRESS, message: messageWith(forged), signature: "0x" },
    { verifyMessage: accept }
  );
  assert.equal(result.ok, false);
  assert.equal(result.error, "invalid_nonce_signature");
});

test("signature verification is not attempted for an invalid nonce", async () => {
  let called = false;
  const spy = async () => {
    called = true;
    return true;
  };

  await verifySignIn(
    { address: ADDRESS, message: messageWith("0".repeat(56)), signature: "0x" },
    { verifyMessage: spy }
  );

  assert.equal(called, false, "an unverifiable nonce should short-circuit before the RPC call");
});

test("issued nonces are unique across calls", async () => {
  const seen = new Set(Array.from({ length: 50 }, () => issueNonce()));
  assert.equal(seen.size, 50);
});
