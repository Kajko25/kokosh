import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { randomBytes } from "node:crypto";
import { createNonce, checkNonce, DEFAULT_TTL_SECONDS } from "./nonce.mjs";

const client = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });

// A shared secret lets any instance validate a nonce another instance issued — the whole
// point of moving off the in-process Set. Without one we fall back to a per-process secret,
// which reproduces the old instance-affinity bug, so it warns rather than failing silently.
const SECRET = process.env.SIWB_NONCE_SECRET || ephemeralSecret();
const TTL_SECONDS = Number(process.env.SIWB_NONCE_TTL ?? DEFAULT_TTL_SECONDS);

function ephemeralSecret() {
  console.warn(
    "SIWB_NONCE_SECRET is not set — using a per-process secret. Sign-in will fail whenever " +
      "verification lands on a different instance than the one that issued the nonce. Set it " +
      "to a shared random value in any multi-instance deployment."
  );
  return randomBytes(32).toString("hex");
}

// Best-effort replay protection within one instance. The nonce's own expiry is what bounds
// replay across instances; this catches the common single-instance case outright. Entries are
// pruned by expiry, so unlike the old Set this cannot grow without bound.
const consumed = new Map();

function prune(nowSeconds) {
  for (const [nonce, expiresAt] of consumed) {
    if (expiresAt <= nowSeconds) consumed.delete(nonce);
  }
}

export function issueNonce() {
  return createNonce({ secret: SECRET, ttlSeconds: TTL_SECONDS });
}

export async function verifySignIn({ address, message, signature }, { verifyMessage } = {}) {
  const nonceMatch = message?.match?.(/Nonce: ([0-9a-zA-Z]+)/);
  if (!nonceMatch) return { ok: false, error: "missing_nonce" };

  const nonce = nonceMatch[1];
  const nowSeconds = Math.floor(Date.now() / 1000);
  prune(nowSeconds);

  if (consumed.has(nonce)) return { ok: false, error: "nonce_already_used" };

  const check = checkNonce(nonce, { secret: SECRET });
  if (!check.ok) return { ok: false, error: check.error };

  // viem's verifyMessage handles ERC-6492 automatically for undeployed smart wallets.
  const verify = verifyMessage ?? ((args) => client.verifyMessage(args));
  const valid = await verify({ address, message, signature });
  if (!valid) return { ok: false, error: "invalid_signature" };

  // Consumed only after the signature checks out, so a failed attempt cannot be used to burn
  // someone else's in-flight nonce.
  consumed.set(nonce, check.expiresAt);

  return { ok: true, address };
}
