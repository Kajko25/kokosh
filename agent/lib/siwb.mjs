import { createPublicClient, http } from "viem";
import { base } from "viem/chains";

const client = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });
const usedNonces = new Set();

export function issueNonce() {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  usedNonces.add(nonce);
  return nonce;
}

export async function verifySignIn({ address, message, signature }) {
  const nonceMatch = message.match(/Nonce: (\w+)/);
  if (!nonceMatch || !usedNonces.has(nonceMatch[1])) {
    return { ok: false, error: "invalid_or_reused_nonce" };
  }
  usedNonces.delete(nonceMatch[1]);

  // viem's verifyMessage handles ERC-6492 automatically for undeployed smart wallets.
  const valid = await client.verifyMessage({ address, message, signature });
  if (!valid) return { ok: false, error: "invalid_signature" };

  return { ok: true, address };
}
