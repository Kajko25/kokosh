// Single-use enforcement for sign-in nonces.
//
// The HMAC nonce in nonce.mjs is stateless and self-validating, which fixed sign-in across
// instances — but "used exactly once" is inherently stateful: two instances cannot agree a
// nonce was spent without somewhere to write that down. This module is that somewhere.
//
// Backed by Vercel KV when configured, falling back to per-process memory otherwise. The KV
// path uses SET .. NX EXAT, so the claim is atomic on the server: exactly one caller can win,
// even if two requests race, and the key expires with the nonce so nothing accumulates.
//
// Deliberately no @vercel/kv dependency — the REST protocol is a single POST, and hand-rolling
// it keeps the agent's dependency list short and the whole thing injectable for tests.

const KEY_PREFIX = "kokosh:nonce:";

export class NonceStoreUnavailable extends Error {
  constructor(cause) {
    super(`nonce store unavailable: ${cause}`);
    this.name = "NonceStoreUnavailable";
  }
}

function createMemoryStore({ now = () => Date.now() } = {}) {
  const seen = new Map();

  return {
    kind: "memory",
    async claim(nonce, expiresAt) {
      const nowSeconds = Math.floor(now() / 1000);
      for (const [key, expiry] of seen) {
        if (expiry <= nowSeconds) seen.delete(key);
      }
      if (seen.has(nonce)) return false;
      seen.set(nonce, expiresAt);
      return true;
    },
  };
}

function createKvStore({ url, token, fetchImpl = fetch }) {
  return {
    kind: "kv",
    async claim(nonce, expiresAt) {
      let res;
      try {
        res = await fetchImpl(url, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          // SET <key> 1 NX EXAT <unix-seconds> — atomic claim plus self-expiry in one call.
          body: JSON.stringify(["SET", KEY_PREFIX + nonce, "1", "NX", "EXAT", String(expiresAt)]),
        });
      } catch (err) {
        throw new NonceStoreUnavailable(err?.message ?? err);
      }

      if (!res.ok) throw new NonceStoreUnavailable(`HTTP ${res.status}`);

      const body = await res.json().catch(() => ({}));
      // Upstash answers {"result":"OK"} when the key was created and {"result":null} when it
      // already existed — i.e. null means this nonce was already spent.
      return body.result === "OK";
    },
  };
}

export function createNonceStore({ env = process.env, fetchImpl = fetch, now = () => Date.now() } = {}) {
  const url = env.KV_REST_API_URL;
  const token = env.KV_REST_API_TOKEN;

  if (url && token) return createKvStore({ url, token, fetchImpl });
  return createMemoryStore({ now });
}

export { createMemoryStore, createKvStore };
