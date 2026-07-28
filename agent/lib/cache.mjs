// A tiny single-flight TTL cache for upstream reads.
//
// Following pagination made a holdings fetch three Blockscout requests instead of one, and
// both /drops and /audit trigger it per request. The HTTP Cache-Control headers only help
// callers that honour them; this bounds what the agent itself asks of upstream.
//
// Single-flight matters as much as the TTL: without it, N concurrent requests arriving on a
// cold cache each start their own three-request walk. Sharing the in-flight promise means
// they all wait on one.

export function createTtlCache({ ttlMs = 60_000, now = () => Date.now() } = {}) {
  let entry = null; // { value, expiresAt }
  let inFlight = null;

  return {
    /** Return the cached value, or produce one with `produce()` and cache it. */
    async get(produce) {
      if (entry && entry.expiresAt > now()) return entry.value;
      if (inFlight) return inFlight;

      inFlight = (async () => {
        try {
          const value = await produce();
          entry = { value, expiresAt: now() + ttlMs };
          return value;
        } finally {
          // Cleared even on failure, so an upstream error is retried on the next request
          // rather than poisoning the cache with a rejected promise.
          inFlight = null;
        }
      })();

      return inFlight;
    },

    invalidate() {
      entry = null;
    },

    get isFresh() {
      return Boolean(entry && entry.expiresAt > now());
    },
  };
}
