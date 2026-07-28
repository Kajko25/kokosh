// Fixed-window rate limiting for the unauthenticated sign-in endpoints.
//
// /auth/verify costs an RPC call and, once KV is configured, a write — per request, with no
// credential required to trigger either. /auth/nonce is cheap but is the other half of the
// same flow. Neither should be freely amplifiable by an anonymous caller.
//
// This is per-instance and in-memory. On a serverless runtime that means the effective limit
// is (limit x instances), which is a real weakening but still bounds any single caller's
// amplification; a shared counter would cost a KV round trip on every request, which is the
// very cost being defended against. The honest description is "a cap on obvious abuse", not
// "a guarantee".

export function createRateLimiter({ limit = 30, windowMs = 60_000, now = () => Date.now() } = {}) {
  const windows = new Map();

  function sweep(currentWindow) {
    for (const [key, entry] of windows) {
      if (entry.window < currentWindow) windows.delete(key);
    }
  }

  return {
    /**
     * Record a hit for `key`. Returns {allowed} and, when blocked, how long until the window
     * rolls over so the caller can be told rather than left guessing.
     */
    hit(key) {
      const currentWindow = Math.floor(now() / windowMs);
      sweep(currentWindow);

      const entry = windows.get(key);
      if (!entry || entry.window !== currentWindow) {
        windows.set(key, { window: currentWindow, count: 1 });
        return { allowed: true, remaining: limit - 1 };
      }

      entry.count += 1;
      if (entry.count > limit) {
        const resetAt = (currentWindow + 1) * windowMs;
        return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now()) / 1000)) };
      }
      return { allowed: true, remaining: limit - entry.count };
    },

    get size() {
      return windows.size;
    },
  };
}

/**
 * Best-effort client identity. Vercel terminates TLS upstream, so the socket address is the
 * proxy's; x-forwarded-for's first entry is the closest thing to the real caller. It is
 * spoofable, which is why this only ever gates cost, never authorisation.
 */
export function clientKey(req) {
  const forwarded = req.headers?.["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return req.ip ?? req.socket?.remoteAddress ?? "unknown";
}

export function rateLimitMiddleware(limiter) {
  return (req, res, next) => {
    const { allowed, retryAfterSeconds } = limiter.hit(clientKey(req));
    if (allowed) return next();

    res.set("Retry-After", String(retryAfterSeconds));
    res.status(429).json({ error: "rate_limited", retryAfterSeconds });
  };
}
