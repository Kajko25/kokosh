import { test } from "node:test";
import assert from "node:assert/strict";
import { createRateLimiter, clientKey } from "../lib/rateLimit.mjs";
import { makeApp } from "../lib/app.mjs";

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

// Node's fetch keeps connections alive, so server.close() alone waits forever for idle
// sockets and the test process never exits. Drop them explicitly.
function shutdown(server) {
  server.closeAllConnections?.();
  server.close();
}

test("requests within the limit are allowed", () => {
  const limiter = createRateLimiter({ limit: 3, now: () => 0 });
  assert.deepEqual([1, 2, 3].map(() => limiter.hit("a").allowed), [true, true, true]);
});

test("the request past the limit is blocked and told when to retry", () => {
  let clock = 0;
  const limiter = createRateLimiter({ limit: 2, windowMs: 60_000, now: () => clock });

  limiter.hit("a");
  limiter.hit("a");
  const blocked = limiter.hit("a");

  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 60);
});

test("the budget resets when the window rolls over", () => {
  let clock = 0;
  const limiter = createRateLimiter({ limit: 1, windowMs: 60_000, now: () => clock });

  assert.equal(limiter.hit("a").allowed, true);
  assert.equal(limiter.hit("a").allowed, false);

  clock = 60_000;
  assert.equal(limiter.hit("a").allowed, true, "a new window starts a fresh budget");
});

test("callers are counted separately", () => {
  const limiter = createRateLimiter({ limit: 1, now: () => 0 });
  assert.equal(limiter.hit("a").allowed, true);
  assert.equal(limiter.hit("b").allowed, true, "one caller must not exhaust another's budget");
  assert.equal(limiter.hit("a").allowed, false);
});

test("stale windows are swept so the map cannot grow without bound", () => {
  let clock = 0;
  const limiter = createRateLimiter({ limit: 5, windowMs: 1000, now: () => clock });

  for (let i = 0; i < 50; i++) limiter.hit(`caller-${i}`);
  assert.equal(limiter.size, 50);

  clock = 5000;
  limiter.hit("someone-new");
  assert.equal(limiter.size, 1, "entries from elapsed windows are dropped");
});

test("the forwarded client address is preferred over the socket", () => {
  // Vercel terminates TLS upstream, so the socket address is the proxy's.
  assert.equal(clientKey({ headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.1" } }), "1.2.3.4");
  assert.equal(clientKey({ headers: {}, ip: "5.6.7.8" }), "5.6.7.8");
  assert.equal(clientKey({ headers: {}, socket: { remoteAddress: "9.9.9.9" } }), "9.9.9.9");
  assert.equal(clientKey({ headers: {} }), "unknown");
});

test("/auth/nonce starts returning 429 once the budget is spent", async () => {
  const app = makeApp({ client: {}, authRateLimit: { limit: 2, windowMs: 60_000 } });
  const server = await listen(app);
  const { port } = server.address();

  const statuses = [];
  let retryAfter = null;
  let body = null;
  try {
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`http://localhost:${port}/auth/nonce`);
      statuses.push(res.status);
      if (res.status === 429) {
        retryAfter = Number(res.headers.get("retry-after"));
        body = await res.json();
      }
    }
  } finally {
    // In a finally block so a failed assertion cannot leave the server open — that turns a
    // clear test failure into a hung run with no output.
    shutdown(server);
  }

  assert.deepEqual(statuses, [200, 200, 429]);
  assert.equal(body.error, "rate_limited");
  // The app runs on the real clock, so the remaining window depends on when the test runs;
  // pinning an exact value here would be testing the wall clock, not the limiter.
  assert.ok(retryAfter >= 1 && retryAfter <= 60, `retry-after out of range: ${retryAfter}`);
});

test("nonce and verify draw on the same budget", async () => {
  // They are two halves of one flow; separate budgets would just double the extractable cost.
  const app = makeApp({ client: {}, authRateLimit: { limit: 1, windowMs: 60_000 } });
  const server = await listen(app);
  const { port } = server.address();

  let first, second;
  try {
    first = await fetch(`http://localhost:${port}/auth/nonce`);
    second = await fetch(`http://localhost:${port}/auth/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
  } finally {
    shutdown(server);
  }

  assert.equal(first.status, 200);
  assert.equal(second.status, 429);
});

test("other endpoints are not rate limited", async () => {
  const app = makeApp({ client: {}, authRateLimit: { limit: 1, windowMs: 60_000 } });
  const server = await listen(app);
  const { port } = server.address();

  let card;
  try {
    await fetch(`http://localhost:${port}/auth/nonce`);
    card = await fetch(`http://localhost:${port}/.well-known/agent-card.json`);
  } finally {
    shutdown(server);
  }

  assert.equal(card.status, 200);
});
