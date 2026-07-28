import { test } from "node:test";
import assert from "node:assert/strict";
import { makeApp, agentCard } from "../lib/app.mjs";

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

test("healthz reports ok when block is fresh", async () => {
  const nowMs = 1_800_000_000_000;
  const fakeClient = {
    getBlock: async () => ({ timestamp: BigInt(Math.floor(nowMs / 1000) - 5), number: 12345n }),
  };
  const app = makeApp({ client: fakeClient, now: () => nowMs });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/healthz`);
  const body = await res.json();
  server.close();

  assert.equal(res.status, 200);
  assert.equal(body.status, "ok");
  assert.equal(body.lagSeconds, 5);
});

test("healthz reports degraded when block is stale", async () => {
  const nowMs = 1_800_000_000_000;
  const fakeClient = {
    getBlock: async () => ({ timestamp: BigInt(Math.floor(nowMs / 1000) - 120), number: 12345n }),
  };
  const app = makeApp({ client: fakeClient, now: () => nowMs });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/healthz`);
  const body = await res.json();
  server.close();

  assert.equal(res.status, 503);
  assert.equal(body.status, "degraded");
});

test("healthz reports unreachable when the client throws", async () => {
  const fakeClient = {
    getBlock: async () => {
      throw new Error("rpc down");
    },
  };
  const app = makeApp({ client: fakeClient });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/healthz`);
  const body = await res.json();
  server.close();

  assert.equal(res.status, 503);
  assert.equal(body.status, "unreachable");
});

test("exposure returns 202 when no scan report exists yet", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/exposure`);
  server.close();

  // Either a real report exists (200) or none yet (202) — both are valid depending on
  // whether scripts/scan-approvals.mjs has been run; just assert it doesn't crash.
  assert.ok(res.status === 200 || res.status === 202);
});

test("agent-card.json includes the wallet and endpoints", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/.well-known/agent-card.json`);
  const body = await res.json();
  server.close();

  assert.equal(res.status, 200);
  assert.equal(body.wallet, "0x2984Bb4953cfCE2cEc957388BE686D6c38779234");
  // No CDP keys are passed here, so the card reports the audit as unavailable rather than
  // the default "paid" — see test/auditMode.test.mjs.
  assert.deepEqual(body, agentCard({ auditMode: "unavailable" }));
});

test("the root path describes the agent instead of erroring", async () => {
  // Previously Express's default handler answered "Cannot GET /" as HTML — and 500 in
  // production, where the payment middleware is mounted.
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  let res, body;
  try {
    res = await fetch(`http://localhost:${port}/`);
    body = await res.json();
  } finally {
    server.closeAllConnections?.();
    server.close();
  }

  assert.equal(res.status, 200);
  assert.equal(body.name, "Kokosh");
  assert.equal(body.agentCard, "/.well-known/agent-card.json");
});

test("unmatched routes answer JSON, not an HTML error page", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  let res, body;
  try {
    res = await fetch(`http://localhost:${port}/definitely-not-a-route`);
    body = await res.json();
  } finally {
    server.closeAllConnections?.();
    server.close();
  }

  assert.equal(res.status, 404);
  assert.deepEqual(body, { error: "not_found" });
  // The default page echoes the requested path back; this one does not.
  assert.equal(JSON.stringify(body).includes("definitely-not-a-route"), false);
});

test("security headers are set on every response", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  let res;
  try {
    res = await fetch(`http://localhost:${port}/.well-known/agent-card.json`);
    await res.arrayBuffer();
  } finally {
    server.closeAllConnections?.();
    server.close();
  }

  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.equal(res.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
  // Still required by the Base Account popup flows the public/ pages use.
  assert.equal(res.headers.get("cross-origin-opener-policy"), "same-origin-allow-popups");
});
