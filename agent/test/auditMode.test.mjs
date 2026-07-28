import { test } from "node:test";
import assert from "node:assert/strict";
import { makeApp, agentCard, resolveAuditMode } from "../app.mjs";
import { warnOnAuditMode } from "../lib/auditMode.mjs";

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

const BOTH_KEYS = { apiKeyId: "id", apiKeySecret: "secret" };

test("both CDP keys mean the audit is paid", () => {
  assert.equal(resolveAuditMode({ cdp: BOTH_KEYS }), "paid");
});

test("a half-configured CDP credential does not count as paid", () => {
  // A typo'd or half-deployed env is the realistic failure, and it must not be treated
  // as "payments are on".
  assert.equal(resolveAuditMode({ cdp: { apiKeyId: "id" } }), "unavailable");
  assert.equal(resolveAuditMode({ cdp: { apiKeySecret: "secret" } }), "unavailable");
});

test("missing keys default to unavailable, not free", () => {
  assert.equal(resolveAuditMode({}), "unavailable");
  assert.equal(resolveAuditMode({ cdp: {} }), "unavailable");
});

test("serving the audit free requires an explicit opt-in", () => {
  assert.equal(resolveAuditMode({ allowUnpaidAudit: true }), "unpaid");
});

test("the opt-in cannot override real credentials", () => {
  assert.equal(resolveAuditMode({ cdp: BOTH_KEYS, allowUnpaidAudit: true }), "paid");
});

test("/audit returns 503 instead of the free report when payments are unconfigured", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/audit`);
  const body = await res.json();
  server.close();

  assert.equal(res.status, 503);
  assert.equal(body.error, "payment_not_configured");
  // The report itself must not leak through the guard.
  assert.equal(body.hygieneScore, undefined);
  assert.equal(body.exposure, undefined);
});

test("the guard covers subpaths of /audit too", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/audit/anything`);
  server.close();

  assert.equal(res.status, 503);
});

test("other endpoints stay reachable while the audit is disabled", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/.well-known/agent-card.json`);
  server.close();

  assert.equal(res.status, 200);
});

test("the agent card advertises the audit's actual mode", () => {
  assert.match(agentCard({ auditMode: "paid" }).endpoints.audit, /paid via x402/);
  assert.match(agentCard({ auditMode: "unpaid" }).endpoints.audit, /free/);
  assert.match(agentCard({ auditMode: "unavailable" }).endpoints.audit, /unavailable/);
  // Defaulting keeps the card valid for callers that don't pass a mode.
  assert.deepEqual(agentCard(), agentCard({ auditMode: "paid" }));
});

test("the served card matches the app's real mode, not the optimistic default", async () => {
  const app = makeApp({ client: {} });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/.well-known/agent-card.json`);
  const body = await res.json();
  server.close();

  assert.deepEqual(body, agentCard({ auditMode: "unavailable" }));
  assert.notDeepEqual(body, agentCard({ auditMode: "paid" }));
});

test("startup warns on unavailable and free modes, and only logs on paid", () => {
  const calls = [];
  const log = { log: (m) => calls.push(["log", m]), warn: (m) => calls.push(["warn", m]) };

  warnOnAuditMode("paid", log);
  warnOnAuditMode("unpaid", log);
  warnOnAuditMode("unavailable", log);

  assert.deepEqual(calls.map(([level]) => level), ["log", "warn", "warn"]);
  assert.match(calls[2][1], /CDP_API_KEY_ID/);
});

test("healthz reports the modes actually in force", async () => {
  const nowMs = 1_800_000_000_000;
  const fakeClient = {
    getBlock: async () => ({ timestamp: BigInt(Math.floor(nowMs / 1000) - 1), number: 1n }),
  };
  const app = makeApp({ client: fakeClient, now: () => nowMs });
  const server = await listen(app);
  const { port } = server.address();

  const res = await fetch(`http://localhost:${port}/healthz`);
  const body = await res.json();
  server.close();

  // No CDP keys and no KV in the test environment, so both degraded modes should be visible
  // rather than only mentioned in a startup log.
  assert.equal(body.config.audit, "unavailable");
  assert.equal(body.config.nonceStore, "memory");
});

// The "paid" path is intentionally not exercised through makeApp: mounting the real x402
// middleware makes it initialise against the CDP facilitator, which rejects placeholder
// credentials. resolveAuditMode covers that branch directly instead.
