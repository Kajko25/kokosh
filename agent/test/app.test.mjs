import { test } from "node:test";
import assert from "node:assert/strict";
import { makeApp, agentCard } from "../app.mjs";

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

// The holdings seam. Before it existed, /drops and /audit — the endpoints carrying this
// agent's actual product, one of them paid — could only be exercised against live Blockscout,
// so neither had a single test.
const TOKENS = [
  { address: "0xaaa", name: "Mirmil", symbol: "MIR", balance: "1", standard: "ERC-20" },
  { address: "0xbbb", name: "Claim: https://aerodrome.supply", symbol: "AERO", balance: "1", standard: "ERC-20" },
];
const NFTS = [
  { address: "0xccc", name: "Waymarks", symbol: "WAYMARK", standard: "ERC-721", instanceCount: 3 },
  { address: "0xddd", name: "HYPERLIQUID REWARD", symbol: "HL", standard: "ERC-1155", instanceCount: 1 },
  { address: "0xeee", name: "[ #181 ] Scan the QR to get a reward", symbol: "QR", standard: "ERC-1155", instanceCount: 1 },
];
const stubHoldings = (tokens = TOKENS, nfts = NFTS) => ({ tokens: async () => tokens, nfts: async () => nfts });

async function get(app, path) {
  const server = await listen(app);
  try {
    const res = await fetch(`http://localhost:${server.address().port}${path}`);
    return { status: res.status, body: await res.json() };
  } finally {
    server.close();
    server.closeAllConnections?.();
  }
}

test("drops counts every standard and labels each finding with its own", async () => {
  const { status, body } = await get(makeApp({ holdings: stubHoldings() }), "/drops");

  assert.equal(status, 200);
  assert.equal(body.scannedTokens, 5);
  assert.deepEqual(body.scannedByStandard, { "ERC-20": 2, "ERC-721": 1, "ERC-1155": 2 });
  assert.equal(body.flaggedCount, 3);
  assert.deepEqual(
    body.flagged.map((f) => [f.standard, f.symbol]),
    [["ERC-20", "AERO"], ["ERC-1155", "HL"], ["ERC-1155", "QR"]]
  );
});

test("drops reports every reason a finding was flagged for, not just the first", async () => {
  const { body } = await get(makeApp({ holdings: stubHoldings() }), "/drops");
  const qr = body.flagged.find((f) => f.symbol === "QR");
  assert.deepEqual(qr.reasons.sort(), ["qr_code_lure", "reward_language"]);
});

test("a clean wallet reports zero findings rather than an empty scan", async () => {
  const { body } = await get(makeApp({ holdings: stubHoldings([TOKENS[0]], [NFTS[0]]) }), "/drops");
  assert.equal(body.scannedTokens, 2);
  assert.equal(body.flaggedCount, 0);
  assert.deepEqual(body.flagged, []);
});

test("drops fails loudly when the NFT walk is down, rather than serving the ERC-20 half", async () => {
  // A partial scan presented as complete reads as an all-clear. This is the failure mode that
  // hid a third of this wallet's tokens once already.
  const holdings = { tokens: async () => TOKENS, nfts: async () => { throw new Error("blockscout 503"); } };
  const { status, body } = await get(makeApp({ holdings }), "/drops");

  assert.equal(status, 502);
  assert.equal(body.error, "holdings_unavailable");
  assert.equal("flaggedCount" in body, false, "no partial result may leak into a failure response");
});

test("the paid audit carries the scam section with per-standard counts", async () => {
  const app = makeApp({ holdings: stubHoldings(), allowUnpaidAudit: true });
  const { status, body } = await get(app, "/audit");

  assert.equal(status, 200);
  assert.equal(body.wallet, "0x2984Bb4953cfCE2cEc957388BE686D6c38779234");
  assert.equal(body.scamAirdrops.scannedTokens, 5);
  assert.deepEqual(body.scamAirdrops.scannedByStandard, { "ERC-20": 2, "ERC-721": 1, "ERC-1155": 2 });
  assert.equal(body.scamAirdrops.flaggedCount, 3);
  assert.equal(typeof body.hygieneScore, "number");
});

test("an audit whose holdings scan fails is a 502, not a report with an empty scam section", async () => {
  // The 202-shaped failure this agent shipped once: a legitimate-looking response that reports
  // nothing found because nothing was looked at. A paid endpoint must not do that.
  const holdings = { tokens: async () => { throw new Error("blockscout 500"); }, nfts: async () => [] };
  const { status, body } = await get(makeApp({ holdings, allowUnpaidAudit: true }), "/audit");

  assert.equal(status, 502);
  assert.equal(body.error, "audit_unavailable");
  assert.equal("hygieneScore" in body, false);
});

test("sentinel reports the cycle's age and whether it is overdue", async () => {
  const { status, body } = await get(makeApp({ holdings: stubHoldings() }), "/sentinel");

  assert.equal(status, 200);
  assert.equal(body.wallet, "0x2984Bb4953cfCE2cEc957388BE686D6c38779234");
  assert.equal(typeof body.overdue, "boolean");
  assert.ok("ageSeconds" in body);
  assert.ok(body.detector.running, "the running detector fingerprint is always reported");
  assert.ok(Array.isArray(body.alertedApprovals));
});

test("the agent card advertises the sentinel endpoint", () => {
  assert.equal(agentCard().endpoints.sentinel, "/sentinel");
});

test("a report-only CSP is sent, so it cannot break a working sign-in flow", async () => {
  const server = await listen(makeApp({ holdings: stubHoldings() }));
  const res = await fetch(`http://localhost:${server.address().port}/healthz`).catch(() => null);
  const policy = res?.headers.get("content-security-policy-report-only");
  server.close();
  server.closeAllConnections?.();

  assert.ok(policy, "the header is present");
  assert.equal(res.headers.get("content-security-policy"), null, "enforcing mode is deliberately not set yet");
  assert.match(policy, /script-src [^;]*https:\/\/esm\.sh/, "the pages import the SDK from esm.sh");
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /report-uri \/csp-report/);
});

test("csp violation reports are logged and answered 204", async () => {
  const logged = [];
  const app = makeApp({ holdings: stubHoldings(), cspLog: (m) => logged.push(m) });
  const server = await listen(app);
  const res = await fetch(`http://localhost:${server.address().port}/csp-report`, {
    method: "POST",
    headers: { "content-type": "application/csp-report" },
    body: JSON.stringify({
      "csp-report": { "document-uri": "https://kokosh-agent.vercel.app/signin.html", "violated-directive": "connect-src", "blocked-uri": "https://keys.coinbase.com" },
    }),
  });
  server.close();
  server.closeAllConnections?.();

  assert.equal(res.status, 204);
  assert.equal(logged.length, 1);
  assert.match(logged[0], /connect-src blocked https:\/\/keys\.coinbase\.com/);
});

test("exposure reports the block the snapshot reached, not just its age", async () => {
  // Age alone cannot tell a fresh incremental refresh from a fresh deploy of a stale file --
  // /exposure serves a committed snapshot, not a live read.
  const { status, body } = await get(makeApp({ holdings: stubHoldings() }), "/exposure");

  assert.equal(status, 200);
  assert.ok(body.scannedToBlock, "the anchor is reported");
  assert.equal(body.scanMode, "incremental");
  assert.equal(body.stale, false);
});

// --- symbol collisions on the reporting endpoints -----------------------------------------

test("/drops reports tickers claimed by more than one held contract", async () => {
  const holdings = {
    tokens: async () => [
      { address: "0xB2662781", name: "Kajko24", symbol: "KJK" },
      { address: "0x35483D56", name: "Kajko", symbol: "KJK" },
      { address: "0xAAAA", name: "Moxie", symbol: "MOXIE" },
    ],
    nfts: async () => [],
  };
  const { status, body } = await get(makeApp({ holdings }), "/drops");

  assert.equal(status, 200);
  assert.equal(body.symbolCollisions.length, 1);
  assert.equal(body.symbolCollisions[0].symbol, "KJK");
  assert.deepEqual(body.symbolCollisions[0].contracts.map((c) => c.name), ["Kajko24", "Kajko"]);
});

test("a collision is reported even when no rule flagged either contract", async () => {
  // Neither name trips anything, which is exactly why this belongs in the report: no
  // single-token rule can see that two contracts claim one ticker.
  const holdings = {
    tokens: async () => [],
    nfts: async () => [
      { address: "0xEdee", name: "CustomPunks", symbol: "CP", standard: "ERC-721" },
      { address: "0x78bc", name: "CustomPunks", symbol: "CP", standard: "ERC-721" },
    ],
  };
  const { body } = await get(makeApp({ holdings }), "/drops");

  assert.equal(body.flaggedCount, 0);
  assert.equal(body.symbolCollisions.length, 1);
  assert.equal(body.symbolCollisions[0].flaggedCount, 0);
});

test("/audit carries collisions without letting them move the hygiene score", async () => {
  const withCollision = {
    tokens: async () => [
      { address: "0x1", name: "Kajko24", symbol: "KJK" },
      { address: "0x2", name: "Kajko", symbol: "KJK" },
    ],
    nfts: async () => [],
  };
  const withoutCollision = {
    tokens: async () => [
      { address: "0x1", name: "Kajko24", symbol: "KJK" },
      { address: "0x2", name: "Moxie", symbol: "MOXIE" },
    ],
    nfts: async () => [],
  };

  const collided = await get(makeApp({ holdings: withCollision, allowUnpaidAudit: true }), "/audit");
  const clean = await get(makeApp({ holdings: withoutCollision, allowUnpaidAudit: true }), "/audit");

  assert.equal(collided.body.scamAirdrops.symbolCollisions.length, 1);
  assert.equal(clean.body.scamAirdrops.symbolCollisions.length, 0);
  // Deliberate: a shared ticker says at most one claimant is genuine, not which one, so it is
  // reported as a fact and never scored as a verdict.
  assert.equal(collided.body.hygieneScore, clean.body.hygieneScore);
});
