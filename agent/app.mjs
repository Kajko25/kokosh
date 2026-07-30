import express from "express";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { classifyToken } from "./lib/scamHeuristics.mjs";
import { fetchTokenHoldings, fetchNftHoldings } from "./lib/blockscout.mjs";
import { readExposureReport } from "./lib/exposure.mjs";
import { buildAuditPaymentMiddleware, AGENT_WALLET, AUDIT_PRICE, AUDIT_NETWORK } from "./lib/x402Seller.mjs";
import { issueNonce, verifySignIn, nonceStoreKind } from "./lib/siwb.mjs";
import { validatePayerInfo } from "./lib/payValidate.mjs";
import { validateSignInRequest } from "./lib/signInRequest.mjs";
import { describeFreshness } from "./lib/freshness.mjs";
import { failure } from "./lib/httpError.mjs";
import { createRateLimiter, rateLimitMiddleware } from "./lib/rateLimit.mjs";
import { createTtlCache } from "./lib/cache.mjs";
import { computeHygieneScore } from "./lib/hygieneScore.mjs";
import { readSentinelReport } from "./lib/sentinelReport.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

const WALLET = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const SENTINEL_STATE_PATH = fileURLToPath(new URL("./data/sentinel-state.json", import.meta.url));
const MAX_LAG_SECONDS = 60;

// One holdings fetch is three Blockscout requests since pagination was fixed, and both
// /drops and /audit need it. Shared so the two endpoints do not each hold their own copy.
const holdingsCache = createTtlCache({ ttlMs: 60_000 });
const cachedHoldings = () => holdingsCache.get(() => fetchTokenHoldings(WALLET));

// Kept as its own cache entry rather than folded into the one above: the NFT walk is four more
// upstream requests, and a failure on one side should not evict a good result on the other.
const nftCache = createTtlCache({ ttlMs: 60_000 });
const cachedNfts = () => nftCache.get(() => fetchNftHoldings(WALLET));

export const LIVE_HOLDINGS = { tokens: cachedHoldings, nfts: cachedNfts };

/**
 * Classify every holding, across all three token standards.
 *
 * Deliberately fails as a whole rather than reporting the ERC-20 half when the NFT walk is
 * down. "Scanned 149 tokens, nothing new" reads as an all-clear, and a partial scan that looks
 * complete is this agent's characteristic failure — it is how ERC-20 pagination hid a third of
 * the holdings and how ERC-721/1155 went unscanned entirely.
 *
 * `sources` is a seam, not a feature: the live pair reads cached Blockscout walks, and tests
 * pass fixtures so the endpoints built on this can be exercised without the network.
 */
export async function scanHoldings(sources = LIVE_HOLDINGS) {
  const [tokens, nfts] = await Promise.all([sources.tokens(), sources.nfts()]);
  const all = [...tokens, ...nfts];
  const classified = all.map((token) => ({ ...token, standard: token.standard || "ERC-20", ...classifyToken(token) }));

  const scannedByStandard = {};
  for (const item of classified) scannedByStandard[item.standard] = (scannedByStandard[item.standard] ?? 0) + 1;

  return {
    scannedTokens: classified.length,
    scannedByStandard,
    flagged: classified.filter((t) => t.suspicious),
  };
}

const flaggedForReport = (flagged) =>
  flagged.map(({ address, name, symbol, standard, reasons }) => ({ address, name, symbol, standard, reasons }));

async function computeAudit(sources) {
  const [report, holdings] = await Promise.all([readExposureReport(), scanHoldings(sources)]);
  const { flagged } = holdings;
  return {
    wallet: WALLET,
    auditedAt: new Date().toISOString(),
    exposure: {
      ...describeFreshness(report?.scannedAt),
      liveErc20Approvals: report?.erc20Live.length ?? null,
      livePermit2Grants: report?.permit2Live.length ?? null,
      approvals: report?.erc20Live ?? [],
      permit2Grants: report?.permit2Live ?? [],
    },
    scamAirdrops: {
      scannedTokens: holdings.scannedTokens,
      scannedByStandard: holdings.scannedByStandard,
      flaggedCount: flagged.length,
      flagged: flaggedForReport(flagged),
    },
    ...computeHygieneScore({ report, flaggedCount: flagged.length }),
  };
}

/**
 * Decide how /audit behaves given the credentials actually present.
 *
 * `paid`        — CDP keys configured, x402 middleware charges for the report.
 * `unpaid`      — no keys, but serving it free was an explicit, deliberate choice.
 * `unavailable` — no keys and no opt-in: refuse rather than give the paid report away.
 *
 * The default is `unavailable` on purpose. Previously a missing key silently downgraded a
 * paid endpoint to a free one with no error anywhere, which is the worst of the three: it
 * looks like a working deployment while the agent's only revenue path is quietly wide open.
 */
export function resolveAuditMode({ cdp, allowUnpaidAudit = false } = {}) {
  if (cdp?.apiKeyId && cdp?.apiKeySecret) return "paid";
  return allowUnpaidAudit ? "unpaid" : "unavailable";
}

export function makeApp({
  client,
  now = () => Date.now(),
  cdp,
  allowUnpaidAudit = false,
  authRateLimit,
  // Injectable so /drops and /audit can be tested at all. Until now the only path to the
  // holdings was a module-level cached fetch against live Blockscout, which is why the two
  // endpoints that carry this agent's actual product had no tests.
  holdings = LIVE_HOLDINGS,
} = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json());
  app.use((req, res, next) => {
    // Needed for the Base Account popup flows the pages under public/ rely on.
    res.set("Cross-Origin-Opener-Policy", "same-origin-allow-popups");

    // public/ serves real wallet sign-in and payment pages, so these are not box-ticking:
    // nosniff stops a JSON response being reinterpreted as script, DENY keeps the signing
    // pages out of a frame, and the referrer policy keeps paths off third-party sites.
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "DENY");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");

    // Deliberately no Content-Security-Policy. The pages import the Base Account SDK and viem
    // from esm.sh and hand off to Coinbase-hosted signing, so a correct policy needs
    // verification in a real browser against a real wallet flow. This environment has no
    // headless browser (missing libnspr4), and shipping an unverified CSP would risk breaking
    // sign-in flows that are known to work. Left as a documented gap rather than a guess.
    next();
  });
  app.use(express.static(join(__dirname, "public")));

  const auditMode = resolveAuditMode({ cdp, allowUnpaidAudit });

  if (auditMode === "paid") {
    app.use(buildAuditPaymentMiddleware({ cdpApiKeyId: cdp.apiKeyId, cdpApiKeySecret: cdp.apiKeySecret }));
  } else if (auditMode === "unavailable") {
    // Registered here, ahead of the GET /audit handler below, so it intercepts rather than
    // falling through to the free report.
    app.use("/audit", (req, res) => {
      res.set("Cache-Control", "no-store");
      res.status(503).json({
        error: "payment_not_configured",
        detail:
          "/audit is a paid endpoint but CDP_API_KEY_ID / CDP_API_KEY_SECRET are not set, " +
          "so payment cannot be collected. Set both to enable charging, or set " +
          "ALLOW_UNPAID_AUDIT=1 to serve the report free on purpose.",
      });
    });
  }

  // Both sign-in endpoints share one budget: they are two halves of a single flow, so
  // limiting them separately would just double what a caller can extract.
  const authLimiter = createRateLimiter({ now, ...authRateLimit });
  app.use(["/auth/nonce", "/auth/verify"], rateLimitMiddleware(authLimiter));

  app.get("/auth/nonce", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ nonce: issueNonce() });
  });

  app.post("/auth/verify", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const parsed = validateSignInRequest(req.body);
    if (!parsed.ok) {
      res.status(400).json({ error: parsed.error });
      return;
    }
    const result = await verifySignIn(parsed.value);
    // A store outage is a server-side failure, not a rejected credential — reporting it as
    // 401 would tell an honest client its signature was bad.
    const status = result.ok ? 200 : result.error === "nonce_store_unavailable" ? 503 : 401;
    res.status(status).json(result);
  });

  app.post("/pay/validate", (req, res) => {
    res.set("Cache-Control", "no-store");
    const { ok, response } = validatePayerInfo(req.body);
    res.status(ok ? 200 : 400).json(response);
  });

  app.get("/healthz", async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      const block = await client.getBlock({ blockTag: "latest" });
      const blockTimeMs = Number(block.timestamp) * 1000;
      const lagSeconds = Math.max(0, Math.round((now() - blockTimeMs) / 1000));
      const degraded = lagSeconds > MAX_LAG_SECONDS;
      res.status(degraded ? 503 : 200).json({
        status: degraded ? "degraded" : "ok",
        lagSeconds,
        blockNumber: block.number.toString(),
        // Configuration that silently degrades is the failure mode this agent has hit twice
        // (payments, then nonces), so the modes actually in force are observable from
        // outside rather than only in a startup log nobody reads.
        config: { audit: auditMode, nonceStore: nonceStoreKind() },
      });
    } catch (err) {
      // Keeps the documented {status} shape for this endpoint while still not echoing the
      // library's own diagnostics back to the caller.
      failure(res, { status: 503, code: "rpc_unreachable", error: err, extra: { status: "unreachable" } });
    }
  });

  app.get("/exposure", async (req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    const report = await readExposureReport();
    if (!report) {
      res.status(202).json({ status: "not_scanned_yet", wallet: WALLET });
      return;
    }
    res.json({
      wallet: WALLET,
      ...describeFreshness(report.scannedAt, { now }),
      liveErc20Approvals: report.erc20Live.length,
      livePermit2Grants: report.permit2Live.length,
      approvals: report.erc20Live,
      permit2Grants: report.permit2Live,
    });
  });

  // The daily cycle stopped once and nothing surfaced it: a stand-down and a dead cron look
  // identical from outside. This makes the last run's age readable by a monitor.
  app.get("/sentinel", async (req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    const report = await readSentinelReport({ path: SENTINEL_STATE_PATH, now });
    if (!report) {
      res.status(202).json({ status: "no_sentinel_state", wallet: WALLET });
      return;
    }
    res.json({ wallet: WALLET, ...report });
  });

  app.get("/drops", async (req, res) => {
    res.set("Cache-Control", "public, max-age=1800");
    try {
      const { scannedTokens, scannedByStandard, flagged } = await scanHoldings(holdings);
      res.json({
        wallet: WALLET,
        scannedTokens,
        scannedByStandard,
        flaggedCount: flagged.length,
        flagged: flaggedForReport(flagged),
      });
    } catch (err) {
      failure(res, { status: 502, code: "holdings_unavailable", error: err });
    }
  });

  app.get("/audit", async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      res.json(await computeAudit(holdings));
    } catch (err) {
      failure(res, { status: 502, code: "audit_unavailable", error: err });
    }
  });

  app.get("/.well-known/agent-card.json", (req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    res.json(agentCard({ auditMode }));
  });

  // The agent's own URL answered with Express's default "Cannot GET /" HTML page — and 500
  // in production, where the payment middleware is mounted. An agent's front door should say
  // what it is and where its machine-readable description lives.
  app.get("/", (req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    const card = agentCard({ auditMode });
    res.json({
      name: card.name,
      description: card.description,
      agentCard: "/.well-known/agent-card.json",
      endpoints: card.endpoints,
      pages: ["/signin.html", "/pay.html", "/subaccount.html", "/subscribe.html", "/prolink.html"],
      source: "https://github.com/Kajko25/kokosh",
    });
  });

  // Everything else is JSON, so unmatched routes should be too — the default handler replies
  // with an HTML error page that also echoes the requested path back.
  app.use((req, res) => {
    res.set("Cache-Control", "no-store");
    res.status(404).json({ error: "not_found" });
  });

  return app;
}

// The card is the machine-readable advertisement other agents act on, so it states the
// audit endpoint's *actual* mode rather than always claiming it is paid and available.
const AUDIT_DESCRIPTIONS = {
  paid: "/audit (paid via x402, $0.01 USDC on Base)",
  unpaid: "/audit (served free — payments deliberately disabled)",
  unavailable: "/audit (unavailable — payments not configured)",
};

export function agentCard({ auditMode = "paid" } = {}) {
  return {
    name: "Kokosh",
    description:
      "Wallet-hygiene sentinel for kajko24.base.eth: tracks token/Permit2 allowance exposure, and flags scam-airdrop tokens by name/URL/homoglyph heuristics.",
    wallet: WALLET,
    // On-chain identity, so a consumer can look the agent up rather than trusting this file.
    registrations: [{ standard: "ERC-8004", registry: "identity", chainId: 8453, agentId: 59633 }],
    endpoints: {
      healthz: "/healthz",
      exposure: "/exposure",
      drops: "/drops",
      sentinel: "/sentinel",
      audit: AUDIT_DESCRIPTIONS[auditMode] ?? AUDIT_DESCRIPTIONS.paid,
    },
    // Everything a paying agent needs to construct the payment without a preflight request,
    // taken from the same constants the middleware charges with so the two cannot drift.
    payment:
      auditMode === "paid"
        ? { "/audit": { scheme: "x402", protocol: "exact", price: AUDIT_PRICE, network: AUDIT_NETWORK, payTo: AGENT_WALLET } }
        : null,
  };
}

// Vercel's Node builder selects app.mjs as the function entrypoint — it is the root file
// importing express — and invokes its default export. Without one, every request routed
// here failed with FUNCTION_INVOCATION_FAILED ("the default export must be a function or
// server"), which is what made GET / a 500 in production while the routes reached through
// api/index.js worked fine.
//
// Built lazily so merely importing this module stays side-effect free: the tests import
// makeApp directly and must not spin up a client or emit startup warnings.
let configuredApp = null;

export default async function handler(req, res) {
  if (!configuredApp) {
    const { buildConfiguredApp } = await import("./lib/configuredApp.mjs");
    configuredApp = buildConfiguredApp(makeApp, { resolveAuditMode });
  }
  return configuredApp(req, res);
}
