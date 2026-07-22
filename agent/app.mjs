import express from "express";
import { classifyToken } from "./lib/scamHeuristics.mjs";
import { fetchTokenHoldings } from "./lib/blockscout.mjs";
import { readExposureReport } from "./lib/exposure.mjs";
import { buildAuditPaymentMiddleware } from "./lib/x402Seller.mjs";

const WALLET = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";
const MAX_LAG_SECONDS = 60;

async function computeAudit() {
  const [report, holdings] = await Promise.all([readExposureReport(), fetchTokenHoldings(WALLET)]);
  const flagged = holdings.map((token) => ({ ...token, ...classifyToken(token) })).filter((t) => t.suspicious);
  const liveApprovals = report ? report.erc20Live.length + report.permit2Live.length : 0;
  return {
    wallet: WALLET,
    auditedAt: new Date().toISOString(),
    exposure: {
      liveErc20Approvals: report?.erc20Live.length ?? null,
      livePermit2Grants: report?.permit2Live.length ?? null,
      approvals: report?.erc20Live ?? [],
      permit2Grants: report?.permit2Live ?? [],
    },
    scamAirdrops: {
      scannedTokens: holdings.length,
      flaggedCount: flagged.length,
      flagged: flagged.map(({ address, name, symbol, reasons }) => ({ address, name, symbol, reasons })),
    },
    hygieneScore: Math.max(0, 100 - liveApprovals * 5 - flagged.length * 2),
  };
}

export function makeApp({ client, now = () => Date.now(), cdp } = {}) {
  const app = express();
  app.disable("x-powered-by");

  if (cdp?.apiKeyId && cdp?.apiKeySecret) {
    app.use(buildAuditPaymentMiddleware({ cdpApiKeyId: cdp.apiKeyId, cdpApiKeySecret: cdp.apiKeySecret }));
  }

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
      });
    } catch (err) {
      res.status(503).json({ status: "unreachable", error: String(err?.shortMessage ?? err) });
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
      scannedAt: report.scannedAt,
      liveErc20Approvals: report.erc20Live.length,
      livePermit2Grants: report.permit2Live.length,
      approvals: report.erc20Live,
      permit2Grants: report.permit2Live,
    });
  });

  app.get("/drops", async (req, res) => {
    res.set("Cache-Control", "public, max-age=1800");
    try {
      const holdings = await fetchTokenHoldings(WALLET);
      const flagged = holdings
        .map((token) => ({ ...token, ...classifyToken(token) }))
        .filter((token) => token.suspicious);
      res.json({
        wallet: WALLET,
        scannedTokens: holdings.length,
        flaggedCount: flagged.length,
        flagged: flagged.map(({ address, name, symbol, reasons }) => ({ address, name, symbol, reasons })),
      });
    } catch (err) {
      res.status(502).json({ error: String(err?.message ?? err) });
    }
  });

  app.get("/audit", async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      res.json(await computeAudit());
    } catch (err) {
      res.status(502).json({ error: String(err?.message ?? err) });
    }
  });

  app.get("/.well-known/agent-card.json", (req, res) => {
    res.set("Cache-Control", "public, max-age=300");
    res.json(agentCard());
  });

  return app;
}

export function agentCard() {
  return {
    name: "Kokosh",
    description:
      "Wallet-hygiene sentinel for kajko24.base.eth: tracks token/Permit2 allowance exposure, and flags scam-airdrop tokens by name/URL/homoglyph heuristics.",
    wallet: WALLET,
    endpoints: {
      healthz: "/healthz",
      exposure: "/exposure",
      drops: "/drops",
      audit: "/audit (paid via x402, $0.01 USDC on Base)",
    },
  };
}
