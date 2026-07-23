// Heuristic scam-airdrop token detection. Real signals seen in kajko24.base.eth's own
// wallet history (e.g. "Claim: https://aerodrome.supply" impersonating AERO, "Fyde Points
// (Claim: www.fyde.cc)"): name/symbol embeds a URL, "claim"-style urgency language, or
// homoglyph confusables mimicking a well-known ticker.

const URL_PATTERN = /(https?:\/\/|www\.)[a-z0-9.-]+\.[a-z]{2,}/i;
const CLAIM_PATTERN = /\bclaim\b|\buntil\b|\bexpires?\b|\bvisit\b|\bairdrop\b/i;

// Common Latin-lookalike confusable ranges (Cyrillic, Greek) that show up in ticker spoofing.
const HOMOGLYPH_PATTERN = /[Ѐ-ӿͰ-Ͽ]/;

// Canonical Base mainnet contract addresses for well-known tickers, so an exact ticker
// match from an unlisted contract gets flagged instead of trusted at face value. Found via
// a real miss: a token in this wallet at 0x9053A44f...554888eD3 is symbol/name "AAVE"/"AAVE"
// with a 2.1B total supply (real AAVE's global supply is ~16M) — a scam, but the old logic
// only compared strings and explicitly required the symbol to differ from the known ticker,
// so an exact-symbol copy (the simplest and most common impersonation) was never flagged.
const KNOWN_TICKER_ADDRESSES = {
  AERO: "0x940181a94a35a4569e4529a3cdfb74e38fd98631",
  USDC: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  WETH: "0x4200000000000000000000000000000000000006",
  AAVE: "0x63706e401c06ac8513145b7687a14804d17f814b",
};

export function classifyToken({ name = "", symbol = "", address = "" }) {
  const reasons = [];

  if (URL_PATTERN.test(name) || URL_PATTERN.test(symbol)) {
    reasons.push("name_or_symbol_contains_url");
  }
  if (CLAIM_PATTERN.test(name)) {
    reasons.push("urgency_language");
  }
  if (HOMOGLYPH_PATTERN.test(name) || HOMOGLYPH_PATTERN.test(symbol)) {
    reasons.push("non_latin_homoglyph");
  }

  const upperSymbol = symbol.toUpperCase().trim();
  const lowerAddress = address.toLowerCase();
  for (const [ticker, canonicalAddress] of Object.entries(KNOWN_TICKER_ADDRESSES)) {
    if (upperSymbol.replace(/[^A-Z]/g, "") === ticker && lowerAddress !== canonicalAddress) {
      reasons.push(`impersonates_${ticker}`);
    }
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
  };
}
