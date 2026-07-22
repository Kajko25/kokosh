// Heuristic scam-airdrop token detection. Real signals seen in kajko24.base.eth's own
// wallet history (e.g. "Claim: https://aerodrome.supply" impersonating AERO, "Fyde Points
// (Claim: www.fyde.cc)"): name/symbol embeds a URL, "claim"-style urgency language, or
// homoglyph confusables mimicking a well-known ticker.

const URL_PATTERN = /(https?:\/\/|www\.)[a-z0-9.-]+\.[a-z]{2,}/i;
const CLAIM_PATTERN = /\bclaim\b|\buntil\b|\bexpires?\b|\bvisit\b|\bairdrop\b/i;

// Common Latin-lookalike confusable ranges (Cyrillic, Greek) that show up in ticker spoofing.
const HOMOGLYPH_PATTERN = /[Ѐ-ӿͰ-Ͽ]/;

const KNOWN_TICKERS = ["AERO", "USDC", "WETH", "ETH", "USDT", "USD0", "AAVE"];

export function classifyToken({ name = "", symbol = "" }) {
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
  for (const ticker of KNOWN_TICKERS) {
    if (upperSymbol !== ticker && upperSymbol.replace(/[^A-Z]/g, "") === ticker && upperSymbol !== ticker) {
      reasons.push(`impersonates_${ticker}`);
    }
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
  };
}
