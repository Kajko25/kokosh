// Heuristic scam-airdrop token detection. Real signals seen in kajko24.base.eth's own
// wallet history (e.g. "Claim: https://aerodrome.supply" impersonating AERO, "Fyde Points
// (Claim: www.fyde.cc)"): name/symbol embeds a URL, "claim"-style urgency language, or
// homoglyph confusables mimicking a well-known ticker.

const URL_PATTERN = /(https?:\/\/|www\.)[a-z0-9.-]+\.[a-z]{2,}/i;

// Scam tokens in this wallet advertise bare hosts without a scheme — "PPBox.io",
// "t.me/s/US_POOL", "t.ly/TRUMP" — which the URL pattern above misses because it requires
// https:// or www. Matching any dotted word would flag legitimate names ("Rai.Finance",
// "U. S. ZORA RESERVE"), so this is deliberately restricted to the TLDs actually used for
// this kind of lure: link shorteners, messengers, and cheap generic domains.
//
// `com` and `net` are in the list; `finance` deliberately is not. Real holdings here include
// "Rai.Finance", a legitimate token, and the one scam that needs that TLD ("cakesv4.finance")
// is caught by the ticker-impersonation rule below instead — a precise mechanism beats a broad
// one that costs a false positive.
const BARE_DOMAIN_PATTERN = /\b[a-z0-9][a-z0-9-]*\.(io|me|ly|cc|xyz|top|link|site|app|gg|to|club|online|shop|vip|win|com|net)\b/i;

// Some of these names space out the dot to slip past a domain regex: "DAONEXT. COM",
// "DAOEVENT . COM", and "t .me/s/sol_shiba" with the space inside the host. A human reading
// the name in a wallet UI still sees a domain, which is the whole point of the trick, so the
// spacing is closed up before the domain rules run. Five collections in this wallet are only
// detectable this way.
const DOT_SPACING = /\s*\.\s*/g;
const closeDotSpacing = (text) => text.replace(DOT_SPACING, ".");
const CLAIM_PATTERN = /\bclaim\b|\buntil\b|\bexpires?\b|\bvisit\b|\bairdrop\b/i;

// The other half of the lure: not "do this now" but "you have won something". Drawn from
// collections in this wallet that carry no domain and no urgency verb, so nothing else here
// sees them — "HYPERLIQUID REWARD" (twice, different contracts), "COIN Earnings",
// "5O OOO USD FOR FREE", "Scan the QR to get a reward". Word-bounded so ordinary names
// containing these as substrings are untouched; no false positive across this wallet's 274
// collections.
const REWARD_PATTERN = /\breward(s|ed)?\b|\bfree\b|\bprize\b|\bwin(ner|nings)?\b|\bbonus\b|\bgiveaway\b|\bearnings\b|\bredeem\b/i;

// A quoted sum of money: "# UP $5,000 TO $50,000", "340.000$ JUP Win", "135.000$ Win".
// The digits must be *grouped* in thousands, or carry a currency word, rather than merely
// following a dollar sign. The loose version — any $ next to any digits — flagged
// "EIP-4844 is Based" (symbol "$4844"), a legitimate collection in this wallet, and a
// detector that cries wolf on real holdings is one its owner stops reading.
// "#0 11 SCAN ME" and "[ #181 ] Scan the QR to get a reward" move the destination out of the
// text entirely and into an image, which defeats every rule that looks for a domain. A token
// name asking to be scanned has no legitimate use: the collection is not where you scan from.
const QR_PATTERN = /\bscan\b|\bqr\b/i;

// Pure pressure, no destination and no sum: "Don't miss this chance!" appears on two separate
// ERC-1155 contracts here.
const PRESSURE_PATTERN = /don'?t miss|last chance|hurry|limited time|act now/i;

const GROUPED_THOUSANDS = String.raw`\d{1,3}(?:[.,\s]\d{3})+`;
const MONEY_PATTERN = new RegExp(
  String.raw`(?:\$|\busd[tc]?\b)\s?${GROUPED_THOUSANDS}|${GROUPED_THOUSANDS}\s?(?:\$|\busd[tc]?\b)`,
  "i"
);

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

  // Domain rules see the de-spaced text; every other rule sees the name as written.
  const deSpacedName = closeDotSpacing(name);
  const deSpacedSymbol = closeDotSpacing(symbol);

  if (URL_PATTERN.test(deSpacedName) || URL_PATTERN.test(deSpacedSymbol)) {
    reasons.push("name_or_symbol_contains_url");
  }
  if (BARE_DOMAIN_PATTERN.test(deSpacedName) || BARE_DOMAIN_PATTERN.test(deSpacedSymbol)) {
    reasons.push("name_or_symbol_contains_bare_domain");
  }
  // Read from the symbol as well as the name. Four ERC-20s here keep the whole lure in the
  // symbol with a clean name — symbol "Visit moodeng.ink to claim" against name "MOODENG",
  // and the same shape for getuni.one, degen.gifts and USD.AC. Their TLDs are outside the
  // bare-domain list, so checking only the name left them entirely unseen.
  if (CLAIM_PATTERN.test(name) || CLAIM_PATTERN.test(symbol)) {
    reasons.push("urgency_language");
  }
  if (REWARD_PATTERN.test(name) || REWARD_PATTERN.test(symbol)) {
    reasons.push("reward_language");
  }
  if (MONEY_PATTERN.test(name) || MONEY_PATTERN.test(symbol)) {
    reasons.push("quotes_a_cash_amount");
  }
  if (QR_PATTERN.test(name) || QR_PATTERN.test(symbol)) {
    reasons.push("qr_code_lure");
  }
  if (PRESSURE_PATTERN.test(name) || PRESSURE_PATTERN.test(symbol)) {
    reasons.push("pressure_language");
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
