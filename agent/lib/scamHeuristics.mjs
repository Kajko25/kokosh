import { createHash } from "node:crypto";

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

// "#0 11 SCAN ME" and "[ #181 ] Scan the QR to get a reward" move the destination out of the
// text entirely and into an image, which defeats every rule that looks for a domain. A token
// name asking to be scanned has no legitimate use: the collection is not where you scan from.
const QR_PATTERN = /\bscan\b|\bqr\b/i;

// Pure pressure, no destination and no sum: "Don't miss this chance!" appears on two separate
// ERC-1155 contracts here.
const PRESSURE_PATTERN = /don'?t miss|last chance|hurry|limited time|act now/i;

// A quoted sum of money: "# UP $5,000 TO $50,000", "340.000$ JUP Win", "135.000$ Win".
// The digits must be *grouped* in thousands, or carry a currency word, rather than merely
// following a dollar sign. The loose version — any $ next to any digits — flagged
// "EIP-4844 is Based" (symbol "$4844"), a legitimate collection in this wallet, and a
// detector that cries wolf on real holdings is one its owner stops reading.
const GROUPED_THOUSANDS = String.raw`\d{1,3}(?:[.,\s]\d{3})+`;
const MONEY_PATTERN = new RegExp(
  String.raw`(?:\$|\busd[tc]?\b)\s?${GROUPED_THOUSANDS}|${GROUPED_THOUSANDS}\s?(?:\$|\busd[tc]?\b)`,
  "i"
);

// Common Latin-lookalike confusable ranges (Cyrillic, Greek) that show up in ticker spoofing.
const HOMOGLYPH_PATTERN = /[Ѐ-ӿͰ-Ͽ]/;

// The largest unflagged cluster in this wallet, and it is a single campaign: tokens borrowing
// the authority of a state or central bank. "Global Digital Oil Reserve", "Official Saudi Oil
// Reserve", "Peace Federal Reserve", "VANGUARD DIGITAL RESERVE", "GUARD OIL RESERVE US",
// "United States Digital Oil Reserve", "Reserve Oil On Trump" and half a dozen more, none of
// which any other rule sees -- no domain, no urgency verb, no cash sum, no confusable.
//
// Both halves are required, and that is the whole design. "Reserve" alone is a normal English
// word and appears in holdings that are not this campaign; the pairing with a sovereign or
// commodity qualifier is what makes it a claim of official backing. Two names deliberately do
// NOT match: "Based USA" (a memecoin, no reserve claim) and "U. S. ZORA RESERVE" (already
// treated as legitimate elsewhere in this file), so the narrow rule leaves both alone where a
// broad one would have flagged them.
const RESERVE_WORD = /\breserves?\b/i;
const RESERVE_QUALIFIER = /\b(oil|federal|digital|treasury|military|strategic|gold|sovereign|petroleum)\b/i;
// The same campaign without the word "reserve": "UNITED NATIONS OIL SUPPLY", "Nation America
// Trump Oil". A supranational name attached to a commodity is the same borrowed authority.
const STATE_BODY = /\b(united states|united nations|nation america)\b/i;
const STATE_COMMODITY = /\b(oil|reserves?|supply|petroleum)\b/i;

const impersonatesAStateReserve = (text) =>
  (RESERVE_WORD.test(text) && RESERVE_QUALIFIER.test(text)) ||
  (STATE_BODY.test(text) && STATE_COMMODITY.test(text));

// AI labs that have never issued a token, sitting unflagged in this wallet as "OpenAI",
// "openAI", "Open AI", "DeepSeek" and "GPT" twice over. The claim these make is not urgency or
// a prize -- it is simply being someone else, and no other rule looks for that.
//
// Matched on the WHOLE normalised name or symbol, never as a substring, and that is what keeps
// it safe: "MikeAI", "Gizai coin" and "Art by Virtuals" are real holdings that a contains-check
// would flag. Normalisation folds case and drops non-alphanumerics, so "Open AI", "open-ai" and
// "OPENAI" all collapse to the same string -- spacing is the cheapest possible evasion and the
// one these names already use.
//
// The list is deliberately short and only names labs whose absence from every chain is a matter
// of public record. A brand that might legitimately ship a token later does not belong here:
// the cost of a wrong entry is flagging a real project, which is how a detector loses its reader.
const IMPERSONATED_AI_BRANDS = new Set([
  "openai",
  "chatgpt",
  "gpt",
  "deepseek",
  "anthropic",
  "claude",
  "midjourney",
  "copilot",
  "perplexity",
]);

const normaliseBrand = (text) => text.toLowerCase().replace(/[^a-z0-9]/g, "");
const impersonatesAnAiBrand = (name, symbol) =>
  IMPERSONATED_AI_BRANDS.has(normaliseBrand(name)) || IMPERSONATED_AI_BRANDS.has(normaliseBrand(symbol));

// Canonical Base mainnet contract addresses for well-known tickers, so an exact ticker
// match from an unlisted contract gets flagged instead of trusted at face value. Found via
// a real miss: a token in this wallet at 0x9053A44f...554888eD3 is symbol/name "AAVE"/"AAVE"
// with a 2.1B total supply (real AAVE's global supply is ~16M) — a scam, but the old logic
// only compared strings and explicitly required the symbol to differ from the known ticker,
// so an exact-symbol copy (the simplest and most common impersonation) was never flagged.
//
// Every address below was verified on Base mainnet before being added: `symbol()` read
// on-chain and matched, `name()` read and matched the real project, and the Blockscout holder
// count checked (112k–1.2M holders each) as evidence of which deployment is the canonical one.
// An address guessed wrong here is worse than a missing entry — it would flag the *real* token
// as an impostor.
//
// CAKE earns its place directly: six ERC-721 collections in this wallet use that symbol, and
// one of them ("cakesv4.finance") is invisible to every other rule.
const KNOWN_TICKER_ADDRESSES = {
  AERO: "0x940181a94a35a4569e4529a3cdfb74e38fd98631",
  USDC: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  WETH: "0x4200000000000000000000000000000000000006",
  AAVE: "0x63706e401c06ac8513145b7687a14804d17f814b",
  CAKE: "0x3055913c90fcc1a6ce9a358911721eeb942013a1",
  DAI: "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
  EURC: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
  CBBTC: "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf",
  USDBC: "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca",
  ZORA: "0x1111111111166b7fe7bd91427724b487980afc69",
  MORPHO: "0xbaa5cc21fd487b8fcc2f632f3f4e8d37262a0842",
  DEGEN: "0x4ed4e862860bed51a9570b96d89af5e1b0efefed",
  TOSHI: "0xac1bd2486aaf3b5c0fc3fd868558b082a531b2b4",
  VIRTUAL: "0x0b3e328455c4059eeb9e3f84b5543f74e24e7e1b",
  WSTETH: "0xc1cba3fcea344f92d9239c08c0568f6f2f0ee452",
};

// Every reason this module can emit, and a short fingerprint over them.
//
// The sentinel attests findings on-chain, so it has to answer a question that has bitten this
// project twice already: did the wallet change, or did the detector? Adding a rule makes tokens
// that have been sitting there for months look brand new, and attesting those misdates the
// exposure. Both times the baseline was re-seeded by hand after noticing. Deriving the
// fingerprint from the rule list means it changes by itself when the rules do, so the sentinel
// can notice without anyone remembering to.
export const RULE_IDS = [
  "name_or_symbol_contains_url",
  "name_or_symbol_contains_bare_domain",
  "urgency_language",
  "reward_language",
  "quotes_a_cash_amount",
  "qr_code_lure",
  "pressure_language",
  "non_latin_homoglyph",
  "impersonates_a_state_reserve",
  "impersonates_an_ai_brand",
  ...Object.keys(KNOWN_TICKER_ADDRESSES).map((ticker) => `impersonates_${ticker}`),
];

/**
 * A stable short digest of the active ruleset.
 *
 * Deliberately content-derived rather than a hand-maintained version number: a rule added
 * without bumping a constant is exactly the case that goes unnoticed. Ordered, so the digest
 * tracks *which* rules exist and not the order they happen to be listed in.
 */
export function detectorFingerprint() {
  return createHash("sha256").update([...RULE_IDS].sort().join("|")).digest("hex").slice(0, 12);
}

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
  if (impersonatesAStateReserve(name) || impersonatesAStateReserve(symbol)) {
    reasons.push("impersonates_a_state_reserve");
  }
  if (impersonatesAnAiBrand(name, symbol)) {
    reasons.push("impersonates_an_ai_brand");
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
