import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyToken, RULE_IDS, detectorFingerprint } from "../lib/scamHeuristics.mjs";

test("flags a name containing a URL", () => {
  const result = classifyToken({ name: "Claim: https://aerodrome.supply", symbol: "AERO" });
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("name_or_symbol_contains_url"));
});

test("flags urgency language", () => {
  const result = classifyToken({ name: "Fyde Points (Claim: www.fyde.cc)", symbol: "FYDE" });
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("urgency_language"));
});

test("does not flag a normal token", () => {
  const result = classifyToken({ name: "Mirmil", symbol: "MIR" });
  assert.equal(result.suspicious, false);
  assert.deepEqual(result.reasons, []);
});

test("flags non-latin homoglyphs", () => {
  const result = classifyToken({ name: "Тoken", symbol: "TKN" }); // Cyrillic T
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("non_latin_homoglyph"));
});

test("flags an exact-symbol impersonation from an unlisted contract address", () => {
  // Real miss this heuristic used to have: a scam token with symbol/name exactly "AAVE"
  // (2.1B total supply vs. the real ~16M) at an address that isn't Aave's own token.
  const result = classifyToken({ name: "AAVE", symbol: "AAVE", address: "0x9053A44fABa4D7a5D71dcd64cf4dE73554888eD3" });
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("impersonates_AAVE"));
});

test("does not flag the real token at its canonical address", () => {
  const result = classifyToken({ name: "Aave Token", symbol: "AAVE", address: "0x63706e401c06ac8513145b7687A14804d17f814b" });
  assert.equal(result.suspicious, false);
  assert.deepEqual(result.reasons, []);
});

test("flags a bare domain with no scheme", () => {
  // Real holding in this wallet; the URL rule missed it because there is no https:// or www.
  const { suspicious, reasons } = classifyToken({ name: "PPBox.io", symbol: "PPBox.io", address: "0x1" });
  assert.equal(suspicious, true);
  assert.ok(reasons.includes("name_or_symbol_contains_bare_domain"));
});

test("flags messenger and shortener lures", () => {
  for (const name of ["t.me/s/US_POOL", "Claim at t.ly/TRUMP", "visit bit.ly/x", "reward at foo.xyz"]) {
    assert.equal(classifyToken({ name, symbol: "X", address: "0x1" }).suspicious, true, name);
  }
});

test("does not flag legitimate names that merely contain a dot", () => {
  // Measured against the wallet's real holdings: these must stay clean or the rule is worse
  // than the gap it closes.
  // cbBTC and USDbC carry their real addresses: their tickers are in the canonical map now, so
  // a placeholder address would (correctly) make them impersonators and stop testing dots.
  for (const [name, symbol, address] of [
    ["Rai.Finance", "SOFI", "0x1"],
    ["U. S. ZORA RESERVE", "USZR", "0x1"],
    ["Coinbase Wrapped BTC", "CBBTC", "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"],
    ["Bridged USDC (Base)", "USDBC", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"],
    ["Art by Virtuals", "ART", "0x1"],
  ]) {
    assert.equal(classifyToken({ name, symbol, address }).suspicious, false, name);
  }
});

test("a full URL still reports the url reason, not only the bare-domain one", () => {
  const { reasons } = classifyToken({
    name: "Airdrop at https://getdrops.io",
    symbol: "X",
    address: "0x1",
  });
  assert.ok(reasons.includes("name_or_symbol_contains_url"));
});

test("a domain with the dot spaced out is still a domain", () => {
  // Verbatim from this wallet's ERC-1155 holdings. Both spellings appear, which is what
  // makes it look like deliberate regex evasion rather than a typo.
  for (const name of ["! [#] DAONEXT. COM", "[ 82 ] DAOEVENT . COM"]) {
    const result = classifyToken({ name, symbol: "." });
    assert.equal(result.suspicious, true, name);
    assert.ok(result.reasons.includes("name_or_symbol_contains_bare_domain"), name);
  }
});

test("a space inside the host does not hide it either", () => {
  const result = classifyToken({ name: "REWARD 🎁🎁🎁 Visit: t .me/s/sol_shiba", symbol: "REWARD" });
  assert.ok(result.reasons.includes("name_or_symbol_contains_bare_domain"));
});

test(".com and .net count as domains", () => {
  assert.ok(classifyToken({ name: "! Airdapp.net", symbol: "AIRDAPP" }).reasons.includes("name_or_symbol_contains_bare_domain"));
});

test("a legitimate name ending in a non-listed TLD word is left alone", () => {
  // Rai.Finance is a real holding in this wallet, which is why `finance` is not in the TLD
  // list: adding it would trade one detection for one false positive.
  const result = classifyToken({ name: "Rai.Finance", symbol: "RAI", address: "0x1234" });
  assert.equal(result.suspicious, false);
});

test("de-spacing does not turn an ordinary abbreviation into a domain", () => {
  // "U. S. ZORA RESERVE" is a real holding; collapsing its dots must not produce a match.
  const result = classifyToken({ name: "U. S. ZORA RESERVE", symbol: "USZR" });
  assert.equal(result.suspicious, false);
});

test("flags reward and prize language with no domain or urgency verb attached", () => {
  // All verbatim holdings that nothing else in this module sees: no URL, no "claim", no
  // homoglyph. Two separate contracts are both named "HYPERLIQUID REWARD".
  for (const name of ["HYPERLIQUID REWARD", "COIN Earnings", "5O OOO USD FOR FREE", "[ #181 ] Scan the QR to get a reward"]) {
    const result = classifyToken({ name, symbol: "" });
    assert.equal(result.suspicious, true, name);
    assert.ok(result.reasons.includes("reward_language"), name);
  }
});

test("reward language is read from the symbol too", () => {
  const result = classifyToken({ name: "", symbol: "Hype REWARD" });
  assert.ok(result.reasons.includes("reward_language"));
});

test("reward words are word-bounded, not substring matches", () => {
  // "Freedom" contains "free", "Winter" contains "win", "Rewarding" is not a holding here but
  // the boundary is what keeps names like these out of the report.
  for (const name of ["Freedom Pass", "Winter Collection", "Basenames"]) {
    assert.equal(classifyToken({ name, symbol: "X" }).suspicious, false, name);
  }
});

test("flags a quoted cash amount", () => {
  for (const name of ["# UP $5,000 TO $50,000", "t.ly/nftjup - 340.000$ JUP Win", "1.000 USDC bonus"]) {
    assert.ok(classifyToken({ name, symbol: "" }).reasons.includes("quotes_a_cash_amount"), name);
  }
});

test("a dollar sign next to plain digits is not a cash amount", () => {
  // "EIP-4844 is Based" with symbol "$4844" is a real holding, and the looser version of this
  // rule flagged it. Grouped thousands or a currency word are what distinguish a sum of money
  // from an identifier that happens to be numeric.
  for (const [name, symbol] of [["EIP-4844 is Based", "$4844"], ["Multiverse: Earth #420", ""], ["Cubes 70", "3D"], ["DuneCon2024 Data City", ""]]) {
    assert.equal(classifyToken({ name, symbol }).reasons.includes("quotes_a_cash_amount"), false, name);
  }
});

test("urgency language in the symbol counts, even when the name looks clean", () => {
  // Four real ERC-20 holdings put the lure in the symbol and leave the name as a plausible
  // ticker. Their domains (.ink, .one, .gifts, USD.AC) are outside the bare-domain TLD list,
  // so the symbol is the only place they can be caught.
  for (const [symbol, name] of [
    ["Visit moodeng.ink to claim", "MOODENG"],
    ["Visit getuni.one to swap", "UNI"],
    ["Airdrop: degen.gifts/?claim", "Degen"],
    ["Claim on: USD.AC", "USDAC"],
  ]) {
    const result = classifyToken({ name, symbol, address: "0xdead" });
    assert.equal(result.suspicious, true, symbol);
    assert.ok(result.reasons.includes("urgency_language"), symbol);
  }
});

test("flags a QR-code lure, which hides the destination in an image", () => {
  for (const name of ["#0 11 SCAN ME", "[ #181 ] Scan the QR to get a reward"]) {
    const result = classifyToken({ name, symbol: "" });
    assert.ok(result.reasons.includes("qr_code_lure"), name);
  }
});

test("flags pressure language carrying no destination at all", () => {
  const result = classifyToken({ name: "Don't miss this chance!", symbol: "." });
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("pressure_language"));
});

test("the new lure rules leave real collections alone", () => {
  // A cross-section of genuine holdings, including ones with digits, punctuation and brand
  // names that the looser versions of these rules would have caught.
  for (const [name, symbol] of [
    ["Basenames", "BASENAME"],
    ["Base Colors", "COLORS"],
    ["Uniswap V3 Positions NFT-V1", "UNI-V3-POS"],
    ["adidas Onchain: Summer of Sports", "aOSoS"],
    ["ENS 7th Anniversary NFT", ""],
    ["Waymarks", "WAYMARK"],
  ]) {
    assert.equal(classifyToken({ name, symbol, address: "0xfeed" }).suspicious, false, name);
  }
});

test("flags an NFT collection borrowing a major token's ticker", () => {
  // "cakesv4.finance" is invisible to every text rule: `finance` is deliberately not in the
  // TLD list, and the name carries no urgency, reward or cash language. Six ERC-721
  // collections in this wallet use the CAKE symbol.
  const result = classifyToken({ name: "cakesv4.finance", symbol: "CAKE", address: "0x87e4ee31417889282667a5d56240719395a5f07f" });
  assert.equal(result.suspicious, true);
  assert.ok(result.reasons.includes("impersonates_CAKE"));
});

test("the real deployments of the tickers in the map are not flagged", () => {
  // The risk of a bigger map is flagging the genuine token, so these are the actual holdings
  // in this wallet at the addresses recorded as canonical.
  for (const [symbol, address] of [
    ["USDC", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"],
    ["cbBTC", "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"],
    ["USDbC", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"],
  ]) {
    assert.equal(classifyToken({ name: symbol, symbol, address }).suspicious, false, symbol);
  }
});

test("canonical matching is case-insensitive on both sides", () => {
  // Blockscout returns mixed-case addresses and PancakeSwap's own symbol() returns "Cake".
  const result = classifyToken({ name: "PancakeSwap Token", symbol: "Cake", address: "0x3055913C90Fcc1A6CE9a358911721eEb942013A1" });
  assert.equal(result.suspicious, false);
});

test("the rule list covers every reason the classifier can emit", () => {
  // If a rule is added without listing it here, the fingerprint stops tracking the ruleset and
  // the sentinel loses its ability to tell a detector change from a wallet change.
  const emitted = new Set();
  for (const token of [
    { name: "Claim: https://aerodrome.supply", symbol: "AERO", address: "0x1" },
    { name: "DAONEXT. COM", symbol: "." },
    { name: "HYPERLIQUID REWARD", symbol: "HL" },
    { name: "# UP $5,000 TO $50,000", symbol: "." },
    { name: "#0 11 SCAN ME", symbol: "TRUSA" },
    { name: "Don't miss this chance!", symbol: "." },
    { name: "Тoken", symbol: "TKN" },
    { name: "cakesv4.finance", symbol: "CAKE", address: "0x87e4ee31417889282667a5d56240719395a5f07f" },
  ]) {
    for (const reason of classifyToken(token).reasons) emitted.add(reason);
  }

  for (const reason of emitted) assert.ok(RULE_IDS.includes(reason), `${reason} is missing from RULE_IDS`);
});

test("the detector fingerprint is stable across calls and order-independent", () => {
  assert.equal(detectorFingerprint(), detectorFingerprint());
  assert.match(detectorFingerprint(), /^[0-9a-f]{12}$/);
});

test("the fingerprint covers the ticker map, since adding a ticker changes what gets flagged", () => {
  assert.ok(RULE_IDS.includes("impersonates_CAKE"));
  assert.ok(RULE_IDS.includes("impersonates_AAVE"));
});

// --- state-reserve impersonation ---------------------------------------------------------
//
// The largest cluster this detector could not see: thirteen tokens in this wallet borrowing the
// authority of a state or central bank, none of which carried a domain, an urgency verb, a cash
// sum or a confusable. Every name below is a real holding.

test("a token claiming to be a sovereign oil reserve is flagged", () => {
  for (const name of [
    "Global Digital Oil Reserve",
    "Official Saudi Oil Reserve",
    "United States Digital Oil Reserve",
    "GUARD OIL RESERVE US",
    "Global Oil Military Arms Reserve",
    "Vanguard Defens Oil Reserve",
    "Reserve Oil On Trump",
    "World Collective Oil Reserve",
  ]) {
    const result = classifyToken({ name, symbol: "X" });
    assert.ok(result.reasons.includes("impersonates_a_state_reserve"), `${name} should be flagged`);
  }
});

test("a token claiming central-bank backing is flagged", () => {
  assert.ok(classifyToken({ name: "Peace Federal Reserve", symbol: "FEDERAL" }).reasons.includes("impersonates_a_state_reserve"));
  assert.ok(classifyToken({ name: "VANGUARD DIGITAL RESERVE", symbol: "VDR" }).reasons.includes("impersonates_a_state_reserve"));
});

test("a supranational body attached to a commodity is flagged without the word reserve", () => {
  assert.ok(classifyToken({ name: "UNITED NATIONS OIL SUPPLY", symbol: "UNOS" }).reasons.includes("impersonates_a_state_reserve"));
  assert.ok(classifyToken({ name: "Nation America Trump Oil", symbol: "NATO" }).reasons.includes("impersonates_a_state_reserve"));
});

test("the rule needs both halves, so ordinary uses of either word are left alone", () => {
  // Both are real holdings in this wallet, and both are why the rule is a conjunction rather
  // than a list of scary words. A detector that flags them is one its owner stops reading.
  assert.equal(classifyToken({ name: "Based USA", symbol: "USA" }).suspicious, false);
  assert.equal(classifyToken({ name: "U. S. ZORA RESERVE", symbol: "USZR" }).suspicious, false);

  // And the general case: neither half alone is a finding.
  assert.equal(classifyToken({ name: "Reserve Protocol", symbol: "RSR" }).suspicious, false);
  assert.equal(classifyToken({ name: "Digital Asset Fund", symbol: "DAF" }).suspicious, false);
});

test("the reserve rule reads the symbol too, not only the name", () => {
  const result = classifyToken({ name: "Ordinary Name", symbol: "FEDERAL RESERVE" });
  assert.ok(result.reasons.includes("impersonates_a_state_reserve"));
});

// --- AI-brand impersonation ---------------------------------------------------------------

test("a token named after an AI lab that has never issued one is flagged", () => {
  for (const [name, symbol] of [
    ["OpenAI", "OpenAI"],
    ["openAI", "openAI"],
    ["Open AI", "AI"],
    ["DeepSeek", "DeepSeek"],
    ["GPT", "GPT"],
  ]) {
    assert.ok(
      classifyToken({ name, symbol }).reasons.includes("impersonates_an_ai_brand"),
      `${name} should be flagged`
    );
  }
});

test("brand matching folds case and spacing, the evasion these names already use", () => {
  for (const name of ["open-ai", "OPENAI", "Open.AI", "o p e n a i"]) {
    assert.ok(classifyToken({ name, symbol: "X" }).reasons.includes("impersonates_an_ai_brand"), name);
  }
});

test("the brand must be the whole name, so real holdings containing it survive", () => {
  // All three are real holdings here, and all three would fall to a substring check.
  assert.equal(classifyToken({ name: "MikeAI", symbol: "WAZ" }).suspicious, false);
  assert.equal(classifyToken({ name: "Gizai coin", symbol: "GIZAI" }).suspicious, false);
  assert.equal(classifyToken({ name: "Art by Virtuals", symbol: "ART" }).suspicious, false);
});
