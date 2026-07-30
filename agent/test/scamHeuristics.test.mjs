import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyToken } from "../lib/scamHeuristics.mjs";

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
