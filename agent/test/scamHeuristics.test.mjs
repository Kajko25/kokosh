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
  for (const [name, symbol] of [
    ["Rai.Finance", "SOFI"],
    ["U. S. ZORA RESERVE", "USZR"],
    ["Coinbase Wrapped BTC", "CBBTC"],
    ["Bridged USDC (Base)", "USDBC"],
    ["Art by Virtuals", "ART"],
  ]) {
    assert.equal(classifyToken({ name, symbol, address: "0x1" }).suspicious, false, name);
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
