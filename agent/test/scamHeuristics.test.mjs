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
