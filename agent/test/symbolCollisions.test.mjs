import { test } from "node:test";
import assert from "node:assert/strict";

import { findSymbolCollisions } from "../lib/symbolCollisions.mjs";

const token = (symbol, name, address, extra = {}) => ({ symbol, name, address, standard: "ERC-20", ...extra });

test("reports a ticker claimed by two different contracts", () => {
  // The real case this was written for: the owner's own token and a later arrival on the same
  // ticker, neither of which any single-token rule can see as related.
  const collisions = findSymbolCollisions([
    token("KJK", "Kajko24", "0xB2662781"),
    token("KJK", "Kajko", "0x35483D56"),
    token("MOXIE", "Moxie", "0xAAAA"),
  ]);

  assert.equal(collisions.length, 1);
  assert.equal(collisions[0].symbol, "KJK");
  assert.deepEqual(collisions[0].contracts.map((c) => c.name), ["Kajko24", "Kajko"]);
});

test("a ticker held once is not a collision", () => {
  assert.deepEqual(findSymbolCollisions([token("MOXIE", "Moxie", "0xA"), token("SOFI", "Rai.Finance", "0xB")]), []);
});

test("the same contract listed twice is one contract, not a collision", () => {
  // ERC-1155 holdings arrive per token id, so a collection appears repeatedly at one address.
  const collisions = findSymbolCollisions([
    token("ABC", "ABCs", "0xdead", { standard: "ERC-1155" }),
    token("ABC", "ABCs", "0xDEAD", { standard: "ERC-1155" }),
  ]);
  assert.deepEqual(collisions, []);
});

test("carries through which side the existing rules already flagged", () => {
  const collisions = findSymbolCollisions([
    token("CAKE", "cakesv4.finance", "0x87E4", { suspicious: true }),
    token("CAKE", "PancakeSwap Token", "0x3055"),
  ]);

  assert.equal(collisions[0].flaggedCount, 1);
  assert.deepEqual(collisions[0].contracts.map((c) => c.flagged), [true, false]);
});

test("a collision where nothing is flagged is still reported", () => {
  // "CustomPunks" at two addresses, both clean. Reporting it is the point: the finding is that
  // one ticker has two claimants, not that either is a fake.
  const collisions = findSymbolCollisions([
    token("CP", "CustomPunks", "0xEdee", { standard: "ERC-721" }),
    token("CP", "CustomPunks", "0x78bc", { standard: "ERC-721" }),
  ]);

  assert.equal(collisions.length, 1);
  assert.equal(collisions[0].flaggedCount, 0);
});

test("symbols that say nothing are skipped, since they collide for the wrong reason", () => {
  // Nine ERC-1155 contracts in this wallet share a symbol of ".". They have nothing to do with
  // each other; treating that as ticker impersonation would bury the collisions that matter.
  const holdings = [
    token(".", "! ( ! ) ADDBOX", "0x1", { standard: "ERC-1155" }),
    token(".", "! [#] AutoETH 2117", "0x2", { standard: "ERC-1155" }),
    token("", "(no symbol)", "0x3"),
    token("", "(no symbol either)", "0x4"),
    token("-", "dash", "0x5"),
    token("-", "dash two", "0x6"),
  ];

  assert.deepEqual(findSymbolCollisions(holdings), []);
  assert.equal(findSymbolCollisions(holdings, { includeMeaningless: true }).length, 3);
});

test("ticker comparison folds case and surrounding whitespace", () => {
  const collisions = findSymbolCollisions([token("openAI", "openAI", "0x1"), token("OpenAI ", "OpenAI", "0x2")]);
  assert.equal(collisions.length, 1);
  assert.equal(collisions[0].symbol, "OPENAI");
});

test("output is ordered by how contested a ticker is, then stably by symbol", () => {
  const collisions = findSymbolCollisions([
    token("BB", "b one", "0x1"),
    token("BB", "b two", "0x2"),
    token("AA", "a one", "0x3"),
    token("AA", "a two", "0x4"),
    token("CC", "c one", "0x5"),
    token("CC", "c two", "0x6"),
    token("CC", "c three", "0x7"),
  ]);

  assert.deepEqual(collisions.map((c) => c.symbol), ["CC", "AA", "BB"]);
});

test("holdings with no symbol field at all do not throw", () => {
  assert.deepEqual(findSymbolCollisions([{ name: "nameless", address: "0x1" }, { address: "0x2" }]), []);
});

test("an empty wallet has no collisions", () => {
  assert.deepEqual(findSymbolCollisions(), []);
  assert.deepEqual(findSymbolCollisions([]), []);
});
