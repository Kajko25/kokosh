import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchTokenHoldings, fetchNftHoldings } from "../lib/blockscout.mjs";

const ADDRESS = "0x2984Bb4953cfCE2cEc957388BE686D6c38779234";

function page(items, next = null) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      items: items.map((symbol) => ({ token: { address_hash: `0x${symbol}`, name: symbol, symbol }, value: "1" })),
      next_page_params: next,
    }),
  };
}

// NFT pages carry the standard in token.type and repeat a contract once per token_id held.
function nftPage(entries, next = null) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      items: entries.map(([symbol, type, tokenId = "1"]) => ({
        token: { address_hash: `0x${symbol}`, name: symbol, symbol, type },
        token_id: tokenId,
        value: "1",
      })),
      next_page_params: next,
    }),
  };
}

function stub(pages) {
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    const next = pages.shift();
    if (!next) throw new Error("unexpected extra request");
    return next;
  };
  return { fetchImpl, urls };
}

test("a single page is returned as-is", async () => {
  const { fetchImpl } = stub([page(["AAA", "BBB"])]);
  const holdings = await fetchTokenHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(holdings.map((h) => h.symbol), ["AAA", "BBB"]);
});

test("pagination is followed until the API stops offering a next page", async () => {
  // The bug this guards: the wallet holds 149 ERC-20s across three pages, and the original
  // single-request version returned only the first 50 — silently scanning a third of the
  // tokens for scams and computing hygieneScore from that.
  const { fetchImpl } = stub([
    page(["A"], { id: 1, items_count: 50 }),
    page(["B"], { id: 2, items_count: 50 }),
    page(["C"]),
  ]);

  const holdings = await fetchTokenHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(holdings.map((h) => h.symbol), ["A", "B", "C"]);
});

test("next_page_params are forwarded as query parameters", async () => {
  const { fetchImpl, urls } = stub([page(["A"], { id: 42, value: "999", fiat_value: null }), page(["B"])]);
  await fetchTokenHoldings(ADDRESS, { fetchImpl });

  const second = new URL(urls[1]);
  assert.equal(second.searchParams.get("id"), "42");
  assert.equal(second.searchParams.get("value"), "999");
  assert.equal(second.searchParams.get("type"), "ERC-20", "the type filter must survive paging");
  assert.equal(second.searchParams.has("fiat_value"), false, "nulls are dropped rather than sent as 'null'");
});

test("the page walk is bounded and reports truncation instead of hiding it", async () => {
  // Every page offers another, so only maxPages protects us.
  const endless = { ok: true, status: 200, json: async () => ({ items: [], next_page_params: { id: 1 } }) };
  const fetchImpl = async () => endless;

  let truncatedAt = null;
  await fetchTokenHoldings(ADDRESS, { fetchImpl, maxPages: 3, onTruncated: (n) => (truncatedAt = n) });
  assert.equal(truncatedAt, 0, "onTruncated fires with the count gathered so far");
});

test("a non-200 response throws rather than yielding an empty holdings list", async () => {
  // Returning [] here would read downstream as "no scam tokens found", which is the worst
  // possible failure for a scam scanner.
  const fetchImpl = async () => ({ ok: false, status: 502, json: async () => ({}) });
  await assert.rejects(fetchTokenHoldings(ADDRESS, { fetchImpl }), /502/);
});

test("a failure partway through pagination propagates", async () => {
  const fetchImpl = async (url) =>
    url.includes("id=2")
      ? { ok: false, status: 500, json: async () => ({}) }
      : page(["A"], { id: 2 });
  await assert.rejects(fetchTokenHoldings(ADDRESS, { fetchImpl }), /500/);
});

test("requests carry a User-Agent and a timeout signal", async () => {
  let init;
  const fetchImpl = async (url, options) => {
    init = options;
    return page(["A"]);
  };
  await fetchTokenHoldings(ADDRESS, { fetchImpl });

  assert.match(init.headers["user-agent"], /kokosh-agent/);
  assert.ok(init.signal, "an unbounded fetch would hang the request path on a slow upstream");
});

test("missing token metadata degrades to empty strings rather than undefined", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ items: [{ value: "5" }], next_page_params: null }),
  });
  const [holding] = await fetchTokenHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(holding, { address: undefined, name: "", symbol: "", balance: "5", standard: "" });
});

test("NFT holdings cover both standards in one call", async () => {
  // Two separate type filters upstream: reporting only ERC-721 would leave the wallet's
  // ERC-1155 scam collections — the larger group of the two — entirely unscanned.
  const { fetchImpl, urls } = stub([
    nftPage([["AAA", "ERC-721"]]),
    nftPage([["BBB", "ERC-1155"]]),
  ]);

  const nfts = await fetchNftHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(nfts.map((n) => n.symbol), ["AAA", "BBB"]);
  assert.deepEqual(nfts.map((n) => n.standard), ["ERC-721", "ERC-1155"]);
  assert.deepEqual(
    urls.map((u) => new URL(u).searchParams.get("type")),
    ["ERC-721", "ERC-1155"]
  );
});

test("a collection held as several token_ids is folded into one entry", async () => {
  // The live wallet holds 71 ERC-1155 items across 56 contracts. Unfolded, one scam
  // collection would be reported — and counted — once per piece held.
  const { fetchImpl } = stub([
    nftPage([]),
    nftPage([
      ["DUP", "ERC-1155", "1"],
      ["DUP", "ERC-1155", "2"],
      ["DUP", "ERC-1155", "3"],
      ["OTHER", "ERC-1155"],
    ]),
  ]);

  const nfts = await fetchNftHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(nfts.map((n) => [n.symbol, n.instanceCount]), [
    ["DUP", 3],
    ["OTHER", 1],
  ]);
});

test("NFT entries carry no balance field", async () => {
  // `value` is per-token_id, so a collection-level balance would be a meaningless number;
  // instanceCount is the honest quantity here.
  const { fetchImpl } = stub([nftPage([["AAA", "ERC-721"]]), nftPage([])]);
  const [nft] = await fetchNftHoldings(ADDRESS, { fetchImpl });
  assert.equal("balance" in nft, false);
  assert.equal(nft.instanceCount, 1);
});

test("pagination is followed for each NFT standard", async () => {
  const { fetchImpl } = stub([
    nftPage([["A", "ERC-721"]], { id: 2 }),
    nftPage([["B", "ERC-721"]]),
    nftPage([["C", "ERC-1155"]], { id: 3 }),
    nftPage([["D", "ERC-1155"]]),
  ]);

  const nfts = await fetchNftHoldings(ADDRESS, { fetchImpl });
  assert.deepEqual(nfts.map((n) => n.symbol), ["A", "B", "C", "D"]);
});

test("an ERC-1155 failure is not hidden by a successful ERC-721 walk", async () => {
  // Half the NFT picture presented as the whole is the same silent-truncation failure the
  // ERC-20 pagination bug was.
  const fetchImpl = async (url) =>
    url.includes("ERC-1155") ? { ok: false, status: 503, json: async () => ({}) } : nftPage([["A", "ERC-721"]]);

  await assert.rejects(fetchNftHoldings(ADDRESS, { fetchImpl }), /503/);
});
