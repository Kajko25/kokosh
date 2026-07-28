import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchTokenHoldings } from "../lib/blockscout.mjs";

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
  assert.deepEqual(holding, { address: undefined, name: "", symbol: "", balance: "5" });
});
