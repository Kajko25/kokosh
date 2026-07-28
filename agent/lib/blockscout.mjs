const BASE_URL = "https://base.blockscout.com/api/v2";

// Blockscout returns 50 holdings per page and hands back `next_page_params` when more exist.
// The original single-request version silently stopped at the first page — and this wallet
// holds well over 50 ERC-20s, most of them airdrop dust, so every scam scan and every
// hygieneScore was computed from a truncated list with no indication it was partial.
const MAX_PAGES = 20;

// Blockscout rejects some clients that send no User-Agent, and an unbounded fetch would hang
// the whole request path on a slow upstream.
const HEADERS = { "user-agent": "kokosh-agent (+https://kokosh-agent.vercel.app)" };
const TIMEOUT_MS = 15_000;

async function getJson(url, fetchImpl) {
  const res = await fetchImpl(url, { headers: HEADERS, signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`Blockscout tokens fetch failed: ${res.status}`);
  return res.json();
}

function normalise(items) {
  return (items ?? []).map((item) => ({
    address: item.token?.address_hash,
    name: item.token?.name ?? "",
    symbol: item.token?.symbol ?? "",
    balance: item.value,
  }));
}

/**
 * All ERC-20 holdings for an address, following pagination.
 *
 * `maxPages` bounds the walk so a pathological account cannot stall the request path
 * indefinitely. Hitting that cap calls `onTruncated` rather than being swallowed the way the
 * single-page version's truncation was.
 */
export async function fetchTokenHoldings(address, { fetchImpl = fetch, maxPages = MAX_PAGES, onTruncated } = {}) {
  const holdings = [];
  let params = null;

  for (let page = 0; page < maxPages; page++) {
    const query = new URLSearchParams({ type: "ERC-20" });
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== null && value !== undefined) query.set(key, String(value));
    }

    const data = await getJson(`${BASE_URL}/addresses/${address}/tokens?${query}`, fetchImpl);
    holdings.push(...normalise(data.items));

    params = data.next_page_params;
    if (!params) return holdings;
  }

  onTruncated?.(holdings.length);
  return holdings;
}
