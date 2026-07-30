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
    standard: item.token?.type ?? "",
  }));
}

/**
 * Walk one token type's holdings, following pagination.
 *
 * `maxPages` bounds the walk so a pathological account cannot stall the request path
 * indefinitely. Hitting that cap calls `onTruncated` rather than being swallowed the way the
 * single-page version's truncation was.
 */
async function fetchHoldingsOfType(address, type, { fetchImpl = fetch, maxPages = MAX_PAGES, onTruncated } = {}) {
  const holdings = [];
  let params = null;

  for (let page = 0; page < maxPages; page++) {
    const query = new URLSearchParams({ type });
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

/** All ERC-20 holdings for an address. */
export function fetchTokenHoldings(address, options = {}) {
  return fetchHoldingsOfType(address, "ERC-20", options);
}

export const NFT_STANDARDS = ["ERC-721", "ERC-1155"];

/**
 * All NFT holdings for an address, as one entry per *collection*.
 *
 * Two things make this different from the ERC-20 walk rather than a parameter change:
 *
 * 1. NFTs live under two separate `type` filters, so this is two paginated walks.
 * 2. The endpoint returns one item per `token_id`, so a collection appears as many times as
 *    the wallet holds pieces of it (0x2984 holds 71 ERC-1155 items across 56 contracts).
 *    Scam classification is a property of the collection, not of each piece, so entries are
 *    folded by contract address with `instanceCount` recording how many were seen. Leaving
 *    them unfolded would report the same scam collection repeatedly and inflate every count.
 *
 * A failure on either standard propagates: reporting the ERC-721 half as if it were the whole
 * NFT picture is the same silent-truncation bug the ERC-20 pagination fix was about.
 */
export async function fetchNftHoldings(address, options = {}) {
  const collections = new Map();

  for (const standard of NFT_STANDARDS) {
    for (const item of await fetchHoldingsOfType(address, standard, options)) {
      const key = item.address?.toLowerCase() ?? "";
      const existing = collections.get(key);
      if (existing) {
        existing.instanceCount += 1;
        continue;
      }
      const { balance, ...rest } = item;
      collections.set(key, { ...rest, standard: item.standard || standard, instanceCount: 1 });
    }
  }

  return [...collections.values()];
}
