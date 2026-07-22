const BASE_URL = "https://base.blockscout.com/api/v2";

export async function fetchTokenHoldings(address) {
  const res = await fetch(`${BASE_URL}/addresses/${address}/tokens?type=ERC-20`);
  if (!res.ok) throw new Error(`Blockscout tokens fetch failed: ${res.status}`);
  const data = await res.json();
  return (data.items ?? []).map((item) => ({
    address: item.token?.address_hash,
    name: item.token?.name ?? "",
    symbol: item.token?.symbol ?? "",
    balance: item.value,
  }));
}
