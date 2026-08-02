// Tokens in this wallet that share a ticker with a different contract.
//
// Every other rule in this agent judges a token by its own name. This one cannot: whether
// "Kajko" is impersonating anything depends on "Kajko24" also being held, which `classifyToken`
// -- correctly -- never sees, because it is handed one token at a time.
//
// Found by grouping the real holdings by symbol. The wallet holds KJK twice ("Kajko24", the
// owner's own token, and "Kajko"), LFI twice ("LienFI", "Lien From AI"), GPT twice, OPENAI
// twice, and a symbol of "." across nine separate ERC-1155 contracts.
//
// REPORTED, NOT ACCUSED. This deliberately does not emit a `classifyToken` reason and does not
// feed the hygiene score. The wallet also holds "CustomPunks" at two addresses with nothing
// wrong with either, so a collision is evidence that *at most one* of the contracts is the one
// the ticker belongs to -- not proof that any particular one is a fake. Presenting a fact the
// owner can act on beats a verdict the data does not support; the existing rules already say
// which of the colliding contracts look like scams, and that judgement stays theirs.

/** Symbols too generic or empty to mean anything when they collide. */
const MEANINGLESS = new Set(["", "-", ".", "?"]);

const normalise = (symbol) => (symbol ?? "").trim().toUpperCase();

/**
 * Groups holdings by ticker and returns only the tickers claimed by more than one contract.
 *
 * @param {Array<{address?: string, name?: string, symbol?: string, standard?: string, suspicious?: boolean}>} holdings
 *   Classified holdings — `suspicious` is carried through when present so a caller can see which
 *   side of a collision the existing rules already flagged.
 * @param {{ includeMeaningless?: boolean }} [options]
 *   `includeMeaningless` keeps symbols like "." that nine contracts share by virtue of saying
 *   nothing. Off by default: those collide for a reason that is not impersonation.
 * @returns {Array<{symbol: string, contracts: Array<object>, flaggedCount: number}>}
 *   Sorted by contract count, then symbol, so the output is stable between runs.
 */
export function findSymbolCollisions(holdings = [], { includeMeaningless = false } = {}) {
  const bySymbol = new Map();

  for (const token of holdings) {
    const symbol = normalise(token.symbol);
    if (!includeMeaningless && MEANINGLESS.has(symbol)) continue;
    if (!bySymbol.has(symbol)) bySymbol.set(symbol, new Map());
    // Keyed by address so the same contract listed twice -- which happens, ERC-1155 collections
    // arrive per token id -- is one contract, not a collision with itself.
    const address = (token.address ?? "").toLowerCase();
    if (!bySymbol.get(symbol).has(address)) bySymbol.get(symbol).set(address, token);
  }

  const collisions = [];
  for (const [symbol, contracts] of bySymbol) {
    if (contracts.size < 2) continue;
    const listed = [...contracts.values()].map(({ address, name, symbol: raw, standard, suspicious }) => ({
      address,
      name,
      symbol: raw,
      standard,
      flagged: Boolean(suspicious),
    }));
    collisions.push({
      symbol,
      contracts: listed,
      flaggedCount: listed.filter((c) => c.flagged).length,
    });
  }

  return collisions.sort((a, b) => b.contracts.length - a.contracts.length || a.symbol.localeCompare(b.symbol));
}
