// Planning logic for the incremental approval rescan.
//
// The full scan walks from block 0 — 4,900+ windows, about 50 minutes — which is why it gets run
// roughly never, and why `/exposure` served a snapshot that was two days stale while `/audit`
// sold a `hygieneScore` computed from it. An incremental refresh is minutes, so it can run often
// enough for the number to mean something.
//
// Two properties make an incremental refresh *correct* rather than merely fast:
//
//   1. **New events since the anchor** find allowances granted after the last scan. An allowance
//      can only become non-zero through a call that emits an event, so nothing that came alive in
//      the gap is invisible here.
//   2. **Every previously-live pair is re-read regardless.** This is the half that is easy to
//      miss: a finite allowance is decremented by `transferFrom`, and ERC-20 does not require an
//      event for that. A grant that was spent to zero produces no log at all, so scanning only
//      new events would keep reporting exposure that no longer exists — the mirror image of the
//      staleness this is meant to fix.
//
// Together those two cover the whole state. What incremental cannot do is repair a *wrong*
// anchor: if the recorded block is later than what was really scanned, the gap is silently
// skipped forever. Hence the anchor is refused rather than guessed when it is missing or ahead
// of the chain.

// Re-scanned on top of the anchor on every run. Base's sequencer can reorg shallowly, and a
// report written from a block that later disappeared would leave a permanent hole. ~8 minutes of
// blocks is far more than any reorg seen on this chain and costs one extra window.
export const DEFAULT_OVERLAP_BLOCKS = 250n;

export class MissingScanAnchor extends Error {
  constructor(message) {
    super(message);
    this.name = "MissingScanAnchor";
  }
}

/**
 * Work out which block range an incremental run has to cover.
 *
 * @param {object} args
 * @param {object|null} args.report the previous report, or null when there is none
 * @param {bigint|number|string} args.latestBlock current chain tip
 * @param {bigint} [args.overlap] blocks re-scanned below the anchor
 */
export function planIncrementalScan({ report, latestBlock, overlap = DEFAULT_OVERLAP_BLOCKS } = {}) {
  const tip = BigInt(latestBlock);
  const anchor = report?.scannedToBlock;

  if (anchor === undefined || anchor === null || anchor === "") {
    // Reports written before this field existed land here. Starting from 0 would silently turn
    // "refresh" into the 50-minute full walk; starting from the tip would skip the wallet's
    // entire history. Neither is a decision this function should make on its own.
    throw new MissingScanAnchor(
      "the report has no scannedToBlock — run a full scan once to establish the anchor, or pass an explicit --from-block"
    );
  }

  let anchorBlock;
  try {
    anchorBlock = BigInt(anchor);
  } catch {
    throw new MissingScanAnchor(`scannedToBlock is not an integer: ${JSON.stringify(anchor)}`);
  }
  if (anchorBlock < 0n) throw new MissingScanAnchor("scannedToBlock is negative");
  if (anchorBlock > tip) {
    // Same failure the sentinel's state validation refuses: an anchor past the tip makes every
    // future run scan an empty range and report "nothing new" while looking perfectly healthy.
    throw new MissingScanAnchor(`scannedToBlock ${anchorBlock} is ahead of the chain tip ${tip}`);
  }

  const fromBlock = anchorBlock > overlap ? anchorBlock - overlap + 1n : 0n;
  return { fromBlock, toBlock: tip, anchorBlock, overlapBlocks: anchorBlock - fromBlock + 1n };
}

const keyOf = ({ kind, token, spender }) => `${kind}:${token.toLowerCase()}:${spender.toLowerCase()}`;

/**
 * The set of (token, spender) pairs whose current allowance must be read back.
 *
 * `previousLive` entries are carried in even when no new event mentions them — see the
 * `transferFrom` reasoning above. Deduplication is case-insensitive because log decoding yields
 * checksummed addresses while stored reports have held both spellings.
 */
export function pairsToRecheck({ previousLive = [], discovered = [] } = {}) {
  const pairs = new Map();
  for (const pair of [...previousLive, ...discovered]) {
    if (!pair?.token || !pair?.spender) continue;
    const kind = pair.kind ?? "erc20";
    const key = keyOf({ ...pair, kind });
    // First writer wins, so a previously-live entry keeps its recorded symbol rather than being
    // replaced by a bare pair rediscovered from a log.
    if (!pairs.has(key)) pairs.set(key, { kind, token: pair.token, spender: pair.spender, symbol: pair.symbol });
  }
  return [...pairs.values()];
}

/**
 * Split a re-read result into the report's two lists.
 *
 * Permit2 grants are live only while unexpired: an expired grant is not exposure, and reporting
 * it as such would inflate both the report and the penalty `hygieneScore` derives from it.
 */
export function partitionLive(entries, { now = () => Date.now() } = {}) {
  const nowSec = Math.floor(now() / 1000);
  const erc20Live = [];
  const permit2Live = [];

  for (const entry of entries) {
    if (!entry || BigInt(entry.amount ?? 0) <= 0n) continue;
    if (entry.kind === "permit2") {
      if (Number(entry.expiration ?? 0) > nowSec) {
        permit2Live.push({ token: entry.token, symbol: entry.symbol, spender: entry.spender, amount: entry.amount, expiration: entry.expiration });
      }
      continue;
    }
    erc20Live.push({ token: entry.token, symbol: entry.symbol, spender: entry.spender, amount: entry.amount });
  }

  return { erc20Live, permit2Live };
}
