// Range-walking and rate-limit handling for the sentinel's log scan.
//
// This lives in lib/ rather than inline in scripts/sentinel-run.mjs specifically so it can
// be tested without a live RPC client. Both behaviours here were written in response to real
// production failures that went undetected for days:
//
//   - Base rejects any eth_getLogs spanning more than 10,000 blocks (-32614), and Base
//     produces ~43,000 blocks/day, so an unchunked incremental scan fails on any run that
//     isn't nearly back-to-back with the previous one.
//   - Walking a long range means dozens of sequential calls, and the public RPC starts
//     answering -32016 "over rate limit" well before that finishes.

export const DEFAULT_MAX_LOG_RANGE = 9500n;

/**
 * Split an inclusive block range into windows no larger than `maxRange`.
 * Returns [] when the range is empty (fromBlock > toBlock), so callers can treat
 * "nothing new since last run" as a normal no-op rather than a special case.
 */
export function planWindows(fromBlock, toBlock, maxRange = DEFAULT_MAX_LOG_RANGE) {
  const from = BigInt(fromBlock);
  const to = BigInt(toBlock);
  const max = BigInt(maxRange);

  if (max <= 0n) throw new Error(`maxRange must be positive, got ${maxRange}`);
  if (from > to) return [];

  const windows = [];
  for (let start = from; start <= to; start += max) {
    const last = start + max - 1n;
    windows.push({ fromBlock: start, toBlock: last > to ? to : last });
  }
  return windows;
}

/** True for the RPC errors that are worth retrying rather than failing the run. */
export function isRateLimited(err) {
  return err?.cause?.code === -32016 || /over rate limit/i.test(err?.details ?? "");
}

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Retry `fn` on rate-limit errors with doubling backoff. Anything else rethrows
 * immediately — a genuine bug must not be retried into looking like a slow success.
 * `sleep`/`log` are injectable so tests run instantly and silently.
 */
export async function withRateLimitRetry(fn, label, options = {}) {
  const { attempts = 5, baseDelayMs = 2000, sleep = defaultSleep, log = console.log } = options;

  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (!isRateLimited(err) || attempt >= attempts - 1) throw err;
      const wait = baseDelayMs * 2 ** attempt;
      log(`rate limited on ${label}, retrying in ${wait}ms (attempt ${attempt + 1}/${attempts})`);
      await sleep(wait);
    }
  }
}
