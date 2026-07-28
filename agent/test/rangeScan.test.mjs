import test from "node:test";
import assert from "node:assert/strict";

import { planWindows, isRateLimited, withRateLimitRetry, DEFAULT_MAX_LOG_RANGE } from "../lib/rangeScan.mjs";

test("a short range stays a single window", () => {
  const windows = planWindows(100n, 200n, 9500n);
  assert.deepEqual(windows, [{ fromBlock: 100n, toBlock: 200n }]);
});

test("windows are inclusive and never exceed the max range", () => {
  const windows = planWindows(1n, 25_000n, 9500n);
  assert.equal(windows.length, 3);
  for (const w of windows) {
    assert.ok(w.toBlock - w.fromBlock + 1n <= 9500n, `window ${w.fromBlock}-${w.toBlock} too wide`);
  }
});

test("windows are contiguous and cover the range exactly, with no gaps or overlaps", () => {
  const from = 49_009_690n;
  const to = 49_241_986n; // the real gap that broke the sentinel in production
  const windows = planWindows(from, to, DEFAULT_MAX_LOG_RANGE);

  assert.equal(windows[0].fromBlock, from);
  assert.equal(windows.at(-1).toBlock, to);
  for (let i = 1; i < windows.length; i++) {
    assert.equal(windows[i].fromBlock, windows[i - 1].toBlock + 1n, "windows must not gap or overlap");
  }
});

test("an exact multiple of the max range does not produce a trailing empty window", () => {
  const windows = planWindows(1n, 19_000n, 9500n);
  assert.equal(windows.length, 2);
  assert.deepEqual(windows.at(-1), { fromBlock: 9501n, toBlock: 19_000n });
});

test("a single-block range is one window", () => {
  assert.deepEqual(planWindows(500n, 500n, 9500n), [{ fromBlock: 500n, toBlock: 500n }]);
});

test("an empty range yields no windows rather than throwing", () => {
  // "no new blocks since the last run" is the normal case on a healthy short cycle.
  assert.deepEqual(planWindows(1000n, 999n, 9500n), []);
});

test("a non-positive max range is rejected instead of looping forever", () => {
  assert.throws(() => planWindows(1n, 10n, 0n), /must be positive/);
});

test("the default max range stays under Base's 10,000-block eth_getLogs cap", () => {
  assert.ok(DEFAULT_MAX_LOG_RANGE <= 10_000n);
  const widest = planWindows(1n, 1_000_000n, DEFAULT_MAX_LOG_RANGE)
    .reduce((max, w) => (w.toBlock - w.fromBlock + 1n > max ? w.toBlock - w.fromBlock + 1n : max), 0n);
  assert.ok(widest <= 10_000n, `widest window ${widest} would be rejected by the RPC`);
});

test("rate-limit errors are recognised by code and by message", () => {
  assert.ok(isRateLimited({ cause: { code: -32016 } }));
  assert.ok(isRateLimited({ details: "over rate limit" }));
  assert.ok(!isRateLimited({ cause: { code: -32614 }, details: "eth_getLogs is limited to a 10,000 range" }));
  assert.ok(!isRateLimited(new Error("boom")));
  assert.ok(!isRateLimited(undefined));
});

test("a rate-limited call is retried until it succeeds", async () => {
  let calls = 0;
  const result = await withRateLimitRetry(
    async () => {
      calls++;
      if (calls < 3) throw { cause: { code: -32016 } };
      return "ok";
    },
    "test",
    { sleep: async () => {}, log: () => {} }
  );

  assert.equal(result, "ok");
  assert.equal(calls, 3);
});

test("retries give up after the configured attempts and rethrow", async () => {
  let calls = 0;
  await assert.rejects(
    withRateLimitRetry(
      async () => {
        calls++;
        throw { cause: { code: -32016 } };
      },
      "test",
      { attempts: 4, sleep: async () => {}, log: () => {} }
    )
  );
  assert.equal(calls, 4);
});

test("a non-rate-limit error is not retried", async () => {
  // The original bug was a hard -32614 range error. Retrying that would have turned a
  // fast, loud failure into a slow one — it must propagate on the first attempt.
  let calls = 0;
  await assert.rejects(
    withRateLimitRetry(
      async () => {
        calls++;
        throw { cause: { code: -32614 }, details: "eth_getLogs is limited to a 10,000 range" };
      },
      "test",
      { sleep: async () => {}, log: () => {} }
    )
  );
  assert.equal(calls, 1);
});

test("backoff doubles between attempts", async () => {
  const waits = [];
  await assert.rejects(
    withRateLimitRetry(
      async () => {
        throw { cause: { code: -32016 } };
      },
      "test",
      { attempts: 4, baseDelayMs: 100, sleep: async (ms) => waits.push(ms), log: () => {} }
    )
  );
  assert.deepEqual(waits, [100, 200, 400]);
});
