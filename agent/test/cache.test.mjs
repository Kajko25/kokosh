import { test } from "node:test";
import assert from "node:assert/strict";
import { createTtlCache } from "../lib/cache.mjs";

test("the first call produces a value and the second is served from cache", async () => {
  let calls = 0;
  const cache = createTtlCache({ ttlMs: 1000, now: () => 0 });
  const produce = async () => ++calls;

  assert.equal(await cache.get(produce), 1);
  assert.equal(await cache.get(produce), 1);
  assert.equal(calls, 1);
});

test("the value is produced again once the TTL elapses", async () => {
  let clock = 0;
  let calls = 0;
  const cache = createTtlCache({ ttlMs: 1000, now: () => clock });
  const produce = async () => ++calls;

  await cache.get(produce);
  clock = 1001;
  assert.equal(await cache.get(produce), 2);
});

test("concurrent callers on a cold cache share one upstream call", async () => {
  // Without single-flight, N simultaneous requests each start their own three-request
  // pagination walk — the exact load this cache exists to avoid.
  let calls = 0;
  let release;
  const gate = new Promise((r) => (release = r));
  const cache = createTtlCache({ ttlMs: 1000, now: () => 0 });

  const produce = async () => {
    calls++;
    await gate;
    return "value";
  };

  const all = Promise.all([cache.get(produce), cache.get(produce), cache.get(produce)]);
  release();

  assert.deepEqual(await all, ["value", "value", "value"]);
  assert.equal(calls, 1);
});

test("a failed production is not cached and is retried next time", async () => {
  let calls = 0;
  const cache = createTtlCache({ ttlMs: 10_000, now: () => 0 });
  const produce = async () => {
    calls++;
    if (calls === 1) throw new Error("upstream down");
    return "recovered";
  };

  await assert.rejects(cache.get(produce), /upstream down/);
  assert.equal(await cache.get(produce), "recovered", "a transient outage must not poison the cache");
  assert.equal(calls, 2);
});

test("a rejection reaches every concurrent caller", async () => {
  const cache = createTtlCache({ ttlMs: 1000, now: () => 0 });
  const produce = async () => {
    throw new Error("boom");
  };

  const results = await Promise.allSettled([cache.get(produce), cache.get(produce)]);
  assert.deepEqual(results.map((r) => r.status), ["rejected", "rejected"]);
});

test("invalidate forces the next call to produce again", async () => {
  let calls = 0;
  const cache = createTtlCache({ ttlMs: 10_000, now: () => 0 });
  const produce = async () => ++calls;

  await cache.get(produce);
  assert.equal(cache.isFresh, true);

  cache.invalidate();
  assert.equal(cache.isFresh, false);
  assert.equal(await cache.get(produce), 2);
});
