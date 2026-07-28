import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createNonceStore,
  createMemoryStore,
  createKvStore,
  NonceStoreUnavailable,
} from "../lib/nonceStore.mjs";

const FUTURE = Math.floor(Date.now() / 1000) + 300;

test("KV is selected when both connection variables are present", () => {
  const store = createNonceStore({ env: { KV_REST_API_URL: "https://kv", KV_REST_API_TOKEN: "t" } });
  assert.equal(store.kind, "kv");
});

test("a half-configured KV falls back to memory rather than failing every sign-in", () => {
  assert.equal(createNonceStore({ env: { KV_REST_API_URL: "https://kv" } }).kind, "memory");
  assert.equal(createNonceStore({ env: { KV_REST_API_TOKEN: "t" } }).kind, "memory");
  assert.equal(createNonceStore({ env: {} }).kind, "memory");
});

test("memory store claims a nonce once", async () => {
  const store = createMemoryStore();
  assert.equal(await store.claim("abc", FUTURE), true);
  assert.equal(await store.claim("abc", FUTURE), false);
});

test("memory store forgets expired entries instead of growing forever", async () => {
  let clock = 1_000_000_000_000;
  const store = createMemoryStore({ now: () => clock });

  const expiresAt = Math.floor(clock / 1000) + 60;
  assert.equal(await store.claim("abc", expiresAt), true);
  assert.equal(await store.claim("abc", expiresAt), false, "still remembered before expiry");

  clock += 61_000;
  // Once expired the entry is pruned, so the nonce is claimable again — harmless, because
  // checkNonce rejects it on expiry before the store is ever consulted.
  assert.equal(await store.claim("abc", expiresAt), true);
});

function kvStub(responses) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return next;
  };
  return { fetchImpl, calls };
}

function ok(result) {
  return { ok: true, status: 200, json: async () => ({ result }) };
}

test("KV claim issues an atomic SET NX EXAT and reads OK as a win", async () => {
  const { fetchImpl, calls } = kvStub([ok("OK")]);
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });

  assert.equal(await store.claim("abc", 1234), true);
  assert.deepEqual(calls[0].body, ["SET", "kokosh:nonce:abc", "1", "NX", "EXAT", "1234"]);
});

test("KV treats a null result as already spent", async () => {
  // Upstash answers {"result":null} when NX found the key present.
  const { fetchImpl } = kvStub([ok(null)]);
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });
  assert.equal(await store.claim("abc", 1234), false);
});

test("KV sends its bearer token", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push(init.headers.authorization);
    return ok("OK");
  };
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });
  await store.claim("abc", 1234);
  assert.equal(calls[0], "Bearer tok");
});

test("a transport failure raises NonceStoreUnavailable rather than looking like a fresh nonce", async () => {
  // The dangerous bug would be returning true here: an unreachable store would silently
  // re-enable replay.
  const { fetchImpl } = kvStub([new Error("ECONNRESET")]);
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });
  await assert.rejects(store.claim("abc", 1234), NonceStoreUnavailable);
});

test("an HTTP error raises NonceStoreUnavailable", async () => {
  const fetchImpl = async () => ({ ok: false, status: 500, json: async () => ({}) });
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });
  await assert.rejects(store.claim("abc", 1234), NonceStoreUnavailable);
});

test("an unparseable body is treated as not-claimed, never as a win", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new Error("not json");
    },
  });
  const store = createKvStore({ url: "https://kv", token: "tok", fetchImpl });
  assert.equal(await store.claim("abc", 1234), false);
});
