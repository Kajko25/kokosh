import { test } from "node:test";
import assert from "node:assert/strict";
import { failure, describeErrorForLog } from "../lib/httpError.mjs";

function fakeRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

test("the client gets a stable code, never the library's message", () => {
  const res = fakeRes();
  const logged = [];
  const err = new Error("connect ECONNREFUSED 10.0.0.5:8545 while calling https://internal/rpc");

  failure(res, { status: 502, code: "holdings_unavailable", error: err, log: (m) => logged.push(m) });

  assert.equal(res.statusCode, 502);
  assert.deepEqual(res.body, { error: "holdings_unavailable" });
  assert.equal(JSON.stringify(res.body).includes("10.0.0.5"), false, "internal detail must not reach the caller");
});

test("the operator gets the detail in the log, keyed by the same code", () => {
  const res = fakeRes();
  const logged = [];
  failure(res, { status: 502, code: "audit_unavailable", error: new Error("upstream exploded"), log: (m) => logged.push(m) });

  assert.equal(logged.length, 1);
  assert.match(logged[0], /\[audit_unavailable\]/);
  assert.match(logged[0], /upstream exploded/);
});

test("extra fields are merged but cannot overwrite the error code", () => {
  const res = fakeRes();
  failure(res, {
    status: 503,
    code: "rpc_unreachable",
    error: new Error("x"),
    extra: { status: "unreachable", error: "spoofed" },
    log: () => {},
  });

  assert.equal(res.body.status, "unreachable");
  assert.equal(res.body.error, "rpc_unreachable");
});

test("viem's shortMessage is preferred over the full dump", () => {
  const viemish = { shortMessage: "HTTP request failed.", message: "HTTP request failed.\n\nURL: ...\nDetails: ...\n" };
  assert.equal(describeErrorForLog(viemish), "HTTP request failed.");
});

test("non-Error throws are still describable", () => {
  assert.equal(describeErrorForLog("just a string"), "just a string");
  assert.equal(describeErrorForLog(undefined), "no error object");
  assert.equal(describeErrorForLog(null), "no error object");
});
