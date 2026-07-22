import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePayerInfo } from "../lib/payValidate.mjs";

test("accepts a valid email", () => {
  const body = {
    calls: [{ to: "0x0", data: "0x", value: "0x0" }],
    capabilities: { dataCallback: { callbackURL: "https://x", requests: [{ type: "email", optional: false }] } },
    chainId: "0x2105",
    requestedInfo: { email: "a@b.com" },
  };
  const { ok, response } = validatePayerInfo(body);
  assert.equal(ok, true);
  assert.deepEqual(response.request, body);
});

test("rejects an invalid email", () => {
  const body = { requestedInfo: { email: "not-an-email" } };
  const { ok, response } = validatePayerInfo(body);
  assert.equal(ok, false);
  assert.ok(response.errors.email);
});

test("rejects missing requestedInfo", () => {
  const { ok } = validatePayerInfo({});
  assert.equal(ok, false);
});
