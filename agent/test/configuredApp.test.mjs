// The single env-to-app wiring shared by server.mjs, api/index.js and app.mjs's default export.
//
// It exists so those three cannot configure the agent differently -- which is a claim about
// behaviour, and so testable. It went untested because it looks like glue; the July production
// incident where only `GET /` was broken came from exactly this layer, where a wrong shape
// reaches every route at once and nothing else can catch it.

import { test } from "node:test";
import assert from "node:assert/strict";

import { appConfigFromEnv, buildConfiguredApp } from "../lib/configuredApp.mjs";

/** Captures console output so a test asserting on startup warnings stays quiet itself. */
function captureConsole(fn) {
  const lines = { log: [], warn: [] };
  const realLog = console.log;
  const realWarn = console.warn;
  console.log = (...args) => lines.log.push(args.join(" "));
  console.warn = (...args) => lines.warn.push(args.join(" "));
  try {
    return { result: fn(), lines };
  } finally {
    console.log = realLog;
    console.warn = realWarn;
  }
}

test("reads the CDP credentials the payment middleware needs", () => {
  const config = appConfigFromEnv({ CDP_API_KEY_ID: "key-id", CDP_API_KEY_SECRET: "key-secret" });
  assert.deepEqual(config.cdp, { apiKeyId: "key-id", apiKeySecret: "key-secret" });
});

test("missing credentials come through as undefined, not as empty strings", () => {
  // resolveAuditMode distinguishes present from absent; "" would read as present and make the
  // agent believe it can collect payment.
  const config = appConfigFromEnv({});
  assert.equal(config.cdp.apiKeyId, undefined);
  assert.equal(config.cdp.apiKeySecret, undefined);
});

test("serving /audit for free requires exactly ALLOW_UNPAID_AUDIT=1", () => {
  // Deliberately strict: this flag gives the agent's paid product away, so anything other than
  // the documented value must leave payments on. "true" and "yes" are the plausible mistakes.
  assert.equal(appConfigFromEnv({ ALLOW_UNPAID_AUDIT: "1" }).allowUnpaidAudit, true);
  for (const value of ["0", "true", "yes", "", " 1", undefined]) {
    assert.equal(
      appConfigFromEnv({ ALLOW_UNPAID_AUDIT: value }).allowUnpaidAudit,
      false,
      `ALLOW_UNPAID_AUDIT=${JSON.stringify(value)} must not enable free audits`
    );
  }
});

test("hands makeApp a Base mainnet client plus the environment config", () => {
  let received;
  buildConfiguredApp((args) => {
    received = args;
    return "app";
  }, { env: { CDP_API_KEY_ID: "id", CDP_API_KEY_SECRET: "secret" } });

  assert.equal(received.client.chain.id, 8453, "the agent must be wired to Base mainnet");
  assert.deepEqual(received.cdp, { apiKeyId: "id", apiKeySecret: "secret" });
  assert.equal(received.allowUnpaidAudit, false);
});

test("returns whatever makeApp returns, unwrapped", () => {
  const app = { marker: Symbol("app") };
  assert.equal(buildConfiguredApp(() => app, { env: {} }), app);
});

test("stays silent when no audit-mode resolver is supplied", () => {
  // app.mjs's tests import makeApp directly and must not get startup noise; the default export
  // is lazy for the same reason. Silence here is what keeps that true.
  const { lines } = captureConsole(() => buildConfiguredApp(() => "app", { env: {} }));
  assert.deepEqual(lines.log, []);
  assert.deepEqual(lines.warn, []);
});

test("reports the resolved audit mode at startup, from the same config makeApp gets", () => {
  let seenByResolver;
  const { lines } = captureConsole(() =>
    buildConfiguredApp(() => "app", {
      env: { CDP_API_KEY_ID: "id", CDP_API_KEY_SECRET: "secret" },
      resolveAuditMode: (config) => {
        seenByResolver = config;
        return "paid";
      },
    })
  );

  assert.deepEqual(seenByResolver.cdp, { apiKeyId: "id", apiKeySecret: "secret" });
  assert.equal(lines.log.length, 1, "a paid deploy should log once, not warn");
  assert.match(lines.log[0], /payments enabled/);
});

test("an unconfigured deploy warns rather than logging", () => {
  const { lines } = captureConsole(() =>
    buildConfiguredApp(() => "app", { env: {}, resolveAuditMode: () => "unavailable" })
  );

  assert.deepEqual(lines.log, []);
  assert.equal(lines.warn.length, 1);
  assert.match(lines.warn[0], /DISABLED/);
});
