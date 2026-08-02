import { test } from "node:test";
import assert from "node:assert/strict";

import { describeInheritedExposure } from "../lib/inheritedExposure.mjs";

const WETH = "0x4200000000000000000000000000000000000006";
const AAVE_POOL = "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5";

const snapshot = (erc20Live = [], permit2Live = []) => ({ erc20Live, permit2Live });

test("an allowance the sentinel never recorded is reported as inherited", () => {
  // The real one: live in the snapshot, absent from a baseline that has only ever scanned
  // forward, and therefore invisible to every future cycle as well.
  const result = describeInheritedExposure(
    snapshot([{ token: WETH, symbol: "WETH", spender: AAVE_POOL, amount: "19999985165190" }]),
    { alertedApprovals: [] }
  );

  assert.equal(result.live, 1);
  assert.equal(result.monitored, 0);
  assert.equal(result.inheritedCount, 1);
  assert.equal(result.inherited[0].symbol, "WETH");
  assert.equal(result.inherited[0].kind, "erc20");
});

test("an allowance the sentinel has recorded is counted as monitored", () => {
  const result = describeInheritedExposure(snapshot([{ token: WETH, spender: AAVE_POOL, amount: "1" }]), {
    alertedApprovals: [`erc20:${WETH}:${AAVE_POOL}`],
  });

  assert.equal(result.monitored, 1);
  assert.equal(result.inheritedCount, 0);
  assert.deepEqual(result.inherited, []);
});

test("key matching folds case, since the two sides come from different sources", () => {
  // The snapshot carries checksummed addresses from Blockscout; the state file carries whatever
  // the sentinel wrote. A case difference here would report monitored exposure as inherited.
  const result = describeInheritedExposure(snapshot([{ token: WETH.toUpperCase(), spender: AAVE_POOL, amount: "1" }]), {
    alertedApprovals: [`erc20:${WETH.toLowerCase()}:${AAVE_POOL.toLowerCase()}`],
  });

  assert.equal(result.inheritedCount, 0);
});

test("Permit2 grants are keyed apart from ERC-20 allowances", () => {
  // Same token and spender, different mechanism: knowing about one says nothing about the other.
  const result = describeInheritedExposure(snapshot([], [{ token: WETH, spender: AAVE_POOL, amount: "5" }]), {
    alertedApprovals: [`erc20:${WETH}:${AAVE_POOL}`],
  });

  assert.equal(result.inheritedCount, 1);
  assert.equal(result.inherited[0].kind, "permit2");
});

test("both kinds are counted together", () => {
  const result = describeInheritedExposure(
    snapshot([{ token: WETH, spender: AAVE_POOL, amount: "1" }], [{ token: "0xabc", spender: "0xdef", amount: "2" }]),
    { alertedApprovals: [] }
  );

  assert.equal(result.live, 2);
  assert.equal(result.inheritedCount, 2);
});

test("no snapshot is absence of data, not a finding of zero", () => {
  // Reporting inheritedCount: 0 here would read as "nothing inherited" when the truth is
  // "nothing scanned" -- the same conflation /exposure had to learn to stop making.
  assert.equal(describeInheritedExposure(null, { alertedApprovals: [] }), null);
});

test("a missing or empty state file means nothing is monitored yet", () => {
  const report = snapshot([{ token: WETH, spender: AAVE_POOL, amount: "1" }]);
  for (const state of [null, undefined, {}, { alertedApprovals: undefined }]) {
    assert.equal(describeInheritedExposure(report, state).inheritedCount, 1);
  }
});

test("an empty snapshot reports zero without inventing entries", () => {
  const result = describeInheritedExposure(snapshot(), { alertedApprovals: [] });
  assert.deepEqual(result, { live: 0, monitored: 0, inheritedCount: 0, inherited: [] });
});
