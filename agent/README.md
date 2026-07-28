# Kokosh — agent

Wallet-hygiene sentinel for `0x2984Bb4953cfCE2cEc957388BE686D6c38779234` (**kajko24.base.eth**).

Kokosh answers one question: *what is this wallet currently exposed to?* It tracks live ERC-20
and Permit2 allowances, flags scam-airdrop tokens sitting in the wallet, and sells the combined
report as a paid endpoint over x402. A cron-driven sentinel re-checks the same ground on a
schedule and attests on-chain when — and only when — something genuinely changed.

- Live: https://kokosh-agent.vercel.app
- Agent card: https://kokosh-agent.vercel.app/.well-known/agent-card.json
- ERC-8004 identity: agentId `59633` on the Base mainnet Identity Registry
- Transaction attribution (ERC-8021 builder code) is a separate concern — see [AGENT_README.md](AGENT_README.md)

## Layout

| Path | Role |
| --- | --- |
| `app.mjs` | `makeApp({ client, now, cdp })` factory — all routes, no I/O bindings of its own |
| `server.mjs` | local entry point (`npm start`, port 3000) |
| `api/index.js` | Vercel entry point; `vercel.json` rewrites every path to it |
| `lib/scamHeuristics.mjs` | `classifyToken()` — the airdrop-scam rules |
| `lib/blockscout.mjs` | ERC-20 holdings via Blockscout v2 |
| `lib/exposure.mjs` | reads the committed approval snapshot |
| `lib/x402Seller.mjs` | x402 payment middleware for `/audit` |
| `lib/payValidate.mjs` | Base Pay `dataCallback` payer-info validation |
| `lib/siwb.mjs` | Sign In With Base nonce issue + signature verification |
| `lib/rangeScan.mjs` | block-range windowing and rate-limit retry for the sentinel |
| `scripts/sentinel-run.mjs` | the autonomous check (see [Sentinel](#sentinel)) |
| `scripts/sentinel-cron.sh` | jitter / stand-down / daily-cap wrapper around it |
| `scripts/pay-audit.mjs` | x402 *buyer* — pays another service, proving the other side of the flow |

The app factory takes its viem client as an argument rather than constructing one, which is
what lets `test/app.test.mjs` drive every route against a stub with no network.

## HTTP API

### `GET /healthz`

Liveness plus a freshness check on the RPC connection. Reads the latest block and compares its
timestamp to now.

- `200 {"status":"ok","lagSeconds":N,"blockNumber":"..."}`
- `503 {"status":"degraded",...}` when `lagSeconds > 60` — a reachable but stale node is a real
  failure mode for a monitor, so it is not reported as healthy
- `503 {"status":"unreachable","error":"..."}` when the call throws

### `GET /exposure`

Live approval exposure for the wallet.

- `200` with `liveErc20Approvals`, `livePermit2Grants`, and the full `approvals` / `permit2Grants` arrays
- `202 {"status":"not_scanned_yet"}` when no snapshot exists

**Caveat, by design:** this serves `docs/approvals-report.json`, a snapshot committed to the
repo by `scripts/scan-approvals.mjs` — it is not scanned per request. `scannedAt` in the
response is the honest timestamp. For a fresh answer, re-run the scanner. Cached 5 minutes.

### `GET /drops`

Scam-airdrop scan, computed live per request from Blockscout holdings.

- `200` with `scannedTokens`, `flaggedCount`, and `flagged[]` (each with `address`, `name`,
  `symbol`, `reasons`)
- `502` when Blockscout is unreachable — an upstream failure is surfaced, not silently
  reported as "nothing flagged"

Cached 30 minutes.

### `GET /audit` — paid

The combined report: exposure + scam scan + a `hygieneScore`.

```
hygieneScore = max(0, 100 - liveApprovals * 5 - flaggedTokens * 2)
```

Priced at **$0.01 USDC on Base** (`eip155:8453`, x402 `exact` scheme), paid to the courier
agent wallet `0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6` — deliberately not the Ledger-held
main wallet, so receiving payments never needs hardware present.

**Deployment caveat:** the payment middleware is only mounted when *both* `CDP_API_KEY_ID` and
`CDP_API_KEY_SECRET` are set. Without them the app still starts and `/audit` is served **free**.
That keeps local development and tests running without CDP credentials, but it means a
production deploy missing those env vars silently gives the report away.

### `GET /.well-known/agent-card.json`

Static agent card — name, description, wallet, endpoint map. Cached 5 minutes.

### `GET /auth/nonce` and `POST /auth/verify`

Sign In With Base. `/auth/nonce` issues a single-use nonce; `/auth/verify` takes
`{address, message, signature}`, checks the nonce is known and unused, consumes it, then
verifies the signature with viem's `verifyMessage` (which handles ERC-6492 for smart accounts
that are not yet deployed).

- `200 {"ok":true,"address":"0x..."}`
- `401` on `invalid_or_reused_nonce` or `invalid_signature`
- `400 {"error":"missing_fields"}`

**Caveat:** nonces live in an in-process `Set`. On Vercel's serverless runtime a verify request
can land on a different instance than the one that issued the nonce, in which case it fails
closed (rejected as unknown) rather than open. Fine for a demo; a shared store is required
before this is load-bearing.

### `POST /pay/validate`

Base Pay data-callback validation — checks the payer info (currently the email) and echoes the
request back on success, or returns `{errors:{email:...}}` for Base Pay to render.

The payload shape here was determined from a live call, not the docs: `requestedInfo` is
**top-level on the body**, not nested under `requestData.capabilities.dataCallback`. That
discrepancy was reported upstream as [base/docs#1730](https://github.com/base/docs/issues/1730).

## Scam heuristics

`classifyToken({name, symbol, address})` returns `{suspicious, reasons[]}`. A token is flagged if
any rule fires:

| Reason | Rule |
| --- | --- |
| `name_or_symbol_contains_url` | name or symbol embeds a URL (`https://…`, `www.…`) |
| `urgency_language` | name matches `claim` / `until` / `expires` / `visit` / `airdrop` |
| `non_latin_homoglyph` | name or symbol contains Cyrillic or Greek confusables |
| `impersonates_<TICKER>` | symbol matches a known ticker but the contract is **not** its canonical address |

The last rule exists because of a real false negative. An earlier version compared strings only
and required the symbol to *differ* from the known ticker before flagging — so an exact copy,
the simplest and most common impersonation, was the one case guaranteed to slip through. A
token at `0x9053A44f…` presenting as `AAVE` with a 2.1B supply (real AAVE: ~16M) was sitting
unflagged in the wallet. The check is now address-based against `KNOWN_TICKER_ADDRESSES`.

Adding a ticker to that map is the intended way to extend coverage.

## Sentinel

`scripts/sentinel-run.mjs` is the autonomous half: an incremental re-scan that only speaks up
when something is genuinely new. It reads `docs/sentinel-state.json`, scans from
`lastScannedBlock + 1` to the current tip for new `Approval` events (ERC-20 and Permit2),
checks which of the resulting pairs still have a live allowance, re-runs the scam classifier
over current holdings, and diffs both against what it already knew.

- **No findings → no attestation.** It logs a stand-down and advances the state file. This is a
  real check, not a heartbeat.
- **New findings →** the courier wallet submits an EAS attestation under schema
  `SentinelCheck(address wallet, uint64 checkedAt, uint16 newFindings, string summary)`
  (`0x37419361…97e93032`).

**What it structurally cannot do:** revoke. Only `0x2984` can call `approve()` on its own
allowances, and that wallet signs exclusively via Ledger — so an unattended cron can report a
newly-discovered live approval but never fix it. The script says so explicitly in its output
rather than implying otherwise. The courier wallet can act autonomously, which is why the
attestation (not the revoke) is the agent's action.

### Running it

```bash
cd agent
DRY_RUN=1 node scripts/sentinel-run.mjs   # full scan, no attestation, no state write
node scripts/sentinel-run.mjs             # real run
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `DRY_RUN` | unset | `1` = scan only; skip the attestation and leave the state file untouched |
| `MAX_LOG_RANGE` | `9500` | blocks per `eth_getLogs` window |
| `WINDOW_DELAY_MS` | `250` | pause between windows |

`MAX_LOG_RANGE` must stay under **10,000** — Base's RPC rejects wider ranges with `-32614`.
Since Base produces roughly 43,000 blocks a day, the range walk is not an optimisation: an
unchunked scan fails outright on any gap longer than a few hours. Rate-limit errors (`-32016`)
are retried with doubling backoff; every other error propagates immediately, so a real bug
stays a fast, loud failure. See `lib/rangeScan.mjs` and `test/rangeScan.test.mjs`.

### Scheduling

`scripts/sentinel-cron.sh` wraps the run with jitter (`MAX_JITTER_SECONDS`, default 45 min), a
per-cycle stand-down probability (`STAND_DOWN_PCT`, default 40), and a hard daily action cap
(`MAX_ACTIONS_PER_DAY`, default 2) so the schedule doesn't read as a fixed-cadence bot.

Reading its log: a healthy cycle ends with `run finished cleanly`, a failed one with
`sentinel-run FAILED (exit N)`. A cycle that stops right after `sleeping Ns of jitter` and never
reaches `jitter complete, starting scan` was killed mid-sleep — the process died, the scan
never started.

## Development

```bash
cd agent
npm install
npm start                 # http://localhost:3000
npm test                  # node --test, no network required
```

Tests cover the routes (against a stubbed client), the payer-info validator, the scam
heuristics including the impersonation regression above, and the sentinel's range/retry logic.
