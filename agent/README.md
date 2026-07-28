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
| `lib/app.mjs` | `makeApp({ client, now, cdp })` factory — all routes, no I/O bindings of its own |
| `server.mjs` | local entry point (`npm start`, port 3000) |
| `api/index.js` | Vercel entry point; `vercel.json` rewrites every path to it |
| `lib/scamHeuristics.mjs` | `classifyToken()` — the airdrop-scam rules |
| `lib/blockscout.mjs` | ERC-20 holdings via Blockscout v2, paginated |
| `lib/exposure.mjs` | reads the committed approval snapshot |
| `lib/x402Seller.mjs` | x402 payment middleware for `/audit` |
| `lib/payValidate.mjs` | Base Pay `dataCallback` payer-info validation |
| `lib/siwb.mjs` | Sign In With Base nonce issue + signature verification |
| `lib/rangeScan.mjs` | block-range windowing and rate-limit retry for the sentinel |
| `lib/freshness.mjs` | snapshot age / staleness reporting |
| `lib/httpError.mjs` | error envelope: stable code to the client, detail to the log |
| `lib/nonceStore.mjs` | single-use nonce claims (Vercel KV or memory) |
| `lib/signInRequest.mjs` | request-shape validation for `/auth/verify` |
| `lib/rateLimit.mjs` | fixed-window rate limiting for the sign-in endpoints |
| `lib/cache.mjs` | single-flight TTL cache for upstream holdings reads |
| `lib/sentinelState.mjs` | validation for the sentinel's state file |
| `scripts/sentinel-run.mjs` | the autonomous check (see [Sentinel](#sentinel)) |
| `scripts/sentinel-cron.sh` | jitter / stand-down / daily-cap wrapper around it |
| `scripts/pay-audit.mjs` | x402 *buyer* — pays another service, proving the other side of the flow |

The app factory takes its viem client as an argument rather than constructing one, which is
what lets `test/app.test.mjs` drive every route against a stub with no network.

## Security headers

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and
`Referrer-Policy: strict-origin-when-cross-origin`, plus the
`Cross-Origin-Opener-Policy: same-origin-allow-popups` the Base Account popup flows need.
These matter here because `public/` serves real wallet sign-in and payment pages, not just
JSON.

They are set **twice, on purpose**: in the Express middleware for function responses, and in
`vercel.json` for everything Vercel's CDN serves directly. The static pages never reach
Express in production — verified by their `x-vercel-cache: HIT` and the absence of the
Express-set headers — so middleware alone protected exactly the responses that needed it
least.

**No Content-Security-Policy, deliberately.** Those pages import the Base Account SDK and viem
from esm.sh and hand off to Coinbase-hosted signing, so a correct policy has to be verified in
a real browser against a real wallet flow. This environment has no headless browser, and an
unverified CSP would risk breaking sign-in flows that are known to work. Recorded as a known
gap rather than guessed at.

## HTTP API

### `GET /`

Describes the agent: name, description, a pointer to the agent card, the endpoint map, the
browser pages under `public/`, and the source repository. Previously this answered Express's
default `Cannot GET /` HTML page — and 500 in production, where the payment middleware is
mounted. Unmatched routes now answer `404 {"error":"not_found"}` as JSON rather than an HTML
error page that echoes the requested path back.

### `GET /healthz`

Liveness plus a freshness check on the RPC connection. Reads the latest block and compares its
timestamp to now.

- `200 {"status":"ok","lagSeconds":N,"blockNumber":"...","config":{...}}`
- `503 {"status":"degraded",...}` when `lagSeconds > 60` — a reachable but stale node is a real
  failure mode for a monitor, so it is not reported as healthy
- `503 {"status":"unreachable","error":"rpc_unreachable"}` when the call throws

`config` reports the modes actually in force — `audit` (`paid` / `unpaid` / `unavailable`) and
`nonceStore` (`kv` / `memory`). Both are things that previously degraded silently when an env
var was missing, so they are observable from outside rather than only in a startup log.

### `GET /exposure`

Live approval exposure for the wallet.

- `200` with `liveErc20Approvals`, `livePermit2Grants`, the full `approvals` /
  `permit2Grants` arrays, and freshness fields `scannedAt`, `ageSeconds`, `stale`
- `202 {"status":"not_scanned_yet"}` when no snapshot exists

**Caveat, by design:** this serves `docs/approvals-report.json`, a snapshot committed to the
repo by `scripts/scan-approvals.mjs` — it is not scanned per request. Because that scan is a
manual step, the response states its own age: `ageSeconds`, plus `stale: true` once the
snapshot is over a day old. A missing or unparseable timestamp also reports `stale: true` —
failing towards "trust this data" would be the wrong default for an exposure report. Cached 5
minutes.

### `GET /drops`

Scam-airdrop scan, computed live per request from Blockscout holdings. Holdings are fetched
across **all** pages — Blockscout returns 50 per request and this wallet holds ~150, so a
single-page fetch silently scanned a third of them.

- `200` with `scannedTokens`, `flaggedCount`, and `flagged[]` (each with `address`, `name`,
  `symbol`, `reasons`)
- `502 {"error":"holdings_unavailable"}` when Blockscout is unreachable — an upstream failure
  is surfaced, not silently reported as "nothing flagged"

Cached 30 minutes at the HTTP layer, and the underlying holdings fetch is cached in-process
for 60s and shared with `/audit` — following pagination made one fetch three Blockscout
requests, and cache-control headers only help callers that honour them.

### `GET /audit` — paid

The combined report: exposure + scam scan + a `hygieneScore`.

```
hygieneScore = max(0, 100 - liveApprovals * 5 - flaggedTokens * 2)
```

Priced at **$0.01 USDC on Base** (`eip155:8453`, x402 `exact` scheme), paid to the courier
agent wallet `0xf2035170A3B5106DBD4c98853D3C9E52c77eA4E6` — deliberately not the Ledger-held
main wallet, so receiving payments never needs hardware present.

**Payment configuration is fail-closed.** `/audit` has three modes, resolved at startup by
`resolveAuditMode()`:

| Mode | When | Behaviour |
| --- | --- | --- |
| `paid` | both `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` set | x402 middleware charges $0.01 |
| `unpaid` | no keys **and** `ALLOW_UNPAID_AUDIT=1` | served free, deliberately |
| `unavailable` | no keys, no opt-in (**default**) | `503 {"error":"payment_not_configured"}` |

A half-configured credential (only one of the two keys) counts as *not* configured. The mode is
logged at startup — a warning for the two non-paying modes — and the agent card advertises the
real mode rather than always claiming the endpoint is paid.

The default matters: an earlier version simply skipped the payment middleware when keys were
missing, so a production deploy with a typo'd env var served the paid report free with no error
anywhere. Serving nothing is a louder, safer failure than silently giving away the agent's only
revenue path. Local development that genuinely wants the free report opts in explicitly.

### `GET /.well-known/agent-card.json`

Agent card — name, description, wallet, endpoint map, plus:

- `registrations`: the ERC-8004 identity (`agentId` 59633 on chain 8453), so a consumer can
  verify the agent on-chain instead of trusting this file
- `payment`: the exact x402 terms for `/audit` (scheme, price, network, payee), taken from the
  same constants the middleware charges with so the two cannot drift apart. It is `null`
  whenever the endpoint is not actually paid — advertising a price for a free or disabled
  endpoint would send a paying agent to construct a payment nothing will accept

Cached 5 minutes.

### `GET /auth/nonce` and `POST /auth/verify`

Sign In With Base. `/auth/nonce` issues a single-use nonce; `/auth/verify` takes
`{address, message, signature}`, checks the nonce is known and unused, consumes it, then
verifies the signature with viem's `verifyMessage` (which handles ERC-6492 for smart accounts
that are not yet deployed).

- `200 {"ok":true,"address":"0x..."}`
- `400` with `missing_fields`, `invalid_field_types`, `invalid_address`, `message_too_large`,
  or `invalid_signature_encoding` — request shape is validated before anything reaches the
  nonce regex or an RPC call
- `401` with `missing_nonce`, `malformed_nonce`, `invalid_nonce_signature`, `expired_nonce`,
  `nonce_already_used`, or `invalid_signature`
- `503 {"error":"nonce_store_unavailable"}` — a store outage is a server failure, not a
  rejected credential, so it must not be reported to an honest client as a bad signature

Both sign-in endpoints share one rate-limit budget (default 30 requests/minute per client),
returning `429 {"error":"rate_limited"}` with a `Retry-After` header. `/auth/verify` costs an
RPC call and a KV write per request with no credential required, so it should not be freely
amplifiable. The limiter is per-instance and in-memory: on serverless the effective ceiling is
limit x instances, which bounds obvious abuse without adding a shared-counter round trip to
every request — the very cost being defended against. It gates cost, never authorisation.

**Nonces are stateless.** Each one is `<16 hex random><8 hex expiry><32 hex HMAC>` — 56
alphanumeric characters, as SIWE requires — signed with `SIWB_NONCE_SECRET`. Any instance
holding that secret can validate a nonce any other instance issued, which is what makes
sign-in work on a serverless runtime at all. An invalid nonce short-circuits before the
signature check, so a forged one never costs an RPC call. A failed signature does **not**
consume the nonce, so a bad submission can't burn someone else's in-flight sign-in.

| Env var | Default | Purpose |
| --- | --- | --- |
| `SIWB_NONCE_SECRET` | per-process random | HMAC key; **must be shared** across instances |
| `SIWB_NONCE_TTL` | `300` | nonce lifetime in seconds |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | unset | Vercel KV, for cross-instance single use |

Without `SIWB_NONCE_SECRET` the module generates a per-process secret and warns loudly at
startup — that reproduces the old instance-affinity failure, so it is a development
convenience, not a deployment option.

**Single use is enforced through a store** (`lib/nonceStore.mjs`). With Vercel KV configured the
claim is a single atomic `SET <nonce> 1 NX EXAT <expiry>`: exactly one caller can win even if two
requests race, the key expires with the nonce so nothing accumulates, and every instance sees the
same answer. Without KV it falls back to a per-process map, which still blocks replay on the
instance that handled the sign-in but cannot see what other instances have spent.

If the store is configured but unreachable, sign-in **fails closed** (`nonce_store_unavailable`).
Returning "not yet used" on a store error would silently re-enable exactly the replay the store
exists to prevent. A half-configured KV (one of the two variables) falls back to memory rather
than failing every sign-in.

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
| `name_or_symbol_contains_bare_domain` | a scheme-less host on a lure TLD (`t.me`, `t.ly`, `PPBox.io`) |
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

The app itself reads `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` and `ALLOW_UNPAID_AUDIT` — see
[`GET /audit`](#get-audit--paid).

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

All environment variables are documented in [`.env.example`](.env.example) — copy it to
`.env.local` to get started. Every one is optional; what changes is which degraded mode you
land in, and each is reported at startup and on `/healthz`.

```bash
cd agent
cp .env.example .env.local
npm install
npm start                 # http://localhost:3000
npm test                  # node --test, no network required
```

Tests cover the routes (against a stubbed client), the payer-info validator, the scam
heuristics including the impersonation regression above, and the sentinel's range/retry logic.
