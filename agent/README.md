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
| `app.mjs` | `makeApp({ client, now, cdp, holdings })` factory — all routes, no I/O bindings of its own. Stays at the package root because Vercel's Node builder picks its entrypoint by finding the root file that imports express |
| `server.mjs` | local entry point (`npm start`, port 3000) |
| `api/index.js` | Vercel entry point; `vercel.json` rewrites every path to it |
| `lib/scamHeuristics.mjs` | `classifyToken()` — the airdrop-scam rules |
| `lib/blockscout.mjs` | holdings via Blockscout v2, paginated: `fetchTokenHoldings` (ERC-20) and `fetchNftHoldings` (ERC-721 + ERC-1155, folded per collection) |
| `lib/exposure.mjs` | reads the committed approval snapshot from `data/` |
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
| `lib/hygieneScore.mjs` | the score `/audit` sells — weights, version, breakdown |
| `lib/tokenFindings.mjs` | decides which flagged tokens are *new*; re-baselines when the ruleset changed |
| `lib/sentinelReport.mjs` | reads the sentinel's state for `/sentinel` — age, overdue, detector match |
| `scripts/sentinel-run.mjs` | the autonomous check (see [Sentinel](#sentinel)) |
| `scripts/sentinel-cron.sh` | jitter / stand-down / daily-cap wrapper around it |
| `scripts/sentinel-heartbeat.sh` | publishes each cycle's outcome to the `sentinel-heartbeat` branch |
| `scripts/pay-audit.mjs` | x402 *buyer* — pays another service, proving the other side of the flow |
| `scripts/calibrate-heuristics.mjs` | runs the rules over live holdings and prints what fired — how rule changes are judged |
| `data/approvals-report.json` | committed approval snapshot served by `/exposure` |
| `data/sentinel-state.json` | the sentinel's baseline and last-run record, served by `/sentinel` |

The app factory takes its viem client *and* its holdings readers as arguments rather than
constructing them, which is what lets `test/app.test.mjs` drive every route against stubs with
no network. Both `data/` files live inside the agent package on purpose: `agent/` is the Vercel
project root, so anything above it is never deployed — the approval snapshot spent weeks
answering "not scanned yet" in production for exactly that reason.

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

**The CSP is report-only, deliberately.** Those pages import the Base Account SDK and viem from
esm.sh and hand off to Coinbase-hosted signing, so an enforcing policy has to be verified in a
real browser against a real wallet flow — and this environment has no headless browser. Rather
than leave the gap open indefinitely, the policy ships as
`Content-Security-Policy-Report-Only`: it cannot block anything, so it cannot break a sign-in
that works, and violations from real use post to `POST /csp-report`, where they are logged. That
turns an unverifiable guess into a measurement.

`object-src`, `base-uri`, `form-action` and `frame-ancestors` are already `'none'` and mean
something as written. `connect-src` and `frame-src` are openly placeholders (`https:`) — the
Coinbase endpoints the SDK reaches are what cannot be enumerated from here, and the reports are
how they get enumerated. `script-src` and `style-src` carry `'unsafe-inline'` because the pages
have inline module scripts and style blocks and are served straight off the CDN, where a
per-response nonce is not available. Enforcing mode is a later step, once the reports say what
the real allowlist is.

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
  `permit2Grants` arrays, freshness fields `scannedAt`, `ageSeconds`, `stale`, and the scan's
  own anchor: `scannedToBlock` and `scanMode`
- `202 {"status":"not_scanned_yet"}` when no snapshot exists

**Caveat, by design:** this serves `data/approvals-report.json`, a snapshot committed to the
repo by `scripts/scan-approvals.mjs` — it is not scanned per request. The response therefore
states its own age (`ageSeconds`, plus `stale: true` past a day) and its anchor
(`scannedToBlock`, `scanMode`). Age alone is not enough: it moves whenever the file is
rewritten, so it cannot distinguish a real refresh from a fresh deploy of an old snapshot,
whereas the anchor can be compared against the chain tip. A missing or unparseable timestamp
also reports `stale: true` — failing towards "trust this data" would be the wrong default for an
exposure report. Cached 5 minutes.

Keeping it fresh is no longer an hour's work: see [Refreshing the approval
snapshot](#refreshing-the-approval-snapshot).

### `GET /drops`

Scam-airdrop scan, computed live per request from Blockscout holdings, across **all three token
standards**: ERC-20, ERC-721 and ERC-1155. Both dimensions of that sentence were once wrong.
Holdings are fetched across all *pages* (Blockscout returns 50 per request and this wallet holds
149 ERC-20s, so a single-page fetch scanned a third of them), and NFTs are fetched at all — the
wallet holds 125 NFT collections, 27 of them scams, and they were outside the scan entirely
until 2026-07-30. NFT entries are folded per collection, since the endpoint returns one row per
`token_id` held.

- `200` with `scannedTokens`, `scannedByStandard`, `flaggedCount`, and `flagged[]` (each with
  `address`, `name`, `symbol`, `standard`, `reasons`)
- `502 {"error":"holdings_unavailable"}` when Blockscout is unreachable — an upstream failure
  is surfaced, not silently reported as "nothing flagged"

Cached 30 minutes at the HTTP layer, and the underlying holdings fetch is cached in-process
for 60s and shared with `/audit` — following pagination made one fetch three Blockscout
requests, and the NFT walk adds four more; cache-control headers only help callers that honour
them. The ERC-20 and NFT walks are cached separately so a failure on one cannot evict a good
result from the other, but the endpoint **fails as a whole** (`502`) if either is down: a
partial scan reported as a complete one reads as an all-clear, which is the failure mode this
agent keeps having.

### `GET /audit` — paid

The combined report: exposure + scam scan + a versioned `hygieneScore` with its own breakdown.

```
hygieneScore = max(0, 100 - approvalPenalty - min(flagged, 10))     # scoreVersion 3

approvalPenalty = 25 * unlimited ERC-20 approvals    # open claim on the whole balance
                +  8 * finite ERC-20 approvals       # bounded by construction
                +  5 * Permit2 grants that expire    # time ends them on its own
                +  8 * Permit2 grants that do not    # uint48 max = "never"; only amount 0 ends it
```

Version 1 was `100 - liveApprovals*5 - flaggedTokens*2`, and it broke the moment the scan
learned to read NFTs: 63 flagged collections is -126 on its own, so the score pinned to 0 and
stopped distinguishing a wallet with one $0.04 allowance from one with ten unlimited approvals
to strangers. Both weights above follow from **agency**. Scam airdrops are received, not chosen
— nobody can refuse an incoming transfer — so they are capped at 10 points and read as "this
wallet is a target", not "its owner is careless". Allowances are decisions, and an unlimited one
is not the same decision as a bounded one.

The Permit2 split is not hypothetical: this wallet granted WETH to Morpho's `GeneralAdapter1`
with `expiration` = `281474976710655` (uint48 max), which nothing but the amount reaching zero
was ever going to end. Discounting that as "it expires by itself" was wrong, so it is priced as
the bare approval it behaves as.

"Unlimited" is a threshold (`2^128`), not an equality test against `uint256` max, because
routers and wallets spell it several ways; an unparseable amount counts as unlimited, since a
malformed report must not read as a clean wallet. With no approval snapshot at all the score is
**`null`**, not 100 — approvals are the half of this the owner can act on, and scoring full
marks for having looked at nothing is the quiet-confident-failure this agent exists to avoid.

`scoreVersion` and `scoreBreakdown` ship with every report so a paying caller can tell "my
wallet changed" from "the formula changed".

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

### `GET /sentinel`

The autonomous cycle's own state, so a monitor can see whether it is alive. It stopped running
once already — the cron log showed a jitter line and then silence while `lastRunAt` sat four
days back — and it was found by reading project notes, not by any alert. A stand-down cycle and
a dead cron produce identical silence, which is the reason this endpoint exists.

- `200` with `lastRunAt`, `ageSeconds`, `overdue`, `expectedIntervalSeconds` (26h — the cron
  jitters up to 45 minutes, so a healthy gap can exceed a day), `lastScannedBlock`,
  `knownFlaggedTokens`, `alertedApprovals[]` (listed in full: each is a human action item,
  because only the Ledger can revoke) and `detector.{running,baseline,willRebaseline}`
- `202 {"status":"no_sentinel_state"}` when the sentinel has never been seeded

A missing or unparseable `lastRunAt` reports `overdue: true`. Absence of evidence is not
evidence of a recent run, and the reassuring answer is the wrong default here.

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
| `urgency_language` | `claim` / `until` / `expires` / `visit` / `airdrop`, in **either** field |
| `reward_language` | `reward` / `free` / `prize` / `win` / `bonus` / `giveaway` / `earnings` / `redeem` |
| `quotes_a_cash_amount` | a sum of money with grouped thousands or a currency word (`$5,000`, `340.000$`, `1.000 USDC`) |
| `qr_code_lure` | asks to be scanned (`SCAN ME`, `Scan the QR…`) — the destination is in an image, not the text |
| `pressure_language` | `don't miss` / `last chance` / `hurry` / `limited time` / `act now` |
| `non_latin_homoglyph` | name or symbol contains Cyrillic or Greek confusables |
| `impersonates_<TICKER>` | symbol matches a known ticker but the contract is **not** its canonical address |

Rules 2–7 all came from reading the wallet's own 274 collections rather than from imagining what
a scam looks like:

- Domain rules run on text with **spacing around dots closed up**. Four collections here are
  named `DAONEXT. COM` / `DAOEVENT . COM` and one ERC-20 is `t .me/s/sol_shiba` — a human still
  reads a domain, which is the point of the trick.
- `urgency_language` reads the **symbol** too. Four ERC-20s keep the whole lure there and leave a
  clean name (`symbol: "Visit moodeng.ink to claim"`, `name: "MOODENG"`), and their TLDs are
  outside the domain list, so the symbol was the only field that could catch them.
- `finance` is deliberately **not** a lure TLD: `Rai.Finance` is a legitimate holding. The scam
  that needed it (`cakesv4.finance`) is caught by ticker impersonation instead.
- `quotes_a_cash_amount` requires grouped thousands or a currency word. The looser version — any
  `$` near digits — flagged `EIP-4844 is Based`, whose symbol is `$4844`.

The last rule exists because of a real false negative. An earlier version compared strings only
and required the symbol to *differ* from the known ticker before flagging — so an exact copy,
the simplest and most common impersonation, was the one case guaranteed to slip through. A
token at `0x9053A44f…` presenting as `AAVE` with a 2.1B supply (real AAVE: ~16M) was sitting
unflagged in the wallet. The check is now address-based against `KNOWN_TICKER_ADDRESSES`.

Adding a ticker to that map is the intended way to extend coverage. **Verify the address
on-chain first** (`symbol()`, `name()`, and a holder count) — a wrong entry is worse than a
missing one, because it flags the genuine token as the impostor. The 15 entries currently there
were each checked that way.

### Judging a rule change

```bash
node scripts/calibrate-heuristics.mjs              # summary + what fired, per standard
node scripts/calibrate-heuristics.mjs --unflagged  # also what did not fire
node scripts/calibrate-heuristics.mjs --json       # for diffing two runs
```

The rules are pattern guesses about adversarial text, and the only honest test of one is the 274
real collections in this wallet. Both of the detector's known bugs — the impersonation check that
could never fire, and ERC-20-only scanning — survived because changes were argued in the abstract.
A new rule is judged by what it newly flags (should be scams) **and** by what it flags that it
should not: `Basenames`, `Base Colors`, `Rai.Finance`, `EIP-4844 is Based` and `Uniswap V3
Positions` are all real holdings here, and there are unit tests pinning each of them clean.

The harness also prints hits per rule. A rule that never fires on real data is untested in
production whatever its unit tests say; one that fires on everything is matching something other
than what it claims to.

### Ruleset fingerprint

`RULE_IDS` lists every reason the classifier can emit (including one per canonical ticker) and
`detectorFingerprint()` hashes the sorted list. The sentinel carries that digest in its state
file, so a rule change is distinguishable from a wallet change — see
[Sentinel](#sentinel). Content-derived rather than a hand-bumped constant, because a rule added
without bumping the constant is exactly the case that slips past. A test drives every rule with a
real holding and asserts the emitted reason appears in `RULE_IDS`, so an unlisted rule fails the
suite instead of silently freezing the digest.

## Sentinel

`scripts/sentinel-run.mjs` is the autonomous half: an incremental re-scan that only speaks up
when something is genuinely new. It reads `data/sentinel-state.json`, scans from
`lastScannedBlock + 1` to the current tip for new `Approval` events (ERC-20 and Permit2),
checks which of the resulting pairs still have a live allowance, re-runs the scam classifier over
current holdings (ERC-20 **and** NFT collections), and diffs both against what it already knew.

- **No findings → no attestation.** It logs a stand-down and advances the state file. This is a
  real check, not a heartbeat.
- **New findings →** the courier wallet submits an EAS attestation under schema
  `SentinelCheck(address wallet, uint64 checkedAt, uint16 newFindings, string summary)`
  (`0x37419361…97e93032`).
- **Ruleset changed → re-baseline, attest nothing.** An attestation says "as of this timestamp
  this exposure appeared", permanently and signed by the agent. When a new rule starts seeing
  dust that arrived months ago, attesting it puts a false date on-chain. So the cycle compares
  the detector fingerprint in its state file against the running one; if they differ it records
  everything currently flagged as known, logs why, and reports nothing. The next cycle behaves
  normally. **EAS attestations record changes in the wallet; git records changes in the
  detector.** This was enforced by hand — and got it wrong twice — until
  `lib/tokenFindings.mjs`.
- **Either both holdings walks or neither.** A partial scan cannot invent a finding, but
  re-baselining on a short list records fewer tokens as known, so the missing ones return next
  cycle looking new and get attested with the wrong date.

**What it structurally cannot see:** approvals granted before its baseline. The sentinel scans
*forward* from `lastScannedBlock`, which makes each cycle cheap but means anything already live
when the baseline was seeded is invisible to it forever. `scripts/scan-approvals.mjs` is what
catches those. A live WETH allowance to the Aave v3 Pool, left over from a July 23 borrow/repay
cycle, sat unnoticed for exactly this reason until a full scan found it — and the reason it sat
that long is that the scan used to cost 50 minutes. It now costs seconds; see below.

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

The wrapper resolves `node` explicitly (PATH, else the newest nvm install) and exits 127 with the
PATH printed if it cannot find one. cron runs with a bare PATH and no nvm shim, which killed the
2026-07-29 cycle with a plain `node: command not found` — the sentinel was then dead for a day
before `/sentinel` surfaced it.

The app itself reads `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` and `ALLOW_UNPAID_AUDIT` — see
[`GET /audit`](#get-audit--paid).

`MAX_LOG_RANGE` must stay under **10,000** — Base's RPC rejects wider ranges with `-32614`.
Since Base produces roughly 43,000 blocks a day, the range walk is not an optimisation: an
unchunked scan fails outright on any gap longer than a few hours. Rate-limit errors (`-32016`)
are retried with doubling backoff; every other error propagates immediately, so a real bug
stays a fast, loud failure. See `lib/rangeScan.mjs` and `test/rangeScan.test.mjs`.

### Refreshing the approval snapshot

```bash
node scripts/scan-approvals.mjs            # incremental: resumes from the report's anchor
node scripts/scan-approvals.mjs --full     # whole history from block 0
```

The full walk is ~4,900 windows per event and takes about **50 minutes**, which is why it was run
roughly never — and why `/exposure` served a two-day-old snapshot while the paid `/audit`
computed `hygieneScore` from it. The incremental refresh resumes from `scannedToBlock` and takes
**seconds** (14s for 75,000 blocks on its first real run), so the snapshot can actually be kept
current.

What makes it correct rather than merely fast, since a wrong refresh is worse than a stale one:

- New `Approval` / `Permit` events since the anchor find grants made in the gap. An allowance
  only becomes non-zero through a call that emits an event.
- **Every previously-live pair is re-read regardless of events.** `transferFrom` decrements a
  finite allowance and ERC-20 requires no event for it, so a grant spent to zero leaves no log —
  events alone would keep reporting exposure that no longer exists.
- A 250-block overlap is re-scanned each run, so a report written from a shallowly-reorged block
  cannot leave a permanent hole.
- The anchor is written only after the allowance re-read succeeds; a failed run cannot advance it
  past blocks it never processed.
- `scannedAt` is taken when the tip is read, not when the run finishes, and `scanFinishedAt`
  records the latter separately. A full scan runs for hours, so a completion timestamp would
  claim freshness the data does not have — the report covers the chain as of `scannedToBlock`,
  and `/exposure` derives `stale` from `scannedAt`. A missing anchor falls back to a full scan rather than guessing,
  and one ahead of the chain tip is refused outright — that would make every future run scan an
  empty range and report "nothing new" while looking healthy.

Both modes scan Permit2's `Permit` event as well as `Approval`. Grants made by signature emit the
former, so a router taking a permit instead of an on-chain approve was previously invisible; no
such grant exists in this wallet's recent history, so that is a hole closed rather than a miss
fixed. Logic and its tests live in `lib/approvalScan.mjs` / `test/approvalScan.test.mjs`.

**The snapshot only reaches production on a deploy.** It is served from the deployed bundle, so a
local refresh changes nothing live until the file is committed and `vercel --prod` runs.

### Scheduling

`scripts/sentinel-cron.sh` wraps the run with jitter (`MAX_JITTER_SECONDS`, default 45 min), a
per-cycle stand-down probability (`STAND_DOWN_PCT`, default 40), and a hard daily action cap
(`MAX_ACTIONS_PER_DAY`, default 2) so the schedule doesn't read as a fixed-cadence bot.

#### Heartbeat

Every cycle publishes one JSON to the **`sentinel-heartbeat`** branch, readable without a
checkout:

```
https://raw.githubusercontent.com/Kajko25/kokosh/sentinel-heartbeat/sentinel-heartbeat.json
```

It carries `publishedAt`, the `outcome` (`stand-down` / `capped` / `clean` / `findings` /
`failed`), the exit code, and what the scan recorded — `lastRunAt`, `lastScannedBlock`,
`knownFlaggedTokens`, `detectorFingerprint` — plus the `codeCommit` that produced it, so a
heartbeat from a stale checkout is identifiable.

Why it exists: `/sentinel` made the cycle observable from outside, but only for state baked into
the deployed bundle, and a local cron run does not touch that. From anywhere but the laptop,
"did the cron fire?" had no answer. **Absence is the signal** — a stale `publishedAt` means no
cycle completed, whatever the reason. Cycles that do no work publish too (`stand-down`,
`capped`); one that published nothing would be indistinguishable from a cron that never ran,
which is the exact failure this addresses.

It is built with git plumbing — `hash-object`, `mktree`, `commit-tree`, then a push of the
resulting object — so it never touches the working tree, the index, or `HEAD`. That is not
fastidiousness: this fires unattended and may land while someone is mid-edit or mid-rebase on
`main`, and a script doing `git add` there could commit unrelated work in progress. Publishing
failure is logged and never fatal, since a failed push says nothing about whether the scan
worked.

It does not fix the underlying limitation: if the machine is asleep at 09:23 local, no cycle runs
and no heartbeat appears. It makes that visible rather than silent.

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

Tests cover the routes (against a stubbed client and stubbed holdings), the payer-info
validator, the scam heuristics — including the impersonation regression above, every rule's
verbatim source name, and guard cases for the legitimate holdings that must stay unflagged — the
score's weights and its null-when-unscanned behaviour, the re-baseline decision, the sentinel
state and report readers, and the sentinel's range/retry logic. No network required.
