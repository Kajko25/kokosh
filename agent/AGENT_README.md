# Kokosh — Agent Attribution

## Builder Code

Registered via `POST https://api.base.dev/v1/agents/builder-codes` with `wallet_address: 0x2984Bb4953cfCE2cEc957388BE686D6c38779234` (kajko24.base.eth).

- `builderCode`: `bc_mxu6lkmb`
- Stored in `constants/builderCode.ts` as `BUILDER_CODE`.

## Rule

Every transaction sent by this program — from `0x2984` (Ledger) or the `courier` burner — MUST include the ERC-8021 data suffix built from `BUILDER_CODE`. There is no error or warning when attribution is missing, just silent invisibility to Base's attribution tracking. Never send a transaction without it.

```ts
import { Attribution } from "ox/erc8021"
import { BUILDER_CODE } from "./constants/builderCode"

const DATA_SUFFIX = Attribution.toDataSuffix({ codes: [BUILDER_CODE] })
```

- **cast** (raw sends via Ledger/courier): append `DATA_SUFFIX` (minus `0x`) to the end of the transaction's calldata.
- **viem**: pass `dataSuffix: DATA_SUFFIX` on the wallet client, or per-call.

## base.dev API key

`BASE_DEV_API_KEY` lives in the project `.env` (git-ignored, never committed). Needed for the domain-verification step (Stage 5, once Kokosh has a live Vercel URL) — not required for the builder-code registration call above.
