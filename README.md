# Kokosh

Mechanism-gap program for `0x2984Bb4953cfCE2cEc957388BE686D6c38779234` (**kajko24.base.eth**) on Base mainnet.

**Kokosh** is a wallet-hygiene sentinel agent: tracks token/Permit2 allowance exposure, flags
scam-airdrop tokens by name/URL/homoglyph heuristics, and sells a paid `/audit` report via x402.

- Live agent: https://kokosh-agent.vercel.app
- Agent card: https://kokosh-agent.vercel.app/.well-known/agent-card.json
- ERC-8004 identity: agentId `59633` on the Base mainnet Identity Registry
- **Agent documentation: [agent/README.md](agent/README.md)** — endpoints, scam heuristics, the sentinel loop and its limits
- Journal: [docs/JOURNAL.md](docs/JOURNAL.md) — every on-chain action with tx hashes and lessons learned

## Structure

- `agent/` — the agent itself: Node/Express app (`makeApp` factory) serving `/healthz`,
  `/exposure`, `/drops` and the x402-paid `/audit`, plus `agent/scripts/` — the autonomous
  sentinel (`sentinel-run.mjs`, `sentinel-cron.sh`) and the x402 buyer (`pay-audit.mjs`).
  Deployed to Vercel. **Start here: [agent/README.md](agent/README.md)**
- `contracts/` — Foundry project: `Waypoint` (CREATE2 profile registry), `Waymarks` (on-chain SVG
  badge NFT), `EncodeMirmil.s.sol` (local pure-encoder for the MIRMIL B20 token, no chain calls)
- `scripts/` — operational one-offs run against the wallet, not part of the agent runtime:
  `scan-approvals.mjs` (from-scratch ERC-20 + Permit2 approval scanner, produces the snapshot
  `/exposure` serves), `l2l1-withdrawal.mjs`, `erc4337-usdc-gas.mjs`, `spend-permission.mjs`,
  `make-prolink.mjs`, `convert-solana-key.mjs`

## Signing

`0x2984` signs exclusively via Ledger hardware wallet (`cast ... --ledger`) — no private key or
seed phrase ever leaves the device. A software burner ("courier") handles gas-only relay
transactions (permit submission, agent-wallet operations).
