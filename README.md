# Kokosh

Mechanism-gap program for `0x2984Bb4953cfCE2cEc957388BE686D6c38779234` (**kajko24.base.eth**) on Base mainnet.

**Kokosh** is a wallet-hygiene sentinel agent: tracks token/Permit2 allowance exposure, flags
scam-airdrop tokens by name/URL/homoglyph heuristics, and sells a paid `/audit` report via x402.

- Live agent: https://kokosh-agent.vercel.app
- Agent card: https://kokosh-agent.vercel.app/.well-known/agent-card.json
- ERC-8004 identity: agentId `59633` on the Base mainnet Identity Registry
- Journal: [docs/JOURNAL.md](docs/JOURNAL.md) — every on-chain action with tx hashes and lessons learned

## Structure

- `contracts/` — Foundry project: `Waypoint` (CREATE2 profile registry), `Waymarks` (on-chain SVG
  badge NFT), `EncodeMirmil.s.sol` (local pure-encoder for the MIRMIL B20 token, no chain calls)
- `agent/` — Node/Express agent (`makeApp` factory, `/healthz`, `/exposure`, `/drops`, paid
  `/audit` via x402), deployed to Vercel
- `scripts/` — `scan-approvals.mjs`, a from-scratch ERC-20 + Permit2 approval scanner

## Signing

`0x2984` signs exclusively via Ledger hardware wallet (`cast ... --ledger`) — no private key or
seed phrase ever leaves the device. A software burner ("courier") handles gas-only relay
transactions (permit submission, agent-wallet operations).
