# kokosh — Plugin Spec Evaluation

**Plugin:** `kokosh.md` · **Evaluated against:** current Base MCP Plugin Specification (fetched live 2026-07-22) · **Date:** 2026-07-22

## Verdict
🟡 Approve with minor changes — conforms structurally and honestly documents a real hazard (smart-wallet signature incompatibility) rather than glossing over it. One net-new tag needs flagging on PR, and the file needs relocating before it can actually be submitted.

## Conformance Checklist
| Requirement | Status | Notes |
|---|---|---|
| File location `plugins/<slug>.md` | 🔴 | Currently staged at `docs/base-mcp-plugin/kokosh.md` in this repo, not `skills/base-mcp/plugins/kokosh.md` in `base/skills` — must move on actual PR. |
| Frontmatter required fields | ✅ | title/description/tags/name/version/integration/chains all present. |
| Enum validity | ✅ | `integration: http-api`, `shell: none`, `auth: none`, `risk: [irreversible]` — all valid enum members. |
| chains ⊆ supported set | ✅ | `[base]` ⊆ supported set. |
| tags (vocabulary, net-new flagged) | 🟡 | `wallet-hygiene` is net-new — needs appending to the vocabulary list in plugin-spec.md on PR (the one sanctioned shared-file edit). `security`, `ai-agents`, `discovery` reuse existing vocabulary. |
| integration most-specific | ✅ | Calls an HTTP API (no CLI, no separate MCP, doesn't purely compose `swap`/`send`) → `http-api` is correct per the ordered-questions test. |
| `> [!IMPORTANT]` callout first | ✅ | |
| `## Overview` | ✅ | States chain, routing, and that it returns a payment-gated HTTP response (not calldata). |
| `## Surface Routing` (+ chat-only behavior) | ✅ | Table covers harness-HTTP and chat-only (`web_request`) paths; both work (host is allowlisted), no stop needed. |
| `## Orchestration` | ✅ | 7 ordered steps, decode → build EIP-712 → sign → resubmit. |
| `## Submission` (names tool + mapping) | ✅ | Names `sign`; explicit mapping from x402 payload to Base MCP `sign` input; **includes the smart-wallet caveat** (see Security notes below). |
| `## Example Prompts` | ✅ | 4 prompts: a paid read, a free read, a paid+decision flow, a chat-only edge case. |
| Conditional sections (Detection/Installation/Auth/Endpoints/Commands/Risks) | ✅ | `## Endpoints` present (http-api); `## Risks & Warnings` present (`risk` non-empty); `## Detection`/`## Installation`/`## Auth` correctly omitted (no externalMcp/cliPackage, auth: none). |
| Canonical headings | ✅ | No synonyms used. |
| Canonical order / anchors intact | ✅ | Matches the spec's numbered order exactly. |
| allowlist accuracy | ✅ | Only host referenced in the body (`kokosh-agent.vercel.app`) is the only allowlist entry. |
| Neutral language (no yield claims, no steering) | ✅ | Descriptive throughout; risk language is guardrail-framed, not promotional. |
| Geoblock parity (if perps/prediction/gambling) | N/A | Not in a gated category. |
| Disclaimers in onboarding callout | 🟡 | Minor — no explicit "third-party service" framing (arguably N/A since author == service operator), but doesn't call out the per-call payment cost inline; the cost is documented in `## Risks & Warnings` instead, which is an acceptable place for it. |
| High-risk category gate (perps/prediction/privacy) | N/A | Not in a gated category. |
| Contribution scope (no self-registration) | ✅ | Diff would touch only the plugin file + one vocabulary-list line; no SKILL.md/Examples/Conformance edits. |

## Detailed Findings

1. **[minor] File not yet at the PR-ready path.** Staged in this project's own repo for review; must be copied to `skills/base-mcp/plugins/kokosh.md` in a `base/skills` fork before a PR can open. Not a defect in the content.
2. **[minor] One net-new tag (`wallet-hygiene`).** Per Contribution Scope, this is the one sanctioned shared-file edit — append it to the tag vocabulary list in `plugin-spec.md` alongside the plugin PR, nothing else.
3. **[nit] `security` tag is broad.** Reused because no narrower existing tag fits ("compliance" would be more precise but is itself net-new); acceptable as-is, could be tightened later if the vocabulary grows a `compliance` tag independently.

## Security & Safety Notes

- **Smart-account signature gotcha (cross-cutting gotcha #1) — correctly handled, not silently broken.** This plugin's `sign`-based flow was hand-verified against an **EOA** signer (Ledger-backed `0x2984`, raw ECDSA over the same EIP-712 domain/message) settling real mainnet USDC end to end. It was explicitly **not** verified against Base MCP's default smart-contract wallet, and the `## Submission` section says so plainly: a smart-wallet `sign` call would return an ERC-1271/6492-shaped signature that standard USDC `transferWithAuthorization` (`ecrecover`-only) will reject, so the documented instruction is to *stop* rather than submit a signature likely to fail facilitator verification. This is the single highest-value finding from live-testing this plugin's premise, and it's already reflected in the file — flagging it here so it isn't lost on a re-review, and recommending Base MCP maintainers confirm (or deny) ERC-6492 support in their `exact`-scheme facilitator before treating this as resolved.
- **Payment irreversibility.** `risk: [irreversible]` is justified here (unlike a swap, this is a pure spend with no "swap back" recovery path) — see gotcha #2's own distinction between swaps (recoverable, `slippage` only) and pure spends (not recoverable).
- **No untrusted calldata risk** — the plugin never constructs or submits onchain calldata; the only "write" is an off-chain EIP-712 signature over a well-defined EIP-3009 authorization struct with a fixed, small (`$0.01`) amount pulled directly from the resource's own `payment-required` header, not from user input.
- **Allowlist is minimal and accurate** — single host, no SSRF surface (no user-supplied URLs are fetched).

## Recommended Changes

1. Before opening a PR: copy the file to `skills/base-mcp/plugins/kokosh.md` in a `base/skills` fork, add `wallet-hygiene` to the tag vocabulary list, run the checklist once more against the fork's copy of the spec (it may have moved).
2. Optional: if/when Base MCP's smart-wallet ERC-6492 support for x402 `exact`-scheme payments is confirmed either way, update the `## Submission` caveat to state the resolved behavior instead of "verify before relying on this."
3. Consider whether `security` should stay generic or wait for a more precise `compliance`/`hygiene`-flavored tag to emerge in the shared vocabulary from a second plugin in this space, before over-fitting Kokosh's own tags to a category of one.
