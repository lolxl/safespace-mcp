# SafeSpace MCP — Project Context

> Context for AI coding assistants (and humans) working in this repo. For the user-facing
> overview see [`README.md`](README.md); for the security model see [`SECURITY.md`](SECURITY.md).

## What this is

SafeSpace is **the AI safety gateway for an agent's external surface** — a provider-agnostic
safety **envelope** between an AI agent and **any source it touches**: input sanitize +
untrusted-content tagging, scope·tier·burst·recipient egress gates, autonomy hardening,
`run_id` session forensics, and OAuth / service tokens behind a pluggable `SecretBackend`, with a
full audit trail on every call. **The envelope is the product; sources are connectors behind it.**

Connectors are evaluated by **credential class**:
- **A. OAuth-account** — Google Workspace (the flagship reference connector), GitHub, Notion, X.
- **B. service-token** — one token in the `SecretBackend`, no OAuth (LINE · Telegram · Discord · Slack · Mattermost).
- **C. keyless** — no credential, pure inbound-sanitize (web-fetch, filesystem read).

The connector seam is a `Source` abstraction over a `Credential` discriminated union
(`oauth` / `service-token` / `none`) with `CredentialResolver` / `Authorizer` strategies; the
OAuth machinery (`V1_SCOPES` / consent / `SCOPE_HIERARCHY` / `requiredScopes`) lives in the
google-workspace source's strategy implementations. Adding a connector (axis 1) is independent
of the Model B multi-operator engine (axis 2).

## Current surface

130 MCP tools across 11 connectors — Google Workspace (Gmail · Drive · Docs · Calendar ·
Contacts · YouTube + Analytics · Tasks · Sheets · Slides · Forms, the flagship · 85) · GitHub
(18) · Notion (8) · X (3, OAuth PKCE) · web-fetch · fs-read · LINE · Telegram · Discord · Slack · Mattermost — plus an
inbound webhook inbox (`inbox_read`). Two deployment models: **Model A** (single-user, stdio,
the default) and **Model B** (a shared multi-operator server over a private tailnet). Tokens live
behind a `SecretBackend` (macOS Keychain / encrypted Linux `FileBackend`).

## Security policy layers

The envelope's controls (full detail + threat model in [`SECURITY.md`](SECURITY.md)):

- **Privilege tier** (`SAFESPACE_TIER=read|write|share`, read default) — filters the exposed tool set; no per-call escalation.
- **Recipient allowlist** — gates `gmail_send` / `gmail_create_draft` / `drive_share_file` (user shares); rejected recipients are HMAC-hashed in the audit log.
- **Drive share whitelist** — folder-subtree + file-ID allowlist at the `drive_share_file` boundary.
- **Per-target write allowlists** — default-deny gates on the public-surface writes (GitHub issue / PR / approve, YouTube comment / video, X post).
- **Filesystem read gate** — default-deny, realpath-contained root allowlist, no path-existence oracle.
- **Outbound URL / SSRF gate** — the `web_fetch` scheme / port / private-IP / DNS-rebind / per-hop-redirect gate.
- **Inbound sanitize pipeline** — zero-width strip → confusables normalize → pattern flag → truncate → `<untrusted-source-${nonce}>` wrap, with per-source `skipFields`.
- **Inbound formula REJECT** (Sheets writes) + **outbound sanitize REJECT** (public-surface text).
- **Autonomy Hardening F1–F6** (`SAFESPACE_AUTONOMOUS`) — write/delete burst caps, deny-by-default allowlists, permanent-delete deny, tainted-source + outbound-secret-shape REJECT, `run_id` session audit, token-at-rest hardening.
- **Enforced mode** (`SAFESPACE_ENFORCED`) — a refuse-to-start company-deployment checklist; `safespace doctor --posture` reports the gates.
- **Egress-destination registry** + **tamper-evident audit hash-chain** (`row_mac` HMAC chain; verify with `safespace audit verify`).
- **Multi-operator (Model B)** — Tailscale-WhoIs (or bearer-token) verified identity → default-deny `operators.json` → per-operator tier + `allowedAccounts` confinement.

## Layout

- Source root: **`.claude-plugin/src/`**. Plugin manifest trio: `.claude-plugin/{package,marketplace,plugin}.json` (versions stay in lockstep).
- Connectors: `src/tools/registry/` (tool definitions) + `src/tools/handlers/` (implementations), split per API.
- Policy gates: `src/policy/`. Sanitize: `src/sanitize/`. Auth / SecretBackend: `src/auth/`. Audit: `src/audit.ts`.
- CLI (`safespace <subcommand>`): `src/cli/` — 18 subcommands (consent · account-* · audit · status · doctor · whitelist · recipient · agent-token · send · line · telegram · discord · slack · mattermost · webhook · migrate-v2).

## Testing

- Runner: **`bun test` from the `.claude-plugin/` directory** (the repo root has no `bunfig.toml`, so `bun test` there finds 0 tests).
- Typecheck: **`bun run typecheck`** from `.claude-plugin/`.
- Coverage target: 100% branch coverage on `src/sanitize/` (CI job `sanitize-coverage`).
- The 3 manifest versions must stay in lockstep — enforced by `src/manifest-versions.test.ts` + `scripts/check-manifest-versions.sh`.
- Mock infra: `src/google-api/test-utils.ts` `setGaxiosHandler` (SDK-level; one uniform mock surface across the Google tools).

## Key docs

- [`README.md`](README.md) — overview + quickstart.
- [`SECURITY.md`](SECURITY.md) — security policy + threat model + the full defense-layer reference.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture overview + full tool list.
- [`docs/DESIGN.md`](docs/DESIGN.md) — the locked design + addenda.
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — Model B operator runbook (Docker / Tailscale / operators.json / fronting gateway).
- [`docs/ADDING-A-CONNECTOR.md`](docs/ADDING-A-CONNECTOR.md) — how to add a new connector.
- [`docs/AUDIT-CHAIN.md`](docs/AUDIT-CHAIN.md) · [`docs/SOLE-EGRESS.md`](docs/SOLE-EGRESS.md) · [`docs/SIEM.md`](docs/SIEM.md) — audit chain, sole-egress checklist, SIEM integration.

## Decision principles

- **Touching `src/sanitize/` or `src/auth/` → do a dedicated security review first;** never edit those directly without one.
- Small, non-security change (≤2 files) → just do it.
- Keep per-change LoC modest; do a dead-code / refactor pass as a feature grows.
- `docs/DESIGN.md` is the spec — a change that conflicts with it gets questioned, not forced in.
- Before a multi-step change (a new tool / a new sanitize rule), write the implementation steps first.
- Before merging, or after a large refactor, run an independent review.
