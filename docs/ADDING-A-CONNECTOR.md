# Adding a connector

SafeSpace is a **safety envelope**, and the envelope is the product. A connector is a
*source behind the envelope* — Gmail, GitHub, a LINE bot, the local filesystem. This
guide is the map for adding one.

## The one idea: the envelope is free

Every tool call is routed through one of three **choke points** by `src/server.ts`
(based on the source's `authModel`). Whichever one your connector uses, it gets — for
free, without you writing it —

- **input sanitize** — every free-text field of a response is wrapped as an
  `<untrusted-source>` before the agent sees it (prompt-injection containment);
- **audit** — a structured row per call (`source`, `run_id`, operator, tier, outcome);
- **tier gating** — `read` / `write` / `share` exposure;
- **autonomous-mode hardening** — write/delete burst caps, permanent-delete deny.

Your job is the *connector-specific* part: how it authenticates, which tools it exposes,
and — for anything that sends data **out** — its egress gate. **You do not touch the
choke points.** Adding LINE, Telegram, Discord, web-fetch, GitHub, and Notion each left
`withToolContext` (the OAuth path) byte-identical.

## Step 0 — which class is your connector?

The `Credential` discriminated union (`src/tools/types.ts`) has three variants; pick by
**how the source authenticates**:

| Class | `authModel` | Auth | Choke point | Examples | Cost |
|---|---|---|---|---|---|
| **A. OAuth-account** | `"oauth"` | Per-user OAuth (consent + refresh) | `withToolContext` | Google, GitHub, Notion | High (consent flow, token store) |
| **B. service-token** | `"service-token"` | One long-lived token, out-of-band | `withNonOAuthContext` | LINE, Telegram, Discord | **Low — the cheapest** |
| **C. keyless** | `"none"` | None | `withNonOAuthContext` | web-fetch, fs-read | Low (but you own the new request surface, e.g. SSRF) |

> Any provider whose token you obtain **out-of-band** (a bot token, a long-lived PAT)
> is class **B**, even big platforms — that's the cheap path. Class **A** is only for
> *in-app* OAuth (a consent screen + refresh you implement).

**The fastest start is to copy the closest existing connector** and adapt it: class B →
`discord` (`handlers/discord.ts`, `registry/discord.ts`, `policy/discord-recipient-allowlist.ts`);
class C → `web` (`policy/url-gate.ts`); class A → `notion` or the `github` OAuth files
under `src/auth/github/`.

## Step 1 — the edit-site checklist

A read-only tool on an existing connector is just a registry fragment + a handler. A
**new connector** touches more. In rough order:

1. **`Source` descriptor** — add an entry in `src/tools/source.ts`
   (`{ id, authModel, skipFields, mapError, authorize, resolveCredential }`). This is
   where the polymorphism lives; the choke points call these methods.
2. **Registry fragment** — `src/tools/registry/<source>.ts` exporting `<source>Tools`
   (the `ToolDef`s). Each `ToolDef` carries `source`, `min_tier`, `requiredScopes`,
   `direction`, and an `inputSchema` with `additionalProperties: false`.
3. **Expose the tools** — import the fragment into `src/tools/registry/index.ts`, spread
   it into `FRAGMENTS`, and add each tool name to **`TOOL_ORDER`**. That's it for
   exposure: `IMPLEMENTED_TOOLS` and `TOOL_REGISTRY` are **derived from `TOOL_ORDER`**
   (single source of truth) — there is no second list to keep in sync.
4. **Connector token** — add the new `source` id to `NON_GOOGLE_CONNECTOR_TOKENS` in
   `src/policy/connector-toggle.ts` so operators can name it in
   `SAFESPACE_CONNECTORS` (a new **Google sub-service** instead adds its tool-name
   prefix to `GOOGLE_SUBSERVICE_TOKENS`). The sentinel test in
   `connector-toggle.test.ts` fails if you skip this; at runtime an unmapped tool is
   fail-safe (always exposed), so the omission never hides a tool — it just makes it
   un-toggleable.
5. **Handlers** — `src/tools/handlers/<source>.ts`. Read the credential via the
   narrowing helper (`requireGithub(ctx)`, `requireServiceToken(ctx)`, …) so a
   wrong-provider credential throws before any network call.
6. **Class B only** — a token in `auth/service-token-store.ts` (a reserved
   `SecretBackend` key) + CLI `set-token` / `status` / `clear-token` subcommands.
7. **Outbound / external-write tools** — see Step 2 (the non-negotiable part).
8. **Error codes** — if the source needs new failure reasons, add to `src/errors.ts`
   (`ErrorName` union + `ERROR_CODES`). Pick the next free `-320xx`; never echo a token
   or a private identifier in the recovery string.
9. **Env vars** — every `SAFESPACE_*` name lives in `src/config.ts` (CI fails on a
   `SAFESPACE_` literal read outside it).
10. **Tests** — sentinel style (see Step 3).
11. **Version + docs** — bump the three manifests in lockstep, add a `CHANGELOG.md`
    entry, and update the tool count in the manifest descriptions.

## Step 2 — the non-negotiable: gate every outbound write

The choke points handle *inbound* safety. **Egress — sending agent-authored content to
an external party — is the one thing a connector must wire itself**, and the place a
naive connector ships dangerous-but-looking-safe. So it is **machine-enforced**:

`src/tools/egress-coverage.test.ts` partitions **every** `write`/`share`-tier tool into
exactly one bucket (the buckets live in `src/tools/egress-coverage.sets.ts`), and **fails
CI if your new tool is unclassified**:

- **`PIPELINE_EGRESS`** — it reaches an external party; write its gate in
  `src/tools/egress.ts` (a default-deny recipient/target allowlist + the F3a
  secret-shape scan), attach it to the tool as an `egress` descriptor
  (`src/tools/egress-pipeline.ts`) so the choke point fires it before the handler runs,
  and label it `direction: "outbound-write"`. The handler must not call the gate itself.
  If the gate transforms the content (e.g. `outboundSanitize` rewrites the text), the
  handler must send the gate's result — `requireEgressResult(ctx, "<kind>")` — never the
  raw args (see the gmail / X / YouTube handlers); a check-only gate (accept or reject,
  as for GitHub, Notion and the service-token sends) leaves the handler to build the body
  from the validated args. Only the OAuth choke point (`with-context.ts`) stores a gate's
  result on `ctx.egress` today; a transforming gate for a service-token connector first
  needs `with-nonoauth-context.ts` to store it too. Add the tool's `PIPELINE_TABLE` row (handler file + gate wrapper) in
  `egress-callsite.test.ts`, which checks the descriptor calls the gate and the handler
  does not.
- **`HANDLER_GATED_EXTERNAL`** — it reaches an external party but the gate is bespoke
  (e.g. `drive_share_file`); name where the gate lives.
- **`OWN_DATA_WRITE`** — it only writes the caller's own data (no external recipient);
  tier + sanitize + audit is the floor.

If your write reaches a third party, it also needs:

- a **default-deny** allowlist policy module (copy `policy/github-write-targets.ts` or
  a `*-recipient-allowlist.ts`) — *empty by default = hard-deny*;
- **`outboundSanitize`** on any text that becomes public (REJECT, not wrap);
- an **allowlist-constructed** request body — build the payload field-by-field; never
  spread `args` (an injected field must not reach the wire);
- **never echo** the token, recipient, or target in an error (PII-oracle defense).

## Step 3 — the sentinels have your back

You don't have to remember every site — CI does. If you forget one, a **drift sentinel**
tells you exactly what's missing:

| Forgot to… | Caught by |
|---|---|
| add the tool to a registry list / wrong count | `registry.test.ts` (exhaustive key list + size) |
| gate an external write | `egress-coverage.test.ts` (the partition fails) |
| add the connector's `SAFESPACE_CONNECTORS` token | `connector-toggle.test.ts` (every tool must map to exactly one token) |
| register / collide an error code | `errors.test.ts` (exhaustive code list) |
| read an env var outside `config.ts` | `config.test.ts` |
| desync the three manifests | `scripts/check-manifest-versions.sh` + a CI sentinel |
| change `src/sanitize/` coverage | the `sanitize-coverage` CI job (100% branch) |

Write your own sentinel for any new security invariant your connector introduces — pin
it so a future change can't quietly regress it.

## What is *not* easy (be warned)

- A **fourth auth paradigm** — anything outside request/response *pull* (inbound
  webhooks / push / streaming, e.g. receiving LINE messages) does **not** fit the
  current seam and needs new architecture. The three classes above are all pull.
- **Cross-provider isolation** is load-bearing: a connector's scopes/tokens must never
  leak into another provider's path (the `requireGithub`-style narrowing is the
  backstop). Keep them separate.

## See also

- [`README.md`](../README.md) — the envelope, the three security pillars, the connector roster.
- [`SECURITY.md`](../SECURITY.md) — the trust boundary and threat model.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — the Source seam and choke points in depth.
