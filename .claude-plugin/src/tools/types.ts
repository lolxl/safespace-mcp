// Shared type-only declarations for tools/.
// Kept in its own file to avoid circular imports between handlers.ts and registry.ts.
//
// SECURITY (review #2): the OAuth credential's `getAccessToken` is a GETTER, NOT
// a raw `accessToken: string` field (and `service-token`'s `token` likewise).
// JSON.stringify drops functions, so any accidental serialization of a
// ToolContext (logging, audit, JSON-RPC error data, etc.) cannot leak the bearer
// token. Handlers narrow `ctx.credential` via `requireOAuth(ctx)`
// (handlers/shared.ts) and call `.getAccessToken()` inline only when
// constructing the Authorization header.

import type { MetaMap } from "../audit";
import type { Tier } from "../tier";
import type { OutboundSecretShape } from "../policy/outbound-secret";

/** v1.64 Phase B (B1 — audit facade) — the full set of channels the per-call
 *  audit sink accepts, mapping each channel NAME to the TYPE of value a handler
 *  records for it:
 *
 *    - the 7 structured forensic channels (= `MetaMap` = the AUDIT_META_CHANNELS
 *      registry), each carrying its channel's `*AuditMeta` (the calling pattern
 *      + field semantics live on each interface in audit.ts);
 *    - 3 SCALAR channels that were standalone `record*` closures pre-v1.64:
 *        · resolvedRecipientHash — plain SHA-256 hex of the resolved recipients
 *          (v1.15 Phase 3; recorded once after a name→email contact-lookup);
 *        · taintedSource — a FLAG (value `void` → NO second argument): set when
 *          a gmail egress recipient first appeared inside untrusted body content
 *          this session (v1.56 F3b; idempotent, NON-blocking observability);
 *        · outboundSecretShape — the closed-set secret-shape CLASS (never the
 *          bytes) when a non-autonomous (interactive-mode) gmail body matched a
 *          secret shape (v1.57 F3a; under autonomous mode the handler throws
 *          -32035 instead of recording).
 *
 *  `AuditSinkChannels extends MetaMap` is the OPEN/CLOSED cut that replaces the
 *  v1.27 recorder-symmetry drift defense at COMPILE TIME: a future 8th meta
 *  channel added to `MetaMap` is AUTOMATICALLY a valid `ctx.audit.record`
 *  channel — no ToolContext edit, no new closure, no symmetry sentinel to keep
 *  in sync. */
export interface AuditSinkChannels extends MetaMap {
  resolvedRecipientHash: string;
  taintedSource: void;
  outboundSecretShape: OutboundSecretShape;
}

/** v1.64 Phase B (B1) — every channel name the audit sink accepts (the 7 meta
 *  channels + the 3 scalars). */
export type AuditChannel = keyof AuditSinkChannels;

/** v1.64 Phase B (B1 — audit facade) — the single typed audit sink that
 *  REPLACES the 10 optional `record*` closures formerly hung on ToolContext (7
 *  meta-channel recorders + recordResolvedRecipientHash / recordTaintedSource /
 *  recordOutboundSecretShape). Handlers record forensic metadata via
 *  `ctx.audit.record("<channel>", meta)`; `with-context.ts` supplies the impl,
 *  which threads the recorded values onto the per-call `auditEnd` row (the 3
 *  scalars become row fields; the 7 meta channels feed the MetaMapStore
 *  aggregator + the mutual-exclusion check). A FLAG channel (value `void`) takes
 *  no second argument:
 *
 *    ctx.audit.record("taintedSource");                     // flag, no meta
 *    ctx.audit.record("resolvedRecipientHash", sha256hex);  // scalar
 *    ctx.audit.record("calendarMutationMeta", { ... });     // structured meta
 *
 *  SECURITY: NEVER record plaintext content — only hashes, flags, counts, and
 *  closed-set classes, per each `*AuditMeta` interface in audit.ts. */
export interface AuditSink {
  record<C extends AuditChannel>(
    channel: C,
    ...meta: AuditSinkChannels[C] extends void ? [] : [meta: AuditSinkChannels[C]]
  ): void;
}

/** v1.64 Phase B (B2 — Credential union, D3b) — the per-call resolved
 *  credential, modeling the 3-class connector taxonomy
 *  (docs/safety-gateway-thesis.md §5) as a DISCRIMINATED UNION rather than an
 *  `authModel` enum the choke point branches on. Handlers narrow on
 *  `credential.kind`. This cycle wires only:
 *
 *    - `oauth`         — an OAuth source (google-workspace today): the `provider`
 *                        discriminator + the account identity (`accountId` — a
 *                        Google email; a GitHub login once that source lands) +
 *                        the middleware-refreshed access token, resolved at the
 *                        with-context.ts choke point. Handlers reach it via
 *                        `requireOAuth(ctx)` (handlers/shared.ts).
 *    - `none`          — keyless / the cross-account `_all` sentinel (B6 moves
 *                        the fan-out here; today the sentinel oauth-wraps its
 *                        placeholders, see proxy.ts).
 *
 *  The `service-token` variant (one secret in `SecretBackend`, no OAuth — e.g. a
 *  Telegram Bot) is declared so the type is complete, but its resolver lands
 *  with the first non-OAuth connector in Phase C (Q3 LOCKED — type exists, only
 *  Google is live this cycle).
 *
 *  SECURITY: `getAccessToken` / `token` are GETTERS, never serializable string
 *  fields — JSON.stringify drops functions so the bearer token can't leak via an
 *  accidental ToolContext serialization (the property the codebase relies on
 *  since review #2; see the file header). R6: a handler must NEVER fabricate an
 *  accountId/token for a non-oauth kind — `requireOAuth` centralizes the narrow
 *  so that shortcut is structurally unavailable. */
export type Credential =
  | {
      readonly kind: "oauth";
      readonly provider: "google" | "github" | "notion" | "x";
      readonly accountId: string;
      readonly getAccessToken: () => string;
    }
  | { readonly kind: "service-token"; readonly token: () => string }
  | { readonly kind: "none" };

export interface ToolContext {
  /** v1.64 Phase B (B2 — Credential union, D3b) — REPLACES the formerly
   *  required `email` + `getAccessToken` fields. The per-call credential for
   *  THIS tool's Source; see {@link Credential}. Under the live
   *  google-workspace source it is always the `oauth` variant; handlers narrow
   *  via `requireOAuth(ctx)` to read `.accountId` / `.getAccessToken()`. The
   *  cross-account `_all` fan-out keeps its own minimal AccountSubContext
   *  (with-all-accounts.ts) until B6 routes it through the shared pipeline. */
  readonly credential: Credential;
  /** v1.38 BLOCKER 3 — the privilege tier for THIS call, resolved ONCE at the
   *  with-context.ts choke point (next to the operator id). Handlers read
   *  `ctx.tier` for their defense-in-depth re-checks instead of re-reading the
   *  process-global `currentTier()`. Under Model A (each operator = own local
   *  process) this equals `currentTier()`; the field is where Model B's
   *  per-session tier will be sourced WITHOUT touching any handler. Required
   *  (not optional) so no site can silently fall back to the global read. */
  readonly tier: Tier;
  /** v1.64 Phase B (B1 — audit facade) — the per-call forensic sink. REPLACES
   *  the 10 optional `record*` closures (the v1.15 / v1.16 / v1.17 / v1.19 /
   *  v1.20 / v1.48 / v1.56 / v1.57 recorder sprawl). Handlers call
   *  `ctx.audit.record(channel, meta)`; see AuditSink + AuditSinkChannels above
   *  for the channel→value contract, and the `*AuditMeta` interfaces in audit.ts
   *  for each channel's calling pattern (record once — for mutation channels
   *  BEFORE the SDK call so the forensic row survives an SDK 5xx; last-write-wins
   *  by Map semantics). Required (not optional): every handler gets a real sink.
   *  The cross-account `_all` fan-out keeps its own minimal AccountSubContext
   *  (no sink) until B6 routes it through the shared pipeline. */
  readonly audit: AuditSink;
  /** v1.80 PR-3 — the calling operator's account-confinement set (the PR-2c
   *  `OperatorContext.allowedAccounts`), now carried per call so the egress
   *  layer can partition the recipient-allowlist SELF-SEND exemption to the
   *  operator's own accounts (docs/v1.80-model-b-pr3-self-partition-registry-reload.md
   *  §1). `null` = unrestricted (Model A / an unconfined operator) — the
   *  partition is a no-op. Required (not optional), the v1.38 `tier`
   *  precedent: an absent-field default would be a silent fail-OPEN. */
  readonly allowedAccounts: readonly string[] | null;
}

/** v1.74 PR-2c — the cross-account `_all` dispatch sentinel. These tools bypass
 *  `withToolContext` (they have no single resolved account — they fan out via
 *  `withAllAccounts`) and the registry shim DROPS `ctx`, so the per-operator
 *  identity that the fan-out needs (the operator id for the inner audit rows) rides
 *  on this WIDENED sentinel: `server.ts` builds it from the call's
 *  `OperatorContext`; the `_all` shims read `operator` / `allowedAccounts` off it
 *  and forward them into `withAllAccounts`. Both are null under Model A →
 *  byte-identical. (`allowedAccounts` itself moved onto `ToolContext` in v1.80
 *  PR-3 — the sentinel now only widens with `operator`.) */
export interface CrossAccountSentinel extends ToolContext {
  readonly operator: string | null;
}

export type ToolHandler<A = Record<string, unknown>, R = unknown> = (
  ctx: ToolContext,
  args: A,
) => Promise<R>;
