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

/** The normalized egress fields of a single-recipient service-token send: one
 *  recipient id + the RAW agent-authored body text (exactly what the gate scans).
 *  B6.1 wave A2a — RELOCATED here from egress-pipeline.ts (this file is the leaf
 *  of tools/, so `ToolContext.egress` below can carry the union without a type
 *  cycle through egress-pipeline → handlers); re-exported from egress-pipeline.ts
 *  so A1 importers stay valid. */
export interface ServiceTokenEgressShape {
  /** A2b sec-rev — runtime discriminant (the Credential.kind pattern): lets
   *  requireEgressResult fail LOUD on a variant mismatch instead of silently
   *  returning the wrong shape. */
  readonly kind: "service-token";
  readonly recipient: string;
  readonly body: string;
}

/** B6.1 wave A2a — the egress fields of x_post_create: the post text only (the
 *  recipient is the authenticated account itself, resolved from the ctx's oauth
 *  credential inside the descriptor's gate). `body` is the RAW text on extract and
 *  the gate-SANITIZED text when the gate RETURNS it (the transforming case). */
export interface XPostEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "x-post";
  readonly body: string;
}

/** B6.1 wave A2b — the egress fields of the YouTube comment writes
 *  (youtube_video_comment_post / youtube_comment_reply): the target `videoId`
 *  (the allowlist key) + the agent-authored comment/reply `body`. `body` is the
 *  RAW text on extract and the gate-SANITIZED text when the transforming gate
 *  RETURNS it. `parentCommentId` (REPLY only; absent for comment_post) is carried
 *  so the shared gate's DENIAL rows keep `parent_comment_id_hash` byte-identical to
 *  the two pre-A2b handler blocks — it is NOT part of the wire body (the handler
 *  re-validates for the requestBody `parentId`). */
export interface YoutubeCommentEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "youtube-comment";
  readonly videoId: string;
  readonly body: string;
  readonly parentCommentId?: string;
}

/** B6.1 wave A2b — the egress fields of youtube_video_update (videos.update
 *  snippet): the target `videoId` (the allowlist key) + the per-field PUBLIC
 *  snippet text. RAW on extract; the gate RETURNS the same variant with each field
 *  outbound-SANITIZED. `category_id` is intentionally NOT here — it is digit-only
 *  (`^[0-9]{1,3}$`), never sanitized, and read by the handler from its own
 *  validator; keeping it out of the shape preserves the "vetted bytes = the gate's
 *  return" contract for the free-text fields only. */
export interface YoutubeVideoUpdateEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "youtube-video-update";
  readonly videoId: string;
  readonly title: string;
  readonly description?: string;
  readonly tags?: readonly string[];
}

/** B6.1 wave A3+D — the egress fields of the two gmail compose writes
 *  (gmail_send / gmail_create_draft): the RAW header/body fields (extract's product)
 *  plus, only on the gate's RETURN (the transforming case), the `resolved` recipient
 *  arrays. Both tools share ONE `kind` + a `tool` discriminant (the youtube-comment
 *  precedent). `resolved` is ABSENT on the extracted shape and PRESENT on the gate's
 *  return — for gmail_send it is the contact-lookup-resolved recipients, for
 *  gmail_create_draft it is the parsed literal arrays (D3 — literal emails, no
 *  resolution). The handler reads `resolved` (+ `subject`/`body`) off ctx.egress to
 *  build the RFC 2822 message; a `resolved`-absent shape means the handler was
 *  reached without the gate's transform → fail-loud internal_routing_error. */
export interface GmailComposeEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "gmail-compose";
  readonly tool: "gmail_send" | "gmail_create_draft";
  readonly to: string;
  readonly cc: string;
  readonly bcc: string;
  readonly subject: string;
  readonly body: string;
  /** Present only on the gate's RETURN (the transformed shape): the parsed
   *  to/cc/bcc arrays — contact-resolved for gmail_send, parsed literals for
   *  gmail_create_draft. Sizes preserve the parsed 1:1 order. */
  readonly resolved?: { readonly to: string[]; readonly cc: string[]; readonly bcc: string[] };
}

/** B6.1 wave A (github sweep) — the egress fields of the 7 GitHub write tools. A
 *  CHECK-ONLY shape: the gate (enforceGithubWriteEgressGates / MergeEgressGates /
 *  ReviewEgressGates) validates and returns void, so the handler never reads this off
 *  ctx.egress — its own already-validated args are the vetted bytes. `owner`/`repo` key
 *  the default-deny target allowlist; `body` is the combined agent-authored outbound text
 *  the F3a secret-shape scan sees (title\nbody for create/update, the join for labels /
 *  merge-commit text, "" for a bare APPROVE), reproduced verbatim from the handler's
 *  pre-gate assembly by the descriptor's extract (single-source: same exported validator).
 *  `event` is present ONLY for github_create_pull_request_review (the EVENT-CONDITIONAL
 *  gate routes APPROVE → approve allowlist, else → write allowlist). */
export interface GithubWriteEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "github-write";
  readonly tool:
    | "github_create_issue"
    | "github_create_issue_comment"
    | "github_update_issue"
    | "github_create_pull_request"
    | "github_merge_pull_request"
    | "github_create_pull_request_review"
    | "github_set_issue_labels";
  readonly owner: string;
  readonly repo: string;
  readonly body: string;
  /** review only — the review verdict routing the event-conditional allowlist. */
  readonly event?: "APPROVE" | "REQUEST_CHANGES" | "COMMENT";
}

/** B6.1 wave A (notion sweep) — the egress fields of the 3 Notion write tools. A
 *  CHECK-ONLY shape (model B — F3a secret-shape only, NO target allowlist, so no
 *  owner/repo). `body` is the combined agent-authored text the secret-shape scan sees:
 *  the raw title(\ntext) for a page-parent create, the buildNotionProperties scan join for
 *  a db-parent create / a properties update, the raw text for append — reproduced verbatim
 *  from the handler's pre-gate assembly by the descriptor's extract (single-source: same
 *  exported prepare function). The handler never reads this off ctx.egress. */
export interface NotionWriteEgressShape {
  /** A2b sec-rev — runtime discriminant; see ServiceTokenEgressShape.kind. */
  readonly kind: "notion-write";
  readonly tool: "notion_create_page" | "notion_append_blocks" | "notion_update_page";
  readonly body: string;
}

/** B6.1 wave A2a — every shape a pipeline-fired egress descriptor can extract /
 *  return (tools/egress-pipeline.ts). A new pipeline-migrated tool with a novel
 *  field set adds its shape to this union. */
export type EgressShape =
  | ServiceTokenEgressShape
  | XPostEgressShape
  | YoutubeCommentEgressShape
  | YoutubeVideoUpdateEgressShape
  | GmailComposeEgressShape
  | GithubWriteEgressShape
  | NotionWriteEgressShape;

export interface ToolContext {
  /** v1.64 Phase B (B2 — Credential union, D3b) — REPLACES the formerly
   *  required `email` + `getAccessToken` fields. The per-call credential for
   *  THIS tool's Source; see {@link Credential}. Under the live
   *  google-workspace source it is always the `oauth` variant; handlers narrow
   *  via `requireOAuth(ctx)` to read `.accountId` / `.getAccessToken()`. The
   *  cross-account `_all` fan-out builds a per-account ToolContext carrying the
   *  same oauth variant (with-all-accounts.ts, v1.121 B6.1 wave C). */
  readonly credential: Credential;
  /** v1.38 BLOCKER 3 — the privilege tier for THIS call, resolved ONCE at the
   *  with-context.ts choke point. Handlers read
   *  `ctx.tier` for their defense-in-depth re-checks instead of re-reading the
   *  process-global `currentTier()` (one operator per process, so the two
   *  agree). Required (not optional) so no site can silently fall back to the
   *  global read. */
  readonly tier: Tier;
  /** v1.64 Phase B (B1 — audit facade) — the per-call forensic sink. REPLACES
   *  the 10 optional `record*` closures (the v1.15 / v1.16 / v1.17 / v1.19 /
   *  v1.20 / v1.48 / v1.56 / v1.57 recorder sprawl). Handlers call
   *  `ctx.audit.record(channel, meta)`; see AuditSink + AuditSinkChannels above
   *  for the channel→value contract, and the `*AuditMeta` interfaces in audit.ts
   *  for each channel's calling pattern (record once — for mutation channels
   *  BEFORE the SDK call so the forensic row survives an SDK 5xx; last-write-wins
   *  by Map semantics). Required (not optional): every handler gets a real sink.
   *  The cross-account `_all` fan-out hands each per-account sub-call its OWN
   *  accumulator-backed sink (with-all-accounts.ts, v1.121 B6.1 wave C). */
  readonly audit: AuditSink;
  /** v1.116 — set to true by the centralized egress gates (tools/egress.ts) the moment
   *  a composite enforce*EgressGates entry point is INVOKED (before its own checks run,
   *  so a gate that DENIES still counts as fired). Read by the choke points after a
   *  successful handler return: direction:"outbound-write" + flag unset ⇒
   *  internal_routing_error (the runtime backstop behind the static
   *  egress-callsite.test.ts sentinel). Mutable by design; never reset within a call. */
  egressGateFired?: boolean;
  /** B6.1 wave A2a — the pipeline-fired gate's TRANSFORMED result. When a tool's
   *  registry def carries an egress descriptor whose gate RETURNS a shape (the
   *  transforming case — x_post_create's gate returns the outbound-SANITIZED text),
   *  the choke point stores it here BEFORE the handler runs. A transforming tool's
   *  handler MUST put this (via requireEgressResult, tools/egress-pipeline.ts), not
   *  its own recomputation, on the wire — the gate's return value IS the vetted
   *  bytes. Absent for void-gate descriptor tools (the 5 A1 service-token sends)
   *  and for every non-descriptor tool. Mutable by design (set once per attempt;
   *  carried across the handler-stage 401-retry ctx rebuild, never re-fired there). */
  egress?: EgressShape;
  /** Fingerprint of a send-approval that THIS call already consumed. The 401-retry
   *  ctx rebuild copies it so a handler-called `requireSendApproval` (drive_share_file
   *  anyone) does not burn the owner's approval on the transparent refresh retry.
   *  Pipeline-fired tools do not need this: their gate runs once and is carried via
   *  `egress`. Mutable; never reset within a call. */
  sendApprovalConsumedFingerprint?: string;
}

export type ToolHandler<A = Record<string, unknown>, R = unknown> = (
  ctx: ToolContext,
  args: A,
) => Promise<R>;
