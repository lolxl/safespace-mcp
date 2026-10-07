// ToolDef shape — extracted verbatim from the former monolithic src/tools/registry.ts.
import type { Tier } from "../../tier";
import type { EgressDescriptor } from "../egress-pipeline";
import type { ToolHandler } from "../types";

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  requiredScopes: readonly string[];
  handler: ToolHandler;
  /** v2.0: minimum tier required for this tool to appear in tools/list.
   *  Drive share is special-cased — exposed at `write` tier but the handler
   *  rejects share_type="anyone" unless tier=share. See driveShareFile. */
  min_tier: Tier;
  /** v1.14 Phase 1: when true, proxy dispatches this tool OUTSIDE
   *  `withToolContext` (no single-account resolution / refresh / sanitize /
   *  audit). The handler is expected to use `withAllAccounts` internally,
   *  which owns its own per-account refresh + per-account sanitize + per-
   *  account audit + outer aggregate audit. The registry-stored `handler`
   *  is still typed `ToolHandler`, but for cross-account tools it ignores
   *  the `ctx` argument (proxy passes a sentinel). */
  cross_account?: boolean;
  /** v1.64 Phase B (B0 relabel) — the safety-gateway Source this tool's
   *  connector belongs to (docs/safety-gateway-thesis.md §5 / v1.64 §3 B0).
   *  Optional; defaults to "google-workspace" (the flagship reference
   *  connector — the ONLY Source this cycle). Threaded onto the audit row so
   *  forensics can attribute a call to its Source before any non-Google
   *  connector exists. A future connector (Telegram bot, etc.) sets its own
   *  id; the pipeline (B2+) resolves that Source's resolveCredential /
   *  authorize / skipFields strategies from this field. Only a
   *  label this cycle — nothing branches on it yet. */
  source?: string;
  /** Classification LABEL for the data-flow direction — read by the test-only
   *  egress-coverage sentinel (`egress-coverage.test.ts`) and
   *  by the choke points' post-handler tripwire (an `"outbound-write"` call that
   *  finished without its gate firing → `internal_routing_error`). `"outbound-write"` ⇔ membership in
   *  `PIPELINE_EGRESS` (the tool reaches an external party and its
   *  `tools/egress.ts` gate is fired by the choke point via its `egress`
   *  descriptor). Handler-gated external tools (`HANDLER_GATED_EXTERNAL` — drive
   *  share) MUST leave this field unset; the coverage sentinel enforces both
   *  directions of that invariant. `"inbound-read"` (or unset on a non-external
   *  tool) means no egress classification. */
  direction?: "inbound-read" | "outbound-write";
  /** B6.1 wave A1 — the PIPELINE-FIRED egress descriptor (tools/egress-pipeline.ts).
   *  When present, the tool's choke point (with-nonoauth-context.ts for the
   *  service-token sends, with-context.ts for the OAuth writes) fires extract →
   *  gate BEFORE the handler runs; the handler must NOT call the gate itself. When
   *  the gate TRANSFORMS the content (sanitize / rewrite), the handler sends the
   *  gate's result (`requireEgressResult`), never the raw args; a check-only gate
   *  leaves the handler to build the body from the validated args. The call-site sentinel (egress-callsite.test.ts) enforces both
   *  directions: the descriptor module must call the tool's gate wrapper, and the
   *  handler file must not (anti-double-fire). Carried by every PIPELINE_EGRESS
   *  tool (egress-coverage.sets.ts) — every external-reaching write except the
   *  bespoke-gated drive_share_file; unset on every other tool. */
  egress?: EgressDescriptor;
}
