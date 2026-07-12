// ToolDef shape — extracted verbatim from the former monolithic src/tools/registry.ts.
import type { Tier } from "../../tier";
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
   *  authorize / mapError / skipFields strategies from this field. Only a
   *  label this cycle — nothing branches on it yet. */
  source?: string;
  /** Classification LABEL for the data-flow direction — read by the test-only
   *  egress sentinels (`egress-coverage.test.ts` + `egress-callsite.test.ts`),
   *  NOT by any runtime choke point today. `"outbound-write"` ⇔ membership in
   *  `CENTRALIZED_EGRESS` (the tool reaches an external party and is gated by
   *  a centralized `enforce*EgressGates` call in its handler). Handler-gated
   *  external tools (`HANDLER_GATED_EXTERNAL` — drive share, YouTube comment/
   *  video writes) MUST leave this field unset; the coverage sentinel enforces
   *  both directions of that invariant. `"inbound-read"` (or unset on a non-
   *  external tool) means no egress classification. Pipeline-fired egress
   *  (auto-routing off this field inside with-context) remains future work. */
  direction?: "inbound-read" | "outbound-write";
}
