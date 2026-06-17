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
  /** v1.64 Phase B (B0 relabel) — the data-flow direction, the label the
   *  centralized egress gate (B3) will key off. "outbound-write" = the call
   *  sends agent-authored content to a recipient OUTSIDE the user's own
   *  surface (gmail_send / gmail_create_draft — a draft is a latent send) and
   *  so must pass the recipient/secret/tainted egress gates. "inbound-read"
   *  (or unset) = no egress gate. ONLY a label this cycle: B3 wires it to
   *  enforceEgressGates; until then nothing reads it (the gates stay inline in
   *  handlers/gmail.ts, the as-built §1 reality). */
  direction?: "inbound-read" | "outbound-write";
}
