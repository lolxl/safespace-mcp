// v1.65/v1.66 Phase C — the NON-OAUTH choke point for class-B (service-token: LINE
// v1.66, Telegram Bot v1.68) and class-C (keyless, web-fetch) connectors.
//
// docs/v1.66-line-oa-connector.md §3 (generalized from the v1.65
// with-keyless-context). The proxy routes a tool whose Source has
// `authModel !== "oauth"` here instead of through `withToolContext` (which is
// wholly Google-OAuth-shaped: account resolve → scope pre-check → token refresh →
// 401 force-refresh retry). A non-OAuth tool has none of that, so it gets a thin,
// mono-purpose choke point — the same "two specialized choke points" shape as
// `withAllAccounts` already is alongside `withToolContext`.
//
// v1.66 — THE SOURCE-STRATEGY DISPATCH. This choke point no longer hard-codes the
// credential: it calls `source.authorize` + `source.resolveCredential`
// polymorphically (tools/source.ts). web-fetch resolves `{kind:"none"}`; LINE reads
// its channel token → `{kind:"service-token"}`. NO `switch (authModel)` here — the
// authModel is read ONCE at the proxy router to pick this choke point; the strategy
// objects do the rest.
//
// What this SHARES with withToolContext (the universal envelope): operator + tier
// resolution, the F4 autonomous-delete + F1 write-burst gates, the per-source
// `sanitize(..., source.skipFields)` wrap, and a real audit sink threaded onto one
// `auditEnd` row. (Errors are mapped by each HANDLER, then re-thrown verbatim — the
// v1.65 posture; there is deliberately NO per-source error-mapping strategy on the
// Source — a future B6.1 shared pipeline would introduce an error-mapping seam.)
//
// What it DELIBERATELY omits: account resolution, scope check, token refresh, the
// 401 retry (no in-band token refresh for keyless or service-token). The credential
// is the honest `{kind:"none"}` / `{kind:"service-token"}`; `requireOAuth(ctx)`
// throws on both (a non-OAuth handler must never reach for a Google account).
//
// EGRESS (B6.1 wave A1 — PIPELINE-FIRED): an outbound non-OAuth tool (the 5
// service-token sends) carries an egress descriptor on its ToolDef
// (tools/egress-pipeline.ts); THIS choke point fires extract (the tool's own arg
// validation) → gate (the composite tools/egress.ts gate) BEFORE the handler runs,
// so egress enforcement is pipeline-owned, not handler-remembered. The gmail path
// (with-context.ts) keeps the B3 handler-called posture.
//
// withToolContext is UNTOUCHED by this file — the Google path stays byte-identical.

import * as crypto from "node:crypto";
import { auditEnd, auditStart, pickAuditErrorForensics } from "../audit";
import { MCPError } from "../errors";
import { envOperatorContext, type OperatorContext } from "../identity/operator-context";
import { enforceAutonomousDeleteDeny } from "../policy/autonomous-mode";
import { classifyWriteTool, enforceWriteBurst } from "../policy/write-burst";
import { sanitize } from "../sanitize";
// v1.66.1 (B6.1a) — the shared per-call audit sink + forensic block (replaces the
// inline sink/MetaMapStore this file used to duplicate from with-context.ts).
import { createAuditAccumulator } from "./audit-accumulator";
import { sourceFor } from "./source";
import { TOOL_REGISTRY } from "./registry";
import type { ToolContext, ToolHandler } from "./types";

export async function withNonOAuthContext(
  toolName: string,
  args: Record<string, unknown>,
  handler: ToolHandler,
  // v1.74 PR-2a — the resolved northbound identity (operator id + tier) for this
  // call. Defaults to the env-backed context (Model A), resolved PER CALL; the
  // proxy passes the per-call `op`. Mirrors withToolContext. (allowedAccounts is
  // irrelevant here — non-OAuth sources have no per-operator account; §6.2.)
  op: OperatorContext = envOperatorContext(),
): Promise<unknown> {
  const start = Date.now();
  const toolDef = TOOL_REGISTRY[toolName];
  // The non-OAuth Source (web-fetch keyless | line service-token). web-fetch's
  // `skipFields` is EMPTY (wrap every field); line's is its opaque-id set.
  const source = sourceFor(toolDef);
  // v1.72 (B6.1 partial) — narrow Source to NonOAuthSource. The proxy routes only
  // authModel !== "oauth" tools here (proxy.ts), so this honest defense-in-depth
  // assertion of that routing contract also narrows `source` so `resolveCredential`
  // takes NO deps (an OAuth source's account/refresh deps are structurally absent
  // here). Unreachable in production, mirroring the with-context.ts narrow.
  if (source.authModel === "oauth") {
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }

  // args is the caller-supplied MCP args; no token is ever merged into it (keyless
  // has none; the service-token is read inside resolveCredential and held only on
  // the credential getter), so the hash input is structurally token-free.
  const argsHash = `sha256:${crypto.createHash("sha256").update(JSON.stringify(args)).digest("hex")}`;
  // v1.74 PR-2a — operator + tier from the resolved `op` (Model A: env via the
  // default EnvOperatorResolver; Model B PR-2b: the connection identity).
  const operator = op.operatorId;
  const tier = op.tier;
  // email is null: a non-OAuth call has no Google account. The audit row's `source`
  // field ("web-fetch" / "line") disambiguates it from a Google `account: null` row.
  auditStart({ tool: toolName, email: null, argsHash, operator });

  let status: "ok" | "error" = "error";
  let errorCode: number | undefined;
  let errorForensics: Record<string, unknown> | undefined;
  // v1.66.1 (B6.1a) — the SAME shared audit observability envelope with-context
  // uses (tools/audit-accumulator.ts): the AuditSink + the 3 scalar row channels +
  // the 7 AUDIT_META_CHANNELS aggregator, in ONE place (no longer duplicated here).
  // web-fetch records nothing → forensicFields() are all undefined → auditEnd omits
  // them → the web-fetch row stays byte-identical to v1.65. A LINE push records
  // outboundSecretShape (interactive secret-shape) via the egress gate.
  const auditAcc = createAuditAccumulator();

  try {
    // v1.66 — dispatch credential resolution through the source strategies. For
    // web-fetch: authorize() is a no-op, resolveCredential() → {kind:"none"}. For
    // line: authorize() is a no-op (tier proxy-enforced), resolveCredential() reads
    // the channel token → {kind:"service-token"} (throws line_api_failed{no_token}
    // if unconfigured). NO 401 retry (no in-band refresh). These run INSIDE the
    // errorCode-stamping try so a resolve failure (e.g. line no_token) is recorded
    // on the audit row like a handler throw — web-fetch is unaffected (its
    // authorize is a no-op + resolveCredential never throws).
    source.authorize(toolDef, {});
    const cred = await source.resolveCredential(toolDef);
    // v1.80 PR-3 — `op.allowedAccounts` rides onto the ctx (see with-context.ts);
    // null under Model A / for unconfined operators → the self-send partition no-ops.
    const ctx: ToolContext = {
      credential: cred,
      tier,
      audit: auditAcc.sink,
      allowedAccounts: op.allowedAccounts,
    };
    // Gate-by-construction: a non-OAuth WRITE inherits F4 + F1. Both are no-ops for
    // a read (classifyWriteTool "exempt"; not a permanent-delete); a LINE push
    // (min_tier "share", a write) is rate-capped by F1 here.
    enforceAutonomousDeleteDeny(toolName);
    // v1.92 — per-operator burst window (Model A null → shared sentinel bucket).
    enforceWriteBurst(classifyWriteTool(toolName, toolDef?.min_tier), op);
    // B6.1 wave A1 — PIPELINE-FIRED egress for tools carrying an egress descriptor
    // (the 5 service-token sends; tools/egress-pipeline.ts): extract (the tool's own
    // arg validation — throws its plain-Error messages) then the composite gate
    // (sets ctx.egressGateFired; throws -32035 / -32019 on denial), both BEFORE the
    // handler. INSIDE the errorCode-stamping try so a denial lands on the audit row
    // exactly like a handler throw. Production rejection order preserved:
    // resolveCredential (no_token) above still precedes extract; F4 + F1 precede
    // both; the handler re-runs the same pure validator as defense-in-depth.
    const eg = toolDef?.egress;
    if (eg !== undefined) {
      const shape = eg.extract(args);
      await eg.gate(ctx, shape);
    }
    // The handler runs the connector (for a descriptor-carrying tool the egress gate
    // has already fired above; the handler must not fire it again).
    const raw = await handler(ctx, args);
    // v1.116 — choke-point egress tripwire (the class-B/C twin of the with-context.ts one).
    // A tool LABELED direction:"outbound-write" whose call completed WITHOUT its centralized
    // egress gate (tools/egress.ts sets ctx.egressGateFired) → a loud, audited failure.
    // Post-A1 every outbound-write tool routed here carries a descriptor, so the pipeline
    // fires the gate itself and this check is a RESIDUAL backstop (it would catch a future
    // outbound-write tool added with neither a descriptor nor a handler-called gate). No
    // 401-retry here (no in-band refresh), so `ctx` is the single instance the handler ran
    // with. PREVENTION stays with the static call-site sentinel (egress-callsite.test.ts).
    // Inside the errorCode-stamping try so the throw lands on the audit row like a handler
    // throw.
    if (toolDef?.direction === "outbound-write" && ctx.egressGateFired !== true) {
      throw new MCPError("internal_routing_error", { reason: "egress_gate_not_fired" });
    }
    // Per-source sanitize. sanitize() is itself fail-closed (any internal throw →
    // MCPError("sanitize_failed")), so a sanitize failure flows through the
    // errorCode stamping below exactly like a handler throw.
    const sanitized = sanitize(raw, { toolName }, source.skipFields);
    status = "ok";
    return sanitized;
  } catch (err) {
    if (err instanceof MCPError) {
      errorCode = err.code;
      errorForensics = pickAuditErrorForensics(err.errorData);
    }
    // Re-throw verbatim (v1.65 behavior, byte-identical for web-fetch). Each
    // non-OAuth HANDLER maps its OWN expected errors to MCPError before they reach
    // here (the web-fetch handler calls mapWebFetchError; the LINE handler throws
    // line_api_failed directly), so a deliberate plain-Error from a handler (e.g.
    // web_fetch input validation) propagates unchanged. There is deliberately no
    // per-source error-mapping strategy in this catch — a future B6.1 shared
    // pipeline would introduce an error-mapping seam.
    throw err;
  } finally {
    // Fire-and-forget standard per-call row. `source.id` = "web-fetch" / "line";
    // `account` = null. The scalar + meta channels are threaded for non-OAuth
    // outbound tools; undefined for a keyless read (omitted from the row).
    void auditEnd({
      tool: toolName,
      source: source.id,
      email: null,
      argsHash,
      operator,
      status,
      durationMs: Date.now() - start,
      sanitize: "applied",
      errorCode,
      errorForensics,
      // v1.66.1 (B6.1a) — single-source forensic block (3 scalars + 7 meta channels),
      // shared with with-context.ts. web-fetch records none (all undefined → omitted).
      ...auditAcc.forensicFields(),
    });
  }
}
