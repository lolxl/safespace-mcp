// withToolContext middleware — wraps every tool handler with the 6 cross-cutting
// concerns from docs/DESIGN.md §withToolContext Middleware (Issue 6A).
//
// Step 3 layout: resolve account → validate via accounts.json → refresh access
// token → audit start → run handler (with 1× force-refresh retry on 401) →
// map upstream errors → sanitize (Step 4 stub) → audit end → set lastUsed.
//
// Step 3 deliberately does NOT update accounts.json `last_used_at` on every
// successful call — that's a CLI-display concern (Step 5/6). The in-memory
// lastUsedAccount is what controls "default account" dispatch.

import * as crypto from "node:crypto";
import {
  // v1.66.1 (B6.1a) — AUDIT_META_CHANNELS drives the finally-block mutex check; the
  // sink + MetaMapStore aggregator moved into tools/audit-accumulator.ts.
  AUDIT_META_CHANNELS,
  auditEnd,
  auditStart,
  pickAuditErrorForensics,
} from "../audit";
// v1.70 (G1) — account resolution (readActive + loadIndex) lifted into the
// google-workspace source's resolveAccount (tools/source.ts); this choke point
// keeps only the 401-cleanup removeAccount.
import { removeAccount } from "../auth/keychain";
// v1.37 BLOCKER 1: the 401-cleanup deleteToken default routes through the facade.
import { deleteToken } from "../auth/token-store";
import {
  // v1.66 — refreshAccessToken moved into the google-workspace source's
  // resolveCredential (tools/source.ts); with-context only keeps the 401-cleanup
  // cache invalidation + the RefreshDeps type (WithContextDeps extends it).
  invalidateTokenCache,
  type RefreshDeps,
} from "../auth/refresh";
import { MCPError } from "../errors";
import { classifyWriteTool, enforceWriteBurst } from "../policy/write-burst";
import { enforceAutonomousDeleteDeny } from "../policy/autonomous-mode";
import { envOperatorContext, type OperatorContext } from "../identity/operator-context";
import { sanitize } from "../sanitize";
import { sourceFor } from "./source";
import { createAuditAccumulator } from "./audit-accumulator";
import type { UpstreamError } from "./handlers/shared";
import { TOOL_REGISTRY } from "./registry";
import type { EgressShape, ToolContext, ToolHandler } from "./types";

// v1.70 (G1) — keyed by Source.id so a google tool's last-used can never be a
// github account (and vice-versa) = the cross-provider-confusion backstop's
// resolution-state layer. The exported getters/setter default the source to
// "google-workspace", so existing single-provider callers + tests are unchanged.
const lastUsedAccount = new Map<string, string>();

// The last-used account per source (the weakest default-selection tier).
export function getLastUsed(sourceId = "google-workspace"): string | null {
  return lastUsedAccount.get(sourceId) ?? null;
}

export function setLastUsed(account: string, sourceId = "google-workspace"): void {
  lastUsedAccount.set(sourceId, account);
}

export function _resetLastUsedForTests(): void {
  lastUsedAccount.clear();
}

/** Test-injection seams.
 *
 *  Production callers leave all fields undefined → defaults to the real I/O
 *  implementations (Keychain, fetch, active-account file). Tests inject
 *  stubs to control side effects without setting up real Google API mocks.
 *
 *  Keep this interface STRICTLY for `*Impl` / function-overrides. Runtime
 *  behaviour flags belong in `WithContextOptions` (5th param) — mixing the
 *  two makes it ambiguous whether a field is test-only or production-callable. */
export interface WithContextDeps extends RefreshDeps {
  /** Widened in PR-1 (v1.1 labels) to include `scopes` so the scope-mismatch
   * pre-check (HIGH from sec-rev) can read the account's granted scope set
   * without doing a second load. `scopes` optional for older accounts.json
   * entries written before this field existed — the check skips gracefully
   * in that case and lets the upstream 403 → `scope_mismatch` path handle it. */
  loadIndexImpl?: () => Promise<{
    accounts: Array<{ email: string; scopes?: string[] }>;
  }>;
  /** Injection seam for tests; defaults to `readActive` (auth/active.ts). */
  readActiveImpl?: () => Promise<string | null>;
}

/** Runtime behaviour flags.
 *
 *  Production-callable. Separate from `WithContextDeps` so the type tells
 *  the maintainer "this field is meant to be set from real code, not just
 *  tests".
 *
 *  Currently one field — `skipSanitize`. Add new behaviour flags here. */
export interface WithContextOptions {
  /** Skip the sanitize `<untrusted-source>` wrap.
   *
   *  ⚠️ Caller asserts: consumer is **NOT** an LLM. Used by `safespace exec
   *  --raw` for non-LLM CLI clients (cron jobs, Python pipelines) where the
   *  wrap is parsing noise rather than security. Auth / kill-switch / audit /
   *  401-retry all intact — only the sanitize step is skipped. Audit records
   *  `sanitize: "bypassed"` on every such call so abuse is traceable.
   *
   *  NEVER set this from the MCP server path. */
  skipSanitize?: boolean;
}

export async function withToolContext(
  toolName: string,
  args: Record<string, unknown> & { account_id?: string },
  handler: ToolHandler,
  deps: WithContextDeps = {},
  opts: WithContextOptions = {},
  // v1.74 PR-2a — the resolved identity for this call. Defaults to the env-backed
  // context, resolved PER CALL (never snapshot) so callers (cli exec, tests) need
  // not pass one; the proxy passes a per-call `op` resolved once at the dispatch
  // choke point.
  op: OperatorContext = envOperatorContext(),
): Promise<unknown> {
  // Defensive: cross_account tools MUST be dispatched outside withToolContext
  // (proxy.ts cross-account branch). If we ever route one through here, the
  // single-account `resolve email → refresh → audit` flow would race against
  // `withAllAccounts` doing the same per-account, and the audit shape would
  // diverge silently. Fail loud.
  const earlyToolDef = TOOL_REGISTRY[toolName];
  if (earlyToolDef?.cross_account) {
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  const start = Date.now();

  // v1.70 (G1) — resolve this tool's safety-gateway Source FIRST, then resolve the
  // active account THROUGH it: account resolution is now a per-source strategy
  // (`source.resolveAccount`), so a google tool resolves a google account and a
  // github tool a github account — never crossed (the cross-provider backstop).
  const toolDef = earlyToolDef;
  // The Source drives per-source sanitize skipFields (B5), the audit-row `source`
  // id, and (v1.66/v1.70) the resolveAccount / authorize / resolveCredential
  // strategies.
  const source = sourceFor(toolDef);
  // v1.72 (B6.1 partial) — narrow Source to OAuthSource. The proxy routes ONLY
  // authModel:"oauth" tools to this choke point (proxy.ts dispatch reads
  // source.authModel), so this is an honest defense-in-depth assertion of that
  // routing contract; it also narrows `source` so `resolveAccount` is statically
  // present and `resolveCredential` requires a resolved accountId — REPLACING the
  // pre-v1.72 `if (!source.resolveAccount) throw` here + the `if (accountId == null)
  // throw` tripwires in source.ts with a compile-time guarantee. Unreachable in
  // production exactly like the old `!resolveAccount` throw.
  if (source.authModel !== "oauth") {
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  // args is the caller-supplied MCP tool args dict; tokenSet is held in
  // this local scope and NEVER merged into args, so access_token cannot
  // feed the hash input. (sec-rev 5.8 LOW guard against future regression.)
  const argsHash = `sha256:${crypto.createHash("sha256").update(JSON.stringify(args)).digest("hex")}`;
  // v1.38 BLOCKER 3 / v1.74 PR-2a — the privilege tier for this call comes from
  // `op` (currentTier()/$SAFESPACE_TIER via the resolver).
  // Threaded as ctx.tier (below) for handler defense-in-depth re-checks.
  const tier = op.tier;
  // Pre-flight (account → scope → credential) runs before the audited try below,
  // so a failure here writes its own terminal row instead of leaving none.
  let preflightAccountId: string | null = null;
  const preflight = async () => {
    // Account resolution lifted VERBATIM into source.resolveAccount (order: explicit
    // args.account_id → active-account file → per-source in-memory last-used →
    // validate against the index; account_not_found payloads byte-identical).
    const resolved = await source.resolveAccount(toolDef, {
      explicitAccountId:
        typeof args.account_id === "string" ? args.account_id : undefined,
      lastUsed: getLastUsed(source.id),
      readActiveImpl: deps.readActiveImpl,
      loadIndexImpl: deps.loadIndexImpl,
    });
    preflightAccountId = resolved.accountId;

    // v1.66 — the OAuth scope pre-check is the source's `authorize` strategy (thesis
    // §4: the OAuth scope machinery demotes to the source). It reads the account's
    // PERSISTED granted scopes (not the token) and throws scope_mismatch BEFORE any
    // token refresh — byte-identical to the pre-v1.66 inline check.
    source.authorize(toolDef, { account: resolved });

    // v1.66 — resolve the per-call credential via the source strategy. For
    // google-workspace this refreshes the active account's access token and returns
    // {kind:"oauth"} with a getter over it. The 401 force-refresh-retry CONTROL FLOW
    // below stays in this choke point, gated on source.refreshable (a non-refreshing
    // OAuth token like a GitHub OAuth-App token skips it). The literal runPipeline
    // collapse is B6.1 — docs/v1.66-line-oa-connector.md §1.2.
    const cred = await source.resolveCredential(toolDef, {
      accountId: resolved.accountId,
      refresh: deps,
    });
    return { accountId: resolved.accountId, cred };
  };
  const preflightResult = await preflight().catch(async (err: unknown) => {
    // Awaited before the rethrow: a CLI caller may exit as soon as this rejects.
    await auditEnd({
      tool: toolName,
      source: source.id,
      email: preflightAccountId,
      argsHash,
      status: "error",
      durationMs: Date.now() - start,
      sanitize: opts.skipSanitize ? "bypassed" : "applied",
      errorCode: err instanceof MCPError ? err.code : undefined,
      errorForensics: err instanceof MCPError ? pickAuditErrorForensics(err.errorData) : undefined,
    });
    throw err;
  });
  const accountId = preflightResult.accountId;
  let cred = preflightResult.cred;

  auditStart({ tool: toolName, email: accountId, argsHash });

  let status: "ok" | "error" = "error";
  // v1.24 Phase 1 Item 2 — captures the numeric MCPError code at every
  // throw path inside the main try-block so `auditEnd()` can stamp
  // `error_code: <number>` on the JSONL row. Set ONLY when the thrown
  // error is an MCPError (PRESENCE-as-signal per design §2.2 / Q3 LOCKED
  // — plain `Error` throws leave the field ABSENT). The catch-all
  // outermost wrap below intercepts every throw site (handler throw,
  // 401-retry second-attempt throw, post-401 refresh_token_invalid
  // throw, mapHttpError-wrapped throw, sanitize_failed re-wrap) so a
  // future regression that adds a new throw site is auto-covered. */
  let errorCode: number | undefined;
  // v1.33 (d) — whitelisted forensic fields lifted from a thrown MCPError's
  // data for the audit-row GAP-FILL safety net (see audit.ts
  // pickAuditErrorForensics). ABSENT unless an MCPError carrying whitelisted
  // forensic fields was thrown; auditEnd gap-fills ONLY keys not already
  // emitted by a channel serialize (collision-safe + byte-stable no-op for
  // handlers that record their meta).
  let errorForensics: Record<string, unknown> | undefined;
  // v1.66.1 (B6.1a) — the per-call audit observability envelope (the AuditSink +
  // the 3 scalar row channels + the 8 AUDIT_META_CHANNELS aggregator) is now ONE
  // shared `createAuditAccumulator()` (tools/audit-accumulator.ts) consumed by both
  // this OAuth choke point AND withNonOAuthContext — eliminating the byte-duplicated
  // sink + auditEnd field-list (architecture review P0-1 / thesis D6). Behavior is
  // byte-identical: same record() switch, same forensic field set. `auditAcc.metas`
  // feeds the mutual-exclusion mutex check in the finally below; `forensicFields()`
  // is spread into auditEnd.
  const auditAcc = createAuditAccumulator();
  try {
    // `ctx` is a `let` rebuilt per credential via a {credential, tier, audit}
    // literal, so the 401 force-refresh retry below can swap in a fresh
    // {kind:"oauth"} credential (the google-workspace source's resolveCredential
    // owns the tokenSet; each call returns a fresh getter, and the choke point
    // rebuilds ctx — behavior-equivalent: the retried handler reads the
    // force-refreshed token either way). The audit sink is stable across the rebuild.
    let ctx: ToolContext = {
      credential: cred,
      tier,
      audit: auditAcc.sink,
    };

    // v1.24 Phase 1 Item 2 — wrap handler + sanitize body with a single
    // catch-all that captures the numeric MCPError code before re-throw.
    // Centralised at this layer so EVERY throw site below (handler-thrown
    // MCPError, 401-second-retry refresh_token_invalid, mapHttpError-wrapped
    // scope_mismatch / rate_limited, sanitize_failed re-wrap) is covered
    // without per-site edits. Plain `Error` throws leave errorCode
    // undefined so auditEnd omits the field (PRESENCE-as-signal). Re-throw
    // preserves the thrown value verbatim; proxy.ts toJsonRpc surfaces the
    // same code to the JSON-RPC reply.
    try {
      // v1.54 F4 — autonomous-mode permanent-delete hard-deny (Autonomy
      // Hardening). When SAFESPACE_AUTONOMOUS=true, permanent-delete tools (F1's
      // PERMANENT_DELETE_TOOLS set) are denied here — the soft "ask the user
      // first" control is meaningless unattended. Fires BEFORE the F1 burst
      // counter so a denied delete does NOT consume the delete bucket's budget,
      // and inside this try so the thrown -32033 flows through the error-code
      // audit stamping like a handler throw. No-op when not autonomous → v1.53
      // behavior is byte-identical.
      enforceAutonomousDeleteDeny(toolName);
      // v1.52 F1 — universal write/delete burst guard (Autonomy Hardening).
      // Reads (min_tier === "read") are exempt; write / permanent-delete calls
      // are rate-capped in a rolling window. Inside this try so a thrown -32032
      // flows through the error-code audit stamping like a handler throw.
      // One process-wide write window and delete window; limits come from env.
      enforceWriteBurst(classifyWriteTool(toolName, TOOL_REGISTRY[toolName]?.min_tier));
      // B6.1 wave A2a — PIPELINE-FIRED egress for OAuth-routed tools carrying an
      // egress descriptor (every OAuth PIPELINE_EGRESS write — gmail, GitHub, Notion,
      // X, YouTube; tools/egress-pipeline.ts — the
      // with-context twin of the A1 firing site in with-nonoauth-context.ts):
      // extract (the tool's own arg validation — throws its plain-Error messages)
      // then the composite gate (sets ctx.egressGateFired; throws on denial), both
      // BEFORE the first handler call. A TRANSFORMING gate returns the transformed
      // shape → stored on ctx.egress so the handler wires the PIPELINE's vetted
      // bytes (requireEgressResult), never its own recomputation. INSIDE the
      // errorCode-stamping try so a denial lands on the audit row exactly like a
      // handler throw. Fires once before the handler; only a 401 raised by the gate
      // itself (gmail recipient resolution) force-refreshes and re-runs it once. The
      // handler-stage 401-retry ctx rebuild below CARRIES egressGateFired/egress
      // forward instead of re-firing. Tools without
      // a descriptor (every non-external OAuth tool, and the bespoke-gated
      // drive_share_file) skip this block.
      const eg = TOOL_REGISTRY[toolName]?.egress;
      if (eg !== undefined) {
        const shape = eg.extract(args);
        // B6.1 wave A3+D — pass the source's contact-resolution strategy so the gmail
        // gate resolves recipient names→emails (People API) BEFORE the allowlist runs;
        // it is undefined for github/notion/x (their gates ignore the arg).
        let out: EgressShape | void;
        try {
          out = await eg.gate(ctx, shape, source.resolveRecipients);
        } catch (err) {
          // GATE-STAGE 401 force-refresh retry (B6.1 wave A3+D). gmail's contact-lookup
          // resolve is a People-API call that can 401 — and it runs OUTSIDE the
          // handler-stage retry loop below, so a transparent-refresh regression here would
          // surface as a bare error. The gate's INVARIANT (tools/egress-pipeline.ts) is that
          // the resolve is its ONLY network sub-step and every audit/approval effect runs
          // AFTER it → re-firing the WHOLE gate once on a 401 has no double side effect
          // (the pre-resolve header gates are local + idempotent; egressGateFired/egress are
          // not set yet, so there is nothing to carry forward — a fresh ctx is correct). A
          // non-refreshable OAuth source (github/notion/x) never resolves recipients and its
          // gate has no network sub-step → this guard is false / unreachable = inert.
          if (!source.refreshable) throw err;
          const upstream = err as UpstreamError;
          if (upstream?.httpStatus !== 401) throw err;
          cred = await source.resolveCredential(toolDef, {
            accountId,
            refresh: deps,
            force: true,
          });
          ctx = {
            credential: cred,
            tier,
            audit: auditAcc.sink,
          };
          try {
            out = await eg.gate(ctx, shape, source.resolveRecipients);
          } catch (err2) {
            const upstream2 = err2 as UpstreamError;
            if (upstream2?.httpStatus === 401) {
              // Force-refresh produced a token Google still rejects → the same
              // Keychain cleanup as the handler-stage double-401 below.
              const dt = deps.deleteToken ?? deleteToken;
              const ra = deps.removeAccount ?? removeAccount;
              invalidateTokenCache(accountId);
              await dt(accountId).catch(() => undefined);
              await ra(accountId).catch(() => undefined);
              throw new MCPError("refresh_token_invalid", { email: accountId });
            }
            throw err2;
          }
        }
        if (out !== undefined) ctx.egress = out;
      }
      let raw: unknown;
      try {
        raw = await handler(ctx, args);
      } catch (err) {
        // v1.70 (G1) — the 401 force-refresh retry + Keychain cleanup is the google
        // OAuth refresh path. A non-refreshing OAuth source (a GitHub OAuth-App
        // token, refreshable:false) has already mapped its own error in the handler
        // → re-throw verbatim, no google refresh / retry / cleanup. For
        // google-workspace (refreshable:true) this guard is false → byte-identical.
        if (!source.refreshable) throw err;
        const upstream = err as UpstreamError;
        if (upstream?.httpStatus === 401) {
          // v1.66 — force-refresh via the source strategy, then rebuild ctx so the
          // retried handler reads the NEW token. Pre-v1.66 this reassigned a `let
          // tokenSet` and reused the same ctx (the getter saw the new token); the
          // source now owns the tokenSet, so a fresh Credential + ctx is the
          // behavior-equivalent form. The 401-retry control flow is otherwise
          // unchanged (still re-runs the handler once; a 2nd 401 → the cleanup
          // below). Only oauth resolveCredential consults `force`.
          cred = await source.resolveCredential(toolDef, {
            accountId,
            refresh: deps,
            force: true,
          });
          ctx = {
            credential: cred,
            tier,
            audit: auditAcc.sink,
            // B6.1 wave A2a — carry the pipeline-fired egress results across the
            // retry rebuild: the pipeline finished before the handler retry loop; gate
            // decisions are args-based and approval/audit already happened —
            // re-firing here would double requireSendApproval + the denial audit
            // rows. Handler-called consume (drive_share_file anyone) is NOT inert:
            // sendApprovalConsumedFingerprint rides the rebuild so the retried
            // handler does not burn the owner's one-time approval.
            egressGateFired: ctx.egressGateFired,
            egress: ctx.egress,
            sendApprovalConsumedFingerprint: ctx.sendApprovalConsumedFingerprint,
          };
          try {
            raw = await handler(ctx, args);
          } catch (err2) {
            const upstream2 = err2 as UpstreamError;
            if (upstream2?.httpStatus === 401) {
              // Force-refresh produced a token Google still rejects → cleanup
              // matches refresh.ts's invalid_grant cleanup so the user is told
              // to re-consent and the stale Keychain entry doesn't linger.
              const dt = deps.deleteToken ?? deleteToken;
              const ra = deps.removeAccount ?? removeAccount;
              invalidateTokenCache(accountId);
              await dt(accountId).catch(() => undefined);
              await ra(accountId).catch(() => undefined);
              throw new MCPError("refresh_token_invalid", { email: accountId });
            }
            throw mapHttpError(upstream2, accountId);
          }
        } else {
          throw mapHttpError(upstream, accountId);
        }
      }

      // v1.116 — choke-point egress tripwire. A tool LABELED direction:"outbound-write"
      // whose call completed WITHOUT its centralized egress gate (tools/egress.ts sets
      // ctx.egressGateFired — PIPELINE-fired above via the tool's egress descriptor) → a loud,
      // audited failure. `ctx` is the `let` the 401 force-refresh retry REASSIGNS, so at
      // this point it is the SUCCESSFUL attempt's ctx instance (never a stale
      // first-attempt ctx after a retried send) — the rebuilt literal CARRIES the
      // pipeline-fired flag forward (the pipeline fires before the handler retry loop).
      //
      // HONEST BOUNDARY: this fires AFTER the handler, so a drifted call's network egress
      // ALREADY happened — the tripwire converts silent gate-omission drift into an audited
      // internal_routing_error and blocks the response, but does NOT prevent the first send.
      // PREVENTION stays with the static call-site sentinel at merge time
      // (egress-callsite.test.ts); this is the production backstop, same posture as the #66
      // invariant tripwires. Sits INSIDE the outer try so the throw is errorCode-stamped onto
      // the audit row exactly like the F4/F1 throws above.
      if (TOOL_REGISTRY[toolName]?.direction === "outbound-write" && ctx.egressGateFired !== true) {
        throw new MCPError("internal_routing_error", { reason: "egress_gate_not_fired" });
      }

      // skipSanitize: --raw escape hatch for non-LLM consumers. The raw handler
      // result is returned verbatim. Auth / kill-switch / audit still ran above —
      // only this last wrap step is skipped. Audit row below records the bypass
      // so abuse is grep-able after the fact (`grep '"sanitize":"bypassed"'`).
      let sanitized: unknown;
      if (opts.skipSanitize) {
        sanitized = raw;
      } else {
        // Fail-closed: any sanitize exception → sanitize_failed (with-context owns
        // this contract; sanitize.ts also catches internally, but if the caller
        // ever passes a non-MCPError through, this re-wraps).
        try {
          // v1.64 Phase B (B5/D5) — per-source skipFields. For google-workspace
          // `source.skipFields` IS the global SKIP_FIELDS (===) → byte-identical.
          sanitized = sanitize(raw, { toolName }, source.skipFields);
        } catch (e) {
          if (e instanceof MCPError) throw e;
          throw new MCPError("sanitize_failed", {
            reason: e instanceof Error ? e.name : "unknown_error",
          });
        }
      }
      setLastUsed(accountId, source.id);
      status = "ok";
      return sanitized;
    } catch (err) {
      // v1.24 Phase 1 Item 2 — MCPError-only code stamping (Q3 LOCKED).
      // The 401-refresh retry already collapsed its first MCPError into a
      // second throw (refresh_token_invalid OR the mapped HTTP error); we
      // capture whichever code propagates out of the inner try.
      if (err instanceof MCPError) {
        errorCode = err.code;
        // v1.33 (d) — capture whitelisted forensic fields for the audit-row
        // gap-fill (closed-set, non-PII per AUDIT_ERROR_FORENSIC_WHITELIST).
        // No-op for handlers that already recorded their channel meta — the
        // gap-fill in auditEnd never overwrites an emitted field.
        errorForensics = pickAuditErrorForensics(err.errorData);
      }
      throw err;
    }
  } finally {
    // v1.17 Phase 3 HOOK B — 6-channel mutual-exclusion runtime assertion.
    // v1.18 Phase 1 — refactored to drive off the AUDIT_META_CHANNELS
    // registry in audit.ts (replaces the previously hand-maintained 4-tuple).
    // v1.19 Phase 2b + v1.20 Phase 1b-2 — extended to 5 / 6 channels via
    // the registry's auto-extension pattern (no hand-list edit required at
    // the iteration site itself).
    // v1.27 Phase 2 Item 1 (NEW-9 — Q4 LOCKED Option A) — REGISTRY-DRIVEN
    // Map aggregator REPLACES the hand-listed `localMetas` literal at this
    // site. The Map is populated by per-channel recorders during handler
    // execution (above); the mutex iterates the registry to derive
    // registry-order labels, NOT call-order, paired with v1.27 Phase 1
    // Item 4 iteration-order sentinel for cross-defense.
    //
    // Defends against future drift (L1 from Phase 1 review): the audit
    // schema's PRESENCE-as-signal discriminator requires that at most one of
    // {commentPostMeta, calendarMutationMeta, docsModifyMeta,
    //  commentDeleteMeta, tasksMutationMeta, sheetsMutationMeta} is set per
    // call. If a future handler accidentally sets two (e.g., copy-paste
    // from one channel to another), log loudly so the regression is
    // visible. Last-write-wins on the emitted JSON (auditEnd reads all 6
    // fields; in a double-record scenario all set channels' fields appear,
    // which IS itself a forensic signal).
    //
    // ─────────────────────────────────────────────────────────────────
    // v1.27 §2.2 Item 2 / Q2 LOCKED Option C — DOCUMENT accepted-risk:
    // ─────────────────────────────────────────────────────────────────
    // The mutex check `console.error`s instead of throwing. Three options
    // were considered at design close:
    //
    //   - Option A (FLIP to throw): rejected — runs in the `finally`
    //     block of withToolContext; a throw HERE would BLOCK the
    //     `void auditEnd({...})` call below and lose the row entirely,
    //     breaking hook #7 audit-on-failure invariant. Throw propagation
    //     from finally is also engine-dependent and can mask the original
    //     handler error. Defense-in-depth value modest because (1) the
    //     mutex is documented as catch-net-only since v1.18; (2) handler
    //     authoring discipline + per-channel TypeScript-distinct recorder
    //     fns + v1.17 Phase 3 + v1.19 Phase 2b + v1.20 Phase 1b-2 tests
    //     pin "exactly one recorder per handler"; (3) v1.25 Phase 2
    //     serialize refactor already neutralizes the worst-case write
    //     conflict via per-channel pure-return functions.
    //   - Option B (serialize-time early-return + marker field): rejected —
    //     would require AuditEndContext shape extension (new
    //     `__channel_mutex_violated: true` field) + audit roundtrip-test
    //     update (violates v1.27 Q3 LOCK regression net). Forensic value
    //     marginal vs today's loud `console.error` + double-channel-presence
    //     on-row signal (auditEnd serializes ALL set channels' fields per
    //     the v1.25 Phase 2 dispatch loop, which is its own forensic alert).
    //   - Option C (LOCKED — document accepted-risk + sentinel test):
    //     chosen — captures today's behavior contract explicitly; the
    //     sentinel test in `src/tools/with-context.mutex-contract.test.ts`
    //     pins the warn-not-throw contract so a future PR flipping
    //     warn → throw requires a re-design conversation (security
    //     implications for hook #7 + finally-block throw propagation
    //     engine-dependence). Preserves v1.25 Phase 2 dual-review
    //     accepted-risk posture — affirmed at v1.27 Phase 2 design close.
    //
    // When auditEnd sees 2+ metas: payload reflects ALL channels'
    // fields via `Object.assign(payload, entry.serialize(meta))` loop
    // (v1.25 Phase 2 Item 2). `policy_decision` collision is
    // last-write-wins per registry iteration order (Phase 1 Item 4
    // sentinel pins the order); all set channels' identifying hashes
    // appear on the row (forensic signal). The double-presence IS the
    // alert.
    //
    // Map.size > 1 replaces the prior `metasSet.length > 1` check —
    // Map.size is O(1) and idiomatic; behavior is identical when only
    // one channel is set (size === 1, no warn).
    const setChannelLabels: string[] = [];
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      // `keyof typeof AUDIT_META_CHANNELS` and `keyof MetaMap` are
      // structurally identical (Phase 1 mapped-type satisfies enforces
      // the 1:1 correspondence). The cast bridges the two index-signature
      // views — MetaMapStore exposes `keyof MetaMap`-typed methods.
      if (auditAcc.metas.has(key as keyof typeof AUDIT_META_CHANNELS)) {
        setChannelLabels.push(entry.label);
      }
    }
    if (auditAcc.metas.size > 1) {
      console.error(
        `[safespace] internal: tool ${toolName} set multiple audit metas: ${setChannelLabels.join(", ")}. Audit row will reflect all set channels but this is a coding error — only one meta should be set per call.`,
      );
    }
    // Fire-and-forget: audit append is best-effort observability, not on
    // the critical path. auditEnd swallows its own errors (logs to stderr).
    //
    // v1.27 Phase 2 Item 1 — AuditEndContext bridge. The interface keeps the
    // 6 named optional meta fields (Q3 LOCK preserves AuditEndContext shape);
    // each per-channel bridge field reads from the aggregator via
    // `recordedMetas.get("<key>")`. Hand-listed getters chosen over registry
    // iteration so the bridge's per-channel typing stays explicit (and
    // aligned with AuditEndContext's per-field optional typing). Preserves
    // the v1.22 audit roundtrip + v1.24 errorCode + v1.25 Phase 2 serialize-
    // refactor tests UNCHANGED (Q3 LOCK regression net).
    //
    // v1.29 Phase 2 (closes v1.27 NEW-3 carry-forward) — the 6 hand-listed
    // `as <Type> | undefined` casts at this bridge are REMOVED. The
    // MetaMapStore wrapper's generic `.get<K>(key: K): MetaMap[K] | undefined`
    // returns the precise per-channel type for each key, and each typed
    // return value is directly assignable to the matching AuditEndContext
    // field (the AuditEndContext field type IS `MetaMap[<channel>] |
    // undefined` by construction). Eliminating the casts closes the
    // "cast-could-hide-mismatch" failure mode — a future bridge-field rename
    // OR a registry-key rename OR a meta-type rename now fails compile at
    // the bridge instead of silently casting through.
    void auditEnd({
      tool: toolName,
      // v1.64 Phase B (B0 + B6) — the tool's Source connector id, now resolved
      // through `sourceFor(toolDef)` (B6) rather than read raw off `toolDef.source`.
      // `source.id` is always defined ("google-workspace" for every current tool),
      // so the emitted row is byte-identical to B0 (auditEnd's `?? "google-workspace"`
      // default produced the same value when this was `toolDef?.source` / undefined).
      source: source.id,
      email: accountId,
      argsHash,
      status,
      durationMs: Date.now() - start,
      sanitize: opts.skipSanitize ? "bypassed" : "applied",
      // v1.66.1 (B6.1a) — the forensic block (3 scalar channels + the 7
      // AUDIT_META_CHANNELS read back from the aggregator) is the SINGLE-SOURCE
      // `auditAcc.forensicFields()` (tools/audit-accumulator.ts), spread here AND in
      // withNonOAuthContext. Each field passes through undefined when its channel
      // was not recorded this call; `auditEnd` only serializes defined fields
      // (presence-as-signal), so the per-channel schema delta stays byte-identical.
      ...auditAcc.forensicFields(),
      // v1.24 Phase 1 Item 2 — passes through undefined on success rows + on
      // error rows where the thrown error is a plain `Error` (non-MCPError).
      // auditEnd serializes the field only when defined, so the schema delta
      // is invisible to pre-v1.24 downstream consumers (PRESENCE-as-signal).
      // Activates 4 v1.23 Phase 1 forward-compat safety nets in
      // cli/audit/suspicious.ts (-32025 / -32026 / -32007 / -32022).
      errorCode,
      // v1.33 (d) — whitelisted MCPError.data forensic fields for the audit-row
      // gap-fill safety net. auditEnd fills ONLY keys a channel serialize did
      // not already emit (byte-stable no-op for meta-recording handlers).
      errorForensics,
    });
  }
}

// v1.66 Phase C PR 2 — `scopeSatisfies` + `SCOPE_HIERARCHY` MOVED to the leaf
// `auth/scopes.ts` (the thesis-prescribed demotion of the OAuth scope machinery
// out of the generic gateway; consumed now by the google-workspace source's
// `authorize` strategy). Re-exported here so existing importers
// (with-all-accounts.ts, tests) keep working unchanged.
export { scopeSatisfies } from "../auth/scopes";

function mapHttpError(err: UpstreamError | undefined, email: string): Error {
  if (err instanceof MCPError) return err;
  const status = err?.httpStatus;
  if (status === 403) {
    // Could be insufficient_scope or principal denied. We deliberately do not
    // parse the response body to distinguish (security-review: response body
    // may contain token fragments). Map to scope_mismatch as the most
    // actionable outcome — user re-runs `safespace consent --re-auth`.
    return new MCPError("scope_mismatch", { email });
  }
  if (status === 429) {
    return new MCPError("rate_limited", { email });
  }
  return err instanceof Error ? err : new Error("unknown_upstream_error");
}
