// v1.14 Phase 1 — `withAllAccounts` middleware helper for cross-account `_all` tools.
//
// See docs/v1.14-cross-account-search.md §5 (binding contract) + §11 (12 sec-rev hooks).
//
// Active-account semantics: `_all` tools do NOT mutate lastUsedAccount (design §3
// + #121 code-rev L3). No setLastUsed() call anywhere in this file.
//
// v1.119 (F6 step 1) — the per-account scope pre-check + credential resolution now
// route through the tool's Source strategies (`source.authorize` +
// `source.resolveCredential`), the SAME strategies the single-account choke point
// (with-context.ts) dispatches through — replacing the inline scope-hierarchy check
// + the direct token-refresh call. Byte-identical for every caller (all `_all` tools
// are google-workspace; the registry `requiredScopes` the check now reads === the
// values the handlers used to pass in opts). The account ENUMERATION stays hand-
// rolled here (see Phase 2) — that is cross-account orchestration, not single-
// account resolution.
//
// v1.121 (B6.1 wave C) — the per-account sub-context IS now the real `ToolContext`
// (the former per-account sub-context shim is deleted); `fn` receives a `{credential, tier,
// audit}` literal built per EXECUTED sub-call, so handlers narrow
// via `requireOAuth(ctx)` exactly like the single-account choke point. Two parity
// gaps the v1.120 header left open are now CLOSED: (1) a per-sub-call egress
// tripwire mirrors with-context.ts's direction:"outbound-write" post-handler
// assertion, and (2) EXECUTED inner audit rows stamp `sanitize:"applied"` (Q2).

import * as crypto from "node:crypto";
import {
  AUDIT_META_CHANNELS,
  auditCrossAccountAggregate,
  auditEnd,
  markErrorAudited,
  pickAuditErrorForensics,
} from "../audit";
import { loadIndex } from "../auth/keychain";
import type { RefreshDeps } from "../auth/refresh";
import { MCPError } from "../errors";
// v1.120 (F6 step 2) — the per-sub-call audit envelope. Each EXECUTED cross-account
// sub-call now gets its OWN createAuditAccumulator() (the same one the single-account
// choke point uses), so a future `*_all` write tool has the identical forensic-
// recording surface; its recorded fields ride onto that account's inner audit row.
import { createAuditAccumulator, type ForensicFields } from "./audit-accumulator";
import { currentTier, type Tier } from "../tier";
import type { ToolContext } from "./types";
// v1.64 Phase B (B6 — R10 closure). The cross-account fan-out used to run NEITHER
// the F1 write-burst nor the F4 autonomous-delete gate (and stamped a stripped
// audit row). These imports wire the SAME gates the single-account choke point
// (with-context.ts) runs + the per-source skipFields, so a future `*_all` WRITE is
// gated by construction.
import { enforceAutonomousDeleteDeny } from "../policy/autonomous-mode";
import { classifyWriteTool, enforceWriteBurst } from "../policy/write-burst";
import { sanitize } from "../sanitize";
import { sourceFor, type OAuthSource } from "./source";
import { EMAIL_RECIPIENT_RE } from "./handlers";
// ⚠️ Circular import (with-all-accounts → registry → handlers/cross-account →
// with-all-accounts), but RUNTIME-SAFE: TOOL_REGISTRY is read ONLY inside the
// async withAllAccounts() body (call time), never at module init — by then the
// `const TOOL_REGISTRY = Object.fromEntries(...)` has fully initialized. DO NOT
// add a top-level read of TOOL_REGISTRY here: at module-load time it would be
// `undefined`. (with-context.ts imports it the same way, for the same reason.)
import { TOOL_REGISTRY } from "./registry";
import type { ToolDef } from "./registry/types";

/** Per-account failure shape inside MultiAccountResult.failures[]. */
export interface AccountFailure {
  account_email: string;
  error: { code: string; message: string };
}

/** Aggregate result returned by `withAllAccounts`. */
export interface MultiAccountResult<T> {
  successes: Array<{ account_email: string } & T>;
  failures: AccountFailure[];
}

export interface WithAllAccountsOptions {
  /** Optional subset of consented accounts. undefined / empty = all consented.
   *  Each entry validated against EMAIL_RECIPIENT_RE BEFORE fan-out (sec-rev
   *  hook 5). Entries not in accounts.json surface as `account_not_found`
   *  failures (sec-rev hook 7 — anti-enumeration). */
  accounts?: string[];
  // v1.119 (F6 step 1) — `requiredScopes` REMOVED. The per-account scope check is
  // now the tool's `source.authorize` strategy, which reads the tool's registry
  // `requiredScopes` (=== the values the handlers used to pass here) — a single
  // source of truth, no longer duplicated in the opts.
}

/** Injection seams for tests + the tier threaded from the cross-account dispatch
 *  sentinel (the registry `_all` shims fill it). */
export interface WithAllAccountsDeps extends RefreshDeps {
  loadIndexImpl?: () => Promise<{
    accounts: Array<{ email: string; scopes?: string[] }>;
  }>;
  auditEndImpl?: typeof auditEnd;
  auditAggregateImpl?: typeof auditCrossAccountAggregate;
  sanitizeImpl?: typeof sanitize;
  /** v1.120 (F6 step 2) — the privilege tier for this fan-out, threaded from the
   *  cross-account sentinel (a ToolContext, which carries `tier`) via the registry
   *  shim. Absent for direct callers (tests) → falls
   *  back to `currentTier()`, the SAME source the single-account path resolves its
   *  tier from. Rides onto each
   *  per-account `ToolContext.tier`. */
  tier?: Tier;
}

/** Construct the synthetic per-sub-call args object whose SHA256 is the
 *  inner audit row's args_hash. Per design §8 — outer args MINUS `accounts?`
 *  PLUS `account_id`. Enables forensic correlation across `gmail_search` +
 *  `gmail_search_all` audit entries. */
function syntheticSubCallArgs(
  outerArgs: Record<string, unknown>,
  accountId: string,
): Record<string, unknown> {
  const { accounts: _omit, ...rest } = outerArgs;
  return { ...rest, account_id: accountId };
}

function sha256Hex(value: unknown): string {
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

/** Map a Promise.allSettled rejected reason → failures[] error.code per design §6 table.
 *  Message is informative-only; NEVER includes token state, refresh body, or other
 *  accounts' state (sec-rev hooks 2 + 8 + 12). */
function mapRejectedReason(
  reason: unknown,
  tool: string,
): { code: string; message: string } {
  if (reason instanceof MCPError) {
    const code = reason.errorName;
    if (
      code === "account_not_found" ||
      code === "scope_mismatch" ||
      code === "refresh_token_invalid" ||
      code === "rate_limited"
    ) {
      return { code, message: code };
    }
    // Other MCPError subclasses (e.g., keychain_locked) — treat as upstream_error.
    return { code: "upstream_error", message: `google_api_upstream_${tool}` };
  }
  // UpstreamError-shaped (has httpStatus field). Check httpStatus presence
  // directly so we don't depend on mapGoogleError's exact thrown class shape.
  const httpStatus = (reason as { httpStatus?: unknown } | null)?.httpStatus;
  if (typeof httpStatus === "number") {
    return {
      code: "upstream_error",
      message: `google_api_${httpStatus}_${tool}`,
    };
  }
  // Generic message — DO NOT include reason.message verbatim (could carry
  // implementation detail / partial state). Anti-PII-echo (sec-rev hook 12).
  return { code: "upstream_error", message: `google_api_upstream_${tool}` };
}

type Plan =
  | { kind: "account_not_found"; email: string }
  | { kind: "scope_mismatch"; email: string }
  | { kind: "ready"; email: string };

/** Build a per-account Plan: validate presence in accounts.json, then run the
 *  Source's scope pre-check.
 *
 *  v1.119 (F6 step 1) — the scope decision is the tool's `source.authorize`
 *  strategy (the SAME one the single-account choke point runs), reading the tool's
 *  registry `requiredScopes` against the account's PERSISTED granted scopes. A
 *  thrown `scope_mismatch` MCPError → the `scope_mismatch` plan; the error's data
 *  payload is DISCARDED, because `failureFromPlan` rebuilds the byte-identical
 *  failures[] entry ({code,message} = "scope_mismatch") + the inner audit `errorCode`
 *  from the plan kind. Any OTHER throw propagates. This runs in the PLAN-BUILDING
 *  phase, BEFORE any refresh I/O — same position as the pre-v1.119 inline check.
 *  googleWorkspace.authorize's skip semantics (toolDef falsy, or account.scopes
 *  missing/empty → no check) match the old inline check for every caller (all use
 *  registered tool names → toolDef present). */
function buildPlan(
  email: string,
  account: { email: string; scopes?: string[] } | undefined,
  source: OAuthSource,
  toolDef: ToolDef | undefined,
): Plan {
  if (!account) return { kind: "account_not_found", email };
  try {
    source.authorize(toolDef, {
      account: { accountId: email, scopes: account.scopes },
    });
  } catch (err) {
    if (err instanceof MCPError && err.errorName === "scope_mismatch") {
      return { kind: "scope_mismatch", email };
    }
    throw err;
  }
  return { kind: "ready", email };
}

interface SubResult {
  plan: Plan;
  outcome:
    | { kind: "ok"; sanitized: unknown }
    // v1.111 (#2) — `errorCode` (numeric MCPError.code) + `errorForensics`
    // (whitelisted MCPError.data fields) ride alongside the flattened public
    // `code`/`message` so the INNER audit row reaches forensic parity with the
    // single-account choke point (with-context.ts). They feed ONLY the durable
    // audit row — the returned `failures[]` shape stays flattened by
    // `mapRejectedReason` (anti-enumeration), unchanged.
    | {
        kind: "failed";
        code: string;
        message: string;
        errorCode?: number;
        errorForensics?: Record<string, unknown>;
      };
  durationMs: number;
  /** v1.120 (F6 step 2) — the forensic envelope captured from THIS sub-call's own
   *  accumulator after `fn` settled (both ok + failed EXECUTED outcomes). Spread onto
   *  the account's inner audit row in Phase 4. ALL fields are undefined today (no
   *  `_all` handler records any channel) → the row stays byte-identical because
   *  `auditEnd` serializes only defined fields. ABSENT for plan-failure sub-results
   *  (account_not_found / scope_mismatch never execute a handler → no accumulator). */
  forensics?: ForensicFields;
}

function failureFromPlan(plan: Plan, subStart: number): SubResult {
  // plan.kind is "account_not_found" or "scope_mismatch" here.
  const code = plan.kind as "account_not_found" | "scope_mismatch";
  return {
    plan,
    // The numeric MCPError code (via the public accessor) so the inner audit row
    // carries `error_code` for these pre-call plan failures too — the
    // suspicious / policy-decisions readers key off it.
    outcome: { kind: "failed", code, message: code, errorCode: new MCPError(code).code },
    durationMs: Date.now() - subStart,
  };
}

/** Cap on concurrent per-account work in the cross-account fan-out. A user with
 *  many consented accounts otherwise triggers N simultaneous token refreshes +
 *  SDK calls in a single tick (thundering herd / upstream rate-limit risk). 6
 *  keeps typical account sets fully parallel while bounding large ones. */
const MAX_ACCOUNT_FANOUT = 6;

/** Order-preserving bounded-parallel map: runs at most `limit` `fn`s at once,
 *  with `results[i]` corresponding to `items[i]` so downstream audit-row order
 *  stays deterministic. `fn` is expected never to reject (the fan-out body
 *  catches internally and returns a SubResult), so there is no per-task
 *  rejection handling here. Empty input → empty result, no `fn` call. */
async function mapWithConcurrency<I, O>(
  items: readonly I[],
  limit: number,
  fn: (item: I, index: number) => Promise<O>,
): Promise<O[]> {
  if (items.length === 0) return [];
  const results = new Array<O>(items.length);
  // Shared cursor: each worker claims the next index with `cursor++`, which is
  // atomic on JS's single thread (read-then-increment runs with no await between
  // them), so no two workers can claim the same index.
  let cursor = 0;
  const workerCount = Math.min(limit, items.length);
  const workers = Array.from({ length: workerCount }, async () => {
    for (let i = cursor++; i < items.length; i = cursor++) {
      results[i] = await fn(items[i] as I, i);
    }
  });
  await Promise.all(workers);
  return results;
}

/** Cross-account `_all` middleware. See module-level comment + design §5
 *  for the binding contract.
 *
 *  Best-effort semantics: ALWAYS resolves (never throws on per-account failure),
 *  even when every per-account sub-call fails. Per-account failures are
 *  encoded as DATA in the `failures[]` array. */
export async function withAllAccounts<T>(
  tool: string,
  outerArgs: Record<string, unknown>,
  fn: (ctx: ToolContext) => Promise<T>,
  opts: WithAllAccountsOptions,
  deps: WithAllAccountsDeps = {},
): Promise<MultiAccountResult<T>> {
  const outerArgsHash = sha256Hex(outerArgs);
  const idxLoader = deps.loadIndexImpl ?? loadIndex;
  const auditInnerImpl = deps.auditEndImpl ?? auditEnd;
  const auditOuterImpl = deps.auditAggregateImpl ?? auditCrossAccountAggregate;
  const sanitizeFn = deps.sanitizeImpl ?? sanitize;

  // ── v1.64 Phase B (B6 — R10 closure) ──
  // Resolve this `_all` tool's ToolDef + safety-gateway Source once. `source` is
  // google-workspace for every current `_all` tool (none set ToolDef.source), so
  // `source.skipFields` IS the global SKIP_FIELDS (===) and the per-account
  // sanitize stays byte-identical (B5).
  const toolDef = TOOL_REGISTRY[tool];
  // v1.119 (F6 step 1, sec-rev) — fail-closed tripwire: an unregistered `tool` here
  // is an internal wiring bug (server.ts rejects unknown names before dispatch, and
  // every production call site passes a registry literal). Without this, a
  // toolDef-less call would silently SKIP the per-account scope pre-check
  // (`source.authorize` no-ops on a falsy toolDef, where the pre-v1.119 inline check
  // ran unconditionally). Same fail-closed posture as sourceFor's unknown-source
  // throw (v1.112.8).
  if (!toolDef) {
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  const source = sourceFor(toolDef);
  // v1.119 (F6 step 1) — narrow the Source to OAuthSource, mirroring the single-
  // account choke point (with-context.ts:164). Every `_all` tool is google-workspace
  // today, and unreachability rests on the REGISTRY invariant that none of the
  // crossAccountTools defs sets `ToolDef.source` — NOT on proxy routing (the
  // cross-account branch dispatches on `def.cross_account` alone and never consults
  // authModel). This narrow is the runtime assertion of that registry invariant.
  // It also narrows `source` so the OAuth-only `authorize` / `resolveCredential(…,
  // deps)` strategies used by the scope check + per-account credential resolve
  // below are statically available.
  if (source.authModel !== "oauth") {
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  // The F1 write-burst + F4 autonomous-delete gates run ONCE here, at the call
  // boundary, mirroring the single-account choke point. For today's read-only
  // `_all` set both are NO-OPs (classifyWriteTool → "exempt" for min_tier:read;
  // none are PERMANENT_DELETE_TOOLS) → byte-identical. A future `*_all` WRITE is
  // rate/autonomy-gated by construction. A thrown -32032 / -32033 is a PRE-CALL
  // POLICY denial (the whole call is refused, like the single-account path), NOT a
  // per-account failure — so it propagates out of the cross-account handler to
  // proxy.ts (which renders the MCPError), and is correctly exempt from the
  // best-effort "never throws per-account" contract.
  // v1.120 (F6 step 2) — resolve the privilege tier ONCE here, so
  // each per-account sub-context carries it (ToolContext-parity). The sentinel/shim
  // threads it; a direct caller leaves it unset → `currentTier()`, the SAME source
  // the single-account choke point reads.
  const tier = deps.tier ?? currentTier();
  // Everything from the policy gates through the index load runs before any per-
  // account row exists; a throw here (F4/F1 denial, bad `accounts` input, index
  // read failure) writes one terminal row for the call instead of leaving none.
  const callStart = Date.now();
  const { requestedSubset, idx } = await (async () => {
    enforceAutonomousDeleteDeny(tool);
    // The same process-wide burst window as the single-account paths. Moot today
    // (every `_all` tool is read-only → "exempt" → no-op); a future `*_all` WRITE is
    // rate-capped here.
    enforceWriteBurst(classifyWriteTool(tool, toolDef?.min_tier));

    // ── Phase 1: input validation BEFORE any I/O (sec-rev hook 5) ──
    // Empty accounts[] → "all accounts" (same as undefined). Duplicates deduped.
    // Each entry MUST match EMAIL_RECIPIENT_RE (anchored, rejects CRLF / path /
    // control chars).
    let requestedSubset: string[] | undefined;
    if (Array.isArray(opts.accounts) && opts.accounts.length > 0) {
      const seen = new Set<string>();
      for (const entry of opts.accounts) {
        if (typeof entry !== "string" || !EMAIL_RECIPIENT_RE.test(entry)) {
          throw new Error(
            `${tool}: 'accounts' entries must each match the recipient email format`,
          );
        }
        seen.add(entry);
      }
      requestedSubset = Array.from(seen);
    }

    // ── Phase 2: resolve target accounts against accounts.json ──
    // v1.119 (F6 step 1) — this fan-out ENUMERATION (loadIndex → EMAIL_RECIPIENT_RE
    // validate → consented-account intersect) stays hand-rolled here: it is
    // cross-account ORCHESTRATION (WHICH accounts to touch), deliberately NOT
    // `source.resolveAccount` (which resolves the ONE active account for a single-
    // account call). Only the per-account scope check + credential resolve route
    // through the Source strategies; collapsing this whole literal pipeline into the
    // Source is B6.1.
    const idx = await idxLoader();
    return { requestedSubset, idx };
  })().catch(async (err: unknown) => {
    // Awaited before the rethrow: a CLI caller may exit as soon as this rejects.
    await auditInnerImpl({
      tool,
      source: source.id,
      email: null,
      argsHash: outerArgsHash,
      status: "error",
      durationMs: Date.now() - callStart,
      errorCode: err instanceof MCPError ? err.code : undefined,
      errorForensics: err instanceof MCPError ? pickAuditErrorForensics(err.errorData) : undefined,
    });
    markErrorAudited(err);
    throw err;
  });
  // sec-H1: validate each persisted account.email against EMAIL_RECIPIENT_RE.
  // A restored/edited accounts.json could inject adversarial text; mismatched
  // entries are treated as if the account doesn't exist (drop from `consented`
  // map; subset-path lookups surface `account_not_found`; all-consented path
  // skips them entirely). Malformed email NEVER propagates to `account_email`
  // output fields.
  const consented = new Map<string, { email: string; scopes?: string[] }>();
  for (const a of idx.accounts) {
    if (
      typeof a.email === "string" &&
      EMAIL_RECIPIENT_RE.test(a.email)
    ) {
      consented.set(a.email, a);
    }
  }

  let plans: Plan[];
  if (requestedSubset) {
    // Subset path — missing (or malformed-in-accounts.json) accounts surface
    // as account_not_found (design §6 + sec-rev hook 7). The failure echoes
    // the caller's input email — does NOT leak which other accounts DO exist.
    plans = requestedSubset.map((email) =>
      buildPlan(email, consented.get(email), source, toolDef),
    );
  } else {
    // All-consented path. Empty accounts.json (or all entries malformed) →
    // empty plans → empty aggregate (NOT an error — test #5).
    plans = Array.from(consented.values()).map((acc) =>
      buildPlan(acc.email, acc, source, toolDef),
    );
  }

  // ── Phase 3: fan-out per account (bounded parallelism — MAX_ACCOUNT_FANOUT) ──
  const subResults = await mapWithConcurrency(plans, MAX_ACCOUNT_FANOUT, async (plan) => {
    const subStart = Date.now();
    if (plan.kind !== "ready") return failureFromPlan(plan, subStart);
    // v1.120 (F6 step 2) — one accumulator per EXECUTED sub-call, mirroring the
    // single-account choke point's per-call `createAuditAccumulator()`. Created only
    // for `ready` plans (an account_not_found / scope_mismatch plan returned above
    // never reaches a handler → no accumulator → its row is byte-unchanged). Whatever
    // this account's handler records via `ctx.audit` is captured onto its OWN inner
    // row below — no cross-account bleed (each sub-call has its own accumulator).
    const acc = createAuditAccumulator();
    try {
      // v1.119 (F6 step 1) — resolve the per-account credential through the Source
      // strategy, replacing the direct token-refresh call. For google-workspace with
      // `force` unset the strategy refreshes `accountId` with `deps.refresh ?? {}`,
      // and `deps` here IS the RefreshDeps (WithAllAccountsDeps extends it) → byte-
      // identical to the pre-v1.119 direct call. The refresh layer's in-flight map
      // still coalesces concurrent invocations on the same email (sec-rev hook 6);
      // N different accounts run in parallel — no shared closure state (hook 10).
      const cred = await source.resolveCredential(toolDef, {
        accountId: plan.email,
        refresh: deps,
      });
      if (cred.kind !== "oauth") {
        // v1.119 — type-unreachable backstop: google-workspace.resolveCredential
        // always returns {kind:"oauth"}. Same defense-in-depth style as
        // with-context.ts's post-resolve narrow.
        throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
      }
      // v1.121 (B6.1 wave C) — build a REAL ToolContext for this EXECUTED sub-call
      // (replacing the former per-account sub-context shim). `const` is fine even
      // though the egress tripwire below READS ctx.egressGateFired and a future
      // `*_all` write's egress gate would SET it — that optional field is
      // non-readonly on ToolContext, so mutating the property (not the binding) is
      // allowed. No current `_all` handler reads tier / audit (reads that record
      // nothing) → byte-identical today.
      const ctx: ToolContext = {
        credential: cred,
        tier,
        audit: acc.sink,
      };
      const raw = await fn(ctx);
      // v1.121 (B6.1 wave C) — per-sub-call egress tripwire, mirroring with-context.ts's
      // choke-point assertion (:352-354). A tool LABELED direction:"outbound-write" whose
      // handler returned successfully WITHOUT invoking its centralized egress gate (which
      // sets ctx.egressGateFired) → a loud failure. Thrown INSIDE this per-account try, so
      // it becomes a per-account failure (caught below → mapRejectedReason + an inner
      // error row with errorCode -32055) — the best-effort "never throws per-account"
      // contract is preserved. UNREACHABLE today: cross_account ∩ outbound-write = ∅ (the
      // v1.116 registry pin); this UPGRADES that pin from sole guard to defense-in-depth,
      // so a future `*_all` WRITE is tripwired by construction.
      if (
        TOOL_REGISTRY[tool]?.direction === "outbound-write" &&
        ctx.egressGateFired !== true
      ) {
        throw new MCPError("internal_routing_error", { reason: "egress_gate_not_fired" });
      }
      // FRESH NONCE per sub-success — sanitize() generates new crypto-random
      // nonce per call (design §7, sec-rev hook 1).
      // v1.64 Phase B (B5/D5) — per-source skipFields (google-workspace's IS the
      // global SKIP_FIELDS → byte-identical).
      const sanitized = sanitizeFn(raw, { toolName: tool }, source.skipFields);
      return {
        plan,
        outcome: { kind: "ok" as const, sanitized },
        durationMs: Date.now() - subStart,
        // v1.120 — capture forensics AFTER fn settled. All-undefined today (nothing
        // recorded) → the Phase-4 spread is a byte-identical no-op on the row.
        forensics: acc.forensicFields(),
      };
    } catch (err) {
      const mapped = mapRejectedReason(err, tool);
      // Capture the PRECISE numeric MCPError code + whitelisted forensic fields for
      // the inner audit row BEFORE `mapRejectedReason` flattens to the anti-
      // enumeration failures[] shape (mirrors with-context.ts). A non-MCPError
      // (plain Error) leaves both undefined → auditEnd omits them (presence-as-signal).
      const errorCode = err instanceof MCPError ? err.code : undefined;
      const errorForensics =
        err instanceof MCPError ? pickAuditErrorForensics(err.errorData) : undefined;
      return {
        plan,
        outcome: {
          kind: "failed" as const,
          code: mapped.code,
          message: mapped.message,
          errorCode,
          errorForensics,
        },
        durationMs: Date.now() - subStart,
        // v1.120 — a handler may record forensic metadata BEFORE it throws (e.g. a
        // BEFORE-SDK mutation recorder), so capture on the failed EXECUTED path too.
        forensics: acc.forensicFields(),
      };
    } finally {
      // v1.120 (F6 step 2) — per-sub-call meta mutual-exclusion warn, mirroring
      // with-context.ts's finally. At most one meta channel should be set per call; a
      // handler that sets >1 is a coding error (the row still reflects all set
      // channels — itself a forensic signal). No-op today: no `_all` handler records
      // any meta, so `acc.metas.size` is 0.
      const setChannelLabels: string[] = [];
      for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
        if (acc.metas.has(key as keyof typeof AUDIT_META_CHANNELS)) {
          setChannelLabels.push(entry.label);
        }
      }
      if (acc.metas.size > 1) {
        console.error(
          `[safespace] internal: tool ${tool} set multiple audit metas: ${setChannelLabels.join(", ")}. Audit row will reflect all set channels but this is a coding error — only one meta should be set per call.`,
        );
      }
    }
  });

  // ── Phase 4: collect successes + failures, emit inner audit rows ──
  //
  // v1.121 (B6.1 wave C) — the two v1.120 PARITY-BOUNDARY gaps are now CLOSED (the
  // fan-out runs the real ToolContext): (1) EXECUTED inner rows stamp
  // `sanitize:"applied"` below (owner-locked Q2 — a MODE marker exactly like
  // with-context.ts's, which stamps it on error rows too; there is no skipSanitize on
  // this path), and (2) the per-sub-call egress tripwire fired in Phase 3
  // (direction:"outbound-write" post-handler). PLAN-FAILURE rows (account_not_found /
  // scope_mismatch) never executed a handler → NO sanitize field (no execution → no
  // sanitize semantics). Each executed sub-call's forensic envelope (`r.forensics`) is
  // still spread onto its inner row, at audit-recording parity with the single-account
  // choke point. NOTE: auditEnd already DEFAULTS an absent `sanitize` to "applied", so
  // the SERIALIZED jsonl row is byte-identical — this makes the mode EXPLICIT in the
  // row context object (envelope parity), it does not change the on-disk bytes.
  const successes: Array<{ account_email: string } & T> = [];
  const failures: AccountFailure[] = [];

  for (const r of subResults) {
    const innerArgs = syntheticSubCallArgs(outerArgs, r.plan.email);
    const innerHash = sha256Hex(innerArgs);
    // v1.121 (B6.1 wave C) — a `ready` plan EXECUTED a handler; account_not_found /
    // scope_mismatch short-circuit via failureFromPlan BEFORE Phase 3 (no handler, no
    // sanitize semantics). Gates the sanitize stamp on the EXECUTED error branch below.
    const executed = r.plan.kind === "ready";
    // Inner audit rows ARE per-account-identifying by design — only the outer aggregate row is anti-enumeration. See design §8.
    if (r.outcome.kind === "ok") {
      const subSuccess: { account_email: string } & T = {
        account_email: r.plan.email,
        ...(r.outcome.sanitized as T),
      };
      successes.push(subSuccess);
      void auditInnerImpl({
        tool,
        // v1.111 (#2) — the Source connector id, mirroring the single-account
        // choke point. source.id === "google-workspace" for every current `_all`
        // tool, so auditEnd's `?? "google-workspace"` default made the old row
        // byte-identical; threading it explicitly is byte-identical TODAY and
        // correct the moment a non-Google `_all` tool exists.
        source: source.id,
        email: r.plan.email,
        argsHash: innerHash,
        status: "ok",
        durationMs: r.durationMs,
        // v1.121 (B6.1 wave C) — stamp sanitize:"applied" on the EXECUTED ok row
        // (owner-locked Q2). A MODE marker exactly like with-context.ts's; there is no
        // skipSanitize on this path, and the ok branch is ALWAYS an executed sub-call
        // (a plan-failure never yields "ok"). auditEnd already DEFAULTS an absent field
        // to "applied", so the serialized row is byte-identical — this makes the mode
        // EXPLICIT in the row context (envelope parity).
        sanitize: "applied",
        // v1.120 (F6 step 2) — this account's own forensic envelope. All fields are
        // undefined today (no `_all` handler records any channel) and `auditEnd`
        // serializes only defined fields → byte-identical row. A future meta-recording
        // `*_all` handler lands its forensics on THIS account's row.
        ...(r.forensics ?? {}),
      });
    } else {
      failures.push({
        account_email: r.plan.email,
        error: { code: r.outcome.code, message: r.outcome.message },
      });
      // sec-rev hook 11: failed sub-calls ALSO emit an inner audit row
      // (status: "error") so forensic audit can reconstruct what was queried.
      void auditInnerImpl({
        tool,
        // v1.111 (#2) — source parity with the ok branch / single-account path.
        source: source.id,
        email: r.plan.email,
        argsHash: innerHash,
        status: "error",
        durationMs: r.durationMs,
        // v1.111 (#2) — the precise numeric MCPError code + whitelisted forensic
        // fields (captured pre-flatten above). Without these the inner error row
        // carried `status:"error"` but NO `error_code`, so a `*_all` per-account
        // failure was invisible to the suspicious / policy-decisions readers (which
        // key off error_code). undefined for a non-MCPError → auditEnd omits them.
        errorCode: r.outcome.errorCode,
        errorForensics: r.outcome.errorForensics,
        // v1.121 (B6.1 wave C) — stamp sanitize:"applied" on EXECUTED error rows ONLY
        // (owner-locked Q2). A PLAN-FAILURE row (account_not_found / scope_mismatch)
        // never executed a handler → NO sanitize field, byte-unchanged. `executed`
        // (r.plan.kind === "ready") distinguishes the two.
        ...(executed ? { sanitize: "applied" as const } : {}),
        // v1.120 (F6 step 2) — this account's forensic envelope (a handler may record
        // a BEFORE-SDK mutation meta then throw). All-undefined today → byte-identical
        // row. Distinct keys from errorCode/errorForensics → no collision with the
        // above (ForensicFields carries the 3 scalar + 8 meta channels only).
        ...(r.forensics ?? {}),
      });
    }
  }

  // ── Phase 5: outer aggregate audit row (sec-rev hook 4: counts MUST match) ──
  void auditOuterImpl({
    tool,
    argsHash: outerArgsHash,
    accountCountQueried: plans.length,
    accountCountSucceeded: successes.length,
    accountCountFailed: failures.length,
  });

  return { successes, failures };
}
