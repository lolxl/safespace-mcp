// v1.14 Phase 1 — `withAllAccounts` middleware helper for cross-account `_all` tools.
//
// See docs/v1.14-cross-account-search.md §5 (binding contract) + §11 (12 sec-rev hooks).
//
// Active-account semantics: `_all` tools do NOT mutate lastUsedAccount (design §3
// + #121 code-rev L3). No setLastUsed() call anywhere in this file.

import * as crypto from "node:crypto";
import { auditCrossAccountAggregate, auditEnd, pickAuditErrorForensics } from "../audit";
import { loadIndex } from "../auth/keychain";
import { refreshAccessToken, type RefreshDeps, type TokenSet } from "../auth/refresh";
import { MCPError } from "../errors";
// v1.64 Phase B (B6 — R10 closure). The cross-account fan-out used to run NEITHER
// the F1 write-burst nor the F4 autonomous-delete gate (and stamped a stripped
// audit row without the operator). These imports wire the SAME gates the
// single-account choke point (with-context.ts) runs + the operator resolver +
// the per-source skipFields, so a future `*_all` WRITE is gated by construction.
import { resolveOperatorId } from "../identity/operator-id";
import { enforceAutonomousDeleteDeny } from "../policy/autonomous-mode";
import { classifyWriteTool, enforceWriteBurst } from "../policy/write-burst";
import { sanitize } from "../sanitize";
import { sourceFor } from "./source";
import { EMAIL_RECIPIENT_RE } from "./handlers";
// ⚠️ Circular import (with-all-accounts → registry → handlers/cross-account →
// with-all-accounts), but RUNTIME-SAFE: TOOL_REGISTRY is read ONLY inside the
// async withAllAccounts() body (call time), never at module init — by then the
// `const TOOL_REGISTRY = Object.fromEntries(...)` has fully initialized. DO NOT
// add a top-level read of TOOL_REGISTRY here: at module-load time it would be
// `undefined`. (with-context.ts imports it the same way, for the same reason.)
import { TOOL_REGISTRY } from "./registry";
import { scopeSatisfies } from "./with-context";

/** Per-account sub-context handed to the cross-account handler's fn().
 *  Shape mirrors ToolContext — same `getAccessToken()` getter pattern. */
export interface AccountSubContext {
  readonly email: string;
  readonly getAccessToken: () => string;
}

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
  /** Required OAuth scopes. Checked per-account against accounts.json scope set
   *  via SCOPE_HIERARCHY (same as withToolContext). */
  requiredScopes: readonly string[];
}

/** Injection seams for tests + (v1.74 PR-2c) the per-operator inputs threaded from
 *  the cross-account dispatch sentinel (the registry `_all` shims fill them). */
export interface WithAllAccountsDeps extends RefreshDeps {
  loadIndexImpl?: () => Promise<{
    accounts: Array<{ email: string; scopes?: string[] }>;
  }>;
  auditEndImpl?: typeof auditEnd;
  auditAggregateImpl?: typeof auditCrossAccountAggregate;
  sanitizeImpl?: typeof sanitize;
  /** v1.74 PR-2c — the operator this fan-out runs as (for the inner audit rows).
   *  Threaded from the connection (Model B) via the sentinel; falls back to
   *  `resolveOperatorId()` when absent (direct callers / Model A) → byte-identical. */
  operator?: string | null;
  /** v1.74 PR-2c — the operator's account-confinement set. When non-null, the
   *  consented-account map is INTERSECTED with it BEFORE fan-out, so an account in
   *  the global index but outside this operator's set is dropped exactly as a
   *  non-consented account is (it never enters the fan-out; a caller naming it in
   *  `opts.accounts` gets the ordinary `account_not_found`). `null`/absent = no
   *  confinement (Model A — the all-consented fan-out is byte-identical). This is
   *  the cross-account half of the in-process isolation (design §6.1) — the path
   *  that bypasses `withToolContext`, so it MUST be confined here separately. */
  confineToAccounts?: readonly string[] | null;
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

/** Build a per-account Plan: validate presence in accounts.json + scope set. */
function buildPlan(
  email: string,
  account: { email: string; scopes?: string[] } | undefined,
  requiredScopes: readonly string[],
): Plan {
  if (!account) return { kind: "account_not_found", email };
  if (Array.isArray(account.scopes) && account.scopes.length > 0) {
    const granted = new Set(account.scopes);
    const missing = requiredScopes.filter((s) => !scopeSatisfies(granted, s));
    if (missing.length > 0) return { kind: "scope_mismatch", email };
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
  fn: (account: AccountSubContext) => Promise<T>,
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
  const source = sourceFor(toolDef);
  // The F1 write-burst + F4 autonomous-delete gates run ONCE here, at the call
  // boundary, mirroring the single-account choke point. For today's read-only
  // `_all` set both are NO-OPs (classifyWriteTool → "exempt" for min_tier:read;
  // none are PERMANENT_DELETE_TOOLS) → byte-identical. A future `*_all` WRITE is
  // rate/autonomy-gated by construction. A thrown -32032 / -32033 is a PRE-CALL
  // POLICY denial (the whole call is refused, like the single-account path), NOT a
  // per-account failure — so it propagates out of the cross-account handler to
  // proxy.ts (which renders the MCPError), and is correctly exempt from the
  // best-effort "never throws per-account" contract.
  // Resolve the operator once: it attributes the per-account inner audit rows to
  // the human actor (co-management forensics) AND (v1.92) keys the F1 burst window
  // per-operator. Byte-stable when $SAFESPACE_OPERATOR_ID is unset
  // (resolveOperatorId() → null → the shared sentinel bucket + `operator: null`
  // rows, exactly as before). v1.74 PR-2c — the operator from the connection
  // (Model B, via the sentinel) falls back to env for direct callers / Model A.
  const operator = deps.operator ?? resolveOperatorId();
  enforceAutonomousDeleteDeny(tool);
  // v1.92 — per-operator burst window. Only the operatorId is available on the
  // cross-account path (no full OperatorContext here), so per-operator registry
  // CAP OVERRIDES are not threaded → this path uses the global env default. Moot
  // today (every `_all` tool is read-only → "exempt" → no-op); a future `*_all`
  // WRITE is still rate-capped, just at the global default until the override is
  // plumbed here.
  enforceWriteBurst(classifyWriteTool(tool, toolDef?.min_tier), { operatorId: operator });

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
  const idx = await idxLoader();
  // sec-H1: validate each persisted account.email against EMAIL_RECIPIENT_RE.
  // A restored/edited accounts.json could inject adversarial text; mismatched
  // entries are treated as if the account doesn't exist (drop from `consented`
  // map; subset-path lookups surface `account_not_found`; all-consented path
  // skips them entirely). Malformed email NEVER propagates to `account_email`
  // output fields.
  // v1.74 PR-2c — per-operator account confinement (design §6.1, the in-process
  // isolation proof). When the operator has a confinement set, an account in the
  // global index but OUTSIDE it is dropped here, exactly as a non-consented account
  // is — so operator A's `*_all` fan-out can NEVER reach operator B's accounts, and
  // a B-named entry in `opts.accounts` surfaces the ordinary `account_not_found`
  // (the subset path's `consented.get(email)` is undefined). `null` = no confinement
  // (Model A) → byte-identical.
  const confine = deps.confineToAccounts ?? null;
  const consented = new Map<string, { email: string; scopes?: string[] }>();
  for (const a of idx.accounts) {
    if (
      typeof a.email === "string" &&
      EMAIL_RECIPIENT_RE.test(a.email) &&
      (confine == null || confine.includes(a.email))
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
      buildPlan(email, consented.get(email), opts.requiredScopes),
    );
  } else {
    // All-consented path. Empty accounts.json (or all entries malformed) →
    // empty plans → empty aggregate (NOT an error — test #5).
    plans = Array.from(consented.values()).map((acc) =>
      buildPlan(acc.email, acc, opts.requiredScopes),
    );
  }

  // ── Phase 3: fan-out per account (bounded parallelism — MAX_ACCOUNT_FANOUT) ──
  const subResults = await mapWithConcurrency(plans, MAX_ACCOUNT_FANOUT, async (plan) => {
    const subStart = Date.now();
    if (plan.kind !== "ready") return failureFromPlan(plan, subStart);
    try {
      // refresh.ts refreshInFlight Map coalesces concurrent invocations on the
      // same email (sec-rev hook 6). N different accounts run in parallel — no
      // shared closure state (sec-rev hook 10).
      const tokenSet: TokenSet = await refreshAccessToken(plan.email, deps);
      const subCtx: AccountSubContext = {
        email: plan.email,
        getAccessToken: () => tokenSet.access_token,
      };
      const raw = await fn(subCtx);
      // FRESH NONCE per sub-success — sanitize() generates new crypto-random
      // nonce per call (design §7, sec-rev hook 1).
      // v1.64 Phase B (B5/D5) — per-source skipFields (google-workspace's IS the
      // global SKIP_FIELDS → byte-identical).
      const sanitized = sanitizeFn(raw, { toolName: tool }, source.skipFields);
      return {
        plan,
        outcome: { kind: "ok" as const, sanitized },
        durationMs: Date.now() - subStart,
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
      };
    }
  });

  // ── Phase 4: collect successes + failures, emit inner audit rows ──
  const successes: Array<{ account_email: string } & T> = [];
  const failures: AccountFailure[] = [];

  for (const r of subResults) {
    const innerArgs = syntheticSubCallArgs(outerArgs, r.plan.email);
    const innerHash = sha256Hex(innerArgs);
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
        // v1.64 Phase B (B6 — R10 audit upgrade) — attribute the operator on the
        // inner row (byte-stable null when $SAFESPACE_OPERATOR_ID is unset).
        operator,
        argsHash: innerHash,
        status: "ok",
        durationMs: r.durationMs,
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
        // v1.64 Phase B (B6 — R10 audit upgrade) — operator on the inner row too
        // (byte-stable null when $SAFESPACE_OPERATOR_ID is unset).
        operator,
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
