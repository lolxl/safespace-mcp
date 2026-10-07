// The routing decision for one implemented tool call, shared by the MCP server
// (server.ts) and `safespace exec` (cli.ts) so the two cannot drift apart:
//   - cross-account `*_all` tools run their handler on a sentinel context and fan out
//     through `withAllAccounts`, which owns per-account resolve / refresh / scope /
//     sanitize / audit;
//   - non-OAuth sources (keyless web-fetch / fs-read, service-token connectors) go
//     through `withNonOAuthContext`;
//   - OAuth sources go through `withToolContext`.
// Gates that sit in FRONT of this (tool existence, tier, connector toggle) stay with
// each caller: the server enforces them; `exec` deliberately bypasses tier.

import * as crypto from "node:crypto";
import { auditEnd, isErrorAudited } from "../audit";
import { MCPError } from "../errors";
import type { OperatorContext } from "../identity/operator-context";
import type { ToolDef } from "./registry/types";
import { sourceFor } from "./source";
import type { ToolContext } from "./types";
import { withToolContext } from "./with-context";
import { withNonOAuthContext } from "./with-nonoauth-context";

/** Same args digest the choke points write. Never throws: an argument tree too deep
 *  to stringify must not cost the call its audit row or its error response. */
export function hashArgs(args: Record<string, unknown>): string {
  try {
    return `sha256:${crypto.createHash("sha256").update(JSON.stringify(args)).digest("hex")}`;
  } catch {
    return "sha256:unhashable";
  }
}

/** True when the tool runs through the single-account OAuth choke point — the only
 *  path with an `account_id` and a sanitize-bypass option. */
export function isSingleAccountOAuth(def: ToolDef): boolean {
  return !def.cross_account && sourceFor(def).authModel === "oauth";
}

export interface DispatchOptions {
  /** Skip the sanitize wrap (`exec --raw`). Single-account OAuth tools only; a
   *  caller must check `isSingleAccountOAuth` first. */
  skipSanitize?: boolean;
}

/** Run one implemented tool through the choke point its definition selects. */
export async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
  def: ToolDef,
  op: OperatorContext,
  opts: DispatchOptions = {},
): Promise<unknown> {
  if (opts.skipSanitize && !isSingleAccountOAuth(def)) {
    // Invariant guard: the other paths always sanitize.
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  if (def.cross_account) {
    // v1.14 Phase 1: cross-account tools bypass `withToolContext` (they don't have a
    // single resolved account — they fan out across all consented accounts via
    // `withAllAccounts` inside the handler). The handler shim reads only the tier
    // from `ctx`; audit / sanitize / refresh are owned by `withAllAccounts` per
    // design §5.
    const SENTINEL_CTX: ToolContext = Object.freeze({
      // v1.64 Phase B (B6 — D12): no single resolved OAuth account on this path, so
      // the credential is the honest `{kind:"none"}` (`requireOAuth(ctx)` would
      // throw on it by design — the shim routes straight to `withAllAccounts`).
      credential: { kind: "none" as const },
      // v1.38 BLOCKER 3: the resolved tier, the same value the caller's gates read.
      tier: op.tier,
      // v1.64 Phase B (B1): `withAllAccounts` owns the per-account audit rows and the
      // outer aggregate (design §5), so the sentinel carries a NO-OP sink.
      audit: { record() {} },
    });
    const handlerStart = Date.now();
    try {
      return await def.handler(SENTINEL_CTX, args);
    } catch (err) {
      // withAllAccounts marks the failures it has already logged; anything else
      // (e.g. the handler's own argument validation before it fans out) would
      // otherwise leave this call with no row.
      if (!isErrorAudited(err)) {
        await auditEnd({
          tool: name,
          source: sourceFor(def).id,
          email: null,
          argsHash: hashArgs(args),
          status: "error",
          durationMs: Date.now() - handlerStart,
          errorCode: err instanceof MCPError ? err.code : undefined,
        });
      }
      throw err;
    }
  }
  if (sourceFor(def).authModel !== "oauth") {
    // v1.65 Phase C — NON-OAUTH connectors: keyless (authModel "none") and
    // service-token. No Google account resolution, no scope check, no token refresh,
    // no 401 retry; credential resolution goes through the source's strategies.
    return withNonOAuthContext(name, args, def.handler, op);
  }
  // `op` is the trailing param; deps take their {} default here (production injects none).
  return withToolContext(name, args, def.handler, {}, { skipSanitize: opts.skipSanitize }, op);
}
