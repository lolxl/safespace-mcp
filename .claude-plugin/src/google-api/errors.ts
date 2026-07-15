/**
 * v1.11 Phase 1b — googleapis error → SafeSpace error mapping.
 *
 * The googleapis SDK throws `GaxiosError` (from the `gaxios` HTTP layer it
 * uses underneath). This module translates that into either:
 *   - an existing SafeSpace `MCPError` for terminal-state errors that should
 *     NOT trigger middleware retry (rate limit, scope mismatch), OR
 *   - an `UpstreamError` (`Error & { httpStatus?: number }`) that matches the
 *     shape `withToolContext`'s middleware already inspects for retry
 *     decisions and proxy-side `upstream_error` mapping.
 *
 * The `httpStatus` field is critical: `with-context.ts:148` triggers a
 * one-shot force-refresh + retry on `httpStatus === 401`. The middleware
 * retry only fires when we propagate the status field from the Gaxios
 * error, not just a structured message string.
 *
 * Phase 2 tool migrations call this in their `catch` blocks:
 *
 *   export async function gmailListLabels(ctx: ToolContext) {
 *     try {
 *       const gmail = await getGmailClient(ctx.email);
 *       return (await gmail.users.labels.list({ userId: "me" })).data;
 *     } catch (err) {
 *       mapGoogleError(err, { tool: "gmail_list_labels", email: ctx.email });
 *     }
 *   }
 *
 * `mapGoogleError` always throws — its return type is `never`. Callers
 * structure their try/catch to let the throw escape.
 */

import { MCPError } from "../errors";
// v1.64 Phase B (B4 — D4): import `UpstreamError` from its DEFINITION SITE
// (handlers/shared.ts — a leaf that imports only ../types), NOT the
// `../tools/handlers` barrel. The barrel re-exports every handler, so importing
// the type from it formed the errors.ts ↔ handlers type-cycle this refactor
// cuts. (The `import type` was erased at runtime, but it still coupled the two
// modules at the type layer + invited a future value-import to load-bear the
// cycle.) The leaf has no path back to this module, so the cycle is gone now.
// DO NOT repoint this at the `../tools/handlers` barrel.
import type { UpstreamError } from "../tools/handlers/shared";

interface GaxiosLikeError {
  response?: {
    status?: number;
    data?: {
      error?: {
        code?: number;
        message?: string;
        status?: string;
        errors?: Array<{ reason?: string; message?: string; domain?: string }>;
      };
    };
  };
  code?: string;
  message?: string;
}

export interface GoogleErrorContext {
  /** Tool name for error attribution (e.g., "gmail_list_labels"). */
  tool: string;
  /** Optional account email — included in error data ONLY for account-not-found-style errors. */
  email?: string;
}

/**
 * Extract HTTP status from a GaxiosError-shaped value. Returns `undefined`
 * for network errors (no HTTP response received).
 */
function extractStatus(err: GaxiosLikeError): number | undefined {
  return err.response?.status;
}

/**
 * Extract the `reason` field from the FIRST detailed error entry. Google's
 * REST API surface uses reasons like `rateLimitExceeded`, `insufficientPermissions`,
 * `userRateLimitExceeded`, `notFound`, etc. The top-level `error.status`
 * (e.g., `PERMISSION_DENIED`) is coarser; the per-error `reason` is more
 * specific and worth checking first.
 */
function extractReason(err: GaxiosLikeError): string | undefined {
  return err.response?.data?.error?.errors?.[0]?.reason;
}

function extractMessage(err: GaxiosLikeError): string {
  return (
    err.response?.data?.error?.message ??
    err.message ??
    "(no message)"
  );
}

/**
 * Build an `UpstreamError` — `Error` with the `httpStatus` field that
 * `with-context.ts` middleware inspects for retry + status mapping.
 */
function makeUpstream(message: string, httpStatus?: number): UpstreamError {
  const e: UpstreamError = new Error(message);
  if (httpStatus !== undefined) {
    e.httpStatus = httpStatus;
  }
  return e;
}

/**
 * Core mapper (v1.64 Phase B B4 — extracted from the former throwing
 * `mapGoogleError`): turn a googleapis/Gaxios error into the SafeSpace error to
 * surface, and RETURN it (never throws — so both the throwing `mapGoogleError`
 * and the returning `toGoogleError` boundary can share this one mapping table).
 *
 * B6.1-B — a DELIBERATE handler-level exception to the client-layer error-mapping
 * contract (src/auth/http/connector-error-contract.ts): the googleapis SDK owns the
 * socket (no SafeSpace client layer exists to map in), and the 401 pass-through
 * (`UpstreamError{httpStatus:401}` escaping the handler) is load-bearing for the
 * choke point's force-refresh retry.
 *
 * Mapping table (verbatim from the pre-B4 mapGoogleError; `throw X` → `return X`):
 *   401          → `UpstreamError` with `httpStatus=401` → middleware
 *                   (`withToolContext`) catches and force-refreshes + retries once.
 *   403          → `MCPError("scope_mismatch")` IF reason ∈
 *                   { insufficientPermissions, forbidden, insufficientScopes }
 *                   OR error.status = "PERMISSION_DENIED"; quotaExceeded /
 *                   dailyLimitExceeded → `MCPError("youtube_quota_exceeded")`;
 *                   otherwise `UpstreamError` with `httpStatus=403`.
 *   404 / 4xx    → `UpstreamError` with the actual `httpStatus` so callers that
 *                   pattern-match (`drive_get_file_content` → `not_found`) keep working.
 *   429          → `MCPError("rate_limited")`.
 *   5xx          → `UpstreamError` with the actual `httpStatus`.
 *   network err  → `UpstreamError` with NO `httpStatus` (generic upstream failure).
 *
 * Does NOT special-case `MCPError` — exactly like the historical throwing
 * mapGoogleError, an MCPError reaching here is a non-Gaxios value and is
 * network-wrapped. The MCPError passthrough lives in `toGoogleError` (the
 * handler catch boundary), which is the only site that ever sees a handler's own
 * validation MCPError.
 */
function mapGoogleErrorImpl(err: unknown, ctx: GoogleErrorContext): Error {
  const e = (err ?? {}) as GaxiosLikeError;
  const status = extractStatus(e);
  const reason = extractReason(e);
  const errorStatus = e.response?.data?.error?.status;
  const message = extractMessage(e);
  const tool = ctx.tool;

  // Network errors — no HTTP status. UpstreamError without httpStatus is
  // treated as a generic upstream failure (no retry, no auth fallout).
  if (status === undefined) {
    const code = e.code ?? "unknown";
    return makeUpstream(`google_api_network_${code}_${tool}: ${message}`);
  }

  if (status === 401) {
    // httpStatus=401 → middleware catches and force-refreshes + retries once.
    // If the retry also returns 401, middleware promotes to MCPError("refresh_token_invalid").
    return makeUpstream(`google_api_unauthorized_${tool}`, 401);
  }

  if (status === 403) {
    // v1.16 Phase 1b — YouTube daily quota exhaustion (10,000 units / day,
    // resets midnight Pacific) returns 403 with reason `quotaExceeded` or
    // `dailyLimitExceeded`. SEPARATE from `rate_limited` (which is for per-
    // second/per-minute limits that recover in seconds) because quota does
    // NOT recover until midnight Pacific. Designed in v1.16 but checked here
    // unconditionally — if a non-YouTube Google API ever returns the same
    // reason on a 403 the same mapping is the correct user surface.
    // See docs/v1.16-youtube-api.md §8.
    if (reason === "quotaExceeded" || reason === "dailyLimitExceeded") {
      return new MCPError("youtube_quota_exceeded", { tool });
    }
    const isScopeIssue =
      errorStatus === "PERMISSION_DENIED" ||
      reason === "insufficientPermissions" ||
      reason === "forbidden" ||
      reason === "insufficientScopes";
    if (isScopeIssue) {
      return new MCPError("scope_mismatch", { tool });
    }
    return makeUpstream(`google_api_403_${tool}: ${message}`, 403);
  }

  if (status === 429) {
    return new MCPError("rate_limited", { tool });
  }

  if (status >= 500 && status < 600) {
    return makeUpstream(`google_api_upstream_${status}_${tool}: ${message}`, status);
  }

  // 4xx other (400 / 404 / 409 etc.) — UpstreamError with the actual status
  // so handlers that branch on httpStatus (e.g., 404 → not_found) still work.
  return makeUpstream(`google_api_${status}_${tool}: ${message}`, status);
}

/**
 * Maps a googleapis error to a SafeSpace error type and THROWS it (return type
 * `never`). Byte-identical to the pre-v1.64 mapGoogleError — `mapGoogleErrorImpl`
 * holds the verbatim mapping table and this wrapper just throws its result.
 * Retained for the non-canonical sites that THROW a constructed error
 * (gmail_modify_messages_batch's synthetic 502s) and the cross-account `_all`
 * per-account callbacks; the canonical handler catches use `toGoogleError`.
 */
export function mapGoogleError(err: unknown, ctx: GoogleErrorContext): never {
  throw mapGoogleErrorImpl(err, ctx);
}

/**
 * v1.64 Phase B (B4 — D4: lift error mapping) — the canonical handler catch
 * boundary. RETURNS the SafeSpace error to throw, COLLAPSING the two lines every
 * google-workspace handler used to repeat:
 *
 *     } catch (err) {
 *       if (err instanceof MCPError) throw err;     // ← toGoogleError returns it unchanged
 *       mapGoogleError(err, { tool, email });       // ← toGoogleError maps it
 *     }
 *
 * into ONE:
 *
 *     } catch (err) {
 *       throw toGoogleError(err, { tool, email: requireOAuth(ctx).accountId });
 *     }
 *
 * An `MCPError` thrown inside the try (a validation / policy reject the handler
 * raised — file_too_large / formula_rejected / batch_too_large) is RETURNED
 * UNCHANGED, so `throw toGoogleError(...)` re-throws it verbatim — identical to
 * the old explicit `if (err instanceof MCPError) throw err`. Any other error
 * routes through the shared `mapGoogleErrorImpl`, so a 401 still leaves the
 * handler as `UpstreamError{httpStatus:401}` and `withToolContext`'s
 * force-refresh retry needs ZERO change (the mapper stays at the handler's
 * SDK-call boundary, NOT lifted to the choke point — see
 * docs/v1.64-phase-b-pipeline-seam.md §3 B4). Keeping the handler's own `try`
 * also preserves each handler's `args` narrowing inside the call (a closure
 * boundary would have dropped it). This returning form is called DIRECTLY by each
 * google handler's catch (`throw toGoogleError(...)` — e.g. gmail.ts / drive.ts);
 * it is not wired as a per-source error-mapping strategy. When B6.1 lands the
 * per-source pipeline, a shared catch would throw what this returns.
 */
export function toGoogleError(err: unknown, ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return mapGoogleErrorImpl(err, ctx);
}

