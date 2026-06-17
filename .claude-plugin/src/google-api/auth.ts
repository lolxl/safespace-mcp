/**
 * v1.11 Phase 1b — googleapis OAuth2Client wrapper.
 *
 * This module is a THIN bridge between SafeSpace's existing auth layer
 * (`refresh.ts`, `keychain.ts`) and the googleapis SDK. The refresh logic
 * — Keychain re-read, in-process mutex, invalid_grant handling, abort
 * timeout, etc. — already lives in `refresh.ts` and is NOT duplicated here.
 *
 * Design:
 *   1. Call SafeSpace's `refreshAccessToken(email)` — Keychain-fresh tokens
 *   2. Construct a googleapis `OAuth2Client` with the refreshed credentials
 *   3. Return it for use with `google.gmail({auth})` / `google.drive({auth})`
 *
 * The returned OAuth2Client has `access_token`, `refresh_token`, and
 * `expiry_date` set. If `refreshAccessToken` returns successfully, the
 * returned client has a valid access_token AT CONSTRUCTION TIME — the
 * googleapis SDK will NOT auto-refresh because `expiry_date` is in the
 * future. However, a subsequent 401 from a Gmail/Drive API call can still
 * surface (concurrent revocation, clock skew, mid-call token rotation).
 *
 * Callers SHOULD use `withGoogleApi(email, tool, fn)` below — it wraps the
 * 401 → force-refresh → retry-once pattern uniformly. Tools that call
 * `getAuthClient` directly inherit responsibility for that retry.
 *
 * This explicit separation keeps `refresh.ts` authoritative — Phase 1a's
 * spike used `OAuth2Client.refreshAccessToken()` (SDK-managed), which would
 * have bypassed our mutex + invalid_grant handling. The spike's approach is
 * NOT lifted.
 */

import { google } from "googleapis";
import type { OAuth2Client } from "googleapis-common";
import { refreshAccessToken, type RefreshDeps } from "../auth/refresh";
import { mapGoogleError } from "./errors";

export type AuthDeps = RefreshDeps;

/**
 * Returns an authenticated `OAuth2Client` for the given account.
 *
 * @param email - account email; must already be consented + present in Keychain
 * @param deps - optional DI seam (forwarded to `refreshAccessToken`); set
 *               `deps.force=true` to bypass the skip-when-valid cache and
 *               always issue a network refresh (used by 401-retry paths).
 * @throws MCPError("account_not_found") if Keychain has no entry for email
 * @throws MCPError("refresh_token_invalid") if Google returns invalid_grant
 * @throws Error("google_token_endpoint_<status>") on non-401 refresh failures
 */
export async function getAuthClient(
  email: string,
  deps?: AuthDeps,
): Promise<OAuth2Client> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error(
      "getAuthClient: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables required",
    );
  }

  const tokens = await refreshAccessToken(email, deps);

  const oauth = new google.auth.OAuth2(clientId, clientSecret);
  oauth.setCredentials({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expiry_date: tokens.expires_at,
    scope: tokens.scopes.join(" "),
    token_type: "Bearer",
  });
  return oauth;
}

/**
 * Test whether an error is a googleapis 401 Unauthorized. Looks for the
 * GaxiosError shape (`response.status === 401`) without coupling to the
 * gaxios class itself (we don't import the SDK error class, just inspect
 * the shape). This is what `withGoogleApi` uses to decide whether to
 * force-refresh + retry.
 */
function isUnauthorized(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as { response?: { status?: number } };
  return e.response?.status === 401;
}

/**
 * Run `fn` with an authenticated `OAuth2Client`, retrying once with a
 * force-refresh if the first attempt returns 401 Unauthorized.
 *
 * This wraps the standard "Phase 2 tool migration" pattern:
 *
 *   return await withGoogleApi(email, "gmail_list_labels", async (auth) => {
 *     const gmail = google.gmail({ version: "v1", auth });
 *     return (await gmail.users.labels.list({ userId: "me" })).data;
 *   });
 *
 * Behavior:
 *   - Happy path: get auth → run fn → return result
 *   - 401: detect via shape (no SDK-class coupling), force-refresh via
 *     `getAuthClient(email, { ...deps, force: true })`, retry fn once.
 *     If retry also fails, call `mapGoogleError` on the retry error.
 *   - Non-401 from initial call: call `mapGoogleError` directly (no retry).
 *
 * `mapGoogleError` always throws (`return never`), so this function never
 * returns from the catch branches — only from the happy path or the retry
 * success branch.
 */
export async function withGoogleApi<T>(
  email: string,
  tool: string,
  fn: (auth: OAuth2Client) => Promise<T>,
  deps?: AuthDeps,
): Promise<T> {
  let auth: OAuth2Client;
  try {
    auth = await getAuthClient(email, deps);
    return await fn(auth);
  } catch (err) {
    if (isUnauthorized(err)) {
      // One retry with force refresh — bypass skip-when-valid cache so we
      // hit the network and get a fresh access_token even if our clock
      // thinks the cached one is still valid.
      try {
        auth = await getAuthClient(email, { ...deps, force: true });
        return await fn(auth);
      } catch (retryErr) {
        mapGoogleError(retryErr, { tool, email });
      }
    }
    mapGoogleError(err, { tool, email });
  }
}
