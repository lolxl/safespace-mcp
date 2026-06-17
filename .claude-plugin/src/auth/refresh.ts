// Per-account access-token refresh with mutex coalescing.
// See docs/DESIGN.md §Concurrency & Crash Safety (Issue 2A).
//
// Security-review fixes (2026-05-07, pre-implementation):
//   - 10s AbortController timeout on the token POST so a hanging upstream
//     does not block all in-flight tool calls for the same email.
//   - Discard `error_description` from non-200 response (could echo token
//     fragments); only the canonical OAuth `error` code influences mapping.
//   - No raw error / cause forwarded into MCPError.errorData — only `email`.
//
// Cross-process note: the in-process Map<email, Promise> coalesces concurrent
// refreshes within ONE Bun process. Two Claude Code instances refreshing the
// same email in parallel will race; v1 accepts last-writer-wins per
// docs/DESIGN.md §Reviewer Concerns.
//
// Scope-on-refresh note: granted scopes are NOT re-validated on refresh
// (intentional, per DESIGN.md §Edge Cases). If the user revokes a scope
// from Google's security dashboard between consent and runtime, the next
// tool call hits 403 → mapped to scope_mismatch → user re-runs `consent`.

import { MCPError } from "../errors";
// v1.37 BLOCKER 1: token get/set/delete defaults now route through the
// SecretBackend facade (email-only API = drop-in for the old keychain.* fns);
// removeAccount is the accounts.json index half, still in keychain.ts.
import * as tokenStore from "./token-store";
import { removeAccount as keychainRemoveAccount } from "./keychain";

export interface TokenSet {
  refresh_token: string;
  access_token: string;
  expires_at: number; // ms epoch
  scopes: string[];
  obtained_at: number; // ms epoch
}

export interface RefreshDeps {
  getToken?: (email: string) => Promise<string | null>;
  setToken?: (email: string, json: string) => Promise<void>;
  deleteToken?: (email: string) => Promise<void>;
  removeAccount?: (email: string) => Promise<void>;
  fetchImpl?: typeof fetch;
  /**
   * When true, bypass the skip-when-valid cache check and force a network
   * refresh. Used by with-context.ts when an upstream 401 indicates the
   * cached access_token is stale even though our local clock says it isn't.
   */
  force?: boolean;
}

const REFRESH_BUFFER_MS = 60_000;
const REFRESH_TIMEOUT_MS = 10_000;
const TOKEN_URL = "https://oauth2.googleapis.com/token";

const refreshInFlight = new Map<string, Promise<TokenSet>>();

// In-memory TokenSet cache keyed by email. with-context.ts calls
// refreshAccessToken on EVERY tool call; before this cache, that meant a
// SecretBackend read per call — on the FileBackend passphrase path a full
// scrypt(N=2^17) derivation (~128 MiB) every time, even when the cached access
// token was still valid and no network refresh was due. The cache returns a
// still-valid TokenSet without touching the backend at all, so getToken (and
// its scrypt / Keychain read) runs only when the token is near expiry.
//
// Posture: a long-lived MCP server already holds the live access_token in
// memory for the duration of each call; this extends that to the process
// lifetime. The at-rest encryption guarantee (FileBackend) is unaffected — it
// protects the disk, not the running process heap. Invalidated on force-refresh
// failure (invalid_grant), on a corrupt cached blob, and on the explicit
// invalidateTokenCache() call from the with-context.ts 401 double-fail cleanup.
const tokenCache = new Map<string, TokenSet>();

/** Drop a cached TokenSet. Called from the with-context.ts 401 double-fail
 *  cleanup so a removed account does not keep a stale entry. Safe for an
 *  absent email. */
export function invalidateTokenCache(email: string): void {
  tokenCache.delete(email);
}

/** Test-only: clear the whole in-memory TokenSet cache between cases. */
export function _resetTokenCacheForTests(): void {
  tokenCache.clear();
}

export async function refreshAccessToken(
  email: string,
  deps: RefreshDeps = {},
): Promise<TokenSet> {
  // Hot-path fast return: a still-valid cached TokenSet skips the SecretBackend
  // read entirely (no Keychain hit / no FileBackend scrypt). Bypassed on force
  // (an upstream 401 means the token is stale despite a healthy local clock).
  if (!deps.force) {
    const memo = tokenCache.get(email);
    if (memo && memo.expires_at - REFRESH_BUFFER_MS > Date.now()) {
      return memo;
    }
  }

  const getToken = deps.getToken ?? tokenStore.getToken;
  const cachedJson = await getToken(email);
  if (!cachedJson) {
    throw new MCPError("account_not_found", { email });
  }

  let cached: TokenSet;
  try {
    cached = JSON.parse(cachedJson) as TokenSet;
  } catch {
    const dt = deps.deleteToken ?? tokenStore.deleteToken;
    await dt(email).catch(() => undefined);
    invalidateTokenCache(email);
    throw new MCPError("account_not_found", { email });
  }

  if (!deps.force && cached.expires_at - REFRESH_BUFFER_MS > Date.now()) {
    tokenCache.set(email, cached);
    return cached;
  }

  if (deps.force) {
    // Force always issues an independent refresh — joining an in-flight refresh
    // could return a token that, while fresh by clock, was generated before the
    // caller learned its current token was rejected. Trade-off: concurrent
    // force calls may issue duplicate refreshes (rare; bounded by mutex semantics
    // of the natural code path).
    return doRefresh(email, cached, deps);
  }

  let pending = refreshInFlight.get(email);
  if (pending) return pending;

  pending = doRefresh(email, cached, deps).finally(() => refreshInFlight.delete(email));
  refreshInFlight.set(email, pending);
  return pending;
}

async function doRefresh(email: string, prev: TokenSet, deps: RefreshDeps): Promise<TokenSet> {
  const setToken = deps.setToken ?? tokenStore.setToken;
  const deleteToken = deps.deleteToken ?? tokenStore.deleteToken;
  const removeAccount = deps.removeAccount ?? keychainRemoveAccount;
  const fetchImpl = deps.fetchImpl ?? fetch;

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required");
  }

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), REFRESH_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetchImpl(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: prev.refresh_token,
        client_id: clientId,
        client_secret: clientSecret,
      }).toString(),
      signal: ac.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    // Read body ONLY to extract the canonical OAuth `error` code. Discard
    // every other field — Google's `error_description` may contain token
    // fragments that would leak into MCPError.data otherwise.
    let errCode = "";
    try {
      const body = (await res.json()) as { error?: unknown };
      errCode = typeof body.error === "string" ? body.error : "";
    } catch {
      /* response not JSON */
    }
    if (errCode === "invalid_grant") {
      invalidateTokenCache(email);
      await deleteToken(email).catch(() => undefined);
      await removeAccount(email).catch(() => undefined);
      throw new MCPError("refresh_token_invalid", { email });
    }
    throw new Error(`google_token_endpoint_${res.status}`);
  }

  const body = (await res.json()) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
  };

  const next: TokenSet = {
    refresh_token: body.refresh_token ?? prev.refresh_token,
    access_token: body.access_token,
    expires_at: Date.now() + body.expires_in * 1000,
    scopes: body.scope ? body.scope.split(/\s+/).filter(Boolean) : prev.scopes,
    obtained_at: Date.now(),
  };

  // Write-then-return: persist to Keychain BEFORE caller sees the new token,
  // so a process crash mid-return does not lose a rotated refresh_token.
  await setToken(email, JSON.stringify(next));
  // ORDERING: must follow the `await setToken` above. If setToken throws, this
  // line never runs, so the cache can never hold a token that was not persisted.
  // Populating it here lets the next call (within validity) skip the backend read.
  tokenCache.set(email, next);
  return next;
}
