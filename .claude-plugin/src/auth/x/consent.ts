// v1.113 — the X (Twitter) OAuth 2.0 PKCE consent flow. SafeSpace's 4th OAuth
// source and the first non-Google source that REQUIRES PKCE (S256) + proactive
// access-token refresh. Mirrors auth/notion/consent.ts (loopback authorization-
// code dance via auth/oauth-callback.ts + D2 cleanup-on-failure), with X specifics:
//   - PKCE S256 (code_verifier / code_challenge) + random state CSRF.
//   - identity via a FOLLOW-UP `GET /2/users/me` (unlike Notion's in-token workspace
//     id; like GitHub's GET /user).
//   - scopes are a FIXED MVP set (`tweet.read users.read tweet.write offline.access`);
//     Source.requiredScopes is empty (authorize is a no-op; tier is enforced elsewhere).
//   - BOTH confidential (HTTP Basic) and public (client_id in body) clients, selected
//     by whether SAFESPACE_X_CLIENT_SECRET is set.
//
// SECURITY:
//   - the access/refresh tokens + client_secret + code_verifier are NEVER logged,
//     echoed, or placed in a thrown Error message (only a sanitized lowercase X
//     error code surfaces).
//   - tokens are persisted only via the SecretBackend (auth/x/oauth.ts), read back
//     through a getter, never a serializable field.
//   - the loopback redirect is 127.0.0.1-bound (auth/oauth-callback.ts); the state
//     CSRF token is verified there before the code is accepted.
//   - every process-owned fetch (token exchange, users/me) calls assertEgressHost
//     against connector "x" BEFORE dispatch.

import { ENV_X_CLIENT_ID, ENV_X_CLIENT_SECRET } from "../../config";
import { acquireConsentLock } from "../consent";
import { startCallbackServer } from "../oauth-callback";
import { openUrl } from "../open-url";
import { X_ERROR_CODE_RE, xFetch } from "./http";
import {
  X_USER_ID_RE,
  X_USERNAME_RE,
  USERNAME_MAX,
  addXAccount,
  clampExpiresIn,
  clearXToken,
  readXAccounts,
  removeXAccount,
  tokenPayloadFromGrant,
  writeXToken,
} from "./oauth";
import { codeChallengeS256, generateCodeVerifier, generateState } from "./pkce";

const AUTHORIZE_URL = "https://x.com/i/oauth2/authorize";
const TOKEN_URL = "https://api.x.com/2/oauth2/token";
const USER_URL = "https://api.x.com/2/users/me";
/** Fixed MVP scope set (space-separated). offline.access is required for the
 *  refresh_token that makes proactive refresh possible. */
export const X_SCOPES = "tweet.read users.read tweet.write offline.access";

export interface XConsentDeps {
  /** Test seam — defaults to the global `fetch`. Injected in tests so no real network
   *  call is made; the injected impl ignores the AbortSignal. */
  fetchImpl?: typeof fetch;
  /** Test seam — open the authorize URL in the browser. Defaults to the cross-platform
   *  `openUrl` helper. Tests inject an impl that drives the loopback callback. */
  openImpl?: (url: string) => void;
}

/** The result of a successful X consent — the user id + username. The tokens are NOT
 *  returned (they live only in the SecretBackend). */
export interface XConsentResult {
  readonly userId: string;
  readonly username: string;
}

/** Exchange the authorization code (+ PKCE verifier) for access + refresh tokens.
 *  NEVER echoes the client_secret, code_verifier, or the tokens. */
async function exchangeCode(
  fetchImpl: typeof fetch,
  body: {
    clientId: string;
    clientSecret: string | undefined;
    code: string;
    redirectUri: string;
    codeVerifier: string;
  },
): Promise<{ accessToken: string; refreshToken: string; expiresIn: number; scope: string }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code: body.code,
    redirect_uri: body.redirectUri,
    code_verifier: body.codeVerifier,
  });
  if (body.clientSecret) {
    headers.Authorization = `Basic ${Buffer.from(`${body.clientId}:${body.clientSecret}`).toString("base64")}`;
  } else {
    params.set("client_id", body.clientId);
  }
  const res = await xFetch(fetchImpl, TOKEN_URL, {
    method: "POST",
    headers,
    body: params.toString(),
  });
  if (!res.ok) {
    let code: string | undefined;
    try {
      const obj = (await res.json()) as Record<string, unknown>;
      if (typeof obj.error === "string" && X_ERROR_CODE_RE.test(obj.error)) code = obj.error;
    } catch {
      /* unparseable — fall through to the status-only message */
    }
    throw new Error(
      code
        ? `x token exchange failed: ${code}`
        : `x token exchange failed (HTTP ${res.status})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new Error("x token exchange returned an unparseable response");
  }
  const obj = (parsed ?? {}) as Record<string, unknown>;
  const err = obj.error;
  if (typeof err === "string") {
    const safe = X_ERROR_CODE_RE.test(err) ? err : "unknown_error";
    throw new Error(`x token exchange failed: ${safe}`);
  }
  if (typeof obj.access_token !== "string" || obj.access_token.length === 0) {
    throw new Error("x token exchange returned no access_token");
  }
  if (typeof obj.refresh_token !== "string" || obj.refresh_token.length === 0) {
    // offline.access is in our scope set — a grant without a refresh token is unusable
    // for the proactive-refresh model. Fail closed rather than persist a 2h-only token.
    throw new Error("x token exchange returned no refresh_token");
  }
  // Clamp so a misbehaving token endpoint cannot push expires_at past the
  // proactive-refresh horizon (tokenPayloadFromGrant re-clamps defense-in-depth).
  const expiresIn = clampExpiresIn(obj.expires_in);
  return {
    accessToken: obj.access_token,
    refreshToken: obj.refresh_token,
    expiresIn,
    scope: typeof obj.scope === "string" ? obj.scope : X_SCOPES,
  };
}

/** Resolve the authenticated identity (id + username) for `accessToken`. NEVER
 *  echoes the token. */
async function fetchIdentity(
  fetchImpl: typeof fetch,
  accessToken: string,
): Promise<{ userId: string; username: string }> {
  const url = new URL(USER_URL);
  url.searchParams.set("user.fields", "id,username");
  const res = await xFetch(fetchImpl, url.toString(), {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    throw new Error(`x identity check failed (HTTP ${res.status})`);
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new Error("x identity check returned an unparseable response");
  }
  const data = (parsed as { data?: unknown })?.data;
  if (!data || typeof data !== "object") {
    throw new Error("x identity check returned no data");
  }
  const d = data as { id?: unknown; username?: unknown };
  if (typeof d.id !== "string" || !X_USER_ID_RE.test(d.id)) {
    throw new Error("x identity check returned no valid user id");
  }
  if (typeof d.username !== "string" || !X_USERNAME_RE.test(d.username)) {
    throw new Error("x identity check returned no valid username");
  }
  return { userId: d.id, username: d.username.slice(0, USERNAME_MAX) };
}

/**
 * Run the X OAuth 2.0 PKCE consent flow. Opens the browser, awaits the loopback
 * callback, exchanges the code (+ verifier), fetches users/me for the identity,
 * and persists the account + token payload via the provider-keyed store. Returns
 * the user id + username. MULTI-account — the account is discovered (no expected id).
 *
 * D2 cleanup discipline (mirror auth/notion/consent.ts): local x state is wiped on
 * failure ONLY if this run already wrote a token for a NEWLY-added account (so a
 * mid-flow failure can never destroy a PRIOR successful x consent).
 */
export async function xConsent(deps: XConsentDeps = {}): Promise<XConsentResult> {
  const clientId = process.env[ENV_X_CLIENT_ID];
  if (!clientId) {
    throw new Error(
      "SAFESPACE_X_CLIENT_ID environment variable is required (SAFESPACE_X_CLIENT_SECRET is optional for public clients)",
    );
  }
  // Optional: presence selects confidential vs public client.
  const clientSecret = process.env[ENV_X_CLIENT_SECRET] || undefined;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const open = deps.openImpl ?? openUrl;

  // One consent at a time (the key carries ":" → can never collide with an email).
  const lock = await acquireConsentLock("x:consent");
  // The user id to CLEAN UP on a mid-flow failure — set ONLY when this run NEWLY
  // adds an account (a re-consent of an existing one already has a valid new token
  // + account, so it is never cleaned; a prior consent of a DIFFERENT account is
  // never touched).
  let cleanupUserId: string | null = null;
  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = codeChallengeS256(codeVerifier);
    const cb = await startCallbackServer(state);
    try {
      const authUrl = new URL(AUTHORIZE_URL);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("redirect_uri", cb.url);
      authUrl.searchParams.set("scope", X_SCOPES);
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      console.error("[safespace] opening browser for x consent...");
      open(authUrl.toString());

      const { code } = await cb.await;
      const grant = await exchangeCode(fetchImpl, {
        clientId,
        clientSecret,
        code,
        redirectUri: cb.url,
        codeVerifier,
      });
      const { userId, username } = await fetchIdentity(fetchImpl, grant.accessToken);

      // Is this a NEW account (vs a re-consent of an existing one)? Decide BEFORE any
      // write so the cleanup flag covers a failure during addXAccount too.
      const wasNew = !(await readXAccounts()).some((a) => a.id === userId);
      // Token first (so a crash before the account write leaves a recoverable
      // token-without-account → account_not_found, not the reverse). Arm cleanup ONLY
      // for a newly-added account — a re-consent's new token is already valid, so it's kept.
      await writeXToken(
        userId,
        tokenPayloadFromGrant({
          access_token: grant.accessToken,
          refresh_token: grant.refreshToken,
          expires_in: grant.expiresIn,
          scope: grant.scope,
        }),
      );
      if (wasNew) cleanupUserId = userId;
      await addXAccount({ id: userId, username });
      console.error(`[safespace] x consent saved for @${username}`);
      return { userId, username };
    } finally {
      cb.stop();
    }
  } catch (err) {
    // D2: wipe ONLY a newly-added account this run persisted. A failure before the
    // token write leaves cleanupUserId null → a prior consent (and a re-consent's
    // valid new token) survive.
    if (cleanupUserId) {
      await clearXToken(cleanupUserId).catch(() => undefined);
      await removeXAccount(cleanupUserId).catch(() => undefined);
    }
    throw err;
  } finally {
    await lock.release();
  }
}
