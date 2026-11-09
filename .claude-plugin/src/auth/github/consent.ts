// v1.70 (G3) — the GitHub OAuth App consent flow. SafeSpace's 2nd OAuth source.
//
// Shape vs Google (auth/consent.ts): same loopback authorization-code dance
// (shared auth/oauth-callback.ts) + the same single-account-lock + D2
// cleanup-on-failure discipline, but the provider specifics differ:
//   - NO PKCE, NO id_token. A GitHub OAuth App uses the client-secret token
//     exchange; you learn the identity by an authenticated API call, not a
//     signed id_token. So the identity step is `GET https://api.github.com/user`.
//   - scopes are FLAT (auth/github/scopes.ts) — no SCOPE_HIERARCHY.
//   - the token does NOT refresh (githubSource.refreshable=false) — there is no
//     refresh_token to persist; the access token is stored as-is.
//
// SECURITY INVARIANTS (verified by consent.test.ts + the G3 sec-review hooks,
// docs/v1.70-github-oauth-connector.md §12):
//   - the GitHub token + the client_secret are NEVER logged, echoed, or placed in
//     a thrown Error message (only GitHub's fixed lowercase error CODES surface).
//   - the token is persisted only via the SecretBackend (auth/github/store.ts),
//     read back through a getter, never a serializable field.
//   - the consented identity is verified to match the expected login
//     (login_mismatch), mirroring Google's email_mismatch guard.
//   - the loopback redirect is 127.0.0.1-bound (auth/oauth-callback.ts).

import * as crypto from "node:crypto";
import { acquireConsentLock } from "../consent";
import { startCallbackServer } from "../oauth-callback";
import { openUrl } from "../open-url";
import { GITHUB_API_VERSION } from "./client";
import {
  GITHUB_LOGIN_RE,
  clearGithubAccount,
  clearGithubToken,
  writeGithubAccount,
  writeGithubToken,
} from "./store";
import {
  GITHUB_REQUIRED_SCOPES,
  findMissingGithubScopes,
  githubScopeParam,
} from "./scopes";

const AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_URL = "https://api.github.com/user";
const USER_AGENT = "safespace-mcp";
/** A consent network step should not hang the CLI indefinitely (mirrors the
 *  v1.69.1 service-token-fetch 10 s discipline; a human is waiting). */
const NETWORK_TIMEOUT_MS = 15_000;

/** GitHub's token-exchange / API `error` field is a fixed lowercase-underscore
 *  enum (`bad_verification_code`, `incorrect_client_credentials`, …). Surface
 *  ONLY a value matching this shape, so an unexpected reflected body can never
 *  leak into a thrown message. */
const GITHUB_ERROR_CODE_RE = /^[a-z_]{1,64}$/;

export interface GithubConsentDeps {
  /** Test seam — defaults to the global `fetch`. Injected in tests so no real
   *  network call is made; the injected impl ignores the AbortSignal. */
  fetchImpl?: typeof fetch;
  /** Test seam — open the authorize URL in the browser. Defaults to the
   *  cross-platform `openUrl` helper. Tests inject an impl that drives the loopback
   *  callback (parse redirect_uri + state, fire GET /callback?code=…&state=…). */
  openImpl?: (url: string) => void;
}

/** The result of a successful GitHub consent — the canonical login (as GitHub
 *  spells it) + the scopes the grant carried. The token is NOT returned (it lives
 *  only in the SecretBackend). */
export interface GithubConsentResult {
  readonly login: string;
  readonly scopes: string[];
}

async function githubFetch(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit & { headers: Record<string, string> },
): Promise<Response> {
  // AbortController + a CLEARED timer (not AbortSignal.timeout) so the timer can
  // never outlive the request — an uncleared timeout keeps the event loop alive
  // (and would hang a test whose injected fetch ignores the signal).
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
  try {
    return await fetchImpl(url, {
      ...init,
      headers: { "User-Agent": USER_AGENT, ...init.headers },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Exchange the authorization code for an access token. Returns the token + the
 *  granted-scope string. NEVER echoes the client_secret or the token. */
async function exchangeCode(
  fetchImpl: typeof fetch,
  body: { clientId: string; clientSecret: string; code: string; redirectUri: string },
): Promise<{ accessToken: string; scope: string | undefined }> {
  const res = await githubFetch(fetchImpl, TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: body.clientId,
      client_secret: body.clientSecret,
      code: body.code,
      redirect_uri: body.redirectUri,
    }),
  });
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    throw new Error(`github token exchange failed (HTTP ${res.status})`);
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new Error("github token exchange returned an unparseable response");
  }
  const obj = (parsed ?? {}) as Record<string, unknown>;
  const err = obj.error;
  if (typeof err === "string") {
    const safe = GITHUB_ERROR_CODE_RE.test(err) ? err : "unknown_error";
    throw new Error(`github token exchange failed: ${safe}`);
  }
  if (typeof obj.access_token !== "string" || obj.access_token.length === 0) {
    throw new Error("github token exchange returned no access_token");
  }
  return {
    accessToken: obj.access_token,
    scope: typeof obj.scope === "string" ? obj.scope : undefined,
  };
}

/** Resolve the authenticated identity (the `login`) for `token`. NEVER echoes the
 *  token. */
async function fetchLogin(fetchImpl: typeof fetch, token: string): Promise<string> {
  const res = await githubFetch(fetchImpl, USER_URL, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
    },
  });
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    throw new Error(`github identity check failed (HTTP ${res.status})`);
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new Error("github identity check returned an unparseable response");
  }
  const login = (parsed as { login?: unknown })?.login;
  if (typeof login !== "string" || !GITHUB_LOGIN_RE.test(login)) {
    throw new Error("github identity check returned no valid login");
  }
  return login;
}

/**
 * Run the GitHub OAuth App consent flow for the user who intends to authorize as
 * `expectedLogin`. Opens the browser, awaits the loopback callback, exchanges the
 * code, verifies the granted scopes + the consented identity, and persists the
 * account + token via the provider-keyed store. Returns the canonical login +
 * granted scopes.
 *
 * Mirrors auth/consent.ts's D2 cleanup discipline: local github state is wiped on
 * failure ONLY if this run already wrote a token (so a mid-flow failure can never
 * destroy a PRIOR successful github consent).
 */
export async function githubConsent(
  expectedLogin: string,
  deps: GithubConsentDeps = {},
): Promise<GithubConsentResult> {
  if (!GITHUB_LOGIN_RE.test(expectedLogin)) {
    throw new Error("githubConsent: invalid github login");
  }
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error(
      "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables are required",
    );
  }
  const fetchImpl = deps.fetchImpl ?? fetch;
  const open = deps.openImpl ?? openUrl;

  // Lock keyed in the github namespace — `github:<login>` can never collide with
  // a Google email lock (emails carry "@", not ":").
  const lock = await acquireConsentLock(`github:${expectedLogin}`);
  // Track the login we actually persisted (the canonical one from the API) so
  // cleanup-on-failure wipes exactly that, and ONLY once a token was written.
  let persistedLogin: string | null = null;
  try {
    const state = crypto.randomBytes(32).toString("base64url");
    const cb = await startCallbackServer(state);
    try {
      const authUrl = new URL(AUTHORIZE_URL);
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("redirect_uri", cb.url);
      authUrl.searchParams.set("scope", githubScopeParam());
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("allow_signup", "false");

      console.error(`[safespace] opening browser for github (${expectedLogin}) consent...`);
      open(authUrl.toString());

      const { code } = await cb.await;
      const { accessToken, scope } = await exchangeCode(fetchImpl, {
        clientId,
        clientSecret,
        code,
        redirectUri: cb.url,
      });

      const missing = findMissingGithubScopes(scope, GITHUB_REQUIRED_SCOPES);
      if (missing.length > 0) {
        throw new Error(`github consent did not grant required scopes: ${missing.join(", ")}`);
      }

      const login = await fetchLogin(fetchImpl, accessToken);
      // Case-insensitive identity match (GitHub logins are case-insensitive); we
      // persist the canonical spelling the API returned.
      if (login.toLowerCase() !== expectedLogin.toLowerCase()) {
        throw new Error(`login_mismatch: consented as ${login}, expected ${expectedLogin}`);
      }

      const grantedScopes = (scope ?? "").split(/[\s,]+/).filter(Boolean);
      // Token first (so a crash before the account write leaves a recoverable
      // token-without-account → account_not_found, not the reverse). Set the
      // cleanup flag the moment the token lands.
      await writeGithubToken(login, accessToken);
      persistedLogin = login;
      await writeGithubAccount({ login, scopes: grantedScopes });
      console.error(`[safespace] github consent saved for ${login}`);
      return { login, scopes: grantedScopes };
    } finally {
      cb.stop();
    }
  } catch (err) {
    // D2 discipline: only wipe if THIS run persisted a token. A failure before
    // the token write (browser closed, state_mismatch, scope shortfall,
    // login_mismatch, network drop) must NOT destroy a prior github consent.
    if (persistedLogin) {
      await clearGithubToken(persistedLogin).catch(() => undefined);
      await clearGithubAccount().catch(() => undefined);
    }
    throw err;
  } finally {
    await lock.release();
  }
}
