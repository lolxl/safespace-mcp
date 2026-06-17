// v1.78 (Notion B) — the Notion public-integration OAuth consent flow. SafeSpace's 3rd
// OAuth source. Mirrors auth/github/consent.ts (the shared loopback authorization-code
// dance via auth/oauth-callback.ts + the D2 cleanup-on-failure discipline), with the
// Notion specifics:
//   - NO PKCE, NO scope param. The token exchange is HTTP Basic (client_id:client_secret
//     in the Authorization header — Notion does NOT accept the secret in the body).
//   - the identity (workspace_id + workspace_name) comes back IN the token-exchange
//     response — there is NO separate identity API call (unlike GitHub's GET /user).
//   - the token does NOT refresh (notionSource.refreshable=false) — stored as-is.
//
// SECURITY:
//   - the Notion token + the client_secret are NEVER logged, echoed, or placed in a thrown
//     Error message (only a sanitized lowercase Notion error code surfaces).
//   - the token is persisted only via the SecretBackend (auth/notion/oauth.ts), read back
//     through a getter, never a serializable field.
//   - the loopback redirect is 127.0.0.1-bound (auth/oauth-callback.ts); the state CSRF
//     token is verified there before the code is accepted.

import * as crypto from "node:crypto";
import { acquireConsentLock } from "../consent";
import { startCallbackServer } from "../oauth-callback";
import { openUrl } from "../open-url";
import {
  NOTION_WORKSPACE_ID_RE,
  WORKSPACE_NAME_MAX,
  addNotionAccount,
  clearNotionToken,
  readNotionAccounts,
  removeNotionAccount,
  writeNotionToken,
} from "./oauth";

const AUTHORIZE_URL = "https://api.notion.com/v1/oauth/authorize";
const TOKEN_URL = "https://api.notion.com/v1/oauth/token";
const USER_AGENT = "safespace-mcp";
/** A consent network step should not hang the CLI indefinitely (mirrors the github
 *  consent + v1.69.1 service-token-fetch 15/10 s discipline; a human is waiting). */
const NETWORK_TIMEOUT_MS = 15_000;

/** Notion's OAuth `error` field is a fixed lowercase-underscore enum
 *  (`invalid_grant`, `invalid_request`, …). Surface ONLY a value matching this shape, so
 *  an unexpected reflected body / error_description can never leak into a thrown message. */
const NOTION_ERROR_CODE_RE = /^[a-z_]{1,64}$/;

export interface NotionConsentDeps {
  /** Test seam — defaults to the global `fetch`. Injected in tests so no real network
   *  call is made; the injected impl ignores the AbortSignal. */
  fetchImpl?: typeof fetch;
  /** Test seam — open the authorize URL in the browser. Defaults to the cross-platform
   *  `openUrl` helper. Tests inject an impl that drives the loopback callback. */
  openImpl?: (url: string) => void;
}

/** The result of a successful Notion consent — the workspace id + name. The token is NOT
 *  returned (it lives only in the SecretBackend). */
export interface NotionConsentResult {
  readonly workspaceId: string;
  readonly workspaceName: string;
}

async function notionFetch(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit & { headers: Record<string, string> },
): Promise<Response> {
  // AbortController + a CLEARED timer (not AbortSignal.timeout) so the timer can never
  // outlive the request (an uncleared timeout keeps the event loop alive).
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

/** Exchange the authorization code (HTTP Basic auth) for an access token + the workspace
 *  identity. NEVER echoes the client_secret or the token. */
async function exchangeCode(
  fetchImpl: typeof fetch,
  body: { clientId: string; clientSecret: string; code: string; redirectUri: string },
): Promise<{ accessToken: string; workspaceId: string; workspaceName: string }> {
  const basic = Buffer.from(`${body.clientId}:${body.clientSecret}`).toString("base64");
  const res = await notionFetch(fetchImpl, TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: body.code,
      redirect_uri: body.redirectUri,
    }),
  });
  if (!res.ok) {
    // A non-2xx may still carry a JSON `{error}` — try to surface the sanitized code,
    // else just the status. NEVER echo the raw body (it can hold error_description).
    let code: string | undefined;
    try {
      const obj = (await res.json()) as Record<string, unknown>;
      if (typeof obj.error === "string" && NOTION_ERROR_CODE_RE.test(obj.error)) code = obj.error;
    } catch {
      /* unparseable — fall through to the status-only message */
    }
    throw new Error(
      code
        ? `notion token exchange failed: ${code}`
        : `notion token exchange failed (HTTP ${res.status})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new Error("notion token exchange returned an unparseable response");
  }
  const obj = (parsed ?? {}) as Record<string, unknown>;
  const err = obj.error;
  if (typeof err === "string") {
    const safe = NOTION_ERROR_CODE_RE.test(err) ? err : "unknown_error";
    throw new Error(`notion token exchange failed: ${safe}`);
  }
  if (typeof obj.access_token !== "string" || obj.access_token.length === 0) {
    throw new Error("notion token exchange returned no access_token");
  }
  if (typeof obj.workspace_id !== "string" || !NOTION_WORKSPACE_ID_RE.test(obj.workspace_id)) {
    throw new Error("notion token exchange returned no valid workspace_id");
  }
  const workspaceName =
    typeof obj.workspace_name === "string" ? obj.workspace_name.slice(0, WORKSPACE_NAME_MAX) : "";
  return { accessToken: obj.access_token, workspaceId: obj.workspace_id, workspaceName };
}

/**
 * Run the Notion public-integration OAuth consent flow. Opens the browser, awaits the
 * loopback callback, exchanges the code (Basic auth), reads the workspace identity from the
 * response, and persists the account + token via the provider-keyed store. Returns the
 * workspace id + name. SINGLE-WORKSPACE v1 — the workspace is discovered (no expected id).
 *
 * D2 cleanup discipline (mirror auth/github/consent.ts): local notion state is wiped on
 * failure ONLY if this run already wrote a token (so a mid-flow failure can never destroy a
 * PRIOR successful notion consent).
 */
export async function notionConsent(deps: NotionConsentDeps = {}): Promise<NotionConsentResult> {
  const clientId = process.env.NOTION_CLIENT_ID;
  const clientSecret = process.env.NOTION_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error(
      "NOTION_CLIENT_ID and NOTION_CLIENT_SECRET environment variables are required",
    );
  }
  const fetchImpl = deps.fetchImpl ?? fetch;
  const open = deps.openImpl ?? openUrl;

  // One consent at a time (the key carries ":" → can never collide with an email).
  const lock = await acquireConsentLock("notion:consent");
  // The workspace to CLEAN UP on a mid-flow failure — set ONLY when this run NEWLY adds a
  // workspace (a re-consent of an existing one already has a valid new token + account, so
  // it is never cleaned; a prior consent of a DIFFERENT workspace is never touched).
  let cleanupWorkspaceId: string | null = null;
  try {
    const state = crypto.randomBytes(32).toString("base64url");
    const cb = await startCallbackServer(state);
    try {
      const authUrl = new URL(AUTHORIZE_URL);
      authUrl.searchParams.set("client_id", clientId);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("owner", "user");
      authUrl.searchParams.set("redirect_uri", cb.url);
      authUrl.searchParams.set("state", state);

      console.error("[safespace] opening browser for notion consent...");
      open(authUrl.toString());

      const { code } = await cb.await;
      const { accessToken, workspaceId, workspaceName } = await exchangeCode(fetchImpl, {
        clientId,
        clientSecret,
        code,
        redirectUri: cb.url,
      });

      // Is this a NEW workspace (vs a re-consent of an existing one)? Decide BEFORE any
      // write so the cleanup flag covers a failure during addNotionAccount too.
      const wasNew = !(await readNotionAccounts()).some((a) => a.workspaceId === workspaceId);
      // Token first (so a crash before the account write leaves a recoverable
      // token-without-account → account_not_found, not the reverse). Arm cleanup ONLY for a
      // newly-added workspace — a re-consent's new token is already valid, so it's kept.
      await writeNotionToken(workspaceId, accessToken);
      if (wasNew) cleanupWorkspaceId = workspaceId;
      // ADD to the index (upsert; re-consent updates the name) + make it the active workspace.
      await addNotionAccount({ workspaceId, workspaceName });
      console.error(`[safespace] notion consent saved for workspace ${workspaceId}`);
      return { workspaceId, workspaceName };
    } finally {
      cb.stop();
    }
  } catch (err) {
    // D2: wipe ONLY a newly-added workspace this run persisted. A failure before the token
    // write (browser closed, state_mismatch, exchange error, network drop) leaves
    // cleanupWorkspaceId null → a prior consent (and a re-consent's valid new token) survive.
    if (cleanupWorkspaceId) {
      await clearNotionToken(cleanupWorkspaceId).catch(() => undefined);
      await removeNotionAccount(cleanupWorkspaceId).catch(() => undefined);
    }
    throw err;
  } finally {
    await lock.release();
  }
}
