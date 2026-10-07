// v1.113 — the X (Twitter) OAuth 2.0 account + token store.
// X is SafeSpace's 4th OAuth source and the FIRST non-Google source whose access
// tokens expire + refresh (2h access tokens; X may rotate the refresh token on
// each use — single-use rotation). Multi-account (multiple consented X users,
// one active), mirroring Notion's multi-workspace store:
//   - accounts + active pointer live in `x-account.json`
//     ({ accounts:[{id, username}], active })
//   - each TOKEN lives in the SecretBackend under a RESERVED key `x:<userId>`
//     (contains ":" and no "@" → never collides with a Google email key).
//
// Token payload (JSON string in the backend):
//   { access_token, refresh_token, expires_at, scope }
// where `expires_at` is epoch-ms computed from `expires_in` at grant/refresh time.
//
// Refresh is PROACTIVE inside `getValidAccessToken` (called by the Source's
// resolveCredential): if `expires_at - 120_000 <= Date.now()` the token is
// refreshed BEFORE being returned. The Source stays `refreshable: false` so the
// choke-point 401-retry path remains Google-only (DO NOT touch with-context.ts).
//
// SECURITY:
//   - tokens / refresh tokens are NEVER logged, echoed, or stored as a serializable
//     Credential field — handlers read them via the oauth Credential's getter.
//   - invalid_grant (or 400/401 from the token endpoint) → MCPError
//     x_api_failed{consent_required}; the stored token is NOT deleted (recovery =
//     re-run consent; a flaky network must not wipe a still-valid grant).
//   - single-flight per accountId so two concurrent resolveCredential calls trigger
//     exactly ONE token-endpoint request (a second concurrent refresh with a
//     already-rotated refresh token would get invalid_grant and falsely kill the
//     session).

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ENV_X_CLIENT_ID, ENV_X_CLIENT_SECRET } from "../../config";
import { MCPError } from "../../errors";
import { configDir } from "../keychain";
import type { SecretBackend } from "../secret-backend";
import { selectBackend } from "../select-backend";
import { xFetch } from "./http";

/** X user id: a numeric snowflake string. Anchored — rejects path separators /
 *  CRLF / "@" / ":" — so it is safe as a SecretBackend key segment. */
export const X_USER_ID_RE = /^[0-9]{1,32}$/;

/** X username: 1–15 chars of [A-Za-z0-9_] (X's own rule). Display-only and for
 *  id-or-username resolution; never a SecretBackend key. */
export const X_USERNAME_RE = /^[A-Za-z0-9_]{1,15}$/;

/** Username length cap on read (defense-in-depth; X's own limit is 15). */
export const USERNAME_MAX = 15;

const ACCOUNT_FILE = "x-account.json";
const TOKEN_URL = "https://api.x.com/2/oauth2/token";
/** Proactive refresh skew: refresh when the access token has ≤ 2 minutes left. */
export const REFRESH_SKEW_MS = 120_000;

/** Clamp token-endpoint `expires_in` (seconds) to [60, 86400]. Non-finite /
 *  absent → 7200 (X's documented 2h default). A misbehaving endpoint must not
 *  push `expires_at` so far out that proactive refresh never fires. */
export function clampExpiresIn(raw: unknown): number {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    if (raw < 60) return 60;
    if (raw > 86_400) return 86_400;
    return raw;
  }
  return 7200;
}

/** A consented X account: its stable user id + display username. */
export interface XAccount {
  readonly id: string;
  readonly username: string;
}

/** The persisted multi-account store: the consented accounts + the active one. */
export interface XStore {
  readonly accounts: XAccount[];
  readonly active: string | null;
}

/** The JSON payload stored under `x:<userId>` in the SecretBackend. */
export interface XTokenPayload {
  readonly access_token: string;
  readonly refresh_token: string;
  /** Epoch ms when the access_token expires. */
  readonly expires_at: number;
  readonly scope: string;
}

function accountPath(): string {
  return path.join(configDir(), ACCOUNT_FILE);
}

const EMPTY: XStore = { accounts: [], active: null };

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** A valid account entry: a numeric id + a string username (capped on read). */
function parseAccount(v: unknown): XAccount | null {
  if (
    isObj(v) &&
    typeof v.id === "string" &&
    X_USER_ID_RE.test(v.id) &&
    typeof v.username === "string"
  ) {
    return { id: v.id, username: v.username.slice(0, USERNAME_MAX) };
  }
  return null;
}

/** Read the multi-account store, or an empty store if missing/corrupt. */
export async function readXStore(): Promise<XStore> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await fs.readFile(accountPath(), "utf8"));
  } catch {
    return EMPTY;
  }
  if (!isObj(parsed)) return EMPTY;
  const raw = Array.isArray(parsed.accounts) ? parsed.accounts : [];
  const accounts: XAccount[] = [];
  const seen = new Set<string>();
  for (const e of raw) {
    const a = parseAccount(e);
    if (a && !seen.has(a.id)) {
      seen.add(a.id);
      accounts.push(a);
    }
  }
  const active =
    typeof parsed.active === "string" && seen.has(parsed.active) ? parsed.active : null;
  return { accounts, active };
}

/** Persist the store (mode 0o600, dir 0o700). Rejects an invalid active/id before
 *  any filesystem work. */
export async function writeXStore(store: XStore): Promise<void> {
  for (const a of store.accounts) {
    if (!X_USER_ID_RE.test(a.id)) {
      throw new Error("writeXStore: invalid x user id");
    }
  }
  if (store.active != null && !store.accounts.some((a) => a.id === store.active)) {
    throw new Error("writeXStore: active is not a stored account");
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const out = {
    accounts: store.accounts.map((a) => ({
      id: a.id,
      username: a.username.slice(0, USERNAME_MAX),
    })),
    active: store.active,
  };
  await fs.writeFile(accountPath(), `${JSON.stringify(out, null, 2)}\n`, { mode: 0o600 });
}

/** The consented accounts (the index). */
export async function readXAccounts(): Promise<XAccount[]> {
  return (await readXStore()).accounts;
}

/** The active user id (validated to still be in the index), or null. */
export async function readXActiveAccount(): Promise<string | null> {
  return (await readXStore()).active;
}

/** Upsert an account (replace if its id already exists — a re-consent updates the
 *  username) and make it active. Returns whether it was NEWLY added. */
export async function addXAccount(account: XAccount): Promise<{ wasNew: boolean }> {
  if (!X_USER_ID_RE.test(account.id)) {
    throw new Error("addXAccount: invalid x user id");
  }
  const store = await readXStore();
  const wasNew = !store.accounts.some((a) => a.id === account.id);
  const accounts = store.accounts.filter((a) => a.id !== account.id);
  accounts.push({ id: account.id, username: account.username.slice(0, USERNAME_MAX) });
  await writeXStore({ accounts, active: account.id });
  return { wasNew };
}

/** Remove an account from the index; clears `active` if it pointed there. Idempotent. */
export async function removeXAccount(userId: string): Promise<void> {
  const store = await readXStore();
  const accounts = store.accounts.filter((a) => a.id !== userId);
  const active = store.active === userId ? null : store.active;
  if (accounts.length === 0) {
    await fs.unlink(accountPath()).catch(() => undefined);
    return;
  }
  await writeXStore({ accounts, active });
}

/** Set the active account (must already be in the index). */
export async function setXActiveAccount(userId: string): Promise<void> {
  const store = await readXStore();
  if (!store.accounts.some((a) => a.id === userId)) {
    throw new Error("setXActiveAccount: not a stored account");
  }
  await writeXStore({ accounts: store.accounts, active: userId });
}

/** Resolve `idOrUsername` against the consented accounts: an exact user id first,
 *  else a UNIQUE case-insensitive username match. Returns the match, "ambiguous"
 *  (>1 username match), or null (no match). PURE — reused by resolveAccount + CLI. */
export function findXAccount(
  idOrUsername: string,
  accounts: XAccount[],
): XAccount | "ambiguous" | null {
  const byId = accounts.find((a) => a.id === idOrUsername);
  if (byId) return byId;
  const lc = idOrUsername.toLowerCase();
  const byName = accounts.filter((a) => a.username.toLowerCase() === lc);
  if (byName.length === 1) return byName[0]!;
  if (byName.length > 1) return "ambiguous";
  return null;
}

/* ── token (SecretBackend, reserved key `x:<userId>`) ─────────────────────── */

let cachedBackend: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cachedBackend === null) cachedBackend = selectBackend();
  return cachedBackend;
}

/** Test-only: drop the cached backend so a test can flip the backend selection. */
export function __resetXBackendForTests(): void {
  cachedBackend = null;
}

function reservedKey(userId: string): string {
  if (!X_USER_ID_RE.test(userId)) {
    throw new Error("x store: invalid x user id");
  }
  return `x:${userId}`;
}

function parseTokenPayload(raw: string | null): XTokenPayload | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (
    !isObj(parsed) ||
    typeof parsed.access_token !== "string" ||
    parsed.access_token.length === 0 ||
    typeof parsed.refresh_token !== "string" ||
    parsed.refresh_token.length === 0 ||
    typeof parsed.expires_at !== "number" ||
    !Number.isFinite(parsed.expires_at)
  ) {
    return null;
  }
  return {
    access_token: parsed.access_token,
    refresh_token: parsed.refresh_token,
    expires_at: parsed.expires_at,
    scope: typeof parsed.scope === "string" ? parsed.scope : "",
  };
}

/** Read the stored X token payload for `userId`, or null if none/corrupt. */
export async function readXToken(userId: string): Promise<XTokenPayload | null> {
  return parseTokenPayload(await backend().getToken(reservedKey(userId)));
}

/** Persist the X token payload (the consent / refresh writer). Opaque to the backend. */
export async function writeXToken(userId: string, payload: XTokenPayload): Promise<void> {
  if (!X_USER_ID_RE.test(userId)) {
    throw new Error("x store: invalid x user id");
  }
  if (
    typeof payload.access_token !== "string" ||
    payload.access_token.length === 0 ||
    typeof payload.refresh_token !== "string" ||
    payload.refresh_token.length === 0 ||
    !Number.isFinite(payload.expires_at)
  ) {
    throw new Error("x store: invalid token payload");
  }
  const stored: XTokenPayload = {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    expires_at: payload.expires_at,
    scope: typeof payload.scope === "string" ? payload.scope : "",
  };
  await backend().setToken(reservedKey(userId), JSON.stringify(stored));
}

/** Remove the stored X token (account-revoke; idempotent at the backend). */
export async function clearXToken(userId: string): Promise<void> {
  await backend().deleteToken(reservedKey(userId));
}

/* ── proactive refresh (rotation-safe + single-flight) ────────────────────── */

/** Test seam — defaults to the global `fetch`. Injected so tests never hit the
 *  network; the injected impl ignores the AbortSignal. */
let fetchImplOverride: typeof fetch | null = null;

/** Test-only: inject (or clear) the fetch used by refresh. */
export function __setXFetchImplForTests(impl: typeof fetch | null): void {
  fetchImplOverride = impl;
}

/** In-flight refresh promises keyed by account id — single-flight so concurrent
 *  resolveCredential calls share ONE token-endpoint request. */
const inflightRefresh = new Map<string, Promise<XTokenPayload>>();

/** Test-only: drop any in-flight refresh map entries (between tests). */
export function __clearXRefreshInFlightForTests(): void {
  inflightRefresh.clear();
}

/** Build the token-endpoint auth + form body for a confidential (Basic) or public
 *  (client_id in body) client. NEVER logs the secret. */
function buildTokenRequest(
  form: Record<string, string>,
): { headers: Record<string, string>; body: string } {
  const clientId = process.env[ENV_X_CLIENT_ID];
  if (!clientId) {
    // Surface as consent_required — without a client id refresh cannot succeed.
    throw new MCPError("x_api_failed", { reason: "consent_required" });
  }
  const clientSecret = process.env[ENV_X_CLIENT_SECRET];
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  const params = new URLSearchParams(form);
  if (clientSecret) {
    // Confidential client: HTTP Basic (client_id:client_secret).
    headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
  } else {
    // Public client: client_id goes in the form body.
    params.set("client_id", clientId);
  }
  return { headers, body: params.toString() };
}

/** Exchange a refresh_token for a new access_token (+ optional rotated refresh).
 *  Rotation-safe: if the response omits refresh_token, the old one is kept. */
async function refreshTokens(
  fetchImpl: typeof fetch,
  current: XTokenPayload,
): Promise<XTokenPayload> {
  const { headers, body } = buildTokenRequest({
    grant_type: "refresh_token",
    refresh_token: current.refresh_token,
  });
  const res = await xFetch(fetchImpl, TOKEN_URL, { method: "POST", headers, body });
  if (!res.ok) {
    // 400/401 (incl. invalid_grant) → consent_required. Do NOT delete the store.
    // Drain the body so the connection is released; NEVER surface error_description
    // (or any field) — recovery is always re-consent.
    try {
      await res.json();
    } catch {
      /* unparseable — ignore */
    }
    throw new MCPError("x_api_failed", { reason: "consent_required" });
  }
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    throw new MCPError("x_api_failed", { reason: "api_error" });
  }
  const obj = (parsed ?? {}) as Record<string, unknown>;
  if (typeof obj.error === "string") {
    // A 200-with-error is unexpected but treat as consent_required for invalid_grant,
    // else api_error. NEVER surface the raw error string beyond the closed reason.
    const reason =
      obj.error === "invalid_grant" ? "consent_required" : "api_error";
    throw new MCPError("x_api_failed", { reason });
  }
  if (typeof obj.access_token !== "string" || obj.access_token.length === 0) {
    throw new MCPError("x_api_failed", { reason: "api_error" });
  }
  // Clamp expires_in so a misbehaving token endpoint cannot push expires_at
  // past the proactive-refresh horizon (or to a near-zero instant).
  const expiresIn = clampExpiresIn(obj.expires_in);
  // Rotation-safe: keep the old refresh_token if the response omits a new one.
  const refreshToken =
    typeof obj.refresh_token === "string" && obj.refresh_token.length > 0
      ? obj.refresh_token
      : current.refresh_token;
  const scope =
    typeof obj.scope === "string" ? obj.scope : current.scope;
  return {
    access_token: obj.access_token,
    refresh_token: refreshToken,
    expires_at: Date.now() + expiresIn * 1000,
    scope,
  };
}

/** Return a valid access_token for `userId`, proactively refreshing if the
 *  stored access token is within REFRESH_SKEW_MS of expiry. Single-flight per
 *  account. Throws MCPError x_api_failed with a closed-set reason. */
export async function getValidAccessToken(userId: string): Promise<string> {
  if (!X_USER_ID_RE.test(userId)) {
    throw new MCPError("x_api_failed", { reason: "no_account" });
  }
  const current = await readXToken(userId);
  if (current === null) {
    throw new MCPError("x_api_failed", { reason: "no_account" });
  }
  // Still fresh enough → return as-is (no network).
  if (current.expires_at - REFRESH_SKEW_MS > Date.now()) {
    return current.access_token;
  }
  // Needs refresh — single-flight.
  const existing = inflightRefresh.get(userId);
  if (existing) {
    const refreshed = await existing;
    return refreshed.access_token;
  }
  const fetchImpl = fetchImplOverride ?? fetch;
  const promise = (async (): Promise<XTokenPayload> => {
    try {
      // Re-read inside the flight in case another path wrote a fresher token
      // between the outer check and here (still single-flight; no double network
      // if we win the race).
      const latest = (await readXToken(userId)) ?? current;
      if (latest.expires_at - REFRESH_SKEW_MS > Date.now()) {
        return latest;
      }
      const next = await refreshTokens(fetchImpl, latest);
      await writeXToken(userId, next);
      return next;
    } finally {
      inflightRefresh.delete(userId);
    }
  })();
  inflightRefresh.set(userId, promise);
  const refreshed = await promise;
  return refreshed.access_token;
}

/** Build a token payload from a token-endpoint grant response (consent exchange).
 *  Shared shape so consent.ts + refresh stay consistent on expires_at math. */
export function tokenPayloadFromGrant(obj: {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  scope?: string;
}): XTokenPayload {
  const expiresIn = clampExpiresIn(obj.expires_in);
  return {
    access_token: obj.access_token,
    refresh_token: obj.refresh_token,
    expires_at: Date.now() + expiresIn * 1000,
    scope: typeof obj.scope === "string" ? obj.scope : "",
  };
}
