// Phase B (B6, v1.64.4) / Phase C (v1.65 web-fetch, v1.66 LINE) — the Source
// descriptor: the safety-gateway seam.
//
// docs/safety-gateway-thesis.md §5 + §4: SafeSpace's product is the safety
// ENVELOPE; concrete sources (Google Workspace; web-fetch; LINE) are connectors
// BEHIND it. A `Source` bundles the per-connector strategies the envelope's choke
// points consume polymorphically, so a new connector is a thin add of a new
// `Source` rather than a fork of the pipeline.
//
// v1.66 (Phase C PR 2) — THE SOURCE-STRATEGY LIFT (owner Q1: "go with the source architecture, build it now"). The descriptor now carries the FOUR strategies the choke points dispatch
// through — promoting `authorize` + `resolveCredential` from inline choke-point
// code into per-source methods, exactly as the thesis §4.1 prescribed:
//
//   - `authorize`        (NEW v1.66) — the pre-handler authorization check.
//     google-workspace = the scope pre-check (`scopeSatisfies` / SCOPE_HIERARCHY /
//     requiredScopes → scope_mismatch); line/web-fetch = no-op (no OAuth scope;
//     tier is proxy-enforced; line's token presence is enforced in
//     resolveCredential). This is the thesis-prescribed demotion of the OAuth
//     scope machinery out of the generic gateway (SCOPE_HIERARCHY moved to the
//     leaf auth/scopes.ts to avoid a source↔with-context cycle).
//   - `resolveCredential` (NEW v1.66) — resolve the per-call Credential.
//     google-workspace = resolve-account-email (passed by the choke point) +
//     `refreshAccessToken` (deps.force on the 401 retry) → {kind:"oauth"};
//     line = read 1 channel token from the service-token store → {kind:"service-
//     token"}; web-fetch = {kind:"none"}.
//   - `skipFields` (B5/D5) — the connector's opaque-key allowlist for
//     `sanitize(raw, ctx, source.skipFields)`.
//   - `mapError` (D4) — the per-connector error mapper (MCPError passthrough; else
//     a source-specific operational error).
//
// WHY the choke point still owns account-RESOLUTION + the 401-retry CONTROL FLOW
// (not lifted into resolveCredential): account resolution reads choke-point module
// state (lastUsedAccount) + args.account_id, and the single force-refresh retry is
// a control-flow loop around the handler. v1.66 keeps that loop in `withToolContext`
// (it now calls `source.resolveCredential(…, {force:true})` for the retry) — the
// auth-critical retry is NOT moved into a shared pipeline. The literal single-
// `runPipeline` collapse of the choke points (+ withAllAccounts) is B6.1. See
// docs/v1.66-line-oa-connector.md §1.2.

import { readActive } from "../auth/active";
import { loadIndex } from "../auth/keychain";
import { refreshAccessToken, type RefreshDeps } from "../auth/refresh";
import { scopeSatisfies } from "../auth/scopes";
import { readServiceToken } from "../auth/service-token-store";
import { readGithubAccount, readGithubToken } from "../auth/github/store";
import {
  findNotionWorkspace,
  readNotionAccounts,
  readNotionActiveWorkspace,
  readNotionToken,
} from "../auth/notion/oauth";
import { MCPError } from "../errors";
import { toGoogleError, type GoogleErrorContext } from "../google-api/errors";
import { mapWebFetchError } from "../policy/url-gate";
import { mapFsReadError } from "../policy/fs-gate";
import { SKIP_FIELDS } from "../sanitize/patterns";
import type { ToolDef } from "./registry/types";
import type { Credential } from "./types";

/** The resolved active account a google-workspace `authorize` checks scopes against.
 *  undefined for non-OAuth sources (they have no account / no scopes). */
export interface AuthorizeContext {
  readonly account?: { readonly accountId: string; readonly scopes?: readonly string[] };
}

/** v1.72 (B6.1 partial) — inputs an {@link OAuthSource}'s `resolveCredential`
 *  consults: the resolved active-account id (REQUIRED — the choke point always
 *  resolves it via `resolveAccount` FIRST), the refresh test seams, and the 401
 *  force flag. A required `accountId` (was optional `ResolveDeps.accountId`) makes
 *  the choke point unable to resolve an OAuth credential without an account at
 *  compile time. Non-OAuth sources take NO deps (their `resolveCredential` reads a
 *  single service token, or returns `{kind:"none"}`). */
export interface OAuthResolveDeps {
  readonly accountId: string;
  readonly refresh?: RefreshDeps;
  readonly force?: boolean;
}

/** v1.70 (G1) — the resolved upstream account a {@link OAuthSource.resolveAccount}
 *  returns: the provider-neutral identity + its persisted granted scopes (the
 *  `authorize` scope pre-check input). For google-workspace `accountId` is the
 *  account email; for a future OAuth provider it is that provider's stable id
 *  (e.g. a GitHub login). */
export interface ResolvedAccount {
  readonly accountId: string;
  readonly scopes?: readonly string[];
}

/** v1.70 (G1) — inputs an {@link OAuthSource.resolveAccount} consults to pick THIS
 *  call's active account. The resolution order google-workspace applies is:
 *  explicit override → active-account file → per-source last-used → validate
 *  against the index. */
export interface ResolveAccountDeps {
  /** `args.account_id` — the explicit per-call override (strongest tier). */
  readonly explicitAccountId?: string;
  /** The choke point's per-source in-memory last-used account (weakest tier). */
  readonly lastUsed: string | null;
  /** v1.74 PR-2c — the operator's account-confinement set (`OperatorContext
   *  .allowedAccounts`). `null` = no restriction (Model A — single operator owns
   *  every account → byte-identical). Model B: a default-selection fallback
   *  (active-file / last-used) NOT in the set is ignored (a shared global default
   *  can't poison an operator who lacks it), and a resolved account outside the set
   *  → `account_not_found` (the SAME error as a nonexistent account — no oracle that
   *  it exists for another operator). An EMPTY array means "zero accounts" (the
   *  operator can resolve none), NOT null. */
  readonly allowedAccounts?: readonly string[] | null;
  /** Test seam; defaults to the real active-account file read. */
  readonly readActiveImpl?: () => Promise<string | null>;
  /** Test seam; defaults to the real accounts.json index load. */
  readonly loadIndexImpl?: () => Promise<{
    accounts: Array<{ email: string; scopes?: string[] }>;
  }>;
}

/** Fields shared by every safety-gateway connector, regardless of auth class. */
export interface BaseSource {
  /** Stable connector id; matches `ToolDef.source` (B0) and the audit row's
   *  `source` field. v1.65 `"web-fetch"`; v1.66 `"line"`; v1.68 `"telegram"`;
   *  v1.69 `"discord"`; v1.70 `"github"`. */
  readonly id: string;
  /** v1.65 Phase C — the credential class, read ONCE by the proxy router to pick
   *  this tool's choke point: `"oauth"` → `withToolContext` (Google/GitHub account
   *  resolve / scope / refresh / 401-retry), `"service-token"` / `"none"` →
   *  `withNonOAuthContext` (no account, no refresh, no retry). A single
   *  dispatch-site read, beside `def.cross_account`. v1.72 — also the DISCRIMINANT
   *  that narrows {@link Source} to {@link OAuthSource} / {@link NonOAuthSource} at
   *  each choke point, so each consumes exactly the strategies its class provides. */
  readonly authModel: "oauth" | "service-token" | "none";
  /** Opaque-key allowlist for `sanitize(raw, ctx, source.skipFields)` (B5/D5). */
  readonly skipFields: ReadonlySet<string>;
  /** Per-source error mapper (D4) — RETURNS the SafeSpace error to throw (an
   *  MCPError is passed through unchanged; an upstream/network error is mapped). */
  mapError(err: unknown, ctx: GoogleErrorContext): Error;
  /** v1.66 — pre-handler authorization (BEFORE any credential resolve/refresh
   *  cost). Throws on denial; returns void on allow. */
  authorize(toolDef: ToolDef | undefined, ctx: AuthorizeContext): void;
}

/** v1.72 (B6.1 partial) — an OAuth-account connector (google-workspace, github).
 *  Routes through `withToolContext`: account resolution → scope authorize →
 *  per-call credential resolve, plus the google 401 force-refresh retry (gated on
 *  {@link OAuthSource.refreshable}). `resolveAccount` is REQUIRED and
 *  `resolveCredential` takes an {@link OAuthResolveDeps} whose `accountId` is
 *  REQUIRED — the type now enforces what the choke point always did at runtime
 *  (the pre-v1.72 `if (!resolveAccount)` + `if (accountId == null)` tripwires). */
export interface OAuthSource extends BaseSource {
  readonly authModel: "oauth";
  /** v1.70 (G1) — does this OAuth source's access token expire + refresh (the
   *  google 401 force-refresh-retry path)? `true` for google-workspace (the OAuth
   *  refresh-token flow); `false` for a non-refreshing OAuth token (a GitHub
   *  OAuth-App token). `withToolContext` gates its 401 refresh / retry /
   *  Keychain-cleanup on this. */
  readonly refreshable: boolean;
  /** v1.70 (G1) — resolve THIS call's active account (id + persisted scopes),
   *  provider-driven so a google tool resolves a google account and a github tool a
   *  github account — never crossed (the cross-provider-confusion backstop). Throws
   *  `account_not_found` on no/unknown account. */
  resolveAccount(
    toolDef: ToolDef | undefined,
    deps: ResolveAccountDeps,
  ): Promise<ResolvedAccount>;
  /** v1.66 — resolve the per-call {@link Credential} from the resolved account id
   *  (+ refresh deps / the 401 force flag). */
  resolveCredential(
    toolDef: ToolDef | undefined,
    deps: OAuthResolveDeps,
  ): Promise<Credential>;
}

/** v1.72 (B6.1 partial) — a non-OAuth connector: service-token (LINE / Telegram /
 *  Discord) or keyless (web-fetch). Routes through `withNonOAuthContext`: no
 *  account, no scope hierarchy, no token refresh, no 401 retry. `resolveCredential`
 *  takes NO deps (it reads a single service token from the store, or returns
 *  `{kind:"none"}`); there is no `resolveAccount` and no `refreshable`. */
export interface NonOAuthSource extends BaseSource {
  readonly authModel: "service-token" | "none";
  resolveCredential(toolDef: ToolDef | undefined): Promise<Credential>;
}

/** A safety-gateway connector's per-source strategies, discriminated on `authModel`
 *  so each choke point narrows to exactly the strategies it consumes. */
export type Source = OAuthSource | NonOAuthSource;

/** The flagship reference connector — Google Workspace (84 tools across Gmail /
 *  Drive / Docs / Calendar / Contacts / YouTube / Tasks / Sheets / Slides /
 *  Forms). Its strategies are today's choke-point code, lifted verbatim. */
export const googleWorkspace: OAuthSource = {
  id: "google-workspace",
  authModel: "oauth",
  refreshable: true,
  skipFields: SKIP_FIELDS,
  mapError: toGoogleError,
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // VERBATIM lift of the pre-v1.70 with-context.ts account-resolution block
    // (Step 5.6 / D8 order): 1. explicit args.account_id → 2. the active-account
    // file (`safespace account-switch`) → 3. the choke point's per-source
    // in-memory last-used; then validate against accounts.json. account_not_found
    // payloads are byte-identical to the pre-lift inline throws.
    // v1.74 PR-2c — the operator's confinement set, interned ONCE as a Set (O(1)
    // membership, no repeated O(n) scan); `null` = unrestricted (Model A).
    const allowSet = deps.allowedAccounts == null ? null : new Set(deps.allowedAccounts);
    const allowed = (id: string | null): id is string =>
      id != null && (allowSet == null || allowSet.has(id));
    const explicit = deps.explicitAccountId ?? null;
    const persistedRaw = explicit ? null : await (deps.readActiveImpl ?? readActive)();
    // Confine the DEFAULT-SELECTION fallbacks (active-file, last-used): a shared
    // global default the operator can't use is ignored (skipped), not an error.
    // Model A (allow == null) → `allowed` is always true → these are byte-identical.
    const persisted = allowed(persistedRaw) ? persistedRaw : null;
    const lastUsed = allowed(deps.lastUsed) ? deps.lastUsed : null;
    const accountId = explicit ?? persisted ?? lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
    }
    // Confinement guard — a resolved account (notably an EXPLICIT out-of-set
    // `args.account_id`) outside the operator's set → account_not_found, byte-
    // IDENTICAL to the index-miss throw below (the echoed `email` is the caller's
    // OWN input, returned the same whether the account exists for another operator
    // or not at all → no oracle; diverging the two payloads would CREATE one).
    // Model A: never fires.
    if (allowSet != null && !allowSet.has(accountId)) {
      throw new MCPError("account_not_found", { email: accountId });
    }
    const idxLoader = deps.loadIndexImpl ?? loadIndex;
    const idx = await idxLoader();
    const account = idx.accounts.find((a) => a.email === accountId);
    if (!account) {
      throw new MCPError("account_not_found", { email: accountId });
    }
    return { accountId, scopes: account.scopes };
  },
  authorize(toolDef, ctx) {
    // VERBATIM from the pre-v1.66 with-context.ts scope pre-check: the account's
    // PERSISTED granted scope set (not the access token) is the source of truth —
    // fail BEFORE refreshing the token or hitting Google, with an actionable
    // scope_mismatch. account.scopes may be undefined on older accounts.json
    // entries → treat as "scopes unknown", skip, let upstream 403 → scope_mismatch.
    const account = ctx.account;
    if (
      toolDef &&
      account &&
      Array.isArray(account.scopes) &&
      account.scopes.length > 0
    ) {
      const granted = new Set(account.scopes);
      const missing = toolDef.requiredScopes.filter((s) => !scopeSatisfies(granted, s));
      if (missing.length > 0) {
        // The error-data KEY stays `email:` (wire-stable); v1.70 G1 renamed the
        // account FIELD (`email`→`accountId`), not the payload key — fed the
        // resolved accountId (a google email for this source) → byte-identical
        // scope_mismatch output. Same for account_not_found / refresh_token_invalid.
        throw new MCPError("scope_mismatch", { email: account.accountId, missing });
      }
    }
  },
  async resolveCredential(_toolDef, deps): Promise<Credential> {
    const accountId = deps.accountId;
    if (accountId == null) {
      // v1.72 — type-unreachable backstop: OAuthResolveDeps.accountId is REQUIRED,
      // so the choke point cannot reach here without a resolved id. Kept (defense in
      // depth) to catch an `as any` bypass; a missing id is an internal wiring bug.
      throw new Error("internal: google-workspace resolveCredential requires accountId");
    }
    // First call: deps.force falsy → pass deps.refresh unchanged. 401 retry:
    // deps.force true → {...refresh, force:true}.
    const refreshDeps: RefreshDeps = deps.force
      ? { ...(deps.refresh ?? {}), force: true }
      : (deps.refresh ?? {});
    const tokenSet = await refreshAccessToken(accountId, refreshDeps);
    // getAccessToken is a GETTER over the freshly-refreshed tokenSet (never a
    // serializable field — types.ts). On a 401 the choke point calls this method
    // again with force:true → a NEW Credential over the new token, and rebuilds ctx.
    return {
      kind: "oauth",
      provider: "google",
      accountId,
      getAccessToken: () => tokenSet.access_token,
    };
  },
};

/** v1.65 Phase C — the class-C KEYLESS connector: `web-fetch`. No upstream account
 *  → `authModel:"none"`. `skipFields` EMPTY (a fetched page is entirely untrusted →
 *  every string field wraps). The SSRF gate lives in `policy/url-gate.ts`. */
export const webFetch: NonOAuthSource = {
  id: "web-fetch",
  authModel: "none",
  skipFields: new Set(),
  mapError: mapWebFetchError,
  authorize() {
    // keyless — no scope, no token; tier is enforced by the proxy + min_tier.
  },
  async resolveCredential(): Promise<Credential> {
    return { kind: "none" };
  },
};

/** v1.75 — the second class-C KEYLESS connector: `fs-read` (host filesystem read).
 *  No upstream account → `authModel:"none"`. `skipFields` EMPTY (file content is
 *  entirely untrusted → every string field wraps). The default-deny path gate lives
 *  in `policy/fs-gate.ts`. */
export const fsRead: NonOAuthSource = {
  id: "fs-read",
  authModel: "none",
  skipFields: new Set(),
  mapError: mapFsReadError,
  authorize() {
    // keyless — no scope, no token; tier is enforced by the proxy + min_tier.
  },
  async resolveCredential(): Promise<Credential> {
    return { kind: "none" };
  },
};

/** v1.102 (W0) — the `webhook` source skipFields, authored against the PERSISTED
 *  NORMALIZED inbox row (docs/v1.102 §4.2), NOT a provider's wire envelope (the v1.98
 *  TELEGRAM_SKIP_FIELDS lesson — a per-source set must match the EXACT keys the handler
 *  emits). The opaque ids/timestamps SKIP; `sender_name` + `text` are OUT → they WRAP
 *  as an untrusted source (inbound message content = the highest injection surface). */
const WEBHOOK_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "provider",
  "event_id",
  "seq",
  "received_at",
  "expires_at",
  "provider_message_id",
  "ts",
  "sender_id",
  "channel_id",
]);

/** Per-source error mapper for the webhook inbox — MCPError passthrough (the handler
 *  already maps a corrupt-store throw to inbox_read_failed); any other thrown value
 *  becomes a generic inbox_read_failed. NEVER echoes message content. */
function mapInboxError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("inbox_read_failed", { reason: "store_unavailable" });
}

/** v1.102 (W0) — the inbound-webhook inbox as a KEYLESS source. `inbox_read` reads a
 *  LOCAL store the listener populated → `authModel:"none"` (no account, no token; the
 *  signing secret is LISTENER infra, not a tool credential — docs/v1.102 §5.0). Routes
 *  through `withNonOAuthContext`; the choke point WRAPS `sender_name`/`text` via
 *  skipFields. The verify/secret machinery lives listener-side (transport/webhook.ts +
 *  webhook/verify/*), deliberately OFF this Source seam. */
export const webhook: NonOAuthSource = {
  id: "webhook",
  authModel: "none",
  skipFields: WEBHOOK_SKIP_FIELDS,
  mapError: mapInboxError,
  authorize() {
    // keyless — no scope, no token; tier is enforced by the proxy + min_tier.
  },
  async resolveCredential(): Promise<Credential> {
    return { kind: "none" };
  },
};

/** Opaque LINE ids that must NOT be confusable-normalized by sanitize (R8(b): each
 *  connector owns its opaque-key set). Barely exercised by line_push_message (its
 *  response is constructed/trusted) but ships correct for a future LINE read. */
const LINE_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "userId",
  "groupId",
  "roomId",
  "to",
  "messageId",
  "quoteToken",
]);

/** Per-source error mapper for LINE — MCPError passthrough (the handler already
 *  maps HTTP-status-specific failures to line_api_failed with a closed-set reason);
 *  any other thrown value becomes a generic line_api_failed. Mirrors
 *  mapWebFetchError. NEVER echoes the token or recipient id. */
function mapLineError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("line_api_failed", { reason: "api_error" });
}

/** v1.66 Phase C PR 2 — the first class-B SERVICE-TOKEN connector: LINE Official
 *  Account (Messaging API). One long-lived channel access token in the
 *  service-token store (env → SecretBackend), no OAuth. `authModel:"service-token"`
 *  routes its tools through `withNonOAuthContext`; `direction:"outbound-write"` on
 *  line_push_message fires the egress gates. */
export const line: NonOAuthSource = {
  id: "line",
  authModel: "service-token",
  skipFields: LINE_SKIP_FIELDS,
  mapError: mapLineError,
  authorize() {
    // service-token — no OAuth scope to check; tier is enforced by the proxy +
    // min_tier. Token PRESENCE is enforced in resolveCredential (throws
    // line_api_failed{no_token}), so authorize stays a no-op.
  },
  async resolveCredential(): Promise<Credential> {
    const token = await readServiceToken("line");
    if (token === null) {
      throw new MCPError("line_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify
    // of a ToolContext can't leak the bearer token.
    return { kind: "service-token", token: () => token };
  },
};

/** Opaque/structural Telegram keys the sanitize tree-walk passes through unwrapped (R8(b):
 *  each connector owns its set; per-source skipFields REPLACES the global SKIP_FIELDS, so
 *  this MUST list every non-content key it wants skipped — the global `id` entry does NOT
 *  apply here). v1.98 — reviewed for the inbound telegram_get_updates read shape:
 *    - The opaque Telegram ids/timestamps (`update_id`, `message_id`, `chat.id`/`from.id`
 *      → leaf `id`, `date`) are NUMERIC in the Bot API → sanitize passes numbers through
 *      untouched (sanitize/index.ts only wraps/normalizes STRINGS), so they need NO entry
 *      here (adding them would be the v1.68 NIT-1 no-op-speculative anti-pattern; the prior
 *      comment's "covered by the global `id`" claim was WRONG for a per-source set).
 *    - `chat.type` is a controlled enum string (private/group/supergroup/channel) → skip it
 *      to avoid wrap-noise on a non-content field.
 *    - INBOUND user content — message `text`, sender `first_name`/`last_name`/`username`,
 *      chat `title` — is deliberately OUT so the choke point WRAPS it as an untrusted source.
 *  `chat_id` stays for the outbound telegram_send_message constructed response (the agent's
 *  own id string). NO `message_id`/`update_id`/`id`/`date` entries — those are numeric (numbers
 *  bypass sanitize), so a skip entry would be inert (the v1.68 NIT-1 lesson). */
const TELEGRAM_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "chat_id",
  "type",
]);

/** Per-source error mapper for Telegram — MCPError passthrough (the handler already
 *  maps HTTP-status-specific failures to telegram_api_failed with a closed-set reason);
 *  any other thrown value becomes a generic telegram_api_failed. Mirrors mapLineError.
 *  NEVER echoes the token, the request URL, or the recipient id. */
function mapTelegramError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("telegram_api_failed", { reason: "api_error" });
}

/** v1.68 — the SECOND class-B SERVICE-TOKEN connector: Telegram Bot (Bot API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on telegram_send_message fires the egress gates. */
export const telegram: NonOAuthSource = {
  id: "telegram",
  authModel: "service-token",
  skipFields: TELEGRAM_SKIP_FIELDS,
  mapError: mapTelegramError,
  authorize() {
    // service-token — no OAuth scope to check; tier is enforced by the proxy +
    // min_tier. Token PRESENCE is enforced in resolveCredential (throws
    // telegram_api_failed{no_token}), so authorize stays a no-op.
  },
  async resolveCredential(): Promise<Credential> {
    const token = await readServiceToken("telegram");
    if (token === null) {
      throw new MCPError("telegram_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the bot token.
    return { kind: "service-token", token: () => token };
  },
};

/** Opaque Discord snowflakes that must NOT be confusable-normalized by sanitize
 *  (R8(b): each connector owns its opaque-key set). `channel_id` is the only id in
 *  today's constructed success response; `id` (a future message/author snowflake) is
 *  already in the global SKIP_FIELDS, so this set stays minimal + honest (the v1.68
 *  NIT-1 lesson — don't pre-populate skipFields with speculative future fields that
 *  aren't in the constructed response). Revisit when an inbound/read Discord tool ships. */
const DISCORD_SKIP_FIELDS: ReadonlySet<string> = new Set(["channel_id"]);

/** Per-source error mapper for Discord — MCPError passthrough (the handler already
 *  maps HTTP-status-specific failures to discord_api_failed with a closed-set reason);
 *  any other thrown value becomes a generic discord_api_failed. Mirrors mapTelegramError.
 *  NEVER echoes the bot token or the channel id. */
function mapDiscordError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("discord_api_failed", { reason: "api_error" });
}

/** v1.69 — the THIRD class-B SERVICE-TOKEN connector: Discord Bot (REST API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on discord_send_message fires the egress gates. */
export const discord: NonOAuthSource = {
  id: "discord",
  authModel: "service-token",
  skipFields: DISCORD_SKIP_FIELDS,
  mapError: mapDiscordError,
  authorize() {
    // service-token — no OAuth scope to check; tier is enforced by the proxy +
    // min_tier. Token PRESENCE is enforced in resolveCredential (throws
    // discord_api_failed{no_token}), so authorize stays a no-op.
  },
  async resolveCredential(): Promise<Credential> {
    const token = await readServiceToken("discord");
    if (token === null) {
      throw new MCPError("discord_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the bot token.
    return { kind: "service-token", token: () => token };
  },
};

/** Opaque Slack ids/timestamps/cursors that must NOT be wrapped/normalized by sanitize
 *  (R8(b): each connector owns its opaque-key set). Per-source skipFields REPLACES the
 *  global SKIP_FIELDS, so this MUST list every opaque/structural key the shapers emit — and
 *  ONLY those: everything attacker-influenceable (v1.97 reads: channel `name`, message
 *  `text`, `topic`/`purpose`) stays OUT → it WRAPS as an untrusted source. The opaque keys:
 *  `channel` (write echo) · `id` (channel id) · `ts`/`thread_ts` (message id / thread ref —
 *  ⚠️ `ts` LOOKS numeric but is an opaque cursor/ref; wrapping it would break a follow-up
 *  call) · `user`/`team` (opaque ids, NOT display names) · `type`/`subtype` (controlled
 *  enums) · `next_cursor` (pagination). v1.104 users.*: `tz` (a controlled IANA zone name,
 *  emitted raw) joins; the user-authored `name`/`real_name`/`display_name` + the PII `email`
 *  stay OUT → they WRAP (the bools are non-strings → sanitize ignores them regardless). */
const SLACK_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "channel",
  "id",
  "ts",
  "thread_ts",
  "user",
  "team",
  "type",
  "subtype",
  "next_cursor",
  "tz",
]);

/** Per-source error mapper for Slack — MCPError passthrough (the handler already maps
 *  HTTP-status + the chat.postMessage `{ok:false}` body to slack_api_failed with a
 *  closed-set reason); any other thrown value becomes a generic slack_api_failed. Mirrors
 *  mapDiscordError. NEVER echoes the bot token or the channel id. */
function mapSlackError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("slack_api_failed", { reason: "api_error" });
}

/** v1.95 — the FOURTH class-B SERVICE-TOKEN connector: Slack Bot (Web API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on slack_send_message fires the egress gates. */
export const slack: NonOAuthSource = {
  id: "slack",
  authModel: "service-token",
  skipFields: SLACK_SKIP_FIELDS,
  mapError: mapSlackError,
  authorize() {
    // service-token — no OAuth scope to check; tier is enforced by the proxy + min_tier.
    // Token PRESENCE is enforced in resolveCredential (throws slack_api_failed{no_token}),
    // so authorize stays a no-op.
  },
  async resolveCredential(): Promise<Credential> {
    const token = await readServiceToken("slack");
    if (token === null) {
      throw new MCPError("slack_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the bot token.
    return { kind: "service-token", token: () => token };
  },
};

/** v1.107 — the per-source opaque-key set for Mattermost. REPLACES the global SKIP_FIELDS,
 *  so it MUST list every opaque/structural key the mattermost shapers emit — and ONLY those:
 *  everything attacker-influenced (team/channel `name`/`display_name`/`header`/`purpose`,
 *  post `message`) stays OUT → it WRAPS as an untrusted source. The opaque keys: `id`
 *  (team/channel/post id) · `channel_id`/`user_id`/`root_id`/`team_id` (opaque refs) · `type`
 *  (controlled enum: channel "O"/"P"/"D"/"G", post "" / "system_*") · `next_post_id`/
 *  `prev_post_id` (pagination cursors — MUST skip so the agent can page). Numeric epochs
 *  (`create_at`) are NUMBERS → sanitize passes them through, so they need no skip entry. */
const MATTERMOST_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "id",
  "channel_id",
  "user_id",
  "root_id",
  "team_id",
  "type",
  "next_post_id",
  "prev_post_id",
]);

/** Per-source error mapper for Mattermost — MCPError passthrough (the handler/client already
 *  map HTTP-status to mattermost_api_failed with a closed-set reason); any other thrown value
 *  becomes a generic mattermost_api_failed. NEVER echoes the token, server URL, or any id. */
function mapMattermostError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("mattermost_api_failed", { reason: "api_error" });
}

/** v1.107 — the FIFTH class-B SERVICE-TOKEN connector, and the FIRST self-hosted one: a
 *  Mattermost bot/personal-access token in the service-token store (env → SecretBackend),
 *  no OAuth. `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on mattermost_send_message fires the egress gates. The
 *  per-deployment server URL is config (SAFESPACE_MATTERMOST_SERVER_URL), resolved by the
 *  client/handlers; resolveCredential enforces only the TOKEN's presence. */
export const mattermost: NonOAuthSource = {
  id: "mattermost",
  authModel: "service-token",
  skipFields: MATTERMOST_SKIP_FIELDS,
  mapError: mapMattermostError,
  authorize() {
    // service-token — no OAuth scope to check; tier is enforced by the proxy + min_tier.
    // Token PRESENCE is enforced in resolveCredential (throws mattermost_api_failed{no_token});
    // the server-URL presence is enforced later, by the client (no_server_url).
  },
  async resolveCredential(): Promise<Credential> {
    const token = await readServiceToken("mattermost");
    if (token === null) {
      throw new MCPError("mattermost_api_failed", { reason: "no_token" });
    }
    return { kind: "service-token", token: () => token };
  },
};

/** v1.77 — the per-source opaque-key set for Notion. Per-source skipFields REPLACES the
 *  global SKIP_FIELDS (the choke point passes source.skipFields to sanitize), so this MUST
 *  enumerate every opaque/structural key the notion shapers emit — anything omitted wraps
 *  (correct for content; WRONG for an id/cursor, which would then break the agent's
 *  follow-up call). Everything attacker-influenced (title / text / property name+value /
 *  column name / people names / date strings) stays OUT → it wraps. */
const NOTION_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "id", // opaque Notion UUID — the agent needs it raw for the next call
  "object", // controlled enum: "page" | "database" | "block" | "list"
  "type", // controlled enum: the block type / property type
  "parent_type", // controlled enum: "page_id" | "database_id" | "workspace"
  "url", // Notion-constructed page URL (skip, like github html_url)
  "created_time",
  "last_edited_time",
  "next_cursor", // pagination cursor — MUST skip so the agent can page
]);

/** Per-source error mapper for Notion — MCPError passthrough (a notion handler's client
 *  maps HTTP-status-specific failures to notion_api_failed with a closed-set reason); any
 *  other thrown value becomes a generic notion_api_failed. Mirrors mapDiscordError.
 *  NEVER echoes the token or any id. */
function mapNotionError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("notion_api_failed", { reason: "api_error" });
}

/** v1.78 (Notion B) — the THIRD OAuth source: Notion (a public integration). Routes
 *  through `withToolContext` (`authModel:"oauth"`) like google-workspace + github, but its
 *  token does NOT refresh (`refreshable:false` → the choke point skips the 401
 *  force-refresh path) and it has no scope hierarchy (Notion OAuth has no scope param).
 *  Single-workspace v1 (mirror github single-account): the account = the consented Notion
 *  workspace. The v1.77 internal-integration-token path is superseded by this OAuth flow.
 *  The handlers + client + skipFields are UNCHANGED — only the credential acquisition
 *  + routing differ (the token is the same non-refreshing api.notion.com Bearer). */
export const notion: OAuthSource = {
  id: "notion",
  authModel: "oauth",
  refreshable: false,
  skipFields: NOTION_SKIP_FIELDS,
  mapError: mapNotionError,
  authorize() {
    // No-op: Notion OAuth has no scope param (an integration's capabilities are configured
    // Notion-side). A token lacking access to a page yields a Notion 403/404 → the client
    // maps it to notion_api_failed{auth_failed/not_found}.
  },
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // v1.79 multi-workspace — mirrors googleWorkspace.resolveAccount: explicit
    // args.account_id (resolved id-OR-name) → active workspace → per-source last-used; then
    // validate against the notion index + the operator's confinement set. Cross-provider
    // safety: reads ONLY the notion store, never google accounts.json.
    const allowSet = deps.allowedAccounts == null ? null : new Set(deps.allowedAccounts);
    const allowed = (id: string | null): id is string =>
      id != null && (allowSet == null || allowSet.has(id));
    const accounts = await readNotionAccounts();
    // Confine the LOOKUP SCOPE to the operator's set (sec-rev nit): name/id resolution only
    // ever sees the operator's own workspaces, so an explicit name can never even resolve to
    // another operator's workspace (no cross-operator name-match) — and an "ambiguous" name
    // only reflects the operator's OWN duplicates. Model A (allowSet null) → visible == accounts.
    const visible = allowSet == null ? accounts : accounts.filter((a) => allowSet.has(a.workspaceId));
    // Explicit account_id may be a workspace id OR a case-insensitive name → resolve it within
    // the operator's set. An unknown / ambiguous value → account_not_found echoing the caller's
    // OWN input (byte-identical to "unknown" → no oracle about which workspaces exist).
    let explicitId: string | null = null;
    if (deps.explicitAccountId != null) {
      const match = findNotionWorkspace(deps.explicitAccountId, visible);
      if (match === "ambiguous" || match == null) {
        throw new MCPError("account_not_found", { email: deps.explicitAccountId });
      }
      explicitId = match.workspaceId;
    }
    // Default-selection fallbacks (active, last-used) are CONFINED: a shared default the
    // operator can't use is skipped (not an error). Model A (allow == null) → byte-identical.
    const activeRaw = explicitId ? null : await readNotionActiveWorkspace();
    const active = allowed(activeRaw) ? activeRaw : null;
    const lastUsed = allowed(deps.lastUsed) ? deps.lastUsed : null;
    const accountId = explicitId ?? active ?? lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
    }
    // The single confinement + index-validation backstop: `accountId` must name a workspace
    // in the operator's VISIBLE set. This catches an out-of-set explicit (already filtered to
    // `visible`, so this is belt-and-suspenders for it) AND a stale `lastUsed` pointing at a
    // deleted workspace. Echoes the caller's OWN input, byte-identical to the unknown throws
    // above → no oracle. (A separate `allowSet.has(accountId)` guard would be dead: every
    // accountId here is from `visible` or passed `allowed()`, so it is always in-set.)
    if (!visible.some((a) => a.workspaceId === accountId)) {
      throw new MCPError("account_not_found", { email: deps.explicitAccountId ?? accountId });
    }
    return { accountId, scopes: [] };
  },
  async resolveCredential(_toolDef, deps): Promise<Credential> {
    const accountId = deps.accountId;
    if (accountId == null) {
      // Type-unreachable backstop (OAuthResolveDeps.accountId REQUIRED); kept to catch an
      // `as any` bypass, mirrors google-workspace + github.
      throw new Error("internal: notion resolveCredential requires accountId");
    }
    const token = await readNotionToken(accountId);
    if (token === null) {
      throw new MCPError("notion_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the notion token.
    return { kind: "oauth", provider: "notion", accountId, getAccessToken: () => token };
  },
};

/** v1.70 (G2) — the SECOND OAuth source: GitHub (a GitHub OAuth App). Routes
 *  through `withToolContext` (`authModel:"oauth"`) like google-workspace, but its
 *  token does NOT refresh (`refreshable:false` → the choke point skips the 401
 *  force-refresh path) and it has no scope hierarchy. SKELETON this PR — no github
 *  tool is registered yet, so the proxy never routes here; the consent flow that
 *  WRITES the store (auth/github/store.ts) lands in G3, the read tools in G4. */
const GITHUB_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "node_id",
  "sha",
  "url",
  "html_url",
  "created_at",
  "updated_at",
  "closed_at",
  "merged_at",
  // v1.70 (G4) — `state` is a controlled enum ("open"/"closed") in the issue/PR
  // read responses, NOT attacker free text → skip the wrap. (title / body / login /
  // label name / branch ref names stay OUT of this set → they wrap.)
  "state",
  // v1.76 — `status` is a GitHub-controlled file-change enum ("added"/"modified"/
  // "removed"/"renamed"/…) in the PR-files / commit-files shape, NOT attacker free
  // text → skip, exactly like `state`. (filename / patch / previous_filename stay
  // OUT of the set → they wrap.)
  "status",
]);

/** Per-source error mapper for GitHub — MCPError passthrough (a github handler maps
 *  HTTP-status-specific failures to github_api_failed with a closed-set reason); any
 *  other thrown value becomes a generic github_api_failed. Mirrors mapDiscordError.
 *  NEVER echoes the token. */
function mapGithubError(err: unknown, _ctx: GoogleErrorContext): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("github_api_failed", { reason: "api_error" });
}

export const github: OAuthSource = {
  id: "github",
  authModel: "oauth",
  refreshable: false,
  skipFields: GITHUB_SKIP_FIELDS,
  mapError: mapGithubError,
  authorize() {
    // No-op: GitHub OAuth scopes are requested wholesale at consent (G3 requests the
    // v1 read set). A token lacking a scope yields a GitHub 403 → the handler maps it
    // to github_api_failed{auth_failed}. Per-tool flat-scope pre-checking can land
    // later if a finer-grained github surface needs it.
  },
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // Single-account v1: the one consented github login. An explicit args.account_id
    // override (or the per-source last-used) must MATCH the stored login. G3's consent
    // writes the account; until then readGithubAccount() is null → account_not_found.
    // Cross-provider safety: reads ONLY the github store, never google accounts.json.
    // v1.74 PR-2c — `deps.allowedAccounts` (the operator confinement set) has NO
    // effect here by design: github is single-account, so there is at most one login
    // and confining it would have no semantic value. Revisit if github becomes
    // multi-account (then mirror google's confinement guard).
    const stored = await readGithubAccount();
    const accountId = deps.explicitAccountId ?? stored?.login ?? deps.lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
    }
    if (!stored || stored.login !== accountId) {
      throw new MCPError("account_not_found", { email: accountId });
    }
    return { accountId, scopes: stored.scopes };
  },
  async resolveCredential(_toolDef, deps): Promise<Credential> {
    const accountId = deps.accountId;
    if (accountId == null) {
      // v1.72 — type-unreachable backstop (OAuthResolveDeps.accountId REQUIRED);
      // kept to catch an `as any` bypass, mirrors google-workspace.
      throw new Error("internal: github resolveCredential requires accountId");
    }
    const token = await readGithubToken(accountId);
    if (token === null) {
      throw new MCPError("github_api_failed", { reason: "no_token" });
    }
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the github token.
    return { kind: "oauth", provider: "github", accountId, getAccessToken: () => token };
  },
};

/** The Source registry (id → descriptor). A future connector adds its own
 *  `Source` here. */
const SOURCES: Readonly<Record<string, Source>> = {
  "google-workspace": googleWorkspace,
  "web-fetch": webFetch,
  "fs-read": fsRead,
  webhook,
  line,
  telegram,
  discord,
  slack,
  mattermost,
  github,
  notion,
};

/** Resolve a tool's Source from its `ToolDef.source` (B0 relabel), defaulting to
 *  google-workspace. An unknown id falls back to google-workspace — defensive: a
 *  typo'd `source` label can never strip a tool of its envelope. */
export function sourceFor(toolDef: Pick<ToolDef, "source"> | undefined): Source {
  const id = toolDef?.source ?? "google-workspace";
  return SOURCES[id] ?? googleWorkspace;
}
