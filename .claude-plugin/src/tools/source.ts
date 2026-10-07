// Phase B (B6, v1.64.4) / Phase C (v1.65 web-fetch, v1.66 LINE) — the Source
// descriptor: the safety-gateway seam.
//
// docs/safety-gateway-thesis.md §5 + §4: SafeSpace's product is the safety
// ENVELOPE; concrete sources (Google Workspace; web-fetch; LINE) are connectors
// BEHIND it. A `Source` bundles the per-connector strategies the envelope's choke
// points consume polymorphically, so a new connector is a thin add of a new
// `Source` rather than a fork of the pipeline.
//
// v1.66 (Phase C PR 2) — THE SOURCE-STRATEGY LIFT (owner Q1: "go with the source architecture, build it now"). The descriptor now carries the THREE strategies the choke points dispatch
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
//
// Per-connector error mapping is NOT a Source strategy: each handler calls its own
// mapper directly (google → `toGoogleError`; web-fetch → `mapWebFetchError`; fs-read
// → `mapFsReadError`; the REST connectors throw their own `*_api_failed` MCPError in
// the handler catch). A future B6.1 shared pipeline would introduce a new error-
// mapping seam; there is deliberately none on the Source today.
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
import { readServiceToken, type ServiceName } from "../auth/service-token-store";
import { readGithubAccount, readGithubToken } from "../auth/github/store";
import {
  findNotionWorkspace,
  readNotionAccounts,
  readNotionActiveWorkspace,
  readNotionToken,
} from "../auth/notion/oauth";
import {
  findXAccount,
  getValidAccessToken,
  readXAccounts,
  readXActiveAccount,
} from "../auth/x/oauth";
import { MCPError, type ErrorName } from "../errors";
import {
  DISCORD_PACK,
  LINE_PACK,
  MATTERMOST_PACK,
  SLACK_PACK,
  TELEGRAM_PACK,
} from "./service-token-pack";
import { SKIP_FIELDS } from "../sanitize/patterns";
import { resolveRecipientsViaContactLookup } from "./handlers/contacts";
import type { ToolDef } from "./registry/types";
import type { Credential, ToolContext } from "./types";

/** B6.1 wave A3+D — the contact-resolution strategy an {@link OAuthSource} may
 *  carry, so the egress pipeline can resolve a gmail recipient's name→email BEFORE
 *  the composite gate runs (the recipient allowlist must see the RESOLVED email).
 *  Signature mirrors `resolveRecipientsViaContactLookup` (handlers/contacts.ts) 1:1
 *  — the `tool` union is the shared one (gmail_send + the two calendar attendee
 *  callers, which keep calling the resolver directly; only gmail rides this Source
 *  strategy). Returns the FULL resolved list (1:1 input order) + the subset that came
 *  from a lookup (drives the audit-hash emission). */
export type RecipientResolver = (
  ctx: ToolContext,
  inputs: string[],
  tool: "gmail_send" | "calendar_create_event" | "calendar_update_event",
) => Promise<{ resolvedEmails: string[]; lookedUpEmails: string[] }>;

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
  /** B6.1 wave A3+D — OPTIONAL contact-resolution strategy consumed by the gmail
   *  egress pipeline (with-context.ts passes it into the descriptor gate). Present
   *  only on google-workspace (its People API contact-lookup); absent on
   *  github/notion/x — those sources have no recipient resolution, so the gate falls
   *  back to identity passthrough. See {@link RecipientResolver}. */
  readonly resolveRecipients?: RecipientResolver;
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

/** v1.112.4 — the class-B SERVICE-TOKEN source factory. The 5 service-token
 *  connectors (LINE / Telegram / Discord / Slack / Mattermost) are byte-identical
 *  modulo `id`, `skipFields`, the `*_api_failed` error code, and the SecretBackend
 *  `storeKey` — so they collapse onto this one constructor (mirrors the v1.112.3
 *  service-token ALLOWLIST factory). `storeKey` is kept a SEPARATE param from `id`
 *  (today they coincide) so a future connector whose audit id ≠ its store key cannot
 *  silently cross-wire. The produced descriptor's `authorize` is the service-token
 *  no-op (no OAuth scope; tier is proxy-enforced; token PRESENCE is enforced here in
 *  `resolveCredential`, throwing `errorName{no_token}`). NOT used for the OAuth
 *  sources — their `resolveAccount` logic stays hand-written. */
function makeServiceTokenSource(opts: {
  readonly id: ServiceName;
  readonly storeKey: ServiceName;
  readonly errorName: ErrorName;
  readonly skipFields: ReadonlySet<string>;
}): NonOAuthSource {
  return {
    id: opts.id,
    authModel: "service-token",
    skipFields: opts.skipFields,
    authorize() {
      // service-token — no OAuth scope to check; tier is enforced by the proxy +
      // min_tier. Token PRESENCE is enforced in resolveCredential (throws
      // <id>_api_failed{no_token}), so authorize stays a no-op.
    },
    async resolveCredential(): Promise<Credential> {
      const token = await readServiceToken(opts.storeKey);
      if (token === null) {
        throw new MCPError(opts.errorName, { reason: "no_token" });
      }
      // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of
      // a ToolContext can't leak the bearer token.
      return { kind: "service-token", token: () => token };
    },
  };
}

/** The flagship reference connector — Google Workspace (84 tools across Gmail /
 *  Drive / Docs / Calendar / Contacts / YouTube / Tasks / Sheets / Slides /
 *  Forms). Its strategies are today's choke-point code, lifted verbatim. */
export const googleWorkspace: OAuthSource = {
  id: "google-workspace",
  authModel: "oauth",
  refreshable: true,
  skipFields: SKIP_FIELDS,
  // B6.1 wave A3+D — the gmail egress pipeline's name→email contact resolution.
  // The resolver BODY stays in handlers/contacts.ts (calendar_create_event /
  // calendar_update_event keep calling it directly for their attendee lists —
  // those tools are not direction:"outbound-write" and are outside the egress
  // pipeline); binding it here lets the gmail descriptor gate resolve recipients
  // through the Source strategy rather than an in-handler call.
  resolveRecipients: resolveRecipientsViaContactLookup,
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // VERBATIM lift of the pre-v1.70 with-context.ts account-resolution block
    // (Step 5.6 / D8 order): 1. explicit args.account_id → 2. the active-account
    // file (`safespace account-switch`) → 3. the choke point's per-source
    // in-memory last-used; then validate against accounts.json. account_not_found
    // payloads are byte-identical to the pre-lift inline throws.
    const explicit = deps.explicitAccountId ?? null;
    const persisted = explicit ? null : await (deps.readActiveImpl ?? readActive)();
    const accountId = explicit ?? persisted ?? deps.lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
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
      // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
      throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
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
  authorize() {
    // keyless — no scope, no token; tier is enforced by the proxy + min_tier.
  },
  async resolveCredential(): Promise<Credential> {
    return { kind: "none" };
  },
};

/** v1.66 Phase C PR 2 — the first class-B SERVICE-TOKEN connector: LINE Official
 *  Account (Messaging API). One long-lived channel access token in the service-token
 *  store (env → SecretBackend), no OAuth. `authModel:"service-token"` routes its tools
 *  through `withNonOAuthContext`; `direction:"outbound-write"` on line_push_message
 *  fires the egress gates. Values come from LINE_PACK (the step-1 pack migration). */
export const line: NonOAuthSource = makeServiceTokenSource({
  id: LINE_PACK.id,
  storeKey: LINE_PACK.storeKey,
  errorName: LINE_PACK.errorName,
  skipFields: LINE_PACK.skipFields,
});

/** v1.68 — the SECOND class-B SERVICE-TOKEN connector: Telegram Bot (Bot API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on telegram_send_message fires the egress gates. Its
 *  per-source skipFields (the opaque `chat_id`/`type` keys) live on TELEGRAM_PACK. */
export const telegram: NonOAuthSource = makeServiceTokenSource({
  id: TELEGRAM_PACK.id,
  storeKey: TELEGRAM_PACK.storeKey,
  errorName: TELEGRAM_PACK.errorName,
  skipFields: TELEGRAM_PACK.skipFields,
});

/** v1.69 — the THIRD class-B SERVICE-TOKEN connector: Discord Bot (REST API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on discord_send_message fires the egress gates. Its
 *  per-source skipFields (the opaque `channel_id`) lives on DISCORD_PACK. */
export const discord: NonOAuthSource = makeServiceTokenSource({
  id: DISCORD_PACK.id,
  storeKey: DISCORD_PACK.storeKey,
  errorName: DISCORD_PACK.errorName,
  skipFields: DISCORD_PACK.skipFields,
});

/** v1.95 — the FOURTH class-B SERVICE-TOKEN connector: Slack Bot (Web API). One
 *  long-lived bot token in the service-token store (env → SecretBackend), no OAuth.
 *  `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on slack_send_message fires the egress gates. Its
 *  per-source skipFields (opaque ids/timestamps/cursors) lives on SLACK_PACK. */
export const slack: NonOAuthSource = makeServiceTokenSource({
  id: SLACK_PACK.id,
  storeKey: SLACK_PACK.storeKey,
  errorName: SLACK_PACK.errorName,
  skipFields: SLACK_PACK.skipFields,
});

/** v1.107 — the FIFTH class-B SERVICE-TOKEN connector, and the FIRST self-hosted one: a
 *  Mattermost bot/personal-access token in the service-token store (env → SecretBackend),
 *  no OAuth. `authModel:"service-token"` routes its tools through `withNonOAuthContext`;
 *  `direction:"outbound-write"` on mattermost_send_message fires the egress gates. The
 *  per-deployment server URL is config (SAFESPACE_MATTERMOST_SERVER_URL), resolved by the
 *  client/handlers; resolveCredential enforces only the TOKEN's presence (the server-URL
 *  presence is enforced later, by the client → no_server_url). Its per-source skipFields
 *  (opaque team/channel/post ids + pagination cursors) lives on MATTERMOST_PACK. */
export const mattermost: NonOAuthSource = makeServiceTokenSource({
  id: MATTERMOST_PACK.id,
  storeKey: MATTERMOST_PACK.storeKey,
  errorName: MATTERMOST_PACK.errorName,
  skipFields: MATTERMOST_PACK.skipFields,
});

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
  authorize() {
    // No-op: Notion OAuth has no scope param (an integration's capabilities are configured
    // Notion-side). A token lacking access to a page yields a Notion 403/404 → the client
    // maps it to notion_api_failed{auth_failed/not_found}.
  },
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // v1.79 multi-workspace — mirrors googleWorkspace.resolveAccount: explicit
    // args.account_id (resolved id-OR-name) → active workspace → per-source last-used; then
    // validate against the notion index. Cross-provider safety: reads ONLY the notion
    // store, never google accounts.json.
    const accounts = await readNotionAccounts();
    // Explicit account_id may be a workspace id OR a case-insensitive name. An unknown /
    // ambiguous value → account_not_found echoing the caller's OWN input (byte-identical to
    // "unknown" → no oracle about which workspaces exist).
    let explicitId: string | null = null;
    if (deps.explicitAccountId != null) {
      const match = findNotionWorkspace(deps.explicitAccountId, accounts);
      if (match === "ambiguous" || match == null) {
        throw new MCPError("account_not_found", { email: deps.explicitAccountId });
      }
      explicitId = match.workspaceId;
    }
    const active = explicitId ? null : await readNotionActiveWorkspace();
    const accountId = explicitId ?? active ?? deps.lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
    }
    // Index validation: `accountId` must name a known workspace (catches a stale `lastUsed`
    // pointing at a deleted workspace). Echoes the caller's OWN input → no oracle.
    if (!accounts.some((a) => a.workspaceId === accountId)) {
      throw new MCPError("account_not_found", { email: deps.explicitAccountId ?? accountId });
    }
    return { accountId, scopes: [] };
  },
  async resolveCredential(_toolDef, deps): Promise<Credential> {
    const accountId = deps.accountId;
    if (accountId == null) {
      // Type-unreachable backstop (OAuthResolveDeps.accountId REQUIRED); kept to catch an
      // `as any` bypass, mirrors google-workspace + github.
      // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
      throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
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

/** v1.113 — X (Twitter) OAuth skipFields: opaque machine fields only (ids, timestamps,
 *  pagination cursors, result counts). Free-text fields like `name`, `description`,
 *  `text` are NOT skipped — they must be sanitize-wrapped when tools arrive in C2. */
export const X_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "id",
  "created_at",
  "edit_history_tweet_ids",
  "newest_id",
  "oldest_id",
  "next_token",
  "result_count",
]);

/** v1.113 — the FOURTH OAuth source: X (Twitter). Routes through `withToolContext`
 *  (`authModel:"oauth"`) like google-workspace + github + notion, but its access
 *  token expires every 2h. Refresh is PROACTIVE inside `resolveCredential` (via
 *  `getValidAccessToken`) — the Source stays `refreshable: false` so the choke-point
 *  401-retry path remains Google-only. ZERO tools this PR (skeleton Source only);
 *  `sourceFor("x")` is ready for C2 tool registration. Multi-account (mirror Notion). */
export const x: OAuthSource = {
  id: "x",
  authModel: "oauth",
  refreshable: false,
  skipFields: X_SKIP_FIELDS,
  authorize() {
    // No-op: X scopes are a fixed MVP set requested at consent time; tier is
    // proxy-enforced. A token lacking a needed capability yields an X 403 →
    // x_api_failed{api_error} once tools land.
  },
  async resolveAccount(_toolDef, deps): Promise<ResolvedAccount> {
    // Multi-account — mirrors notion.resolveAccount: explicit args.account_id
    // (resolved id-OR-username) → active account → per-source last-used; then
    // validate against the x index. Cross-provider safety: reads ONLY the x store, never
    // google accounts.json / notion.
    const accounts = await readXAccounts();
    // Explicit account_id may be a user id OR a case-insensitive username. An unknown /
    // ambiguous value → account_not_found echoing the caller's OWN input (byte-identical
    // to "unknown" → no oracle about which accounts exist).
    let explicitId: string | null = null;
    if (deps.explicitAccountId != null) {
      const match = findXAccount(deps.explicitAccountId, accounts);
      if (match === "ambiguous" || match == null) {
        throw new MCPError("account_not_found", { email: deps.explicitAccountId });
      }
      explicitId = match.id;
    }
    const active = explicitId ? null : await readXActiveAccount();
    const accountId = explicitId ?? active ?? deps.lastUsed;
    if (!accountId) {
      throw new MCPError("account_not_found", { reason: "no_active_account" });
    }
    // Index validation: `accountId` must name a known account. Echoes the caller's OWN
    // input → no oracle.
    if (!accounts.some((a) => a.id === accountId)) {
      throw new MCPError("account_not_found", { email: deps.explicitAccountId ?? accountId });
    }
    return { accountId, scopes: [] };
  },
  async resolveCredential(_toolDef, deps): Promise<Credential> {
    const accountId = deps.accountId;
    if (accountId == null) {
      // Type-unreachable backstop (OAuthResolveDeps.accountId REQUIRED); kept to catch
      // an `as any` bypass, mirrors google-workspace + github + notion.
      // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
      throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
    }
    // Proactive refresh lives inside getValidAccessToken (rotation-safe + single-
    // flight). refreshable:false on this Source keeps the choke-point 401-retry
    // Google-only.
    const token = await getValidAccessToken(accountId);
    // token is a GETTER, never a serializable field (types.ts) — JSON.stringify of a
    // ToolContext can't leak the x access token.
    return { kind: "oauth", provider: "x", accountId, getAccessToken: () => token };
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

export const github: OAuthSource = {
  id: "github",
  authModel: "oauth",
  refreshable: false,
  skipFields: GITHUB_SKIP_FIELDS,
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
      // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
      throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
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
  line,
  telegram,
  discord,
  slack,
  mattermost,
  github,
  notion,
  x,
};

/** Resolve a tool's Source from its `ToolDef.source` (B0 relabel), defaulting to
 *  google-workspace when `source` is omitted/undefined. An unknown id is FAIL-
 *  CLOSED (v1.112.8): throw `internal_routing_error{unknown_source}` rather than
 *  silently routing a typo'd label onto google-workspace (which would send the
 *  wrong OAuth token / skip the right envelope). Never echoes the bogus id. */
export function sourceFor(toolDef: Pick<ToolDef, "source"> | undefined): Source {
  // Omitted / undefined → google-workspace default (google tools omit `source`).
  if (toolDef?.source === undefined) {
    return googleWorkspace;
  }
  const source = SOURCES[toolDef.source];
  if (source === undefined) {
    throw new MCPError("internal_routing_error", { reason: "unknown_source" });
  }
  return source;
}
