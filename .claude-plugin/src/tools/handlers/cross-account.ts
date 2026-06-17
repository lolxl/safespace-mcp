// Cross-account (*_all) fan-out — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { driveClientFromToken, gmailClientFromToken, tasksClientFromToken, youtubeClientFromToken } from "../../google-api/client";
import { mapGoogleError } from "../../google-api/errors";
import { withAllAccounts, type AccountSubContext, type MultiAccountResult, type WithAllAccountsDeps } from "../with-all-accounts";

import { TASKLIST_ID_RE, clampYoutubeMaxResults } from "./shared";

/* ───────── v1.14 Phase 1: gmail_search_all (CROSS-ACCOUNT READ tool) ─────────
 *
 * First transverse pattern in SafeSpace. Fan-out across consented Google
 * accounts via `withAllAccounts` middleware. Per-account fresh sanitize nonce
 * + per-account audit row + 1 outer aggregate row. Best-effort partial-
 * success semantics: per-account failures encoded into `failures[]`, never
 * thrown. See `docs/v1.14-cross-account-search.md` (binding contract) +
 * `src/tools/with-all-accounts.ts` for the helper.
 *
 * Active-account semantics: this handler is dispatched OUTSIDE `withToolContext`
 * (proxy.ts cross-account branch), so it does NOT trigger any
 * single-account preference state. Cross-account tools never set
 * `lastUsedAccount` (design §3).
 *
 * Per-account args.max_results bounds (per design §3):
 *   - Default: 25 per account (smaller than single-account's 10 because the
 *     cross-account caller expects a wider snapshot but still bounded)
 *   - Hard cap: 50 per account (anti-DoS guard at handler boundary)
 */
const GMAIL_SEARCH_ALL_DEFAULT_MAX_RESULTS = 25;
const GMAIL_SEARCH_ALL_MAX_RESULTS_CAP = 50;

export interface GmailSearchAllSubSuccess {
  messages: unknown;
  nextPageToken?: string;
}

/** Cross-account `gmail_search_all` handler.
 *
 *  Signature note: takes `(args, deps?)` — NOT the normal `(ctx, args)` shape
 *  used by single-account tools. Cross-account tools are dispatched OUTSIDE
 *  `withToolContext` (proxy.ts cross-account branch); the helper itself owns
 *  account resolution + refresh + audit + sanitize, so there's no single
 *  `ctx` to pass. Registry exposes a thin `(ctx, args)` shim that drops
 *  `ctx` and forwards `args` here. */
export async function gmailSearchAll(
  args: Record<string, unknown>,
  deps: WithAllAccountsDeps = {},
): Promise<MultiAccountResult<GmailSearchAllSubSuccess>> {
  // Type-then-presence split — same pattern as gmailSend / gmailSearch.
  if (typeof args.query !== "string") {
    throw new Error("gmail_search_all: 'query' must be a string");
  }
  if (!args.query.trim()) {
    throw new Error("gmail_search_all requires a non-empty 'query' string");
  }
  const query = args.query;
  // Defense-in-depth: schema already constrains compliant clients, but
  // non-compliant ones (or test harnesses) can slip NaN / -Infinity / Infinity
  // past `typeof === "number"`. `Math.min(NaN, CAP) === NaN` → Math.floor(NaN)
  // → NaN → SDK 400. Force a finite ≥1 value or fall back to DEFAULT.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : GMAIL_SEARCH_ALL_DEFAULT_MAX_RESULTS;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : GMAIL_SEARCH_ALL_DEFAULT_MAX_RESULTS;
  const maxResults = Math.floor(Math.min(requested, GMAIL_SEARCH_ALL_MAX_RESULTS_CAP));

  // accounts? filter — undefined / non-array / empty → all consented.
  // Type-narrow only; helper does the EMAIL_RECIPIENT_RE validation +
  // accounts.json intersection + per-entry failure mapping.
  let accountsFilter: string[] | undefined;
  if (Array.isArray(args.accounts)) {
    const filtered: string[] = [];
    for (const entry of args.accounts) {
      if (typeof entry !== "string") {
        throw new Error(
          "gmail_search_all: 'accounts' entries must each be a string",
        );
      }
      filtered.push(entry);
    }
    if (filtered.length > 0) accountsFilter = filtered;
  }

  return withAllAccounts<GmailSearchAllSubSuccess>(
    "gmail_search_all",
    args,
    async (subAccount: AccountSubContext) => {
      // Sub-call shape: parallel single-account gmail.users.messages.list
      // call per account. mapGoogleError re-throws with the right shape
      // (httpStatus / MCPError) — the helper catches and maps to
      // failures[] entries per design §6.
      try {
        const gmail = gmailClientFromToken(subAccount.getAccessToken());
        const res = await gmail.users.messages.list({
          userId: "me",
          q: query,
          maxResults,
        });
        return {
          messages: res.data.messages ?? [],
          ...(res.data.nextPageToken !== undefined && res.data.nextPageToken !== null
            ? { nextPageToken: res.data.nextPageToken }
            : {}),
        };
      } catch (err) {
        // Re-throw via mapGoogleError so helper sees the
        // {httpStatus, MCPError} shape it expects. mapGoogleError is
        // declared `never` — execution does not continue past this point.
        mapGoogleError(err, { tool: "gmail_search_all", email: subAccount.email });
      }
    },
    {
      accounts: accountsFilter,
      requiredScopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    },
    deps,
  );
}

/* ───────── v1.14 Phase 2: drive_search_all (CROSS-ACCOUNT READ tool) ─────────
 *
 * Pattern-copy of gmailSearchAll. Fan-out across consented Google accounts
 * via `withAllAccounts` middleware. Per-account fresh sanitize nonce + per-
 * account audit row + 1 outer aggregate row. Best-effort partial-success
 * semantics. See `docs/v1.14-cross-account-search.md` §3 (binding contract).
 *
 * Active-account semantics: cross-account branch in proxy.ts dispatches OUTSIDE
 * `withToolContext`, so `lastUsedAccount` is NOT mutated (design §3).
 *
 * v2.1 Drive whitelist (drive-whitelist.json) is INTENTIONALLY NOT consulted
 * here (sec-rev hook P2-1). The whitelist gates `drive_share_file` only — a
 * write boundary. `drive_search_all` is read-only; consulting the whitelist
 * would defeat the very purpose of cross-account search (the whole point is to
 * discover files across accounts; whitelist scope is per-share-target).
 *
 * Required scope: drive.readonly (matches single-account `drive_search`).
 * SCOPE_HIERARCHY (with-context.ts) encodes `drive.readonly ⊂ drive`, so an
 * account that granted broader `drive` also satisfies this requirement
 * (sec-rev hook P2-3).
 *
 * Per-account args.max_results bounds (per design §3):
 *   - Default: 25 per account (cross-account caller expects wider snapshot)
 *   - Hard cap: 50 per account (anti-DoS guard at handler boundary)
 */
const DRIVE_SEARCH_ALL_DEFAULT_MAX_RESULTS = 25;
const DRIVE_SEARCH_ALL_MAX_RESULTS_CAP = 50;

// Field projection — IDENTICAL to single-account `drive_search` (do NOT loosen
// per Phase 2 spec). Keeps cross-account response shape symmetric with
// single-account search.
const DRIVE_SEARCH_ALL_FIELDS =
  "files(id,name,mimeType,modifiedTime,webViewLink,size,iconLink,parents),nextPageToken";

export interface DriveSearchAllSubSuccess {
  files: unknown;
  nextPageToken?: string;
}

/** Cross-account `drive_search_all` handler.
 *
 *  Signature note: takes `(args, deps?)` — NOT the normal `(ctx, args)` shape
 *  used by single-account tools. Cross-account tools are dispatched OUTSIDE
 *  `withToolContext` (proxy.ts cross-account branch); the helper itself owns
 *  account resolution + refresh + audit + sanitize, so there's no single
 *  `ctx` to pass. Registry exposes a thin `(ctx, args)` shim that drops
 *  `ctx` and forwards `args` here. */
export async function driveSearchAll(
  args: Record<string, unknown>,
  deps: WithAllAccountsDeps = {},
): Promise<MultiAccountResult<DriveSearchAllSubSuccess>> {
  // Type-then-presence split — same pattern as gmailSearchAll.
  if (typeof args.query !== "string") {
    throw new Error("drive_search_all: 'query' must be a string");
  }
  if (!args.query.trim()) {
    throw new Error("drive_search_all requires a non-empty 'query' string");
  }
  const query = args.query;
  // Defense-in-depth: schema already constrains compliant clients, but
  // non-compliant ones (or test harnesses) can slip NaN / -Infinity / Infinity
  // past `typeof === "number"`. `Math.min(NaN, CAP) === NaN` → Math.floor(NaN)
  // → NaN → SDK 400. Force a finite ≥1 value or fall back to DEFAULT.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : DRIVE_SEARCH_ALL_DEFAULT_MAX_RESULTS;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : DRIVE_SEARCH_ALL_DEFAULT_MAX_RESULTS;
  const maxResults = Math.floor(Math.min(requested, DRIVE_SEARCH_ALL_MAX_RESULTS_CAP));

  // accounts? filter — undefined / non-array / empty → all consented.
  // Type-narrow only; helper does the EMAIL_RECIPIENT_RE validation +
  // accounts.json intersection + per-entry failure mapping.
  let accountsFilter: string[] | undefined;
  if (Array.isArray(args.accounts)) {
    const filtered: string[] = [];
    for (const entry of args.accounts) {
      if (typeof entry !== "string") {
        throw new Error(
          "drive_search_all: 'accounts' entries must each be a string",
        );
      }
      filtered.push(entry);
    }
    if (filtered.length > 0) accountsFilter = filtered;
  }

  return withAllAccounts<DriveSearchAllSubSuccess>(
    "drive_search_all",
    args,
    async (subAccount: AccountSubContext) => {
      // Sub-call shape: parallel single-account drive.files.list call per
      // account. Note our input field name is `query` (matches single-account
      // drive_search input), but the Drive SDK parameter name is `q`. Keep
      // this mapping; do NOT rename either side.
      try {
        const drive = driveClientFromToken(subAccount.getAccessToken());
        const res = await drive.files.list({
          q: query,
          pageSize: maxResults,
          fields: DRIVE_SEARCH_ALL_FIELDS,
        });
        return {
          files: res.data.files ?? [],
          ...(res.data.nextPageToken !== undefined && res.data.nextPageToken !== null
            ? { nextPageToken: res.data.nextPageToken }
            : {}),
        };
      } catch (err) {
        // Re-throw via mapGoogleError so helper sees the
        // {httpStatus, MCPError} shape it expects. mapGoogleError is
        // declared `never` — execution does not continue past this point.
        mapGoogleError(err, { tool: "drive_search_all", email: subAccount.email });
      }
    },
    {
      accounts: accountsFilter,
      requiredScopes: ["https://www.googleapis.com/auth/drive.readonly"],
    },
    deps,
  );
}

/* ───────── v1.15 Phase 1b — contacts_search / contacts_lookup_email / contacts_get (READ tools) ─────────
 *
 * Read-tier Google People (Contacts) API tools. See docs/v1.15-contacts-api.md
 * §3-§4. Pattern mirrors v1.13 calendar_list_events / calendar_get_event —
 * handler is a thin shim over the People SDK; sanitize + error mapping happen
 * at the middleware layer (`with-context.ts`).
 *
 * Three quirks unique to this family (per design):
 *
 *   1. CACHE-WARMING (design §4 "Warming-call shape (locked)")
 *      People API `searchContacts` requires a per-account cache-warming dance
 *      (empty-query call + ~3000ms wait) on first call after sign-in BEFORE
 *      the index is populated. Without it, the first real call frequently
 *      returns empty results. Handler maintains a per-process Set of warmed
 *      accounts; first call triggers warm + sleep, subsequent calls skip.
 *
 *      Timing-leak scope is INTENTIONAL (§4): observable warm/cold variance
 *      reveals only "has contacts_search been called for this account in this
 *      process" — not contact contents. Per-process cache; per-account-token
 *      already isolates the observation surface.
 *
 *   2. AMBIGUITY CONTRACT (design §4 + §11 hook #2 + #6)
 *      `contacts_lookup_email` MUST return ALL matches with `ambiguous: true`
 *      when matches.length > 1 — NEVER auto-pick. Phase 3 will use this to
 *      gate `gmail_send` / `calendar_create_event` recipient resolution;
 *      auto-pick would defeat the name-collision defense.
 *
 *      Error data shape (locked §11 hook #6): when ambiguity returns,
 *      response field MUST contain ONLY { ambiguous: true, match_count: N } —
 *      NEVER echoes display_name / email / any contact-identifying string
 *      (would convert the response into a contact-enumeration oracle).
 *
 *   3. RESOURCE NAME VALIDATION (design §4)
 *      `contacts_get` validates resource_name with /^people\/c[0-9]{1,32}$/
 *      at handler boundary BEFORE any SDK call. Rejects path traversal /
 *      CRLF / over-long input early.
 *
 * Sec-rev hooks (per design §11) applied here:
 *   #1  Fixed-duration sleep on warming path (PEOPLE_WARM_SLEEP_MS = 3000ms,
 *       no shortcut, no jitter); see `warmPeopleCache` below.
 *   #2  `contacts_lookup_email` ambiguity contract — ALL matches always
 *       surfaced; never auto-picks; `match_count` summary only on ambiguity.
 *   #4  Sanitize wrap on `biographies` — handled at middleware layer; ABSENCE
 *       sentinels in patterns.test.ts assert `biographies` NOT in SKIP_FIELDS.
 *   #7  ABSENCE sentinels — patterns.test.ts asserts user-controllable Person
 *       fields (displayName / value / formattedValue / biographies / etc.)
 *       are NOT in SKIP_FIELDS.
 *   #9  `etag` MUST NOT be required input — none of the 3 read tools accept
 *       `etag`. Verified by registry.ts inputSchema.
 *  #11  args_hash plain SHA-256 — middleware (`with-context.ts`) uses the
 *       existing audit machinery; v1.15 makes no audit-schema changes.
 *  #12  Per-account isolation — warming cache key is `email` only at the
 *       Set level; SDK call uses `ctx.getAccessToken()` (per-account token).
 *       Cross-account lookup is impossible by construction.
 *
 * Hooks #3, #5, #6, #8 apply to Phase 2 / Phase 3 (deferred); hook #10
 * (re-consent destructive-cleanup) already in main via PR #106.
 */

const YOUTUBE_SUBSCRIPTIONS_DEFAULT_MAX = 25;
const YOUTUBE_SUBSCRIPTIONS_MAX_CAP = 50;

const YOUTUBE_READONLY_SCOPE = "https://www.googleapis.com/auth/youtube.readonly";

/* ── youtube_search burst-limit state ────────────────────────────────────
 *
 * Per-process integer counter `youtubeSearchesThisSession`. Caps prompt-
 * injection-driven `youtube_search` loops at the most expensive READ tool
 * (100 quota units / call). Default cap 20 = 2000u = 20% of daily quota,
 * still within budget yet caps over-burn.
 *
 * Counter resets on MCP server restart (= new Claude session). No durable
 * state — restart IS the recovery path.
 *
 * v1.18 Phase 1: the env-var parser `getYoutubeSearchBurstLimit` was
 * hoisted to `src/policy/youtube-search-burst.ts` (mirrors v1.16 Phase 2a
 * `youtube-comment-burst.ts` layout). The doctor row in `src/status.ts`
 * reads from the policy module to avoid a `src/cli/` → `src/tools/`
 * layering cycle. The counter + reset helpers remain here because the
 * sole consumer (`youtubeSearch` below) lives in this file.
 *
 * See docs/v1.16-youtube-api.md §4 (`youtube_search` description) + §13
 * Risk 3 + §11 sec-rev hook #19; docs/v1.18-operational-quality.md §2.1
 * code-A3 for the v1.18 extraction. */

/** `youtube_subscriptions_all` — CROSS-ACCOUNT fan-out via `withAllAccounts`.
 *
 *  Per design §4: subscriptions are account-owned data; the natural query
 *  is "what am I subscribed to across all my YouTube accounts". Single-
 *  account form intentionally omitted (caller can pass `accounts: ['<email>']`
 *  to scope to one account).
 *
 *  Active-account semantics: does NOT mutate lastUsedAccount (v1.14 §3).
 *  Per-account fresh sanitize nonce via `withAllAccounts` internals (sec-rev
 *  hooks #3, #5).
 *
 *  Quota: `subscriptions.list` = 1 unit / call × N accounts. Cheap. */
export interface YoutubeSubscriptionsAllSubSuccess {
  subscriptions: unknown;
  nextPageToken?: string;
}

export async function youtubeSubscriptionsAll(
  args: Record<string, unknown>,
  deps: WithAllAccountsDeps = {},
): Promise<MultiAccountResult<YoutubeSubscriptionsAllSubSuccess>> {
  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_SUBSCRIPTIONS_DEFAULT_MAX,
    YOUTUBE_SUBSCRIPTIONS_MAX_CAP,
  );

  // accounts? filter — type-narrow ONLY. helper does EMAIL_RECIPIENT_RE
  // validation + accounts.json intersection + per-entry failure mapping.
  let accountsFilter: string[] | undefined;
  if (Array.isArray(args.accounts)) {
    const filtered: string[] = [];
    for (const entry of args.accounts) {
      if (typeof entry !== "string") {
        throw new Error(
          "youtube_subscriptions_all: 'accounts' entries must each be a string",
        );
      }
      filtered.push(entry);
    }
    if (filtered.length > 0) accountsFilter = filtered;
  }

  return withAllAccounts<YoutubeSubscriptionsAllSubSuccess>(
    "youtube_subscriptions_all",
    args,
    async (subAccount: AccountSubContext) => {
      try {
        const yt = youtubeClientFromToken(subAccount.getAccessToken());
        const res = await yt.subscriptions.list({
          part: ["snippet"],
          mine: true,
          maxResults,
        });
        return {
          subscriptions: res.data.items ?? [],
          ...(res.data.nextPageToken !== undefined && res.data.nextPageToken !== null
            ? { nextPageToken: res.data.nextPageToken }
            : {}),
        };
      } catch (err) {
        // mapGoogleError throws — declared `never`. Execution does not
        // continue past this point.
        if (err instanceof MCPError) throw err;
        mapGoogleError(err, {
          tool: "youtube_subscriptions_all",
          email: subAccount.email,
        });
      }
    },
    {
      accounts: accountsFilter,
      requiredScopes: [YOUTUBE_READONLY_SCOPE],
    },
    deps,
  );
}

const TASKS_SEARCH_ALL_DEFAULT_MAX = 50;
const TASKS_SEARCH_ALL_CAP = 100;
/** Per design §2.3 + sec-rev hook #10. Length cap is a DoS guard — also
 *  prevents a megabyte-string from reaching Google's API and from feeding
 *  unbounded work into the per-account substring match below. */
const TASKS_SEARCH_QUERY_MAX_LENGTH = 256;

export interface TasksSearchAllSubSuccess {
  items: unknown;
  nextPageToken?: string;
}

/** Cross-account `tasks_search_all` handler.
 *
 *  Signature note: takes `(args, deps?)` — NOT the normal `(ctx, args)` shape
 *  used by single-account tools. Cross-account tools are dispatched OUTSIDE
 *  `withToolContext` (proxy.ts cross-account branch); the helper itself owns
 *  account resolution + refresh + audit + sanitize, so there's no single
 *  `ctx` to pass. Registry exposes a thin `(ctx, args)` shim that drops
 *  `ctx` and forwards `args` here. */
export async function tasksSearchAll(
  args: Record<string, unknown>,
  deps: WithAllAccountsDeps = {},
): Promise<MultiAccountResult<TasksSearchAllSubSuccess>> {
  // ── Phase 1: query strict-parse (sec-rev hook #10) ──
  // Type-then-presence split — same pattern as gmail_search_all /
  // drive_search_all. Empty / whitespace-only / non-string / over-length
  // all rejected BEFORE any fan-out so zero SDK calls occur on bad input.
  if (typeof args.query !== "string") {
    throw new Error("tasks_search_all: 'query' must be a string");
  }
  const queryTrimmed = args.query.trim();
  if (queryTrimmed.length === 0) {
    throw new Error("tasks_search_all requires a non-empty 'query' string");
  }
  // Cap on the RAW (pre-trim) input so attacker-controlled padding can't
  // sneak a megabyte string past the trim. Matches sec-rev hook #10 spec:
  // "args.query as string + non-empty post-trim + length cap ≤ 256".
  if (args.query.length > TASKS_SEARCH_QUERY_MAX_LENGTH) {
    throw new Error(
      `tasks_search_all: 'query' exceeds ${TASKS_SEARCH_QUERY_MAX_LENGTH} chars`,
    );
  }
  const queryLower = queryTrimmed.toLowerCase();

  // ── Phase 2: optional tasklist_id (sec-rev hook #5; carry-forward) ──
  // Default to `@default` per design §2.3 — the well-known sentinel for each
  // account's primary task list. Multi-tasklist scan is Phase 4+; this is
  // documented as a UX surprise in §11 Risk 5.
  let tasklistId = "@default";
  if (args.tasklist_id !== undefined) {
    if (typeof args.tasklist_id !== "string") {
      throw new Error("tasks_search_all: 'tasklist_id' must be a string");
    }
    // `@default` is the documented sentinel and MUST be accepted even though
    // it does not match the [A-Za-z0-9_-]{1,128} regex. Allow it as a literal
    // before the regex check.
    if (
      args.tasklist_id !== "@default" &&
      !TASKLIST_ID_RE.test(args.tasklist_id)
    ) {
      throw new Error(
        "tasks_search_all: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
      );
    }
    tasklistId = args.tasklist_id;
  }

  // ── Phase 3: max_results clamp with finite-and-positive guard ──
  // Defense-in-depth identical to v1.14 gmailSearchAll / driveSearchAll +
  // Phase 1b tasksList: non-conforming clients can slip NaN / Infinity past
  // `typeof === "number"`. `Math.min(NaN, CAP) === NaN` → SDK 400. Force a
  // finite ≥1 value or fall back to DEFAULT.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : TASKS_SEARCH_ALL_DEFAULT_MAX;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : TASKS_SEARCH_ALL_DEFAULT_MAX;
  const maxResults = Math.floor(Math.min(requested, TASKS_SEARCH_ALL_CAP));

  // ── Phase 4: accounts filter (type-narrow only; helper does email regex) ──
  // EMAIL_RECIPIENT_RE validation happens inside `withAllAccounts` (Phase 1
  // of the helper). We only type-narrow + reject obviously-malformed array
  // entries here so the helper sees a clean string[].
  let accountsFilter: string[] | undefined;
  if (Array.isArray(args.accounts)) {
    const filtered: string[] = [];
    for (const entry of args.accounts) {
      if (typeof entry !== "string") {
        throw new Error(
          "tasks_search_all: 'accounts' entries must each be a string",
        );
      }
      filtered.push(entry);
    }
    if (filtered.length > 0) accountsFilter = filtered;
  }

  return withAllAccounts<TasksSearchAllSubSuccess>(
    "tasks_search_all",
    args,
    async (subAccount: AccountSubContext) => {
      // Per-account sub-call shape: parallel single-account tasks.tasks.list
      // per account, then client-side title+notes substring filter.
      //
      // showCompleted / showHidden are HARD-CODED FALSE per design (locked
      // from Phase 1b tasksList): hidden tasks expose Google-internal UI
      // state the user did not consciously mark visible; completed tasks
      // are usually clutter in a cross-account search.
      try {
        const tasks = tasksClientFromToken(subAccount.getAccessToken());
        const res = await tasks.tasks.list({
          tasklist: tasklistId,
          maxResults,
          showCompleted: false,
          showHidden: false,
        });
        // Client-side filter — case-insensitive title + notes substring
        // (logical OR per design §2.3). Both fields checked; either match
        // surfaces the task. Bounded by per-account fetch cap (maxResults).
        const items = (res.data.items ?? []).filter(
          (task: { title?: unknown; notes?: unknown }) => {
            const titleMatch =
              typeof task.title === "string" &&
              task.title.toLowerCase().includes(queryLower);
            const notesMatch =
              typeof task.notes === "string" &&
              task.notes.toLowerCase().includes(queryLower);
            return titleMatch || notesMatch;
          },
        );
        return {
          items,
          ...(res.data.nextPageToken !== undefined &&
          res.data.nextPageToken !== null
            ? { nextPageToken: res.data.nextPageToken }
            : {}),
        };
      } catch (err) {
        // Re-throw via mapGoogleError so helper sees the
        // {httpStatus, MCPError} shape it expects. mapGoogleError is
        // declared `never` — execution does not continue past this point.
        if (err instanceof MCPError) throw err;
        mapGoogleError(err, {
          tool: "tasks_search_all",
          email: subAccount.email,
        });
      }
    },
    {
      accounts: accountsFilter,
      requiredScopes: ["https://www.googleapis.com/auth/tasks"],
    },
    deps,
  );
}

/* ───────── v1.19 Phase 2b — tasks_create / tasks_update / tasks_delete (WRITE tools) ─────────
 *
 * Write-tier Google Tasks API tools. See docs/v1.19-tasks-api.md §2.5 / §2.6 / §2.7.
 * Pattern mirrors v1.13 calendar_create_event PR #118 (positive ALLOWLIST + 15-field
 * NEGATIVE sentinel via requestBody construction) + v1.17 Phase 1 calendar mutation
 * tools (audit-before-SDK + tier check FIRST + tasksMutationMeta channel) + v1.17
 * Phase 3 youtube_comment_delete (permanently destructive; min_tier=write; NO
 * pre-fetch TOCTOU).
 *
 * Sec-rev hooks applied (per design §10):
 *   #1   tasks_delete min_tier=write — registry asserts; handler tier check.
 *   #2   NEGATIVE sentinel for tasks_create requestBody — 15 forbidden fields:
 *        id / etag / kind / selfLink / position / updated / completed / deleted /
 *        hidden / links / webViewLink / parent / previous / taskListId / assignmentInfo.
 *   #3   NEGATIVE sentinel for tasks_update requestBody — same 15 fields.
 *   #4   status enum closed-set (`needsAction` | `completed` only).
 *   #5   tasklist_id + task_id regex pinned + DoS length caps (carry-forward
 *        from Phase 1b — same TASKLIST_ID_RE / TASK_ID_RE).
 *   #6   Per-call delete only — no bulk schema.
 *  #11   Audit-on-denial invariant — recordTasksMutationMeta called BEFORE
 *        SDK call so forensic fields survive SDK 5xx (mirror v1.16 INFO-4 +
 *        v1.17 Phase 1/2/3 reconciliation pattern). Denied-tier rows still
 *        record meta then throw.
 *  #12   No PII echo — error messages reference the RULE, not the input value.
 *  #13   tasks_delete recovery-impossibility — Google Tasks has NO trash;
 *        registry description warns; `safespace audit deletes` extends to
 *        count tasks_delete rows.
 *  #14   `due` field strict-parse pre-SDK (RFC 3339 regex + length cap 32) —
 *        defense against Google echoing raw user input in error responses.
 */

