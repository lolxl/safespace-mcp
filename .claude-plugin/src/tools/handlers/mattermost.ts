// v1.107 — the Mattermost handler (the FIFTH class-B SERVICE-TOKEN connector, after
// v1.66 LINE + v1.68 Telegram + v1.69 Discord + v1.95/v1.97 Slack). The FIRST self-hosted
// connector: the server host is the OWNER-configured SAFESPACE_MATTERMOST_SERVER_URL
// (auth/mattermost/base-url.ts), pinned by assertEgressHost.
//
// SERVICE-TOKEN: reads the bot/personal-access token via requireServiceToken(ctx) (the R6
// narrow) and uses it ONLY inline in the Authorization header (never stored). The
// cross-cutting envelope (tier / write-burst / sanitize / audit) is applied by
// withNonOAuthContext around it.
//
// 1 WRITE + 3 READ:
//   - mattermost_send_message  (POST /api/v4/posts)                — egress-gated
//   - mattermost_list_teams    (GET  /api/v4/users/me/teams)       — discover team_id
//   - mattermost_list_channels (GET  .../teams/{team_id}/channels) — channels in a team
//   - mattermost_read_messages (GET  /api/v4/channels/{id}/posts)  — a channel's posts
//
// MENTION NEUTRALIZATION — ACCEPTED BOUNDED RISK (the Mattermost-specific delta vs
// Slack/Discord): Slack escapes `<>&` to defuse `<!channel>` and Discord sends
// allowed_mentions:{parse:[]}; Mattermost's special mentions (`@all`/`@channel`/`@here`)
// are bare tokens with NO delimiter and NO reliable API flag / escaping primitive to
// disable them. v1 does NOT auto-neutralize them. The blast is BOUNDED by: (a) the
// recipient allowlist (the owner chooses which channels the agent may post to), (b) F3a
// secret-shape on the body, (c) Mattermost being a self-hosted, typically-internal
// deployment (not a public broadcast surface). Documented for the security review; a
// reliable neutralization is a possible follow-up.
//
// READ shaping: each read CURATES the response (picks only safe fields, never the raw
// object). Inbound content (team/channel display names, headers, purposes, post messages)
// is left OUT of MATTERMOST_SKIP_FIELDS (tools/source.ts) so the choke point's sanitize
// tree-walk WRAPS it as an untrusted source; opaque ids/cursors/enums ARE in skipFields so
// the agent gets them raw for follow-up calls.

import { MATTERMOST_ID_RE } from "../../policy/mattermost-recipient-allowlist";
import { mattermostApiGet } from "../../auth/mattermost/client";
import { requireMattermostBaseUrl } from "../../auth/mattermost/base-url";
import { enforceMattermostEgressGates } from "../egress";
import type { ToolContext } from "../types";
import { postServiceTokenJson, type ServiceTokenReason } from "./service-token-fetch";
import { assertEgressHost } from "../../policy/egress-destinations";
import { requireServiceToken } from "./shared";

/** Mattermost default max post length (chars). The server enforces its own (configurable)
 *  limit; we reject locally first so an oversize body never leaves the process. */
const MATTERMOST_MESSAGE_MAX = 16383;

const READ_PER_PAGE_DEFAULT = 50;
const READ_PER_PAGE_MAX = 200; // bounded page (context protection)

/** Test-injection seam (shared by send + reads) — production leaves it undefined. */
export interface MattermostDeps {
  fetchImpl?: typeof fetch;
}

/** Map a non-2xx HTTP status to the closed-set send reason. Mattermost uses real codes:
 *  400/404 (bad/unknown channel) → invalid_recipient; 401/403 → auth_failed; 429 → throttle. */
function mapSendStatus(status: number): ServiceTokenReason {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 404) return "invalid_recipient";
  return "api_error";
}

type Obj = Record<string, unknown>;
const asObj = (v: unknown): Obj | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null;

function clampPerPage(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : READ_PER_PAGE_DEFAULT;
  return Math.floor(Math.min(n, READ_PER_PAGE_MAX));
}

function clampPage(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? raw : 0;
  return Math.floor(Math.min(n, 1_000_000));
}

/** A team → curated shape. `name` (slug) + `display_name` are user-authored → they WRAP;
 *  `id` is opaque (in skipFields). */
function shapeTeam(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return { id: o.id, name: o.name, display_name: o.display_name };
}

/** A channel → curated shape. `name`/`display_name`/`header`/`purpose` are user-authored →
 *  they WRAP; `id`/`type` are opaque/controlled (in skipFields). */
function shapeChannel(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    id: o.id,
    type: o.type,
    name: o.name,
    display_name: o.display_name,
    header: typeof o.header === "string" ? o.header : undefined,
    purpose: typeof o.purpose === "string" ? o.purpose : undefined,
  };
}

/** A post → curated shape. `message` is the HIGHEST prompt-injection surface (it WRAPS);
 *  `id`/`user_id`/`channel_id`/`root_id`/`type` are opaque/controlled (in skipFields);
 *  `create_at` is a numeric epoch (sanitize passes numbers through untouched). */
function shapePost(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    id: o.id,
    channel_id: o.channel_id,
    user_id: o.user_id,
    root_id: o.root_id,
    type: o.type,
    message: typeof o.message === "string" ? o.message : "",
    create_at: typeof o.create_at === "number" ? o.create_at : undefined,
  };
}

/** mattermost_send_message — POST one text message to a known channel (WRITE). */
export async function mattermostSendMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: MattermostDeps = {},
): Promise<unknown> {
  // 1. Validate the channel id (well-formedness). Plain Error (bad input) — echoes the
  //    RULE, never the value. A well-formed id the server rejects → invalid_recipient below.
  const channelId = args.channel_id;
  if (typeof channelId !== "string" || !MATTERMOST_ID_RE.test(channelId)) {
    throw new Error("mattermost_send_message: 'channel_id' must be a 26-char Mattermost id ([a-z0-9])");
  }

  // 2. Validate the message body.
  const message = args.message;
  if (typeof message !== "string" || message.length === 0) {
    throw new Error("mattermost_send_message: 'message' must be a non-empty string");
  }
  if (message.length > MATTERMOST_MESSAGE_MAX) {
    throw new Error(`mattermost_send_message: 'message' exceeds the ${MATTERMOST_MESSAGE_MAX}-character limit`);
  }

  // 3. Egress gates (handler-called, B3 posture): secret-shape (F3a) on the body then the
  //    Mattermost recipient allowlist on `channel_id`. Throws -32035 / -32019 on denial.
  await enforceMattermostEgressGates(ctx, {
    tool: "mattermost_send_message",
    channel_id: channelId,
    body: message,
  });

  // 4. Send. Token read inline → Authorization header (never the URL/logs). The base URL is
  //    the configured server. NOTE: this is the SOLE egress pin for the WRITE path — the send
  //    goes through postServiceTokenJson (not mattermostApiGet, which is the read path's own
  //    pin), so this explicit assertEgressHost is load-bearing, not redundant.
  const token = requireServiceToken(ctx).token();
  const url = `${requireMattermostBaseUrl()}/api/v4/posts`;
  assertEgressHost(new URL(url).hostname, "mattermost");
  // Allowlist-constructed body: channel_id + message ONLY (no props / file_ids / no
  // server-fetched fields → no SSRF-by-proxy). Mattermost returns 201 + the post; the
  // shared helper discards the body (no checkBody — Mattermost uses real HTTP codes).
  await postServiceTokenJson({
    url,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${token}`,
    },
    body: { channel_id: channelId, message },
    mapStatus: mapSendStatus,
    errorName: "mattermost_api_failed",
    fetchImpl: deps.fetchImpl,
  });

  return { channel_id: channelId, sent: true, message_type: "text" };
}

/** mattermost_list_teams — the teams the bot is a member of (READ). Discovers team_id. */
export async function mattermostListTeams(
  ctx: ToolContext,
  _args: Record<string, unknown>,
  deps: MattermostDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const data = await mattermostApiGet({ token, path: "users/me/teams", fetchImpl: deps.fetchImpl });
  return { teams: Array.isArray(data) ? data.map(shapeTeam) : [] };
}

/** mattermost_list_channels — the channels the bot can see in a team (READ). */
export async function mattermostListChannels(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: MattermostDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const teamId = args.team_id;
  if (typeof teamId !== "string" || !MATTERMOST_ID_RE.test(teamId)) {
    throw new Error("mattermost_list_channels: 'team_id' must be a 26-char Mattermost id (from mattermost_list_teams)");
  }
  const data = await mattermostApiGet({
    token,
    path: `users/me/teams/${teamId}/channels`,
    fetchImpl: deps.fetchImpl,
  });
  return {
    team_id: teamId,
    channels: Array.isArray(data) ? data.map(shapeChannel) : [],
  };
}

/** mattermost_read_messages — the posts in a channel (READ; page-paginated). */
export async function mattermostReadMessages(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: MattermostDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const channelId = args.channel_id;
  if (typeof channelId !== "string" || !MATTERMOST_ID_RE.test(channelId)) {
    throw new Error("mattermost_read_messages: 'channel_id' must be a 26-char Mattermost id");
  }
  const data = await mattermostApiGet({
    token,
    path: `channels/${channelId}/posts`,
    query: { per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  // GET /channels/{id}/posts → { order: [postId…], posts: { postId: {post} }, next_post_id, prev_post_id }.
  // Re-assemble into the `order`-sorted array of curated posts; the opaque cursors are skipFields.
  const obj = asObj(data) ?? {};
  const order = Array.isArray(obj.order) ? (obj.order as unknown[]) : [];
  const posts = asObj(obj.posts) ?? {};
  const shaped = order
    .map((pid) => (typeof pid === "string" ? posts[pid] : undefined))
    .filter((p) => p !== undefined)
    .map(shapePost);
  return {
    channel_id: channelId,
    posts: shaped,
    next_post_id: typeof obj.next_post_id === "string" ? obj.next_post_id : "",
    prev_post_id: typeof obj.prev_post_id === "string" ? obj.prev_post_id : "",
  };
}
