// ServiceTokenPack — the declarative descriptor for a class-B service-token connector.
//
// A pack is the SINGLE place the connector-varying parameters live, so the shared
// factories (recipient-allowlist, CLI trio, Source entry inputs) cannot drift apart
// on a security-sensitive surface. STEP 1 migrated LINE as the proof; STEP 2 migrated the
// other four connectors (telegram/discord/slack/mattermost) onto the same machinery and
// derives the 5 service-token rows of egress-posture.ts from SERVICE_TOKEN_PACKS.
//
// ── What a pack DERIVES today ────────────────────────────────────────────────
//   - policy/*-recipient-allowlist.ts  → makeServiceTokenRecipientAllowlist(pack)
//   - cli/{id}.ts set-token/status/clear-token trio → makeServiceTokenCommands(pack)
//   - tools/source.ts entry inputs     → makeServiceTokenSource({id,storeKey,errorName,skipFields})
//
// ── What stays HAND-WIRED on purpose (NOT derived from the pack) ─────────────
//   - registry/tool defs     — tool schemas + min_tier + direction are product surface, not pack data
//   - handler                — per-API request body/URL/status-map are connector-specific
//   - egress wrapper name    — enforceLineEgressGates is a hand-pinned sentinel target (GATE_TABLE)
//   - egress-coverage sentinels — deliberately independent cross-checks; deriving them would defeat the tripwire
//   - errors.ts union        — MCPError closed set is the global error taxonomy, not per-connector config
//   - egress-destinations entry — fixed host registry for assertEgressHost; not a pack concern
//
// Circular-import discipline: this module imports ONLY leaf types + config constants.
// policy/ + cli/ + tools/source.ts all import it; it must never import them.

import type { ServiceName } from "../auth/service-token-store";
import {
  ENV_DISCORD_BOT_TOKEN,
  ENV_DISCORD_RECIPIENT_ALLOW,
  ENV_DISCORD_RECIPIENT_ALLOW_EXTRA,
  ENV_LINE_CHANNEL_TOKEN,
  ENV_LINE_RECIPIENT_ALLOW,
  ENV_LINE_RECIPIENT_ALLOW_EXTRA,
  ENV_MATTERMOST_BOT_TOKEN,
  ENV_MATTERMOST_RECIPIENT_ALLOW,
  ENV_MATTERMOST_RECIPIENT_ALLOW_EXTRA,
  ENV_SLACK_BOT_TOKEN,
  ENV_SLACK_RECIPIENT_ALLOW,
  ENV_SLACK_RECIPIENT_ALLOW_EXTRA,
  ENV_TELEGRAM_BOT_TOKEN,
  ENV_TELEGRAM_RECIPIENT_ALLOW,
  ENV_TELEGRAM_RECIPIENT_ALLOW_EXTRA,
} from "../config";
import type { ServiceTokenErrorName } from "./handlers/service-token-fetch";

/** The connector-varying parameters of a class-B service-token connector.
 *  Field set is YAGNI-derived from what the LINE migration genuinely consumes. */
export interface ServiceTokenPack {
  /** Audit / Source id (and usually the SecretBackend service key). */
  readonly id: ServiceName;
  /** SecretBackend service key passed to read/set/deleteServiceToken. Today = id. */
  readonly storeKey: ServiceName;
  /** Closed-set `*_api_failed` MCPError name for this connector. */
  readonly errorName: ServiceTokenErrorName;
  /** Per-source sanitize opaque-key set (replaces the global SKIP_FIELDS). */
  readonly skipFields: ReadonlySet<string>;
  readonly env: {
    /** Persistent recipient allowlist env var name. */
    readonly recipientAllow: string;
    /** Shell-only additive recipient allowlist overlay env var name. */
    readonly recipientAllowExtra: string;
    /** Shell-only service-token override env var name. */
    readonly token: string;
  };
  readonly recipientIdSpec: {
    /** Anchored + restricted-class regex used by the allowlist parse + handler pre-check. */
    readonly regex: RegExp;
    /** Human label for the id class (docs / diagnostics). */
    readonly label: string;
  };
  readonly cli: {
    /** Top-level CLI command name (`safespace <commandName> …`). */
    readonly commandName: string;
    /** Full noun phrase in save/status/clear output, e.g. "LINE channel access token". */
    readonly tokenLabel: string;
    /** Short kind in the USAGE stdin line, e.g. "channel access token". */
    readonly tokenKind: string;
    /** Display name for allowlist status lines, e.g. "LINE". */
    readonly displayName: string;
    /** Noun fragment in the OFF allowlist message: "all valid {allowlistIdNoun} allowed". */
    readonly allowlistIdNoun: string;
    /** OPTIONAL extra USAGE trailer line (static CLI copy). Only mattermost needs it
     *  (its server URL is env-config, not a CLI-managed secret); omitted → USAGE is the
     *  standard 4-line block. The DYNAMIC status line (mattermost's server-URL state) is
     *  a separate runtime seam on makeServiceTokenCommands, since it must call auth code
     *  the pack cannot import (leaf-types + config-consts only). */
    readonly usageNote?: string;
  };
}

/** Opaque LINE ids that must NOT be confusable-normalized by sanitize (R8(b)). */
const LINE_SKIP_FIELDS: ReadonlySet<string> = new Set([
  "userId",
  "groupId",
  "roomId",
  "to",
  "messageId",
  "quoteToken",
]);

/** LINE Official Account — the flagship class-B pack instance (step-1 migration proof). */
export const LINE_PACK: ServiceTokenPack = {
  id: "line",
  storeKey: "line",
  errorName: "line_api_failed",
  skipFields: LINE_SKIP_FIELDS,
  env: {
    recipientAllow: ENV_LINE_RECIPIENT_ALLOW,
    recipientAllowExtra: ENV_LINE_RECIPIENT_ALLOW_EXTRA,
    token: ENV_LINE_CHANNEL_TOKEN,
  },
  recipientIdSpec: {
    // user `U…` / group `C…` / room `R…` + 32 lowercase hex. Anchored + restricted class
    // implicitly rejects CR/LF/NUL/path/whitespace (the gmail recipient-gate invariant).
    regex: /^[UCR][0-9a-f]{32}$/,
    label: "LINE userId/groupId/roomId",
  },
  cli: {
    commandName: "line",
    tokenLabel: "LINE channel access token",
    tokenKind: "channel access token",
    displayName: "LINE",
    allowlistIdNoun: "ids",
  },
};

/** Opaque/structural Telegram keys the sanitize tree-walk passes through unwrapped
 *  (R8(b): per-source skipFields REPLACES the global SKIP_FIELDS, so this MUST list every
 *  non-content key it wants skipped — the global `id` entry does NOT apply here).
 *  `chat_id` = the outbound telegram_send_message constructed response's own id string;
 *  `type` = a controlled chat-type enum (private/group/supergroup/channel). NO numeric-id
 *  entries (update_id/message_id/date are NUMBERS → sanitize passes them through → a skip
 *  entry would be inert, the v1.68 NIT-1 lesson); INBOUND user text stays OUT → it wraps. */
const TELEGRAM_SKIP_FIELDS: ReadonlySet<string> = new Set(["chat_id", "type"]);

/** Telegram Bot — the SECOND class-B pack (step-2 migration). */
export const TELEGRAM_PACK: ServiceTokenPack = {
  id: "telegram",
  storeKey: "telegram",
  errorName: "telegram_api_failed",
  skipFields: TELEGRAM_SKIP_FIELDS,
  env: {
    recipientAllow: ENV_TELEGRAM_RECIPIENT_ALLOW,
    recipientAllowExtra: ENV_TELEGRAM_RECIPIENT_ALLOW_EXTRA,
    token: ENV_TELEGRAM_BOT_TOKEN,
  },
  recipientIdSpec: {
    // Two LOCKED-accepted shapes (docs §0 Q2): a numeric chat id (optional leading `-`
    // then 1–20 digits) OR a public `@username` (`@` + a leading letter + 4–31 of
    // [A-Za-z0-9_]). Each alternative is anchored + restricted → CR/LF/NUL/whitespace/
    // `+`/decimals are implicitly rejected (the gmail/LINE recipient-gate invariant).
    regex: /^(?:-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$/,
    label: "Telegram chat_id/@username",
  },
  cli: {
    commandName: "telegram",
    tokenLabel: "Telegram bot token",
    tokenKind: "bot token",
    displayName: "Telegram",
    allowlistIdNoun: "chat ids",
  },
};

/** Opaque Discord snowflakes that must NOT be confusable-normalized by sanitize. `channel_id`
 *  is the only id in today's constructed success response; a future message/author `id` is
 *  already in the global SKIP_FIELDS, so this set stays minimal + honest (the v1.68 NIT-1
 *  lesson — no speculative future fields). Revisit when an inbound/read Discord tool ships. */
const DISCORD_SKIP_FIELDS: ReadonlySet<string> = new Set(["channel_id"]);

/** Discord Bot — the THIRD class-B pack (step-2 migration). */
export const DISCORD_PACK: ServiceTokenPack = {
  id: "discord",
  storeKey: "discord",
  errorName: "discord_api_failed",
  skipFields: DISCORD_SKIP_FIELDS,
  env: {
    recipientAllow: ENV_DISCORD_RECIPIENT_ALLOW,
    recipientAllowExtra: ENV_DISCORD_RECIPIENT_ALLOW_EXTRA,
    token: ENV_DISCORD_BOT_TOKEN,
  },
  recipientIdSpec: {
    // A numeric snowflake (64-bit; currently 18–19 digits, 20-digit max) → 17–20 digits
    // covers the range with margin. Anchored + digit-only implicitly rejects CR/LF/NUL/
    // `@name`/path/whitespace/sign; since the id is also a URL path segment in the handler,
    // digit-only forecloses any traversal.
    regex: /^\d{17,20}$/,
    label: "Discord channel_id snowflake",
  },
  cli: {
    commandName: "discord",
    tokenLabel: "Discord bot token",
    tokenKind: "bot token",
    displayName: "Discord",
    allowlistIdNoun: "channel ids",
  },
};

/** Opaque Slack ids/timestamps/cursors that must NOT be wrapped/normalized by sanitize.
 *  Per-source skipFields REPLACES the global SKIP_FIELDS, so this MUST list every opaque/
 *  structural key the shapers emit — and ONLY those: everything attacker-influenceable
 *  (channel `name`, message `text`, `topic`/`purpose`, `real_name`/`display_name`, the PII
 *  `email`) stays OUT → it WRAPS. `ts`/`thread_ts` LOOK numeric but are opaque cursor/refs;
 *  `tz` (v1.104) is a controlled IANA zone name emitted raw. */
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

/** Slack Bot — the FOURTH class-B pack (step-2 migration). */
export const SLACK_PACK: ServiceTokenPack = {
  id: "slack",
  storeKey: "slack",
  errorName: "slack_api_failed",
  skipFields: SLACK_SKIP_FIELDS,
  env: {
    recipientAllow: ENV_SLACK_RECIPIENT_ALLOW,
    recipientAllowExtra: ENV_SLACK_RECIPIENT_ALLOW_EXTRA,
    token: ENV_SLACK_BOT_TOKEN,
  },
  recipientIdSpec: {
    // A conversation target: channel `C…`, private group `G…`, DM `D…`, or a user `U…`/`W…`
    // (a user id addresses a DM). Uppercase base-34-ish [A-Z0-9], typically 9–11 chars;
    // `{6,20}` covers the range with margin while staying bounded. Anchored + fixed-alphabet
    // implicitly rejects CR/LF/NUL/`#name`/`@name`/whitespace; the id rides the request BODY
    // (not a URL path segment) so the bound is hygiene, not a path guard.
    regex: /^[CDGUW][A-Z0-9]{6,20}$/,
    label: "Slack conversation id",
  },
  cli: {
    commandName: "slack",
    tokenLabel: "Slack bot token",
    tokenKind: "bot token",
    displayName: "Slack",
    allowlistIdNoun: "conversation ids",
  },
};

/** Opaque Mattermost keys the sanitize tree-walk passes through unwrapped. REPLACES the
 *  global SKIP_FIELDS, so it MUST list every opaque/structural key the shapers emit — and
 *  ONLY those: attacker-influenced text (team/channel `name`/`display_name`/`header`/
 *  `purpose`, post `message`) stays OUT → it WRAPS. `type` = a controlled enum (channel
 *  "O"/"P"/"D"/"G", post ""/"system_*"); `next_post_id`/`prev_post_id` = pagination cursors
 *  (MUST skip so the agent can page). Numeric epochs (`create_at`) are NUMBERS → no entry. */
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

/** Mattermost — the FIFTH class-B pack, and the FIRST self-hosted connector (step-2
 *  migration). Its server URL is per-deployment config (SAFESPACE_MATTERMOST_SERVER_URL),
 *  resolved by the client/handlers — NOT a pack concern; the CLI surfaces its state via the
 *  makeServiceTokenCommands `extraStatusLines` runtime seam. The USAGE trailer note is the
 *  only static CLI delta, carried on `cli.usageNote`. */
export const MATTERMOST_PACK: ServiceTokenPack = {
  id: "mattermost",
  storeKey: "mattermost",
  errorName: "mattermost_api_failed",
  skipFields: MATTERMOST_SKIP_FIELDS,
  env: {
    recipientAllow: ENV_MATTERMOST_RECIPIENT_ALLOW,
    recipientAllowExtra: ENV_MATTERMOST_RECIPIENT_ALLOW_EXTRA,
    token: ENV_MATTERMOST_BOT_TOKEN,
  },
  recipientIdSpec: {
    // A Mattermost id (channel/team/user/post) — exactly 26 lowercase base-32-ish [a-z0-9].
    // Anchored + fixed-alphabet implicitly rejects CR/LF/NUL/`/`/`.`/`:`/whitespace, so even
    // where the id rides a URL PATH segment (e.g. GET /channels/{id}/posts) there is no
    // traversal / host-escape surface.
    regex: /^[a-z0-9]{26}$/,
    label: "Mattermost channel/team/user/post id",
  },
  cli: {
    commandName: "mattermost",
    tokenLabel: "Mattermost bot token",
    tokenKind: "bot token",
    displayName: "Mattermost",
    allowlistIdNoun: "channel ids",
    usageNote: "(the server URL is set via the SAFESPACE_MATTERMOST_SERVER_URL env var, not this CLI)",
  },
};

/** Every class-B service-token pack, in the LOCKED order the egress-posture rows enumerate
 *  them (line, telegram, discord, slack, mattermost). A NEW service-token connector MUST add
 *  its pack here — the completeness sentinel test asserts this list covers exactly the
 *  `ServiceName` set, so an unregistered 6th connector fails CI. */
export const SERVICE_TOKEN_PACKS: readonly ServiceTokenPack[] = [
  LINE_PACK,
  TELEGRAM_PACK,
  DISCORD_PACK,
  SLACK_PACK,
  MATTERMOST_PACK,
];
