// v1.64 Phase B (B6 — D1/D5) — the Source descriptor seam.

import { describe, expect, test } from "bun:test";
import { MCPError } from "../errors";
import { toGoogleError } from "../google-api/errors";
import { SKIP_FIELDS } from "../sanitize/patterns";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./registry";
import { discord, github, googleWorkspace, line, notion, slack, sourceFor, telegram, webFetch, x } from "./source";
import type { NonOAuthSource, OAuthResolveDeps, OAuthSource } from "./source";

describe("Source descriptor — googleWorkspace (v1.64 B6)", () => {
  test("id is 'google-workspace'", () => {
    expect(googleWorkspace.id).toBe("google-workspace");
  });

  test("authModel is 'oauth' (v1.65 — routes through withToolContext)", () => {
    expect(googleWorkspace.authModel).toBe("oauth");
  });

  test("skipFields IS the global SKIP_FIELDS (=== — the B5 byte-identical guarantee)", () => {
    // Identity, not equality: with-context.ts / with-all-accounts.ts pass
    // `source.skipFields` to sanitize(); it MUST be the very same Set the module
    // global drives, or the google-workspace sanitize tree-walk would diverge.
    expect(googleWorkspace.skipFields).toBe(SKIP_FIELDS);
  });

  test("mapError IS toGoogleError (the B4 returning catch boundary)", () => {
    expect(googleWorkspace.mapError).toBe(toGoogleError);
  });

  test("mapError passes an MCPError through unchanged (identity — a handler's own validation reject)", () => {
    const e = new MCPError("rate_limited", { tool: "drive_get_file_content" });
    expect(googleWorkspace.mapError(e, { tool: "drive_get_file_content" })).toBe(e);
  });

  test("mapError maps a 404 Gaxios error to an UpstreamError carrying httpStatus", () => {
    const gaxios = { response: { status: 404, data: { error: { message: "Not Found" } } } };
    const mapped = googleWorkspace.mapError(gaxios, {
      tool: "drive_get_file_content",
    }) as Error & { httpStatus?: number };
    expect(mapped).toBeInstanceOf(Error);
    expect(mapped).not.toBeInstanceOf(MCPError);
    expect(mapped.httpStatus).toBe(404);
  });
});

describe("Source descriptor — webFetch (v1.65 Phase C — the first keyless connector)", () => {
  test("id is 'web-fetch' and authModel is 'none' (routes through withKeylessContext)", () => {
    expect(webFetch.id).toBe("web-fetch");
    expect(webFetch.authModel).toBe("none");
  });

  test("skipFields is EMPTY — a remote page is all untrusted, so every field wraps", () => {
    expect(webFetch.skipFields.size).toBe(0);
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as web_fetch_failed", () => {
    const e = new MCPError("url_blocked_by_policy", { reason: "scheme_not_allowed" });
    expect(webFetch.mapError(e, { tool: "web_fetch" })).toBe(e);
    const wrapped = webFetch.mapError(new Error("boom"), { tool: "web_fetch" });
    expect(wrapped).toBeInstanceOf(MCPError);
    expect((wrapped as MCPError).errorName).toBe("web_fetch_failed");
  });
});

describe("Source descriptor — sourceFor (v1.64 B6)", () => {
  test("undefined toolDef → google-workspace (the default connector)", () => {
    expect(sourceFor(undefined)).toBe(googleWorkspace);
  });

  test("source:'web-fetch' → the webFetch connector (v1.65)", () => {
    expect(sourceFor({ source: "web-fetch" })).toBe(webFetch);
  });

  test("toolDef without a `source` field → google-workspace (every current tool)", () => {
    expect(sourceFor({ source: undefined })).toBe(googleWorkspace);
  });

  test("explicit source:'google-workspace' → googleWorkspace", () => {
    expect(sourceFor({ source: "google-workspace" })).toBe(googleWorkspace);
  });

  test("unknown source id → throws internal_routing_error{unknown_source} (fail-closed; never echoes the bogus id)", () => {
    // v1.112.8 flipped the silent google-workspace fallback: a typo'd `source`
    // must NOT route onto Google OAuth. Closed reason only — no source string echo.
    try {
      sourceFor({ source: "telegram-bot-not-wired-yet" });
      expect.unreachable("sourceFor must throw on unknown source");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      const m = e as MCPError;
      expect(m.errorName).toBe("internal_routing_error");
      expect(m.code).toBe(-32055);
      expect(m.errorData).toEqual({ reason: "unknown_source" });
      // No echo of the bogus source string anywhere on the rendered surface.
      const j = m.toJsonRpc();
      expect(JSON.stringify(j)).not.toContain("telegram-bot-not-wired-yet");
    }
  });

  // v1.112.8 behavioral sentinel — load-time-equivalent guarantee that no
  // TOOL_REGISTRY entry carries a typo'd `source` (sourceFor would throw).
  test("every TOOL_REGISTRY entry resolves via sourceFor without throwing", () => {
    for (const name of Object.keys(TOOL_REGISTRY)) {
      expect(() => sourceFor(TOOL_REGISTRY[name]), `sourceFor(${name})`).not.toThrow();
    }
  });
});

describe("dispatch routing — the proxy's authModel branch (v1.65 / v1.66 Phase C)", () => {
  // The proxy reads `sourceFor(def).authModel` once to pick the choke point:
  // "oauth" → withToolContext, anything else (none / service-token) →
  // withNonOAuthContext. This pins which tools are non-OAuth — a future tool can't
  // silently inherit the non-OAuth path (which skips OAuth/scope/refresh) by a
  // stray `source` label.
  test("web_fetch + fs_read are keyless, line/telegram/discord are service-token; google/github/notion (+ the rest) are oauth", () => {
    // v1.102 (W0) — inbox_read is keyless (source:"webhook", authModel "none"): it reads
    // a local store the listener populated; the signing secret is listener infra, not a
    // tool credential.
    const keyless = new Set(["web_fetch", "fs_read", "inbox_read"]);
    // v1.78 — Notion moved from service-token (v1.77 A) to OAuth (the 3rd OAuth source),
    // so its 5 tools are now in the `oauth` (default) bucket below.
    const serviceToken = new Set([
      "line_push_message",
      "telegram_send_message",
      // v1.98 — Telegram READ (the inbound poll-inbox).
      "telegram_get_updates",
      "discord_send_message",
      "slack_send_message",
      // v1.97 — the first service-token READS.
      "slack_list_channels",
      "slack_read_messages",
      // v1.104 — Slack users.* directory READS.
      "slack_users_list",
      "slack_user_info",
      // v1.107 — Mattermost (the fifth service-token connector, self-hosted).
      "mattermost_send_message",
      "mattermost_list_teams",
      "mattermost_list_channels",
      "mattermost_read_messages",
    ]);
    for (const name of IMPLEMENTED_TOOLS) {
      const model = sourceFor(TOOL_REGISTRY[name]).authModel;
      const expected =
        keyless.has(name) ? "none" : serviceToken.has(name) ? "service-token" : "oauth";
      expect(model, `authModel for ${name}`).toBe(expected);
    }
  });
});

describe("Source descriptor — line (v1.66 Phase C PR 2)", () => {
  test("id 'line', authModel 'service-token', skipFields carries the opaque LINE ids", () => {
    expect(line.id).toBe("line");
    expect(line.authModel).toBe("service-token");
    expect(line.skipFields.has("userId")).toBe(true);
    expect(line.skipFields.has("messageId")).toBe(true);
  });

  test("sourceFor('line') resolves the line connector", () => {
    expect(sourceFor({ source: "line" })).toBe(line);
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as line_api_failed", () => {
    const e = new MCPError("line_api_failed", { reason: "auth_failed" });
    expect(line.mapError(e, { tool: "line_push_message" })).toBe(e);
    const wrapped = line.mapError(new Error("boom"), { tool: "line_push_message" });
    expect((wrapped as MCPError).errorName).toBe("line_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (no scope; tier proxy-enforced; token presence in resolveCredential)", () => {
    expect(() => line.authorize(TOOL_REGISTRY["line_push_message"], {})).not.toThrow();
  });
});

describe("Source descriptor — telegram (v1.68)", () => {
  test("id 'telegram', authModel 'service-token', skipFields skips opaque/structural keys + WRAPS inbound content", () => {
    expect(telegram.id).toBe("telegram");
    expect(telegram.authModel).toBe("service-token");
    // opaque/structural keys SKIP (chat_id = outbound echo; type = controlled enum)
    expect(telegram.skipFields.has("chat_id")).toBe(true);
    expect(telegram.skipFields.has("type")).toBe(true);
    // numeric opaque ids need NO skip entry (sanitize passes numbers through untouched)
    for (const numericId of ["update_id", "message_id", "id", "date"]) {
      expect(telegram.skipFields.has(numericId), `${numericId} is numeric → no skip entry`).toBe(false);
    }
    // v1.98 inbound content keys must NOT be skipped → they WRAP as an untrusted source
    for (const content of ["text", "first_name", "last_name", "username", "title"]) {
      expect(telegram.skipFields.has(content), `${content} must wrap`).toBe(false);
    }
  });

  test("sourceFor('telegram') resolves the telegram connector", () => {
    expect(sourceFor({ source: "telegram" })).toBe(telegram);
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as telegram_api_failed", () => {
    const e = new MCPError("telegram_api_failed", { reason: "auth_failed" });
    expect(telegram.mapError(e, { tool: "telegram_send_message" })).toBe(e);
    const wrapped = telegram.mapError(new Error("boom"), { tool: "telegram_send_message" });
    expect((wrapped as MCPError).errorName).toBe("telegram_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (no scope; tier proxy-enforced; token presence in resolveCredential)", () => {
    expect(() => telegram.authorize(TOOL_REGISTRY["telegram_send_message"], {})).not.toThrow();
  });
});

describe("Source descriptor — discord (v1.69)", () => {
  test("id 'discord', authModel 'service-token', skipFields carries the opaque channel id", () => {
    expect(discord.id).toBe("discord");
    expect(discord.authModel).toBe("service-token");
    expect(discord.skipFields.has("channel_id")).toBe(true);
  });

  test("sourceFor('discord') resolves the discord connector", () => {
    expect(sourceFor({ source: "discord" })).toBe(discord);
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as discord_api_failed", () => {
    const e = new MCPError("discord_api_failed", { reason: "auth_failed" });
    expect(discord.mapError(e, { tool: "discord_send_message" })).toBe(e);
    const wrapped = discord.mapError(new Error("boom"), { tool: "discord_send_message" });
    expect((wrapped as MCPError).errorName).toBe("discord_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (no scope; tier proxy-enforced; token presence in resolveCredential)", () => {
    expect(() => discord.authorize(TOOL_REGISTRY["discord_send_message"], {})).not.toThrow();
  });
});

describe("Source descriptor — slack (v1.95)", () => {
  test("id 'slack', authModel 'service-token', skipFields skips opaque ids but NOT untrusted text", () => {
    expect(slack.id).toBe("slack");
    expect(slack.authModel).toBe("service-token");
    // v1.97 reads + v1.104 users.* — opaque ids/timestamps/cursors + the controlled `tz`
    // SKIP (the agent needs them raw)…
    for (const k of ["channel", "id", "ts", "thread_ts", "user", "team", "type", "subtype", "next_cursor", "tz"]) {
      expect(slack.skipFields.has(k), `skip ${k}`).toBe(true);
    }
    // …while attacker-influenceable text + the PII email stay OUT → they WRAP as untrusted.
    for (const k of ["name", "text", "topic", "purpose", "real_name", "display_name", "email"]) {
      expect(slack.skipFields.has(k), `wrap ${k}`).toBe(false);
    }
  });

  test("sourceFor('slack') resolves the slack connector", () => {
    expect(sourceFor({ source: "slack" })).toBe(slack);
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as slack_api_failed", () => {
    const e = new MCPError("slack_api_failed", { reason: "auth_failed" });
    expect(slack.mapError(e, { tool: "slack_send_message" })).toBe(e);
    const wrapped = slack.mapError(new Error("boom"), { tool: "slack_send_message" });
    expect((wrapped as MCPError).errorName).toBe("slack_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (no scope; tier proxy-enforced; token presence in resolveCredential)", () => {
    expect(() => slack.authorize(TOOL_REGISTRY["slack_send_message"], {})).not.toThrow();
  });
});

describe("Source descriptor — notion (v1.78 — the 3rd OAuth source)", () => {
  test("id 'notion', authModel 'oauth', refreshable FALSE (no Notion OAuth refresh token)", () => {
    expect(notion.id).toBe("notion");
    expect(notion.authModel).toBe("oauth");
    expect((notion as { refreshable?: boolean }).refreshable).toBe(false);
  });

  test("sourceFor('notion') resolves the notion connector", () => {
    expect(sourceFor({ source: "notion" })).toBe(notion);
  });

  test("implements resolveAccount + resolveCredential (it IS an OAuth source)", () => {
    expect(typeof (notion as { resolveAccount?: unknown }).resolveAccount).toBe("function");
    expect(typeof notion.resolveCredential).toBe("function");
  });

  test("skipFields skips ONLY opaque/structural keys (id/object/type/url/cursor/timestamps)", () => {
    for (const k of ["id", "object", "type", "parent_type", "url", "created_time", "last_edited_time", "next_cursor"]) {
      expect(notion.skipFields.has(k)).toBe(true);
    }
    // attacker-influenced content stays OUT of the set → it wraps:
    for (const k of ["title", "text", "name", "value", "plain_text"]) {
      expect(notion.skipFields.has(k)).toBe(false);
    }
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as notion_api_failed", () => {
    const e = new MCPError("notion_api_failed", { reason: "not_found" });
    expect(notion.mapError(e, { tool: "notion_get_page" })).toBe(e);
    const wrapped = notion.mapError(new Error("boom"), { tool: "notion_get_page" });
    expect((wrapped as MCPError).errorName).toBe("notion_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (no scope; tier proxy-enforced; token presence in resolveCredential)", () => {
    expect(() => notion.authorize(TOOL_REGISTRY["notion_get_page"], {})).not.toThrow();
  });
});

describe("Source descriptor — x (v1.113 — the 4th OAuth source; ZERO tools yet)", () => {
  test("id 'x', authModel 'oauth', refreshable FALSE (proactive refresh lives in resolveCredential, not the choke-point 401 path)", () => {
    expect(x.id).toBe("x");
    expect(x.authModel).toBe("oauth");
    expect((x as { refreshable?: boolean }).refreshable).toBe(false);
  });

  test("sourceFor('x') resolves the x connector", () => {
    expect(sourceFor({ source: "x" })).toBe(x);
  });

  test("implements resolveAccount + resolveCredential (it IS an OAuth source)", () => {
    expect(typeof (x as { resolveAccount?: unknown }).resolveAccount).toBe("function");
    expect(typeof x.resolveCredential).toBe("function");
  });

  test("skipFields skips ONLY opaque machine fields (ids/timestamps/cursors/counts)", () => {
    for (const k of ["id", "created_at", "edit_history_tweet_ids", "newest_id", "oldest_id", "next_token", "result_count"]) {
      expect(x.skipFields.has(k)).toBe(true);
    }
    // free-text / attacker-influenced content stays OUT of the set → it wraps when tools land:
    for (const k of ["name", "description", "text", "username"]) {
      expect(x.skipFields.has(k)).toBe(false);
    }
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as x_api_failed", () => {
    const e = new MCPError("x_api_failed", { reason: "consent_required" });
    expect(x.mapError(e, { tool: "x_placeholder" })).toBe(e);
    const wrapped = x.mapError(new Error("boom"), { tool: "x_placeholder" });
    expect((wrapped as MCPError).errorName).toBe("x_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("authorize is a no-op (fixed MVP scopes at consent; tier proxy-enforced)", () => {
    expect(() => x.authorize(undefined, {})).not.toThrow();
  });
});

describe("Source strategies — authorize / resolveCredential (v1.66 Phase C PR 2)", () => {
  const driveRead = TOOL_REGISTRY["drive_search"]; // requiredScopes: [drive.readonly]

  test("googleWorkspace.authorize throws scope_mismatch when the account lacks the scope", () => {
    expect(() =>
      googleWorkspace.authorize(driveRead, {
        account: { accountId: "a@x.com", scopes: ["https://www.googleapis.com/auth/gmail.readonly"] },
      }),
    ).toThrow(MCPError);
  });

  test("googleWorkspace.authorize passes when a satisfying (broader) scope is granted", () => {
    expect(() =>
      googleWorkspace.authorize(driveRead, {
        account: { accountId: "a@x.com", scopes: ["https://www.googleapis.com/auth/drive"] },
      }),
    ).not.toThrow();
  });

  test("googleWorkspace.authorize skips the check when scopes are unknown (older accounts.json)", () => {
    expect(() =>
      googleWorkspace.authorize(driveRead, { account: { accountId: "a@x.com" } }),
    ).not.toThrow();
  });

  test("googleWorkspace.resolveCredential backstop still throws on an `as any` bypass of the required accountId", async () => {
    // v1.72 — OAuthResolveDeps.accountId is now REQUIRED, so a typed caller cannot
    // omit it (the with-context.ts choke point always resolves it first). The
    // runtime throw is kept as a defense-in-depth backstop; force it with a cast.
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    await expect(
      googleWorkspace.resolveCredential(driveRead, {} as unknown as OAuthResolveDeps),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "invariant_violation" } });
  });

  test("webFetch.resolveCredential → {kind:'none'} (no deps); authorize no-op", async () => {
    expect(() => webFetch.authorize(undefined, {})).not.toThrow();
    expect(await webFetch.resolveCredential(undefined)).toEqual({ kind: "none" });
  });
});

describe("Source.resolveAccount + refreshable (v1.70 G1)", () => {
  const driveRead = TOOL_REGISTRY["drive_search"];
  const idx =
    (accounts: Array<{ email: string; scopes?: string[] }>) => async () => ({ accounts });

  test("refreshable lives on OAuthSource only: google true, github false; absent on every non-OAuth source", () => {
    // v1.72 — `refreshable` moved onto OAuthSource (read only by the with-context
    // 401-retry guard). The non-OAuth sources no longer carry it (type + runtime).
    expect(googleWorkspace.refreshable).toBe(true);
    expect(github.refreshable).toBe(false);
    expect("refreshable" in webFetch).toBe(false);
    expect("refreshable" in line).toBe(false);
    expect("refreshable" in telegram).toBe(false);
    expect("refreshable" in discord).toBe(false);
  });

  test("resolveAccount lives on OAuthSource only (google + github); absent on every non-OAuth source", () => {
    // v1.72 — both OAuth sources implement it (the provider-keyed account resolve);
    // the non-OAuth sources have no account, so the property is absent by type.
    expect(typeof googleWorkspace.resolveAccount).toBe("function");
    expect(typeof github.resolveAccount).toBe("function");
    expect("resolveAccount" in webFetch).toBe(false);
    expect("resolveAccount" in line).toBe(false);
    expect("resolveAccount" in telegram).toBe(false);
    expect("resolveAccount" in discord).toBe(false);
  });

  test("resolveAccount: explicit override wins → {accountId, scopes} from the index", async () => {
    const resolved = await googleWorkspace.resolveAccount(driveRead, {
      explicitAccountId: "carol@x.com",
      lastUsed: "stale@x.com",
      readActiveImpl: async () => "active@x.com",
      loadIndexImpl: idx([{ email: "carol@x.com", scopes: ["s1"] }]),
    });
    expect(resolved).toEqual({ accountId: "carol@x.com", scopes: ["s1"] });
  });

  test("resolveAccount: resolution order falls back active-file → per-source last-used", async () => {
    const viaActive = await googleWorkspace.resolveAccount(driveRead, {
      lastUsed: "stale@x.com",
      readActiveImpl: async () => "active@x.com",
      loadIndexImpl: idx([{ email: "active@x.com" }]),
    });
    expect(viaActive.accountId).toBe("active@x.com");
    const viaLastUsed = await googleWorkspace.resolveAccount(driveRead, {
      lastUsed: "last@x.com",
      readActiveImpl: async () => null,
      loadIndexImpl: idx([{ email: "last@x.com" }]),
    });
    expect(viaLastUsed.accountId).toBe("last@x.com");
  });

  test("resolveAccount: account_not_found when no tier resolves an id", async () => {
    await expect(
      googleWorkspace.resolveAccount(driveRead, {
        lastUsed: null,
        readActiveImpl: async () => null,
        loadIndexImpl: idx([]),
      }),
    ).rejects.toThrow(MCPError);
  });

  test("resolveAccount: account_not_found when the resolved id is absent from the index", async () => {
    await expect(
      googleWorkspace.resolveAccount(driveRead, {
        explicitAccountId: "ghost@x.com",
        lastUsed: null,
        loadIndexImpl: idx([{ email: "other@x.com" }]),
      }),
    ).rejects.toThrow(MCPError);
  });
});

describe("Source descriptor — github (v1.70 G2 — the 2nd OAuth source skeleton)", () => {
  test("id 'github', authModel 'oauth', refreshable FALSE (skips the google 401-refresh path)", () => {
    expect(github.id).toBe("github");
    expect(github.authModel).toBe("oauth");
    expect(github.refreshable).toBe(false);
  });

  test("sourceFor('github') resolves the github connector", () => {
    expect(sourceFor({ source: "github" })).toBe(github);
  });

  test("authorize is a no-op (scopes are requested wholesale at consent)", () => {
    expect(() => github.authorize(undefined, {})).not.toThrow();
  });

  test("mapError passes an MCPError through + wraps a non-MCPError as github_api_failed", () => {
    const e = new MCPError("github_api_failed", { reason: "not_found" });
    expect(github.mapError(e, { tool: "github_get_issue" })).toBe(e);
    const wrapped = github.mapError(new Error("boom"), { tool: "github_get_issue" });
    expect((wrapped as MCPError).errorName).toBe("github_api_failed");
    expect((wrapped as MCPError).errorData.reason).toBe("api_error");
  });

  test("skipFields carries opaque github ids but NOT attacker-influenced free text", () => {
    expect(github.skipFields.has("node_id")).toBe(true);
    expect(github.skipFields.has("html_url")).toBe(true);
    expect(github.skipFields.has("title")).toBe(false);
    expect(github.skipFields.has("body")).toBe(false);
  });

  test("v1.76 — `status` (the controlled file-change enum) skips; filename/patch wrap", () => {
    expect(github.skipFields.has("status")).toBe(true); // controlled enum, like `state`
    expect(github.skipFields.has("state")).toBe(true);
    // the read-deepening free-text fields stay OUT of the set → they wrap:
    expect(github.skipFields.has("filename")).toBe(false);
    expect(github.skipFields.has("patch")).toBe(false);
    expect(github.skipFields.has("message")).toBe(false);
    expect(github.skipFields.has("content")).toBe(false);
  });

  test("github implements resolveAccount + resolveCredential (it IS an OAuth source)", () => {
    expect(typeof github.resolveAccount).toBe("function");
    expect(typeof github.resolveCredential).toBe("function");
  });

  test("resolveCredential backstop still throws on an `as any` bypass of the required accountId", async () => {
    // v1.72 — OAuthResolveDeps.accountId REQUIRED; force the defense-in-depth
    // backstop with a cast (a typed caller cannot omit accountId).
    // v1.115.3 — stable MCPError (never a plain Error that leaks internal detail as -32603).
    await expect(
      github.resolveCredential(undefined, {} as unknown as OAuthResolveDeps),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "invariant_violation" } });
  });

  test("v1.72 — the Source union variant-shape pin: OAuth sources are OAuthSource, non-OAuth are NonOAuthSource", () => {
    // Compile-time assertions (the `satisfies` checks fail the build if a source
    // mis-declares its variant — e.g. a non-OAuth source sprouting `refreshable`,
    // or an OAuth source dropping `resolveAccount`). Paired with a trivial runtime
    // assert so the test body is non-empty.
    googleWorkspace satisfies OAuthSource;
    github satisfies OAuthSource;
    webFetch satisfies NonOAuthSource;
    line satisfies NonOAuthSource;
    telegram satisfies NonOAuthSource;
    discord satisfies NonOAuthSource;
    expect(googleWorkspace.authModel === "oauth" && github.authModel === "oauth").toBe(true);
  });
});
