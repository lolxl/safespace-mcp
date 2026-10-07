// v1.107 — Mattermost handler tests (4 tools) + the client/egress behavior via a fetch stub.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { serviceTokenCred, recorderSink } from "./test-audit";
import {
  mattermostSendMessage,
  mattermostListTeams,
  mattermostListChannels,
  mattermostReadMessages,
} from "./handlers";
import { MCPError } from "../errors";
import type { ToolContext } from "./types";
import { ENV_MATTERMOST_SERVER_URL } from "../config";
import { __resetMattermostServerForTests } from "../auth/mattermost/base-url";
import { ENV_AUTONOMOUS } from "../policy/autonomous-mode";
import { ENV_MM_ALLOW } from "../policy/mattermost-recipient-allowlist";

const HOST = "https://mm.example.com";
const CHAN = "abcdefghijklmnopqrstuvwxyz"; // 26-char id
const TEAM = "0123456789abcdefghijklmnop";

const ENV_KEYS = [ENV_MATTERMOST_SERVER_URL, ENV_AUTONOMOUS, ENV_MM_ALLOW] as const;
let saved: Record<string, string | undefined>;

function ctx(tier: "read" | "write" | "share" = "share"): ToolContext {
  return {
    credential: serviceTokenCred(() => "bot-tok"),
    tier,
    audit: recorderSink({}),
  };
}

/** A fetch stub that captures the request + returns a canned Response. */
function stub(status: number, body: unknown): { fetchImpl: typeof fetch; calls: { url: string; init?: RequestInit }[] } {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env[ENV_MATTERMOST_SERVER_URL] = HOST;
  __resetMattermostServerForTests();
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  __resetMattermostServerForTests();
});

describe("mattermost_send_message", () => {
  test("bad channel_id rejected pre-flight (echoes RULE), no fetch", async () => {
    const s = stub(201, undefined);
    await expect(
      mattermostSendMessage(ctx(), { channel_id: "../x", message: "hi" }, s),
    ).rejects.toThrow(/channel_id.*26-char/);
    expect(s.calls.length).toBe(0);
  });

  test("empty + oversize message rejected", async () => {
    const s = stub(201, undefined);
    await expect(mattermostSendMessage(ctx(), { channel_id: CHAN, message: "" }, s)).rejects.toThrow(/non-empty/);
    await expect(
      mattermostSendMessage(ctx(), { channel_id: CHAN, message: "x".repeat(16384) }, s),
    ).rejects.toThrow(/exceeds/);
  });

  test("happy path → POST /api/v4/posts {channel_id, message} on the configured host", async () => {
    const s = stub(201, { id: "p", message: "ok" });
    const out = await mattermostSendMessage(ctx(), { channel_id: CHAN, message: "hello" }, s);
    expect(out).toEqual({ channel_id: CHAN, sent: true, message_type: "text" });
    const call = s.calls[0]!;
    expect(call.url).toBe(`${HOST}/api/v4/posts`);
    expect(JSON.parse(String(call.init!.body))).toEqual({ channel_id: CHAN, message: "hello" });
    expect((call.init!.headers as Record<string, string>).Authorization).toBe("Bearer bot-tok");
  });

  // B6.1 wave A1 — the two egress-gate cases (autonomous secret-shape F3a +
  // autonomous off→deny allowlist) MOVED to tools/egress-pipeline.test.ts (same
  // assertions, driven through the pipeline's egress descriptor): the gate is now
  // PIPELINE-FIRED (withNonOAuthContext runs extract → gate BEFORE the handler),
  // so the handler no longer calls it.

  test("server URL unset → mattermost_api_failed{no_server_url}", async () => {
    delete process.env[ENV_MATTERMOST_SERVER_URL];
    __resetMattermostServerForTests();
    const s = stub(201, undefined);
    let caught: unknown;
    try {
      await mattermostSendMessage(ctx(), { channel_id: CHAN, message: "hi" }, s);
    } catch (e) {
      caught = e;
    }
    expect((caught as MCPError).errorName).toBe("mattermost_api_failed");
    expect((caught as MCPError).errorData).toMatchObject({ reason: "no_server_url" });
  });

  test("400 from server → invalid_recipient (no body echo)", async () => {
    const s = stub(400, { message: "channel not found", status_code: 400 });
    await expect(
      mattermostSendMessage(ctx(), { channel_id: CHAN, message: "hi" }, s),
    ).rejects.toMatchObject({ errorName: "mattermost_api_failed", errorData: { reason: "invalid_recipient" } });
  });
});

describe("mattermost reads (curated, host-pinned)", () => {
  test("list_teams → GET users/me/teams, curated {id,name,display_name}", async () => {
    const s = stub(200, [{ id: TEAM, name: "eng", display_name: "Engineering", extra: "DROP" }]);
    const out = (await mattermostListTeams(ctx("read"), {}, s)) as { teams: Record<string, unknown>[] };
    expect(s.calls[0]!.url).toBe(`${HOST}/api/v4/users/me/teams`);
    expect(out.teams).toEqual([{ id: TEAM, name: "eng", display_name: "Engineering" }]);
  });

  test("list_channels validates team_id + GET .../teams/{id}/channels", async () => {
    const bad = stub(200, []);
    await expect(mattermostListChannels(ctx("read"), { team_id: "bad" }, bad)).rejects.toThrow(/team_id/);
    expect(bad.calls.length).toBe(0);
    const s = stub(200, [{ id: CHAN, type: "O", name: "town", display_name: "Town", header: "h", purpose: "p" }]);
    const out = (await mattermostListChannels(ctx("read"), { team_id: TEAM }, s)) as { channels: Record<string, unknown>[] };
    expect(s.calls[0]!.url).toBe(`${HOST}/api/v4/users/me/teams/${TEAM}/channels`);
    expect(out.channels[0]!.id).toBe(CHAN);
  });

  test("read_messages reassembles order→posts, curates message, surfaces cursors", async () => {
    const s = stub(200, {
      order: ["p2", "p1"],
      posts: {
        p1: { id: "p1", channel_id: CHAN, user_id: "u1", message: "first", create_at: 100, type: "" },
        p2: { id: "p2", channel_id: CHAN, user_id: "u2", message: "second", create_at: 200, type: "" },
      },
      next_post_id: "pN",
      prev_post_id: "",
    });
    const out = (await mattermostReadMessages(ctx("read"), { channel_id: CHAN }, s)) as {
      channel_id: string;
      posts: Record<string, unknown>[];
      next_post_id: string;
    };
    expect(s.calls[0]!.url).toContain(`${HOST}/api/v4/channels/${CHAN}/posts`);
    expect(out.posts.map((p) => p.message)).toEqual(["second", "first"]); // order-sorted
    expect(out.next_post_id).toBe("pN");
  });

  test("read_messages rejects a bad channel_id", async () => {
    const s = stub(200, {});
    await expect(mattermostReadMessages(ctx("read"), { channel_id: "bad" }, s)).rejects.toThrow(/channel_id/);
  });

  test("401 → auth_failed (status-mapped, no body echo)", async () => {
    const s = stub(401, { message: "invalid token" });
    await expect(mattermostListTeams(ctx("read"), {}, s)).rejects.toMatchObject({
      errorName: "mattermost_api_failed",
      errorData: { reason: "auth_failed" },
    });
  });
});
