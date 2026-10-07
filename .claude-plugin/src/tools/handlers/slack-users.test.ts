// v1.104 — Slack users.* READ handlers (slack_users_list + slack_user_info). The PII posture
// is the design center: users.list returns NO email (privacy-by-default — no bulk-email
// export of a whole workspace); users.info returns a single user's email (wrapped at the
// choke point). Opaque ids + controlled bools/tz are in SLACK_SKIP_FIELDS; names + email stay
// OUT → they WRAP. The shared slackApiGet client (Bearer, host-pin, byte-cap, 200-ok:false →
// closed-set reason) is exercised by slack-read.test.ts; here we assert the users-specific
// shaping, the email asymmetry, and the user-id validation. The Web API is mocked (no network).

import { describe, expect, test } from "bun:test";
import { NOOP_AUDIT, oauthCred, serviceTokenCred } from "../test-audit";
import type { ToolContext } from "../types";
import { slackUserInfo, slackUsersList } from "./slack";

const USER = "U0123456789";

function ctx(token = "bot-tok"): ToolContext {
  return { credential: serviceTokenCred(() => token), tier: "read", audit: NOOP_AUDIT };
}

/** A fetch stub returning `body` (JSON) with `status`; records url + init. */
function fetchStub(body: unknown, status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const MEMBER = {
  id: "U0000000001",
  name: "ada",
  real_name: "Ada Lovelace",
  deleted: false,
  is_admin: true,
  is_bot: false,
  tz: "Europe/London",
  updated: 1700000000,
  profile: {
    real_name: "Ada Lovelace",
    display_name: "ada",
    email: "ada@example.com", // ⚠️ MUST NOT surface in users.list (bulk-email-export defense)
    phone: "+44 20 7946 0000", // never shaped
    title: "Countess",
  },
  team_id: "T1",
};

const LIST_BODY = {
  ok: true,
  members: [MEMBER, { id: "U0000000002", name: "helperbot", is_bot: true, profile: { email: "bot@example.com" } }],
  response_metadata: { next_cursor: "dXNlcjpVMDA=" },
};

const INFO_BODY = { ok: true, user: MEMBER };

describe("slackUsersList", () => {
  test("GETs users.list with the Bearer header + a curated shape that OMITS email", async () => {
    const f = fetchStub(LIST_BODY);
    const out = (await slackUsersList(ctx("secret-tok"), { limit: 25 }, { fetchImpl: f.impl })) as {
      users: Array<Record<string, unknown>>;
      next_cursor: string | null;
    };
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toContain("https://slack.com/api/users.list");
    expect(url).toContain("limit=25");
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer secret-tok");
    // Curated shape: opaque id + names + controlled bools/tz; NO email / phone / title.
    expect(out.users[0]).toEqual({
      id: "U0000000001",
      name: "ada",
      real_name: "Ada Lovelace",
      display_name: "ada",
      is_bot: false,
      is_admin: true,
      deleted: false,
      tz: "Europe/London",
    });
    // PRIVACY-BY-DEFAULT: not a single email anywhere in a bulk listing.
    expect(out.users[0]).not.toHaveProperty("email");
    expect(JSON.stringify(out)).not.toContain("ada@example.com");
    expect(JSON.stringify(out)).not.toContain("bot@example.com");
    expect(JSON.stringify(out)).not.toContain("+44 20 7946 0000"); // phone never shaped either
    expect(out.next_cursor).toBe("dXNlcjpVMDA=");
  });

  test("limit is clamped to ≤200; absent / out-of-range defaults to 50", async () => {
    const f = fetchStub(LIST_BODY);
    await slackUsersList(ctx(), { limit: 9999 }, { fetchImpl: f.impl });
    expect(f.calls[0]!.url).toContain("limit=200");
    const f2 = fetchStub(LIST_BODY);
    await slackUsersList(ctx(), {}, { fetchImpl: f2.impl });
    expect(f2.calls[0]!.url).toContain("limit=50");
  });

  test("passes an opaque cursor through; rejects an over-long cursor before any fetch", async () => {
    const f = fetchStub(LIST_BODY);
    await slackUsersList(ctx(), { cursor: "abc" }, { fetchImpl: f.impl });
    expect(f.calls[0]!.url).toContain("cursor=abc");
    const f2 = fetchStub(LIST_BODY);
    await expect(slackUsersList(ctx(), { cursor: "x".repeat(2000) }, { fetchImpl: f2.impl })).rejects.toThrow(/cursor/);
    expect(f2.calls).toHaveLength(0);
  });
});

describe("slackUserInfo", () => {
  test("GETs users.info for a user id + a curated shape that INCLUDES email", async () => {
    const f = fetchStub(INFO_BODY);
    const out = (await slackUserInfo(ctx(), { user: USER }, { fetchImpl: f.impl })) as Record<string, unknown>;
    const { url } = f.calls[0]!;
    expect(url).toContain("https://slack.com/api/users.info");
    expect(url).toContain(`user=${USER}`);
    expect(out).toEqual({
      id: "U0000000001",
      name: "ada",
      real_name: "Ada Lovelace",
      display_name: "ada",
      is_bot: false,
      is_admin: true,
      deleted: false,
      tz: "Europe/London",
      email: "ada@example.com", // raw here; the choke point WRAPS it (email NOT in skipFields)
    });
  });

  test("rejects a malformed / non-user id (channel id, #name, lowercase) before any fetch", async () => {
    for (const bad of ["#general", "C0123456789", "notanid", ""]) {
      const f = fetchStub(INFO_BODY);
      await expect(slackUserInfo(ctx(), { user: bad }, { fetchImpl: f.impl })).rejects.toThrow(/'user'/);
      expect(f.calls).toHaveLength(0);
    }
  });

  test("a missing user arg is rejected before any fetch", async () => {
    const f = fetchStub(INFO_BODY);
    await expect(slackUserInfo(ctx(), {}, { fetchImpl: f.impl })).rejects.toThrow(/'user'/);
    expect(f.calls).toHaveLength(0);
  });

  test("user_not_found maps through the shared client → not_found", async () => {
    const f = fetchStub({ ok: false, error: "user_not_found" }, 200);
    await expect(slackUserInfo(ctx(), { user: USER }, { fetchImpl: f.impl })).rejects.toMatchObject({
      errorName: "slack_api_failed",
      errorData: { reason: "not_found" },
    });
  });

  test("an OAuth credential is refused (R6 service-token narrow)", async () => {
    const oauthCtx: ToolContext = { credential: oauthCred(), tier: "read", audit: NOOP_AUDIT };
    const f = fetchStub(INFO_BODY);
    await expect(slackUserInfo(oauthCtx, { user: USER }, { fetchImpl: f.impl })).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "credential_mismatch" } });
    expect(f.calls).toHaveLength(0);
  });
});
