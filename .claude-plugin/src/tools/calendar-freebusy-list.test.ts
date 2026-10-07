// v1.45 (backlog A5) — Calendar free/busy + calendar list
// (calendar_query_freebusy / calendar_list_calendars). Tested through the
// SDK-level `setGaxiosHandler` seam, same as the other Calendar READ handlers.
// Both are READ tools on NEW minimum-privilege scopes (no allowlist / env setup).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { currentTier } from "../tier";
import { calendarListCalendars, calendarQueryFreebusy } from "./handlers";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const FAKE_CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
  audit: NOOP_AUDIT,
  get tier() {
    return currentTier();
  },
};

interface CapturedOpts {
  url?: string;
  method?: string;
  data?: unknown;
  params?: Record<string, unknown>;
}

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("calendarQueryFreebusy (READ tool, calendar.freebusy)", () => {
  test("happy — POSTs freebusy.query with items=[{id}] + caller time window", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return {
        data: {
          kind: "calendar#freeBusy",
          timeMin: "2026-06-01T00:00:00Z",
          timeMax: "2026-06-02T00:00:00Z",
          calendars: { "alice@example.com": { busy: [{ start: "2026-06-01T09:00:00Z", end: "2026-06-01T10:00:00Z" }] } },
        },
        status: 200,
      };
    });
    const r = (await calendarQueryFreebusy(FAKE_CTX, {
      calendar_ids: ["primary", "bob@example.com"],
      time_min: "2026-06-01T00:00:00Z",
      time_max: "2026-06-02T00:00:00Z",
    })) as { calendars: Record<string, unknown> };
    expect(r.calendars).toBeDefined();
    expect(opts?.url).toContain("/calendar/v3/freeBusy");
    const body = opts?.data as { timeMin?: string; timeMax?: string; items?: Array<{ id: string }> };
    expect(body?.timeMin).toBe("2026-06-01T00:00:00Z");
    expect(body?.timeMax).toBe("2026-06-02T00:00:00Z");
    expect(body?.items).toEqual([{ id: "primary" }, { id: "bob@example.com" }]);
  });

  test("defaults — omitted time window resolves to now / now+7d (RFC 3339)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { calendars: {} }, status: 200 };
    });
    await calendarQueryFreebusy(FAKE_CTX, { calendar_ids: ["primary"] });
    const body = opts?.data as { timeMin?: string; timeMax?: string };
    // Both default to ISO strings; max is exactly 7 days after min.
    expect(typeof body?.timeMin).toBe("string");
    expect(Date.parse(body!.timeMax!) - Date.parse(body!.timeMin!)).toBe(7 * 24 * 60 * 60 * 1000);
  });

  test("empty calendar_ids → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(calendarQueryFreebusy(FAKE_CTX, { calendar_ids: [] })).rejects.toThrow(
      /non-empty 'calendar_ids'/,
    );
    expect(called).toBe(false);
  });

  test("over-50 calendar_ids → reject (blast-radius cap), no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    const ids = Array.from({ length: 51 }, (_, i) => `c${i}@example.com`);
    await expect(calendarQueryFreebusy(FAKE_CTX, { calendar_ids: ids })).rejects.toThrow(
      /50-calendar cap/,
    );
    expect(called).toBe(false);
  });

  test("invalid calendar id → reject echoing the RULE not the value; no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    const badValue = "not a calendar\r\nid";
    const p = calendarQueryFreebusy(FAKE_CTX, { calendar_ids: ["primary", badValue] });
    await expect(p).rejects.toThrow(/must be 'primary' OR an email-shaped value/);
    // The thrown message must NOT echo the attacker-controlled value.
    await p.catch((e: Error) => expect(e.message).not.toContain(badValue));
    expect(called).toBe(false);
  });

  test("non-string entry in calendar_ids → reject, no HTTP", async () => {
    await expect(
      calendarQueryFreebusy(FAKE_CTX, { calendar_ids: ["primary", 42] }),
    ).rejects.toThrow(/must be 'primary' OR an email-shaped value/);
  });
});

describe("calendarListCalendars (READ tool, calendar.calendarlist.readonly)", () => {
  test("happy — GET calendarList with default maxResults=100; returns items verbatim", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return {
        data: {
          kind: "calendar#calendarList",
          items: [
            { id: "alice@example.com", summary: "Personal", accessRole: "owner", primary: true },
            { id: "team@group.calendar.google.com", summary: "Team Shared", accessRole: "reader" },
          ],
        },
        status: 200,
      };
    });
    const r = (await calendarListCalendars(FAKE_CTX, {})) as { items: unknown[] };
    expect(r.items).toHaveLength(2);
    expect(opts?.url).toContain("/calendar/v3/users/me/calendarList");
    expect(opts?.params?.maxResults).toBe(100);
  });

  test("max_results clamps to the 250 handler cap (defense-in-depth vs non-conforming client)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { items: [] }, status: 200 };
    });
    await calendarListCalendars(FAKE_CTX, { max_results: 9999 });
    expect(opts?.params?.maxResults).toBe(250);
  });

  test("max_results honored when within range", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { items: [] }, status: 200 };
    });
    await calendarListCalendars(FAKE_CTX, { max_results: 10 });
    expect(opts?.params?.maxResults).toBe(10);
  });
});
