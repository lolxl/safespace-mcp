// v1.59 — youtube_analytics_query tests. Through the SDK-level setGaxiosHandler
// seam. Pins: the own-channel-only invariant (ids ALWAYS channel==MINE), the
// metrics/dimensions allowlists, strict dates, the 3-key filters object, sort
// validation, and the max_results clamp.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { currentTier } from "../tier";
import { youtubeAnalyticsQuery } from "./handlers";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
  audit: NOOP_AUDIT,
  get tier() {
    return currentTier();
  },
};

interface CapturedOpts {
  url?: string;
  method?: string;
  params?: Record<string, unknown>;
}

let captured: CapturedOpts | undefined;

beforeEach(async () => {
  const { resetGaxiosHandler, setGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  captured = undefined;
  setGaxiosHandler(async (o) => {
    captured = o as CapturedOpts;
    return { data: { kind: "youtubeAnalytics#resultTable", rows: [[100]] }, status: 200 };
  });
});
afterEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

const OK = { metrics: "views", start_date: "2026-05-01", end_date: "2026-05-28" };

describe("youtube_analytics_query — happy path + own-channel invariant", () => {
  test("valid query → ids FORCED to channel==MINE + metrics/dates passed; returns data", async () => {
    const res = (await youtubeAnalyticsQuery(CTX, {
      metrics: "views,subscribersGained",
      start_date: "2026-05-01",
      end_date: "2026-05-28",
    })) as { rows: unknown };
    expect(res.rows).toEqual([[100]]);
    expect(captured?.params?.ids).toBe("channel==MINE");
    expect(captured?.params?.metrics).toBe("views,subscribersGained");
    expect(captured?.params?.startDate).toBe("2026-05-01");
    expect(captured?.params?.endDate).toBe("2026-05-28");
  });

  test("SECURITY: ids is ALWAYS channel==MINE — no arg can change it", async () => {
    // even if a caller smuggles an `ids` arg (rejected by schema, but prove the
    // handler ignores it), the SDK call uses channel==MINE.
    await youtubeAnalyticsQuery(CTX, { ...OK, ids: "channel==UCattacker" } as Record<string, unknown>);
    expect(captured?.params?.ids).toBe("channel==MINE");
  });
});

describe("youtube_analytics_query — metrics + dimensions allowlists", () => {
  test("unknown metric → reject (rule, not silent)", async () => {
    await expect(
      youtubeAnalyticsQuery(CTX, { ...OK, metrics: "views,estimatedRevenue" }),
    ).rejects.toThrow(/unsupported metrics|allowed:/);
    expect(captured).toBeUndefined(); // no SDK call
  });

  test("missing / empty metrics → reject", async () => {
    await expect(youtubeAnalyticsQuery(CTX, { start_date: "2026-05-01", end_date: "2026-05-28" })).rejects.toThrow(
      /requires a non-empty 'metrics'/,
    );
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, metrics: "  " })).rejects.toThrow(/metrics/);
  });

  test("valid dimensions passed; unknown dimension → reject", async () => {
    await youtubeAnalyticsQuery(CTX, { ...OK, dimensions: "day" });
    expect(captured?.params?.dimensions).toBe("day");
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, dimensions: "ipAddress" })).rejects.toThrow(/unsupported dimensions/);
    // a mixed valid+invalid list rejects (the loop walks all names, not just [0])
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, dimensions: "day,ipAddress" })).rejects.toThrow(/unsupported dimensions/);
  });
});

describe("youtube_analytics_query — dates / filters / sort / max_results", () => {
  test("bad date format → reject", async () => {
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, start_date: "2026/05/01" })).rejects.toThrow(/start_date.*YYYY-MM-DD/);
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, end_date: "last week" })).rejects.toThrow(/end_date.*YYYY-MM-DD/);
  });

  test("filters object built into the filter string; bad video id → reject; empty {} → no filters param", async () => {
    await youtubeAnalyticsQuery(CTX, { ...OK, filters: { video: "dQw4w9WgXcQ", country: "US" } });
    expect(captured?.params?.filters).toBe("video==dQw4w9WgXcQ;country==US");
    // empty filters object → the `filters` param is omitted entirely
    await youtubeAnalyticsQuery(CTX, { ...OK, filters: {} });
    expect(captured?.params?.filters).toBeUndefined();
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, filters: { video: "not-an-id" } })).rejects.toThrow(/filters.video/);
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, filters: { country: "usa" } })).rejects.toThrow(/filters.country/);
  });

  test("sort must reference a requested metric (± '-')", async () => {
    await youtubeAnalyticsQuery(CTX, { ...OK, metrics: "views", sort: "-views" });
    expect(captured?.params?.sort).toBe("-views");
    await expect(youtubeAnalyticsQuery(CTX, { ...OK, metrics: "views", sort: "likes" })).rejects.toThrow(
      /'sort' must be one of the requested metrics/,
    );
  });

  test("max_results clamped to [1,200] (over-cap → 200; below-min → default 200; valid passes)", async () => {
    await youtubeAnalyticsQuery(CTX, { ...OK, max_results: 9999 });
    expect(captured?.params?.maxResults).toBe(200);
    await youtubeAnalyticsQuery(CTX, { ...OK, max_results: 25 });
    expect(captured?.params?.maxResults).toBe(25);
    // Below-min (defense-in-depth; the schema's minimum:1 is the primary gate):
    // clampYoutubeMaxResults falls a < 1 value to its default (200), not to 1.
    await youtubeAnalyticsQuery(CTX, { ...OK, max_results: 0 });
    expect(captured?.params?.maxResults).toBe(200);
  });
});

// v1.61 — the monetary (revenue) opt-in. Default (flag unset / non-"true") =
// byte-identical to v1.59: revenue metrics rejected. Flag "true" unlocks them.
describe("youtube_analytics_query — monetary opt-in (v1.61)", () => {
  const ENV = "SAFESPACE_YOUTUBE_ANALYTICS_MONETARY";
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env[ENV];
    delete process.env[ENV]; // start each case from a known-OFF baseline
  });
  afterEach(() => {
    // Restore exactly — never leak the flag into other test files (v1.57 lesson).
    if (prev === undefined) delete process.env[ENV];
    else process.env[ENV] = prev;
  });

  test("flag UNSET (default) → revenue metric rejected with the rule, no SDK call", async () => {
    await expect(
      youtubeAnalyticsQuery(CTX, { ...OK, metrics: "estimatedRevenue" }),
    ).rejects.toThrow(/unsupported metrics|allowed/);
    expect(captured).toBeUndefined();
  });

  test("flag 'true' → revenue metrics accepted + passed to the SDK; ids still channel==MINE", async () => {
    process.env[ENV] = "true";
    await youtubeAnalyticsQuery(CTX, {
      ...OK,
      metrics: "estimatedRevenue,estimatedAdRevenue,cpm,monetizedPlaybacks",
    });
    expect(captured?.params?.metrics).toBe("estimatedRevenue,estimatedAdRevenue,cpm,monetizedPlaybacks");
    expect(captured?.params?.ids).toBe("channel==MINE"); // own-channel invariant untouched
  });

  test("flag 'true' → base (non-monetary) metrics still work; mixed base+revenue OK", async () => {
    process.env[ENV] = "true";
    await youtubeAnalyticsQuery(CTX, { ...OK, metrics: "views,estimatedRevenue,subscribersGained" });
    expect(captured?.params?.metrics).toBe("views,estimatedRevenue,subscribersGained");
  });

  test("STRICT-TRUTHY: 'True' / 'TRUE' / '1' / 'yes' / '' → revenue still rejected (treated as off)", async () => {
    for (const v of ["True", "TRUE", "1", "yes", "on", ""]) {
      process.env[ENV] = v;
      captured = undefined;
      await expect(
        youtubeAnalyticsQuery(CTX, { ...OK, metrics: "estimatedRevenue" }),
      ).rejects.toThrow(/unsupported metrics|allowed/);
      expect(captured).toBeUndefined();
    }
  });

  test("flag 'true' → an unknown (non-revenue, non-base) metric is STILL rejected", async () => {
    // the union is base ∪ monetary — it does not become an open allowlist.
    process.env[ENV] = "true";
    await expect(
      youtubeAnalyticsQuery(CTX, { ...OK, metrics: "totallyMadeUpMetric" }),
    ).rejects.toThrow(/unsupported metrics|allowed/);
    expect(captured).toBeUndefined();
  });
});
