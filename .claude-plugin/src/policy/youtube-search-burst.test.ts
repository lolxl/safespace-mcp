import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { __internal, getYoutubeSearchBurstLimit } from "./youtube-search-burst";

const ENV_KEY = "SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT";
let envBackup: string | undefined;

beforeEach(() => {
  envBackup = process.env[ENV_KEY];
  delete process.env[ENV_KEY];
});

afterEach(() => {
  if (envBackup === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = envBackup;
});

/* ──────────────────────────────────────────────────────────────
 *  getYoutubeSearchBurstLimit — env-var clamp + parse-failure fallback
 *  (mirrors youtube-comment-burst.test.ts shape; same parser body, just
 *  different default constant)
 * ────────────────────────────────────────────────────────────── */

describe("getYoutubeSearchBurstLimit — env parsing", () => {
  test("env unset → default 20", () => {
    expect(getYoutubeSearchBurstLimit()).toBe(__internal.YOUTUBE_SEARCH_BURST_DEFAULT);
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });

  test("env empty string → default 20", () => {
    process.env[ENV_KEY] = "";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });

  test("env whitespace-only → default 20", () => {
    process.env[ENV_KEY] = "   ";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });

  test("env valid integer in range → respected", () => {
    process.env[ENV_KEY] = "5";
    expect(getYoutubeSearchBurstLimit()).toBe(5);
    process.env[ENV_KEY] = "50";
    expect(getYoutubeSearchBurstLimit()).toBe(50);
  });

  test("env value at MIN boundary (1) → respected", () => {
    process.env[ENV_KEY] = "1";
    expect(getYoutubeSearchBurstLimit()).toBe(1);
  });

  test("env value at MAX boundary (100) → respected", () => {
    process.env[ENV_KEY] = "100";
    expect(getYoutubeSearchBurstLimit()).toBe(100);
  });

  test("env value above MAX (101+) → clamped to 100", () => {
    process.env[ENV_KEY] = "150";
    expect(getYoutubeSearchBurstLimit()).toBe(100);
    process.env[ENV_KEY] = "99999";
    expect(getYoutubeSearchBurstLimit()).toBe(100);
  });

  test("env value below MIN (0 / negative) → fallback to default 20", () => {
    // Mirrors comment-burst semantics: below-min is "operator error"
    // not "operator wanted 0". Fall back to safe default, not MIN clamp.
    process.env[ENV_KEY] = "0";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
    process.env[ENV_KEY] = "-5";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });

  test("env non-numeric → fallback to default 20", () => {
    process.env[ENV_KEY] = "not-a-number";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
    process.env[ENV_KEY] = "abc";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });

  test("env value with trailing non-numeric (parseInt partial) → respected if int prefix", () => {
    // parseInt("5abc") = 5 — this is Node's documented behavior. We accept
    // it as parsing "best effort" matching comment-burst (intentional
    // consistency across both burst limiters).
    process.env[ENV_KEY] = "5abc";
    expect(getYoutubeSearchBurstLimit()).toBe(5);
  });

  test("env hex / scientific → parseInt base-10 yields '1' (stops at 'e')", () => {
    process.env[ENV_KEY] = "1e3";
    // parseInt("1e3", 10) returns 1 (stops at 'e').
    expect(getYoutubeSearchBurstLimit()).toBe(1);
  });

  test("env leading whitespace → parseInt tolerates after trim() check passes", () => {
    process.env[ENV_KEY] = " 25 ";
    // " 25 ".trim() = "25" non-empty → parseInt(" 25 ", 10) = 25.
    expect(getYoutubeSearchBurstLimit()).toBe(25);
  });

  test("env Infinity literal → parseInt yields NaN → fallback", () => {
    process.env[ENV_KEY] = "Infinity";
    expect(getYoutubeSearchBurstLimit()).toBe(20);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  __internal constants — pinned shape sentinel
 * ────────────────────────────────────────────────────────────── */

describe("__internal constants", () => {
  test("DEFAULT = 20, MIN = 1, MAX = 100", () => {
    expect(__internal.YOUTUBE_SEARCH_BURST_DEFAULT).toBe(20);
    expect(__internal.YOUTUBE_SEARCH_BURST_MIN).toBe(1);
    expect(__internal.YOUTUBE_SEARCH_BURST_MAX).toBe(100);
  });
});
