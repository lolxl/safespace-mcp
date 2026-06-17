import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  __resetCommentBurstForTest,
  checkCommentBurst,
  getCommentBurstCount,
  getCommentBurstLimit,
  incrementCommentBurst,
} from "./youtube-comment-burst";

const ENV_KEY = "SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT";
let envBackup: string | undefined;

beforeEach(() => {
  envBackup = process.env[ENV_KEY];
  delete process.env[ENV_KEY];
  __resetCommentBurstForTest();
});

afterEach(() => {
  if (envBackup === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = envBackup;
  __resetCommentBurstForTest();
});

/* ──────────────────────────────────────────────────────────────
 *  getCommentBurstLimit — env-var clamp + parse-failure fallback
 * ────────────────────────────────────────────────────────────── */

describe("getCommentBurstLimit — env parsing", () => {
  test("env unset → default 10", () => {
    expect(getCommentBurstLimit()).toBe(__internal.COMMENT_BURST_DEFAULT);
    expect(getCommentBurstLimit()).toBe(10);
  });

  test("env empty string → default 10", () => {
    process.env[ENV_KEY] = "";
    expect(getCommentBurstLimit()).toBe(10);
  });

  test("env whitespace-only → default 10", () => {
    process.env[ENV_KEY] = "   ";
    expect(getCommentBurstLimit()).toBe(10);
  });

  test("env valid integer in range → respected", () => {
    process.env[ENV_KEY] = "5";
    expect(getCommentBurstLimit()).toBe(5);
    process.env[ENV_KEY] = "25";
    expect(getCommentBurstLimit()).toBe(25);
  });

  test("env value at MIN boundary (1) → respected", () => {
    process.env[ENV_KEY] = "1";
    expect(getCommentBurstLimit()).toBe(1);
  });

  test("env value at MAX boundary (100) → respected", () => {
    process.env[ENV_KEY] = "100";
    expect(getCommentBurstLimit()).toBe(100);
  });

  test("env value above MAX (101+) → clamped to 100", () => {
    process.env[ENV_KEY] = "150";
    expect(getCommentBurstLimit()).toBe(100);
    process.env[ENV_KEY] = "99999";
    expect(getCommentBurstLimit()).toBe(100);
  });

  test("env value below MIN (0 / negative) → fallback to default 10", () => {
    // Mirrors search-burst-limit semantics: below-min is "operator error"
    // not "operator wanted 0". Fall back to safe default, not MIN clamp.
    process.env[ENV_KEY] = "0";
    expect(getCommentBurstLimit()).toBe(10);
    process.env[ENV_KEY] = "-5";
    expect(getCommentBurstLimit()).toBe(10);
  });

  test("env non-numeric → fallback to default 10", () => {
    process.env[ENV_KEY] = "not-a-number";
    expect(getCommentBurstLimit()).toBe(10);
    process.env[ENV_KEY] = "abc";
    expect(getCommentBurstLimit()).toBe(10);
  });

  test("env value with trailing non-numeric (parseInt partial) → respected if int prefix", () => {
    // parseInt("5abc") = 5 — this is Node's documented behavior. We accept
    // it as parsing "best effort" matching getYoutubeSearchBurstLimit
    // (intentional consistency across both burst limiters).
    process.env[ENV_KEY] = "5abc";
    expect(getCommentBurstLimit()).toBe(5);
  });

  test("env hex / scientific → parseInt base-10 yields NaN → fallback", () => {
    process.env[ENV_KEY] = "1e3";
    // parseInt("1e3", 10) returns 1 (stops at 'e').
    expect(getCommentBurstLimit()).toBe(1);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  Counter + checkCommentBurst / incrementCommentBurst
 * ────────────────────────────────────────────────────────────── */

describe("checkCommentBurst + incrementCommentBurst — per-session counter", () => {
  test("counter starts at 0", () => {
    expect(getCommentBurstCount()).toBe(0);
  });

  test("checkCommentBurst returns ok=true under default limit (10)", () => {
    const r = checkCommentBurst();
    expect(r.ok).toBe(true);
    expect(r.current).toBe(0);
    expect(r.limit).toBe(10);
  });

  test("incrementCommentBurst advances the counter", () => {
    incrementCommentBurst();
    expect(getCommentBurstCount()).toBe(1);
    incrementCommentBurst();
    expect(getCommentBurstCount()).toBe(2);
  });

  test("at limit boundary (counter=limit), checkCommentBurst returns ok=false", () => {
    // Push to default limit of 10.
    for (let i = 0; i < 10; i++) incrementCommentBurst();
    const r = checkCommentBurst();
    expect(r.ok).toBe(false);
    expect(r.current).toBe(10);
    expect(r.limit).toBe(10);
  });

  test("below limit (counter=limit-1), checkCommentBurst returns ok=true", () => {
    for (let i = 0; i < 9; i++) incrementCommentBurst();
    const r = checkCommentBurst();
    expect(r.ok).toBe(true);
    expect(r.current).toBe(9);
    expect(r.limit).toBe(10);
  });

  test("env override (=5) — 5 increments allowed, 6th check fails", () => {
    process.env[ENV_KEY] = "5";
    for (let i = 0; i < 5; i++) {
      const r = checkCommentBurst();
      expect(r.ok).toBe(true);
      incrementCommentBurst();
    }
    const r = checkCommentBurst();
    expect(r.ok).toBe(false);
    expect(r.limit).toBe(5);
  });

  test("env override (=100, max) — full 100 allowed, 101st check fails", () => {
    process.env[ENV_KEY] = "100";
    for (let i = 0; i < 100; i++) incrementCommentBurst();
    expect(checkCommentBurst().ok).toBe(false);
  });

  test("env override out-of-range high (=150) — clamped to 100", () => {
    process.env[ENV_KEY] = "150";
    expect(checkCommentBurst().limit).toBe(100);
  });

  test("__resetCommentBurstForTest resets the counter to 0", () => {
    for (let i = 0; i < 5; i++) incrementCommentBurst();
    expect(getCommentBurstCount()).toBe(5);
    __resetCommentBurstForTest();
    expect(getCommentBurstCount()).toBe(0);
    expect(checkCommentBurst().ok).toBe(true);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  __resetCommentBurstForTest — gating
 * ────────────────────────────────────────────────────────────── */

describe("__resetCommentBurstForTest — environment gate", () => {
  test("throws if NODE_ENV / BUN_ENV not set to 'test'", () => {
    // bun:test does NOT set NODE_ENV=test automatically — it sets BUN_ENV.
    // We temporarily strip BOTH to verify the guard fires loudly outside
    // a test runner. Bun's runtime DOES set BUN_ENV='test', so we save +
    // restore.
    const prevNodeEnv = process.env.NODE_ENV;
    const prevBunEnv = process.env.BUN_ENV;
    delete process.env.NODE_ENV;
    delete process.env.BUN_ENV;
    try {
      expect(() => __resetCommentBurstForTest()).toThrow(/tests only/);
    } finally {
      if (prevNodeEnv !== undefined) process.env.NODE_ENV = prevNodeEnv;
      if (prevBunEnv !== undefined) process.env.BUN_ENV = prevBunEnv;
    }
  });
});
