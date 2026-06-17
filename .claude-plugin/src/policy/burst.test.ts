import { afterEach, describe, expect, test } from "bun:test";
import { makeBurstLimitReader } from "./burst";

// A throwaway env var so these tests never collide with the real
// SAFESPACE_YOUTUBE_*_BURST_LIMIT vars (or with each other).
const ENV = "SAFESPACE__BURST_TEST_LIMIT";

afterEach(() => {
  delete process.env[ENV];
});

function reader(defaultLimit = 10, min?: number, max?: number) {
  return makeBurstLimitReader({ envVar: ENV, defaultLimit, min, max });
}

describe("makeBurstLimitReader — env-var parsing contract", () => {
  test("unset env -> defaultLimit", () => {
    delete process.env[ENV];
    expect(reader(10)()).toBe(10);
    expect(reader(20)()).toBe(20);
  });

  test("empty / whitespace-only -> defaultLimit", () => {
    process.env[ENV] = "";
    expect(reader(10)()).toBe(10);
    process.env[ENV] = "   ";
    expect(reader(10)()).toBe(10);
  });

  test("valid in-range integer -> the value", () => {
    process.env[ENV] = "37";
    expect(reader(10)()).toBe(37);
  });

  test("value < min -> defaultLimit (NOT clamped to min)", () => {
    process.env[ENV] = "0";
    expect(reader(10)()).toBe(10);
    process.env[ENV] = "-5";
    expect(reader(10)()).toBe(10);
  });

  test("value > max -> clamped to max", () => {
    process.env[ENV] = "9999";
    expect(reader(10)()).toBe(100);
  });

  test("non-integer / NaN -> defaultLimit", () => {
    process.env[ENV] = "abc";
    expect(reader(10)()).toBe(10);
    process.env[ENV] = "NaN";
    expect(reader(10)()).toBe(10);
  });

  test('Number.parseInt leading-numeric leniency preserved ("12abc" -> 12)', () => {
    process.env[ENV] = "12abc";
    expect(reader(10)()).toBe(12);
  });

  test("boundary values min=1 and max=100 are accepted as-is", () => {
    process.env[ENV] = "1";
    expect(reader(10)()).toBe(1);
    process.env[ENV] = "100";
    expect(reader(10)()).toBe(100);
  });

  test("per-call resolution (uncached): re-reads env each call", () => {
    const read = reader(10);
    process.env[ENV] = "5";
    expect(read()).toBe(5);
    process.env[ENV] = "50";
    expect(read()).toBe(50);
  });

  test("custom min/max override the 1/100 defaults", () => {
    const read = reader(10, 5, 50);
    process.env[ENV] = "3"; // < custom min 5 -> default
    expect(read()).toBe(10);
    process.env[ENV] = "75"; // > custom max 50 -> clamp 50
    expect(read()).toBe(50);
    process.env[ENV] = "25"; // in range
    expect(read()).toBe(25);
  });
});

describe("makeBurstLimitReader — matches the two shipped burst configs", () => {
  test("comment-burst config: default 10, range 1-100", () => {
    const read = makeBurstLimitReader({
      envVar: ENV,
      defaultLimit: 10,
      min: 1,
      max: 100,
    });
    delete process.env[ENV];
    expect(read()).toBe(10);
    process.env[ENV] = "200";
    expect(read()).toBe(100);
  });

  test("search-burst config: default 20, range 1-100", () => {
    const read = makeBurstLimitReader({
      envVar: ENV,
      defaultLimit: 20,
      min: 1,
      max: 100,
    });
    delete process.env[ENV];
    expect(read()).toBe(20);
    process.env[ENV] = "0";
    expect(read()).toBe(20);
  });
});
