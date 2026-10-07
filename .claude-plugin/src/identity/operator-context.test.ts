import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  EnvOperatorResolver,
  envOperatorContext,
  type OperatorContext,
} from "./operator-context";

// The EnvOperatorResolver reads the tier from env. These tests pin (1) it reads the
// right env, (2) it is resolved PER CALL — never a snapshot — so the env-mutation
// contract the choke points rely on survives, and (3) the default tier (read).

const TIER = "SAFESPACE_TIER";

let savedTier: string | undefined;

beforeEach(() => {
  savedTier = process.env[TIER];
  delete process.env[TIER];
});

afterEach(() => {
  if (savedTier === undefined) delete process.env[TIER];
  else process.env[TIER] = savedTier;
});

describe("EnvOperatorResolver.resolve()", () => {
  test("reads $SAFESPACE_TIER", () => {
    process.env[TIER] = "write";
    expect(new EnvOperatorResolver().resolve()).toEqual({ tier: "write" });
  });

  test("defaults to tier read", () => {
    expect(new EnvOperatorResolver().resolve().tier).toBe("read");
  });

  test("an invalid tier falls back to read (fail-safe, reuses currentTier)", () => {
    process.env[TIER] = "superuser";
    expect(new EnvOperatorResolver().resolve().tier).toBe("read");
  });

  test("resolve() is PER CALL — env mutation between calls is honored (NO snapshot)", () => {
    const resolver = new EnvOperatorResolver();
    process.env[TIER] = "read";
    const first = resolver.resolve();
    // Mutate env on the SAME resolver instance — a snapshot-at-construction
    // implementation would miss this; the per-call read must see it.
    process.env[TIER] = "share";
    const second = resolver.resolve();
    expect(first.tier).toBe("read");
    expect(second.tier).toBe("share");
  });
});

describe("envOperatorContext()", () => {
  test("is the EnvOperatorResolver context (the choke-point default)", () => {
    process.env[TIER] = "share";
    const op: OperatorContext = envOperatorContext();
    expect(op).toEqual({ tier: "share" });
  });

  test("re-reads env on each call (default param must not freeze)", () => {
    process.env[TIER] = "read";
    expect(envOperatorContext().tier).toBe("read");
    process.env[TIER] = "write";
    expect(envOperatorContext().tier).toBe("write");
  });
});
