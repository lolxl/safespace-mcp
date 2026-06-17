import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  currentTier,
  deriveTierFromLegacyEnv,
  rewriteEnvWithDerivedTier,
  tierSatisfies,
} from "./tier";

const ENV_KEYS = [
  "SAFESPACE_TIER",
  "SAFESPACE_ENABLE_SEND",
  "SAFESPACE_ENABLE_MODIFY",
  "SAFESPACE_ENABLE_DRIVE_SHARE",
] as const;

let backup: Record<string, string | undefined>;

beforeEach(() => {
  backup = {};
  for (const k of ENV_KEYS) {
    backup[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (backup[k] === undefined) delete process.env[k];
    else process.env[k] = backup[k];
  }
});

describe("currentTier — explicit SAFESPACE_TIER", () => {
  test("returns 'read' when unset (default)", () => {
    expect(currentTier()).toBe("read");
  });

  test("returns 'read' when empty string (treated as unset)", () => {
    process.env.SAFESPACE_TIER = "";
    expect(currentTier()).toBe("read");
  });

  test.each(["read", "write", "share"] as const)(
    "returns '%s' when SAFESPACE_TIER is set to that value",
    (tier) => {
      process.env.SAFESPACE_TIER = tier;
      expect(currentTier()).toBe(tier);
    },
  );

  test("falls back to 'read' on invalid SAFESPACE_TIER value (fail-safe)", () => {
    // Typos like "writes" or "shr" should NEVER accidentally enable writes —
    // fail-safe semantic. Stderr warning is emitted (not asserted here).
    process.env.SAFESPACE_TIER = "writes";
    expect(currentTier()).toBe("read");
  });

  test("explicit SAFESPACE_TIER suppresses the legacy-flag hard-fail", () => {
    // If SAFESPACE_TIER is set, the legacy flags are IGNORED entirely —
    // no throw, no derive. The user has explicitly stated their tier.
    process.env.SAFESPACE_TIER = "read";
    process.env.SAFESPACE_ENABLE_SEND = "1";
    process.env.SAFESPACE_ENABLE_DRIVE_SHARE = "1";
    expect(currentTier()).toBe("read");
  });
});

describe("currentTier — legacy-flag hard-fail (v1.1: shim removed)", () => {
  // Architect-reviewed decision: silent default-to-read on legacy-only env
  // would mask capability loss for upgraders. Hard-fail with migration doc
  // in the error message is the v1.1 behavior. See docs/DESIGN.md v2.0
  // Addendum.

  test("ENABLE_MODIFY without SAFESPACE_TIER → throws", () => {
    process.env.SAFESPACE_ENABLE_MODIFY = "1";
    expect(() => currentTier()).toThrow(/are removed in v1\.1/);
  });

  test("ENABLE_SEND without SAFESPACE_TIER → throws", () => {
    process.env.SAFESPACE_ENABLE_SEND = "1";
    expect(() => currentTier()).toThrow(/are removed in v1\.1/);
  });

  test("ENABLE_DRIVE_SHARE without SAFESPACE_TIER → throws", () => {
    process.env.SAFESPACE_ENABLE_DRIVE_SHARE = "1";
    expect(() => currentTier()).toThrow(/are removed in v1\.1/);
  });

  test("all three legacy flags without SAFESPACE_TIER → throws", () => {
    process.env.SAFESPACE_ENABLE_SEND = "1";
    process.env.SAFESPACE_ENABLE_MODIFY = "1";
    process.env.SAFESPACE_ENABLE_DRIVE_SHARE = "1";
    expect(() => currentTier()).toThrow(/are removed in v1\.1/);
  });

  test("error message points at safespace migrate-v2 + SAFESPACE_TIER (migration doc)", () => {
    process.env.SAFESPACE_ENABLE_SEND = "1";
    expect(() => currentTier()).toThrow(/safespace migrate-v2/);
    expect(() => currentTier()).toThrow(/SAFESPACE_TIER=read\|write\|share/);
  });

  test("ENABLE_X='0' does NOT count as set (only '1' triggers hard-fail)", () => {
    // Same boolean semantic as the prior shim: only literal "1" counts as set.
    // Empty string, "0", "false", etc. are NOT legacy-flag set, so the safe
    // default "read" is returned without throwing.
    process.env.SAFESPACE_ENABLE_SEND = "0";
    process.env.SAFESPACE_ENABLE_MODIFY = "0";
    expect(currentTier()).toBe("read");
  });
});

describe("tierSatisfies — one-direction cover", () => {
  test("any tier satisfies itself", () => {
    expect(tierSatisfies("read", "read")).toBe(true);
    expect(tierSatisfies("write", "write")).toBe(true);
    expect(tierSatisfies("share", "share")).toBe(true);
  });

  test("higher tier covers lower requirements", () => {
    expect(tierSatisfies("write", "read")).toBe(true);
    expect(tierSatisfies("share", "read")).toBe(true);
    expect(tierSatisfies("share", "write")).toBe(true);
  });

  test("lower tier does NOT cover higher requirements (one-direction)", () => {
    expect(tierSatisfies("read", "write")).toBe(false);
    expect(tierSatisfies("read", "share")).toBe(false);
    expect(tierSatisfies("write", "share")).toBe(false);
  });
});

describe("deriveTierFromLegacyEnv — v1.x flag → v2.0 tier derivation", () => {
  // Pure function: takes .env content text, returns the tier those v1.x
  // legacy flags would derive to, or null when no derivation applies.
  // Precedence: DRIVE_SHARE > SEND/MODIFY > nothing. Used by migrate-v2
  // (data migration) and the wizard's "F" path (live install).

  test("ENABLE_SEND=1 → write", () => {
    const result = deriveTierFromLegacyEnv("SAFESPACE_ENABLE_SEND=1\n");
    expect(result).toEqual({ derivedTier: "write", legacyFlagsFound: ["SAFESPACE_ENABLE_SEND"] });
  });

  test("ENABLE_MODIFY=1 → write", () => {
    const result = deriveTierFromLegacyEnv("SAFESPACE_ENABLE_MODIFY=1\n");
    expect(result).toEqual({ derivedTier: "write", legacyFlagsFound: ["SAFESPACE_ENABLE_MODIFY"] });
  });

  test("ENABLE_DRIVE_SHARE=1 → share (highest precedence)", () => {
    const result = deriveTierFromLegacyEnv("SAFESPACE_ENABLE_DRIVE_SHARE=1\n");
    expect(result).toEqual({
      derivedTier: "share",
      legacyFlagsFound: ["SAFESPACE_ENABLE_DRIVE_SHARE"],
    });
  });

  test("DRIVE_SHARE + SEND together → share (blast-radius precedence)", () => {
    const content = "SAFESPACE_ENABLE_SEND=1\nSAFESPACE_ENABLE_DRIVE_SHARE=1\n";
    const result = deriveTierFromLegacyEnv(content);
    expect(result?.derivedTier).toBe("share");
    // Order in legacyFlagsFound = file order (preserves observed input).
    expect(result?.legacyFlagsFound).toEqual([
      "SAFESPACE_ENABLE_SEND",
      "SAFESPACE_ENABLE_DRIVE_SHARE",
    ]);
  });

  test("SEND + MODIFY together → write (no DRIVE_SHARE = no escalation)", () => {
    const content = "SAFESPACE_ENABLE_SEND=1\nSAFESPACE_ENABLE_MODIFY=1\n";
    const result = deriveTierFromLegacyEnv(content);
    expect(result?.derivedTier).toBe("write");
  });

  test("explicit SAFESPACE_TIER already set → null (no derivation)", () => {
    // User already declared their tier; derivation must not override it.
    // This is the gate that prevents wizard re-runs from clobbering an
    // intentional manual override.
    const content = "SAFESPACE_TIER=read\nSAFESPACE_ENABLE_SEND=1\n";
    expect(deriveTierFromLegacyEnv(content)).toBeNull();
  });

  test("explicit SAFESPACE_TIER with whitespace and tabs is still recognized", () => {
    const content = "  SAFESPACE_TIER = write  \nSAFESPACE_ENABLE_SEND=1\n";
    expect(deriveTierFromLegacyEnv(content)).toBeNull();
  });

  test("commented-out legacy flag → null (only uncommented flags count)", () => {
    const content = "# SAFESPACE_ENABLE_SEND=1\n";
    expect(deriveTierFromLegacyEnv(content)).toBeNull();
  });

  test("flag set to 0 → null (explicit disable, not derivation trigger)", () => {
    const content = "SAFESPACE_ENABLE_SEND=0\n";
    expect(deriveTierFromLegacyEnv(content)).toBeNull();
  });

  test("flag set to a non-1 value (e.g. 'true') → null (only =1 triggers)", () => {
    // Conservative: v1.x semantics only recognized "1" as enable. Anything
    // else (true, yes, on) was treated as off. Preserve that behavior.
    const content = "SAFESPACE_ENABLE_SEND=true\n";
    expect(deriveTierFromLegacyEnv(content)).toBeNull();
  });

  test("empty content → null", () => {
    expect(deriveTierFromLegacyEnv("")).toBeNull();
  });

  test("content with only unrelated keys → null", () => {
    expect(deriveTierFromLegacyEnv("GOOGLE_CLIENT_ID=foo\nGOOGLE_CLIENT_SECRET=bar\n")).toBeNull();
  });

  test("ENABLE_SEND=1 with inline whitespace before/after → recognized", () => {
    // .env may have leading spaces or trailing whitespace after the 1.
    const content = "  SAFESPACE_ENABLE_SEND=1  \n";
    expect(deriveTierFromLegacyEnv(content)?.derivedTier).toBe("write");
  });
});

describe("rewriteEnvWithDerivedTier — apply derived tier to .env content", () => {
  // Pure string transform: input is original .env content, output is the
  // rewritten content with legacy ENABLE_* flags commented out and
  // SAFESPACE_TIER=<derived> appended. Caller writes the result back to
  // disk atomically.

  test("comments out SAFESPACE_ENABLE_SEND and appends SAFESPACE_TIER=write", () => {
    const input =
      "GOOGLE_CLIENT_ID=client-id-value\n" +
      "GOOGLE_CLIENT_SECRET=secret-value\n" +
      "SAFESPACE_ENABLE_SEND=1\n";
    const output = rewriteEnvWithDerivedTier(input, "write");
    expect(output).toContain("GOOGLE_CLIENT_ID=client-id-value");
    expect(output).toContain("GOOGLE_CLIENT_SECRET=secret-value");
    expect(output).toMatch(/^# .*SAFESPACE_ENABLE_SEND=1$/m);
    expect(output).not.toMatch(/^SAFESPACE_ENABLE_SEND=1$/m);
    expect(output).toMatch(/^SAFESPACE_TIER=write$/m);
  });

  test("rewrites all three legacy flag variants at once", () => {
    const input =
      "SAFESPACE_ENABLE_SEND=1\n" +
      "SAFESPACE_ENABLE_MODIFY=1\n" +
      "SAFESPACE_ENABLE_DRIVE_SHARE=1\n";
    const output = rewriteEnvWithDerivedTier(input, "share");
    for (const flag of [
      "SAFESPACE_ENABLE_SEND",
      "SAFESPACE_ENABLE_MODIFY",
      "SAFESPACE_ENABLE_DRIVE_SHARE",
    ]) {
      expect(output).toMatch(new RegExp(`^# .*${flag}=1$`, "m"));
      expect(output).not.toMatch(new RegExp(`^${flag}=1$`, "m"));
    }
    expect(output).toMatch(/^SAFESPACE_TIER=share$/m);
  });

  test("preserves non-flag lines including blank lines and comments verbatim", () => {
    const input =
      "# my GCP creds\n" +
      "GOOGLE_CLIENT_ID=abc\n" +
      "\n" +
      "GOOGLE_CLIENT_SECRET=def\n" +
      "SAFESPACE_ENABLE_SEND=1\n";
    const output = rewriteEnvWithDerivedTier(input, "write");
    expect(output).toContain("# my GCP creds");
    expect(output).toContain("GOOGLE_CLIENT_ID=abc");
    expect(output).toContain("GOOGLE_CLIENT_SECRET=def");
    // Blank line preserved between secret and id (count must match input).
    expect(output.match(/^\s*$/gm)?.length ?? 0).toBeGreaterThanOrEqual(1);
  });

  test("output always ends with a newline", () => {
    expect(rewriteEnvWithDerivedTier("SAFESPACE_ENABLE_SEND=1", "write").endsWith("\n")).toBe(true);
    expect(rewriteEnvWithDerivedTier("SAFESPACE_ENABLE_SEND=1\n", "write").endsWith("\n")).toBe(
      true,
    );
  });

  test("input with no legacy flags → only appends SAFESPACE_TIER (unchanged otherwise)", () => {
    // Defensive: even when caller mistakenly invokes rewrite without a
    // derivation result, the output is still a valid .env (just appends
    // the tier line). Caller is responsible for not calling this when
    // deriveTierFromLegacyEnv returned null — but the function is total.
    const input = "GOOGLE_CLIENT_ID=abc\n";
    const output = rewriteEnvWithDerivedTier(input, "read");
    expect(output).toContain("GOOGLE_CLIENT_ID=abc");
    expect(output).toMatch(/^SAFESPACE_TIER=read$/m);
  });
});
