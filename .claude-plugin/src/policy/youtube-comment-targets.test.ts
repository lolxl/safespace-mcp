import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  buildCommentTargetAllowlistState,
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
  getCommentTargetAllowlistState,
  isCommentTargetAllowed,
  parseCommentTargets,
  summarizeCommentTargetAllowlist,
} from "./youtube-comment-targets";

const ENV_KEYS = [ENV_TARGETS, ENV_TARGETS_EXTRA] as const;
let envBackup: Record<string, string | undefined>;
let prevConsoleError: typeof console.error;
let capturedConsoleErrors: string[];

beforeEach(() => {
  envBackup = {};
  for (const k of ENV_KEYS) {
    envBackup[k] = process.env[k];
    delete process.env[k];
  }
  __internal.resetSingletons();

  // Capture stderr so WARN-ONCE / malformed-warning assertions can inspect
  // the messages without polluting test output. Restore in afterEach.
  capturedConsoleErrors = [];
  prevConsoleError = console.error;
  console.error = (...args: unknown[]): void => {
    capturedConsoleErrors.push(args.map(String).join(" "));
  };
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (envBackup[k] === undefined) delete process.env[k];
    else process.env[k] = envBackup[k];
  }
  __internal.resetSingletons();
  console.error = prevConsoleError;
});

/* ──────────────────────────────────────────────────────────────
 *  parseCommentTargets — per-type regex + prefix rules (locked)
 * ────────────────────────────────────────────────────────────── */

describe("parseCommentTargets — happy paths per type", () => {
  test("video:<11-char> parses", () => {
    const r = parseCommentTargets("video:dQw4w9WgXcQ");
    expect(r.ok).toEqual([{ type: "video", id: "dQw4w9WgXcQ" }]);
    expect(r.rejected).toHaveLength(0);
  });

  test("video: with `_` and `-` in payload parses (URL-safe base64 charset)", () => {
    // Exactly 11 chars including `_` and `-` (URL-safe base64).
    const r = parseCommentTargets("video:abc_-DEF123");
    expect(r.ok).toEqual([{ type: "video", id: "abc_-DEF123" }]);
  });

  test("channel:UC<22-char> parses", () => {
    const r = parseCommentTargets("channel:UC1234567890abcdefghijkl");
    expect(r.ok).toEqual([
      { type: "channel", id: "UC1234567890abcdefghijkl" },
    ]);
  });

  test("playlist:PL<...> parses (PL prefix)", () => {
    const r = parseCommentTargets("playlist:PLabc123");
    expect(r.ok).toEqual([{ type: "playlist", id: "PLabc123" }]);
  });

  test("playlist:UU<...> parses (UU = uploads-playlist prefix)", () => {
    const r = parseCommentTargets("playlist:UUxyz789_-AB");
    expect(r.ok).toEqual([{ type: "playlist", id: "UUxyz789_-AB" }]);
  });

  test("playlist:RD / LL / OL / FL prefixes all accepted", () => {
    for (const prefix of ["RD", "LL", "OL", "FL"]) {
      const r = parseCommentTargets(`playlist:${prefix}aaaaaa`);
      expect(r.ok).toHaveLength(1);
      expect(r.ok[0]?.type).toBe("playlist");
      expect(r.ok[0]?.id.startsWith(prefix)).toBe(true);
    }
  });
});

describe("parseCommentTargets — per-type rejection paths", () => {
  test("video too short rejected", () => {
    const r = parseCommentTargets("video:abc");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["video:abc"]);
  });

  test("video too long rejected", () => {
    const r = parseCommentTargets("video:abc12345678abcd");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["video:abc12345678abcd"]);
  });

  test("channel without UC prefix rejected", () => {
    const r = parseCommentTargets("channel:abc1234567890abcdefghijk");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("channel:abc1234567890abcdefghijk");
  });

  test("channel with UC but wrong length rejected", () => {
    const r = parseCommentTargets("channel:UCshort");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("channel:UCshort");
  });

  test("playlist with unknown prefix rejected (no PL/UU/LL/OL/FL/RD)", () => {
    const r = parseCommentTargets("playlist:XXabc123");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("playlist:XXabc123");
  });

  test("playlist with valid prefix but oversized payload (>64) rejected (DoS guard)", () => {
    // 65 chars after PL prefix — exceeds the 64-char DoS cap.
    const oversized = "PL" + "a".repeat(65);
    const r = parseCommentTargets(`playlist:${oversized}`);
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain(`playlist:${oversized}`);
  });

  test("playlist payload exactly at 64-char cap (PL + 64) accepted", () => {
    // PL + 64 chars = 66 total. Regex allows {1,64} AFTER the prefix.
    const maxOk = "PL" + "a".repeat(64);
    const r = parseCommentTargets(`playlist:${maxOk}`);
    expect(r.ok).toHaveLength(1);
  });
});

describe("parseCommentTargets — case sensitivity (locked)", () => {
  test("capital prefix rejected — `Video:` not normalized", () => {
    const r = parseCommentTargets("Video:dQw4w9WgXcQ");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["Video:dQw4w9WgXcQ"]);
  });

  test("all-caps prefix rejected", () => {
    const r = parseCommentTargets("CHANNEL:UC1234567890abcdefghijkl");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("CHANNEL:UC1234567890abcdefghijkl");
  });

  test("payload charset case preserved on parse (YouTube IDs are case-sensitive)", () => {
    // YouTube video IDs are case-sensitive; "dQw4w9WgXcQ" ≠ "DqW4W9WgXcQ".
    const r = parseCommentTargets("video:dQw4w9WgXcQ");
    expect(r.ok[0]?.id).toBe("dQw4w9WgXcQ");
  });
});

describe("parseCommentTargets — structural rejection", () => {
  test("missing colon rejected", () => {
    const r = parseCommentTargets("videodQw4w9WgXcQ");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["videodQw4w9WgXcQ"]);
  });

  test("empty payload after colon rejected", () => {
    const r = parseCommentTargets("video:");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("video:");
  });

  test("empty prefix before colon rejected", () => {
    const r = parseCommentTargets(":dQw4w9WgXcQ");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain(":dQw4w9WgXcQ");
  });

  test("extra colon rejected (video:abc:def — payload contains `:`)", () => {
    // Per design §4.1.1: exactly one colon. Token format `<prefix>:<id>`,
    // payload class `[A-Za-z0-9_-]` excludes `:`.
    const r = parseCommentTargets("video:abc:def");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("video:abc:def");
  });

  test("whitespace inside payload rejected (per-type regex excludes space)", () => {
    const r = parseCommentTargets("video:abc def 123");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toContain("video:abc def 123");
  });

  test("unknown prefix rejected", () => {
    const r = parseCommentTargets("user:dQw4w9WgXcQ");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["user:dQw4w9WgXcQ"]);
  });
});

describe("parseCommentTargets — multi-token + whitespace + dedup", () => {
  test("multiple valid tokens parse", () => {
    const r = parseCommentTargets(
      "video:dQw4w9WgXcQ,channel:UC1234567890abcdefghijkl,playlist:PLabc",
    );
    expect(r.ok).toHaveLength(3);
    expect(r.ok[0]?.type).toBe("video");
    expect(r.ok[1]?.type).toBe("channel");
    expect(r.ok[2]?.type).toBe("playlist");
  });

  test("outer whitespace trimmed around tokens", () => {
    const r = parseCommentTargets("  video:dQw4w9WgXcQ  ,   playlist:PLabc   ");
    expect(r.ok).toHaveLength(2);
  });

  test("trailing / multiple commas tolerated", () => {
    const r = parseCommentTargets(",video:dQw4w9WgXcQ,,,playlist:PLabc,");
    expect(r.ok).toHaveLength(2);
  });

  test("duplicate tokens dedupped to one entry", () => {
    const r = parseCommentTargets("video:dQw4w9WgXcQ,video:dQw4w9WgXcQ");
    expect(r.ok).toHaveLength(1);
  });

  test("malformed tokens do not poison valid ones (partial success)", () => {
    const r = parseCommentTargets(
      "video:bad,video:dQw4w9WgXcQ,Video:capital,channel:UC1234567890abcdefghijkl",
    );
    expect(r.ok).toHaveLength(2);
    expect(r.rejected).toEqual(["video:bad", "Video:capital"]);
  });

  test("undefined input → empty result", () => {
    const r = parseCommentTargets(undefined);
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toHaveLength(0);
  });

  test("empty string → empty result", () => {
    const r = parseCommentTargets("");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toHaveLength(0);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  isCommentTargetAllowed — default-deny semantics (sec hook #9 + #10)
 * ────────────────────────────────────────────────────────────── */

describe("isCommentTargetAllowed — default-deny semantics", () => {
  test("state.kind === 'off' → false (hard-deny default, asymmetric vs recipient)", () => {
    // Per design §4.1 — comment writes default to HARD-DENY, opposite of
    // recipient-allowlist (which is "off = policy off, allow"). This is
    // the load-bearing default-deny invariant for sec-rev hook #9.
    expect(
      isCommentTargetAllowed("video", "dQw4w9WgXcQ", { kind: "off" }),
    ).toBe(false);
  });

  test("state.kind === 'active' with 0 entries → false (empty allowlist hard-denies)", () => {
    expect(
      isCommentTargetAllowed("video", "dQw4w9WgXcQ", {
        kind: "active",
        targets: [],
      }),
    ).toBe(false);
  });

  test("matching video tuple → true", () => {
    expect(
      isCommentTargetAllowed("video", "dQw4w9WgXcQ", {
        kind: "active",
        targets: [{ type: "video", id: "dQw4w9WgXcQ" }],
      }),
    ).toBe(true);
  });

  test("matching channel tuple → true", () => {
    expect(
      isCommentTargetAllowed("channel", "UC1234567890abcdefghijkl", {
        kind: "active",
        targets: [{ type: "channel", id: "UC1234567890abcdefghijkl" }],
      }),
    ).toBe(true);
  });

  test("video id matches but type=channel → false (type discrimination)", () => {
    // Defense against caller passing video_id under wrong type. The
    // (type, id) tuple is the equality key.
    expect(
      isCommentTargetAllowed("channel", "dQw4w9WgXcQ", {
        kind: "active",
        targets: [{ type: "video", id: "dQw4w9WgXcQ" }],
      }),
    ).toBe(false);
  });

  test("non-matching id → false", () => {
    expect(
      isCommentTargetAllowed("video", "different___", {
        kind: "active",
        targets: [{ type: "video", id: "dQw4w9WgXcQ" }],
      }),
    ).toBe(false);
  });

  test("empty-string id → false (degenerate input guard)", () => {
    expect(
      isCommentTargetAllowed("video", "", {
        kind: "active",
        targets: [{ type: "video", id: "" }],
      }),
    ).toBe(false);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  buildCommentTargetAllowlistState — off-vs-active distinction
 * ────────────────────────────────────────────────────────────── */

describe("buildCommentTargetAllowlistState", () => {
  test("both env unset → off", () => {
    const s = buildCommentTargetAllowlistState(undefined, undefined);
    expect(s.kind).toBe("off");
  });

  test("base set to empty string → active with 0 entries (explicit default-deny)", () => {
    // Mirrors recipient-allowlist.ts:198 — "" is explicit configuration
    // intent, distinct from undefined. Active state means policy is ON,
    // even though zero entries means everything denied.
    const s = buildCommentTargetAllowlistState("", undefined);
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.targets).toHaveLength(0);
  });

  test("extra set without base → active (per-session override semantics)", () => {
    const s = buildCommentTargetAllowlistState(undefined, "video:dQw4w9WgXcQ");
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.targets).toHaveLength(1);
  });

  test("base + extra → union, dedupped on (type,id) key", () => {
    const s = buildCommentTargetAllowlistState(
      "video:dQw4w9WgXcQ,playlist:PLbase",
      "video:dQw4w9WgXcQ,channel:UC1234567890abcdefghijkl",
    );
    expect(s.kind).toBe("active");
    if (s.kind === "active") {
      expect(s.targets).toHaveLength(3); // dup video collapsed
      const types = s.targets.map((t) => t.type).sort();
      expect(types).toEqual(["channel", "playlist", "video"]);
    }
  });
});

/* ──────────────────────────────────────────────────────────────
 *  getCommentTargetAllowlistState — singleton + WARN-ONCE
 * ────────────────────────────────────────────────────────────── */

describe("getCommentTargetAllowlistState — env-driven singleton", () => {
  test("env unset → off (hard-deny default)", () => {
    const s = getCommentTargetAllowlistState();
    expect(s.kind).toBe("off");
  });

  test("env set → active, parses entries", () => {
    process.env[ENV_TARGETS] = "video:dQw4w9WgXcQ,playlist:PLabc";
    const s = getCommentTargetAllowlistState();
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.targets).toHaveLength(2);
  });

  test("singleton: second call returns same cached state", () => {
    process.env[ENV_TARGETS] = "video:dQw4w9WgXcQ";
    const s1 = getCommentTargetAllowlistState();
    // Mutate env AFTER first load — should NOT affect cached result.
    process.env[ENV_TARGETS] = "video:CACHED_CACHED";
    const s2 = getCommentTargetAllowlistState();
    expect(s1).toBe(s2);
  });

  test("WARN-ONCE: EXTRA set without base → ONE console.error at first call only", () => {
    process.env[ENV_TARGETS_EXTRA] = "video:dQw4w9WgXcQ";
    // First call emits the warning.
    getCommentTargetAllowlistState();
    const matchingFirst = capturedConsoleErrors.filter((m) =>
      m.includes("SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA is set"),
    );
    expect(matchingFirst).toHaveLength(1);

    // Subsequent calls do NOT re-emit (cached state path).
    getCommentTargetAllowlistState();
    getCommentTargetAllowlistState();
    const matchingTotal = capturedConsoleErrors.filter((m) =>
      m.includes("SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA is set"),
    );
    expect(matchingTotal).toHaveLength(1);
  });

  test("malformed entries trigger per-entry stderr warnings at load", () => {
    process.env[ENV_TARGETS] = "video:dQw4w9WgXcQ,video:bad,Video:capital";
    getCommentTargetAllowlistState();
    const rejectedWarns = capturedConsoleErrors.filter((m) =>
      m.includes("rejected malformed entry"),
    );
    expect(rejectedWarns).toHaveLength(2);
  });

  test("env set but yields 0 valid entries → loud stderr warning", () => {
    process.env[ENV_TARGETS] = "Video:capital,channel:bad";
    getCommentTargetAllowlistState();
    const zeroWarn = capturedConsoleErrors.filter((m) =>
      m.includes("yielded 0 valid entries"),
    );
    expect(zeroWarn.length).toBeGreaterThanOrEqual(1);
  });

  test("env set to empty string → active state, hard-deny applies", () => {
    process.env[ENV_TARGETS] = "";
    const s = getCommentTargetAllowlistState();
    expect(s.kind).toBe("active");
    expect(
      isCommentTargetAllowed("video", "dQw4w9WgXcQ", s),
    ).toBe(false);
  });
});

/* ──────────────────────────────────────────────────────────────
 *  summarizeCommentTargetAllowlist — diagnostic shape
 * ────────────────────────────────────────────────────────────── */

describe("summarizeCommentTargetAllowlist", () => {
  test("off state → all-zero counts", () => {
    const s = summarizeCommentTargetAllowlist({ kind: "off" });
    expect(s).toEqual({
      kind: "off",
      count: 0,
      video_count: 0,
      channel_count: 0,
      playlist_count: 0,
    });
  });

  test("active state → per-type counts", () => {
    const s = summarizeCommentTargetAllowlist({
      kind: "active",
      targets: [
        { type: "video", id: "dQw4w9WgXcQ" },
        { type: "video", id: "abc12345678" },
        { type: "channel", id: "UC1234567890abcdefghijkl" },
        { type: "playlist", id: "PLabc" },
      ],
    });
    expect(s).toEqual({
      kind: "active",
      count: 4,
      video_count: 2,
      channel_count: 1,
      playlist_count: 1,
    });
  });
});
