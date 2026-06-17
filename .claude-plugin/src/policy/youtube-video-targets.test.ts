// v1.106 — SAFESPACE_YOUTUBE_VIDEO_TARGETS allowlist (youtube_video_update gate #3).
// Mirrors youtube-comment-targets.test.ts but video-only: `video:<id>` is the
// ONLY accepted prefix (channel: / playlist: reject), default-empty hard-deny.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  buildVideoTargetAllowlistState,
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
  getVideoTargetAllowlistState,
  isVideoTargetAllowed,
  parseVideoTargets,
  summarizeVideoTargetAllowlist,
} from "./youtube-video-targets";

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

const VID = "dQw4w9WgXcQ"; // valid 11-char video id

describe("parseVideoTargets", () => {
  test("undefined → empty result", () => {
    expect(parseVideoTargets(undefined)).toEqual({ ok: [], rejected: [] });
  });

  test("accepts a valid video:<id> entry (payload only in ok)", () => {
    const r = parseVideoTargets(`video:${VID}`);
    expect(r.ok).toEqual([VID]);
    expect(r.rejected).toEqual([]);
  });

  test("rejects channel: and playlist: (video-only allowlist)", () => {
    const r = parseVideoTargets("channel:UCabcdefghijklmnopqrstuv,playlist:PLabc");
    expect(r.ok).toEqual([]);
    expect(r.rejected.sort()).toEqual(
      ["channel:UCabcdefghijklmnopqrstuv", "playlist:PLabc"].sort(),
    );
  });

  test("rejects bare id, wrong-case prefix, and bad-length payload", () => {
    const r = parseVideoTargets(`${VID},Video:${VID},video:tooShort`);
    expect(r.ok).toEqual([]);
    expect(r.rejected.sort()).toEqual([VID, `Video:${VID}`, "video:tooShort"].sort());
  });

  test("trims surrounding whitespace + tolerates trailing commas", () => {
    const r = parseVideoTargets(`  video:${VID}  , ,`);
    expect(r.ok).toEqual([VID]);
  });

  test("dedupes identical tokens", () => {
    const r = parseVideoTargets(`video:${VID},video:${VID}`);
    expect(r.ok).toEqual([VID]);
  });

  test("rejects an entry with an extra colon", () => {
    const r = parseVideoTargets(`video:${VID}:extra`);
    expect(r.ok).toEqual([]);
    expect(r.rejected).toEqual([`video:${VID}:extra`]);
  });
});

describe("buildVideoTargetAllowlistState", () => {
  test("both undefined → off (policy not configured)", () => {
    expect(buildVideoTargetAllowlistState(undefined, undefined)).toEqual({ kind: "off" });
  });

  test("empty string → active with zero entries (explicit default-deny)", () => {
    const s = buildVideoTargetAllowlistState("", undefined);
    expect(s.kind).toBe("active");
    expect(summarizeVideoTargetAllowlist(s).count).toBe(0);
  });

  test("merges base + extra, deduped", () => {
    const s = buildVideoTargetAllowlistState(`video:${VID}`, `video:${VID},video:00000000000`);
    expect(s.kind).toBe("active");
    expect(summarizeVideoTargetAllowlist(s).count).toBe(2);
  });
});

describe("isVideoTargetAllowed (default-deny)", () => {
  test("off → false even for a well-formed id", () => {
    expect(isVideoTargetAllowed(VID, { kind: "off" })).toBe(false);
  });

  test("active + id present → true; absent → false", () => {
    const s = buildVideoTargetAllowlistState(`video:${VID}`, undefined);
    expect(isVideoTargetAllowed(VID, s)).toBe(true);
    expect(isVideoTargetAllowed("00000000000", s)).toBe(false);
  });

  test("empty/blank id → false", () => {
    const s = buildVideoTargetAllowlistState(`video:${VID}`, undefined);
    expect(isVideoTargetAllowed("", s)).toBe(false);
  });
});

describe("summarizeVideoTargetAllowlist (count-only, no values)", () => {
  test("off → {off,0}", () => {
    expect(summarizeVideoTargetAllowlist({ kind: "off" })).toEqual({ kind: "off", count: 0 });
  });
  test("active → count of distinct ids, no ids surfaced", () => {
    const s = buildVideoTargetAllowlistState(`video:${VID}`, undefined);
    const sum = summarizeVideoTargetAllowlist(s);
    expect(sum).toEqual({ kind: "active", count: 1 });
    expect(JSON.stringify(sum)).not.toContain(VID);
  });
});

describe("getVideoTargetAllowlistState (singleton + warnings)", () => {
  test("unset → off (load-once cached)", () => {
    expect(getVideoTargetAllowlistState()).toEqual({ kind: "off" });
  });

  test("EXTRA set without base → WARN-ONCE on stderr", () => {
    process.env[ENV_TARGETS_EXTRA] = `video:${VID}`;
    __internal.resetSingletons();
    const s = getVideoTargetAllowlistState();
    expect(s.kind).toBe("active");
    expect(capturedConsoleErrors.some((l) => l.includes("_EXTRA is set"))).toBe(true);
  });

  test("malformed entry → stderr warning at load", () => {
    process.env[ENV_TARGETS] = "channel:UCabcdefghijklmnopqrstuv";
    __internal.resetSingletons();
    getVideoTargetAllowlistState();
    expect(
      capturedConsoleErrors.some((l) => l.includes("rejected malformed entry")),
    ).toBe(true);
  });

  test("set but zero valid entries → hard-deny warning", () => {
    process.env[ENV_TARGETS] = "video:bad";
    __internal.resetSingletons();
    const s = getVideoTargetAllowlistState();
    expect(s.kind).toBe("active");
    expect(isVideoTargetAllowed(VID, s)).toBe(false);
    expect(capturedConsoleErrors.some((l) => l.includes("hard-denied"))).toBe(true);
  });
});
