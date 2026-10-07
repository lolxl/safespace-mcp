// v1.106 — youtube_video_update (videos.update snippet metadata) handler tests.
// SDK-level mock via setGaxiosHandler. Security-relevant assertions:
//   - input validation (video_id / category_id regex, title non-empty, tags shape) pre-SDK
//   - tier=read defense-in-depth (denied_tier audit + scope_mismatch, handler not called)
//   - SAFESPACE_YOUTUBE_VIDEO_TARGETS default-deny gate (off=no_allowlist / miss=not_in_allowlist;
//     NO video_id echo; denial via errorCode, NOT a videoMutationMeta row)
//   - per-field outbound sanitize REJECT (denied_outbound_sanitize_rejected audit)
//   - F3a secret-shape on the combined text (autonomous → -32035)
//   - literal requestBody (part=["snippet"] ONLY; NEGATIVE sentinel: no status / no arg spread)
//   - REPLACE semantics (omitted description/tags → snippet key absent = clears)
//   - audit operation/hash/length shape

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, recorderSink } from "./test-audit";
import { youtubeVideoUpdate } from "./handlers";
import type { VideoMutationAuditMeta } from "../audit";
import { MCPError } from "../errors";
import type { ToolContext, YoutubeVideoUpdateEgressShape } from "./types";
import {
  __internal as videoTargets,
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
} from "../policy/youtube-video-targets";
import { ENV_AUTONOMOUS } from "../policy/autonomous-mode";

const VID = "dQw4w9WgXcQ"; // valid 11-char video id, allowlisted by default below
const OTHER_VID = "01234567890";

let captured: VideoMutationAuditMeta | undefined;

function makeCtx(tier: "read" | "write" | "share"): ToolContext {
  return {
    credential: oauthCred("alice@example.com", () => "fake-token"),
    tier,
    audit: recorderSink({ videoMutationMeta: (m) => { captured = m; } }),
  };
}

const WRITE_CTX = makeCtx("write");
const READ_CTX = makeCtx("read");

// B6.1 wave A2b — the allowlist/per-field-sanitize/F3a gate is now PIPELINE-FIRED
// (the MOVED gate cases live in tools/egress-pipeline.test.ts). A DIRECT handler call
// reads the gate's per-field SANITIZED snippet off ctx.egress (what withToolContext
// stores pre-handler); this helper supplies it for the requestBody-shape tests below.
function ctxWithEgress(egress: YoutubeVideoUpdateEgressShape): ToolContext {
  return {
    credential: oauthCred("alice@example.com", () => "fake-token"),
    tier: "write",
    audit: recorderSink({ videoMutationMeta: (m) => { captured = m; } }),
    egress,
  };
}

const ENV_KEYS = [ENV_TARGETS, ENV_TARGETS_EXTRA, ENV_AUTONOMOUS] as const;
let envBackup: Record<string, string | undefined>;

beforeEach(async () => {
  captured = undefined;
  envBackup = {};
  for (const k of ENV_KEYS) {
    envBackup[k] = process.env[k];
    delete process.env[k];
  }
  // Default: VID is allowlisted (happy-path tests). Deny tests override.
  process.env[ENV_TARGETS] = `video:${VID}`;
  videoTargets.resetSingletons();
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (envBackup[k] === undefined) delete process.env[k];
    else process.env[k] = envBackup[k];
  }
  videoTargets.resetSingletons();
});

async function noSdk(): Promise<() => boolean> {
  let called = false;
  const { setGaxiosHandler } = await import("../google-api/test-utils");
  setGaxiosHandler(async () => {
    called = true;
    return { data: {}, status: 200 };
  });
  return () => called;
}

describe("youtube_video_update — input validation (pre-SDK, plain Error)", () => {
  test("bad video_id rejected, echoes RULE not value, handler not called", async () => {
    const wasCalled = await noSdk();
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: "../x\r\n", title: "T", category_id: "22" }),
    ).rejects.toThrow(/video_id.*\^\[A-Za-z0-9_-\]\{11\}/);
    expect(wasCalled()).toBe(false);
  });

  test("empty title rejected", async () => {
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: VID, title: "   ", category_id: "22" }),
    ).rejects.toThrow(/non-empty 'title'/);
  });

  test("missing category_id rejected (API mandates it under REPLACE)", async () => {
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: VID, title: "T" }),
    ).rejects.toThrow(/category_id/);
  });

  test("non-numeric category_id rejected", async () => {
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: VID, title: "T", category_id: "abc" }),
    ).rejects.toThrow(/category_id/);
  });

  test("tags not an array rejected", async () => {
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: VID, title: "T", category_id: "22", tags: "nope" }),
    ).rejects.toThrow(/'tags'.*array/);
  });

  test("tags over the 50-entry cap rejected", async () => {
    await expect(
      youtubeVideoUpdate(WRITE_CTX, {
        video_id: VID,
        title: "T",
        category_id: "22",
        tags: Array.from({ length: 51 }, (_, i) => `t${i}`),
      }),
    ).rejects.toThrow(/exceeds 50 entries/);
  });
});

describe("youtube_video_update — tier gate (defense-in-depth)", () => {
  test("tier=read → scope_mismatch + audit denied_tier BEFORE throw, handler not called", async () => {
    const wasCalled = await noSdk();
    await expect(
      youtubeVideoUpdate(READ_CTX, { video_id: VID, title: "T", category_id: "22" }),
    ).rejects.toMatchObject({ errorName: "scope_mismatch" });
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.operation).toBe("video_update");
    expect(wasCalled()).toBe(false);
  });
});

// B6.1 wave A2b — the GATE cases (SAFESPACE_YOUTUBE_VIDEO_TARGETS default-deny off/miss;
// per-field outbound-sanitize REJECT; F3a secret-shape) MOVED to
// tools/egress-pipeline.test.ts (same assertions, driven through the registry-carried
// youtube_video_update descriptor). Validation + tier + requestBody-shape cases stay here.

describe("youtube_video_update — pipeline-bypass backstop (B6.1 wave A2b)", () => {
  test("ctx.egress ABSENT → internal_routing_error{invariant_violation}, NO SDK", async () => {
    const wasCalled = await noSdk();
    await expect(
      youtubeVideoUpdate(WRITE_CTX, { video_id: VID, title: "T", category_id: "22" }),
    ).rejects.toMatchObject({
      errorName: "internal_routing_error",
      errorData: { reason: "invariant_violation" },
    });
    expect(wasCalled()).toBe(false);
  });
});

describe("youtube_video_update — happy path + literal requestBody", () => {
  test("title+category only → part=[snippet], snippet={title,categoryId}; NO status/description/tags keys", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { id?: string; snippet?: Record<string, unknown> } = {};
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { id: VID }, status: 200 };
    });

    await youtubeVideoUpdate(ctxWithEgress({ kind: "youtube-video-update", videoId: VID, title: "New Title" }), {
      video_id: VID,
      title: "New Title",
      category_id: "22",
    });

    expect(params.part).toEqual(["snippet"]);
    expect(body.id).toBe(VID);
    expect(Object.keys(body.snippet ?? {}).sort()).toEqual(["categoryId", "title"]);
    expect(body.snippet?.title).toBe("New Title");
    expect(body.snippet?.categoryId).toBe("22");
    // NEGATIVE sentinel — no status part, no visibility field smuggled in
    expect("status" in body).toBe(false);
    expect("privacyStatus" in (body.snippet ?? {})).toBe(false);

    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.operation).toBe("video_update");
    expect(captured?.title_length).toBe("New Title".length);
    expect(captured?.description_length).toBeUndefined();
    expect(captured?.tag_count).toBeUndefined();
  });

  test("description + tags supplied → snippet carries them; audit length+count present", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: Record<string, unknown> } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: VID }, status: 200 };
    });

    await youtubeVideoUpdate(
      ctxWithEgress({
        kind: "youtube-video-update",
        videoId: VID,
        title: "T",
        description: "line one\nline two",
        tags: ["alpha", "beta"],
      }),
      {
        video_id: VID,
        title: "T",
        category_id: "27",
        description: "line one\nline two",
        tags: ["alpha", "beta"],
      },
    );

    expect(body.snippet?.description).toBe("line one\nline two");
    expect(body.snippet?.tags).toEqual(["alpha", "beta"]);
    expect(captured?.description_length).toBe("line one\nline two".length);
    expect(captured?.tag_count).toBe(2);
  });

  test("REPLACE semantics — caller-supplied unknown keys (e.g. status) never reach the requestBody", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: Record<string, unknown> } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: VID }, status: 200 };
    });

    await youtubeVideoUpdate(ctxWithEgress({ kind: "youtube-video-update", videoId: VID, title: "T" }), {
      video_id: VID,
      title: "T",
      category_id: "22",
      status: { privacyStatus: "public" },
      privacyStatus: "public",
    } as Record<string, unknown>);

    expect(Object.keys(body.snippet ?? {}).sort()).toEqual(["categoryId", "title"]);
    expect("status" in body).toBe(false);
  });
});
