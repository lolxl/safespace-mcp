// v1.48 B4 — YouTube playlists (5 tools, non-destructive).
// SDK-level mock via setGaxiosHandler. Security-relevant assertions:
// playlist_id / video_id / channel_id regex validation + title control-char +
// byte-cap + privacy-enum allowlist pre-SDK; handler-side tier re-check
// (denied_tier audit + scope_mismatch); literal requestBody construction
// (privacy default "private", no arg spread); audit operation + hash shape
// (create 2-step real-id override; item_insert carries both hashes).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, recorderSink } from "./test-audit";
import {
  youtubePlaylistsList,
  youtubePlaylistItemsList,
  youtubePlaylistCreate,
  youtubePlaylistUpdate,
  youtubePlaylistItemInsert,
  youtubePlaylistItemRemove,
  youtubePlaylistDelete,
} from "./handlers";
import type { PlaylistMutationAuditMeta } from "../audit";
import type { ToolContext } from "./types";

const VALID_PLAYLIST_ID = "PLabcdefghijklmnopqrstuvwxyz012345";
const VALID_VIDEO_ID = "dQw4w9WgXcQ";
const VALID_CHANNEL_ID = "UCabcdefghijklmnopqrstuv";
const VALID_PLAYLIST_ITEM_ID = "PLabcdefghijklmnopqrstuvwxyz012345.0123456789ABCDEF";

let capturedAll: PlaylistMutationAuditMeta[] = [];
let captured: PlaylistMutationAuditMeta | undefined;

function makeCtx(tier: "read" | "write" | "share"): ToolContext {
  return { allowedAccounts: null,
    credential: oauthCred("alice@example.com", () => "fake-token"),
    tier,
    audit: recorderSink({
      playlistMutationMeta: (m) => {
        capturedAll.push(m);
        captured = m;
      },
    }),
  };
}

const WRITE_CTX = makeCtx("write");
const READ_CTX = makeCtx("read");

beforeEach(async () => {
  capturedAll = [];
  captured = undefined;
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

// ───────────────────────── READ: youtube_playlists_list ─────────────────────
describe("youtube_playlists_list", () => {
  test("no channel_id → mine:true; returns res.data", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { items: [{ id: VALID_PLAYLIST_ID }] }, status: 200 };
    });

    const out = (await youtubePlaylistsList(READ_CTX, {})) as { items: unknown[] };
    expect(out.items).toHaveLength(1);
    expect(params.mine).toBeTruthy();
    expect(params.channelId).toBeUndefined();
  });

  test("channel_id → channelId param, mine NOT sent", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { items: [] }, status: 200 };
    });

    await youtubePlaylistsList(READ_CTX, { channel_id: VALID_CHANNEL_ID });
    expect(params.channelId).toBe(VALID_CHANNEL_ID);
    expect(params.mine).toBeUndefined();
  });

  test("max_results clamped to 50", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { items: [] }, status: 200 };
    });
    await youtubePlaylistsList(READ_CTX, { max_results: 9999 });
    expect(params.maxResults).toBe(50);
  });

  test("hostile channel_id rejected pre-SDK (echoes RULE not value)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistsList(READ_CTX, { channel_id: "../etc/passwd\r\n" }),
    ).rejects.toThrow(/channel_id.*\^UC/);
    expect(handlerCalled).toBe(false);
  });
});

// ─────────────────────── READ: youtube_playlist_items_list ──────────────────
describe("youtube_playlist_items_list", () => {
  test("happy path — playlistItems.list on the playlist", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { items: [{ id: "PLI_1" }] }, status: 200 };
    });
    const out = (await youtubePlaylistItemsList(READ_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
    })) as { items: unknown[] };
    expect(out.items).toHaveLength(1);
    expect(url).toContain("/playlistItems");
    expect(params.playlistId).toBe(VALID_PLAYLIST_ID);
  });

  test("missing / hostile playlist_id rejected pre-SDK", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(youtubePlaylistItemsList(READ_CTX, {})).rejects.toThrow(
      /playlist_id/,
    );
    await expect(
      youtubePlaylistItemsList(READ_CTX, { playlist_id: "../etc\r\n" }),
    ).rejects.toThrow(/playlist_id.*\^\(\?:PL\|UU/);
    expect(handlerCalled).toBe(false);
  });
});

// ─────────────────────── WRITE: youtube_playlist_create ─────────────────────
describe("youtube_playlist_create", () => {
  test("happy path — default private, literal body, 2-step audit ends on REAL id", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: Record<string, unknown>; status?: Record<string, unknown> } = {};
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: "PLcreatedREALid000000000000000000000", snippet: { title: "My list" } }, status: 200 };
    });

    const out = (await youtubePlaylistCreate(WRITE_CTX, { title: "My list" })) as {
      id: string;
    };
    expect(out.id).toBe("PLcreatedREALid000000000000000000000");
    expect(method).toBe("POST");
    // Literal body: default privacy=private, snippet keys ⊆ {title,description}.
    expect(body.status?.privacyStatus).toBe("private");
    expect(body.snippet?.title).toBe("My list");
    expect(Object.keys(body.snippet ?? {}).sort()).toEqual(["title"]);

    // 2-step: pre-call sentinel hash, then REAL id hash overrides (last wins).
    expect(capturedAll).toHaveLength(2);
    expect(capturedAll[0]?.target_playlist_hash).not.toBe(
      capturedAll[1]?.target_playlist_hash,
    );
    expect(captured?.operation).toBe("playlist_create");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_video_hash).toBeUndefined();
  });

  test("description forwarded; privacy_status=unlisted honored", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: Record<string, unknown>; status?: Record<string, unknown> } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: VALID_PLAYLIST_ID }, status: 200 };
    });
    await youtubePlaylistCreate(WRITE_CTX, {
      title: "T",
      description: "D",
      privacy_status: "unlisted",
    });
    expect(body.snippet?.description).toBe("D");
    expect(body.status?.privacyStatus).toBe("unlisted");
  });

  test("bad privacy_status rejected (allowlist); title control-char + byte cap rejected", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistCreate(WRITE_CTX, { title: "T", privacy_status: "secret" }),
    ).rejects.toThrow(/privacy_status.*allowlist/);
    await expect(
      youtubePlaylistCreate(WRITE_CTX, { title: "bad\r\ntitle" }),
    ).rejects.toThrow(/control characters/);
    await expect(
      youtubePlaylistCreate(WRITE_CTX, { title: "x".repeat(601) }),
    ).rejects.toThrow(/exceeds 600 bytes/);
    await expect(
      youtubePlaylistCreate(WRITE_CTX, { title: "" }),
    ).rejects.toThrow(/non-empty/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier (BEFORE throw, handler not called)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistCreate(READ_CTX, { title: "T" }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);
    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("playlist_create");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ─────────────────────── WRITE: youtube_playlist_update ─────────────────────
describe("youtube_playlist_update", () => {
  test("happy path — id in body, title required, status part only when privacy supplied", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { id?: string; snippet?: Record<string, unknown>; status?: unknown } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: VALID_PLAYLIST_ID }, status: 200 };
    });
    await youtubePlaylistUpdate(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
      title: "New title",
    });
    expect(body.id).toBe(VALID_PLAYLIST_ID);
    expect(body.snippet?.title).toBe("New title");
    // No privacy_status supplied → status omitted from the body.
    expect(body.status).toBeUndefined();

    expect(captured?.operation).toBe("playlist_update");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("privacy_status supplied → status block present", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { status?: { privacyStatus?: string } } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: VALID_PLAYLIST_ID }, status: 200 };
    });
    await youtubePlaylistUpdate(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
      title: "T",
      privacy_status: "public",
    });
    expect(body.status?.privacyStatus).toBe("public");
  });

  test("missing title rejected (REPLACE semantics); hostile playlist_id rejected", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistUpdate(WRITE_CTX, { playlist_id: VALID_PLAYLIST_ID }),
    ).rejects.toThrow(/title/);
    await expect(
      youtubePlaylistUpdate(WRITE_CTX, { playlist_id: "../x\r\n", title: "T" }),
    ).rejects.toThrow(/playlist_id.*\^\(\?:PL\|UU/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistUpdate(READ_CTX, { playlist_id: VALID_PLAYLIST_ID, title: "T" }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);
    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("playlist_update");
    expect(captured?.policy_decision).toBe("denied_tier");
  });
});

// ──────────────────── WRITE: youtube_playlist_item_insert ───────────────────
describe("youtube_playlist_item_insert", () => {
  test("happy path — literal resourceId, both hashes in audit", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: { playlistId?: string; resourceId?: Record<string, unknown> } } = {};
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: "PLI_new" }, status: 200 };
    });
    await youtubePlaylistItemInsert(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
      video_id: VALID_VIDEO_ID,
    });
    expect(method).toBe("POST");
    expect(body.snippet?.playlistId).toBe(VALID_PLAYLIST_ID);
    expect(body.snippet?.resourceId?.kind).toBe("youtube#video");
    expect(body.snippet?.resourceId?.videoId).toBe(VALID_VIDEO_ID);

    expect(captured?.operation).toBe("playlist_item_insert");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_video_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("position forwarded when provided", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { snippet?: { position?: number } } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: "PLI_new" }, status: 200 };
    });
    await youtubePlaylistItemInsert(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
      video_id: VALID_VIDEO_ID,
      position: 3,
    });
    expect(body.snippet?.position).toBe(3);
  });

  test("hostile video_id / playlist_id / bad position rejected pre-SDK", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistItemInsert(WRITE_CTX, {
        playlist_id: VALID_PLAYLIST_ID,
        video_id: "../etc/passwd",
      }),
    ).rejects.toThrow(/video_id.*\^\[A-Za-z0-9_-\]\{11\}/);
    await expect(
      youtubePlaylistItemInsert(WRITE_CTX, {
        playlist_id: "bad\r\n",
        video_id: VALID_VIDEO_ID,
      }),
    ).rejects.toThrow(/playlist_id/);
    await expect(
      youtubePlaylistItemInsert(WRITE_CTX, {
        playlist_id: VALID_PLAYLIST_ID,
        video_id: VALID_VIDEO_ID,
        position: -1,
      }),
    ).rejects.toThrow(/position/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier + both hashes", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      youtubePlaylistItemInsert(READ_CTX, {
        playlist_id: VALID_PLAYLIST_ID,
        video_id: VALID_VIDEO_ID,
      }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);
    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("playlist_item_insert");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_video_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ──────────────── v1.49 WRITE: youtube_playlist_item_remove ─────────────────
describe("youtube_playlist_item_remove", () => {
  test("happy path — playlistItems.delete by item id, audit (recoverable; no video hash)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: {}, status: 204 };
    });
    const out = (await youtubePlaylistItemRemove(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
      playlist_item_id: VALID_PLAYLIST_ITEM_ID,
    })) as { deleted: boolean; playlist_item_id: string };
    expect(out.deleted).toBe(true);
    expect(out.playlist_item_id).toBe(VALID_PLAYLIST_ITEM_ID);
    expect(method).toBe("DELETE");
    expect(url).toContain("/playlistItems");
    // SDK keys off the item id; playlist_id is forensic-only (NOT sent).
    expect(params.id).toBe(VALID_PLAYLIST_ITEM_ID);

    expect(captured?.operation).toBe("playlist_item_remove");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
    // PRESENCE-as-signal: no video hash on a remove row.
    expect(captured?.target_video_hash).toBeUndefined();
  });

  test("missing / hostile ids rejected pre-SDK (echo RULE not value)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 204 };
    });
    await expect(
      youtubePlaylistItemRemove(WRITE_CTX, { playlist_item_id: VALID_PLAYLIST_ITEM_ID }),
    ).rejects.toThrow(/playlist_id/);
    await expect(
      youtubePlaylistItemRemove(WRITE_CTX, {
        playlist_id: VALID_PLAYLIST_ID,
        playlist_item_id: "../etc/passwd\r\n",
      }),
    ).rejects.toThrow(/playlist_item_id.*\^\[A-Za-z0-9_\.\\-\]\{1,128\}/);
    await expect(
      youtubePlaylistItemRemove(WRITE_CTX, {
        playlist_id: "bad\r\n",
        playlist_item_id: VALID_PLAYLIST_ITEM_ID,
      }),
    ).rejects.toThrow(/playlist_id.*\^\(\?:PL\|UU/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier (BEFORE throw, handler not called)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 204 };
    });
    await expect(
      youtubePlaylistItemRemove(READ_CTX, {
        playlist_id: VALID_PLAYLIST_ID,
        playlist_item_id: VALID_PLAYLIST_ITEM_ID,
      }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);
    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("playlist_item_remove");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ──────────────────── v1.49 WRITE: youtube_playlist_delete ──────────────────
describe("youtube_playlist_delete", () => {
  test("happy path — playlists.delete by playlist id; PERMANENT; audit operation", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: {}, status: 204 };
    });
    const out = (await youtubePlaylistDelete(WRITE_CTX, {
      playlist_id: VALID_PLAYLIST_ID,
    })) as { deleted: boolean; playlist_id: string };
    expect(out.deleted).toBe(true);
    expect(out.playlist_id).toBe(VALID_PLAYLIST_ID);
    expect(method).toBe("DELETE");
    expect(url).toContain("/playlists");
    expect(params.id).toBe(VALID_PLAYLIST_ID);

    expect(captured?.operation).toBe("playlist_delete");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_video_hash).toBeUndefined();
  });

  test("audit allow-meta recorded BEFORE the SDK call (survives a 5xx)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw Object.assign(new Error("boom"), { response: { status: 500 } });
    });
    await expect(
      youtubePlaylistDelete(WRITE_CTX, { playlist_id: VALID_PLAYLIST_ID }),
    ).rejects.toThrow();
    // The forensic row was captured before the SDK threw.
    expect(captured?.operation).toBe("playlist_delete");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("missing / hostile playlist_id rejected pre-SDK (no PII echo)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 204 };
    });
    await expect(youtubePlaylistDelete(WRITE_CTX, {})).rejects.toThrow(/playlist_id/);
    await expect(
      youtubePlaylistDelete(WRITE_CTX, { playlist_id: "../etc\r\n" }),
    ).rejects.toThrow(/playlist_id.*\^\(\?:PL\|UU/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier (recovery-bias does NOT bypass tier)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 204 };
    });
    await expect(
      youtubePlaylistDelete(READ_CTX, { playlist_id: VALID_PLAYLIST_ID }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);
    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("playlist_delete");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_playlist_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});
