// B6.1 wave A1 — pipeline-fired egress descriptor tests.
// B6.1 wave A2a — extended with the TRANSFORMING, OAuth-routed x_post_create
// descriptor (fired by withToolContext) + requireEgressResult + the 401-retry
// egress carry-forward.
//
// Layers:
//   1. MOVED gate cases — the per-connector "egress gates" cases that used to drive
//      each send HANDLER directly (handlers/line.test.ts / telegram.test.ts /
//      discord.test.ts / slack.test.ts / ../mattermost.test.ts; A2a adds
//      handlers/x.test.ts). The handlers no longer call the gate (it is
//      pipeline-fired), so the SAME assertions now drive each tool's
//      registry-carried egress descriptor (extract → gate).
//   2. NEW pipeline pins — (i) extract precedes gate at the production choke point
//      (a validation plain-Error wins over a recipient denial), (ii) the gate fires
//      via withNonOAuthContext BEFORE the handler (denial pre-handler; on a pass the
//      handler observes ctx.egressGateFired === true at entry), (iii) slack's gate
//      input is the RAW text (escapeSlackText is wire-only — the SOURCE-wins pin).
//   3. A2a pins — the x gate RETURNS the sanitized text; withToolContext stores it
//      on ctx.egress pre-handler; the handler wires the PIPELINE result;
//      requireEgressResult fails loud when the pipeline was bypassed; the 401-retry
//      ctx rebuild CARRIES egressGateFired/egress instead of re-firing.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import { ENV_LINE_ALLOW, ENV_LINE_ALLOW_EXTRA } from "../policy/line-recipient-allowlist";
import { ENV_TG_ALLOW, ENV_TG_ALLOW_EXTRA } from "../policy/telegram-recipient-allowlist";
import { ENV_DC_ALLOW, ENV_DC_ALLOW_EXTRA } from "../policy/discord-recipient-allowlist";
import { ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA } from "../policy/slack-recipient-allowlist";
import { ENV_MM_ALLOW, ENV_MM_ALLOW_EXTRA } from "../policy/mattermost-recipient-allowlist";
import { __resetWriteBurstForTests } from "../policy/write-burst";
import { ENV_X_POST_ACCOUNTS, ENV_X_POST_ACCOUNTS_EXTRA } from "../config";
import { __internal as xPostAllowlist } from "../policy/x-post-allowlist";
import {
  __resetXBackendForTests,
  addXAccount,
  tokenPayloadFromGrant,
  writeXToken,
} from "../auth/x/oauth";
import {
  requireEgressResult,
  type EgressDescriptor,
  type EgressShape,
} from "./egress-pipeline";
import { TOOL_REGISTRY } from "./registry";
import { NOOP_AUDIT, capturingAudit, oauthCred, serviceTokenCred } from "./test-audit";
import type { CapturingAudit } from "./test-audit";
import { __internal as commentTargets } from "../policy/youtube-comment-targets";
import {
  __internal as videoTargets,
  ENV_TARGETS as ENV_VIDEO_TARGETS,
  ENV_TARGETS_EXTRA as ENV_VIDEO_TARGETS_EXTRA,
} from "../policy/youtube-video-targets";
import {
  __resetCommentBurstForTest,
  getCommentBurstCount,
  incrementCommentBurst,
} from "../policy/youtube-comment-burst";
import type { GmailComposeEgressShape, ToolContext, YoutubeVideoUpdateEgressShape } from "./types";
import type { UpstreamError } from "./handlers/shared";
import type { RecipientResolver } from "./source";
import { googleWorkspace } from "./source";
import { gmailCreateDraft, gmailSend } from "./handlers";
import { xPostCreate } from "./handlers/x";
import { youtubeVideoCommentPost, youtubeVideoUpdate } from "./handlers/youtube";
import { withNonOAuthContext } from "./with-nonoauth-context";
import { withToolContext, type WithContextDeps } from "./with-context";
import { loadPendingSends, pendingSendsPath } from "../auth/send-approval-store";

// ── recipient fixtures (all syntactically valid for their connector) ───────────
const LINE_TO = "U" + "0".repeat(32);
const LINE_OTHER = "U" + "9".repeat(32);
const TG_CHAT = "123456789";
const TG_OTHER = "987654321";
const DC_CHAN = "12345678901234567";
const DC_OTHER = "98765432109876543";
const SK_CHAN = "C0123456789";
const SK_OTHER = "C9876543210";
const MM_CHAN = "abcdefghijklmnopqrstuvwxyz";

const SECRET_BODY = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";

function gateCtx(): ToolContext {
  return {
    credential: serviceTokenCred(() => "tok"),
    tier: "share",
    audit: NOOP_AUDIT,
  };
}

/** The registry-carried descriptor — the SAME object the choke point fires. */
function descriptorFor(tool: string): EgressDescriptor {
  const d = TOOL_REGISTRY[tool]?.egress;
  if (d === undefined) throw new Error(`no egress descriptor on ${tool}`);
  return d;
}

/** extract → gate, exactly the choke-point sequence. */
async function fire(tool: string, ctx: ToolContext, args: Record<string, unknown>): Promise<void> {
  const d = descriptorFor(tool);
  await d.gate(ctx, d.extract(args));
}

const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_AUTONOMOUS",
  "SAFESPACE_REQUIRE_SEND_APPROVAL",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_SECRET_PASSPHRASE",
  "SAFESPACE_LINE_CHANNEL_TOKEN",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  ENV_LINE_ALLOW,
  ENV_LINE_ALLOW_EXTRA,
  ENV_TG_ALLOW,
  ENV_TG_ALLOW_EXTRA,
  ENV_DC_ALLOW,
  ENV_DC_ALLOW_EXTRA,
  ENV_SK_ALLOW,
  ENV_SK_ALLOW_EXTRA,
  ENV_MM_ALLOW,
  ENV_MM_ALLOW_EXTRA,
  ENV_X_POST_ACCOUNTS,
  ENV_X_POST_ACCOUNTS_EXTRA,
  // B6.1 wave A2b — youtube gate env (GOOGLE_CLIENT_ID/SECRET already listed above)
  "SAFESPACE_TIER",
  "SAFESPACE_YOUTUBE_COMMENT_TARGETS",
  "SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA",
  "SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT",
  ENV_VIDEO_TARGETS,
  ENV_VIDEO_TARGETS_EXTRA,
];
let tmpDir: string;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  // A gate denial writes an audit denied-event → give it a tmp config dir
  // (mirrors the moved handler suites' scaffolding).
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-egress-pipe-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  __resetWriteBurstForTests();
  // A2a — the x allowlist + the x store backend memoize off env; re-derive per test.
  xPostAllowlist.resetSingletons();
  __resetXBackendForTests();
  // B6.1 wave A2b — youtube gate singletons (allowlist caches + burst counter).
  commentTargets.resetSingletons();
  videoTargets.resetSingletons();
  __resetCommentBurstForTest();
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetWriteBurstForTests();
  xPostAllowlist.resetSingletons();
  __resetXBackendForTests();
  commentTargets.resetSingletons();
  videoTargets.resetSingletons();
  __resetCommentBurstForTest();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

// ── 1. MOVED gate cases (same assertions; now driven via the descriptor) ───────

describe("line_push_message — egress gates (moved from handlers/line.test.ts)", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy", async () => {
    process.env[ENV_LINE_ALLOW] = LINE_OTHER; // active allowlist excluding LINE_TO
    await expect(
      fire("line_push_message", gateCtx(), { to: LINE_TO, text: "x" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
  });

  test("recipient IN the allowlist → allowed (gate resolves)", async () => {
    process.env[ENV_LINE_ALLOW] = LINE_TO;
    const ctx = gateCtx();
    await fire("line_push_message", ctx, { to: LINE_TO, text: "x" });
    expect(ctx.egressGateFired).toBe(true);
  });

  test("autonomous + secret-shape body → outbound_secret_rejected", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_LINE_ALLOW] = LINE_TO; // allow the recipient so secret-shape is the gate
    await expect(
      fire("line_push_message", gateCtx(), { to: LINE_TO, text: SECRET_BODY }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });
});

describe("telegram_send_message — egress gates (moved from handlers/telegram.test.ts)", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy", async () => {
    process.env[ENV_TG_ALLOW] = TG_OTHER; // active allowlist excluding TG_CHAT
    await expect(
      fire("telegram_send_message", gateCtx(), { chat_id: TG_CHAT, text: "x" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
  });

  test("recipient IN the allowlist → allowed (gate resolves)", async () => {
    process.env[ENV_TG_ALLOW] = TG_CHAT;
    const ctx = gateCtx();
    await fire("telegram_send_message", ctx, { chat_id: TG_CHAT, text: "x" });
    expect(ctx.egressGateFired).toBe(true);
  });

  test("autonomous + secret-shape body → outbound_secret_rejected", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_TG_ALLOW] = TG_CHAT; // allow the recipient so secret-shape is the gate
    await expect(
      fire("telegram_send_message", gateCtx(), { chat_id: TG_CHAT, text: SECRET_BODY }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });
});

describe("discord_send_message — egress gates (moved from handlers/discord.test.ts)", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy", async () => {
    process.env[ENV_DC_ALLOW] = DC_OTHER; // active allowlist excluding DC_CHAN
    await expect(
      fire("discord_send_message", gateCtx(), { channel_id: DC_CHAN, content: "x" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
  });

  test("recipient IN the allowlist → allowed (gate resolves)", async () => {
    process.env[ENV_DC_ALLOW] = DC_CHAN;
    const ctx = gateCtx();
    await fire("discord_send_message", ctx, { channel_id: DC_CHAN, content: "x" });
    expect(ctx.egressGateFired).toBe(true);
  });

  test("autonomous + secret-shape body → outbound_secret_rejected", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_DC_ALLOW] = DC_CHAN; // allow the recipient so secret-shape is the gate
    await expect(
      fire("discord_send_message", gateCtx(), { channel_id: DC_CHAN, content: SECRET_BODY }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });
});

describe("slack_send_message — egress gates (moved from handlers/slack.test.ts)", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy", async () => {
    process.env[ENV_SK_ALLOW] = SK_OTHER; // active allowlist excluding SK_CHAN
    await expect(
      fire("slack_send_message", gateCtx(), { channel: SK_CHAN, text: "x" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
  });

  test("recipient IN the allowlist → allowed (gate resolves)", async () => {
    process.env[ENV_SK_ALLOW] = SK_CHAN;
    const ctx = gateCtx();
    await fire("slack_send_message", ctx, { channel: SK_CHAN, text: "x" });
    expect(ctx.egressGateFired).toBe(true);
  });

  test("autonomous + secret-shape body → outbound_secret_rejected", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_SK_ALLOW] = SK_CHAN; // allow the recipient so secret-shape is the gate
    await expect(
      fire("slack_send_message", gateCtx(), { channel: SK_CHAN, text: SECRET_BODY }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });
});

describe("mattermost_send_message — egress gates (moved from ../mattermost.test.ts)", () => {
  test("autonomous + secret-shape in message → outbound_secret_rejected (F3a)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    await expect(
      fire("mattermost_send_message", gateCtx(), { channel_id: MM_CHAN, message: "key AKIAIOSFODNN7EXAMPLE" }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });

  test("autonomous + channel NOT in allowlist → recipient_denied_by_policy", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true"; // off→deny under autonomous
    await expect(
      fire("mattermost_send_message", gateCtx(), { channel_id: MM_CHAN, message: "hi" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
  });
});

// ── 2. NEW pipeline pins ────────────────────────────────────────────────────────

describe("pipeline choke-point order + firing (withNonOAuthContext, line fixture style)", () => {
  test("(i) extract precedes gate: invalid args + denied recipient → the VALIDATION plain-Error wins", async () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // hermetic — no Keychain
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    process.env[ENV_LINE_ALLOW] = LINE_OTHER; // the gate WOULD deny — but extract throws first
    let handlerRan = false;
    await expect(
      withNonOAuthContext("line_push_message", { to: "not-a-line-id", text: "x" }, async () => {
        handlerRan = true;
        return { sent: true };
      }),
    ).rejects.toThrow(/'to' must be a valid LINE id/);
    expect(handlerRan).toBe(false);
  });

  test("(ii-a) denied recipient via the production choke point → -32019, handler never runs", async () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    process.env[ENV_LINE_ALLOW] = LINE_OTHER; // active allowlist EXCLUDING LINE_TO
    let handlerRan = false;
    let caught: unknown;
    try {
      await withNonOAuthContext("line_push_message", { to: LINE_TO, text: "hi" }, async () => {
        handlerRan = true;
        return { sent: true };
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("recipient_denied_by_policy");
    expect((caught as MCPError).code).toBe(-32019);
    expect(handlerRan).toBe(false); // the gate fired at the pipeline, pre-handler
  });

  test("(ii-b) allowed recipient: the pipeline-fired gate has run BEFORE the handler (egressGateFired at entry)", async () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    process.env[ENV_LINE_ALLOW] = LINE_TO;
    let firedAtHandlerEntry: boolean | undefined;
    const result = await withNonOAuthContext("line_push_message", { to: LINE_TO, text: "hi" }, async (ctx) => {
      firedAtHandlerEntry = ctx.egressGateFired;
      return { sent: true };
    });
    expect(result).toBeDefined();
    expect(firedAtHandlerEntry).toBe(true);
  });
});

describe("slack — the gate input is the RAW text (SOURCE-wins pin)", () => {
  test("(iii) extract returns the raw text unescaped — escapeSlackText is wire-only, applied later in the handler", () => {
    // Pre-A1 the handler passed the gate the RAW text and escaped only the wire
    // body (handlers/slack.ts). The descriptor must reproduce that byte-identically:
    // the shape the choke point hands the gate is exactly extract's return value.
    const raw = "ping <!channel> & <https://example.com|click>";
    // B6.1 wave A2b — narrow to the service-token shape (EgressShape now also unions the
    // bodyless YoutubeVideoUpdateEgressShape, so a bare `.body` on the union no longer
    // type-resolves).
    const shape = descriptorFor("slack_send_message").extract({
      channel: SK_CHAN,
      text: raw,
    }) as { kind: "service-token"; recipient: string; body: string };
    expect(shape).toEqual({ kind: "service-token", recipient: SK_CHAN, body: raw });
    expect(shape.body).not.toContain("&lt;"); // NOT the escaped wire form
    expect(shape.body).not.toContain("&amp;");
  });
});

// ── 3. B6.1 wave A2a — x_post_create: the TRANSFORMING, OAuth-routed descriptor ──

const X_USER = "2244994945";
const X_OTHER = "1111111111";
// NFC-transformable fixture: outboundSanitize step 2 (NFC normalize) rewrites the
// decomposed form (e + U+0301 combining acute) to the precomposed one (U+00E9) — a
// deterministic, observable transform (same property the sanitize/outbound suite
// relies on), so "the wire carries the GATE's return, not the raw input" is provable.
const X_RAW_DECOMPOSED = "cafe\u0301"; // e + combining acute (NFD)
const X_NFC_PRECOMPOSED = "caf\u00e9"; // precomposed e-acute (NFC)

function xGateCtx(): ToolContext {
  return {
    credential: {
      kind: "oauth",
      provider: "x",
      accountId: X_USER,
      getAccessToken: () => "x-tok",
    },
    tier: "write",
    audit: NOOP_AUDIT,
  };
}

/** Seed the x store (file backend inside the per-test tmp config dir) with one
 *  account + a FRESH token, so withToolContext's resolveAccount / resolveCredential
 *  run for real with ZERO network (a fresh token skips the proactive refresh). */
async function seedXAccount(): Promise<void> {
  process.env.SAFESPACE_SECRET_BACKEND = "file"; // hermetic — no Keychain
  __resetXBackendForTests();
  await addXAccount({ id: X_USER, username: "tester" });
  await writeXToken(
    X_USER,
    tokenPayloadFromGrant({
      access_token: "x-access-tok",
      refresh_token: "x-refresh-tok",
      expires_in: 7200,
    }),
  );
}

describe("x_post_create — egress gates (moved from handlers/x.test.ts)", () => {
  test("EMPTY allowlist → x_post_denied_by_policy{no_allowlist} (default-deny)", async () => {
    await expect(
      fire("x_post_create", xGateCtx(), { text: "should never post" }),
    ).rejects.toMatchObject({
      errorName: "x_post_denied_by_policy",
      errorData: { reason: "no_allowlist", tool: "x_post_create" },
    });
  });

  test("active allowlist + non-matching account → not_in_allowlist; NEVER echoes ids or text", async () => {
    process.env[ENV_X_POST_ACCOUNTS] = X_OTHER; // not X_USER
    xPostAllowlist.resetSingletons();
    let thrown: unknown;
    await fire("x_post_create", xGateCtx(), { text: "secret-text" }).catch((e) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("x_post_denied_by_policy");
    expect((thrown as MCPError).errorData).toMatchObject({ reason: "not_in_allowlist" });
    const s = JSON.stringify(thrown);
    expect(s).not.toContain(X_USER);
    expect(s).not.toContain("secret-text");
    expect(s).not.toContain(X_OTHER);
  });

  test("allowed account: the gate RETURNS the sanitized (NFC-normalized) text — the transforming case", async () => {
    process.env[ENV_X_POST_ACCOUNTS] = X_USER;
    xPostAllowlist.resetSingletons();
    const ctx = xGateCtx();
    const d = descriptorFor("x_post_create");
    const out = await d.gate(ctx, d.extract({ text: X_RAW_DECOMPOSED }));
    expect(ctx.egressGateFired).toBe(true);
    expect(out).toEqual({ kind: "x-post", body: X_NFC_PRECOMPOSED });
    expect((out as { body: string }).body).not.toBe(X_RAW_DECOMPOSED);
  });
});

describe("requireEgressResult — the transforming handler's narrow", () => {
  test("ctx.egress ABSENT → internal_routing_error{invariant_violation}", () => {
    let thrown: unknown;
    try {
      requireEgressResult(xGateCtx(), "x-post");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("internal_routing_error");
    expect((thrown as MCPError).errorData).toMatchObject({ reason: "invariant_violation" });
  });

  test("ctx.egress present → returns the stored shape verbatim", () => {
    const ctx = xGateCtx();
    const shape: EgressShape = { kind: "x-post", body: "vetted" };
    ctx.egress = shape;
    expect(requireEgressResult(ctx, "x-post")).toBe(shape);
  });

  test("A2b sec-rev: ctx.egress carries the WRONG kind → internal_routing_error, kinds never echoed, ZERO fetch (handler vehicle)", async () => {
    // A mis-wired pipeline stored ANOTHER tool's shape (a youtube-comment shape on an
    // x_post_create call). The kind discriminant must fail LOUD — never a silent
    // wrong-shape read (`.body` here happens to exist on both; the guard is the
    // discriminant, not field luck) — and the wire must never be touched.
    const ctx = xGateCtx();
    ctx.egress = { kind: "youtube-comment", videoId: "dQw4w9WgXcQ", body: "smuggled" };
    let fetchCalls = 0;
    const fetchImpl = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 201 });
    }) as unknown as typeof fetch;
    let thrown: unknown;
    await xPostCreate(ctx, { text: "hi" }, { fetchImpl }).catch((e) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("internal_routing_error");
    expect((thrown as MCPError).errorData).toMatchObject({ reason: "invariant_violation" });
    // No-echo posture: neither the expected nor the found kind leaks.
    const serialized = JSON.stringify(thrown);
    expect(serialized).not.toContain("x-post");
    expect(serialized).not.toContain("youtube-comment");
    expect(fetchCalls).toBe(0);
  });
});

describe("x_post_create — pipeline choke point (withToolContext, real registry def)", () => {
  test("(iv-a) the choke point stores the gate's transformed return on ctx.egress BEFORE the handler", async () => {
    await seedXAccount();
    process.env[ENV_X_POST_ACCOUNTS] = X_USER;
    xPostAllowlist.resetSingletons();
    let egressAtEntry: EgressShape | undefined;
    let firedAtEntry: boolean | undefined;
    await withToolContext("x_post_create", { text: X_RAW_DECOMPOSED }, async (hctx) => {
      egressAtEntry = hctx.egress;
      firedAtEntry = hctx.egressGateFired;
      return { data: { id: "1" } };
    });
    expect(firedAtEntry).toBe(true);
    expect(egressAtEntry).toEqual({ kind: "x-post", body: X_NFC_PRECOMPOSED });
  });

  test("(iv-b) allowlist denial fires AT the choke point — handler never runs (deny before any network)", async () => {
    await seedXAccount();
    // Allowlist unset → default-deny.
    let handlerRan = false;
    await expect(
      withToolContext("x_post_create", { text: "hi" }, async () => {
        handlerRan = true;
        return {};
      }),
    ).rejects.toMatchObject({
      errorName: "x_post_denied_by_policy",
      errorData: { reason: "no_allowlist" },
    });
    expect(handlerRan).toBe(false);
  });

  test("(iv-c) extract precedes gate: invalid text + empty allowlist → the VALIDATION plain-Error wins", async () => {
    await seedXAccount();
    let handlerRan = false;
    await expect(
      withToolContext("x_post_create", { text: "" }, async () => {
        handlerRan = true;
        return {};
      }),
    ).rejects.toThrow(/'text' must be a non-empty string/);
    expect(handlerRan).toBe(false);
  });

  test("(iv-d) END-TO-END: the wire body is the PIPELINE's sanitized text (fetch captures the gate's return)", async () => {
    await seedXAccount();
    process.env[ENV_X_POST_ACCOUNTS] = X_USER;
    xPostAllowlist.resetSingletons();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: unknown, init?: unknown) => {
      calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
      return new Response(JSON.stringify({ data: { id: "9", text: X_NFC_PRECOMPOSED } }), {
        status: 201,
      });
    }) as unknown as typeof fetch;
    await withToolContext("x_post_create", { text: X_RAW_DECOMPOSED }, (hctx, hargs) =>
      xPostCreate(hctx, hargs, { fetchImpl }),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.x.com/2/tweets");
    // The wire body is EXACTLY the gate's sanitized return — the NFC-normalized
    // text, NOT the raw decomposed input the args carried.
    expect(calls[0]!.init.body).toBe(JSON.stringify({ text: X_NFC_PRECOMPOSED }));
    expect(calls[0]!.init.body).not.toBe(JSON.stringify({ text: X_RAW_DECOMPOSED }));
    expect((calls[0]!.init.headers as Record<string, string>).Authorization).toBe(
      "Bearer x-access-tok",
    );
  });
});

describe("401-retry ctx rebuild carries the pipeline egress fields (B6.1 wave A2a)", () => {
  test("egressGateFired + egress set before a 401 survive onto the rebuilt retry ctx (google fixture, non-egress tool)", async () => {
    // The x source is refreshable:false (no in-band 401 retry) and no refreshable
    // pipeline tool exists until wave A2b — so the rebuild path is driven with the
    // google fixture on a NON-egress tool, proving the rebuilt ctx literal carries
    // the two fields when set. The handler simulates the pipeline's pre-retry-loop
    // writes on its FIRST attempt (the same `let ctx` instance the pipeline writes
    // to), throws a 401, and the retried call observes the CARRIED values.
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    const email = "b61a2a-carry@example.com";
    const tokenSet = {
      refresh_token: "rt",
      access_token: "old-access-token",
      expires_at: Date.now() + 60 * 60_000,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      obtained_at: Date.now(),
    };
    const store = new Map<string, string>([[email, JSON.stringify(tokenSet)]]);
    const deps: WithContextDeps = {
      async getToken(e: string) {
        return store.get(e) ?? null;
      },
      async setToken(e: string, json: string) {
        store.set(e, json);
      },
      async deleteToken(e: string) {
        store.delete(e);
      },
      async removeAccount() {},
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({ access_token: "new-access-token", expires_in: 3600 }),
          { status: 200 },
        )) as unknown as typeof fetch,
      loadIndexImpl: async () => ({ accounts: [{ email }] }),
    };
    let attempt = 0;
    let carriedFired: boolean | undefined;
    let carriedEgress: EgressShape | undefined;
    await withToolContext(
      "gmail_search",
      { query: "x", account_id: email },
      async (hctx) => {
        attempt++;
        if (attempt === 1) {
          hctx.egressGateFired = true;
          hctx.egress = { kind: "x-post", body: "vetted" };
          const e: UpstreamError = new Error("upstream_401");
          e.httpStatus = 401;
          throw e;
        }
        carriedFired = hctx.egressGateFired;
        carriedEgress = hctx.egress;
        return "ok";
      },
      deps,
    );
    expect(attempt).toBe(2);
    expect(carriedFired).toBe(true);
    expect(carriedEgress).toEqual({ kind: "x-post", body: "vetted" });
  });

  test("sendApprovalConsumedFingerprint survives the 401-retry ctx rebuild", async () => {
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    const email = "b61a2a-appr-carry@example.com";
    const tokenSet = {
      refresh_token: "rt",
      access_token: "old-access-token",
      expires_at: Date.now() + 60 * 60_000,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      obtained_at: Date.now(),
    };
    const store = new Map<string, string>([[email, JSON.stringify(tokenSet)]]);
    const deps: WithContextDeps = {
      async getToken(e: string) {
        return store.get(e) ?? null;
      },
      async setToken(e: string, json: string) {
        store.set(e, json);
      },
      async deleteToken(e: string) {
        store.delete(e);
      },
      async removeAccount() {},
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({ access_token: "new-access-token", expires_in: 3600 }),
          { status: 200 },
        )) as unknown as typeof fetch,
      loadIndexImpl: async () => ({ accounts: [{ email }] }),
    };
    let attempt = 0;
    let carried: string | undefined;
    await withToolContext(
      "gmail_search",
      { query: "x", account_id: email },
      async (hctx) => {
        attempt++;
        if (attempt === 1) {
          hctx.sendApprovalConsumedFingerprint = "ab".repeat(32);
          const e: UpstreamError = new Error("upstream_401");
          e.httpStatus = 401;
          throw e;
        }
        carried = hctx.sendApprovalConsumedFingerprint;
        return "ok";
      },
      deps,
    );
    expect(attempt).toBe(2);
    expect(carried).toBe("ab".repeat(32));
  });
});

// ── 4. B6.1 wave A2b — YouTube comment + video writes (TRANSFORMING, OAuth-routed) ──
//
// The 3 youtube public-surface writes migrated onto pipeline-fired egress. These are
// the GATE cases MOVED from handlers.test.ts (youtubeVideoCommentPost / youtubeCommentReply
// blocks) + youtube-video-update.test.ts, driven through the registry-carried descriptor
// (extract → gate) exactly as the choke point fires them. Plus the LOAD-BEARING
// end-to-end 401-retry carry-forward proof (youtube is the FIRST refreshable pipeline
// tool — closes wave A2a's deferred LOW).

const YT_VID = "dQw4w9WgXcQ";
const YT_OTHER_VID = "abcDEF12345"; // a valid 11-char id that is NOT YT_VID
const YT_PARENT = "Ugxabc123_parent";
// NFC-transformable fixture (as in the x section): outboundSanitize step 2 (NFC) rewrites
// the decomposed "café" to the precomposed "café" — a deterministic, observable
// transform proving the wire carries the GATE's return, not the raw input.
const YT_RAW_DECOMPOSED = "café";
const YT_NFC_PRECOMPOSED = "café";

function ytCtx(): { ctx: ToolContext; cap: CapturingAudit } {
  const cap = capturingAudit();
  return {
    ctx: { credential: oauthCred(), tier: "write", audit: cap.sink },
    cap,
  };
}

describe("youtube_video_comment_post — egress gates (moved from handlers.test.ts)", () => {
  test("video NOT in an active allowlist → comment_target_denied_by_policy + audit denied_not_in_allowlist; NEVER echoes video_id", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_OTHER_VID}`;
    commentTargets.resetSingletons();
    const { ctx, cap } = ytCtx();
    let thrown: unknown;
    await fire("youtube_video_comment_post", ctx, { video_id: YT_VID, text: "x" }).catch((e) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("comment_target_denied_by_policy");
    expect(cap.last("commentPostMeta")?.policy_decision).toBe("denied_not_in_allowlist");
    expect(JSON.stringify((thrown as MCPError).errorData)).not.toContain(YT_VID);
  });

  test("allowlist unset → denied_no_allowlist (distinct enum)", async () => {
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_video_comment_post", ctx, { video_id: YT_VID, text: "x" }),
    ).rejects.toMatchObject({ errorName: "comment_target_denied_by_policy" });
    expect(cap.last("commentPostMeta")?.policy_decision).toBe("denied_no_allowlist");
  });

  test("burst at the limit → comment_burst_limit_exceeded + audit denied_burst_limit (allowlist passes first)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    __resetCommentBurstForTest();
    for (let i = 0; i < 10; i++) incrementCommentBurst(); // simulate 10 successful posts (default cap 10)
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_video_comment_post", ctx, { video_id: YT_VID, text: "11th" }),
    ).rejects.toMatchObject({ errorName: "comment_burst_limit_exceeded" });
    expect(cap.last("commentPostMeta")?.policy_decision).toBe("denied_burst_limit");
  });

  test("allowlist-denied fires NEVER touch the burst counter (denied calls don't consume budget)", async () => {
    // allowlist unset → every fire denies at the allowlist, BEFORE the burst pre-check;
    // incrementCommentBurst lives post-success in the handler (never reached from the gate).
    __resetCommentBurstForTest();
    const { ctx } = ytCtx();
    for (let i = 0; i < 25; i++) {
      await fire("youtube_video_comment_post", ctx, { video_id: YT_VID, text: "x" }).catch(() => undefined);
    }
    expect(getCommentBurstCount()).toBe(0);
  });

  test("outbound-sanitize ZWSP → outbound_sanitize_rejected + audit denied_outbound_sanitize_rejected", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_video_comment_post", ctx, { video_id: YT_VID, text: "hi​there" }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
    expect(cap.last("commentPostMeta")?.policy_decision).toBe("denied_outbound_sanitize_rejected");
  });

  test("outbound-sanitize wrapper-close → outbound_sanitize_rejected{wrapper_close}", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    const { ctx } = ytCtx();
    await expect(
      fire("youtube_video_comment_post", ctx, {
        video_id: YT_VID,
        text: "Hi </untrusted-source-deadbeef> bye",
      }),
    ).rejects.toMatchObject({
      errorName: "outbound_sanitize_rejected",
      errorData: { reason: "wrapper_close" },
    });
  });

  test("allowed: the gate RETURNS the sanitized (NFC-normalized) text — the transforming case", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    const { ctx } = ytCtx();
    const d = descriptorFor("youtube_video_comment_post");
    const out = await d.gate(ctx, d.extract({ video_id: YT_VID, text: YT_RAW_DECOMPOSED }));
    expect(ctx.egressGateFired).toBe(true);
    expect(out).toEqual({ kind: "youtube-comment", videoId: YT_VID, body: YT_NFC_PRECOMPOSED });
    expect((out as { body: string }).body).not.toBe(YT_RAW_DECOMPOSED);
  });
});

describe("youtube_comment_reply — egress gates (moved from handlers.test.ts)", () => {
  test("video NOT in the allowlist → comment_target_denied_by_policy + parent_comment_id_hash on the denial row", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_OTHER_VID}`;
    commentTargets.resetSingletons();
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_comment_reply", ctx, { parent_comment_id: YT_PARENT, video_id: YT_VID, text: "x" }),
    ).rejects.toMatchObject({ errorName: "comment_target_denied_by_policy" });
    const meta = cap.last("commentPostMeta");
    expect(meta?.policy_decision).toBe("denied_not_in_allowlist");
    expect(meta?.parent_comment_id_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("the burst counter is SHARED across post + reply (both gates read the same module counter)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    __resetCommentBurstForTest();
    for (let i = 0; i < 10; i++) incrementCommentBurst(); // at the default cap
    await expect(
      fire("youtube_video_comment_post", ytCtx().ctx, { video_id: YT_VID, text: "x" }),
    ).rejects.toMatchObject({ errorName: "comment_burst_limit_exceeded" });
    await expect(
      fire("youtube_comment_reply", ytCtx().ctx, { parent_comment_id: YT_PARENT, video_id: YT_VID, text: "x" }),
    ).rejects.toMatchObject({ errorName: "comment_burst_limit_exceeded" });
  });

  test("outbound-sanitize truncate-marker → outbound_sanitize_rejected (audit captures parent_comment_id_hash)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_comment_reply", ctx, {
        parent_comment_id: YT_PARENT,
        video_id: YT_VID,
        text: "Reply <safespace-truncated/> attack",
      }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
    const meta = cap.last("commentPostMeta");
    expect(meta?.policy_decision).toBe("denied_outbound_sanitize_rejected");
    expect(meta?.parent_comment_id_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("v1.128 Q3-B — public-write send-approval fires through the gate", () => {
  test("x_post flag on + allowlisted → send_approval_required; pending target is the posting account id", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    process.env[ENV_X_POST_ACCOUNTS] = X_USER;
    xPostAllowlist.resetSingletons();
    await expect(fire("x_post_create", xGateCtx(), { text: "hello public" })).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "awaiting_approval" },
    });
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs).toHaveLength(1);
    expect(recs[0]!.target).toEqual({ kind: "x_post", account_id: X_USER });
    expect(recs[0]!.body).toBe("hello public");
  });

  test("x_post flag on + allowlist miss → no pending", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await fire("x_post_create", xGateCtx(), { text: "should never post" }).catch(() => undefined);
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("youtube_video_comment_post flag on + allowlisted → pending target is the video id", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    await expect(
      fire("youtube_video_comment_post", ytCtx().ctx, { video_id: YT_VID, text: "hi" }),
    ).rejects.toMatchObject({ errorName: "send_approval_required" });
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs[0]!.target).toEqual({ kind: "youtube_video", video_id: YT_VID });
  });

  test("youtube_comment_reply flag on + allowlisted → pending target is the parent comment id", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    await expect(
      fire("youtube_comment_reply", ytCtx().ctx, {
        parent_comment_id: YT_PARENT,
        video_id: YT_VID,
        text: "hi",
      }),
    ).rejects.toMatchObject({ errorName: "send_approval_required" });
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs[0]!.target).toEqual({ kind: "youtube_comment", parent_comment_id: YT_PARENT });
  });

  test("youtube comment flag on + allowlist miss → no pending", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await fire("youtube_video_comment_post", ytCtx().ctx, { video_id: YT_VID, text: "x" }).catch(() => undefined);
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });
});

describe("youtube_video_update — egress gates (moved from youtube-video-update.test.ts)", () => {
  test("allowlist unset (off) → video_target_denied_by_policy{no_allowlist}, NO video_id echo, NO videoMutationMeta row", async () => {
    const { ctx, cap } = ytCtx();
    let thrown: unknown;
    await fire("youtube_video_update", ctx, { video_id: YT_VID, title: "T", category_id: "22" }).catch((e) => {
      thrown = e;
    });
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("video_target_denied_by_policy");
    expect((thrown as MCPError).errorData).toMatchObject({ reason: "no_allowlist" });
    expect(JSON.stringify((thrown as MCPError).errorData)).not.toContain(YT_VID);
    // github-write model — the denial is captured via errorCode, NOT a videoMutationMeta row.
    expect(cap.has("videoMutationMeta")).toBe(false);
  });

  test("active but target not listed → not_in_allowlist", async () => {
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_OTHER_VID}`;
    videoTargets.resetSingletons();
    await expect(
      fire("youtube_video_update", ytCtx().ctx, { video_id: YT_VID, title: "T", category_id: "22" }),
    ).rejects.toMatchObject({
      errorName: "video_target_denied_by_policy",
      errorData: { reason: "not_in_allowlist" },
    });
  });

  test("zero-width in title → outbound_sanitize_rejected + audit denied_outbound_sanitize_rejected", async () => {
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_VID}`;
    videoTargets.resetSingletons();
    const { ctx, cap } = ytCtx();
    await expect(
      fire("youtube_video_update", ctx, { video_id: YT_VID, title: "hi​there", category_id: "22" }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
    expect(cap.last("videoMutationMeta")?.policy_decision).toBe("denied_outbound_sanitize_rejected");
  });

  test("zero-width in a tag is also rejected", async () => {
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_VID}`;
    videoTargets.resetSingletons();
    await expect(
      fire("youtube_video_update", ytCtx().ctx, {
        video_id: YT_VID,
        title: "ok",
        category_id: "22",
        tags: ["fine", "ba​d"],
      }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
  });

  test("autonomous + secret-shape in description → outbound_secret_rejected (F3a)", async () => {
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_VID}`;
    process.env.SAFESPACE_AUTONOMOUS = "true";
    videoTargets.resetSingletons();
    await expect(
      fire("youtube_video_update", ytCtx().ctx, {
        video_id: YT_VID,
        title: "ok",
        category_id: "22",
        description: "my key AKIAIOSFODNN7EXAMPLE oops",
      }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });

  test("allowed: the gate RETURNS the per-FIELD NFC-sanitized snippet — transforming per-field (NEW)", async () => {
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_VID}`;
    videoTargets.resetSingletons();
    const { ctx } = ytCtx();
    const d = descriptorFor("youtube_video_update");
    const out = (await d.gate(
      ctx,
      d.extract({
        video_id: YT_VID,
        title: YT_RAW_DECOMPOSED,
        category_id: "22",
        description: YT_RAW_DECOMPOSED,
        tags: [YT_RAW_DECOMPOSED],
      }),
    )) as YoutubeVideoUpdateEgressShape;
    expect(ctx.egressGateFired).toBe(true);
    // Every free-text field is NFC-normalized on the RETURN; category_id is NOT in the shape.
    expect(out).toEqual({
      kind: "youtube-video-update",
      videoId: YT_VID,
      title: YT_NFC_PRECOMPOSED,
      description: YT_NFC_PRECOMPOSED,
      tags: [YT_NFC_PRECOMPOSED],
    });
  });
});

describe("youtube_video_comment_post — END-TO-END 401-retry egress carry-forward (B6.1 wave A2b, load-bearing)", () => {
  test("first SDK 401 → force-refresh → retry succeeds; the RETRIED wire body carries the PIPELINE's sanitized text; the gate fired ONCE", async () => {
    // Youtube is the FIRST refreshable (google-workspace) pipeline tool, so this drives
    // the with-context.ts 401 force-refresh + ctx-rebuild with a REAL pipeline-fired gate.
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    process.env.SAFESPACE_TIER = "write";
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = `video:${YT_VID}`;
    commentTargets.resetSingletons();
    __resetCommentBurstForTest();

    const email = "b61a2b-yt@example.com";
    const tokenSet = {
      refresh_token: "rt",
      access_token: "old-access-token",
      expires_at: Date.now() + 60 * 60_000,
      scopes: ["https://www.googleapis.com/auth/youtube.force-ssl"],
      obtained_at: Date.now(),
    };
    const store = new Map<string, string>([[email, JSON.stringify(tokenSet)]]);
    const deps: WithContextDeps = {
      async getToken(e: string) {
        return store.get(e) ?? null;
      },
      async setToken(e: string, json: string) {
        store.set(e, json);
      },
      async deleteToken(e: string) {
        store.delete(e);
      },
      async removeAccount() {},
      fetchImpl: (async () =>
        new Response(JSON.stringify({ access_token: "new-access-token", expires_in: 3600 }), {
          status: 200,
        })) as unknown as typeof fetch,
      loadIndexImpl: async () => ({ accounts: [{ email }] }),
    };

    // SDK mock: first commentThreads.insert → 401 GaxiosError; retry → 200. Capture BOTH
    // attempts' requestBody to prove the RETRY reused the gate's vetted bytes.
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    const bodies: unknown[] = [];
    let sdkCalls = 0;
    setGaxiosHandler(async (opts) => {
      bodies.push(opts.data);
      sdkCalls++;
      if (sdkCalls === 1) throw makeGaxiosError({ status: 401, errorStatus: "UNAUTHENTICATED" });
      return { data: { id: "thread-X", snippet: {} }, status: 200 };
    });

    const result = await withToolContext(
      "youtube_video_comment_post",
      { video_id: YT_VID, text: YT_RAW_DECOMPOSED, account_id: email },
      (hctx, hargs) => youtubeVideoCommentPost(hctx, hargs),
      deps,
    );

    // (a) the call SUCCEEDED — two SDK attempts (the 401 force-refresh + retry happened).
    expect(result).toBeDefined();
    expect(sdkCalls).toBe(2);
    // (b) BOTH SDK attempts carried the PIPELINE's sanitized (NFC) text, never the raw
    //     decomposed args text — the retried attempt reused ctx.egress (carried, not re-fired).
    const textOf = (b: unknown) =>
      (b as { snippet: { topLevelComment: { snippet: { textOriginal: string } } } }).snippet
        .topLevelComment.snippet.textOriginal;
    expect(bodies).toHaveLength(2);
    expect(textOf(bodies[0])).toBe(YT_NFC_PRECOMPOSED);
    expect(textOf(bodies[1])).toBe(YT_NFC_PRECOMPOSED);
    expect(textOf(bodies[1])).not.toBe(YT_RAW_DECOMPOSED);
    // (c) the gate fired ONCE: the success-only incrementCommentBurst ran EXACTLY once
    //     despite TWO handler attempts (attempt-1's 401 threw before the post-SDK increment),
    //     and checkCommentBurst is non-mutating — a retry consumed no second check.
    expect(getCommentBurstCount()).toBe(1);
    // (d) ctx.egressGateFired survived the rebuild — implied by the success: youtube_video_comment_post
    //     is direction:"outbound-write", so an unset flag at the post-handler tripwire would have
    //     thrown internal_routing_error{egress_gate_not_fired} instead of returning a result.
  });
});

describe("youtube_video_update — per-field transform THROUGH the choke point (B6.1 wave A2b)", () => {
  test("the wire snippet fields (title/description/tags) carry the PIPELINE's per-field NFC-sanitized bytes; category_id is the handler's own validated value", async () => {
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    process.env.SAFESPACE_TIER = "write";
    process.env[ENV_VIDEO_TARGETS] = `video:${YT_VID}`;
    videoTargets.resetSingletons();

    const email = "b61a2b-vu@example.com";
    const tokenSet = {
      refresh_token: "rt",
      access_token: "at",
      expires_at: Date.now() + 60 * 60_000,
      scopes: ["https://www.googleapis.com/auth/youtube.force-ssl"],
      obtained_at: Date.now(),
    };
    const store = new Map<string, string>([[email, JSON.stringify(tokenSet)]]);
    const deps: WithContextDeps = {
      async getToken(e: string) {
        return store.get(e) ?? null;
      },
      async setToken(e: string, json: string) {
        store.set(e, json);
      },
      async deleteToken(e: string) {
        store.delete(e);
      },
      async removeAccount() {},
      loadIndexImpl: async () => ({ accounts: [{ email }] }),
    };
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: { id?: string; snippet?: Record<string, unknown> } = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as typeof body;
      return { data: { id: YT_VID }, status: 200 };
    });
    await withToolContext(
      "youtube_video_update",
      {
        video_id: YT_VID,
        title: YT_RAW_DECOMPOSED,
        category_id: "22",
        description: YT_RAW_DECOMPOSED,
        tags: [YT_RAW_DECOMPOSED],
        account_id: email,
      },
      (hctx, hargs) => youtubeVideoUpdate(hctx, hargs),
      deps,
    );
    expect(body.snippet?.title).toBe(YT_NFC_PRECOMPOSED);
    expect(body.snippet?.description).toBe(YT_NFC_PRECOMPOSED);
    expect(body.snippet?.tags).toEqual([YT_NFC_PRECOMPOSED]);
    // category_id is the handler's own validated digit-only value — never sanitized,
    // never on ctx.egress.
    expect(body.snippet?.categoryId).toBe("22");
    expect(body.id).toBe(YT_VID);
  });
});

// ── 5. B6.1 wave A3+D — gmail compose (send + draft): TRANSFORMING, OAuth-routed ──
//
// gmail_send / gmail_create_draft migrated onto pipeline-fired egress. The composite
// wrapper (enforceGmailComposeEgressGates, tools/egress.ts) runs header gates →
// contact-lookup resolution (send only, via source.resolveRecipients) → recipient/secret/
// tainted gates → supervised-send approval, and RETURNS the shape with `resolved`
// populated. New for A3: a GATE-STAGE 401-retry at the choke point (the resolve step is a
// People-API call OUTSIDE the handler-stage retry loop).

const GMAIL_SENDER = "sender@example.com";

/** A direct-fire ctx for descriptor gate tests (no choke point). */
function gmailCtx(): { ctx: ToolContext; cap: CapturingAudit } {
  const cap = capturingAudit();
  return {
    ctx: { credential: oauthCred(GMAIL_SENDER, () => "tok"), tier: "write", audit: cap.sink },
    cap,
  };
}

/** extract → gate → store, exactly the choke-point sequence (with an optional resolver). */
async function fireGmail(
  tool: string,
  ctx: ToolContext,
  args: Record<string, unknown>,
  resolver?: RecipientResolver,
): Promise<GmailComposeEgressShape> {
  const d = descriptorFor(tool);
  const out = await d.gate(ctx, d.extract(args), resolver);
  if (out !== undefined) ctx.egress = out;
  return out as GmailComposeEgressShape;
}

/** WithContextDeps for the google (refreshable) choke-point gmail tests. `refreshFetch.n`
 *  counts token-endpoint refreshes (a forced refresh fetches; a fresh token does not). */
function makeGmailDeps(refreshFetch: { n: number }): WithContextDeps {
  const tokenSet = {
    refresh_token: "rt",
    access_token: "old-access-token",
    expires_at: Date.now() + 60 * 60_000, // fresh → the INITIAL resolve does NOT refresh
    scopes: ["https://www.googleapis.com/auth/gmail.send"],
    obtained_at: Date.now(),
  };
  const store = new Map<string, string>([[GMAIL_SENDER, JSON.stringify(tokenSet)]]);
  return {
    async getToken(e: string) {
      return store.get(e) ?? null;
    },
    async setToken(e: string, json: string) {
      store.set(e, json);
    },
    async deleteToken(e: string) {
      store.delete(e);
    },
    async removeAccount(e: string) {
      store.delete(e);
    },
    fetchImpl: (async () => {
      refreshFetch.n++;
      return new Response(JSON.stringify({ access_token: "new-access-token", expires_in: 3600 }), {
        status: 200,
      });
    }) as unknown as typeof fetch,
    loadIndexImpl: async () => ({ accounts: [{ email: GMAIL_SENDER }] }),
  };
}

describe("B6.1 wave A3+D — gmail compose pipeline egress (send + draft)", () => {
  const GMAIL_ENV = [
    "SAFESPACE_RECIPIENT_ALLOW",
    "SAFESPACE_RECIPIENT_ALLOW_EXTRA",
    "SAFESPACE_RECIPIENT_ALLOW_CONTACTS",
    "SAFESPACE_REQUIRE_SEND_APPROVAL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
  ];
  const savedGmail: Record<string, string | undefined> = {};
  const origResolve = googleWorkspace.resolveRecipients;
  const origRefreshable = googleWorkspace.refreshable;

  beforeEach(async () => {
    for (const k of GMAIL_ENV) savedGmail[k] = process.env[k];
    for (const k of GMAIL_ENV) delete process.env[k];
    const { __internal } = await import("../policy/recipient-allowlist");
    __internal.resetSingletons();
  });
  afterEach(async () => {
    for (const k of GMAIL_ENV) {
      if (savedGmail[k] === undefined) delete process.env[k];
      else process.env[k] = savedGmail[k]!;
    }
    // Restore the monkey-patched Source strategy fields (tests below swap them).
    (googleWorkspace as { resolveRecipients?: RecipientResolver }).resolveRecipients = origResolve;
    (googleWorkspace as { refreshable: boolean }).refreshable = origRefreshable;
    const { __internal } = await import("../policy/recipient-allowlist");
    __internal.resetSingletons();
  });

  // ── (a) descriptor extract — verbatim validation messages (both tools) ──────────
  describe("(a) descriptor extract — verbatim validation messages", () => {
    test("gmail_send: type-then-presence branches", () => {
      const ex = (args: Record<string, unknown>) => () => descriptorFor("gmail_send").extract(args);
      expect(ex({})).toThrow("gmail_send: 'to' must be a string");
      expect(ex({ to: "a@b.co" })).toThrow("gmail_send: 'subject' must be a string");
      expect(ex({ to: "a@b.co", subject: "s" })).toThrow("gmail_send: 'body' must be a string");
      expect(ex({ to: "a@b.co", subject: "s", body: "b", cc: 42 })).toThrow(
        "gmail_send: 'cc' must be a string when provided",
      );
      expect(ex({ to: "a@b.co", subject: "s", body: "b", bcc: 42 })).toThrow(
        "gmail_send: 'bcc' must be a string when provided",
      );
      expect(ex({ to: "   ", subject: "s", body: "b" })).toThrow(
        "gmail_send requires non-empty 'to', 'subject', and 'body'",
      );
    });

    test("gmail_create_draft: per-field type + at-least-one", () => {
      const ex = (args: Record<string, unknown>) => () => descriptorFor("gmail_create_draft").extract(args);
      expect(ex({ to: 42 })).toThrow("gmail_create_draft: 'to' must be a string when provided");
      expect(ex({ subject: 7 })).toThrow("gmail_create_draft: 'subject' must be a string when provided");
      expect(ex({})).toThrow(
        "gmail_create_draft requires at least one of non-empty 'to', 'subject', or 'body'",
      );
      expect(ex({ to: "   ", subject: "", body: "" })).toThrow(
        "gmail_create_draft requires at least one of non-empty 'to', 'subject', or 'body'",
      );
    });
  });

  // ── (b) gate order: header → resolve → format/allowlist; draft skips resolve ─────
  test("(b) gate order pin: header err precedes resolve; resolve precedes format; draft skips resolve", async () => {
    let resolveCalls = 0;
    const passthru: RecipientResolver = async (_ctx, inputs) => {
      resolveCalls++;
      return { resolvedEmails: inputs, lookedUpEmails: [] };
    };
    // header-injection `to` → the header gate throws BEFORE resolve (resolver untouched).
    await expect(
      fireGmail("gmail_send", gmailCtx().ctx, { to: "a@b.co\r\nBcc: evil", subject: "s", body: "b" }, passthru),
    ).rejects.toThrow(/header injection/);
    expect(resolveCalls).toBe(0);

    // valid header → the resolver runs (send path).
    resolveCalls = 0;
    await fireGmail("gmail_send", gmailCtx().ctx, { to: "a@b.co", subject: "s", body: "b" }, passthru);
    expect(resolveCalls).toBe(1);

    // resolve precedes the format gate: a resolver returning an INVALID email → the
    // per-recipient format gate (inside enforceEgressGates, AFTER resolve) rejects it.
    const toInvalid: RecipientResolver = async () => ({ resolvedEmails: ["not-an-email"], lookedUpEmails: [] });
    await expect(
      fireGmail("gmail_send", gmailCtx().ctx, { to: "alice", subject: "s", body: "b" }, toInvalid),
    ).rejects.toThrow(/not a valid email address: not-an-email/);

    // draft skips resolve entirely (literal-only, D3) even with a name-shaped `to`.
    resolveCalls = 0;
    const draftOut = await fireGmail(
      "gmail_create_draft",
      gmailCtx().ctx,
      { to: "a@b.co", subject: "s", body: "b" },
      passthru,
    );
    expect(resolveCalls).toBe(0);
    expect(draftOut.resolved).toEqual({ to: ["a@b.co"], cc: [], bcc: [] });
  });

  // ── (c) gate-stage 401-retry — three states ─────────────────────────────────────
  describe("(c) gate-stage 401-retry (the resolve step 401s OUTSIDE the handler loop)", () => {
    test("(i) resolve 401 → force-refresh → re-fire succeeds (gate fires twice, refresh once, send once)", async () => {
      process.env.GOOGLE_CLIENT_ID = "fake";
      process.env.GOOGLE_CLIENT_SECRET = "fake";
      const refreshFetch = { n: 0 };
      let resolveCalls = 0;
      (googleWorkspace as { resolveRecipients?: RecipientResolver }).resolveRecipients = async (
        _ctx,
        inputs,
      ) => {
        resolveCalls++;
        if (resolveCalls === 1) {
          const e: UpstreamError = new Error("people_401");
          e.httpStatus = 401;
          throw e;
        }
        // 2nd fire: resolve the name → a real email (a lookup happened).
        return { resolvedEmails: inputs.map(() => "alice@example.com"), lookedUpEmails: ["alice@example.com"] };
      };
      const { setGaxiosHandler } = await import("../google-api/test-utils");
      let sdkCalls = 0;
      let sdkRaw: string | undefined;
      setGaxiosHandler(async (opts) => {
        sdkCalls++;
        sdkRaw = (opts.data as { raw?: string })?.raw;
        return { data: { id: "m1", threadId: "t1", labelIds: ["SENT"] }, status: 200 };
      });
      const result = await withToolContext(
        "gmail_send",
        { to: "alice", subject: "s", body: "b", account_id: GMAIL_SENDER },
        (hctx, hargs) => gmailSend(hctx, hargs),
        makeGmailDeps(refreshFetch),
      );
      expect(result).toBeDefined();
      expect(resolveCalls).toBe(2); // gate re-fired exactly once
      expect(refreshFetch.n).toBe(1); // a force-refresh happened between the two fires
      expect(sdkCalls).toBe(1); // the send ran ONCE (only on the successful fire)
      // the wire carries the RESOLVED email, not the raw name.
      const decoded = Buffer.from(sdkRaw!, "base64url").toString("utf-8");
      expect(decoded).toContain("To: alice@example.com\r\n");
    });

    test("(ii) resolve double-401 → Keychain cleanup + refresh_token_invalid", async () => {
      process.env.GOOGLE_CLIENT_ID = "fake";
      process.env.GOOGLE_CLIENT_SECRET = "fake";
      const refreshFetch = { n: 0 };
      let resolveCalls = 0;
      const deps = makeGmailDeps(refreshFetch);
      let deleted = false;
      const origDelete = deps.deleteToken!;
      deps.deleteToken = async (e: string) => {
        deleted = true;
        return origDelete(e);
      };
      (googleWorkspace as { resolveRecipients?: RecipientResolver }).resolveRecipients = async () => {
        resolveCalls++;
        const e: UpstreamError = new Error("people_401");
        e.httpStatus = 401;
        throw e;
      };
      let caught: unknown;
      await withToolContext(
        "gmail_send",
        { to: "alice", subject: "s", body: "b", account_id: GMAIL_SENDER },
        (hctx, hargs) => gmailSend(hctx, hargs),
        deps,
      ).catch((e) => {
        caught = e;
      });
      expect(caught).toBeInstanceOf(MCPError);
      expect((caught as MCPError).errorName).toBe("refresh_token_invalid");
      expect(resolveCalls).toBe(2); // one retry, then give up
      expect(deleted).toBe(true); // stale token cleaned up
    });

    test("(iii) a refreshable:false OAuth source + resolve 401 → rethrown raw (no retry, no cleanup)", async () => {
      process.env.GOOGLE_CLIENT_ID = "fake";
      process.env.GOOGLE_CLIENT_SECRET = "fake";
      (googleWorkspace as { refreshable: boolean }).refreshable = false;
      const refreshFetch = { n: 0 };
      const deps = makeGmailDeps(refreshFetch);
      let deleted = false;
      deps.deleteToken = async () => {
        deleted = true;
      };
      let resolveCalls = 0;
      (googleWorkspace as { resolveRecipients?: RecipientResolver }).resolveRecipients = async () => {
        resolveCalls++;
        const e: UpstreamError = new Error("people_401");
        e.httpStatus = 401;
        throw e;
      };
      let caught: unknown;
      await withToolContext(
        "gmail_send",
        { to: "alice", subject: "s", body: "b", account_id: GMAIL_SENDER },
        (hctx, hargs) => gmailSend(hctx, hargs),
        deps,
      ).catch((e) => {
        caught = e;
      });
      // Raw upstream error — NOT re-mapped to refresh_token_invalid; no retry/cleanup.
      expect((caught as UpstreamError)?.httpStatus).toBe(401);
      expect((caught as MCPError).errorName).toBeUndefined();
      expect(resolveCalls).toBe(1);
      expect(deleted).toBe(false);
    });
  });

  // ── (d) end-to-end handler-401 carry-forward (resolve/gate once; only the SDK retries) ──
  test("(d) gmail e2e: handler 401 → SDK retry reuses ctx.egress (resolve ONCE, wire carries the resolved email)", async () => {
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    const refreshFetch = { n: 0 };
    let resolveCalls = 0;
    (googleWorkspace as { resolveRecipients?: RecipientResolver }).resolveRecipients = async (_ctx, inputs) => {
      resolveCalls++;
      return { resolvedEmails: inputs.map(() => "alice@example.com"), lookedUpEmails: ["alice@example.com"] };
    };
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    const raws: string[] = [];
    let sdkCalls = 0;
    setGaxiosHandler(async (opts) => {
      raws.push((opts.data as { raw?: string })?.raw ?? "");
      sdkCalls++;
      if (sdkCalls === 1) throw makeGaxiosError({ status: 401, errorStatus: "UNAUTHENTICATED" });
      return { data: { id: "m1", threadId: "t1", labelIds: ["SENT"] }, status: 200 };
    });
    const result = await withToolContext(
      "gmail_send",
      { to: "alice", subject: "s", body: "b", account_id: GMAIL_SENDER },
      (hctx, hargs) => gmailSend(hctx, hargs),
      makeGmailDeps(refreshFetch),
    );
    expect(result).toBeDefined();
    expect(sdkCalls).toBe(2); // the send retried after the 401
    expect(resolveCalls).toBe(1); // resolve/gate ran ONCE (pre-handler) — the retry reused ctx.egress
    expect(refreshFetch.n).toBe(1); // the handler 401 forced a token refresh
    // BOTH SDK attempts carried the SAME resolved recipient (the gate's vetted bytes).
    expect(raws).toHaveLength(2);
    for (const r of raws) {
      expect(Buffer.from(r, "base64url").toString("utf-8")).toContain("To: alice@example.com\r\n");
    }
  });

  // ── (e) a DIRECT handler call (bypassing the pipeline) → fail loud ───────────────
  test("(e) direct handler call (no ctx.egress) → internal_routing_error{invariant_violation}", async () => {
    const { ctx } = gmailCtx();
    await expect(
      gmailSend(ctx, { to: "a@b.co", subject: "s", body: "b" }),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "invariant_violation" } });
    await expect(
      gmailCreateDraft(ctx, { to: "a@b.co", subject: "s", body: "b" }),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "invariant_violation" } });
  });

  // ── (f) draft: empty recipient passes; draft is NOT supervised-send-gated ────────
  test("(f) draft with no recipient passes the gate (empty resolved.to); approval never fires for a draft", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true"; // ON — a draft must still pass (not in APPROVAL_GATED_SENDS)
    const out = await fireGmail("gmail_create_draft", gmailCtx().ctx, { body: "just a note to myself" });
    expect(out.resolved).toEqual({ to: [], cc: [], bcc: [] });
  });
});
