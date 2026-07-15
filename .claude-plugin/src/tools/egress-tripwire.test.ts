// v1.116 — choke-point egress tripwire tests. Pins the RUNTIME backstop behind the
// static egress-callsite.test.ts sentinel: a tool LABELED direction:"outbound-write"
// whose handler returns WITHOUT invoking its centralized egress gate
// (tools/egress.ts, which sets ctx.egressGateFired) → the choke point throws
// internal_routing_error{egress_gate_not_fired} and blocks the response.
//
// Reuses the EXISTING harnesses (no new mock layer): the WithContextDeps injection
// seam + freshTokenSet shape from with-context.test.ts (OAuth path), the LINE
// service-token env scaffolding from with-nonoauth-context.test.ts (class-B path),
// and the capturingAudit / oauthCred helpers from test-audit.ts (flag-unit ctx).
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import type { TokenSet } from "../auth/refresh";
import { currentTier } from "../tier";
import type { ToolContext } from "./types";
import { capturingAudit, oauthCred } from "./test-audit";
import {
  _resetLastUsedForTests,
  withToolContext,
  type WithContextDeps,
} from "./with-context";
import { withNonOAuthContext } from "./with-nonoauth-context";
import {
  enforceEgressGates,
  enforceGithubMergeEgressGates,
  enforceGithubReviewEgressGates,
  enforceGithubWriteEgressGates,
  enforceLineEgressGates,
  enforceNotionWriteEgressGates,
  enforceXPostEgressGates,
} from "./egress";
import { __resetWriteBurstForTests } from "../policy/write-burst";
import { ENV_LINE_ALLOW } from "../policy/line-recipient-allowlist";

// A syntactically-valid LINE recipient id (LINE_ID_RE: /^[UCR][0-9a-f]{32}$/).
const LINE_ID = "U" + "0".repeat(32);
// A second valid id, used as an ACTIVE allowlist entry that EXCLUDES LINE_ID.
const OTHER_LINE_ID = "U" + "9".repeat(32);

async function resetRecipientAllowlist(): Promise<void> {
  const { __internal } = await import("../policy/recipient-allowlist");
  __internal.resetSingletons();
}

// ── OAuth path (withToolContext) ──────────────────────────────────────────────

function freshTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    refresh_token: "rt",
    access_token: "old-access-token",
    expires_at: Date.now() + 30 * 60_000, // not expired → resolveCredential won't refresh
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
    ...overrides,
  };
}

/** Minimal OAuth deps — the same WithContextDeps injection seam with-context.test.ts
 *  uses. The index carries NO `scopes` field, so the scope pre-check is skipped
 *  (a gmail_send stub thus never fails scope_mismatch before the handler runs). */
function makeDeps(emails = ["alice@example.com"]): WithContextDeps {
  const store = new Map<string, string>();
  for (const e of emails) store.set(e, JSON.stringify(freshTokenSet()));
  const index = { accounts: emails.map((e) => ({ email: e })) };
  return {
    async getToken(email: string) {
      return store.get(email) ?? null;
    },
    async setToken(email: string, json: string) {
      store.set(email, json);
    },
    async deleteToken(email: string) {
      store.delete(email);
    },
    async removeAccount() {
      /* no-op */
    },
    fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
    loadIndexImpl: async () => index,
  };
}

describe("egress tripwire — OAuth choke point (withToolContext)", () => {
  let tmpDir: string;
  const ENV_BACKUP = {
    id: process.env.GOOGLE_CLIENT_ID,
    secret: process.env.GOOGLE_CLIENT_SECRET,
    allow: process.env.SAFESPACE_RECIPIENT_ALLOW,
    autonomous: process.env.SAFESPACE_AUTONOMOUS,
    configDir: process.env.SAFESPACE_CONFIG_DIR,
  };

  beforeEach(async () => {
    process.env.GOOGLE_CLIENT_ID = "fake";
    process.env.GOOGLE_CLIENT_SECRET = "fake";
    delete process.env.SAFESPACE_RECIPIENT_ALLOW;
    delete process.env.SAFESPACE_AUTONOMOUS;
    // B6.1 wave A3+D — gmail_send is PIPELINE_EGRESS: a recipient-denial fires the
    // pipeline gate pre-handler and writes a recipient-denied audit row → give it a
    // hermetic config dir (mirrors the LINE tripwire describe below).
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-egress-tripwire-oauth-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
    _resetLastUsedForTests();
    __resetWriteBurstForTests();
    await resetRecipientAllowlist();
  });

  afterEach(async () => {
    process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
    process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
    if (ENV_BACKUP.allow === undefined) delete process.env.SAFESPACE_RECIPIENT_ALLOW;
    else process.env.SAFESPACE_RECIPIENT_ALLOW = ENV_BACKUP.allow;
    if (ENV_BACKUP.autonomous === undefined) delete process.env.SAFESPACE_AUTONOMOUS;
    else process.env.SAFESPACE_AUTONOMOUS = ENV_BACKUP.autonomous;
    if (ENV_BACKUP.configDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
    else process.env.SAFESPACE_CONFIG_DIR = ENV_BACKUP.configDir;
    _resetLastUsedForTests();
    __resetWriteBurstForTests();
    await resetRecipientAllowlist();
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  });

  // B6.1 wave A3+D — gmail_send is now PIPELINE_EGRESS (like line_push_message in the
  // non-OAuth describe below): the old NEGATIVE premise ("handler forgets the gate →
  // post-handler tripwire fires") is structurally impossible — the choke point fires the
  // composite gate BEFORE the handler via the registry def's egress descriptor. This test
  // pins the STRONGER guarantee that replaced it: enforcement no longer depends on handler
  // behavior at all (a gate-skipping stub handler still gets pre-handler denial).
  test("PIPELINE: gmail_send — pipeline fires the gate even when the handler skips it (denied recipient → -32019 BEFORE the handler)", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "someone-else@example.com"; // active, EXCLUDES x@example.com
    await resetRecipientAllowlist();
    const deps = makeDeps();
    let handlerRan = false;
    const skipsGate = async () => {
      handlerRan = true;
      return { id: "m1" };
    };
    let caught: unknown;
    try {
      await withToolContext(
        "gmail_send",
        { to: "x@example.com", subject: "s", body: "b", account_id: "alice@example.com" },
        skipsGate,
        deps,
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("recipient_denied_by_policy");
    expect((caught as MCPError).code).toBe(-32019);
    expect(handlerRan).toBe(false); // the denial fired at the pipeline, pre-handler
  });

  test("POSITIVE: gmail_send — pipeline-fired gate passes; a gate-less handler resolves with egressGateFired set (no tripwire)", async () => {
    const deps = makeDeps();
    // The handler does NOT call the gate (a handler-level call would be a double fire,
    // which the pipeline call-site sentinel forbids); the choke point fired it already,
    // so the handler observes egressGateFired === true at entry.
    let firedAtHandlerEntry: boolean | undefined;
    const gateLess = async (ctx: ToolContext) => {
      firedAtHandlerEntry = ctx.egressGateFired;
      return { id: "m1" };
    };
    const result = await withToolContext(
      "gmail_send",
      { to: "alice@example.com", subject: "s", body: "hi", account_id: "alice@example.com" },
      gateLess,
      deps,
    );
    expect(result).toBeDefined();
    expect(firedAtHandlerEntry).toBe(true);
  });
});

// ── non-OAuth path (withNonOAuthContext) ──────────────────────────────────────

describe("egress tripwire — non-OAuth choke point (withNonOAuthContext)", () => {
  let tmpDir: string;
  const saved: Record<string, string | undefined> = {};
  const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_LINE_CHANNEL_TOKEN", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_AUTONOMOUS", ENV_LINE_ALLOW];

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-egress-tripwire-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // hermetic — no Keychain
    delete process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
    delete process.env.SAFESPACE_AUTONOMOUS; // LINE allowlist off→allow (autonomous would deny-all)
    __resetWriteBurstForTests();
  });

  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    __resetWriteBurstForTests();
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  });

  // B6.1 wave A1 — line_push_message is PIPELINE_EGRESS: the old NEGATIVE premise
  // ("handler forgets the gate → post-handler tripwire fires") is structurally
  // impossible now — the choke point fires the gate BEFORE the handler via the
  // registry def's egress descriptor. This test pins the STRONGER guarantee that
  // replaced it: enforcement no longer depends on handler behavior at all.
  test("PIPELINE: line_push_message — pipeline fires the gate even when the handler skips it (denied recipient → -32019 BEFORE the handler)", async () => {
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    process.env[ENV_LINE_ALLOW] = OTHER_LINE_ID; // active allowlist EXCLUDING LINE_ID
    let handlerRan = false;
    const skipsGate = async () => {
      handlerRan = true;
      return { sent: true };
    };
    let caught: unknown;
    try {
      await withNonOAuthContext("line_push_message", { to: LINE_ID, text: "hi" }, skipsGate);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("recipient_denied_by_policy");
    expect((caught as MCPError).code).toBe(-32019);
    expect(handlerRan).toBe(false); // the denial fired at the pipeline, pre-handler
  });

  test("POSITIVE: line_push_message — pipeline-fired gate passes; a gate-less handler resolves with egressGateFired set (no tripwire)", async () => {
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    process.env[ENV_LINE_ALLOW] = LINE_ID; // allowlist admits the recipient
    // B6.1 wave A1 — the handler does NOT call the gate (a handler-level call would
    // be a double fire, which the pipeline call-site sentinel forbids); the choke
    // point fired it already, so the handler observes egressGateFired === true.
    let firedAtHandlerEntry: boolean | undefined;
    const gateLess = async (ctx: ToolContext) => {
      firedAtHandlerEntry = ctx.egressGateFired;
      return { sent: true };
    };
    const result = await withNonOAuthContext("line_push_message", { to: LINE_ID, text: "hi" }, gateLess);
    expect(result).toBeDefined();
    expect(firedAtHandlerEntry).toBe(true);
  });

  test("READ-TOOL NO-OP: web_fetch (not outbound-write) → no tripwire even with a gate-less handler", async () => {
    const result = await withNonOAuthContext("web_fetch", { url: "https://x/" }, async () => ({ ok: true }));
    expect(result).toBeDefined();
  });
});

// ── FLAG UNIT: every gate entry point sets the flag as its FIRST statement ─────

describe("egress tripwire — flag set-site unit (all 7 entry points)", () => {
  const saved: Record<string, string | undefined> = {};
  const ENV = [
    "SAFESPACE_AUTONOMOUS",
    "SAFESPACE_RECIPIENT_ALLOW",
    "SAFESPACE_GITHUB_WRITE_TARGETS",
    "SAFESPACE_GITHUB_MERGE_TARGETS",
    "SAFESPACE_GITHUB_APPROVE_TARGETS",
    "SAFESPACE_X_POST_ACCOUNTS",
    "SAFESPACE_REQUIRE_SEND_APPROVAL",
  ];

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    for (const k of ENV) delete process.env[k]; // github/x default-deny; gmail/line/notion clean
    await resetRecipientAllowlist();
  });

  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    await resetRecipientAllowlist();
  });

  function makeGateCtx(): ToolContext {
    return {
      credential: oauthCred("alice@example.com", () => "tok"),
      get tier() {
        return currentTier();
      },
      audit: capturingAudit().sink,
      allowedAccounts: null,
    };
  }

  test("each of the 7 gate entry points sets ctx.egressGateFired — EVEN WHEN it denies", async () => {
    // The flag is the FIRST statement of every gate, so a default-deny throw
    // (github/x with empty env) does not prevent it. gmail/line/notion pass clean.
    // enforceServiceTokenRecipientGate is private → exercised via enforceLineEgressGates.
    const cases: Array<{ label: string; run: (ctx: ToolContext) => unknown }> = [
      {
        label: "enforceEgressGates (gmail)",
        run: (ctx) =>
          enforceEgressGates(ctx, { tool: "gmail_send", recipients: ["bob@example.com"], body: "hi" }),
      },
      {
        label: "enforceServiceTokenRecipientGate (via enforceLineEgressGates)",
        run: (ctx) => enforceLineEgressGates(ctx, { tool: "line_push_message", to: LINE_ID, body: "hi" }),
      },
      {
        label: "enforceGithubWriteEgressGates",
        run: (ctx) =>
          enforceGithubWriteEgressGates(ctx, { tool: "github_create_issue", owner: "o", repo: "r", body: "b" }),
      },
      {
        label: "enforceGithubMergeEgressGates",
        run: (ctx) =>
          enforceGithubMergeEgressGates(ctx, { tool: "github_merge_pull_request", owner: "o", repo: "r", body: "b" }),
      },
      {
        label: "enforceGithubReviewEgressGates",
        run: (ctx) =>
          enforceGithubReviewEgressGates(ctx, {
            tool: "github_create_pull_request_review",
            event: "APPROVE",
            owner: "o",
            repo: "r",
            body: "b",
          }),
      },
      {
        label: "enforceNotionWriteEgressGates",
        run: (ctx) => enforceNotionWriteEgressGates(ctx, { tool: "notion_create_page", body: "b" }),
      },
      {
        label: "enforceXPostEgressGates",
        run: (ctx) => enforceXPostEgressGates(ctx, "123", "hello"),
      },
    ];
    for (const c of cases) {
      const ctx = makeGateCtx();
      try {
        const r = c.run(ctx);
        if (r instanceof Promise) await r.catch(() => undefined);
      } catch {
        /* default-deny throw expected for github/x — flag is still set */
      }
      expect(ctx.egressGateFired, c.label).toBe(true);
    }
  });
});
