// v1.65 Phase C — withNonOAuthContext (the keyless choke point) tests. Pins the
// keyless ctx shape, the per-source (empty-skipFields) sanitize wrap, and the thin
// audit row (source "web-fetch", account null). Uses a real on-disk audit.jsonl
// via SAFESPACE_CONFIG_DIR, mirroring the with-context.ts audit tests.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import { requireOAuth } from "./handlers/shared";
import type { ToolContext } from "./types";
import { withNonOAuthContext } from "./with-nonoauth-context";
import { __drainAuditWrites } from "../audit";

describe("withNonOAuthContext (web-fetch keyless path — byte-identical to v1.65)", () => {
  let tmpDir: string;
  let prevConfigDir: string | undefined;

  beforeEach(async () => {
    prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-keyless-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  });
  afterEach(async () => {
    if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
    else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  async function readAuditLines(): Promise<Array<Record<string, unknown>>> {
    const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    return content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
  }
  async function waitForAudit(): Promise<void> {
    await __drainAuditWrites();
  }

  test("ctx is keyless: credential {kind:'none'}, no account, requireOAuth throws", async () => {
    let captured: ToolContext | undefined;
    await withNonOAuthContext("web_fetch", { url: "https://x/" }, async (ctx) => {
      captured = ctx;
      return { ok: true };
    });
    expect(captured!.credential).toEqual({ kind: "none" });
    expect(captured!.tier).toBeDefined();
    expect(typeof captured!.audit.record).toBe("function");
    // R6 invariant: a keyless handler can NEVER reach for an OAuth account.
    expect(() => requireOAuth(captured!)).toThrow();
  });

  test("applies per-source sanitize with EMPTY skipFields — EVERY field wraps", async () => {
    const out = (await withNonOAuthContext("web_fetch", { url: "https://x/" }, async () => ({
      greeting: "hello world",
      id: "12345", // on the Google source `id` is a SKIP_FIELD; for web-fetch it WRAPS
    }))) as { greeting: string; id: string };
    expect(out.greeting).toContain("untrusted-source-");
    expect(out.greeting).toContain("hello world");
    expect(out.greeting).toContain('origin="web_fetch"');
    // The empty-skipFields posture: an id-shaped key is NOT carved out — it wraps too.
    expect(out.id).toContain("untrusted-source-");
    expect(out.id).toContain("12345");
  });

  test("success audit row is thin: source web-fetch, account null, status ok", async () => {
    await withNonOAuthContext("web_fetch", { url: "https://x/" }, async () => ({ ok: true }));
    await waitForAudit();
    const rows = await readAuditLines();
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.tool).toBe("web_fetch");
    expect(row.source).toBe("web-fetch");
    expect(row.account).toBeNull();
    expect(row.status).toBe("ok");
    expect(row.sanitize).toBe("applied");
    expect(row.run_id).toBeDefined();
    // No forensic meta channels on a keyless read.
    expect(row.error_code).toBeUndefined();
  });

  // v1.74 PR-2a — the OperatorContext threads through the NON-OAuth choke point
  // too (the path server.ts dispatches for keyless/service-token tools).
  test("explicit op drives ctx.tier, OVERRIDING env; the row's operator is null", async () => {
    const prevTier = process.env.SAFESPACE_TIER;
    process.env.SAFESPACE_TIER = "read";
    try {
      let seenTier: string | undefined;
      await withNonOAuthContext(
        "web_fetch",
        { url: "https://x/" },
        async (ctx) => {
          seenTier = ctx.tier;
          return { ok: true };
        },
        { tier: "write" },
      );
      await waitForAudit();
      const rows = await readAuditLines();
      expect(rows).toHaveLength(1);
      expect(rows[0]!.operator).toBeNull();
      expect(seenTier).toBe("write"); // handler saw op.tier, not env "read"
    } finally {
      if (prevTier === undefined) delete process.env.SAFESPACE_TIER;
      else process.env.SAFESPACE_TIER = prevTier;
    }
  });

  test("omitting op falls back to the env tier", async () => {
    const prevTier = process.env.SAFESPACE_TIER;
    process.env.SAFESPACE_TIER = "write";
    try {
      let seenTier: string | undefined;
      await withNonOAuthContext("web_fetch", { url: "https://x/" }, async (ctx) => {
        seenTier = ctx.tier;
        return { ok: true };
      });
      expect(seenTier).toBe("write");
    } finally {
      if (prevTier === undefined) delete process.env.SAFESPACE_TIER;
      else process.env.SAFESPACE_TIER = prevTier;
    }
  });

  test("handler MCPError → status error, error_code stamped, error rethrown", async () => {
    const boom = new MCPError("url_blocked_by_policy", { reason: "private_or_reserved_ip" });
    await expect(
      withNonOAuthContext("web_fetch", { url: "http://10.0.0.1/" }, async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    await waitForAudit();
    const rows = await readAuditLines();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.status).toBe("error");
    expect(rows[0]!.error_code).toBe(-32036);
    expect(rows[0]!.account).toBeNull();
    expect(rows[0]!.source).toBe("web-fetch");
  });

  test("a sanitize failure flows through as an error row (fail-closed)", async () => {
    // A circular object makes the sanitize tree-walk throw sanitize_failed.
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await expect(
      withNonOAuthContext("web_fetch", { url: "https://x/" }, async () => circular),
    ).rejects.toMatchObject({ errorName: "sanitize_failed" });
    await waitForAudit();
    const rows = await readAuditLines();
    expect(rows[0]!.status).toBe("error");
    expect(rows[0]!.error_code).toBe(-32000); // sanitize_failed
  });
});

describe("withNonOAuthContext (LINE service-token route — v1.66 Phase C PR 2)", () => {
  let tmpDir: string;
  const saved: Record<string, string | undefined> = {};
  const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_LINE_CHANNEL_TOKEN", "SAFESPACE_SECRET_BACKEND"];

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-line-ctx-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // hermetic — no Keychain
    delete process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
  });
  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  });

  async function readRows(): Promise<Array<Record<string, unknown>>> {
    await __drainAuditWrites();
    const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    return content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
  }

  test("resolves a service-token credential and runs the handler; audit row source 'line'", async () => {
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "chan-tok-xyz";
    let captured: ToolContext | undefined;
    // B6.1 wave A1 — a VALID LINE id: the pipeline now validates args (the egress
    // descriptor's extract) BEFORE the handler, so the fixture must be well-formed.
    await withNonOAuthContext("line_push_message", { to: "U" + "0".repeat(32), text: "hi" }, async (c) => {
      c.egressGateFired = true; // v1.116 — stub stands in for a gate-calling outbound handler
      captured = c;
      return { sent: true };
    });
    expect(captured!.credential.kind).toBe("service-token");
    if (captured!.credential.kind !== "service-token") throw new Error("unreachable");
    expect(captured!.credential.token()).toBe("chan-tok-xyz");
    // A LINE handler must never reach for an OAuth account.
    expect(() => requireOAuth(captured!)).toThrow();

    const rows = await readRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("line_push_message");
    expect(rows[0]!.source).toBe("line");
    expect(rows[0]!.account).toBeNull();
    expect(rows[0]!.status).toBe("ok");
  });

  test("no token configured → resolveCredential throws line_api_failed{no_token}; error row", async () => {
    // no env token + empty file backend → readServiceToken returns null.
    let handlerRan = false;
    await expect(
      withNonOAuthContext("line_push_message", { to: "U", text: "hi" }, async () => {
        handlerRan = true;
        return { sent: true };
      }),
    ).rejects.toMatchObject({ errorName: "line_api_failed", errorData: { reason: "no_token" } });
    expect(handlerRan).toBe(false); // resolveCredential fails BEFORE the handler
    const rows = await readRows();
    expect(rows[0]!.status).toBe("error");
    expect(rows[0]!.error_code).toBe(-32038);
    expect(rows[0]!.source).toBe("line");
  });
});
