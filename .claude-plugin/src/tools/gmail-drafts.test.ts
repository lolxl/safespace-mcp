// v1.43 — Gmail drafts (gmail_create_draft / gmail_list_drafts /
// gmail_get_draft / gmail_delete_draft). Tested through the SDK-level
// `setGaxiosHandler` seam, same as the other Gmail handlers. The v2.2
// recipient-allowlist gate (Q2 LOCKED) is exercised here at the integration
// boundary; the allowlist matching itself is unit-tested in
// src/policy/recipient-allowlist.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { currentTier } from "../tier";
import {
  gmailCreateDraft,
  gmailDeleteDraft,
  gmailGetDraft,
  gmailListDrafts,
} from "./handlers";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const FAKE_CTX: ToolContext = { allowedAccounts: null,
  credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
  audit: NOOP_AUDIT,
  get tier() {
    return currentTier();
  },
};

interface CapturedOpts {
  url?: string;
  method?: string;
  params?: Record<string, unknown>;
  data?: unknown;
}

let tmpDir: string;
let prevConfigDir: string | undefined;
let prevAllow: string | undefined;
let prevAllowExtra: string | undefined;

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  const { __internal } = await import("../policy/recipient-allowlist");
  __internal.resetSingletons();
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-drafts-"));
  prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
  prevAllow = process.env.SAFESPACE_RECIPIENT_ALLOW;
  prevAllowExtra = process.env.SAFESPACE_RECIPIENT_ALLOW_EXTRA;
  process.env.SAFESPACE_CONFIG_DIR = tmpDir; // isolate audit + selfEmails (empty)
  // Default: allowlist OFF — happy-path tests don't get gated. Tests that
  // exercise the gate set SAFESPACE_RECIPIENT_ALLOW themselves.
  delete process.env.SAFESPACE_RECIPIENT_ALLOW;
  delete process.env.SAFESPACE_RECIPIENT_ALLOW_EXTRA;
});

afterEach(async () => {
  if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
  if (prevAllow === undefined) delete process.env.SAFESPACE_RECIPIENT_ALLOW;
  else process.env.SAFESPACE_RECIPIENT_ALLOW = prevAllow;
  if (prevAllowExtra === undefined) delete process.env.SAFESPACE_RECIPIENT_ALLOW_EXTRA;
  else process.env.SAFESPACE_RECIPIENT_ALLOW_EXTRA = prevAllowExtra;
  const { __internal } = await import("../policy/recipient-allowlist");
  __internal.resetSingletons();
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("gmailCreateDraft (WRITE tool)", () => {
  test("happy path — raw decodes to To/Subject/body; SDK posts to /drafts", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { id: "r123", message: { id: "m1", threadId: "t1", labelIds: ["DRAFT"] } }, status: 200 };
    });
    const result = (await gmailCreateDraft(FAKE_CTX, {
      to: "bob@example.com",
      subject: "Hello",
      body: "Draft body",
    })) as { id: string };
    expect(result.id).toBe("r123");
    expect(opts?.url).toContain("/gmail/v1/users/me/drafts");
    const raw = (opts?.data as { message?: { raw?: string } })?.message?.raw;
    expect(typeof raw).toBe("string");
    const decoded = Buffer.from(raw!, "base64url").toString("utf-8");
    expect(decoded).toContain("From: alice@example.com");
    expect(decoded).toContain("To: bob@example.com");
    expect(decoded).toContain("Subject: Hello");
    expect(decoded).toContain("Draft body");
  });

  test("body-only draft — no recipients → no To: header, succeeds (allowlist no-op)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { id: "r2" }, status: 200 };
    });
    await gmailCreateDraft(FAKE_CTX, { body: "just a note to myself" });
    const raw = (opts?.data as { message?: { raw?: string } })?.message?.raw;
    const decoded = Buffer.from(raw!, "base64url").toString("utf-8");
    expect(decoded).not.toContain("To:");
    expect(decoded).not.toContain("Cc:");
    expect(decoded).toContain("just a note to myself");
  });

  test("at-least-one gate — all empty → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(gmailCreateDraft(FAKE_CTX, {})).rejects.toThrow(/at least one/);
    await expect(gmailCreateDraft(FAKE_CTX, { to: "   ", subject: "", body: "" })).rejects.toThrow(/at least one/);
    expect(called).toBe(false);
  });

  test("header-injection — CR/LF in to/cc/bcc/subject → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      gmailCreateDraft(FAKE_CTX, { to: "bob@example.com\r\nBcc: evil@x.com", body: "x" }),
    ).rejects.toThrow(/header injection/);
    await expect(
      gmailCreateDraft(FAKE_CTX, { subject: "hi\nthere", body: "x" }),
    ).rejects.toThrow(/header injection/);
    expect(called).toBe(false);
  });

  test("ASCII subject gate — non-ASCII subject → reject", async () => {
    await expect(
      gmailCreateDraft(FAKE_CTX, { subject: "你好", body: "x" }),
    ).rejects.toThrow(/ASCII/);
  });

  test("10-recipient cap — 11 across to+cc+bcc → reject", async () => {
    const eleven = Array.from({ length: 11 }, (_, i) => `u${i}@example.com`).join(",");
    await expect(
      gmailCreateDraft(FAKE_CTX, { to: eleven, body: "x" }),
    ).rejects.toThrow(/at most 10 recipients/);
  });

  test("email-format gate — non-email recipient → reject (no contact lookup)", async () => {
    await expect(
      gmailCreateDraft(FAKE_CTX, { to: "alice", body: "x" }),
    ).rejects.toThrow(/not a valid email address/);
  });

  test("body byte cap — body > 1 MiB → reject", async () => {
    const big = "a".repeat(1024 * 1024 + 1);
    await expect(
      gmailCreateDraft(FAKE_CTX, { subject: "ok", body: big }),
    ).rejects.toThrow(/exceeds/);
  });

  test("allowlist gate — recipient not allowed → recipient_denied_by_policy (-32019), no HTTP", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "@allowed.com";
    const { __internal } = await import("../policy/recipient-allowlist");
    __internal.resetSingletons();
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      gmailCreateDraft(FAKE_CTX, { to: "bob@evil.com", subject: "hi", body: "x" }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
    expect(called).toBe(false);
  });

  test("allowlist gate — matching domain → passes through to SDK", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "@allowed.com";
    const { __internal } = await import("../policy/recipient-allowlist");
    __internal.resetSingletons();
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: { id: "r3" }, status: 200 };
    });
    const r = (await gmailCreateDraft(FAKE_CTX, {
      to: "bob@allowed.com",
      subject: "hi",
      body: "x",
    })) as { id: string };
    expect(r.id).toBe("r3");
    expect(called).toBe(true);
  });
});

describe("gmailListDrafts (READ tool)", () => {
  test("pass-through — SDK lists /drafts, returns data", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { drafts: [{ id: "r1", message: { id: "m1", threadId: "t1" } }] }, status: 200 };
    });
    const r = (await gmailListDrafts(FAKE_CTX, {})) as { drafts: unknown[] };
    expect(r.drafts).toHaveLength(1);
    expect(opts?.url).toContain("/gmail/v1/users/me/drafts");
  });

  test("max_results clamp — request 999 → maxResults capped at 50", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: {}, status: 200 };
    });
    await gmailListDrafts(FAKE_CTX, { max_results: 999 });
    expect(opts?.params?.maxResults).toBe(50);
  });
});

describe("gmailGetDraft (READ tool)", () => {
  test("non-empty id gate — empty id → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(gmailGetDraft(FAKE_CTX, { id: "" })).rejects.toThrow(/non-empty 'id'/);
    expect(called).toBe(false);
  });

  test("injection-clean id gate — CR/LF in id → reject", async () => {
    await expect(gmailGetDraft(FAKE_CTX, { id: "r1\r\nx" })).rejects.toThrow(
      /must not contain/,
    );
  });

  test("happy — fetches /drafts/<id> with format=full", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { id: "r1", message: { id: "m1" } }, status: 200 };
    });
    const r = (await gmailGetDraft(FAKE_CTX, { id: "r1" })) as { id: string };
    expect(r.id).toBe("r1");
    expect(opts?.url).toContain("/gmail/v1/users/me/drafts/r1");
    expect(opts?.params?.format).toBe("full");
  });
});

describe("gmailDeleteDraft (WRITE tool)", () => {
  test("non-empty id gate — empty id → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(gmailDeleteDraft(FAKE_CTX, { id: "" })).rejects.toThrow(/non-empty 'id'/);
    expect(called).toBe(false);
  });

  test("injection-clean id gate — CR/LF in id → reject", async () => {
    await expect(gmailDeleteDraft(FAKE_CTX, { id: "r1\r\nx" })).rejects.toThrow(
      /must not contain/,
    );
  });

  test("happy — DELETE /drafts/<id> → {success, id}", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: {}, status: 204 };
    });
    const r = (await gmailDeleteDraft(FAKE_CTX, { id: "r9" })) as { success: boolean; id: string };
    expect(r).toEqual({ success: true, id: "r9" });
    expect(opts?.url).toContain("/gmail/v1/users/me/drafts/r9");
    expect(String(opts?.method).toUpperCase()).toBe("DELETE");
  });
});
