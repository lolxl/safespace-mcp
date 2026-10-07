// v1.44 — Gmail threads + attachments (gmail_get_thread / gmail_get_attachment).
// Tested through the SDK-level `setGaxiosHandler` seam, same as the other
// Gmail READ handlers. Both are READ tools (no allowlist / env setup needed).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { currentTier } from "../tier";
import { gmailGetAttachment, gmailGetThread } from "./handlers";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const FAKE_CTX: ToolContext = {
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
}

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("gmailGetThread (READ tool)", () => {
  test("happy — fetches /threads/<id> with format=metadata", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return {
        data: { id: "t1", historyId: "99", messages: [{ id: "m1", threadId: "t1", snippet: "hi" }] },
        status: 200,
      };
    });
    const r = (await gmailGetThread(FAKE_CTX, { id: "t1" })) as { id: string; messages: unknown[] };
    expect(r.id).toBe("t1");
    expect(r.messages).toHaveLength(1);
    expect(opts?.url).toContain("/gmail/v1/users/me/threads/t1");
    expect(opts?.params?.format).toBe("metadata");
  });

  test("non-empty id gate — empty id → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(gmailGetThread(FAKE_CTX, { id: "" })).rejects.toThrow(/non-empty 'id'/);
    expect(called).toBe(false);
  });

  test("injection-clean id gate — CR/LF in id → reject", async () => {
    await expect(gmailGetThread(FAKE_CTX, { id: "t1\r\nx" })).rejects.toThrow(/must not contain/);
  });
});

describe("gmailGetAttachment (READ tool)", () => {
  test("happy — fetches /messages/<mid>/attachments/<aid>, returns {size,data}", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let opts: CapturedOpts | undefined;
    setGaxiosHandler(async (o) => {
      opts = o as CapturedOpts;
      return { data: { size: 12, data: "QUJDREVG" }, status: 200 };
    });
    const r = (await gmailGetAttachment(FAKE_CTX, {
      message_id: "m1",
      attachment_id: "a1",
    })) as { size: number; data: string };
    expect(r.data).toBe("QUJDREVG");
    expect(opts?.url).toContain("/gmail/v1/users/me/messages/m1/attachments/a1");
  });

  test("non-empty message_id gate — empty → reject, no HTTP", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "", attachment_id: "a1" }),
    ).rejects.toThrow(/non-empty 'message_id'/);
    expect(called).toBe(false);
  });

  test("non-empty attachment_id gate — empty → reject, no HTTP", async () => {
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "m1", attachment_id: "" }),
    ).rejects.toThrow(/non-empty 'attachment_id'/);
  });

  test("injection-clean gates — CR/LF in either id → reject", async () => {
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "m1\r\nx", attachment_id: "a1" }),
    ).rejects.toThrow(/must not contain/);
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "m1", attachment_id: "a1\nx" }),
    ).rejects.toThrow(/must not contain/);
  });

  test("5 MB cap via declared size → file_too_large (-32007)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({
      data: { size: 6 * 1024 * 1024, data: "QQQQ" },
      status: 200,
    }));
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "m1", attachment_id: "a1" }),
    ).rejects.toMatchObject({ errorName: "file_too_large" });
  });

  test("cap via decoded-length fallback when size absent → reject oversized", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    // ~7 M base64url chars decode to ~5.25 MB > 5 MB cap; no `size` field.
    const big = "A".repeat(7 * 1024 * 1024);
    setGaxiosHandler(async () => ({ data: { data: big }, status: 200 }));
    await expect(
      gmailGetAttachment(FAKE_CTX, { message_id: "m1", attachment_id: "a1" }),
    ).rejects.toMatchObject({ errorName: "file_too_large" });
  });

  test("under-cap with size absent — decoded-length fallback passes", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { data: "QUJD" }, status: 200 }));
    const r = (await gmailGetAttachment(FAKE_CTX, {
      message_id: "m1",
      attachment_id: "a1",
    })) as { data: string };
    expect(r.data).toBe("QUJD");
  });
});
