// v1.51 (backlog B3) — gmail_list_filters / gmail_create_filter /
// gmail_delete_filter. SDK-level mock via setGaxiosHandler (same surface as
// contacts-write.test.ts). Security-relevant assertions: the `forward` action is
// rejected (persistent-exfil block), TRASH/SPAM-add is blocked (reuses
// system_label_forbidden), criteria/action allowlist-construction rejects
// unknown fields, free-text byte caps + header-injection on criteria, label
// caps, and tier defense-in-depth (read tier → scope_mismatch, no SDK call).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { gmailCreateFilter, gmailDeleteFilter, gmailListFilters } from "./handlers";
import { MCPError } from "../errors";
import type { ToolContext } from "./types";

const FAKE_CTX: ToolContext = { allowedAccounts: null,
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};
const READ_CTX: ToolContext = { allowedAccounts: null,
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "read",
};

const FILTER_ID = "ANe1Bmj4iJOaQxY_z-123";

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("gmail_create_filter", () => {
  test("happy path — criteria + addLabelIds; POSTs {criteria, action}; returns created filter", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      body = (opts.data ?? {}) as Record<string, unknown>;
      return { data: { id: FILTER_ID, criteria: body.criteria, action: body.action }, status: 200 };
    });
    const res = (await gmailCreateFilter(FAKE_CTX, {
      criteria: { from: "boss@example.com", subject: "invoice" },
      action: { addLabelIds: ["Label_42"] },
    })) as { id: string };
    expect(res.id).toBe(FILTER_ID);
    expect(method).toBe("POST");
    expect(body.criteria).toEqual({ from: "boss@example.com", subject: "invoice" });
    expect(body.action).toEqual({ addLabelIds: ["Label_42"] });
  });

  test("removeLabelIds:['INBOX'] (auto-archive) is allowed — the real auto-organize use case", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as Record<string, unknown>;
      return { data: { id: FILTER_ID }, status: 200 };
    });
    await gmailCreateFilter(FAKE_CTX, {
      criteria: { query: "from:newsletter@x.com" },
      action: { removeLabelIds: ["INBOX", "UNREAD"] },
    });
    expect(body.action).toEqual({ removeLabelIds: ["INBOX", "UNREAD"] });
  });

  test("accepts the full benign criteria set (bools / size / sizeComparison)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as Record<string, unknown>;
      return { data: { id: FILTER_ID }, status: 200 };
    });
    await gmailCreateFilter(FAKE_CTX, {
      criteria: {
        to: "me@example.com",
        negatedQuery: "is:chat",
        hasAttachment: true,
        excludeChats: true,
        size: 1048576,
        sizeComparison: "larger",
      },
      action: { addLabelIds: ["Label_1"] },
    });
    expect(body.criteria).toEqual({
      to: "me@example.com",
      negatedQuery: "is:chat",
      hasAttachment: true,
      excludeChats: true,
      size: 1048576,
      sizeComparison: "larger",
    });
  });

  test("REJECT the forward action (persistent exfiltration block) — no SDK call", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { forward: "attacker@evil.com" },
      }),
    ).rejects.toThrow(/forward.*not permitted/);
    // forward present alongside an otherwise-valid label add is STILL rejected.
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: ["Label_1"], forward: "attacker@evil.com" },
      }),
    ).rejects.toThrow(/forward.*not permitted/);
    expect(called).toBe(false);
  });

  test("REJECT addLabelIds containing TRASH or SPAM (system_label_forbidden)", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: ["TRASH"] },
      }),
    ).rejects.toBeInstanceOf(MCPError);
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: ["Label_1", "SPAM"] },
      }),
    ).rejects.toBeInstanceOf(MCPError);
  });

  test("removeLabelIds:['TRASH'] is allowed (recovery direction; only add is blocked)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: FILTER_ID }, status: 200 }));
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { removeLabelIds: ["TRASH"] },
      }),
    ).resolves.toBeDefined();
  });

  test("rejects an unknown criteria field (allowlist construction)", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com", evilField: "boom" },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/criteria field 'evilField' is not allowed/);
  });

  test("rejects an unknown action field (only addLabelIds / removeLabelIds)", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: ["Label_1"], smtpMsa: { host: "evil" } },
      }),
    ).rejects.toThrow(/action field 'smtpMsa' is not allowed/);
  });

  test("rejects an empty criteria (would match ALL mail)", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, { criteria: {}, action: { addLabelIds: ["Label_1"] } }),
    ).rejects.toThrow(/at least one match field/);
  });

  test("rejects an empty action (no add/remove; forward is blocked)", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, { criteria: { from: "x@y.com" }, action: {} }),
    ).rejects.toThrow(/at least one of addLabelIds \/ removeLabelIds/);
  });

  test("label cap — >10 ids per side → label_limit_exceeded", async () => {
    const eleven = Array.from({ length: 11 }, (_, i) => `Label_${i}`);
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: eleven },
      }),
    ).rejects.toBeInstanceOf(MCPError);
  });

  test("criteria free-text byte cap (>1024) + header-injection rejected", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { subject: "x".repeat(1025) },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/exceeds 1024 bytes/);
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { from: "a@b.com\r\nBcc: evil@x.com" },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/CR\/LF/);
  });

  test("criteria type gates — size integer, sizeComparison enum, bool fields", async () => {
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { size: 1.5 },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/non-negative integer/);
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { sizeComparison: "biggerish" },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/smaller\|larger\|unspecified/);
    await expect(
      gmailCreateFilter(FAKE_CTX, {
        criteria: { hasAttachment: "yes" },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toThrow(/must be a boolean/);
  });

  test("tier=read → scope_mismatch (defense-in-depth), no SDK call", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      gmailCreateFilter(READ_CTX, {
        criteria: { from: "x@y.com" },
        action: { addLabelIds: ["Label_1"] },
      }),
    ).rejects.toBeInstanceOf(MCPError);
    expect(called).toBe(false);
  });
});

describe("gmail_delete_filter", () => {
  test("happy path — DELETE; returns {success, id}", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      return { data: {}, status: 204 };
    });
    const res = (await gmailDeleteFilter(FAKE_CTX, { id: FILTER_ID })) as {
      success: boolean;
      id: string;
    };
    expect(res).toEqual({ success: true, id: FILTER_ID });
    expect(method).toBe("DELETE");
  });

  test("rejects an empty id", async () => {
    await expect(gmailDeleteFilter(FAKE_CTX, { id: "" })).rejects.toThrow(/non-empty 'id'/);
  });

  test("rejects a malformed id (path traversal / CRLF)", async () => {
    await expect(
      gmailDeleteFilter(FAKE_CTX, { id: "../etc/passwd" }),
    ).rejects.toThrow(/invalid Gmail filter id format/);
    await expect(
      gmailDeleteFilter(FAKE_CTX, { id: "abc\r\ndef" }),
    ).rejects.toThrow(/invalid Gmail filter id format/);
  });

  test("tier=read → scope_mismatch (defense-in-depth), no SDK call", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 204 };
    });
    await expect(
      gmailDeleteFilter(READ_CTX, { id: FILTER_ID }),
    ).rejects.toBeInstanceOf(MCPError);
    expect(called).toBe(false);
  });
});

describe("gmail_list_filters", () => {
  test("happy path — GET; returns {filter:[...]}", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      return {
        data: { filter: [{ id: FILTER_ID, criteria: { from: "x@y.com" }, action: { addLabelIds: ["Label_1"] } }] },
        status: 200,
      };
    });
    const res = (await gmailListFilters(FAKE_CTX, {})) as { filter: unknown[] };
    expect(method).toBe("GET");
    expect(Array.isArray(res.filter)).toBe(true);
    expect(res.filter).toHaveLength(1);
  });
});
