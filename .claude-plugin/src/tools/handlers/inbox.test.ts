// v1.102 (W0) — inbox_read handler: curated projection, cursor/limit defaulting, the
// corrupt-store → inbox_read_failed mapping. Uses the injected `read` seam (no real store).

import { describe, expect, test } from "bun:test";
import { MCPError } from "../../errors";
import type { InboxReadResult } from "../../webhook/inbox-store";
import type { InboxRow } from "../../webhook/types";
import { inboxRead } from "./inbox";

// inbox_read ignores ctx (credential {kind:"none"}); a bare cast satisfies the signature.
const CTX = { credential: { kind: "none" } } as never;

function row(seq: number, text: string): InboxRow {
  return {
    seq,
    provider: "slack",
    event_id: `Ev${seq}`,
    received_at: "2026-06-16T00:00:00.000Z",
    expires_at: "2026-06-17T00:00:00.000Z",
    msg: { provider_message_id: `m${seq}`, ts: `${seq}.0`, sender_id: "U1", sender_name: null, channel_id: "C1", text },
  };
}

describe("inbox_read handler", () => {
  test("projects rows to the curated shape + passes the cursor/limit through", async () => {
    const captured: Array<{ provider: string; afterSeq: number; limit: number }> = [];
    const read = async (_f: string, provider: string, afterSeq: number, limit: number): Promise<InboxReadResult> => {
      captured.push({ provider, afterSeq, limit });
      return { messages: [row(1, "hi"), row(2, "there")], max_seq: 2, oldest_seq: 1 };
    };
    const out = (await inboxRead(CTX, { provider: "slack", after_seq: 5, limit: 10 }, { read: read as never, inboxFile: "/x" })) as Record<string, unknown>;
    expect(captured[0]).toEqual({ provider: "slack", afterSeq: 5, limit: 10 });
    expect(out.provider).toBe("slack");
    expect(out.max_seq).toBe(2);
    expect(out.oldest_seq).toBe(1);
    const msgs = out.messages as Array<Record<string, unknown>>;
    expect(msgs).toHaveLength(2);
    expect(msgs[0]).toEqual({ seq: 1, event_id: "Ev1", received_at: "2026-06-16T00:00:00.000Z", provider_message_id: "m1", ts: "1.0", sender_id: "U1", sender_name: null, channel_id: "C1", text: "hi" });
  });

  test("defaults after_seq=0 and limit=50 when omitted; clamps limit to 100", async () => {
    const seen: Array<{ afterSeq: number; limit: number }> = [];
    const read = async (_f: string, _p: string, afterSeq: number, limit: number): Promise<InboxReadResult> => {
      seen.push({ afterSeq, limit });
      return { messages: [], max_seq: afterSeq, oldest_seq: null };
    };
    await inboxRead(CTX, { provider: "slack" }, { read: read as never });
    await inboxRead(CTX, { provider: "slack", limit: 9999 }, { read: read as never });
    await inboxRead(CTX, { provider: "slack", after_seq: -3 }, { read: read as never }); // invalid → 0
    expect(seen).toEqual([{ afterSeq: 0, limit: 50 }, { afterSeq: 0, limit: 100 }, { afterSeq: 0, limit: 50 }]);
  });

  test("a corrupt store throw → inbox_read_failed (no content echoed)", async () => {
    const read = async (): Promise<InboxReadResult> => {
      throw new Error("[safespace] inbox store invalid: not valid JSON");
    };
    try {
      await inboxRead(CTX, { provider: "slack" }, { read: read as never });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("inbox_read_failed");
    }
  });

  test("an MCPError from the store passes through unchanged", async () => {
    const read = async (): Promise<InboxReadResult> => {
      throw new MCPError("inbox_read_failed", { reason: "store_unavailable" });
    };
    try {
      await inboxRead(CTX, { provider: "slack" }, { read: read as never });
      throw new Error("expected throw");
    } catch (e) {
      expect((e as MCPError).errorName).toBe("inbox_read_failed");
    }
  });
});
