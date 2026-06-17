// v1.65 Phase C — web_fetch handler tests. The handler is thin: validate the one
// arg, delegate to the SSRF gate, map a stray error. Happy path uses the injected
// `fetch` seam; the reject paths exercise the REAL gate (private IP / bad scheme).
import { describe, expect, test } from "bun:test";
import { MCPError } from "../../errors";
import type { ToolContext } from "../types";
import { webFetchHandler } from "./web-fetch";

// web_fetch is keyless — the handler never reads ctx, so a bare keyless ctx is fine.
const KEYLESS_CTX = { credential: { kind: "none" }, tier: "read", audit: { record() {} } } as unknown as ToolContext;

describe("webFetchHandler", () => {
  test("rejects a missing / non-string / blank url with a plain Error", async () => {
    await expect(webFetchHandler(KEYLESS_CTX, {})).rejects.toThrow(/must be a non-empty string/);
    await expect(webFetchHandler(KEYLESS_CTX, { url: 123 })).rejects.toThrow(/non-empty string/);
    await expect(webFetchHandler(KEYLESS_CTX, { url: "   " })).rejects.toThrow(/non-empty string/);
  });

  test("returns the gate result on success (injected fetch)", async () => {
    const result = {
      url: "https://example.com/",
      final_url: "https://example.com/",
      status: 200,
      content_type: "text/html",
      content: "<p>hi</p>",
    };
    const out = await webFetchHandler(KEYLESS_CTX, { url: "  https://example.com/  " }, {
      fetch: async (u) => {
        expect(u).toBe("https://example.com/"); // trimmed before the gate
        return result;
      },
    });
    expect(out).toEqual(result);
  });

  test("passes an MCPError from the gate through unchanged", async () => {
    const e = new MCPError("url_blocked_by_policy", { reason: "scheme_not_allowed" });
    try {
      await webFetchHandler(KEYLESS_CTX, { url: "https://x/" }, {
        fetch: async () => {
          throw e;
        },
      });
      throw new Error("expected throw");
    } catch (caught) {
      expect(caught).toBe(e);
    }
  });

  test("wraps a non-MCPError from the gate as web_fetch_failed", async () => {
    try {
      await webFetchHandler(KEYLESS_CTX, { url: "https://x/" }, {
        fetch: async () => {
          throw new Error("socket boom 10.1.2.3");
        },
      });
      throw new Error("expected throw");
    } catch (caught) {
      expect(caught).toBeInstanceOf(MCPError);
      expect((caught as MCPError).errorName).toBe("web_fetch_failed");
      expect((caught as Error).message).not.toContain("10.1.2.3");
    }
  });

  test("end-to-end (real gate): a private IP URL is blocked", async () => {
    try {
      await webFetchHandler(KEYLESS_CTX, { url: "http://169.254.169.254/latest/meta-data/" });
      throw new Error("expected throw");
    } catch (caught) {
      expect(caught).toBeInstanceOf(MCPError);
      expect((caught as MCPError).errorName).toBe("url_blocked_by_policy");
      expect((caught as MCPError).errorData.reason).toBe("private_or_reserved_ip");
    }
  });

  test("end-to-end (real gate): a file:// scheme is blocked", async () => {
    try {
      await webFetchHandler(KEYLESS_CTX, { url: "file:///etc/passwd" });
      throw new Error("expected throw");
    } catch (caught) {
      expect((caught as MCPError).errorName).toBe("url_blocked_by_policy");
      expect((caught as MCPError).errorData.reason).toBe("scheme_not_allowed");
    }
  });
});
