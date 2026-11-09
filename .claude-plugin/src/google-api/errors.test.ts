/**
 * Tests for `mapGoogleError` — the googleapis → MCPError / UpstreamError
 * mapping layer.
 *
 * Covers each branch of the mapping table:
 *   - 401 → UpstreamError with httpStatus=401 (middleware retry trigger)
 *   - 403 + scope reason → MCPError("scope_mismatch") (terminal)
 *   - 403 other → UpstreamError with httpStatus=403
 *   - 404 → UpstreamError with httpStatus=404 (callers may pattern-match)
 *   - 429 → MCPError("rate_limited") (terminal)
 *   - 5xx → UpstreamError with httpStatus=<status>
 *   - network error (no response) → UpstreamError with NO httpStatus
 *   - other 4xx → UpstreamError with httpStatus=<status>
 *   - completely empty err → still throws (no crash)
 */

import { describe, test, expect } from "bun:test";
import { mapGoogleError, toGoogleError } from "./errors";
import { makeGaxiosError } from "./test-utils";
import { MCPError } from "../errors";

const ctx = { tool: "test_tool" };

/** Capture the thrown error (mapGoogleError always throws). */
function thrownBy(fn: () => unknown): Error & { httpStatus?: number } {
  try {
    fn();
    throw new Error("expected fn to throw");
  } catch (e) {
    return e as Error & { httpStatus?: number };
  }
}

describe("mapGoogleError — status code mapping", () => {
  test("401 → UpstreamError with httpStatus=401 (middleware retry trigger)", () => {
    const err = makeGaxiosError({ status: 401 });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_unauthorized_test_tool");
    expect(thrown.httpStatus).toBe(401);
    expect(thrown).not.toBeInstanceOf(MCPError);
  });

  test("403 with PERMISSION_DENIED → MCPError scope_mismatch", () => {
    const err = makeGaxiosError({ status: 403, errorStatus: "PERMISSION_DENIED" });
    try {
      mapGoogleError(err, ctx);
      throw new Error("expected mapGoogleError to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("scope_mismatch");
      expect((e as MCPError).errorData).toEqual({ tool: "test_tool" });
    }
  });

  test("403 with insufficientPermissions reason → scope_mismatch", () => {
    const err = makeGaxiosError({
      status: 403,
      errors: [{ reason: "insufficientPermissions" }],
    });
    expect(() => mapGoogleError(err, ctx)).toThrow(MCPError);
  });

  test("403 with insufficientScopes reason → scope_mismatch", () => {
    const err = makeGaxiosError({
      status: 403,
      errors: [{ reason: "insufficientScopes" }],
    });
    try {
      mapGoogleError(err, ctx);
      throw new Error("expected throw");
    } catch (e) {
      expect((e as MCPError).errorName).toBe("scope_mismatch");
    }
  });

  test("403 with forbidden reason → scope_mismatch", () => {
    const err = makeGaxiosError({
      status: 403,
      errors: [{ reason: "forbidden" }],
    });
    try {
      mapGoogleError(err, ctx);
      throw new Error("expected throw");
    } catch (e) {
      expect((e as MCPError).errorName).toBe("scope_mismatch");
    }
  });

  test("403 with unrecognized reason → UpstreamError with httpStatus=403", () => {
    const err = makeGaxiosError({
      status: 403,
      errorMessage: "some other 403 reason",
      errors: [{ reason: "weirdUnknownReason" }],
    });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_403_test_tool: some other 403 reason");
    expect(thrown.httpStatus).toBe(403);
    expect(thrown).not.toBeInstanceOf(MCPError);
  });

  test("429 → MCPError rate_limited", () => {
    const err = makeGaxiosError({
      status: 429,
      errorStatus: "RESOURCE_EXHAUSTED",
      errors: [{ reason: "userRateLimitExceeded" }],
    });
    try {
      mapGoogleError(err, ctx);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("rate_limited");
      expect((e as MCPError).errorData).toEqual({ tool: "test_tool" });
    }
  });

  test("500 → UpstreamError with httpStatus=500", () => {
    const err = makeGaxiosError({ status: 500, errorMessage: "Internal" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_upstream_500_test_tool: Internal");
    expect(thrown.httpStatus).toBe(500);
  });

  test("503 → UpstreamError with httpStatus=503", () => {
    const err = makeGaxiosError({ status: 503, errorMessage: "Unavailable" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toContain("google_api_upstream_503");
    expect(thrown.httpStatus).toBe(503);
  });

  test("400 → UpstreamError with httpStatus=400", () => {
    const err = makeGaxiosError({ status: 400, errorMessage: "Bad request: invalid value" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_400_test_tool: Bad request: invalid value");
    expect(thrown.httpStatus).toBe(400);
  });

  test("404 → UpstreamError with httpStatus=404 (caller pattern-match for not_found)", () => {
    const err = makeGaxiosError({ status: 404, errorMessage: "Not Found" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_404_test_tool: Not Found");
    expect(thrown.httpStatus).toBe(404);
  });
});

describe("mapGoogleError — network errors (no HTTP response)", () => {
  test("ECONNRESET → UpstreamError without httpStatus", () => {
    const err = makeGaxiosError({ code: "ECONNRESET", errorMessage: "Connection reset" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toBe("google_api_network_ECONNRESET_test_tool: Connection reset");
    expect(thrown.httpStatus).toBeUndefined();
  });

  test("ETIMEDOUT → UpstreamError without httpStatus", () => {
    const err = makeGaxiosError({ code: "ETIMEDOUT", errorMessage: "Request timed out" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toContain("google_api_network_ETIMEDOUT");
    expect(thrown.httpStatus).toBeUndefined();
  });

  test("network error with no code → google_api_network_unknown_<tool>", () => {
    const err = makeGaxiosError({ errorMessage: "Generic network failure" });
    const thrown = thrownBy(() => mapGoogleError(err, ctx));
    expect(thrown.message).toContain("google_api_network_unknown_test_tool");
    expect(thrown.httpStatus).toBeUndefined();
  });
});

describe("mapGoogleError — edge cases", () => {
  test("completely empty object → still throws (no crash)", () => {
    expect(() => mapGoogleError({}, ctx)).toThrow(/google_api_network_unknown/);
  });

  test("null input → still throws (no crash)", () => {
    expect(() => mapGoogleError(null, ctx)).toThrow(/google_api_network_unknown/);
  });

  test("undefined input → still throws (no crash)", () => {
    expect(() => mapGoogleError(undefined, ctx)).toThrow(/google_api_network_unknown/);
  });

  test("tool name is preserved in error message across all branches", () => {
    const tools = ["gmail_search", "drive_get_file_content", "weird_tool_with_underscores"];
    for (const tool of tools) {
      const err = makeGaxiosError({ status: 500 });
      expect(() => mapGoogleError(err, { tool })).toThrow(
        new RegExp(`google_api_upstream_500_${tool}`),
      );
    }
  });

  test("non-GaxiosError-shaped value (regular Error) → network branch", () => {
    const err = new Error("totally unrelated error");
    expect(() => mapGoogleError(err, ctx)).toThrow(/google_api_network_unknown/);
  });
});

describe("toGoogleError — v1.64 B4 handler catch boundary (RETURNS, never throws)", () => {
  test("MCPError passthrough — returns the SAME instance unchanged (NOT network-wrapped)", () => {
    // The security-load-bearing property: a handler's own validation / policy
    // MCPError (file_too_large, formula_rejected, batch_too_large, …) thrown
    // inside the try is RETURNED as-is, so `throw toGoogleError(...)` re-throws it
    // verbatim — exactly what the pre-B4 explicit `if (err instanceof MCPError)
    // throw err` did. Were it routed through the mapper it would be mangled into
    // a `google_api_network_unknown` UpstreamError (data + code lost).
    const original = new MCPError("file_too_large", { id: "abc", size: 99, max: 10 });
    const out = toGoogleError(original, ctx);
    expect(out).toBe(original); // identity: same instance, same code + data
    expect(out).toBeInstanceOf(MCPError);
    expect((out as MCPError).errorName).toBe("file_too_large");
  });

  test("Gaxios 401 → returns UpstreamError{httpStatus:401} (so withToolContext's retry still fires)", () => {
    const out = toGoogleError(makeGaxiosError({ status: 401 }), ctx) as Error & { httpStatus?: number };
    expect(out).not.toBeInstanceOf(MCPError);
    expect(out.httpStatus).toBe(401);
    expect(out.message).toBe("google_api_unauthorized_test_tool");
  });

  test("Gaxios 403 scope reason → returns MCPError(scope_mismatch)", () => {
    const out = toGoogleError(
      makeGaxiosError({ status: 403, errorStatus: "PERMISSION_DENIED" }),
      ctx,
    );
    expect(out).toBeInstanceOf(MCPError);
    expect((out as MCPError).errorName).toBe("scope_mismatch");
  });

  test("Gaxios 429 → returns MCPError(rate_limited)", () => {
    const out = toGoogleError(makeGaxiosError({ status: 429 }), ctx);
    expect(out).toBeInstanceOf(MCPError);
    expect((out as MCPError).errorName).toBe("rate_limited");
  });

  test("Gaxios 404 → returns UpstreamError{httpStatus:404}", () => {
    const out = toGoogleError(makeGaxiosError({ status: 404 }), ctx) as Error & { httpStatus?: number };
    expect(out).not.toBeInstanceOf(MCPError);
    expect(out.httpStatus).toBe(404);
  });

  test("network error (no HTTP response) → returns UpstreamError with NO httpStatus", () => {
    const out = toGoogleError(new Error("ECONNRESET"), ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBeUndefined();
    expect(out.message).toMatch(/google_api_network_unknown/);
  });

  test("equivalence: a non-MCPError maps identically via toGoogleError and mapGoogleError (shared core)", () => {
    const g = makeGaxiosError({ status: 500, errorMessage: "Internal" });
    const returned = toGoogleError(g, ctx) as Error & { httpStatus?: number };
    const thrown = thrownBy(() => mapGoogleError(g, ctx));
    expect(returned.message).toBe(thrown.message);
    expect(returned.httpStatus).toBe(thrown.httpStatus);
  });
});

// gaxios >= 7 delivers `response.data` as the RAW STRING for responseType
// "text" (gmail batch) and for non-2xx "stream" (drive downloads). The mapper
// must read the Google error envelope out of that string.
describe("toGoogleError — string response bodies (gaxios 8 text/stream)", () => {
  const withBody = (status: number, data: unknown, message = "boom"): Error =>
    Object.assign(new Error(message), { response: { status, data } });

  test("403 insufficientPermissions in a JSON STRING body → scope_mismatch", () => {
    const body = JSON.stringify({
      error: { code: 403, status: "PERMISSION_DENIED", errors: [{ reason: "insufficientPermissions" }] },
    });
    const out = toGoogleError(withBody(403, body), ctx);
    expect(out).toBeInstanceOf(MCPError);
    expect((out as MCPError).errorName).toBe("scope_mismatch");
  });

  test("403 quotaExceeded in a JSON STRING body → youtube_quota_exceeded", () => {
    const body = JSON.stringify({ error: { errors: [{ reason: "quotaExceeded" }] } });
    const out = toGoogleError(withBody(403, body), ctx);
    expect((out as MCPError).errorName).toBe("youtube_quota_exceeded");
  });

  test("string body message is used for the upstream message", () => {
    const body = JSON.stringify({ error: { message: "Backend Error" } });
    const out = toGoogleError(withBody(500, body, "raw gaxios message"), ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBe(500);
    expect(out.message).toBe("google_api_upstream_500_test_tool: Backend Error");
  });

  // gaxios 8 sets err.message to the RAW response body, so model message == body.
  test("non-JSON string (HTML) / malformed JSON / oversized / non-object → fixed `HTTP <status>`, body NEVER echoed, never throws", () => {
    const big = "{" + " ".repeat(70_000) + "}";
    for (const data of ["<html>Forbidden SECRET-BODY</html>", '{"error": {', big, "[1,2]", "null", ""]) {
      const out = toGoogleError(withBody(403, data, data), ctx) as Error & { httpStatus?: number };
      expect(out).not.toBeInstanceOf(MCPError);
      expect(out.httpStatus).toBe(403);
      expect(out.message).toBe("google_api_403_test_tool: HTTP 403");
    }
  });

  test("JSON string that is an object without `error` → fixed fallback (body not echoed)", () => {
    const body = '{"foo":"SECRET-BODY"}';
    const out = toGoogleError(withBody(404, body, body), ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBe(404);
    expect(out.message).toBe("google_api_404_test_tool: HTTP 404");
  });

  test("envelope message is truncated to a small bound", () => {
    const body = JSON.stringify({ error: { message: "m".repeat(5000) } });
    const out = toGoogleError(withBody(500, body, body), ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBe(500);
    expect(out.message.length).toBeLessThan(600);
    expect(out.message.startsWith("google_api_upstream_500_test_tool: mmmm")).toBe(true);
  });

  test("network error (no response) keeps err.message but truncated", () => {
    const out = toGoogleError(new Error("e".repeat(5000)), ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBeUndefined();
    expect(out.message.length).toBeLessThan(600);
  });

  // The upstream body is attacker-influenced: wrong-typed fields must be ignored,
  // never trusted and never able to make the mapper throw.
  test("wrong-typed envelope fields are ignored; mapper returns with the right httpStatus", () => {
    const hostile: unknown[] = [
      { error: { message: { toString: null } } },
      { error: { message: 42, status: ["PERMISSION_DENIED"], errors: "nope" } },
      { error: { errors: [null] } },
      { error: { errors: [{ reason: { toString: null } }] } },
      { error: { errors: [["insufficientPermissions"]] } },
      { error: "PERMISSION_DENIED" },
      { error: null },
      { error: [] },
      [],
      null,
      42,
    ];
    for (const data of hostile) {
      for (const encode of [false, true]) {
        const wire = encode ? JSON.stringify(data) : data;
        const out = toGoogleError(withBody(403, wire, "x"), ctx) as Error & { httpStatus?: number };
        expect(out).not.toBeInstanceOf(MCPError); // hostile types must NOT be granted scope_mismatch
        expect(out.httpStatus).toBe(403);
        expect(out.message).toBe("google_api_403_test_tool: HTTP 403");
      }
    }
  });

  test("non-number response.status is treated as a network error; hostile code/message never throw", () => {
    const e = Object.assign(new Error("x"), {
      code: { toString: null },
      message: { toString: null },
      response: { status: "403", data: {} },
    });
    const out = toGoogleError(e, ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBeUndefined();
    expect(out.message).toBe("google_api_network_unknown_test_tool: (no message)");
  });

  test("valid envelope with one valid + well-typed fields still works alongside junk siblings", () => {
    const body = { error: { message: "ok msg", status: "PERMISSION_DENIED", errors: [{ reason: "forbidden", message: 5 }] } };
    const out = toGoogleError(withBody(403, body, "x"), ctx);
    expect((out as MCPError).errorName).toBe("scope_mismatch");
  });

  test("gaxios 8 numeric error.code on a response-less error still maps as network error", () => {
    const e = Object.assign(new Error("x"), { code: 28 });
    const out = toGoogleError(e, ctx) as Error & { httpStatus?: number };
    expect(out.httpStatus).toBeUndefined();
    expect(out.message).toBe("google_api_network_28_test_tool: x");
  });
});
