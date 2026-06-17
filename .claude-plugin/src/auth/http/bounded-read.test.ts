// Shared streaming byte-cap primitive (auth/http/bounded-read.ts): the cap is enforced on the
// bytes actually streamed (independent of Content-Length), a bodiless response yields "" (the
// sec-N1 null-body fix — the former unbounded `res.text()` fallback is gone), and an oversize
// stream throws the generic `Error("response_too_large")` that each connector's client maps to
// its own closed-set api_error. The end-to-end cap behavior is also covered, per connector, by
// the github/notion/slack client tests; this exercises the extracted leaf directly.

import { describe, expect, test } from "bun:test";
import { MAX_RESPONSE_BYTES, readBounded } from "./bounded-read";

/** A streamed (Content-Length-less) Response from the given UTF-8 parts. */
function streamOf(...parts: string[]): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      const enc = new TextEncoder();
      for (const p of parts) c.enqueue(enc.encode(p));
      c.close();
    },
  });
  return new Response(stream, { status: 200 });
}

describe("readBounded", () => {
  test("MAX_RESPONSE_BYTES is the 5 MB context-protection cap", () => {
    expect(MAX_RESPONSE_BYTES).toBe(5 * 1024 * 1024);
  });

  test("reads a normal body to a string", async () => {
    expect(await readBounded(new Response("hello world", { status: 200 }), MAX_RESPONSE_BYTES)).toBe("hello world");
  });

  test("concatenates multiple stream chunks (no Content-Length)", async () => {
    expect(await readBounded(streamOf("foo", "bar", "baz"), MAX_RESPONSE_BYTES)).toBe("foobarbaz");
  });

  test("sec-N1: a null-body response returns '' (NOT an unbounded res.text() fallback)", async () => {
    const res = new Response(null);
    expect(res.body).toBeNull(); // precondition: this is the bodiless path the fix targets
    expect(await readBounded(res, MAX_RESPONSE_BYTES)).toBe("");
  });

  test("throws response_too_large once STREAMED bytes exceed maxBytes (header-less, no bypass)", async () => {
    await expect(readBounded(streamOf("x".repeat(11)), 10)).rejects.toThrow("response_too_large");
  });

  test("a body exactly at the cap is allowed; one byte over throws", async () => {
    expect(await readBounded(streamOf("x".repeat(10)), 10)).toBe("x".repeat(10));
    await expect(readBounded(streamOf("x".repeat(10), "y"), 10)).rejects.toThrow("response_too_large");
  });
});
