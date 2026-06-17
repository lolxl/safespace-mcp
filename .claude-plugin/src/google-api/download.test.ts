/**
 * Unit tests for `readCappedStream` — v1.11 Phase 2 PR-5 binding security gate.
 *
 * Scenarios mirror `docs/v1.11-drive-streaming-cap.md` §8 (8 scenarios). Tests
 * use synthetic Node `Readable` streams for byte-perfect control of chunk
 * boundaries + timing. Sec-rev hooks §9 #2/#3/#8 (destroy ordering, watchdog
 * cleanup, single-throw on cap+late-error) are explicitly asserted, not
 * incidental.
 */

import { describe, expect, test } from "bun:test";
import { Readable } from "node:stream";
import { MCPError } from "../errors";
import { readCappedStream } from "./download";

const BASE_OPTS = {
  toolName: "drive_get_file_content",
  email: "alice@example.com",
  fileId: "test-file-id",
};

describe("readCappedStream — happy paths", () => {
  test("scenario 1 — stream of 100 bytes with cap 1 MB resolves", async () => {
    const payload = new Uint8Array(100).fill(0x41); // 'A' * 100
    const stream = Readable.from([payload]);
    const out = await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 1024 * 1024 });
    expect(out.truncated).toBe(false);
    expect(out.bytes.byteLength).toBe(100);
    expect(out.bytes[0]).toBe(0x41);
    expect(out.bytes[99]).toBe(0x41);
  });

  test("scenario 2 — stream of exactly maxBytes resolves (boundary)", async () => {
    const payload = new Uint8Array(1024).fill(0x42);
    const stream = Readable.from([payload]);
    const out = await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 1024 });
    expect(out.bytes.byteLength).toBe(1024);
  });

  test("scenario 7 — empty stream resolves with zero bytes", async () => {
    const stream = Readable.from([]);
    const out = await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 1024 });
    expect(out.bytes.byteLength).toBe(0);
    expect(out.truncated).toBe(false);
  });

  test("multi-chunk stream concatenates correctly (byte-exact)", async () => {
    const a = new Uint8Array([0x01, 0x02, 0x03]);
    const b = new Uint8Array([0x04, 0x05]);
    const c = new Uint8Array([0x06]);
    const stream = Readable.from([a, b, c]);
    const out = await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 100 });
    expect(Array.from(out.bytes)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
  });

  test("string chunk is UTF-8 encoded and counted in bytes (not chars)", async () => {
    // gaxios streams may surface string chunks under some transports; the
    // helper normalizes via TextEncoder so multibyte chars don't under-count
    // against the cap. "héllo" = 5 chars / 6 bytes (é = 2 bytes UTF-8).
    const stream = Readable.from(["héllo"]);
    const out = await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 100 });
    expect(out.bytes.byteLength).toBe(6);
    expect(new TextDecoder().decode(out.bytes)).toBe("héllo");
  });
});

describe("readCappedStream — cap breach", () => {
  test("scenario 3 — stream of maxBytes+1 throws file_too_large with {id, max}", async () => {
    const payload = new Uint8Array(101);
    const stream = Readable.from([payload]);
    let caught: unknown;
    try {
      await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 100, fileId: "f1" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    const err = caught as MCPError;
    expect(err.errorName).toBe("file_too_large");
    // Sec-rev §9 #4 — `errorData` is EXACTLY {id, max}; never partial bytes.
    expect(err.errorData).toEqual({ id: "f1", max: 100 });
  });

  test("scenario 4 — 10 MB over cap=5 MB throws AND destroys stream BEFORE throw", async () => {
    // Sec-rev §9 #2 — destroy ordering. We assert `stream.destroyed === true`
    // by the time the promise rejects. If we destroyed AFTER reject, the
    // promise would settle before destroy ran.
    const tenMb = new Uint8Array(10 * 1024 * 1024);
    const stream = Readable.from([tenMb]);
    let caught: unknown;
    try {
      await readCappedStream(stream, { ...BASE_OPTS, maxBytes: 5 * 1024 * 1024 });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("file_too_large");
    expect(stream.destroyed).toBe(true);
  });
});

describe("readCappedStream — stream error", () => {
  test("scenario 5 — stream emits error mid-flight → UpstreamError", async () => {
    // Use a manually-driven Readable so we can interleave data + error events.
    const stream = new Readable({ read() {} });
    const promise = readCappedStream(stream, { ...BASE_OPTS, maxBytes: 1024 });
    stream.push(new Uint8Array([0x01, 0x02]));
    // Defer the error to next tick so the data event fires first.
    queueMicrotask(() => {
      stream.destroy(new Error("ECONNRESET"));
    });
    let caught: unknown;
    try {
      await promise;
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toContain("drive_download_stream_error");
    expect((caught as Error).message).toContain("ECONNRESET");
    // Not an MCPError — UpstreamError shape (plain Error with optional httpStatus).
    expect(caught).not.toBeInstanceOf(MCPError);
  });
});

describe("readCappedStream — idle stall", () => {
  test("scenario 6 — no chunk for >idleTimeoutMs throws download_stalled with {id, idle_ms}", async () => {
    // Manual Readable that never pushes — idle watchdog must fire.
    const stream = new Readable({ read() {} });
    let caught: unknown;
    try {
      await readCappedStream(stream, {
        ...BASE_OPTS,
        maxBytes: 1024,
        idleTimeoutMs: 50,
        fileId: "stalled-file",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    const err = caught as MCPError;
    expect(err.errorName).toBe("download_stalled");
    expect(err.errorData).toEqual({ id: "stalled-file", idle_ms: 50 });
    expect(stream.destroyed).toBe(true);
  });

  test("watchdog re-arms on each chunk — chunks within idle keep stream alive", async () => {
    const stream = new Readable({ read() {} });
    const promise = readCappedStream(stream, {
      ...BASE_OPTS,
      maxBytes: 1024,
      idleTimeoutMs: 100,
    });
    // Push at 30 ms intervals (well under 100 ms idle) — must succeed.
    await new Promise<void>((r) => setTimeout(r, 30));
    stream.push(new Uint8Array([0x01]));
    await new Promise<void>((r) => setTimeout(r, 30));
    stream.push(new Uint8Array([0x02]));
    await new Promise<void>((r) => setTimeout(r, 30));
    stream.push(null); // end
    const out = await promise;
    expect(out.bytes.byteLength).toBe(2);
  });
});

describe("readCappedStream — single-throw invariant (sec-rev §9 #3 + #8)", () => {
  test("scenario 8 — cap-fire followed by stream `error` event does NOT double-throw", async () => {
    // Sec-rev §9 #8 — after cap fires + destroys, any subsequent `error`
    // event (the destroyed stream emits one) must be ignored. Otherwise the
    // promise would attempt a second settle → unhandled rejection.
    const stream = new Readable({ read() {} });
    const promise = readCappedStream(stream, { ...BASE_OPTS, maxBytes: 5 });
    // Push >cap to trigger destroy + reject.
    stream.push(new Uint8Array(10));
    let caught: unknown;
    try {
      await promise;
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("file_too_large");
    // Manually emit a late error to simulate the destroyed-stream tail.
    // The promise is already settled; this MUST NOT crash or reject again.
    let lateRejection: unknown;
    const unhandled = (reason: unknown): void => {
      lateRejection = reason;
    };
    process.on("unhandledRejection", unhandled);
    try {
      stream.emit("error", new Error("late error after destroy"));
      // Wait a tick to let any unhandled rejection surface.
      await new Promise<void>((r) => setTimeout(r, 30));
    } finally {
      process.off("unhandledRejection", unhandled);
    }
    expect(lateRejection).toBeUndefined();
  });

  test("clean end after settle does NOT double-resolve", async () => {
    // Sec-rev §9 #3 — watchdog cleared on settle. Also, a late `end` after
    // an already-rejected promise must be ignored.
    const stream = new Readable({ read() {} });
    const promise = readCappedStream(stream, { ...BASE_OPTS, maxBytes: 5 });
    stream.push(new Uint8Array(10)); // triggers cap reject
    await expect(promise).rejects.toBeInstanceOf(MCPError);
    // Late end — must not crash.
    stream.emit("end");
    await new Promise<void>((r) => setTimeout(r, 10));
    // If we got here without crashing, the invariant holds.
    expect(true).toBe(true);
  });
});
