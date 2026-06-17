/**
 * Capped streaming reader for Drive downloads.
 *
 * BINDING SECURITY GATE for `drive_get_file_content`. Future Drive download
 * tools MUST route through `readCappedStream`, not bypass it. The pre-flight
 * metadata `size` check is advisory only; TOCTOU between pre-flight and
 * download is bounded by THIS helper's per-chunk cap.
 *
 * Design source of truth: `docs/v1.11-drive-streaming-cap.md`. The 7 sec-rev
 * hooks (§9) are enforced inline; deviations require an ADR.
 */

import type { Readable } from "node:stream";
import { MCPError } from "../errors";
// v1.64 Phase B (B4 — D4): import from the `handlers/shared` leaf, not the
// `../tools/handlers` barrel — same circular-import cut as errors.ts (the barrel
// re-exports handlers that import google-api/, forming a type-layer cycle).
import type { UpstreamError } from "../tools/handlers/shared";

export interface CappedDownloadResult {
  /** Exact concatenation of stream chunks; length ≤ `maxBytes`. */
  bytes: Uint8Array;
  /** Always `false`. Overflow throws — never silently truncates. */
  truncated: false;
}

export interface CappedDownloadOpts {
  /** Per-call hard cap; binding gate. NO default — every caller MUST set it. */
  maxBytes: number;
  /** Abort if no chunk arrives within N ms after stream starts. Default 15_000. */
  idleTimeoutMs?: number;
  /** Tool name for error context (logging side; not stored in MCPError data). */
  toolName: string;
  /** Account email for error context (logging side; not stored in MCPError data). */
  email: string;
  /** File ID — included in MCPError data so the caller knows which file failed. */
  fileId: string;
}

const DEFAULT_IDLE_MS = 15_000;

/**
 * Accumulate a gaxios stream-response body until end-of-stream, capping at
 * `maxBytes`. Behavior matrix:
 *   - cap breach          → destroy stream, throw MCPError("file_too_large", {id, max})
 *   - stream `error`      → destroy stream, throw UpstreamError (msg from underlying err)
 *   - idle > idleTimeoutMs → destroy stream, throw MCPError("download_stalled", {id, idle_ms})
 *   - clean `end`         → resolve { bytes, truncated: false }
 *
 * Single-throw invariant: cap-firing destroys the stream and a subsequent
 * `error` event from the destroyed stream MUST NOT trigger a double-throw or
 * unhandled rejection. We use a `settled` flag to ignore late events.
 */
export function readCappedStream(
  stream: Readable,
  opts: CappedDownloadOpts,
): Promise<CappedDownloadResult> {
  const idleMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_MS;
  const chunks: Uint8Array[] = [];
  let received = 0;
  let settled = false;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;

  return new Promise<CappedDownloadResult>((resolve, reject) => {
    const clearIdle = (): void => {
      if (idleTimer !== undefined) {
        clearTimeout(idleTimer);
        idleTimer = undefined;
      }
    };

    const armIdle = (): void => {
      clearIdle();
      idleTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        // Sec-rev §9 #2: destroy BEFORE throw, so the TCP connection releases
        // promptly. Throw-then-destroy leaks the socket until GC.
        try {
          stream.destroy();
        } catch {
          // Swallow — destroy on an already-destroyed stream can throw.
        }
        // Sec-rev §9 #4: error `data` is EXACTLY {id, idle_ms}; partial bytes
        // never leak.
        reject(
          new MCPError("download_stalled", {
            id: opts.fileId,
            idle_ms: idleMs,
          }),
        );
      }, idleMs);
    };

    const settle = (
      kind: "resolve" | "reject",
      payload: CappedDownloadResult | Error,
    ): void => {
      if (settled) return;
      settled = true;
      // Sec-rev §9 #3: clear the idle watchdog on EVERY terminal path. A
      // late-firing timer after settle would crash Bun via unhandled rejection.
      clearIdle();
      if (kind === "resolve") {
        resolve(payload as CappedDownloadResult);
      } else {
        reject(payload as Error);
      }
    };

    stream.on("data", (raw: Uint8Array | string) => {
      if (settled) return;
      // gaxios stream chunks may arrive as Buffer or string depending on the
      // transport; normalize to Uint8Array so byteLength is consistent and the
      // final concat is binary-safe.
      const chunk =
        typeof raw === "string" ? new TextEncoder().encode(raw) : raw;
      received += chunk.byteLength;
      if (received > opts.maxBytes) {
        // Sec-rev §9 #8: claim settled BEFORE destroy(). Node's stream
        // `destroy()` is async-by-default but not contractually so — a stream
        // impl that emits 'error' synchronously would let the error listener
        // race in and settle with UpstreamError, masking file_too_large.
        // Mirrors the idle-timer path's ordering.
        settled = true;
        clearIdle();
        try {
          stream.destroy();
        } catch {
          // ignore
        }
        // Sec-rev §9 #4: `data` is EXACTLY {id, max}.
        reject(
          new MCPError("file_too_large", {
            id: opts.fileId,
            max: opts.maxBytes,
          }),
        );
        return;
      }
      chunks.push(chunk);
      // Re-arm idle watchdog on every successful chunk.
      armIdle();
    });

    stream.on("end", () => {
      if (settled) return;
      const out = new Uint8Array(received);
      let offset = 0;
      for (const c of chunks) {
        out.set(c, offset);
        offset += c.byteLength;
      }
      settle("resolve", { bytes: out, truncated: false });
    });

    stream.on("error", (err: Error) => {
      if (settled) return;
      // Surface as UpstreamError so middleware treats it as a generic upstream
      // failure (no retry, no auth fallout). The download-side cap & stall
      // throws are the structured failures; raw stream errors are everything
      // else (TLS reset, ECONNRESET mid-flight, etc.).
      const e: UpstreamError = new Error(
        `drive_download_stream_error_${opts.toolName}: ${err.message ?? "(no message)"}`,
      );
      settle("reject", e);
    });

    // Start the idle watchdog immediately — if the stream produces no `data`
    // event within idleMs, we abort. (Headers timeout is gaxios' job.)
    armIdle();
  });
}
