// The stdio transport SafeSpace serves MCP over (the only transport).
//
// @modelcontextprotocol/sdk 1.32 added a read-buffer cap to the stdio transport
// (STDIO_DEFAULT_MAX_BUFFER_SIZE = 10 MiB). Exceeding it CLOSES the transport —
// every later request is lost, not just the oversized one. Our own per-tool caps
// allow larger frames than that: drive_create_file accepts 5 MiB of UTF-8
// content, and JSON encoding can grow it up to 6x (a control character becomes
// `\u00XX`), so a legitimate call can reach ~30 MiB on the wire. The cap is set
// to cover that worst case while still bounding memory.
//
// The SDK keeps an onerror set before connect() and chains its own after it, so
// the hook below makes the new failure mode visible on stderr instead of a
// silent disconnect.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Readable, Writable } from "node:stream";

/** Largest single JSON-RPC frame accepted on stdin (bytes). */
export const STDIO_MAX_BUFFER_BYTES = 32 * 1024 * 1024;

export function createStdioTransport(stdin?: Readable, stdout?: Writable): StdioServerTransport {
  const transport = new StdioServerTransport(stdin, stdout, {
    maxBufferSize: STDIO_MAX_BUFFER_BYTES,
  });
  transport.onerror = (err) => {
    console.error(`[safespace] stdio transport error: ${err.message}`);
  };
  return transport;
}
