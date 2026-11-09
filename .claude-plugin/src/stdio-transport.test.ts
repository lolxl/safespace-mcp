import { afterEach, expect, spyOn, test } from "bun:test";
import { PassThrough } from "node:stream";
import { createStdioTransport, STDIO_MAX_BUFFER_BYTES } from "./stdio-transport";

// Real transport boundary: these feed bytes through the SDK's stdio framing,
// which the in-memory transport used by the handler tests never exercises.

const SDK_DEFAULT_CAP = 10 * 1024 * 1024;
const CHUNK = 64 * 1024;

function frame(id: number, padBytes: number): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id, method: "ping", params: { pad: "x".repeat(padBytes) } })}\n`;
}

async function feed(stdin: PassThrough, data: string): Promise<void> {
  for (let i = 0; i < data.length; i += CHUNK) {
    stdin.write(data.slice(i, i + CHUNK));
    if ((i / CHUNK) % 32 === 0) await new Promise((r) => setImmediate(r));
  }
  await new Promise((r) => setImmediate(r));
}

let errSpy: ReturnType<typeof spyOn> | undefined;
afterEach(() => errSpy?.mockRestore());

test("the cap covers a worst-case-escaped 5 MiB drive_create_file payload", () => {
  // 5 MiB of control characters, each JSON-escaped to `\u00XX` (6 bytes).
  expect(STDIO_MAX_BUFFER_BYTES).toBeGreaterThan(5 * 1024 * 1024 * 6);
});

test("a frame above the SDK's 10 MiB default is delivered and the transport stays open", async () => {
  const stdin = new PassThrough();
  const t = createStdioTransport(stdin, new PassThrough());
  const got: unknown[] = [];
  let closed = false;
  t.onmessage = (m) => got.push(m);
  t.onclose = () => {
    closed = true;
  };
  await t.start();

  await feed(stdin, frame(1, SDK_DEFAULT_CAP + 1024 * 1024));
  await feed(stdin, frame(2, 10));

  expect(closed).toBe(false);
  expect(got.map((m) => (m as { id: number }).id)).toEqual([1, 2]);
  await t.close();
});

test("a frame above the cap closes the transport and logs to stderr", async () => {
  errSpy = spyOn(console, "error").mockImplementation(() => {});
  const stdin = new PassThrough();
  const t = createStdioTransport(stdin, new PassThrough());
  let closed = false;
  t.onmessage = () => {};
  t.onclose = () => {
    closed = true;
  };
  await t.start();

  await feed(stdin, frame(1, STDIO_MAX_BUFFER_BYTES + 1024));
  await new Promise((r) => setTimeout(r, 10));

  expect(closed).toBe(true);
  const logged = errSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
  expect(logged).toContain("[safespace] stdio transport error:");
  expect(logged).toContain("ReadBuffer exceeded maximum size");
});
