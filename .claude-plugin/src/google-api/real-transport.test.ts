// Real-transport regression: handlers that UPLOAD a body must hand googleapis a
// stream that terminates, or the request hangs forever on Bun.
//
// Background: googleapis-common wraps a string `media.body` in a PassThrough ended
// by `push(null)`; gaxios >= 7 then sends `Readable.toWeb(<that stream>)`, and on
// Bun 1.3.x that web stream never emits EOF. The in-process gaxios mock
// (test-utils.ts) can never see this — it never touches a request body — so this
// test runs the handler in a SUBPROCESS through the real googleapis/gaxios stack
// (the bun test preload mocks `gaxios` process-wide) with only `globalThis.fetch`
// replaced by an in-memory server that reads the request body to EOF.
//
// Proven failing before the fix: with `media: { body: content }` (string) the
// fixture reports "request body never reached EOF".

import { describe, expect, test } from "bun:test";
import { join } from "node:path";

const FIXTURE = join(import.meta.dir, "real-transport-fixture.ts");

interface FixtureOut {
  ok: boolean;
  error?: string;
  res?: { id: string };
  method: string;
  url: string;
  contentType: string | null;
  bodyText: string | null;
  bodyLength?: number;
  bodyHasPayload?: boolean;
  errorName?: string;
  httpStatus?: number;
}

async function runFixture(scenario: string): Promise<FixtureOut> {
  const proc = Bun.spawn([process.execPath, "run", FIXTURE, scenario], {
    stdout: "pipe",
    stderr: "pipe",
    // The fixture must NOT inherit the parent's mock preload (it is `bun run`, not
    // `bun test`, so bunfig [test] preload does not apply) — real gaxios is the point.
    env: { ...process.env },
  });
  const killer = setTimeout(() => proc.kill(), 25_000);
  const out = await new Response(proc.stdout).text();
  await proc.exited;
  clearTimeout(killer);
  return JSON.parse(out.trim().split("\n").pop() ?? "{}") as FixtureOut;
}

describe("real googleapis/gaxios transport — upload bodies reach EOF", () => {
  test("drive_create_file: multipart body is fully delivered (UTF-8 intact)", async () => {
    const r = await runFixture("drive_create_file");
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.method).toBe("POST");
    expect(r.url).toContain("/upload/drive/v3/files");
    expect(r.contentType).toMatch(/^multipart\/related; boundary=/);
    const boundary = /boundary=(.+)$/.exec(r.contentType ?? "")![1];
    expect(r.bodyText).toContain('{"name":"notes.txt","mimeType":"text/plain"}');
    expect(r.bodyText).toContain("\r\n\r\nhéllo wörld ✓\r\n");
    expect(r.bodyText!.endsWith(`--${boundary}--`)).toBe(true);
    expect(r.res?.id).toBe("1NewFileAAAAAAAAAAAAAAA");
  }, 30_000);

  test("drive_create_file: empty content still terminates", async () => {
    const r = await runFixture("drive_create_file_empty");
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
    const boundary = /boundary=(.+)$/.exec(r.contentType ?? "")![1];
    expect(r.bodyText!.endsWith(`--${boundary}--`)).toBe(true);
  }, 30_000);

  test("drive_create_file: multi-MB content is delivered whole", async () => {
    const r = await runFixture("drive_create_file_large");
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.bodyLength).toBeGreaterThan(4 * 1024 * 1024);
    expect(r.bodyHasPayload).toBe(true);
  }, 30_000);
});

// Response-side shape contract of gaxios 8 under real googleapis (stream / text /
// WHATWG Headers / string error bodies) — the in-process mock cannot prove these.
describe("real googleapis/gaxios transport — response shapes", () => {
  test("drive_get_file_content: stream body is consumed by readCappedStream", async () => {
    const r = await runFixture("drive_get_content");
    expect(r.error).toBeUndefined();
    expect((r as unknown as { res: { content: string } }).res.content).toBe("hello from drive");
  }, 30_000);

  test("drive_get_file_content: 403 on a streamed download maps to scope_mismatch (string error body)", async () => {
    const r = await runFixture("drive_get_content_403");
    expect(r.ok).toBe(false);
    expect(r.errorName).toBe("scope_mismatch");
  }, 30_000);

  test("forms_publish: real transport sends the allowlist-constructed setPublishSettings body", async () => {
    const r = await runFixture("forms_publish");
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.method).toBe("POST");
    expect(r.url).toContain("/v1/forms/1FormAAAAAAAAAAAAAAAAAA:setPublishSettings");
    expect(JSON.parse(r.bodyText ?? "{}")).toEqual({
      publishSettings: { publishState: { isPublished: true, isAcceptingResponses: true } },
      updateMask: "publish_state",
    });
    expect((r as unknown as { res: unknown }).res).toEqual({
      form_id: "1FormAAAAAAAAAAAAAAAAAA",
      published: true,
      accepting_responses: true,
    });
  }, 30_000);

  test("gmail_modify_messages_batch: text body + WHATWG Content-Type header boundary parse", async () => {
    const r = await runFixture("gmail_batch_ok");
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
  }, 30_000);

  test("gmail_modify_messages_batch: outer 403 (text responseType) maps to scope_mismatch", async () => {
    const r = await runFixture("gmail_batch_403");
    expect(r.ok).toBe(false);
    expect(r.errorName).toBe("scope_mismatch");
  }, 30_000);
});
