/**
 * v1.11 Phase 3 PR-1 — multipart construction + parse unit tests.
 *
 * Kept separate from the handler test file so the multipart format is
 * exercised without spinning up the full handler stack (auth, sanitize,
 * audit, error mapping). Handler tests in handlers.test.ts assert the
 * security gates + the gaxios-level request shape; these tests pin the
 * wire format itself.
 */

import { describe, expect, test } from "bun:test";
import {
  buildBatchModifyBody,
  newBoundary,
  parseBatchResponse,
  type BatchSubResponse,
} from "./batch";

describe("newBoundary", () => {
  test("starts with 'batch_' and contains a UUID-shaped suffix", () => {
    const b = newBoundary();
    expect(b.startsWith("batch_")).toBe(true);
    // crypto.randomUUID format: 8-4-4-4-12 hex chars
    expect(b).toMatch(
      /^batch_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  test("two consecutive calls return different values", () => {
    const a = newBoundary();
    const b = newBoundary();
    expect(a).not.toBe(b);
  });
});

describe("buildBatchModifyBody", () => {
  const VALID_ID_A = "19de5a8c628b9010";
  const VALID_ID_B = "19de5a8c628b9011";
  const BOUNDARY = "batch_test_boundary_abc";

  test("emits one part per id + closing marker", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A, VALID_ID_B],
      { addLabelIds: ["STARRED"] },
      BOUNDARY,
    );
    // 2 opening + 1 closing
    const opens = body.split(`--${BOUNDARY}`).length - 1;
    expect(opens).toBe(3);
    // Closing marker is `--boundary--`
    expect(body).toContain(`--${BOUNDARY}--\r\n`);
  });

  test("each sub-request targets /gmail/v1/users/me/messages/{id}/modify", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A, VALID_ID_B],
      { addLabelIds: ["STARRED"] },
      BOUNDARY,
    );
    expect(body).toContain(`POST /gmail/v1/users/me/messages/${VALID_ID_A}/modify`);
    expect(body).toContain(`POST /gmail/v1/users/me/messages/${VALID_ID_B}/modify`);
  });

  test("part Content-Type is application/http", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { addLabelIds: ["STARRED"] },
      BOUNDARY,
    );
    expect(body).toContain("Content-Type: application/http");
  });

  test("Content-ID per part uses the message id", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A, VALID_ID_B],
      { addLabelIds: ["STARRED"] },
      BOUNDARY,
    );
    expect(body).toContain(`Content-ID: <${VALID_ID_A}>`);
    expect(body).toContain(`Content-ID: <${VALID_ID_B}>`);
  });

  test("sub-body JSON contains addLabelIds when provided", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { addLabelIds: ["STARRED", "Label_42"] },
      BOUNDARY,
    );
    expect(body).toContain(`{"addLabelIds":["STARRED","Label_42"]}`);
  });

  test("sub-body JSON contains removeLabelIds when provided", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { removeLabelIds: ["UNREAD"] },
      BOUNDARY,
    );
    expect(body).toContain(`{"removeLabelIds":["UNREAD"]}`);
  });

  test("sub-body JSON contains both when both provided", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { addLabelIds: ["Label_X"], removeLabelIds: ["INBOX"] },
      BOUNDARY,
    );
    expect(body).toContain(`{"addLabelIds":["Label_X"],"removeLabelIds":["INBOX"]}`);
  });

  test("empty addLabelIds is omitted from sub-body (no-op guard)", () => {
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { addLabelIds: [], removeLabelIds: ["UNREAD"] },
      BOUNDARY,
    );
    expect(body).toContain(`{"removeLabelIds":["UNREAD"]}`);
    expect(body).not.toContain("addLabelIds");
  });

  test("sub-request Content-Length is byte-correct (not char-correct)", () => {
    // Multi-byte UTF-8 in a label name — make sure we count bytes, not chars.
    const body = buildBatchModifyBody(
      [VALID_ID_A],
      { addLabelIds: ["タグ"] },
      BOUNDARY,
    );
    const expectedJson = `{"addLabelIds":["タグ"]}`;
    const expectedByteLen = Buffer.byteLength(expectedJson, "utf8");
    expect(body).toContain(`Content-Length: ${expectedByteLen}`);
  });

  test("empty ids array produces only the closing marker (no sub-requests)", () => {
    // Handler boundary rejects empty ids before reaching here, but the
    // function must not produce malformed output if called directly.
    const body = buildBatchModifyBody([], { addLabelIds: ["STARRED"] }, BOUNDARY);
    expect(body).toBe(`--${BOUNDARY}--\r\n`);
  });
});

describe("parseBatchResponse", () => {
  test("parses two 204 sub-responses in order", () => {
    const boundary = "batch_xyz";
    const body =
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `Content-ID: <response-19de5a8c628b9010>\r\n` +
      `\r\n` +
      `HTTP/1.1 204 No Content\r\n` +
      `Date: Mon, 19 May 2026 00:00:00 GMT\r\n` +
      `\r\n` +
      `\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `Content-ID: <response-19de5a8c628b9011>\r\n` +
      `\r\n` +
      `HTTP/1.1 204 No Content\r\n` +
      `\r\n` +
      `\r\n` +
      `--${boundary}--\r\n`;
    const out = parseBatchResponse(body, boundary);
    expect(out).toHaveLength(2);
    expect(out[0]?.status).toBe(204);
    expect(out[1]?.status).toBe(204);
  });

  test("parses 200 sub-response with JSON body", () => {
    const boundary = "batch_xyz";
    const responseBody = `{"id":"19de5a8c628b9010","labelIds":["STARRED","INBOX"]}`;
    const body =
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `Content-ID: <response-19de5a8c628b9010>\r\n` +
      `\r\n` +
      `HTTP/1.1 200 OK\r\n` +
      `Content-Type: application/json\r\n` +
      `\r\n` +
      responseBody +
      `\r\n` +
      `--${boundary}--\r\n`;
    const out = parseBatchResponse(body, boundary);
    expect(out).toHaveLength(1);
    expect(out[0]?.status).toBe(200);
    expect(out[0]?.body).toBe(responseBody);
  });

  test("parses mixed success + failure (200 + 404)", () => {
    const boundary = "batch_xyz";
    const errBody = `{"error":{"code":404,"message":"Not Found"}}`;
    const body =
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `\r\n` +
      `HTTP/1.1 200 OK\r\n` +
      `\r\n` +
      `\r\n` +
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `\r\n` +
      `HTTP/1.1 404 Not Found\r\n` +
      `Content-Type: application/json\r\n` +
      `\r\n` +
      errBody +
      `\r\n` +
      `--${boundary}--\r\n`;
    const out = parseBatchResponse(body, boundary);
    expect(out).toHaveLength(2);
    expect(out[0]?.status).toBe(200);
    expect(out[1]?.status).toBe(404);
    expect(out[1]?.body).toContain("Not Found");
  });

  test("LF-only (no CRLF) variant also parses", () => {
    // Some intermediaries normalize CRLF→LF. Be tolerant.
    const boundary = "batch_xyz";
    const body =
      `--${boundary}\n` +
      `Content-Type: application/http\n` +
      `\n` +
      `HTTP/1.1 204 No Content\n` +
      `\n` +
      `\n` +
      `--${boundary}--\n`;
    const out = parseBatchResponse(body, boundary);
    expect(out).toHaveLength(1);
    expect(out[0]?.status).toBe(204);
  });

  test("empty body returns empty array", () => {
    expect(parseBatchResponse("", "batch_xyz")).toEqual([]);
  });

  test("missing boundary returns empty array (caller treats as upstream malformed)", () => {
    expect(parseBatchResponse("garbage", "batch_xyz")).toEqual([]);
  });

  test("part without HTTP line yields status=0 (malformed sub-response signal)", () => {
    const boundary = "batch_xyz";
    // No `HTTP/1.x` line in the sub-response section.
    const body =
      `--${boundary}\r\n` +
      `Content-Type: application/http\r\n` +
      `\r\n` +
      `garbage no status line\r\n` +
      `\r\n` +
      `\r\n` +
      `--${boundary}--\r\n`;
    const out: BatchSubResponse[] = parseBatchResponse(body, boundary);
    expect(out).toHaveLength(1);
    expect(out[0]?.status).toBe(0);
  });
});
