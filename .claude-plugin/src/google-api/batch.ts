/**
 * v1.11 Phase 3 PR-1 — Gmail batch multipart helpers.
 *
 * The googleapis Node SDK has NO built-in batch interface. (The deprecated
 * `google-batch` npm package was last released 2017-11-22 and explicitly
 * warns it is "for poc purpose only" — REJECTED.) Per Gmail's documented
 * batch protocol, a batch request is a single POST to
 * `https://gmail.googleapis.com/batch/gmail/v1` with `Content-Type:
 * multipart/mixed; boundary=...`, each part a serialized HTTP sub-request.
 *
 * THIS MODULE OWNS only construction/parse — no auth, no token attachment,
 * no error mapping. Callers wire it into an OAuth2Client.request() call.
 * Kept isolated so the multipart format is unit-testable without spinning
 * up the full handler stack.
 *
 * Threat model: this module touches only caller-supplied IDs (validated
 * against /^[0-9a-f]{16,}$/ at the handler boundary) + label IDs (validated
 * non-empty strings at the handler boundary) + a server-supplied response
 * body. No secrets transit here. Multipart-parse failures throw plain
 * Errors; callers route those through `mapGoogleError` as upstream failures
 * — the parse layer is NOT a security boundary, the handler-level gates are.
 *
 * Limits documented at <https://developers.google.com/gmail/api/guides/batch>:
 *   - Max 100 sub-requests per batch (Gmail's API allows up to 1000; we cap
 *     at 100 at the handler boundary as a prompt-injection blast-radius guard).
 *   - Sub-requests must have `Content-Type: application/http` part headers.
 *   - Each sub-request line uses the SDK path (no host), e.g.
 *     `POST /gmail/v1/users/me/messages/{id}/modify`.
 *
 * Note: we use ONE sub-request per message ID rather than Gmail's native
 * `users.messages.batchModify` REST endpoint. Why? batchModify applies the
 * SAME label change to all ids atomically (no per-message status), and a
 * single bad id rejects the whole call with an opaque 400. Composing N
 * single-message modify sub-requests inside ONE HTTP batch keeps the same
 * single-round-trip throughput win (~300x vs sequential single-message HTTP calls)
 * while preserving per-message error visibility — partial failures are
 * surfaced by sub-response status codes, not buried by an all-or-nothing
 * 400. This also means a future variant ("modify N messages with N different
 * labels") slots into the same transport without a second endpoint.
 */

const CRLF = "\r\n";

/**
 * Defense-in-depth ID validator. The handler-level gate
 * (GMAIL_MESSAGE_ID_RE in handlers.ts) is the authoritative check; this
 * re-validation makes batch.ts non-violable even if a future caller forgets
 * to gate, OR if the handler gate regresses. Cost: one regex per ID at
 * build time (negligible vs the HTTP round-trip).
 *
 * Sec-rev PR #95 §A2: without this, a regression of the handler check (or
 * a new caller bypassing it) lets CRLF / `<` / `>` into the Content-ID line
 * or sub-request URL — multipart smuggling vector.
 */
const HEX_ID_RE = /^[0-9a-f]{16,}$/;

/** A single label modification (same shape for every message in the batch). */
export interface BatchModifyOp {
  addLabelIds?: string[];
  removeLabelIds?: string[];
}

/** Parsed result for a single sub-response. */
export interface BatchSubResponse {
  /** HTTP status code from the sub-response (200 success / 4xx / 5xx). */
  status: number;
  /** Raw response body (JSON for success, error envelope for failure). May be empty. */
  body: string;
}

/**
 * Generate a multipart boundary string. Format follows RFC 2046 + Google's
 * own examples: `batch_<random>`. crypto.randomUUID is used for collision
 * safety (a body byte that matches the boundary would corrupt the request);
 * the chance of a Gmail message ID containing the UUID is effectively 0,
 * but using randomness is the standard pattern.
 *
 * Entropy budget: crypto.randomUUID is RFC 4122 v4 = **122 bits** of
 * CSPRNG-sourced entropy (4 bits of version + 2 bits of variant are fixed).
 * Collision requires ~2^61 calls (birthday bound) — billions of years at any
 * realistic rate. Sufficient for A1 boundary-collision threat (see sec-rev
 * PR #95 §A1); no need to switch to crypto.randomBytes(16) = 128 bits.
 */
export function newBoundary(): string {
  return `batch_${crypto.randomUUID()}`;
}

/**
 * Build the multipart/mixed body for a Gmail batch request that applies the
 * same `op` (addLabelIds / removeLabelIds) to every message in `ids`.
 *
 * Each sub-request is a serialized HTTP POST to
 * `/gmail/v1/users/me/messages/{id}/modify` with a JSON body containing the
 * label change. Content-ID is set to the message id so the caller can later
 * correlate sub-responses (Gmail prefixes each response Content-ID with
 * `response-` per documented protocol).
 */
export function buildBatchModifyBody(
  ids: string[],
  op: BatchModifyOp,
  boundary: string,
): string {
  // Defense-in-depth: re-validate each id before it touches multipart wire
  // format. See HEX_ID_RE comment above.
  for (const id of ids) {
    if (!HEX_ID_RE.test(id)) {
      throw new Error(
        `buildBatchModifyBody: id ${JSON.stringify(id)} fails hex-only check (handler-side gate regressed?)`,
      );
    }
  }

  // Build the JSON body once — every sub-request uses the same label change.
  // omit empty arrays so we never POST `{addLabelIds:[],removeLabelIds:[]}`
  // (Gmail accepts it but it's a no-op that wastes a sub-request slot).
  const bodyObj: Record<string, string[]> = {};
  if (op.addLabelIds && op.addLabelIds.length > 0) {
    bodyObj.addLabelIds = op.addLabelIds;
  }
  if (op.removeLabelIds && op.removeLabelIds.length > 0) {
    bodyObj.removeLabelIds = op.removeLabelIds;
  }
  const bodyJson = JSON.stringify(bodyObj);

  const parts: string[] = [];
  for (const id of ids) {
    // Each part: --boundary + part headers + blank line + sub-request lines.
    // Sub-request: METHOD + path + sub-headers + blank line + JSON body.
    parts.push(
      `--${boundary}${CRLF}` +
        `Content-Type: application/http${CRLF}` +
        `Content-Transfer-Encoding: binary${CRLF}` +
        // Content-ID lets the caller correlate sub-responses 1:1 with the
        // input ids. We use the id verbatim; the handler's hex-ID gate
        // (^[0-9a-f]{16,}$) already excludes any chars that need escaping
        // (CRLF / `<` / `>` / spaces are all impossible in a hex string).
        `Content-ID: <${id}>${CRLF}` +
        CRLF +
        `POST /gmail/v1/users/me/messages/${id}/modify${CRLF}` +
        `Content-Type: application/json${CRLF}` +
        `Content-Length: ${Buffer.byteLength(bodyJson, "utf8")}${CRLF}` +
        CRLF +
        bodyJson +
        CRLF,
    );
  }
  // Final closing boundary marker per RFC 2046 §5.1.1.
  parts.push(`--${boundary}--${CRLF}`);
  return parts.join("");
}

/**
 * Parse a multipart/mixed batch response into per-sub-response status + body.
 * Sub-responses arrive in the same order as the input sub-requests (per the
 * Gmail batch contract), so the caller can correlate by index without
 * inspecting Content-ID.
 *
 * Tolerant parse: anything that doesn't look like a part is skipped; we ONLY
 * trust the `--boundary` markers + the `HTTP/1.x <status>` line inside each
 * part. Failure modes:
 *   - boundary not found → returns [] (caller treats as upstream malformed)
 *   - part with no recognizable HTTP line → status=0, body="" (caller treats
 *     as upstream malformed for that sub-request)
 */
export function parseBatchResponse(
  body: string,
  boundary: string,
): BatchSubResponse[] {
  if (!body || !boundary) return [];

  // Gmail uses CRLF but some intermediaries normalize to LF — accept both.
  const normalized = body.replace(/\r\n/g, "\n");
  const delimiter = `--${boundary}`;
  // If the boundary doesn't appear, the body is malformed at the envelope
  // level; the caller treats an empty result as "upstream malformed" for
  // every sub-request slot. Returning [] keeps the contract simple.
  if (!normalized.includes(delimiter)) return [];

  // Split on the delimiter; the first chunk is preamble (often empty), and
  // the last chunk after `--boundary--` is epilogue.
  const chunks = normalized.split(delimiter);

  const results: BatchSubResponse[] = [];
  for (const rawChunk of chunks) {
    // Skip preamble + closing marker. Closing marker chunk starts with `--`.
    const chunk = rawChunk.replace(/^\n/, "").replace(/\n$/, "");
    if (chunk === "" || chunk.startsWith("--")) continue;

    // Each part: <part-headers>\n\n<sub-response>
    // sub-response: <HTTP/1.x status line>\n<sub-headers>\n\n<body>
    const partSplit = chunk.split("\n\n");
    if (partSplit.length < 2) {
      // Malformed part — no separator between part-headers and sub-response.
      results.push({ status: 0, body: "" });
      continue;
    }

    // First section: part headers (Content-Type / Content-ID).
    // Second section onward: the sub-response (which itself contains a blank
    // line between sub-headers and sub-body). Rejoin in case the sub-body
    // contained `\n\n` itself (JSON normally doesn't, but be defensive).
    const subResponse = partSplit.slice(1).join("\n\n");
    const subSplit = subResponse.split("\n\n");
    const statusLineSection = subSplit[0] ?? "";
    const subBody = subSplit.slice(1).join("\n\n");

    // Status line: HTTP/1.1 200 OK
    const firstLine = statusLineSection.split("\n")[0] ?? "";
    const match = firstLine.match(/^HTTP\/[\d.]+\s+(\d{3})/);
    const status = match && match[1] ? parseInt(match[1], 10) : 0;

    results.push({ status, body: subBody.trim() });
  }
  return results;
}
