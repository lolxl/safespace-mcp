// v1.62 — Google Forms (READ-only slice). Mirrors the read handlers
// (forms_get ≈ slides_get / docs_get_content). docs/v1.62-forms-readonly.md.
// v1.63 — Google Forms WRITE slice (forms_create ≈ slides_create, forms_modify ≈
// slides_modify with a Forms-specific DEEP content gate). docs/v1.63-forms-write.md.
//
// SECURITY: form RESPONSES are attacker-influenced free text (anyone with the
// link can submit). The handler returns the raw response payload; the untrusted
// content is wrapped by the SHARED sanitize tree-walk in withToolContext (the
// same pipeline that wraps an inbound email body / Drive doc) — there is NO
// handler-local sanitize, and NO SKIP_FIELDS carve-out for response fields, so
// respondent free-text + respondentEmail wrap normally. All ids are
// format-gated (echo the RULE, not the value).

import { MCPError } from "../../errors";
import { driveClientFromToken, formsClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import { requireSendApproval } from "../../policy/send-approval";
import type { ToolContext } from "../types";
import { enforceDriveShareWhitelist } from "./drive";
import { requireGoogle, HEADER_INJECTION_RE } from "./shared";

// Form / response ids are url-safe (the id segment from the form URL, NOT the
// full URL). Generous upper bound; mirror SLIDES_PRESENTATION_ID_RE.
const FORMS_ID_RE = /^[a-zA-Z0-9_-]{1,200}$/;
// RFC3339 instant (e.g. 2026-01-31T00:00:00Z or with millis / numeric offset).
// Anchored → ReDoS-safe (no nested quantifier over an overlapping class).
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const FORMS_RESPONSES_MAX_PAGE_SIZE = 5000; // Forms API page-size ceiling

/** Validate a url-safe id field (form_id / response_id) — type + format gate.
 *  Echoes the RULE (the field name + regex), never the bad value (no PII echo). */
function requireUrlSafeId(ctx: string, field: string, raw: unknown): string {
  if (typeof raw !== "string") {
    throw new Error(`${ctx}: '${field}' must be a string`);
  }
  if (!FORMS_ID_RE.test(raw)) {
    throw new Error(`${ctx}: '${field}' must match /^[a-zA-Z0-9_-]{1,200}$/`);
  }
  return raw;
}

/* ───────── forms_get (READ) — mirror slides_get ───────── */
export async function formsGet(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_get", "form_id", args.form_id);
  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await forms.forms.get({ formId });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "forms_get", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── forms_list_responses (READ) ─────────
 *
 * `page_size` clamped [1, 5000]; `page_token` is an opaque pass-through; the
 * optional `time_after` filter is ALLOWLIST-CONSTRUCTED into the Forms filter
 * string `timestamp >= <RFC3339>` (never a raw filter string — the v1.59
 * filters-object posture). Forms' response filter supports a timestamp
 * lower-bound; we expose exactly that, format-gated. */
export async function formsListResponses(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_list_responses", "form_id", args.form_id);

  // page_size clamp [1, 5000] (defense-in-depth; the schema's min/max is primary).
  let pageSize: number | undefined;
  if (args.page_size !== undefined) {
    if (typeof args.page_size !== "number" || !Number.isInteger(args.page_size)) {
      throw new Error("forms_list_responses: 'page_size' must be an integer");
    }
    pageSize = Math.min(Math.max(args.page_size, 1), FORMS_RESPONSES_MAX_PAGE_SIZE);
  }

  let pageToken: string | undefined;
  if (args.page_token !== undefined) {
    if (typeof args.page_token !== "string") {
      throw new Error("forms_list_responses: 'page_token' must be a string");
    }
    pageToken = args.page_token; // opaque pass-through
  }

  // time_after → `timestamp >= <RFC3339>` (allowlist-constructed; no raw filter).
  let filter: string | undefined;
  if (args.time_after !== undefined) {
    if (typeof args.time_after !== "string" || !RFC3339_RE.test(args.time_after)) {
      throw new Error(
        "forms_list_responses: 'time_after' must be an RFC3339 instant (e.g. 2026-01-31T00:00:00Z)",
      );
    }
    filter = `timestamp >= ${args.time_after}`;
  }

  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await forms.forms.responses.list({
      formId,
      ...(pageSize !== undefined ? { pageSize } : {}),
      ...(pageToken !== undefined ? { pageToken } : {}),
      ...(filter !== undefined ? { filter } : {}),
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "forms_list_responses", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── forms_get_response (READ) — single response by id ───────── */
export async function formsGetResponse(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_get_response", "form_id", args.form_id);
  const responseId = requireUrlSafeId("forms_get_response", "response_id", args.response_id);
  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await forms.forms.responses.get({ formId, responseId });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "forms_get_response", email: requireGoogle(ctx).accountId });
  }
}

/* ═════════════ v1.63 — WRITE slice ═════════════ */

const FORMS_TITLE_MAX_BYTES = 1000; // forms_create title (mirror slides_create)
const FORMS_MODIFY_MAX_REQUESTS = 50; // mirror SLIDES_MODIFY_MAX_REQUESTS
// SHALLOW defence-in-depth cap on the TOP-LEVEL item/info title+description only
// (deeper strings — choice labels, nested question titles — pass through;
// Google enforces its own field-length limits server-side; mirror slides_modify
// where structural fields pass verbatim).
const FORMS_TEXT_MAX_BYTES = 10 * 1024;
// deep-scan node budget (anti-DoS), allocated PER createItem/updateItem request
// (NOT global) — worst case = FORMS_MODIFY_MAX_REQUESTS × this, still sub-ms
// (one decrement + Set.has per node) and the requests array is itself capped.
const FORMS_SCAN_MAX_NODES = 5000;

// forms.batchUpdate POSITIVE request-type allowlist (the load-bearing top-level
// gate). Verified against forms_v1: these are the COMPLETE 6 request types. A
// Google-added 7th auto-rejects (default-deny). docs/v1.63-forms-write.md §3.2(a).
export const FORMS_MODIFY_ALLOWED_REQUEST_TYPES: ReadonlySet<string> = new Set([
  "createItem",
  "deleteItem",
  "moveItem",
  "updateItem",
  "updateFormInfo",
  "updateSettings",
]);

// The Forms-specific DEEP gate (§3.2(b)): unlike Slides (where the SSRF is a
// top-level request type left off the allowlist), Forms hides external-URL fetch
// + Drive-artifact surfaces INSIDE item content. Any of these keys anywhere in a
// createItem/updateItem item tree → reject the whole request:
//   sourceUri          — Image.sourceUri = external URL Google FETCHES (SSRF,
//                        the Sheets IMAGE / Slides createImage class); can nest
//                        inside imageItem OR questionItem.image OR questionGroupItem.image
//   imageItem/videoItem — standalone external image/video embeds
//   fileUploadQuestion  — provisions a Drive folder to collect uploads (write-side
//                        Drive artifact + storage surface)
// v1 supports text-based items only (text/choice/scale/date/time questions +
// textItem + pageBreakItem + non-image questionGroupItem). Q4-LOCKED.
const FORMS_FORBIDDEN_ITEM_KEYS: ReadonlySet<string> = new Set([
  "sourceUri",
  "imageItem",
  "videoItem",
  "fileUploadQuestion",
]);

/** Bounded recursive scan: returns the first forbidden key found anywhere in
 *  `node`, else undefined. Depth/breadth bounded by a shared node budget so a
 *  pathologically deep/wide payload cannot DoS the scan (the `requests` array is
 *  already length-capped). */
function findForbiddenItemKey(node: unknown, budget: { n: number }): string | undefined {
  if (--budget.n < 0) {
    throw new Error("forms_modify: request item is too large to validate (node budget exceeded)");
  }
  if (Array.isArray(node)) {
    for (const el of node) {
      const hit = findForbiddenItemKey(el, budget);
      if (hit !== undefined) return hit;
    }
    return undefined;
  }
  if (typeof node === "object" && node !== null) {
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (FORMS_FORBIDDEN_ITEM_KEYS.has(key)) return key;
      const hit = findForbiddenItemKey(value, budget);
      if (hit !== undefined) return hit;
    }
  }
  return undefined;
}

/** Cap a named free-text field if present (string-only; structural fields pass). */
function capText(ctx: string, label: string, value: unknown): void {
  if (typeof value === "string" && Buffer.byteLength(value, "utf-8") > FORMS_TEXT_MAX_BYTES) {
    throw new Error(`${ctx}: ${label} exceeds ${FORMS_TEXT_MAX_BYTES} bytes`);
  }
}

/* ───────── forms_create (WRITE) — mirror slides_create ─────────
 * The Forms API accepts ONLY info.title at create (items + description must be
 * added via batchUpdate). Construct { info: { title } } explicitly — never
 * forward a caller requestBody. */
export async function formsCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.title !== "string") {
    throw new Error("forms_create: 'title' must be a string");
  }
  const rawTitle = args.title;
  const trimmed = rawTitle.trim();
  if (trimmed.length === 0) {
    throw new Error("forms_create: 'title' must be non-empty after trim");
  }
  // Injection check on the RAW (pre-trim) string — a control char must be
  // rejected regardless of surrounding whitespace (mirror slides_create); the
  // byte-cap below applies to the trimmed value that is actually sent.
  if (HEADER_INJECTION_RE.test(rawTitle)) {
    throw new Error("forms_create: 'title' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  if (Buffer.byteLength(trimmed, "utf-8") > FORMS_TITLE_MAX_BYTES) {
    throw new Error(`forms_create: 'title' exceeds ${FORMS_TITLE_MAX_BYTES} bytes (defensive client-side cap)`);
  }
  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    // `unpublished: true` is sent EXPLICITLY: the Forms API treats an unset value as
    // "published and accepting responses", so we never rely on the server default.
    const res = await forms.forms.create({ unpublished: true, requestBody: { info: { title: trimmed } } });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "forms_create", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── forms_modify (WRITE) — mirror slides_modify + DEEP content gate ───────── */
export async function formsModify(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_modify", "form_id", args.form_id);

  if (!Array.isArray(args.requests)) {
    throw new Error("forms_modify: 'requests' must be an array");
  }
  if (args.requests.length === 0) {
    throw new Error("forms_modify: 'requests' array must be non-empty");
  }
  if (args.requests.length > FORMS_MODIFY_MAX_REQUESTS) {
    throw new Error(
      `forms_modify: at most ${FORMS_MODIFY_MAX_REQUESTS} requests per call (got ${args.requests.length})`,
    );
  }
  const requests = args.requests;

  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    if (typeof req !== "object" || req === null || Array.isArray(req)) {
      throw new Error(`forms_modify: requests[${i}] must be an object`);
    }
    const keys = Object.keys(req as Record<string, unknown>);
    if (keys.length !== 1) {
      throw new Error(`forms_modify: requests[${i}] must have exactly ONE key (got ${keys.length})`);
    }
    const requestType = keys[0]!;
    if (!FORMS_MODIFY_ALLOWED_REQUEST_TYPES.has(requestType)) {
      // Echo the request TYPE (Google API surface, not user data) + the allowlist.
      throw new Error(
        `forms_modify: requests[${i}] type '${requestType}' not in allowlist {createItem, deleteItem, moveItem, updateItem, updateFormInfo, updateSettings}`,
      );
    }
    const body = (req as Record<string, unknown>)[requestType];
    // DEEP content gate — createItem/updateItem carry the item tree where the
    // external-URL SSRF + Drive-artifact surfaces hide. Reject the whole request
    // if any forbidden key appears anywhere in it (§3.2(b)).
    if (requestType === "createItem" || requestType === "updateItem") {
      const hit = findForbiddenItemKey(body, { n: FORMS_SCAN_MAX_NODES });
      if (hit !== undefined) {
        throw new Error(
          `forms_modify: requests[${i}] (${requestType}) contains forbidden field '${hit}' — image/video/file-upload items are not supported (external-URL fetch = SSRF; fileUpload provisions a Drive folder). v1 supports text-based items only.`,
        );
      }
    }
    // Content byte caps on the common free-text fields (structural fields pass).
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      const b = body as Record<string, unknown>;
      capText(`forms_modify: requests[${i}]`, `${requestType}.item?.title`, (b.item as Record<string, unknown> | undefined)?.title);
      capText(`forms_modify: requests[${i}]`, `${requestType}.item?.description`, (b.item as Record<string, unknown> | undefined)?.description);
      capText(`forms_modify: requests[${i}]`, `${requestType}.info?.title`, (b.info as Record<string, unknown> | undefined)?.title);
      capText(`forms_modify: requests[${i}]`, `${requestType}.info?.description`, (b.info as Record<string, unknown> | undefined)?.description);
    }
  }

  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await forms.forms.batchUpdate({
      formId,
      requestBody: { requests: requests as object[] },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "forms_modify", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── forms_publish / forms_unpublish ─────────
 * Forms created via the API are UNPUBLISHED (accept no responses) until
 * forms.setPublishSettings flips them. Both tools share ONE allowlist-
 * constructed requestBody builder: only publishState{isPublished,
 * isAcceptingResponses} + updateMask "publish_state" ever reach the wire (both
 * state fields must be set; accepting=true with published=false is an API error,
 * and neither tool can produce that combination). Caller args beyond form_id /
 * account_id are never forwarded. */
async function setPublishSettings(
  ctx: ToolContext,
  tool: "forms_publish" | "forms_unpublish",
  formId: string,
  state: boolean,
): Promise<unknown> {
  try {
    const forms = formsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await forms.forms.setPublishSettings({
      formId,
      requestBody: {
        publishSettings: { publishState: { isPublished: state, isAcceptingResponses: state } },
        updateMask: "publish_state",
      },
    });
    const publishState = res.data.publishSettings?.publishState;
    return {
      form_id: res.data.formId ?? formId,
      published: publishState?.isPublished ?? null,
      accepting_responses: publishState?.isAcceptingResponses ?? null,
    };
  } catch (err) {
    throw toGoogleError(err, { tool, email: requireGoogle(ctx).accountId });
  }
}

/** forms_publish (SHARE): publishing exposes the form to anyone with its responder
 *  link, so it follows the drive_share_file `share_type=anyone` path exactly (a Google
 *  Form id IS a Drive file id). Gate order, ALL before any setPublishSettings call:
 *  ① handler-level tier re-check (closes `safespace exec`; same error as drive.ts)
 *  ② Drive share-whitelist (shared `enforceDriveShareWhitelist`; fail-closed;
 *     default-deny under SAFESPACE_AUTONOMOUS)
 *  ③ supervised send-approval (no-op unless SAFESPACE_REQUIRE_SEND_APPROVAL; fixed
 *     summary, no form content; target reuses the closed `drive_share` kind) */
export async function formsPublish(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_publish", "form_id", args.form_id);
  if (ctx.tier !== "share") {
    throw new MCPError("share_target_forbidden", {
      reason: "anyone_requires_share_tier",
      current_tier: ctx.tier,
      required_tier: "share",
    });
  }
  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    await enforceDriveShareWhitelist(ctx, drive, formId);
  } catch (err) {
    if (err instanceof MCPError) throw err;
    throw toGoogleError(err, { tool: "forms_publish", email: requireGoogle(ctx).accountId });
  }
  await requireSendApproval(ctx, {
    tool: "forms_publish",
    recipients: [],
    body: "",
    target: { kind: "drive_share", file_id: formId, share_type: "anyone", role: "reader" },
  });
  return setPublishSettings(ctx, "forms_publish", formId, true);
}

/** forms_unpublish (WRITE): recovery action — no whitelist / approval (like
 *  drive_unshare_file: recovery > policy). */
export async function formsUnpublish(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const formId = requireUrlSafeId("forms_unpublish", "form_id", args.form_id);
  return setPublishSettings(ctx, "forms_unpublish", formId, false);
}
