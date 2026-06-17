// Calendar — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { calendarClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import type { ToolContext } from "../types";

import { requireGoogle, EMAIL_RECIPIENT_RE, HEADER_INJECTION_RE, sha256Hex } from "./shared";
import { hashResolvedRecipientEmails, resolveRecipientsViaContactLookup } from "./contacts";

/** Anti-DoS cap on `max_results`. Google's Calendar API max is 2500; SafeSpace
 * caps lower (matches drive_search / gmail_search blast-radius posture).
 * See docs/v1.13-calendar-api.md §3 / §7 hook #1. */
const CALENDAR_LIST_MAX_RESULTS_CAP = 100;

/** Default time-horizon when `time_max` is omitted: 7 days from `time_min`.
 * One-week look-ahead is the typical "what's next" query shape. */
const CALENDAR_DEFAULT_TIME_HORIZON_MS = 7 * 24 * 60 * 60 * 1000;

/** Calendar ID format check (design §7 hook #9).
 *
 *   - Literal "primary" — special-case for the user's own primary calendar.
 *   - Email-shape — covers BOTH user-account calendars (alice@example.com)
 *     AND Google secondary calendars (c_xxxxx@group.calendar.google.com).
 *
 * Reject anything else (whitespace, control chars, URL-unsafe bytes) at the
 * handler boundary so malformed input fails fast with a clear message rather
 * than hitting Google and returning an opaque 400/404.
 *
 * Relaxed by design — we are NOT trying to enforce RFC 5322 here; the goal
 * is to catch obviously-malformed input early. Google's server-side
 * validation is the authoritative check.
 */
const CALENDAR_ID_EMAIL_LIKE_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
function isValidCalendarId(id: string): boolean {
  if (id === "primary") return true;
  return CALENDAR_ID_EMAIL_LIKE_RE.test(id);
}

/** Google Calendar event IDs are URL-safe base64-ish (letters / digits /
 * `-` / `_`); empty values + obviously-wrong shapes fail fast at the
 * handler boundary. We do NOT enforce a minimum length — Google's own
 * event IDs vary in length and the source of truth is Google's server. */
const CALENDAR_EVENT_ID_RE = /^[A-Za-z0-9_-]+$/;

export async function calendarListEvents(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    // Echo the rule, NOT the bad value — same posture as docs_get_content
    // (sec-rev §7 hook #11: error paths must not reflect user-supplied
    // content back to the caller verbatim).
    throw new Error(
      "calendar_list_events: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  // Defaults: time_min = now; time_max = time_min + 7 days. The string
  // representation must be ISO 8601 (RFC 3339) so the SDK can pass it as a
  // URL query parameter. Defer full RFC 3339 + timezone validation to
  // Google's server-side error (mapped via mapGoogleError → 400 surface).
  const timeMin = typeof args.time_min === "string" ? args.time_min : new Date().toISOString();
  const timeMax =
    typeof args.time_max === "string"
      ? args.time_max
      : new Date(Date.parse(timeMin) + CALENDAR_DEFAULT_TIME_HORIZON_MS).toISOString();

  // Defense-in-depth clamp: schema declares no explicit max (Google's own
  // ceiling is 2500), but the handler caps at CALENDAR_LIST_MAX_RESULTS_CAP
  // so a non-conforming MCP client (or prompt-injected oversize request)
  // can't request an oversized Calendar response.
  const requestedMax = typeof args.max_results === "number" ? args.max_results : 25;
  const maxResults = Math.min(requestedMax, CALENDAR_LIST_MAX_RESULTS_CAP);

  const q = typeof args.q === "string" ? args.q : undefined;
  const singleEvents = typeof args.single_events === "boolean" ? args.single_events : true;

  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await calendar.events.list({
      calendarId,
      timeMin,
      timeMax,
      maxResults,
      q,
      singleEvents,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_list_events", email: requireGoogle(ctx).accountId });
  }
}

export async function calendarGetEvent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    throw new Error(
      "calendar_get_event: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  const eventId = typeof args.event_id === "string" ? args.event_id : "";
  if (!eventId) {
    throw new Error("calendar_get_event requires a non-empty 'event_id' string");
  }
  // Same character-class gate as docs_get_content / docs_append_text — URL-safe
  // base64 (letters/digits/`-`/`_`). Fails fast on whitespace / control bytes /
  // URL-unsafe characters rather than waiting for a Google 400/404.
  if (!CALENDAR_EVENT_ID_RE.test(eventId)) {
    throw new Error(
      "calendar_get_event: 'event_id' must be url-safe (letters / digits / `-` / `_`)",
    );
  }

  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await calendar.events.get({ calendarId, eventId });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_get_event", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.45 — calendar_query_freebusy (READ tool, calendar.freebusy scope) ─────────
 *
 * Free/busy lookup across one or more calendars (backlog A5). `freebusy.query`'s
 * minimum scope is `calendar.freebusy`, which exposes busy WINDOWS only — never
 * event titles / descriptions / attendees. See docs/v1.45-calendar-freebusy-list.md §3.
 *
 * Validation (fail-fast, never echoes the bad value back):
 *   1. calendar_ids — array, 1..FREEBUSY_MAX_CALENDARS entries; each entry
 *      'primary' OR email-shaped (reuses isValidCalendarId — same gate as the
 *      Phase 1b read tools).
 *   2. time_min / time_max — default now / now+7d (RFC 3339); full RFC 3339 +
 *      timezone validation deferred to Google (mapGoogleError → 400).
 *
 * The response — {kind, timeMin, timeMax, calendars:{<id>:{busy:[{start,end}],
 * errors?}}} — carries NO user free-text; every leaf is a Google timestamp, a
 * closed enum (errors[].reason), or a calendar-ID map KEY (keys are not wrapped
 * by the walker). No SKIP_FIELDS change. */
const FREEBUSY_MAX_CALENDARS = 50;

export async function calendarQueryFreebusy(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const rawIds = Array.isArray(args.calendar_ids) ? args.calendar_ids : [];
  if (rawIds.length === 0) {
    throw new Error("calendar_query_freebusy requires a non-empty 'calendar_ids' array");
  }
  if (rawIds.length > FREEBUSY_MAX_CALENDARS) {
    throw new Error(
      `calendar_query_freebusy: 'calendar_ids' exceeds the ${FREEBUSY_MAX_CALENDARS}-calendar cap`,
    );
  }
  const calendarIds: string[] = [];
  for (const id of rawIds) {
    if (typeof id !== "string" || !isValidCalendarId(id)) {
      // Echo the RULE, not the bad value (sec posture: error paths never
      // reflect user-supplied content verbatim; same as the Phase 1b reads).
      throw new Error(
        "calendar_query_freebusy: each 'calendar_ids' entry must be 'primary' OR an email-shaped value",
      );
    }
    calendarIds.push(id);
  }

  const timeMin = typeof args.time_min === "string" ? args.time_min : new Date().toISOString();
  const timeMax =
    typeof args.time_max === "string"
      ? args.time_max
      : new Date(Date.parse(timeMin) + CALENDAR_DEFAULT_TIME_HORIZON_MS).toISOString();

  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await calendar.freebusy.query({
      requestBody: { timeMin, timeMax, items: calendarIds.map((id) => ({ id })) },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_query_freebusy", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.45 — calendar_list_calendars (READ tool, calendar.calendarlist.readonly) ─────────
 *
 * Enumerate the calendars on the account's calendar list — primary + shared +
 * subscribed (backlog A5). Uses calendarList.list; minimum scope
 * `calendar.calendarlist.readonly`. Per-entry summary / summaryOverride /
 * description / location are UNTRUSTED (a shared calendar may be named by
 * someone else) → the middleware sanitize walker wraps them in <untrusted-source>
 * (they are NOT in SKIP_FIELDS). The opaque calendar `id` — needed verbatim for
 * follow-up calendar_query_freebusy / calendar_list_events — is already in
 * SKIP_FIELDS. See docs/v1.45-calendar-freebusy-list.md §4-§5. */
const CALENDARLIST_MAX_RESULTS_CAP = 250;

export async function calendarListCalendars(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Defense-in-depth clamp: the schema declares minimum 1 / maximum 250
  // (Google's ceiling), but a non-conforming MCP client could bypass it.
  const requestedMax = typeof args.max_results === "number" ? args.max_results : 100;
  const maxResults = Math.min(Math.max(requestedMax, 1), CALENDARLIST_MAX_RESULTS_CAP);

  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await calendar.calendarList.list({ maxResults });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_list_calendars", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.13 Phase 2: calendar_create_event (WRITE tool, calendar.events scope) ─────────
 *
 * Write-tier Google Calendar API tool. See docs/v1.13-calendar-api.md §3 (Phase 2)
 * and §7 hooks 3, 4, 5, 6, 10, 13. Pattern-copied from docsCreate (PR #109) +
 * docsAppendText (PR #110) — handler is a thin shim over `events.insert` with
 * STRICT handler-side validation BEFORE any SDK call.
 *
 * Validation order (fail-fast, never echoes raw user-supplied content to caller):
 *   1. calendar_id format check (hook #9, reused from Phase 1b).
 *   2. summary — type + non-empty + HEADER_INJECTION_RE + 1000-byte cap.
 *   3. start / end shape consistency — both `dateTime` OR both `date`,
 *      lightweight regex pre-check, chronological order (`end > start`).
 *   4. description — type + 8000-byte cap (NO header check; body content).
 *   5. location — type + 1000-byte cap.
 *   6. attendees — count ≤ 50, each email validated against EMAIL_RECIPIENT_RE.
 *
 * Sec-rev hooks applied (per design §7):
 *   #3  ALLOWLIST sentinel on requestBody — handler constructs `{summary, start,
 *       end, description?, location?, attendees?}` LITERALLY. Tests assert
 *       `Object.keys(requestBody).sort() ⊆ ALLOWED_KEYS` AND requestBody contains
 *       NONE of 20 forbidden Event resource fields (id / recurrence /
 *       recurringEventId / eventType / transparency / visibility / attachments /
 *       conferenceData / extendedProperties / gadget / reminders / source /
 *       colorId / anyoneCanAddSelf / guestsCanInviteOthers / guestsCanModify /
 *       guestsCanSeeOtherGuests / sequence / creator / organizer). Future
 *       regression that smuggles a forbidden field trips BOTH layers.
 *   #4  `sendUpdates: "none"` — handler ALWAYS passes the literal lowercase
 *       `"none"` to events.insert. Schema `additionalProperties: false` also
 *       prevents caller from supplying `sendUpdates` directly (would reject at
 *       JSON-Schema layer); even if the schema were bypassed, the SDK call
 *       is built without forwarding any caller-supplied value. Sentinel test
 *       asserts URL params `sendUpdates === "none"` (lowercase exact match —
 *       Google may default `"None"` / `"NONE"` silently to `"all"`).
 *   #5  Summary input — HEADER_INJECTION_RE (CR/LF/NUL/NEL/U+2028/U+2029)
 *       rejected on RAW (pre-trim) value; 1000-byte cap via Buffer.byteLength.
 *       Same regex shared with gmail_send / gmail_create_label / docs_create.
 *   #6  Description input — 8000-byte cap via Buffer.byteLength. NO
 *       HEADER_INJECTION_RE check (body content, line breaks legitimate;
 *       same rationale as docs_append_text).
 *  #10  Datetime input — lightweight regex pre-check for obvious malformed
 *       input. Full RFC 3339 + timezone validation deferred to Google's
 *       server-side error (mapGoogleError → 400 surface). Start/end shape
 *       consistency + chronological order enforced handler-side.
 *  #13  Audit log shape — handler emits standard `with-context.ts` audit row
 *       per call; args_hash = sha256(JSON.stringify(args)) covers summary +
 *       description + attendees[]. Plain SHA-256 (matches v1.15 contacts API
 *       design §7 + Phase 0 sec-I1 patch — NOT HMAC, distinct from share/
 *       recipient-denied event rows that use HMAC against the audit-salt).
 *       Plaintext NEVER written to audit. v1.15 Phase 3 adds the
 *       `resolved_recipient_hash` field on the same audit row when a
 *       contact-lookup resolution occurred — see audit.ts for the field
 *       semantics.
 *
 * NO recipient-allowlist gate on attendees (per design §7 hook #8 + v1.15
 * design §9 C1 patch): attendees appear in their own Calendar (informational)
 * but receive NO invite email because sendUpdates="none" is hard-coded.
 * Equivalent surface to drive_share_file (explicit sharing) doesn't apply
 * here. v1.15 Phase 3 PRESERVES this no-allowlist design — contact-lookup
 * augments attendee RESOLUTION (name → email) only; the resolved email is
 * NOT subsequently gated through `isRecipientAllowed`. This is INTENTIONAL
 * and load-bearing — adding an allowlist gate would regress v1.13's locked
 * design.
 *
 * SECURITY: the googleapis SDK type for `events.insert({ requestBody:
 * Schema$Event })` accepts the FULL Schema$Event shape (server-side ignores
 * output-only fields, but the SDK doesn't enforce). Handler MUST construct
 * requestBody LITERALLY from the allowlisted input fields — NEVER spread or
 * pass-through user-supplied requestBody. Tests pin this with positive
 * (allowlist) + negative (per-forbidden-field) assertions.
 */
const CALENDAR_SUMMARY_MAX_BYTES = 1000;
const CALENDAR_DESCRIPTION_MAX_BYTES = 8000;
const CALENDAR_LOCATION_MAX_BYTES = 1000;
const CALENDAR_ATTENDEES_MAX = 50;
/** Lightweight `dateTime` pre-check — catches obvious malformed input early
 * (e.g., "not-a-date", "2026/05/20"). Full RFC 3339 + timezone validation is
 * deferred to Google's server-side error (mapGoogleError → 400). */
const CALENDAR_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T/;
/** Lightweight all-day `date` pre-check — strict YYYY-MM-DD. */
const CALENDAR_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Per design §3 / §7 hook #3 — allowed top-level keys in events.insert
 * requestBody. Matches the inputSchema property names 1:1. Used by the sentinel
 * test to assert `Object.keys(requestBody) ⊆ this set`. */
type CalendarStartEnd = {
  dateTime?: string;
  date?: string;
  timeZone?: string;
};

type CalendarAttendee = { email: string; displayName?: string };

/** Pre-SDK start/end validation: shape consistency + chronological order.
 * Mixed shapes (start.dateTime + end.date) → reject. Returns the validated
 * normalized objects ready to flow into requestBody. */
function validateCalendarStartEnd(
  startRaw: unknown,
  endRaw: unknown,
): { start: CalendarStartEnd; end: CalendarStartEnd } {
  if (typeof startRaw !== "object" || startRaw === null || Array.isArray(startRaw)) {
    throw new Error("calendar_create_event: 'start' must be an object");
  }
  if (typeof endRaw !== "object" || endRaw === null || Array.isArray(endRaw)) {
    throw new Error("calendar_create_event: 'end' must be an object");
  }
  const start = startRaw as Record<string, unknown>;
  const end = endRaw as Record<string, unknown>;

  const startHasDateTime = typeof start.dateTime === "string";
  const startHasDate = typeof start.date === "string";
  const endHasDateTime = typeof end.dateTime === "string";
  const endHasDate = typeof end.date === "string";

  if (startHasDateTime && startHasDate) {
    throw new Error(
      "calendar_create_event: 'start' must have EITHER 'dateTime' OR 'date', not both",
    );
  }
  if (endHasDateTime && endHasDate) {
    throw new Error(
      "calendar_create_event: 'end' must have EITHER 'dateTime' OR 'date', not both",
    );
  }
  if (!startHasDateTime && !startHasDate) {
    throw new Error(
      "calendar_create_event: 'start' must contain 'dateTime' (RFC 3339) OR 'date' (YYYY-MM-DD)",
    );
  }
  if (!endHasDateTime && !endHasDate) {
    throw new Error(
      "calendar_create_event: 'end' must contain 'dateTime' (RFC 3339) OR 'date' (YYYY-MM-DD)",
    );
  }
  // Shape consistency: both dateTime OR both date — mixed shapes reject.
  if (startHasDateTime !== endHasDateTime) {
    throw new Error(
      "calendar_create_event: 'start' and 'end' must share the same shape — both 'dateTime' (timed) OR both 'date' (all-day)",
    );
  }

  // Lightweight regex pre-check + chronological order.
  let startMs: number;
  let endMs: number;
  const out: { start: CalendarStartEnd; end: CalendarStartEnd } = {
    start: {},
    end: {},
  };
  if (startHasDateTime) {
    const startDt = start.dateTime as string;
    const endDt = end.dateTime as string;
    if (!CALENDAR_DATETIME_RE.test(startDt)) {
      throw new Error(
        "calendar_create_event: 'start.dateTime' must look like RFC 3339 (YYYY-MM-DDTHH:MM:SS[Z|±HH:MM])",
      );
    }
    if (!CALENDAR_DATETIME_RE.test(endDt)) {
      throw new Error(
        "calendar_create_event: 'end.dateTime' must look like RFC 3339 (YYYY-MM-DDTHH:MM:SS[Z|±HH:MM])",
      );
    }
    startMs = Date.parse(startDt);
    endMs = Date.parse(endDt);
    if (Number.isNaN(startMs)) {
      throw new Error("calendar_create_event: 'start.dateTime' is not a valid date");
    }
    if (Number.isNaN(endMs)) {
      throw new Error("calendar_create_event: 'end.dateTime' is not a valid date");
    }
    out.start.dateTime = startDt;
    out.end.dateTime = endDt;
    if (typeof start.timeZone === "string") {
      out.start.timeZone = start.timeZone;
    }
    if (typeof end.timeZone === "string") {
      out.end.timeZone = end.timeZone;
    }
  } else {
    const startD = start.date as string;
    const endD = end.date as string;
    if (!CALENDAR_DATE_RE.test(startD)) {
      throw new Error(
        "calendar_create_event: 'start.date' must look like YYYY-MM-DD",
      );
    }
    if (!CALENDAR_DATE_RE.test(endD)) {
      throw new Error(
        "calendar_create_event: 'end.date' must look like YYYY-MM-DD",
      );
    }
    startMs = Date.parse(startD);
    endMs = Date.parse(endD);
    if (Number.isNaN(startMs)) {
      throw new Error("calendar_create_event: 'start.date' is not a valid date");
    }
    if (Number.isNaN(endMs)) {
      throw new Error("calendar_create_event: 'end.date' is not a valid date");
    }
    out.start.date = startD;
    out.end.date = endD;
  }
  if (endMs <= startMs) {
    throw new Error(
      "calendar_create_event: 'end' must be strictly after 'start' (chronological order)",
    );
  }
  return out;
}

export async function calendarCreateEvent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. calendar_id ─────────────────────────────────────────────────────
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    // Echo the rule, NOT the bad value — sec-rev §7 hook #11 (cross-PR L1
    // echo): error paths must not reflect user-supplied content back verbatim.
    throw new Error(
      "calendar_create_event: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  // ─── 2. summary ─────────────────────────────────────────────────────────
  if (typeof args.summary !== "string") {
    throw new Error("calendar_create_event: 'summary' must be a string");
  }
  const rawSummary = args.summary;
  const trimmedSummary = rawSummary.trim();
  if (trimmedSummary.length === 0) {
    throw new Error("calendar_create_event: 'summary' must be non-empty after trim");
  }
  // HEADER_INJECTION_RE check runs on RAW (pre-trim) value to catch payloads
  // that smuggle the dangerous bytes around whitespace. Same posture as
  // docs_create + gmail_create_label.
  if (HEADER_INJECTION_RE.test(rawSummary)) {
    throw new Error(
      "calendar_create_event: 'summary' must not contain CR/LF/NUL/NEL/U+2028/U+2029",
    );
  }
  if (Buffer.byteLength(trimmedSummary, "utf-8") > CALENDAR_SUMMARY_MAX_BYTES) {
    // Echo the limit, NOT the summary (sec-rev §7 hook #11).
    throw new Error(
      `calendar_create_event: 'summary' exceeds ${CALENDAR_SUMMARY_MAX_BYTES} bytes (defensive client-side cap)`,
    );
  }

  // ─── 3. start / end ─────────────────────────────────────────────────────
  if (args.start === undefined) {
    throw new Error("calendar_create_event: 'start' is required");
  }
  if (args.end === undefined) {
    throw new Error("calendar_create_event: 'end' is required");
  }
  const { start, end } = validateCalendarStartEnd(args.start, args.end);

  // ─── 4. description (optional) ──────────────────────────────────────────
  let description: string | undefined;
  if (args.description !== undefined) {
    if (typeof args.description !== "string") {
      throw new Error("calendar_create_event: 'description' must be a string when provided");
    }
    description = args.description;
    // NOTE: HEADER_INJECTION_RE is INTENTIONALLY NOT applied here — description
    // is body content, CR/LF are legitimate line breaks (same rationale as
    // docs_append_text). Sanitize-on-read pipeline wraps description via
    // <untrusted-source> on subsequent reads.
    if (Buffer.byteLength(description, "utf-8") > CALENDAR_DESCRIPTION_MAX_BYTES) {
      throw new Error(
        `calendar_create_event: 'description' exceeds ${CALENDAR_DESCRIPTION_MAX_BYTES} bytes (defensive client-side cap)`,
      );
    }
  }

  // ─── 5. location (optional) ─────────────────────────────────────────────
  let location: string | undefined;
  if (args.location !== undefined) {
    if (typeof args.location !== "string") {
      throw new Error("calendar_create_event: 'location' must be a string when provided");
    }
    location = args.location;
    if (Buffer.byteLength(location, "utf-8") > CALENDAR_LOCATION_MAX_BYTES) {
      throw new Error(
        `calendar_create_event: 'location' exceeds ${CALENDAR_LOCATION_MAX_BYTES} bytes (defensive client-side cap)`,
      );
    }
  }

  // ─── 6. attendees (optional) ────────────────────────────────────────────
  let attendees: CalendarAttendee[] | undefined;
  if (args.attendees !== undefined) {
    if (!Array.isArray(args.attendees)) {
      throw new Error("calendar_create_event: 'attendees' must be an array when provided");
    }
    if (args.attendees.length > CALENDAR_ATTENDEES_MAX) {
      throw new Error(
        `calendar_create_event: at most ${CALENDAR_ATTENDEES_MAX} attendees per call (got ${args.attendees.length})`,
      );
    }
    // v1.15 Phase 3 — collect raw email inputs first, then run the entire
    // batch through the contact-lookup resolver in one pass. This lets us
    // surface ambiguity / not-found errors as MCPError("recipient_lookup_failed")
    // before any per-attendee work is done, AND avoids per-attendee parallel
    // calls (which would race against the warming-cache singleflight and burn
    // duplicate quota).
    const rawEmails: string[] = [];
    const builtPartial: CalendarAttendee[] = [];
    for (let i = 0; i < args.attendees.length; i++) {
      const a = args.attendees[i];
      if (typeof a !== "object" || a === null || Array.isArray(a)) {
        throw new Error(
          `calendar_create_event: attendees[${i}] must be an object {email, displayName?}`,
        );
      }
      const attendee = a as Record<string, unknown>;
      if (typeof attendee.email !== "string") {
        throw new Error(
          `calendar_create_event: attendees[${i}].email must be a string`,
        );
      }
      rawEmails.push(attendee.email);
      const built: CalendarAttendee = { email: attendee.email }; // placeholder, overwritten below
      if (typeof attendee.displayName === "string") {
        built.displayName = attendee.displayName;
      }
      builtPartial.push(built);
    }

    // Resolution pass (returns inputs unchanged when env var not set OR all
    // inputs already email-shaped).
    const { resolvedEmails: resolvedAttendeeEmails, lookedUpEmails } =
      await resolveRecipientsViaContactLookup(
        ctx,
        rawEmails,
        "calendar_create_event",
      );

    // Per-attendee email-format gate — same regex as gmail_send. attendees do
    // NOT pass through SAFESPACE_RECIPIENT_ALLOW (per design §7 hook #8 +
    // v1.15 design §9 C1 patch): sendUpdates is hard-coded "none", so no
    // outbound mail is sent at create-time and the allowlist's anti-prompt-
    // injection guarantee is not at risk. v1.15 Phase 3 PRESERVES this design
    // — contact lookup only changes input SHAPE (name → email); resolved
    // emails are NOT gated through `isRecipientAllowed` here.
    const out: CalendarAttendee[] = [];
    for (let i = 0; i < builtPartial.length; i++) {
      const resolved = resolvedAttendeeEmails[i]!;
      if (!EMAIL_RECIPIENT_RE.test(resolved)) {
        throw new Error(
          `calendar_create_event: attendees[${i}].email is not a valid email address`,
        );
      }
      out.push({ ...builtPartial[i]!, email: resolved });
    }
    attendees = out;

    // v1.15 Phase 3 — record audit hash for the resolved attendee emails.
    // Skips when no resolution happened (all inputs were already emails) so
    // the audit row's `resolved_recipient_hash` field stays absent and
    // signals "no contact-lookup occurred" to log readers.
    if (lookedUpEmails.length > 0) {
      ctx.audit.record("resolvedRecipientHash", 
        hashResolvedRecipientEmails(resolvedAttendeeEmails),
      );
    }
  }

  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    // SECURITY (design §3 / §7 hook #3): construct requestBody LITERALLY from
    // the allowlisted inputs. NEVER spread `...args` or pass-through any
    // caller-supplied requestBody shape. Tests assert positively (keys ⊆
    // allowlist) AND negatively (none of 20 forbidden Event fields present).
    const requestBody: Record<string, unknown> = {
      summary: trimmedSummary,
      start,
      end,
    };
    if (description !== undefined) requestBody.description = description;
    if (location !== undefined) requestBody.location = location;
    if (attendees !== undefined) requestBody.attendees = attendees;

    const res = await calendar.events.insert({
      calendarId,
      // HARD-CODED: literal lowercase "none". Google may silently default
      // capitalized variants to "all" — sentinel test asserts exact lowercase.
      sendUpdates: "none",
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_create_event", email: requireGoogle(ctx).accountId });
  }
}

/** Calendar event-ID path-segment regex — defends against path-traversal
 *  smuggling and DoS via oversized IDs. Per design §2.1 + §8 hook #11.
 *  Anchored at both ends; allowed chars are URL-safe base64-ish + underscore. */
const CALENDAR_EVENT_ID_MUTATION_RE = /^[a-zA-Z0-9_-]{1,128}$/;

/** Allowlist for calendar_update_event top-level requestBody keys. Per design
 *  §2.1 + §8 hook #2 — 6 explicit keys, NEVER spread args. Tests assert
 *  Object.keys(requestBody) ⊆ this set AND none of the 20 forbidden Event
 *  fields are present (NEGATIVE sentinel; mirror v1.13 PR #118 pattern). */
const CALENDAR_UPDATE_EVENT_ALLOWED_KEYS: ReadonlySet<string> = new Set([
  "summary",
  "description",
  "location",
  "start",
  "end",
  "attendees",
]);

/** Per-attendee allowlist for calendar_update_event. Per design §2.1 +
 *  §8 hook #2 — only {email, displayName} allowed at attendee level.
 *  FORBIDDEN (rejected at handler boundary): responseStatus / optional /
 *  additionalGuests / comment / self / organizer / resource. Caller MUST
 *  NOT smuggle responseStatus via update path — RSVP-state mutation is
 *  calendar_respond's exclusive surface. */
const CALENDAR_UPDATE_ATTENDEE_ALLOWED_KEYS: ReadonlySet<string> = new Set([
  "email",
  "displayName",
]);

/** Closed enum for calendar_respond. Per design §2.3 — exactly the 4 Google
 *  Calendar attendee responseStatus values. Case-sensitive (Google's API
 *  requires lowercase per RFC 5545 ↔ Calendar API mapping). */
const CALENDAR_RESPOND_VALID_RESPONSES: ReadonlySet<string> = new Set([
  "accepted",
  "declined",
  "tentative",
  "needsAction",
]);

/**
 * `calendar_update_event` — WRITE TIER. Partial-update an existing Calendar
 * event via events.patch. NEGATIVE sentinel: only the 6 allowlisted top-level
 * keys may flow into requestBody. Per-attendee allowlist enforced
 * pre-resolution. Phase 3 contact-lookup applies (same flag as
 * calendar_create_event). See docs/v1.17-deferred-completion.md §2.1.
 *
 * NOT shipped in Phase 1: ETag / If-Match optimistic concurrency (Risk 3
 * accepted; Phase 1c follow-up); single-field start OR end (current Phase 1
 * requires BOTH if either supplied — caller reads existing via
 * calendar_get_event first; Phase 1c follow-up).
 */
export async function calendarUpdateEvent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. event_id (path-segment validation per hook #11) ─────────────
  if (typeof args.event_id !== "string") {
    throw new Error("calendar_update_event: 'event_id' must be a string");
  }
  if (!CALENDAR_EVENT_ID_MUTATION_RE.test(args.event_id)) {
    // Echo the RULE, NOT the bad value (hook #8 — no PII echo).
    throw new Error(
      "calendar_update_event: 'event_id' must match /^[a-zA-Z0-9_-]{1,128}$/",
    );
  }
  const eventId = args.event_id;

  // ─── 2. calendar_id (default "primary") ─────────────────────────────
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    throw new Error(
      "calendar_update_event: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  // ─── 3. At-least-one-field rule + start/end-both-required ───────────
  // Phase 1 simplification (design §2.1 LOCKED): start AND end must both be
  // supplied if either is supplied. Phase 1c follow-up will add single-field
  // update if duration preserved.
  const hasSummary = args.summary !== undefined;
  const hasDescription = args.description !== undefined;
  const hasLocation = args.location !== undefined;
  const hasStart = args.start !== undefined;
  const hasEnd = args.end !== undefined;
  const hasAttendees = args.attendees !== undefined;
  if (
    !hasSummary &&
    !hasDescription &&
    !hasLocation &&
    !hasStart &&
    !hasEnd &&
    !hasAttendees
  ) {
    throw new Error(
      "calendar_update_event requires at least one of {summary, description, location, start, end, attendees}",
    );
  }
  if (hasStart !== hasEnd) {
    throw new Error(
      "calendar_update_event requires BOTH 'start' AND 'end' if either is supplied (Phase 1 simplification; Phase 1c follow-up planned)",
    );
  }

  // ─── 4. Per-field validation ────────────────────────────────────────
  let summary: string | undefined;
  if (hasSummary) {
    if (typeof args.summary !== "string") {
      throw new Error("calendar_update_event: 'summary' must be a string when provided");
    }
    const raw = args.summary;
    const trimmed = raw.trim();
    if (trimmed.length === 0) {
      throw new Error("calendar_update_event: 'summary' must be non-empty after trim");
    }
    if (HEADER_INJECTION_RE.test(raw)) {
      throw new Error(
        "calendar_update_event: 'summary' must not contain CR/LF/NUL/NEL/U+2028/U+2029",
      );
    }
    if (Buffer.byteLength(trimmed, "utf-8") > CALENDAR_SUMMARY_MAX_BYTES) {
      throw new Error(
        `calendar_update_event: 'summary' exceeds ${CALENDAR_SUMMARY_MAX_BYTES} bytes (defensive client-side cap)`,
      );
    }
    summary = trimmed;
  }

  let description: string | undefined;
  if (hasDescription) {
    if (typeof args.description !== "string") {
      throw new Error("calendar_update_event: 'description' must be a string when provided");
    }
    description = args.description;
    if (Buffer.byteLength(description, "utf-8") > CALENDAR_DESCRIPTION_MAX_BYTES) {
      throw new Error(
        `calendar_update_event: 'description' exceeds ${CALENDAR_DESCRIPTION_MAX_BYTES} bytes (defensive client-side cap)`,
      );
    }
  }

  let location: string | undefined;
  if (hasLocation) {
    if (typeof args.location !== "string") {
      throw new Error("calendar_update_event: 'location' must be a string when provided");
    }
    location = args.location;
    if (Buffer.byteLength(location, "utf-8") > CALENDAR_LOCATION_MAX_BYTES) {
      throw new Error(
        `calendar_update_event: 'location' exceeds ${CALENDAR_LOCATION_MAX_BYTES} bytes (defensive client-side cap)`,
      );
    }
  }

  let start: CalendarStartEnd | undefined;
  let end: CalendarStartEnd | undefined;
  if (hasStart && hasEnd) {
    const validated = validateCalendarStartEnd(args.start, args.end);
    start = validated.start;
    end = validated.end;
  }

  // ─── 5. Tier check (defense-in-depth) — HOISTED before attendee allowlist + Phase 3 ──
  // Tier check FIRST (defense-in-depth). Hoisted from post-lookup position
  // per PR #138 pre-merge review code-M1/sec-M2: tier=read callers bypassing
  // tools/list filter should not burn People API quota before getting denied.
  // Matches youtube_video_comment_post ordering pattern.
  //
  // All earlier steps (1-4) are pure input regex/format validation — no
  // network calls, no Google quota consumed. Tier check sits at the boundary
  // between "cheap caller-bug rejections" and "side-effecting work". Per
  // hook #7 + hook #10 — audit BEFORE throw so forensic row carries
  // target_event_hash + denied_tier.
  const eventHash = sha256Hex(eventId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("calendarMutationMeta", {
      target_event_hash: eventHash,
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "calendar_update_event",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 6. Attendees with per-attendee allowlist + Phase 3 contact-lookup ───
  let attendees: CalendarAttendee[] | undefined;
  if (hasAttendees) {
    if (!Array.isArray(args.attendees)) {
      throw new Error("calendar_update_event: 'attendees' must be an array when provided");
    }
    if (args.attendees.length > CALENDAR_ATTENDEES_MAX) {
      throw new Error(
        `calendar_update_event: at most ${CALENDAR_ATTENDEES_MAX} attendees per call (got ${args.attendees.length})`,
      );
    }
    // Per-attendee key allowlist BEFORE resolution. Sec-rev hook #2 — caller
    // MUST NOT smuggle responseStatus / optional / etc. via update path. Each
    // forbidden key triggers handler rejection at the boundary.
    const rawEmails: string[] = [];
    const builtPartial: CalendarAttendee[] = [];
    for (let i = 0; i < args.attendees.length; i++) {
      const a = args.attendees[i];
      if (typeof a !== "object" || a === null || Array.isArray(a)) {
        throw new Error(
          `calendar_update_event: attendees[${i}] must be an object {email, displayName?}`,
        );
      }
      const attendee = a as Record<string, unknown>;
      for (const key of Object.keys(attendee)) {
        if (!CALENDAR_UPDATE_ATTENDEE_ALLOWED_KEYS.has(key)) {
          throw new Error(
            `calendar_update_event: attendees[${i}] key '${key}' is not in allowlist {email, displayName}`,
          );
        }
      }
      if (typeof attendee.email !== "string") {
        throw new Error(
          `calendar_update_event: attendees[${i}].email must be a string`,
        );
      }
      rawEmails.push(attendee.email);
      const built: CalendarAttendee = { email: attendee.email };
      if (typeof attendee.displayName === "string") {
        built.displayName = attendee.displayName;
      }
      builtPartial.push(built);
    }

    // Phase 3 contact-lookup resolution (env-var opt-in). Mirrors
    // calendar_create_event pattern verbatim — same helper, same
    // recipient_lookup_failed (-32022) on miss / ambiguity.
    // PR #138 code-M2: helper union widened to include
    // calendar_update_event so via_tool attribution is accurate on
    // scope_mismatch (previously misattributed to calendar_create_event).
    const { resolvedEmails: resolvedAttendeeEmails, lookedUpEmails } =
      await resolveRecipientsViaContactLookup(
        ctx,
        rawEmails,
        "calendar_update_event",
      );

    const out: CalendarAttendee[] = [];
    for (let i = 0; i < builtPartial.length; i++) {
      const resolved = resolvedAttendeeEmails[i]!;
      if (!EMAIL_RECIPIENT_RE.test(resolved)) {
        throw new Error(
          `calendar_update_event: attendees[${i}].email is not a valid email address`,
        );
      }
      out.push({ ...builtPartial[i]!, email: resolved });
    }
    attendees = out;

    // v1.15 Phase 3 audit hash — emitted only when at least one name was
    // resolved. Same semantics as calendar_create_event.
    if (lookedUpEmails.length > 0) {
      ctx.audit.record("resolvedRecipientHash", 
        hashResolvedRecipientEmails(resolvedAttendeeEmails),
      );
    }
  }

  // ─── 7. Record allow-meta BEFORE the SDK call ───────────────────────
  // Hook #7 — forensic completeness: meta is captured BEFORE the SDK call
  // so if Google returns 5xx (or the network fails), the audit row still
  // shows what Claude attempted + the failure status. Mirror of v1.16
  // PR #135 INFO-4 reconciliation.
  ctx.audit.record("calendarMutationMeta", {
    target_event_hash: eventHash,
    policy_decision: "allowed",
  });

  // ─── 8. Construct requestBody LITERALLY (NEGATIVE sentinel) ─────────
  // Per hook #2 — only 6 keys at top level; sentinel tests assert
  // positive (keys ⊆ allowlist) AND negative (none of 20 forbidden fields).
  const requestBody: Record<string, unknown> = {};
  if (summary !== undefined) requestBody.summary = summary;
  if (description !== undefined) requestBody.description = description;
  if (location !== undefined) requestBody.location = location;
  if (start !== undefined && end !== undefined) {
    requestBody.start = start;
    requestBody.end = end;
  }
  if (attendees !== undefined) requestBody.attendees = attendees;

  // ─── 9. SDK call (sendUpdates="none" hard-coded per hook #1) ────────
  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await calendar.events.patch({
      calendarId,
      eventId,
      sendUpdates: "none",
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_update_event", email: requireGoogle(ctx).accountId });
  }
}

/**
 * `calendar_delete_event` — WRITE TIER. Permanently delete a Calendar event
 * via events.delete. Per design §2.2 + §10 Q4 LOCKED — min_tier=write (NOT
 * read like drive_unshare_file) because delete destroys content AND audit
 * evidence; reversible only via Google Calendar trash (30-day window, web
 * UI only). NO bulk delete (blast-radius bound). See
 * docs/v1.17-deferred-completion.md §2.2.
 */
export async function calendarDeleteEvent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. event_id ─────────────────────────────────────────────────────
  if (typeof args.event_id !== "string") {
    throw new Error("calendar_delete_event: 'event_id' must be a string");
  }
  if (!CALENDAR_EVENT_ID_MUTATION_RE.test(args.event_id)) {
    throw new Error(
      "calendar_delete_event: 'event_id' must match /^[a-zA-Z0-9_-]{1,128}$/",
    );
  }
  const eventId = args.event_id;

  // ─── 2. calendar_id ─────────────────────────────────────────────────
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    throw new Error(
      "calendar_delete_event: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  // ─── 3. Tier check (defense-in-depth) ───────────────────────────────
  const eventHash = sha256Hex(eventId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("calendarMutationMeta", {
      target_event_hash: eventHash,
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "calendar_delete_event",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 4. Record allow-meta BEFORE SDK call (hook #7) ─────────────────
  ctx.audit.record("calendarMutationMeta", {
    target_event_hash: eventHash,
    policy_decision: "allowed",
  });

  // ─── 5. SDK call (sendUpdates="none" hard-coded per hook #1) ────────
  try {
    const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
    await calendar.events.delete({
      calendarId,
      eventId,
      sendUpdates: "none",
    });
    // Google returns 204 No Content on success; synthesize a friendly shape
    // so callers don't have to interpret "empty body = success" magic.
    return { deleted: true, event_id: eventId };
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_delete_event", email: requireGoogle(ctx).accountId });
  }
}

/**
 * `calendar_respond` — WRITE TIER. RSVP to a Calendar event by setting the
 * caller's own attendee responseStatus. Per design §2.3 — handler MUST
 * pre-fetch via events.get, then submit events.patch with the FULL attendees
 * list (Google's patch treats subset-of-attendees as REPLACE, which would
 * wipe non-self entries). Non-self entries are byte-for-byte preserved from
 * pre-fetch (hook #9 deep-equality).
 *
 * TOCTOU: get-then-patch has a race window. Concurrent organizer modification
 * BETWEEN get and patch is silently overwritten. Accepted out-of-scope for
 * Phase 1 (Risk 3 per design §11; Phase 1c follow-up will add If-Match).
 */
export async function calendarRespond(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. event_id ─────────────────────────────────────────────────────
  if (typeof args.event_id !== "string") {
    throw new Error("calendar_respond: 'event_id' must be a string");
  }
  if (!CALENDAR_EVENT_ID_MUTATION_RE.test(args.event_id)) {
    throw new Error(
      "calendar_respond: 'event_id' must match /^[a-zA-Z0-9_-]{1,128}$/",
    );
  }
  const eventId = args.event_id;

  // ─── 2. response (closed enum) ──────────────────────────────────────
  if (typeof args.response !== "string") {
    throw new Error("calendar_respond: 'response' must be a string");
  }
  if (!CALENDAR_RESPOND_VALID_RESPONSES.has(args.response)) {
    throw new Error(
      "calendar_respond: 'response' must be one of {accepted, declined, tentative, needsAction}",
    );
  }
  const response = args.response;

  // ─── 3. calendar_id ─────────────────────────────────────────────────
  const calendarId =
    typeof args.calendar_id === "string" && args.calendar_id.length > 0
      ? args.calendar_id
      : "primary";
  if (!isValidCalendarId(calendarId)) {
    throw new Error(
      "calendar_respond: 'calendar_id' must be 'primary' OR an email-shaped value",
    );
  }

  // ─── 4. Tier check (defense-in-depth) ───────────────────────────────
  const eventHash = sha256Hex(eventId);
  const tier = ctx.tier;
  if (tier === "read") {
    // PR #138 sec-M1 — include rsvp_response even on denied_tier rows so
    // log readers see WHICH RSVP value was attempted (forensic completeness
    // mirrors hook #7 — denied rows still carry the operational intent).
    ctx.audit.record("calendarMutationMeta", {
      target_event_hash: eventHash,
      policy_decision: "denied_tier",
      rsvp_response: response as
        | "accepted"
        | "declined"
        | "tentative"
        | "needsAction",
    });
    throw new MCPError("scope_mismatch", {
      tool: "calendar_respond",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 5. Record allow-meta BEFORE SDK call (hook #7) ─────────────────
  // PR #138 sec-M1 — design §5 specifies calendar_respond rows include
  // the RSVP value. Closed-enum (validated in step 3), no PII. Other 2
  // calendar mutation tools (update / delete) MUST NOT set this field.
  ctx.audit.record("calendarMutationMeta", {
    target_event_hash: eventHash,
    policy_decision: "allowed",
    rsvp_response: response as
      | "accepted"
      | "declined"
      | "tentative"
      | "needsAction",
  });

  // ─── 6. Pre-fetch (separate try) ────────────────────────────────────
  // Risk 3 (accepted TOCTOU race). Snapshot of attendees + self-discriminator
  // (`attendee.self === true`).
  const calendar = calendarClientFromToken(requireGoogle(ctx).getAccessToken());
  let attendees: Array<Record<string, unknown>>;
  try {
    const eventRes = await calendar.events.get({
      calendarId,
      eventId,
    });
    const event = eventRes.data;
    attendees = Array.isArray(event.attendees)
      ? (event.attendees as Array<Record<string, unknown>>)
      : [];
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_respond", email: requireGoogle(ctx).accountId });
  }

  // ─── 7. Not-attendee check (OUTSIDE try) ────────────────────────────
  // v1.17.0 release sec-M1 — hoisted out of the SDK try-block. Previously
  // throwing a plain Error INSIDE the try meant `mapGoogleError` caught it
  // (instanceof MCPError === false) and wrapped it as `network_unknown`,
  // hiding the real cause behind a misleading "network failure" surface.
  // The check is purely synchronous local logic — it must NOT live inside
  // a Google-SDK try-catch boundary.
  const selfIdx = attendees.findIndex((a) => a?.self === true);
  if (selfIdx === -1) {
    throw new Error(
      "calendar_respond: caller is not an attendee of this event",
    );
  }

  // ─── 8. Patch via events.patch ──────────────────────────────────────
  // Hook #9 deep-equality: rebuild attendees list with non-self entries
  // byte-for-byte preserved (same keys + same values). Self entry has
  // ALL pre-fetched keys preserved with ONLY responseStatus mutated.
  // Object-spread preserves all keys + values per JavaScript spread
  // semantics; responseStatus override is the ONLY mutation on self.
  const newAttendees = attendees.map((att, idx) => {
    if (idx === selfIdx) {
      return { ...att, responseStatus: response };
    }
    // Non-self: byte-for-byte preserve. Shallow-spread is sufficient since
    // Schema$EventAttendee is a flat primitive-keyed object (no nested
    // objects per Google's schema — confirmed via v1.13 Phase 1b probe).
    return { ...att };
  });

  try {
    const patchRes = await calendar.events.patch({
      calendarId,
      eventId,
      sendUpdates: "none",
      requestBody: { attendees: newAttendees },
    });
    return patchRes.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "calendar_respond", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.19 Phase 1b — tasks_lists / tasks_list / tasks_get (READ tools) ─────────
 *
 * Read-tier Google Tasks API tools. See docs/v1.19-tasks-api.md §2.1 / §2.2 / §2.4.
 * Pattern mirrors v1.13 calendar_list_events / calendar_get_event — handler is
 * a thin shim over the SDK; sanitize + error mapping happen at the middleware
 * layer. NO cache-warming needed (Tasks API has no v1.15 People-API cold-cache
 * search-index quirk).
 *
 * Sec-rev hooks applied (per design §10):
 *   #5  `tasklist_id` + `task_id` regex pinned + DoS length caps — both
 *       `^[A-Za-z0-9_-]{1,128}$`. Cap tightened from prior {1,256} per
 *       design §2.4 (Google observed up to ~120 chars; 128 is a snug ceiling
 *       reducing attack surface). Handler-side regex BEFORE SDK call rejects
 *       path-traversal (`../etc/passwd`), CRLF injection, NUL, wrong charset,
 *       oversized ≥129-char inputs.
 *  #11  N/A for read tier — read tools have no audit-meta channel. Phase 2b
 *       write tools record `tasksMutationMeta` BEFORE the SDK call.
 *  #12  No PII echo — error messages reference the RULE, not the input value
 *       (mirrors calendar_get_event / contacts_get posture). Same pattern as
 *       v1.13 sec-rev hook #11 / v1.15 §11 hook #11.
 *  #13  N/A for read tier — recovery-impossibility only applies to
 *       `tasks_delete` (Phase 2b).
 *
 * Hooks #1 / #2 / #3 / #4 / #6 / #14 are Phase 2b (write tier) territory.
 * Hooks #7 / #8 / #9 / #10 are Phase 2a (cross-account `_all`) / Phase 2b
 * (audit channel) territory.
 */

