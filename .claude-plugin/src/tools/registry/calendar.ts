// Calendar tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  CALENDAR_EVENTS_READONLY,
  CALENDAR_EVENTS,
  CALENDAR_FREEBUSY,
  CALENDAR_CALENDARLIST_READONLY,
} from "./scopes";

export const calendarTools: Record<string, ToolDef> = {
  calendar_list_events: {
    name: "calendar_list_events",
    description:
      "List Google Calendar events within a time range (READ OPERATION). Uses the Calendar API `events.list` endpoint and returns the raw response — {kind, items: CalendarEvent[], nextPageToken?, ...} — verbatim per docs/v1.13-calendar-api.md §3. Defaults: calendar_id='primary'; time_min=now (RFC 3339); time_max=time_min + 7 days; max_results=25 (handler-side CAP at 100 as anti-DoS guard, Google API ceiling is 2500); single_events=true (recurring events expanded into per-occurrence instances). Use single_events=false to get master events with their recurrence rules instead. Optional q parameter is a full-text search across event fields (summary, description, location, attendee displayName/email). User-visible text (summary, description, location, attendees[*].displayName, attendees[*].email) is sanitize-wrapped per the standard <untrusted-source> pipeline; Google opaque metadata (iCalUID / htmlLink / hangoutLink / etag / recurringEventId) and closed enums (status / transparency / visibility / eventType) pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value (e.g., 'alice@example.com' or 'c_xxxxx@group.calendar.google.com' for secondary calendars).",
        },
        time_min: {
          type: "string",
          description:
            "RFC 3339 lower bound for events (default: now). Inclusive. Example: '2026-05-20T00:00:00Z'.",
        },
        time_max: {
          type: "string",
          description:
            "RFC 3339 upper bound for events (default: time_min + 7 days). Exclusive. Example: '2026-05-27T00:00:00Z'.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 25,
          description:
            "Maximum number of events to return (default 25, handler-side cap at 100 as anti-DoS guard).",
        },
        q: {
          type: "string",
          description:
            "Full-text search query across event summary / description / location / attendee fields.",
        },
        single_events: {
          type: "boolean",
          default: true,
          description:
            "Expand recurring events into per-occurrence instances (default true). Set false to get master events with recurrence rules instead.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    // `calendar.events.readonly` is the narrowest scope sufficient for
    // events.list / events.get; V1_SCOPES grants the broader
    // `calendar.events` (read + write) which satisfies this via
    // SCOPE_HIERARCHY (with-context.ts).
    requiredScopes: [CALENDAR_EVENTS_READONLY],
    handler: handlers.calendarListEvents,
    min_tier: "read",
  },
  calendar_get_event: {
    name: "calendar_get_event",
    description:
      "Get a single Google Calendar event by ID (READ OPERATION). Returns the full Event resource verbatim from Calendar API `events.get` — including summary, description, location, start/end, attendees, organizer, creator, recurrence, conferenceData (Meet links), attachments, reminders. Use this after calendar_list_events to get full details of a specific event. User-visible text (summary, description, location, attendees[*].displayName, attendees[*].email, organizer/creator, conferenceData.entryPoints[*].label, attachments[*].title) is sanitize-wrapped per the standard <untrusted-source> pipeline; Google opaque metadata (iCalUID / htmlLink / hangoutLink / etag / recurringEventId) and closed enums (status / transparency / visibility / eventType) pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value.",
        },
        event_id: {
          type: "string",
          description:
            "Calendar event ID from calendar_list_events (url-safe chars: letters / digits / `-` / `_`).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["event_id"],
      additionalProperties: false,
    },
    requiredScopes: [CALENDAR_EVENTS_READONLY],
    handler: handlers.calendarGetEvent,
    min_tier: "read",
  },
  // v1.45 (backlog A5) — Calendar free/busy + calendar list. Two READ tools,
  // each on a NEW minimum-privilege scope (re-consent ceremony; see
  // docs/v1.45-calendar-freebusy-list.md §1-§4).
  calendar_query_freebusy: {
    name: "calendar_query_freebusy",
    description:
      "Query free/busy windows across one or more Google Calendars (READ OPERATION). Uses the Calendar API `freebusy.query` endpoint. Returns ONLY busy time intervals per calendar — {kind, timeMin, timeMax, calendars: {<calendar_id>: {busy: [{start, end}], errors?: [...]}}} — NEVER event titles, descriptions, attendees, or any event content (that is what makes `calendar.freebusy` the minimum-privilege scope for availability checks; use calendar_list_events / calendar_get_event for event detail). Defaults: time_min=now (RFC 3339); time_max=time_min + 7 days. Up to 50 calendars per query. Each calendar_ids entry is 'primary' or an email-shaped calendar ID. A calendar the account cannot see free/busy for comes back as a per-calendar `errors` entry (not a hard failure). All response leaves are Google timestamps / closed enums / calendar-ID map keys (no user free-text); busy start/end timestamps pass through the standard sanitize walker as opaque text.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_ids: {
          type: "array",
          minItems: 1,
          maxItems: 50,
          items: { type: "string" },
          description:
            "Calendars to check (1-50). Each entry is 'primary' for the user's own calendar OR an email-shaped value (e.g., 'alice@example.com' or 'c_xxxxx@group.calendar.google.com').",
        },
        time_min: {
          type: "string",
          description:
            "RFC 3339 lower bound (default: now). Inclusive. Example: '2026-05-20T00:00:00Z'.",
        },
        time_max: {
          type: "string",
          description:
            "RFC 3339 upper bound (default: time_min + 7 days). Exclusive. Example: '2026-05-27T00:00:00Z'.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["calendar_ids"],
      additionalProperties: false,
    },
    // `calendar.freebusy` is the narrowest scope for freebusy.query — busy
    // windows only, NO event content. NOT covered by `calendar.events` (the
    // v1.13 scope); new scope added to V1_SCOPES in v1.45 (re-consent).
    requiredScopes: [CALENDAR_FREEBUSY],
    handler: handlers.calendarQueryFreebusy,
    min_tier: "read",
  },
  calendar_list_calendars: {
    name: "calendar_list_calendars",
    description:
      "List the calendars on the account's calendar list — primary, shared, and subscribed (READ OPERATION). Uses the Calendar API `calendarList.list` endpoint and returns the raw response — {kind, etag, nextPageToken?, items: CalendarListEntry[]} — verbatim. Each entry includes the calendar `id` (use it as calendar_id for calendar_query_freebusy / calendar_list_events / calendar_get_event), `summary` (name), `description`, `timeZone`, `colorId`, `accessRole` (freeBusyReader / reader / writer / owner), and `primary`. User-visible text (summary, summaryOverride, description, location) is sanitize-wrapped per the standard <untrusted-source> pipeline — a shared calendar may be named by another user; the opaque calendar `id` / `etag` / `kind` / pagination cursors pass through unwrapped. Defaults: max_results=100 (handler-side cap at 250, Google's ceiling). Read-only — cannot create / modify / delete / subscribe to calendars.",
    inputSchema: {
      type: "object",
      properties: {
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 250,
          default: 100,
          description:
            "Maximum number of calendars to return (default 100, handler-side cap at 250).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    // `calendar.calendarlist.readonly` is the narrowest scope for
    // calendarList.list. New scope added to V1_SCOPES in v1.45 (re-consent).
    requiredScopes: [CALENDAR_CALENDARLIST_READONLY],
    handler: handlers.calendarListCalendars,
    min_tier: "read",
  },
  calendar_create_event: {
    name: "calendar_create_event",
    description:
      "Create a new event on a Google Calendar (WRITE OPERATION, undoable — the event can be deleted via the Calendar web UI; not exposed in v1.13). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. APPEND-ONLY style: cannot modify existing events (Phase 3, deferred). Uses Calendar API `events.insert` with HARD-CODED `sendUpdates=none` — caller cannot override; NO invite emails sent on creation (anti-spam blast-radius guard; per docs/v1.13-calendar-api.md §3). Start/end MUST have the same shape (both `dateTime` for timed events OR both `date` for all-day events); chronological order enforced (`end > start`). Hard caps: summary 1000 bytes UTF-8 (rejects CR/LF/NUL/NEL/U+2028/U+2029), description 8000 bytes UTF-8 (line breaks legitimate, no header-injection check), location 1000 bytes UTF-8, attendees max 50. Attendee emails are format-validated but do NOT pass through SAFESPACE_RECIPIENT_ALLOW (no outbound mail with sendUpdates=none). Caller-supplied fields outside the allowlist (calendar_id / summary / start / end / description / location / attendees) — e.g., eventType / recurrence / conferenceData / attachments / extendedProperties / id / visibility — are EXPLICITLY REJECTED via additionalProperties:false (NOT silent ignore — silent ignore could let prompt-injection believe specialized event types were honored). Returns the created Event resource (with Google-assigned id, htmlLink, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value.",
        },
        summary: {
          type: "string",
          description:
            "Event title (1-1000 bytes UTF-8 after validation, no CR/LF/NUL/NEL/U+2028/U+2029).",
        },
        start: {
          type: "object",
          description:
            "Start time — either {dateTime, timeZone?} for timed events (RFC 3339 dateTime) OR {date} for all-day events (YYYY-MM-DD). Must match `end` shape.",
        },
        end: {
          type: "object",
          description:
            "End time — same shape as `start` (both dateTime OR both date). Must be chronologically AFTER `start`.",
        },
        description: {
          type: "string",
          description:
            "Event body text (max 8000 bytes UTF-8). Line breaks preserved (no header-injection check — body content).",
        },
        location: {
          type: "string",
          description: "Location text (max 1000 bytes UTF-8).",
        },
        attendees: {
          type: "array",
          maxItems: 50,
          description:
            "Attendee list (max 50). Each entry is {email: string (validated), displayName?: string}. NO invite emails are sent (sendUpdates=none is hard-coded).",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["summary", "start", "end"],
      additionalProperties: false,
    },
    // Full `calendar.events` scope required — `calendar.events.readonly`
    // cannot insert. Already part of V1_SCOPES (added in Phase 1a for Phase
    // 1b read tools; sufficient for Phase 2 write).
    requiredScopes: [CALENDAR_EVENTS],
    handler: handlers.calendarCreateEvent,
    min_tier: "write",
  },
  // v1.17 Phase 1 — Calendar mutation tier (3 tools, same scope as Phase 2).
  // See docs/v1.17-deferred-completion.md §2.1-2.3. NO re-consent ceremony
  // (calendar.events scope already in V1_SCOPES since v1.13 Phase 1a).
  calendar_update_event: {
    name: "calendar_update_event",
    description:
      "PARTIAL-UPDATE an existing Google Calendar event via events.patch (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). HARD-CODED `sendUpdates=none` — caller cannot override; NO invite emails sent on update (anti-spam blast-radius guard; same as calendar_create_event). Partial semantics: only listed keys mutate; omitted keys preserve their existing values. ALLOWED top-level fields: summary / description / location / start / end / attendees. FORBIDDEN (rejected via additionalProperties:false + handler-side allowlist): eventType / recurrence / recurringEventId / transparency / visibility / attachments / conferenceData / extendedProperties / id and 11 other Event resource fields. Per-attendee allowlist: only {email, displayName} (FORBIDDEN: responseStatus / optional / additionalGuests / comment / self / organizer / resource — caller MUST NOT smuggle responseStatus via update path; use calendar_respond for RSVP). PHASE 1 SIMPLIFICATION: if start OR end is supplied, BOTH must be supplied (caller reads existing values via calendar_get_event first). Phase 3 contact-lookup applies — when SAFESPACE_RECIPIENT_ALLOW_CONTACTS=true, attendee names resolve to emails (same gate as calendar_create_event). Hard caps same as calendar_create_event (summary 1000 bytes, description 8000 bytes, location 1000 bytes, attendees max 50). Returns the updated Event resource. Audit row gains target_event_hash (plain SHA-256 of event_id) + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value.",
        },
        event_id: {
          type: "string",
          pattern: "^[a-zA-Z0-9_-]{1,128}$",
          description:
            "Opaque Google Calendar event ID (1-128 chars; URL-safe). Resolve via calendar_list_events / calendar_get_event.",
        },
        summary: {
          type: "string",
          description:
            "Event title (1-1000 bytes UTF-8 after validation, no CR/LF/NUL/NEL/U+2028/U+2029). Omit to leave unchanged.",
        },
        description: {
          type: "string",
          description:
            "Event body text (max 8000 bytes UTF-8). Line breaks preserved. Omit to leave unchanged.",
        },
        location: {
          type: "string",
          description: "Location text (max 1000 bytes UTF-8). Omit to leave unchanged.",
        },
        start: {
          type: "object",
          description:
            "Start time — either {dateTime, timeZone?} for timed events OR {date} for all-day events. Must match `end` shape. If supplied, `end` MUST also be supplied (Phase 1 simplification).",
        },
        end: {
          type: "object",
          description:
            "End time — same shape as `start`. Must be chronologically AFTER `start`. If supplied, `start` MUST also be supplied (Phase 1 simplification).",
        },
        attendees: {
          type: "array",
          maxItems: 50,
          description:
            "Attendee list (max 50; REPLACES the existing attendees on Google Calendar — this is patch-replace semantics, not merge). Each entry is {email: string (validated), displayName?: string}. NO invite emails (sendUpdates=none hard-coded). Forbidden per-attendee keys (responseStatus / optional / additionalGuests / comment / self / organizer / resource) are REJECTED at handler boundary.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["event_id"],
      additionalProperties: false,
    },
    requiredScopes: [CALENDAR_EVENTS],
    handler: handlers.calendarUpdateEvent,
    min_tier: "write",
  },
  calendar_delete_event: {
    name: "calendar_delete_event",
    description:
      "DELETE a Google Calendar event via events.delete (WRITE OPERATION, DESTRUCTIVE — recoverable only via Google Calendar trash within 30 days, web UI only; SafeSpace does NOT ship calendar_undelete_event). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). HARD-CODED `sendUpdates=none` — NO cancellation notices sent to attendees. Per-call only (no bulk delete; blast-radius bound). min_tier=write (NOT read like drive_unshare_file) because delete destroys content AND audit evidence — see docs/v1.17-deferred-completion.md §10 Q4 for asymmetry reasoning. Returns {deleted: true, event_id}. Audit row gains target_event_hash + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value.",
        },
        event_id: {
          type: "string",
          pattern: "^[a-zA-Z0-9_-]{1,128}$",
          description:
            "Opaque Google Calendar event ID (1-128 chars; URL-safe). Resolve via calendar_list_events / calendar_get_event.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["event_id"],
      additionalProperties: false,
    },
    requiredScopes: [CALENDAR_EVENTS],
    handler: handlers.calendarDeleteEvent,
    min_tier: "write",
  },
  calendar_respond: {
    name: "calendar_respond",
    description:
      "RSVP to a Google Calendar event — set the caller's own attendee responseStatus (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). HARD-CODED `sendUpdates=none` — declining a meeting does NOT email the organizer (anti-spam; user can notify via Calendar web UI). Mechanism: pre-fetches event via events.get to read the current attendees, then submits events.patch with the FULL attendees list (Google PATCH treats subset-of-attendees as REPLACE — handler MUST preserve non-self entries byte-for-byte). Caller responds AS themselves — no per-attendee allowlist gate (the caller's own email is implicitly trusted). TOCTOU: get-then-patch has a race window (organizer modifications between get and patch are silently overwritten); accepted out-of-scope for Phase 1 (Phase 1c follow-up will add If-Match). Returns the updated Event resource. Audit row gains target_event_hash + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        calendar_id: {
          type: "string",
          description:
            "Calendar ID — 'primary' for the user's own calendar (default), OR an email-shaped value.",
        },
        event_id: {
          type: "string",
          pattern: "^[a-zA-Z0-9_-]{1,128}$",
          description:
            "Opaque Google Calendar event ID (1-128 chars; URL-safe). Resolve via calendar_list_events / calendar_get_event.",
        },
        response: {
          type: "string",
          enum: ["accepted", "declined", "tentative", "needsAction"],
          description:
            "RSVP response — one of {accepted, declined, tentative, needsAction} (case-sensitive, per Google Calendar API).",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["event_id", "response"],
      additionalProperties: false,
    },
    requiredScopes: [CALENDAR_EVENTS],
    handler: handlers.calendarRespond,
    min_tier: "write",
  },
};
