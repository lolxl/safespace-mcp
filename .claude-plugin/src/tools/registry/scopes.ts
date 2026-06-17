// OAuth scope constants — extracted verbatim from the former monolithic
// src/tools/registry.ts. `export` added so the per-API registry fragments and
// the ./index.ts barrel can consume / re-export them (surface unchanged).

export const GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly";
export const GMAIL_LABELS = "https://www.googleapis.com/auth/gmail.labels";
export const GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify";
export const GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send";
// v1.51 (backlog B3) — Gmail settings (basic) scope. The narrowest scope that
// authorizes `users.settings.filters.{list,create,delete}`. Deliberately NOT
// `gmail.settings.sharing` (which would additionally grant forwarding-address /
// delegate management — the more-sensitive surface SafeSpace intentionally does
// NOT expose; see docs/v1.51-gmail-filters.md §1). Neither `gmail.modify` nor
// `gmail.labels` covers settings.filters, so V1_SCOPES (consent.ts) gains this
// scope → one-time re-consent ceremony. Like the other Gmail scopes it is FLAT
// (no narrower/broader variant SafeSpace uses), so there is intentionally NO
// SCOPE_HIERARCHY entry in with-context.ts — `scopeSatisfies` checks it directly.
export const GMAIL_SETTINGS_BASIC = "https://www.googleapis.com/auth/gmail.settings.basic";
export const DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly";
// v1.2: full Drive scope for permission-modify (share / unshare) tools. We
// deliberately chose this over `drive.file` because `drive.file` only grants
// access to files the app itself created or opened — our use case is sharing
// arbitrary files the user references by id, none of which were opened by
// this MCP server. `drive.metadata` was also ruled out (metadata-only, no
// permission-write). There is no Drive scope narrower than `drive` that
// grants permission-modification on arbitrary files (sec-rev Q1, 2026-05-16).
export const DRIVE = "https://www.googleapis.com/auth/drive";
// v1.12 Phase 1b: Google Docs API scopes. `DOCUMENTS_READONLY` is the
// narrowest scope sufficient for `docs_get_content` (structured read);
// `DOCUMENTS` (full) is required for `docs_create` (and any future write
// tool — append/edit). The SCOPE_HIERARCHY in with-context.ts encodes
// `documents.readonly ⊂ documents` so an account that re-consented to
// V1_SCOPES (full `documents`) satisfies any narrower readonly requirement.
export const DOCUMENTS_READONLY = "https://www.googleapis.com/auth/documents.readonly";
export const DOCUMENTS = "https://www.googleapis.com/auth/documents";
// v1.60: Google Slides API. `PRESENTATIONS` (full read+write, bundled — mirror
// the v1.12 Docs / v1.20 Sheets precedent; Slides is write-oriented) is required
// by slides_get/create/modify. SCOPE_HIERARCHY (with-context.ts) encodes
// `presentations.readonly ⊂ presentations` (two-key, mirror documents) so an
// account that re-consented to V1_SCOPES (full `presentations`) satisfies any
// narrower readonly requirement. `PRESENTATIONS_READONLY` is pre-loaded for a
// future narrower-scope read tool. See docs/v1.60-slides.md §3.
export const PRESENTATIONS_READONLY = "https://www.googleapis.com/auth/presentations.readonly";
export const PRESENTATIONS = "https://www.googleapis.com/auth/presentations";
// v1.13 Phase 1b: Google Calendar API scopes. `CALENDAR_EVENTS_READONLY` is
// the narrowest scope sufficient for `calendar_list_events` + `calendar_get_event`
// (read-only event access; cannot create/update/delete). `CALENDAR_EVENTS`
// (the broader read+write scope) is what V1_SCOPES (consent.ts) actually
// requests — sufficient for Phase 2 `calendar_create_event`. The
// SCOPE_HIERARCHY in with-context.ts encodes
// `calendar.events.readonly ⊂ calendar.events ⊂ calendar` so an account
// that re-consented to V1_SCOPES (`calendar.events`) satisfies the narrower
// readonly requirement here without an extra ceremony.
export const CALENDAR_EVENTS_READONLY = "https://www.googleapis.com/auth/calendar.events.readonly";
// v1.13 Phase 2: full `calendar.events` (read + write) is the narrowest scope
// sufficient for `events.insert`. `calendar.events.readonly` cannot create.
// V1_SCOPES (consent.ts) already grants `calendar.events` from Phase 1a, so
// no consent-surface widening here — read tools satisfy the narrower readonly
// requirement via SCOPE_HIERARCHY (with-context.ts), and write tools satisfy
// the full requirement directly.
export const CALENDAR_EVENTS = "https://www.googleapis.com/auth/calendar.events";
// v1.45 (backlog A5): two NEW minimum-privilege READ scopes — the first scope
// additions since v1.20. `CALENDAR_FREEBUSY` is the single narrowest scope
// Google offers for `freebusy.query` (busy WINDOWS only — no event titles /
// descriptions / attendees). `CALENDAR_CALENDARLIST_READONLY` is the narrowest
// for `calendarList.list` (enumerate accessible calendars). NEITHER is covered
// by the v1.13 `calendar.events` scope, so V1_SCOPES (consent.ts) gains both →
// re-consent ceremony. SCOPE_HIERARCHY (with-context.ts) pre-lists the broader
// `calendar.readonly` / `calendar` grants as transitive-closure satisfiers.
// See docs/v1.45-calendar-freebusy-list.md §1.
export const CALENDAR_FREEBUSY = "https://www.googleapis.com/auth/calendar.freebusy";
export const CALENDAR_CALENDARLIST_READONLY =
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly";
// v1.15 Phase 1b: Google People (Contacts) API. `CONTACTS_READONLY` is the
// only scope used in Phase 1 (search / lookup_email / get). V1_SCOPES
// (consent.ts) requests `contacts.readonly` — sufficient for all three read
// tools. SCOPE_HIERARCHY (with-context.ts) encodes
// `contacts.readonly ⊂ contacts` so a Phase 2 upgrade (write tier) would
// still satisfy the readonly requirement here without an extra ceremony.
//
// Phase 2 implementer note: when `contacts_create` ships, define a sibling
// `CONTACTS` constant + new SCOPE_HIERARCHY key per design §5. (DONE in v1.50.)
export const CONTACTS_READONLY = "https://www.googleapis.com/auth/contacts.readonly";
// v1.50 (backlog B5) Phase 2: full `contacts` (read + write) — the narrowest
// scope sufficient for the People API write tools `contacts_create`
// (people.createContact) + `contacts_update` (people.updateContact).
// `contacts.readonly` cannot write (Google returns 403 insufficient_scope).
// V1_SCOPES (consent.ts) UPGRADES `contacts.readonly` → `contacts` (one-time
// re-consent ceremony for accounts consented before v1.50). SCOPE_HIERARCHY
// (with-context.ts) gains the second KEY `"contacts": ["contacts"]` so the
// write tools have a satisfying granted scope; the existing `contacts.readonly`
// KEY already pre-lists `contacts`, so the v1.15 read tools stay satisfied
// post-upgrade with NO hierarchy edit. See docs/v1.50-contacts-write.md §1.
export const CONTACTS = "https://www.googleapis.com/auth/contacts";
// v1.16 Phase 1b: Google YouTube Data API v3. `YOUTUBE_READONLY` is the
// only scope used in Phase 1 (subscriptions / channel uploads / video /
// search / comments READ). V1_SCOPES (consent.ts) requests
// `youtube.readonly` — sufficient for all 5 read tools. SCOPE_HIERARCHY
// (with-context.ts) encodes `youtube.readonly ⊂ youtube.force-ssl ⊂ youtube`
// so a future Phase 2 upgrade (`youtube.force-ssl` for comment writes)
// would still satisfy the readonly requirement here without an extra
// ceremony.
//
// Phase 2 implementer note: when `youtube_video_comment_post` ships,
// define a sibling `YOUTUBE_FORCE_SSL` constant + new SCOPE_HIERARCHY key
// (`"youtube.force-ssl": ["youtube.force-ssl", "youtube"]`) per design §5.
export const YOUTUBE_READONLY = "https://www.googleapis.com/auth/youtube.readonly";
// v1.16 Phase 2b: youtube.force-ssl is the narrowest scope sufficient for
// comment WRITE tools (commentThreads.insert / comments.insert). Phase 2a
// shipped the SCOPE_HIERARCHY 2nd KEY entry (`youtube.force-ssl` →
// `[force-ssl, youtube]`), so an account that re-consented to V1_SCOPES
// (`youtube.force-ssl`) satisfies both the read-tier (via the
// `youtube.readonly` key's transitive closure) and write-tier requirements.
// `youtube` (full upload + channel mgmt) is locked rejected per v1.16 §14.
export const YOUTUBE_FORCE_SSL = "https://www.googleapis.com/auth/youtube.force-ssl";
// v1.59: YouTube Analytics API v2 (read-only channel metrics). A SEPARATE scope
// FAMILY from the YouTube Data API scopes above — `youtube.readonly` /
// `youtube.force-ssl` / `youtube` do NOT satisfy Analytics and vice-versa
// (`reports.query` needs `yt-analytics*`). v1.59 ships the NON-MONETARY scope
// only (views / watch-time / engagement / subscriber / traffic); the monetary
// (revenue) variant `yt-analytics-monetary.readonly` was deferred to a later
// opt-in (design §2 / Q1) — SHIPPED in v1.61 as YT_ANALYTICS_MONETARY_READONLY
// below. As of v1.61 the base key gains a SCOPE_HIERARCHY entry (the monetary
// scope is a strict superset → satisfies the base read); the YouTube *Data*
// scopes still do NOT satisfy Analytics and vice-versa.
export const YT_ANALYTICS_READONLY = "https://www.googleapis.com/auth/yt-analytics.readonly";
// v1.61: YouTube Analytics MONETARY (revenue) read scope. A strict SUPERSET of
// `yt-analytics.readonly` (Google: covers all non-monetary metrics PLUS revenue
// — estimatedRevenue / ad revenue / CPM / monetized playbacks). OPT-IN ONLY:
// requested at consent solely when SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true
// (see auth/consent.ts effectiveConsentScopes + policy/youtube-analytics-monetary.ts).
// No tool's `requiredScopes` references it (youtube_analytics_query stays base);
// instead SCOPE_HIERARCHY (with-context.ts) records `yt-analytics.readonly ⊂
// yt-analytics-monetary.readonly` so a monetary-consented account satisfies the
// base read. See docs/v1.61-youtube-analytics-monetary.md §2.
export const YT_ANALYTICS_MONETARY_READONLY =
  "https://www.googleapis.com/auth/yt-analytics-monetary.readonly";
// v1.62: Google Forms API v1 — TWO narrow READ scopes (read-structure and
// read-responses are SEPARATE Google scopes; neither implies the other).
// `FORMS_BODY_READONLY` covers forms.get (form structure); `FORMS_RESPONSES_READONLY`
// covers forms.responses.list/get (submitted responses). Deliberately the
// narrowest reads — NOT the broader `forms.body` (read+write structure), which is
// reserved for the future write cycle. SCOPE_HIERARCHY (with-context.ts) pre-loads
// `forms.body.readonly ⊂ forms.body` (so a future forms_create/forms_modify ships
// without a hierarchy edit); `forms.responses.readonly` is FLAT (there is NO
// write-responses scope — the API cannot write responses). See
// docs/v1.62-forms-readonly.md §2.
export const FORMS_BODY_READONLY = "https://www.googleapis.com/auth/forms.body.readonly";
export const FORMS_RESPONSES_READONLY = "https://www.googleapis.com/auth/forms.responses.readonly";
// v1.63: Forms write — full `forms.body` (read+write FORM STRUCTURE). A strict
// SUPERSET of `forms.body.readonly` (SCOPE_HIERARCHY pre-loaded the
// `forms.body.readonly ⊂ forms.body` edge in v1.62), so upgrading V1_SCOPES from
// the narrow read to this full scope keeps the v1.62 read tools satisfied via the
// hierarchy while authorizing forms_create (forms.create) + forms_modify
// (forms.batchUpdate). This is the v1.50 contacts.readonly → contacts upgrade
// pattern (re-consent). `forms.responses.readonly` is UNCHANGED — responses stay
// read-only (the API cannot write responses). See docs/v1.63-forms-write.md §2.
export const FORMS_BODY = "https://www.googleapis.com/auth/forms.body";
// v1.19 Phase 1b: Google Tasks API scope. `TASKS` is the full read + write
// (and delete) bundled scope; v1.19 §3 Q1 LOCKED — Tasks is heavily write-
// oriented, so the split readonly + Phase-2-upgrade pattern (v1.16 precedent)
// is intentionally NOT applied. V1_SCOPES (consent.ts) already requests `tasks`
// from Phase 1a, so Phase 1b read tools satisfy the requirement directly.
// SCOPE_HIERARCHY (with-context.ts) encodes `tasks.readonly ⊂ tasks` so a
// future cycle introducing read-only-only use cases could declare a narrower
// `TASKS_READONLY` constant + tool entry without re-consent (see v1.19 §3
// "Re-evaluate" + §4 future-proofing).
export const TASKS = "https://www.googleapis.com/auth/tasks";
// v1.20 Phase 1b-1: Google Sheets API scope. `SPREADSHEETS` is the full
// read + write bundled scope; v1.20 §3 Q1 LOCKED — Sheets is heavily write-
// oriented for personal automation, so the split readonly + Phase-2-upgrade
// pattern (v1.15/v1.16 precedent) is intentionally NOT applied. V1_SCOPES
// (consent.ts) already requests `spreadsheets` from Phase 1a, so Phase 1b
// read tools satisfy the requirement directly. SCOPE_HIERARCHY
// (with-context.ts) encodes `spreadsheets.readonly ⊂ spreadsheets` so a
// future cycle introducing read-only-only use cases could declare a
// narrower `SPREADSHEETS_READONLY` constant + tool entry without re-consent
// (see v1.20 §3 "Re-evaluate" + §4 future-proofing).
export const SPREADSHEETS = "https://www.googleapis.com/auth/spreadsheets";

// Re-export so withToolContext can map a tool's requiredScopes against the
// account's persisted scope set. Single source of truth — V1_SCOPES in
// consent.ts is the request side; these are the runtime check side.
