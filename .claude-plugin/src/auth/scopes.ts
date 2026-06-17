// v1.66 Phase C (PR 2) — the google-workspace OAuth scope hierarchy, moved out of
// the generic choke point (`tools/with-context.ts`) into a leaf module.
//
// WHY THIS MOVED (docs/safety-gateway-thesis.md §4): "The OAuth machinery
// (V1_SCOPES, consent, SCOPE_HIERARCHY, requiredScopes) becomes the
// google-workspace source's Authorizer impl — NOT a property of the gateway." As
// of v1.66 `googleWorkspace.authorize` (tools/source.ts) is the per-source
// strategy that runs the scope pre-check, so `scopeSatisfies` had to be reachable
// from `source.ts` WITHOUT a `source ↔ with-context` import cycle (the B4
// anti-cycle lesson). A leaf — imported by source.ts (the authorize strategy),
// with-context.ts (re-exports for back-compat), and with-all-accounts.ts (the
// OAuth-only `_all` choke point's own inline scope check) — is the clean home.
//
// The content below is VERBATIM from the pre-v1.66 with-context.ts (the table +
// the single-hop `scopeSatisfies`); behavior is byte-identical.

// v1.2 PR-1: scope hierarchy. Google OAuth returns the literal granted scope
// string — `drive` (full) does NOT auto-expand to also include `drive.readonly`
// in the granted set. But semantically `drive` covers `drive.readonly` (and
// `drive.metadata.readonly`, `drive.file`, etc.). Without this table, a send
// profile that re-consented to v1.2 scopes (token has `drive` only) would
// fail the scope-mismatch check on every existing read tool that still
// declares `requiredScopes: [drive.readonly]`.
//
// Map = required-scope → list of granted-scopes that count as satisfying it.
// Keep narrow: only encode hierarchies we actually use. Gmail scopes are
// flat in our setup so they don't appear here. The Drive `drive.activity`
// family is unused.
//
// SECURITY NOTE: hierarchy is encoded one direction only (broader covers
// narrower). Never let a narrower scope satisfy a broader one. Adding a new
// row here widens what counts as "satisfied" — sec-rev required before
// any expansion.
const SCOPE_HIERARCHY: Record<string, readonly string[]> = {
  "https://www.googleapis.com/auth/drive.readonly": [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive",
  ],
  // v1.12 Phase 1a — mirrors the drive.readonly ⊂ drive pattern for the Docs
  // API family. `documents` (full) satisfies any `documents.readonly` requirement.
  "https://www.googleapis.com/auth/documents.readonly": [
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/documents",
  ],
  // v1.60 — Google Slides API family. Mirrors the documents.readonly ⊂ documents
  // two-key pattern. V1_SCOPES requests full `presentations`; the readonly key is
  // pre-loaded (transitive closure) so a future narrower-scope read tool ships
  // without a hierarchy edit. `presentations` (full) satisfies any
  // `presentations.readonly` requirement. See docs/v1.60-slides.md §3.
  "https://www.googleapis.com/auth/presentations.readonly": [
    "https://www.googleapis.com/auth/presentations.readonly",
    "https://www.googleapis.com/auth/presentations",
  ],
  // v1.62 — Google Forms API family (read-only slice). Mirrors the
  // documents.readonly ⊂ documents two-key pattern: V1_SCOPES requests the narrow
  // `forms.body.readonly`, and the broader write scope `forms.body` is pre-loaded
  // in the closure so a future forms_create/forms_modify cycle (requiredScopes:
  // [forms.body]) ships without a hierarchy edit. `forms.body` (full) satisfies
  // any `forms.body.readonly` requirement.
  //
  // NOTE: `forms.responses.readonly` is deliberately NOT a key here — there is no
  // broader "write responses" scope (the Forms API cannot write responses), so it
  // is FLAT and `scopeSatisfies` checks it by literal equality (mirror
  // gmail.settings.basic v1.51 / yt-analytics.readonly v1.59). See
  // docs/v1.62-forms-readonly.md §2.
  "https://www.googleapis.com/auth/forms.body.readonly": [
    "https://www.googleapis.com/auth/forms.body.readonly",
    "https://www.googleapis.com/auth/forms.body",
  ],
  // v1.61 — YouTube Analytics monetary opt-in. The monetary scope is a strict
  // SUPERSET of the base read (Google: all non-monetary metrics PLUS revenue),
  // so an account that consented to the monetary scope satisfies
  // youtube_analytics_query's base `requiredScopes: [yt-analytics.readonly]`.
  // v1.59 shipped this scope FLAT (no entry, exact-match only); v1.61 adds the
  // two-element closure. Note: the monetary scope is NOT itself a tool
  // requiredScope, so it needs no self-key. The YouTube *Data* scopes still do
  // NOT satisfy Analytics. See docs/v1.61-youtube-analytics-monetary.md §2.
  "https://www.googleapis.com/auth/yt-analytics.readonly": [
    "https://www.googleapis.com/auth/yt-analytics.readonly",
    "https://www.googleapis.com/auth/yt-analytics-monetary.readonly",
  ],
  "https://www.googleapis.com/auth/presentations": [
    "https://www.googleapis.com/auth/presentations",
  ],
  // v1.13 Phase 1a — Google Calendar API family.
  //
  // Two KEY entries (not a chain) — each key maps to ALL transitively
  // satisfying granted scopes (precomputed transitive closure). `scopeSatisfies`
  // does a single-hop lookup, so a chain (readonly → events → calendar) would
  // not work: looking up `calendar.events.readonly` would only return events,
  // missing the `calendar` (broadest) coverage. See PR #113 finding H1.
  //
  // Hierarchy:
  //   calendar (broadest, full admin)
  //     ⊇ calendar.events           (read + write events; v1.13 chosen scope)
  //       ⊇ calendar.events.readonly (read events only)
  "https://www.googleapis.com/auth/calendar.events.readonly": [
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar",
  ],
  "https://www.googleapis.com/auth/calendar.events": [
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar",
  ],
  // v1.45 (backlog A5) — Calendar free/busy + calendar list families. Two
  // SEPARATE scope families, each its own KEY (scopeSatisfies is single-hop);
  // value arrays are the transitive closure (broader granted scopes pre-listed
  // for future-proofing). SafeSpace requests the EXACT narrow scope in
  // V1_SCOPES, so element-0 alone satisfies the check; the broader entries only
  // matter for an account that consented to calendar.readonly / calendar (full).
  //
  //   freebusy.query    ← calendar.freebusy ⊂ calendar.readonly ⊂ calendar
  //   calendarList.list ← calendar.calendarlist.readonly ⊂ calendar.calendarlist
  //                       ⊂ calendar.readonly ⊂ calendar
  //
  // NOTE: calendar.events / calendar.events.readonly do NOT satisfy either —
  // event scopes grant no free/busy or calendar-list access (Google API ref).
  // See docs/v1.45-calendar-freebusy-list.md §1.
  "https://www.googleapis.com/auth/calendar.freebusy": [
    "https://www.googleapis.com/auth/calendar.freebusy",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar",
  ],
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly": [
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    "https://www.googleapis.com/auth/calendar.calendarlist",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/calendar",
  ],
  // v1.15 Phase 1a — Google People (Contacts) API family.
  //
  // Hierarchy (mirrors drive / documents / calendar pattern):
  //   contacts (full read+write)
  //     ⊇ contacts.readonly (read-only; v1.15 Phase 1 chosen scope)
  //
  // The value array IS the transitive closure — `contacts` is pre-listed
  // here even though Phase 1 never asks for it, so that a future Phase-2
  // user who consented to the broader `contacts` scope still satisfies
  // Phase 1 read tools. This mirrors how `calendar.events.readonly` already
  // lists `calendar` even though SafeSpace never asks for `calendar` (full).
  //
  // Phase 2 implementer note (DONE in v1.50): when `contacts_create` ships
  // (requires full `contacts` scope), MUST add a SECOND KEY entry
  // `"contacts": ["contacts"]` — because `scopeSatisfies` is single-hop. See
  // v1.13's calendar.events block above for the two-key pattern, and the
  // `contacts` KEY immediately below. See docs/v1.50-contacts-write.md §1.
  "https://www.googleapis.com/auth/contacts.readonly": [
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/contacts",
  ],
  // v1.50 (backlog B5) Phase 2 — full `contacts` write scope. SECOND KEY entry
  // (the Phase-2 implementer must-do called out in the contacts.readonly block
  // above) so the write tools `contacts_create` / `contacts_update` (which
  // declare `requiredScope: contacts`) have a satisfying granted scope under the
  // single-hop `scopeSatisfies`. `contacts` maps to itself — there is no
  // broader Contacts scope. See docs/v1.50-contacts-write.md §1.
  "https://www.googleapis.com/auth/contacts": [
    "https://www.googleapis.com/auth/contacts",
  ],
  // v1.16 Phase 1a — Google YouTube API family.
  //
  // Hierarchy (mirrors calendar.events.readonly → events → calendar pattern):
  //   youtube (broadest — read + write + UPLOAD + channel mgmt; locked rejected §14)
  //     ⊇ youtube.force-ssl (read + comment writes; v1.16 Phase 2 chosen scope)
  //       ⊇ youtube.readonly (read only; v1.16 Phase 1 chosen scope)
  //
  // Value array IS the transitive closure (broader scopes pre-listed even
  // though Phase 1 never asks for them), so a future Phase-2 user who
  // consented to youtube.force-ssl still satisfies Phase 1 read tools.
  //
  // ⚠ Phase 2 implementer note: when youtube_video_comment_post ships
  // (requires youtube.force-ssl scope), MUST add a SECOND KEY entry
  // `"youtube.force-ssl": ["youtube.force-ssl", "youtube"]` — because
  // scopeSatisfies is single-hop. Phase 2 write tools would have no
  // satisfying granted scope without it. See v1.13 calendar block above
  // for the two-key pattern. See docs/v1.16-youtube-api.md §5.
  "https://www.googleapis.com/auth/youtube.readonly": [
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube",
  ],
  // v1.16 Phase 2a — youtube.force-ssl (write scope; covers reads too via
  // Google's design).
  //
  // Phase 1a pre-loaded this as required: scopeSatisfies is single-hop, so a
  // Phase 2 write tool with requiredScopes: [YOUTUBE_FORCE_SSL] needs an
  // explicit KEY entry. Without this, an account that consented to
  // youtube.force-ssl would FAIL scope_mismatch when calling write tools.
  // Mirrors v1.13's two-key calendar block (calendar.events.readonly +
  // calendar.events) — same transitive-closure-not-chain pattern per
  // PR #113 finding H1.
  //
  // The existing youtube.readonly key's value array already lists force-ssl
  // and youtube (Phase 1a transitive closure), so narrower readonly
  // requirements continue to be satisfied by force-ssl / youtube grants.
  // One-direction guard preserved: youtube.force-ssl granted does NOT
  // satisfy youtube (broader / upload) required.
  "https://www.googleapis.com/auth/youtube.force-ssl": [
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube",
  ],
  // v1.19 Phase 1a — Google Tasks API family.
  //
  // Hierarchy (mirrors drive.readonly / documents.readonly / calendar.events.readonly pattern):
  //   tasks (read + write; v1.19 chosen scope — bundled because Tasks is
  //          heavily write-oriented per design §3 / locked Q1)
  //     ⊇ tasks.readonly (read only; NOT consented in v1.19, pre-loaded for
  //                       future narrower-scope upgrades per §3 "re-evaluate")
  //
  // Both keys pre-loaded: `tasks` (chosen scope for v1.19; only `tasks` satisfies)
  // AND `tasks.readonly` (future-proof: a user who only granted `tasks.readonly`
  // MUST be able to call any read-only tool that ever ships requiring
  // tasks.readonly; pre-loading the closure avoids drift if a future cycle
  // introduces a narrower-scope read tool). Mirrors v1.16 pattern where
  // youtube.readonly was pre-loaded with [readonly, force-ssl, youtube] before
  // any tool declared youtube.force-ssl as requiredScope.
  //
  // Two KEY entries (mirror v1.13 calendar.events / v1.16 youtube.force-ssl
  // two-key pattern) — scopeSatisfies is single-hop; without an explicit
  // `tasks` key entry a tool with requiredScopes: [TASKS] would FAIL
  // scope_mismatch even on an account that consented to `tasks`. See
  // PR #113 finding H1.
  //
  // One-direction guard: narrower `tasks.readonly` granted does NOT satisfy
  // broader `tasks` required.
  "https://www.googleapis.com/auth/tasks.readonly": [
    "https://www.googleapis.com/auth/tasks.readonly",
    "https://www.googleapis.com/auth/tasks",
  ],
  "https://www.googleapis.com/auth/tasks": [
    "https://www.googleapis.com/auth/tasks",
  ],
  // v1.20 Phase 1a — Google Sheets API family.
  //
  // Hierarchy (mirrors drive.readonly / documents.readonly / calendar.events.readonly /
  // tasks.readonly pattern):
  //   spreadsheets (read + write; v1.20 chosen scope — bundled because Sheets
  //                 is heavily write-oriented per design §3 / locked Q1)
  //     ⊇ spreadsheets.readonly (read only; NOT consented in v1.20, pre-loaded
  //                              for future narrower-scope upgrades per §3
  //                              "re-evaluate")
  //
  // Both keys pre-loaded: `spreadsheets` (chosen scope for v1.20; only
  // `spreadsheets` satisfies) AND `spreadsheets.readonly` (future-proof: a
  // user who only granted `spreadsheets.readonly` MUST be able to call any
  // read-only tool that ever ships requiring spreadsheets.readonly;
  // pre-loading the closure avoids drift if a future cycle introduces a
  // narrower-scope read tool). Mirrors v1.19 pattern where `tasks.readonly`
  // was pre-loaded with [readonly, tasks] before any tool declared
  // tasks.readonly as requiredScope.
  //
  // Two KEY entries (mirror v1.13 calendar.events / v1.16 youtube.force-ssl /
  // v1.19 tasks two-key pattern) — scopeSatisfies is single-hop; without an
  // explicit `spreadsheets` key entry a tool with requiredScopes:
  // [SPREADSHEETS] would FAIL scope_mismatch even on an account that
  // consented to `spreadsheets`. See PR #113 finding H1.
  //
  // One-direction guard: narrower `spreadsheets.readonly` granted does NOT
  // satisfy broader `spreadsheets` required.
  //
  // See docs/v1.20-sheets-api.md §4.
  "https://www.googleapis.com/auth/spreadsheets.readonly": [
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/spreadsheets",
  ],
  "https://www.googleapis.com/auth/spreadsheets": [
    "https://www.googleapis.com/auth/spreadsheets",
  ],
};

export function scopeSatisfies(granted: Set<string>, required: string): boolean {
  const acceptable = SCOPE_HIERARCHY[required] ?? [required];
  return acceptable.some((s) => granted.has(s));
}
