// Pattern + confusables + skip-list tables for sanitize.
// See docs/DESIGN.md §P1(c) Sanitize pipeline.
//
// Coverage boundary (security-reviewer 2026-05-11):
//   - Confusables: Cyrillic (U+0400–U+04FF) and Greek (U+0370–U+03FF) high-
//     confusion pairs ONLY. Armenian, Georgian, full-width Latin, and other
//     scripts are out of scope for v1 — the full Unicode confusables table
//     over-normalizes legitimate non-Latin content (Chinese names, etc.).
//   - Patterns: prompt-injection (4), token leak (2), unicode-tag stego (1),
//     suspicious data URL (1). Translated-language injection (CJK
//     "ignore-above" phrases etc.) is deliberately NOT covered — accepted
//     per DESIGN.md §P6.
//   - Flag SEMANTICS: observability-only. Never used to block. The wrapper
//     itself is the actual security boundary; flags are hints to Claude.
//   - Pattern flag NEVER includes matched text — only the stable `id` reaches
//     the wrapper attribute. The match object from `.test()`/`.exec()` is
//     used only to determine presence, not to extract content.

export interface PatternDef {
  /** Stable id; emitted to the wrapper's `flags` attribute. */
  id: string;
  re: RegExp;
}

export const PATTERNS: readonly PatternDef[] = [
  { id: "ignore-prev", re: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|directives)/i },
  { id: "system-prompt-injection", re: /(system|assistant)\s*[:：]\s*you\s+are\s+/i },
  { id: "role-hijack", re: /\[INST\]|<\|im_start\|>|<\/instructions>|<\/system>/i },
  { id: "new-instructions", re: /new\s+instructions\s*[:：]/i },
  // /i because RFC 6750's scheme is case-insensitive AND leaked tokens in
  // free-form text (email body, log line) can appear with any casing.
  { id: "bearer-token", re: /Bearer\s+[A-Za-z0-9._\-]{20,}/i },
  { id: "oauth-code", re: /4\/[0-9A-Za-z\-_]{20,}/ },
  { id: "unicode-tag", re: /[\u{E0020}-\u{E007F}]/u },
  // MIME type capped to {1,200} to bound the scan if attacker stuffs
  // `data:` followed by 50KB of non-semicolon bytes (ReDoS hardening).
  // Min base64 portion = 50 chars (~36 bytes) — catches short instruction
  // payloads that a 200-char minimum would miss.
  { id: "data-url-base64", re: /data:[^;]{1,200};base64,[A-Za-z0-9+/=]{50,}/ },
] as const;

// v1.56 F3 — inbound credential-lure flag (docs/v1.56-...md §4.2). Unlike the
// single-regex PATTERNS above, this is a CO-OCCURRENCE rule: a credential/consent
// lure keyword AND a "risk token" (a non-Google link OR a non-Google email
// address). It surfaces the C1/C7 confused-deputy class — e.g. the Google
// app-name lure where the attacker makes Google's own servers send a
// legit-looking "someone added X as your recovery contact" notice whose tell is
// the foreign address (dmitrisorvanov9@mail.ru). Flag id ONLY — never the matched
// text (same no-oracle rule as PATTERNS). It is a FLAG, not a judgment of
// legitimacy; the keyword/host/domain sets are curated + tunable.

// Lure keywords (EN + zh-TW). `.test()`-only → NO `g` flag (stateful-regex trap).
const CREDENTIAL_LURE_KEYWORDS_RE =
  /recovery\s+contact|verification\s+code|verify\s+your\s+account|secure\s+your\s+account|confirm\s+your\s+identity|two[-\s]?factor|two[-\s]?step|one[-\s]?time\s+(?:code|password|passcode)|\b2fa\b|備援聯絡人|驗證碼|兩步驟|帳號安全|安全性警示|確認.{0,4}身分/i;

// Hosts whose links are EXPECTED in a genuine Google security notice → NOT a risk
// token (so a real "secure your account" email does not self-flag). Anchored to
// the host SUFFIX (sub.google.com matches; evil-google.com does NOT).
const GOOGLE_PROPERTY_HOST_RE =
  /(?:^|\.)(?:google\.com|googleapis\.com|gstatic\.com|googlemail\.com|youtube\.com|withgoogle\.com|goo\.gl)$/i;

// Email domains that are Google's own → excluded from the email risk-token (a
// legit Google notice references the user's gmail/google address).
const GOOGLE_EMAIL_DOMAIN_RE = /@(?:gmail\.com|googlemail\.com|google\.com)$/i;

// ⚠ Both are module-level `/g` regexes (allocated once — sanitize is a hot path).
// STATEFUL-REGEX DISCIPLINE: LURE_EMAIL_RE is used ONLY via `.match()` (stateless
// — does not consult/advance lastIndex), so it needs no reset. LURE_URL_RE is
// used via `.exec()` in a loop and is EXPLICITLY reset (`lastIndex = 0`) before
// that loop below. A future caller adding a `.test()` or a second `.exec()` path
// MUST reset lastIndex first (or move the regex inline) to avoid a cross-call bug.
const LURE_EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const LURE_URL_RE = /https?:\/\/([^\s/<>"')\]]+)/gi;

/** True iff `text` co-occurs a credential/consent lure keyword with a risk token
 *  (a non-Google email address OR a non-Google http(s) link). Pure + side-effect-
 *  free; resets its own stateful regexes so repeated calls are deterministic. */
export function detectCredentialLure(text: string): boolean {
  if (!CREDENTIAL_LURE_KEYWORDS_RE.test(text)) return false;
  // Risk token (a): a NON-Google email address (the foreign-domain tell).
  const emails = text.match(LURE_EMAIL_RE);
  if (emails && emails.some((e) => !GOOGLE_EMAIL_DOMAIN_RE.test(e))) return true;
  // Risk token (b): an http(s) URL whose host is NOT a Google property.
  LURE_URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LURE_URL_RE.exec(text)) !== null) {
    const host = (m[1] ?? "").toLowerCase().replace(/:\d+$/, "");
    if (host.length > 0 && !GOOGLE_PROPERTY_HOST_RE.test(host)) return true;
  }
  return false;
}

/** Zero-width / invisible chars frequently abused for prompt-injection evasion.
 * Using Unicode escapes (not literal invisible chars) so the source is robust
 * against editor whitespace normalization.
 *
 *   U+00AD  SOFT HYPHEN          — renders invisibly in HTML / email clients
 *   U+200B  ZERO WIDTH SPACE     — e.g. "i​gnore previous" bypasses /ignore/
 *   U+200C  ZERO WIDTH NON-JOINER
 *   U+200D  ZERO WIDTH JOINER
 *   U+2060  WORD JOINER
 *   U+FEFF  ZERO WIDTH NO-BREAK SPACE / BOM
 */
export const ZERO_WIDTH_RE = /[\u00AD\u200B\u200C\u200D\u2060\uFEFF]/g;

/** Per-string-leaf char cap before truncation kicks in. */
export const TRUNCATE_THRESHOLD = 50_000;

/** Truncation marker. Structurally distinct from `<untrusted-source-...>`
 * so truncation at the boundary cannot be confused with the wrapper. */
export const TRUNCATE_MARKER = "<safespace-truncated/>";

/** Latin↔Cyrillic + Latin↔Greek high-confusion homoglyph map (~40 entries). */
export const CONFUSABLES: ReadonlyMap<string, string> = new Map([
  // Cyrillic → Latin
  ["а", "a"], ["А", "A"],
  ["е", "e"], ["Е", "E"],
  ["о", "o"], ["О", "O"],
  ["р", "p"], ["Р", "P"],
  ["с", "c"], ["С", "C"],
  ["х", "x"], ["Х", "X"],
  ["у", "y"], ["У", "Y"],
  ["і", "i"], ["І", "I"],
  ["ѕ", "s"], ["Ѕ", "S"],
  ["ј", "j"], ["Ј", "J"],
  ["М", "M"],
  ["Н", "H"],
  ["В", "B"],
  ["К", "K"],
  ["Т", "T"],
  // Greek → Latin
  ["α", "a"], ["Α", "A"],
  ["ε", "e"], ["Ε", "E"],
  ["ο", "o"], ["Ο", "O"],
  ["ρ", "p"], ["Ρ", "P"],
  ["Β", "B"],
  ["Ζ", "Z"],
  ["Η", "H"],
  ["Ι", "I"],
  ["Κ", "K"],
  ["Μ", "M"],
  ["Ν", "N"],
  ["Τ", "T"],
  ["Υ", "Y"],
  ["Χ", "X"],
]);

/** Character class matching exactly the CONFUSABLES keys. Lets the sanitize hot
 *  path replace only the confusable code points in a single pass, instead of
 *  `Array.from(text).map(...).join("")` which allocates a full code-point array
 *  for every non-ASCII string leaf (expensive on large Docs/Drive payloads).
 *  Every key is a single BMP code unit, so a `u`-flag char class matches
 *  identically to per-code-point iteration — output is byte-for-byte unchanged.
 *  None of the keys are character-class metacharacters (`] \ ^ -`), so they
 *  need no escaping. */
const CONFUSABLE_KEYS = Array.from(CONFUSABLES.keys());
// Build-time invariant: no key may be a character-class metacharacter (`] \ ^ -`),
// otherwise the unescaped join below would malform the class or silently match
// the wrong set. Fail loudly at module load rather than mis-normalize at runtime.
if (CONFUSABLE_KEYS.some((k) => /[\]\\^-]/.test(k))) {
  throw new Error("CONFUSABLES_RE: a confusable key needs escaping — fix the regex builder");
}
export const CONFUSABLES_RE: RegExp = new RegExp(`[${CONFUSABLE_KEYS.join("")}]`, "gu");

/** Object key names that hold opaque IDs or structural metadata. Their
 * string values pass through sanitize without being wrapped — wrapping
 * would break downstream programmatic use (Claude can no longer use the
 * id as a key for follow-up tool calls). Per-key-name lookup (any nesting
 * depth). Verified against Google REST JSON for gmail.users.messages.list,
 * drive.files.list, calendar.events.list.
 *
 * **Invariant — values under a SKIP_FIELDS key MUST be primitives or
 * arrays of primitives.** sanitize/index.ts's `walk` propagates `inSkip=true`
 * to ALL descendants of a matched key, so if a future Google API ever
 * returned an object value under one of these keys, inner string fields
 * would be emitted unwrapped — re-introducing an injection surface. Before
 * adding a new key here, verify against the actual Google REST JSON shape
 * that the value cannot become an object containing user-influenced strings.
 * (issue #23) */
export const SKIP_FIELDS: ReadonlySet<string> = new Set([
  "id",
  "threadId",
  "historyId",
  "messageId",
  "fileId",
  "mimeType",
  "size",
  "internalDate",
  "labelIds",
  "webViewLink",
  "iconLink",
  // Pagination cursors + opaque structural fields — Google-controlled, NOT user content.
  // Found via Step 3 E2E: gmail.users.messages.list wrapped nextPageToken inside
  // <untrusted-source-...>, forcing Claude to extract the raw token before
  // passing it to the next page call. Same applies to Drive / Calendar list APIs.
  "nextPageToken", "pageToken", "nextSyncToken",
  "etag", "kind",
  // Gmail MIME part identifiers — opaque, Google-assigned. `partId` is positional
  // ("", "0", "0.1"); `attachmentId` is the handle used by messages.attachments.get.
  // Wrapping them blocks Step 5.4 from fetching attachments programmatically.
  // Pre-emptive add per 5.1 security review.
  "partId", "attachmentId",
  // Drive `parents` — array of folder ID strings used to navigate hierarchy.
  // Opaque Google-assigned IDs (e.g. "0AA_..."), not user content.
  // Found via 5.2 unit test on real `drive files list` response shape.
  // NOTE: deliberately NOT `owners` / `lastModifyingUser` — those contain
  // displayName/emailAddress which ARE user content and must wrap.
  "parents",
  // ISO-timestamp suffixes — common across Workspace APIs
  "createdAt", "updatedAt", "modifiedAt", "deliveredAt", "sentAt",
  "createdDate", "modifiedDate", "lastModifiedDate", "createdTime", "modifiedTime",
  // v1.12 Phase 1b — Google Docs API opaque metadata. See docs/v1.12-docs-api.md §5.
  //
  //   `objectId` — internal Google reference assigned to every StructuralElement,
  //     paragraph, table, inlineObject, etc. Opaque; appears throughout the
  //     response tree. NOT user-influenced text.
  //   `revisionId` — Docs document revision marker (HMAC-like opaque token).
  //     Google-controlled; only ever read back, never user-supplied.
  //   `inheritedNamedStyleType` — closed enum from the Docs spec:
  //     NORMAL_TEXT / HEADING_1..HEADING_6 / TITLE / SUBTITLE /
  //     NAMED_STYLE_TYPE_UNSPECIFIED. Not a user-definable custom style name.
  //
  // NOT added: `startIndex` / `endIndex` (both are `number` — sanitize only
  // wraps `typeof v === "string"` leaves; numerics pass through unwrapped).
  "objectId", "revisionId", "inheritedNamedStyleType",
  // v1.13 Phase 1b — Google Calendar API opaque metadata + closed enums.
  // See docs/v1.13-calendar-api.md §5 + §7 hook #2. Each key is either
  // Google-controlled opaque (URL / ID / ETag) or a closed enum the caller
  // cannot extend via the API — wrapping them in <untrusted-source> would
  // block Claude from using them as opaque references in follow-up calls
  // (e.g., dereferencing `recurringEventId` to fetch the master event).
  //
  //   `iCalUID` — RFC 5545 GUID, Google-generated. Stable across copies of
  //     the same event; opaque identifier, never user-supplied free text.
  //   `htmlLink` — Google-generated URL into calendar.google.com. Wrapping
  //     prevents downstream tools from treating it as a navigable link.
  //   `hangoutLink` — Google-generated Meet URL. Same rationale as htmlLink.
  //   `etag` — HTTP ETag, version marker. Already in SKIP_FIELDS via the
  //     generic Workspace block above; listed here as a per-API reaffirmation.
  //   `recurringEventId` — reference to master event (Google-controlled
  //     event ID). Opaque; identifier, not user-supplied content.
  //   `status` — closed enum: confirmed / tentative / cancelled. User can
  //     pick from the fixed set via the Calendar UI but cannot inject
  //     arbitrary strings via the API.
  //   `transparency` — closed enum: opaque / transparent. Same shape.
  //   `visibility` — closed enum: default / public / private / confidential.
  //   `eventType` — closed enum: default / outOfOffice / focusTime /
  //     workingLocation / birthday / fromGmail (Google API reference
  //     enumeration; user-extensible types are NOT permitted via the API).
  //
  // INTENTIONALLY NOT added (per docs/v1.13-calendar-api.md §5 + PR #113 L1):
  //   - `originalStartTime` — this is an OBJECT (`{dateTime, date, timeZone}`),
  //     not a primitive. The SKIP_FIELDS invariant (above, line ~104) requires
  //     values to be primitives or arrays of primitives; an object value would
  //     propagate `inSkip=true` to its descendants and emit user-influenced
  //     timezone strings unwrapped. The walker handles `originalStartTime`'s
  //     primitive children naturally — no SKIP_FIELDS entry needed.
  //   - `conferenceData` / `attachments` — top-level objects whose children
  //     include user-visible strings (entryPoints[].label, attachments[].title).
  //     Per design §5 + PR #113 M2: the tree-walker uniformly wraps all string
  //     leaves under these; adding a SKIP_FIELDS entry would un-wrap user-
  //     visible labels. Opaque IDs (conferenceId / signature / fileId) being
  //     wrapped is acceptable — Claude treats wrapped strings as text content,
  //     and these IDs are not used for follow-up API calls today.
  "iCalUID", "htmlLink", "hangoutLink", "recurringEventId",
  "status", "transparency", "visibility", "eventType",
  // `etag` is already in SKIP_FIELDS above via the cross-API set; not repeated.
  //
  // v1.15 Phase 1b — Google People (Contacts) API opaque metadata + closed enum.
  // See docs/v1.15-contacts-api.md §6. Two NEW keys; `id` / `etag` / `kind` /
  // `nextPageToken` already covered by the cross-API set above. Each key is
  // either Google-controlled opaque (resource handle) or a closed enum the
  // caller cannot extend via the API.
  //
  //   `resourceName` — opaque server-assigned People API ID (e.g.,
  //     "people/c1234567890123456789"). Same rationale as Drive `parents`
  //     and Calendar `recurringEventId`: identifier-only, never user-supplied
  //     free text. Wrapping it blocks `contacts_get({ resource_name })`
  //     follow-up calls from using the value programmatically.
  //   `objectType` — People API closed enum: PERSON (and any future Google-
  //     defined types). User cannot extend this set via the API. Mirrors
  //     Calendar's `eventType` / `transparency` SKIP rationale — wrapping
  //     a closed enum has no security upside and blocks programmatic
  //     comparison (`objectType === "PERSON"`).
  //
  // INTENTIONALLY NOT added (per docs/v1.15-contacts-api.md §6 sec-rev hook #7):
  //   - `displayName` / `givenName` / `familyName` / `middleName` /
  //     `honorificPrefix` / `honorificSuffix` — user-typed contact names.
  //   - `value` — appears under `emailAddresses[].value`, `phoneNumbers[].value`,
  //     `urls[].value`, `userDefined[].value`. CROSS-API invariant — also
  //     protects Calendar `extendedProperties[].value`, Drive `properties.value`,
  //     Gmail header `value`. Adding `value` to SKIP_FIELDS would silently
  //     unwrap user-controllable strings across 4 Google APIs.
  //   - `biographies` / `notes` (notes live under biographies[].value) —
  //     free-text bio; highest prompt-injection surface in a Person resource.
  //   - `organizations` / `title` / `department` — user-typed org affiliation.
  //   - `formattedValue` — `addresses[].formattedValue` user-typed.
  //   - `urls` (the array key) — must wrap each `value` underneath.
  //   - `userDefined.key` / `userDefined.value` — explicit user-supplied free text.
  "resourceName", "objectType",
  // v1.16 Phase 1b — Google YouTube Data API v3 opaque IDs + closed enums.
  // See docs/v1.16-youtube-api.md §6. Cross-API SKIP keys already cover
  // `id` / `etag` / `kind` / `nextPageToken` (used throughout YouTube
  // responses). The keys below are YouTube-specific and EITHER opaque
  // identifiers OR closed enums the caller cannot extend via the API.
  //
  //   `videoId` — opaque 11-char YouTube video ID (e.g., "dQw4w9WgXcQ").
  //     Identifier-only; never user-supplied free text. Wrapping it would
  //     block `youtube_video_get({video_id})` follow-up calls from using
  //     the value programmatically.
  //   `channelId` — opaque YouTube channel ID (`UC` + 22 chars). Same
  //     rationale as Drive `parents` / Calendar `recurringEventId`:
  //     programmatic reference, not display text. NOTE: `channelTitle`
  //     (the display string) is INTENTIONALLY NOT skipped — user-controllable,
  //     MUST wrap. WRITE-side (Phase 2 `youtube_video_comment_post`) treats
  //     `channelId` as a regex-validated USER-INTENT field; same key name,
  //     opposite valence by direction. See docs/v1.16-youtube-api.md §9
  //     "WRITE vs READ `channelId` reconcile".
  //   `playlistId` — opaque YouTube playlist ID (`PL...` / `UU...` etc.).
  //     Same rationale.
  //   `subscriptionId` — opaque server-assigned subscription ID. Mirrors
  //     `resourceName` (People) / `recurringEventId` (Calendar) rationale.
  //   `commentId` — opaque YouTube comment ID. Identifier-only; the COMMENT
  //     TEXT lives under `textDisplay` / `textOriginal` which MUST wrap
  //     (largest UGC injection surface in SafeSpace history).
  //   `authorChannelId` — nested opaque channel ID under
  //     `comment.snippet.authorChannelId.value` (object-shape edge case from
  //     YouTube's API). The unqualified key NAME `authorChannelId` is the
  //     OBJECT itself; its primitive `.value` child is what the walker reaches
  //     for SKIP propagation. Per primitive-only invariant, this works because
  //     `.value` IS a primitive — the wrapper sees a string leaf and skips
  //     wrapping it.
  //   `liveBroadcastContent` — closed enum: `none` / `live` / `upcoming`.
  //     Same rationale as Calendar `status` / `transparency` (caller cannot
  //     extend via API; wrapping blocks programmatic comparison).
  //   `privacyStatus` — closed enum: `public` / `private` / `unlisted`.
  //     Same rationale as `liveBroadcastContent`; caller cannot extend.
  //   `uploadStatus` — closed enum: `uploaded` / `processed` / `failed` /
  //     `rejected` / `deleted`. Same rationale.
  //   `license` — closed enum: `youtube` / `creativeCommon`. Same rationale.
  //
  // INTENTIONALLY NOT added (per docs/v1.16-youtube-api.md §6):
  //   - `title` / `description` / `channelTitle` / `tags` / `customUrl` /
  //     `keywords` — uploader-controlled free-text; highest prompt-injection
  //     surface among uploader fields.
  //   - `textDisplay` / `textOriginal` — comment body; wholly attacker-
  //     controlled by ANY YouTube viewer worldwide. MUST wrap.
  //   - `authorDisplayName` / `authorChannelUrl` / `authorProfileImageUrl` —
  //     attacker-controllable (display name + URL fields are craftable
  //     vanity redirects). MUST wrap; do NOT special-case URLs.
  //   - `country` — closed enum per spec BUT Google has historically returned
  //     undocumented variants (custom country / sub-country / `"ZZ"`); WRAP
  //     defense-in-depth. Asymmetry vs v1.13 strictly-closed enums is
  //     INTENTIONAL — `country` has documented variance.
  //   - `url` (under `thumbnails.*.url`) — Google CDN URL but conservative
  //     WRAP. Cross-API invariant: bare `url` MUST NEVER enter SKIP_FIELDS
  //     because YouTube `thumbnails.*.url`, future APIs' `url` keys, would
  //     all silently unwrap on one config change. Drive `webViewLink` /
  //     Calendar `htmlLink` are DIFFERENT key names; the bare-`url` ABSENCE
  //     test treats this as a project-wide guard.
  "videoId", "channelId", "playlistId", "subscriptionId", "commentId",
  "authorChannelId", "liveBroadcastContent",
  "privacyStatus", "uploadStatus", "license",
  // v1.19 Phase 1b — Google Tasks API opaque metadata. See
  // docs/v1.19-tasks-api.md §5. Cross-API SKIP keys already cover `id` /
  // `etag` / `kind` / `nextPageToken` / `webViewLink` / `updated*` timestamp
  // suffix patterns. The keys below are NEW to v1.19 — either Google-
  // controlled opaque (API URL) OR closed/opaque sort key the caller cannot
  // meaningfully extend via the API.
  //
  //   `selfLink` — opaque Google API URL pointing back to the resource
  //     (e.g., "https://www.googleapis.com/tasks/v1/lists/MTk5MTI...").
  //     Same rationale as Calendar `htmlLink` / People `resourceName`:
  //     identifier-only, never user-supplied free text. Wrapping it would
  //     block any future programmatic dereference.
  //   `position` — opaque sort key (large integer-as-string like
  //     "00000000003626655418") used by Google to order tasks within a list.
  //     Same rationale as Calendar `recurringEventId` / People `resourceName`:
  //     Google-controlled, not user-influenced text. Caller cannot set this
  //     directly (positioning is via `previous` field — Phase 4+ scope).
  //
  // INTENTIONALLY NOT added (per docs/v1.19-tasks-api.md §5 ABSENCE sentinels):
  //   - `title` — user-typed task title. HIGHEST prompt-injection surface
  //     on the Task resource (free-form text shown verbatim to Claude).
  //   - `notes` — user-typed task notes (multi-line free text). Same.
  //   - `due` — user-supplied RFC 3339 datetime. While the FORMAT is closed,
  //     the VALUE is wholly user-controlled; the FORMAT is enforced server-
  //     side by Google. Wrapping it costs nothing and maintains uniformity.
  //   - `links[*].description` / `links[*].link` / `links[*].type` —
  //     free-text array embedded in tasks (rare; design §2.5 rejects on
  //     write per allowlist). MUST wrap.
  //   - `completed` (timestamp string, server-controlled when status flips)
  //     — already wrapped via tree-walk; deliberately NOT in SKIP_FIELDS to
  //     keep the primitive-string surface uniform with other Workspace APIs.
  "selfLink", "position",
  // v1.20 Phase 1b-1 — Google Sheets API opaque metadata. See
  // docs/v1.20-sheets-api.md §6. Cross-API SKIP keys already cover `id` /
  // `etag` / `kind` / `nextPageToken`. The keys below are NEW to v1.20 —
  // either Google-controlled opaque IDs OR closed enums the caller cannot
  // extend via the API.
  //
  //   `spreadsheetId` — opaque Drive file ID (40-100 chars). Identifier-only,
  //     never user-supplied free text. Wrapping it would block
  //     `sheets_get_metadata({spreadsheet_id})` follow-up calls from using
  //     the value programmatically. Cross-referenced via Drive — same opaque
  //     class as Drive `fileId` / Gmail `messageId`.
  //   `sheetId` — opaque numeric tab ID (e.g., 0 / 1234567890). Server-
  //     assigned per-sheet identifier (NOT user-editable). Per primitive-only
  //     invariant: Sheets API returns this as INTEGER, but downstream Sheets
  //     APIs (e.g., batchUpdate request targeting) accept the value in both
  //     numeric AND string forms — the walker only wraps `typeof === "string"`
  //     so numerics pass through anyway; listing here defends defense-in-depth
  //     against any future API revision that surfaces the value as a string.
  //   `dataSourceId` — opaque external-data-source ID (BigQuery / Looker
  //     connection). Same rationale as `spreadsheetId`.
  //   `developerMetadataId` — opaque programmatic-app metadata ID. Same.
  //   `dimensionGroupId` — opaque row/column group ID. Same.
  //   `bandedRangeId` — opaque alternating-format range ID. Same.
  //   `conditionalFormatRuleId` — opaque per-rule ID. Same.
  //   `chartId` — opaque embedded chart ID. Same.
  //   `filterId` — opaque filter view ID. Same.
  //   `protectedRangeId` — opaque per-protection ID. Same.
  //   `dataSourceTableId` — opaque external-table ID. Same.
  //   `namedRangeId` — opaque named-range ID. Same.
  //
  // INTENTIONALLY NOT added (per docs/v1.20-sheets-api.md §6 ABSENCE sentinels):
  //   - `title` — user-typed spreadsheet title + per-sheet tab title. Already
  //     covered by the cross-API uploader-display invariant (`title` ABSENCE
  //     since v1.16 Phase 1b).
  //   - `value` — cell content (per-cell `userEnteredValue` etc.). CROSS-API
  //     invariant — same `value` key protects Calendar `extendedProperties[].value`,
  //     Drive `properties.value`, Gmail header `value`, People
  //     `emailAddresses[].value`. Adding here would unwrap user-controllable
  //     strings across 5 APIs.
  //   - `formattedValue` — rendered cell value (the display form of a cell).
  //     Highest user-visible surface in `sheets_get_values` responses.
  //   - `note` — per-cell note (the "comment on cell" feature; multi-line free text).
  //   - `text` — structured text run content (cells with rich-text formatting
  //     expose this).
  //   - `description` — named-range description / data-source description.
  //     Cross-API: also Tasks `links[*].description`.
  //   - `customSubtotalCalculationFormula` — user-supplied formula string;
  //     MUST wrap to prevent injection-via-display.
  //
  // Closed-enum SKIPs that overlap with cross-API set:
  //   - `sheetType` (closed enum: GRID / OBJECT / DATA_SOURCE) — defer to
  //     primitive-only walker semantics; small-keyspace string but the
  //     primitive-string surface is uniform across Workspace APIs so we DO
  //     NOT add it here (mirrors `completed` decision in v1.19 Phase 1b §6).
  //   - `majorDimension` (closed enum: ROWS / COLUMNS) — same. Phase 1
  //     hard-codes `majorDimension: "ROWS"` on the handler side anyway
  //     (sec-rev hook #3).
  "spreadsheetId", "sheetId",
  "dataSourceId", "developerMetadataId", "dimensionGroupId",
  "bandedRangeId", "conditionalFormatRuleId", "chartId",
  "filterId", "protectedRangeId", "dataSourceTableId", "namedRangeId",
  // v1.20 Phase 1b-2 — `spreadsheetUrl` carry-forward M1 from Phase 1b-1.
  //   Server-assigned Google-controlled URL (formatted as
  //   `https://docs.google.com/spreadsheets/d/<spreadsheet_id>/edit`).
  //   Identifier-only — never user-supplied free text. Wrapping it would
  //   block downstream callers (e.g., share-link copy / browser-open) from
  //   using the URL programmatically. Mirrors Calendar `htmlLink` /
  //   `hangoutLink` SKIP_FIELDS rationale — opaque server-assigned URL
  //   class. Returned by both `sheets_create` and `sheets_get_metadata`.
  "spreadsheetUrl",
]);
