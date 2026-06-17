import { describe, expect, test } from "bun:test";
import {
  CONFUSABLES,
  detectCredentialLure,
  PATTERNS,
  SKIP_FIELDS,
  TRUNCATE_MARKER,
  TRUNCATE_THRESHOLD,
  ZERO_WIDTH_RE,
} from "./patterns";

describe("detectCredentialLure — F3 inbound lure flag (v1.56)", () => {
  test("the motivating case: 'recovery contact' + a foreign email → lure", () => {
    expect(
      detectCredentialLure(
        "Someone added dmitrisorvanov9@mail.ru as your recovery contact. If this wasn't you, secure your account.",
      ),
    ).toBe(true);
  });

  test("zh-TW: 備援聯絡人 + 外部 email → lure", () => {
    expect(detectCredentialLure("有人把 attacker@mail.ru 加成你的備援聯絡人")).toBe(true);
  });

  test("lure keyword + a NON-Google link → lure", () => {
    expect(
      detectCredentialLure("Enter your verification code at https://accounts-google.evil.com/verify"),
    ).toBe(true);
  });

  test("lure keyword ALONE (no risk token) → NOT a lure", () => {
    expect(detectCredentialLure("Your verification code is below.")).toBe(false);
  });

  test("a risk token ALONE (no lure keyword) → NOT a lure", () => {
    expect(detectCredentialLure("Reach me at someone@evil.ru or https://evil.com")).toBe(false);
  });

  test("genuine Google notice: lure keyword + a google.com link → NOT flagged (excluded host)", () => {
    expect(
      detectCredentialLure("Secure your account: https://myaccount.google.com/security"),
    ).toBe(false);
  });

  test("lure keyword + only a gmail.com address → NOT flagged (Google email domain excluded)", () => {
    expect(
      detectCredentialLure("Verify your account; we emailed you.user@gmail.com"),
    ).toBe(false);
  });

  test("sub.google.com is treated as a Google property (suffix anchor), evil-google.com is NOT", () => {
    expect(detectCredentialLure("verify your account at https://sites.google.com/x")).toBe(false);
    expect(detectCredentialLure("verify your account at https://evil-google.com/x")).toBe(true);
  });

  test("'2fa' word-boundary keyword + foreign address → lure", () => {
    expect(detectCredentialLure("Disable 2FA by mailing reset@takeover.ru")).toBe(true);
  });

  test("empty string → NOT a lure (no keyword)", () => {
    expect(detectCredentialLure("")).toBe(false);
  });

  test("deterministic across repeated calls (no stateful-regex drift)", () => {
    const s = "secure your account via https://evil.example/x";
    expect(detectCredentialLure(s)).toBe(true);
    expect(detectCredentialLure(s)).toBe(true);
    expect(detectCredentialLure(s)).toBe(true);
  });
});

describe("PATTERNS", () => {
  test("every entry has a unique id", () => {
    const ids = PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("contains the 8 expected pattern ids", () => {
    expect(PATTERNS.map((p) => p.id).sort()).toEqual([
      "bearer-token",
      "data-url-base64",
      "ignore-prev",
      "new-instructions",
      "oauth-code",
      "role-hijack",
      "system-prompt-injection",
      "unicode-tag",
    ]);
  });

  test("every regex is pre-compiled (RegExp instance)", () => {
    for (const p of PATTERNS) {
      expect(p.re).toBeInstanceOf(RegExp);
    }
  });

  test("data-url-base64 regex caps MIME type to avoid unbounded scan", () => {
    const pattern = PATTERNS.find((p) => p.id === "data-url-base64");
    expect(pattern?.re.source).toContain("{1,200}");
  });
});

describe("CONFUSABLES", () => {
  test("all keys are non-ASCII characters", () => {
    for (const key of CONFUSABLES.keys()) {
      expect(key.charCodeAt(0)).toBeGreaterThan(127);
    }
  });

  test("all values are single-codepoint ASCII Latin letters", () => {
    for (const value of CONFUSABLES.values()) {
      expect(value.length).toBe(1);
      const code = value.charCodeAt(0);
      const isLatin =
        (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
      expect(isLatin).toBe(true);
    }
  });

  test("includes the canonical Cyrillic 'і' (U+0456) → Latin 'i' mapping", () => {
    expect(CONFUSABLES.get("і")).toBe("i");
  });

  test("includes the canonical Greek 'α' (U+03B1) → Latin 'a' mapping", () => {
    expect(CONFUSABLES.get("α")).toBe("a");
  });
});

describe("SKIP_FIELDS", () => {
  test("contains the core opaque ID fields", () => {
    for (const key of ["id", "threadId", "historyId", "fileId", "messageId"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("contains common Workspace timestamp suffix patterns", () => {
    for (const key of ["createdAt", "updatedAt", "modifiedTime", "internalDate"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("does NOT contain user-visible content fields", () => {
    for (const key of ["subject", "snippet", "body", "from", "to", "name", "title"]) {
      expect(SKIP_FIELDS.has(key)).toBe(false);
    }
  });

  test("contains pagination cursors + opaque structural fields (Step 3 E2E regression)", () => {
    for (const key of ["nextPageToken", "pageToken", "nextSyncToken", "etag", "kind"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("contains Gmail MIME part identifiers (5.1 sec-review pre-emptive)", () => {
    for (const key of ["partId", "attachmentId"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("contains Drive `parents` folder-ID array (5.2 regression)", () => {
    expect(SKIP_FIELDS.has("parents")).toBe(true);
  });

  test("does NOT contain Drive `owners` / `lastModifyingUser` (those embed user content)", () => {
    expect(SKIP_FIELDS.has("owners")).toBe(false);
    expect(SKIP_FIELDS.has("lastModifyingUser")).toBe(false);
  });

  test("v1.12 Phase 1b — contains Docs API opaque keys (objectId / revisionId / inheritedNamedStyleType)", () => {
    for (const key of ["objectId", "revisionId", "inheritedNamedStyleType"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.12 Phase 1b — does NOT add numeric Docs fields (startIndex / endIndex) — sanitize only wraps string leaves", () => {
    // Per code-rev M1 in docs/v1.12-docs-api.md §5: startIndex/endIndex are
    // `number`, and sanitize/index.ts only wraps `typeof v === "string"`.
    // Adding them would be cosmetic / misleading.
    expect(SKIP_FIELDS.has("startIndex")).toBe(false);
    expect(SKIP_FIELDS.has("endIndex")).toBe(false);
  });

  test("v1.13 Phase 1b — contains Calendar API opaque keys (iCalUID / htmlLink / hangoutLink / recurringEventId)", () => {
    // Google-controlled opaque identifiers / URLs. See docs/v1.13-calendar-api.md §5.
    for (const key of ["iCalUID", "htmlLink", "hangoutLink", "recurringEventId"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.13 Phase 1b — contains Calendar API closed-enum keys (status / transparency / visibility / eventType)", () => {
    // Caller cannot extend these enums via the Calendar API. Wrapping them
    // would block downstream programmatic comparison (e.g., "is this event
    // status=='cancelled'?") without adding security value.
    for (const key of ["status", "transparency", "visibility", "eventType"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.13 Phase 1b — `etag` already covered by the cross-API set (not re-added per-API)", () => {
    // `etag` was added in the early cross-API SKIP_FIELDS block (pagination
    // cursors + opaque structural fields). Calendar uses it too, but the
    // single entry covers all APIs. Sentinel ensures no duplicate slipped in.
    expect(SKIP_FIELDS.has("etag")).toBe(true);
  });

  test("v1.13 Phase 1b — does NOT add `originalStartTime` (object value violates primitive-only invariant)", () => {
    // Per docs/v1.13-calendar-api.md §5 + PR #113 L1: `originalStartTime` is
    // an OBJECT (`{dateTime, date, timeZone}`), not a primitive. The SKIP_FIELDS
    // invariant requires values to be primitives or arrays of primitives —
    // adding an object key would propagate `inSkip=true` to its descendants
    // (timezone, datetime strings) and emit them unwrapped, RE-INTRODUCING
    // an injection surface. The walker handles `originalStartTime`'s
    // primitive children naturally; no SKIP_FIELDS entry needed.
    //
    // Sentinel: if someone accidentally adds it to SKIP_FIELDS in the future,
    // this test fails, forcing the change to be reviewed against the invariant.
    expect(SKIP_FIELDS.has("originalStartTime")).toBe(false);
  });

  test("v1.13 Phase 1b — does NOT add `conferenceData` / `attachments` (tree-walk handles uniformly)", () => {
    // Per docs/v1.13-calendar-api.md §5 + PR #113 M2: these are TOP-LEVEL
    // objects whose children include user-visible strings (entryPoints[].label,
    // attachments[].title). Adding them to SKIP_FIELDS would un-wrap user-
    // visible labels — exactly the wrong behavior. The tree-walker handles
    // the wrap-all-string-leaves contract uniformly.
    //
    // Sentinel: same regression-guard rationale as originalStartTime above.
    expect(SKIP_FIELDS.has("conferenceData")).toBe(false);
    expect(SKIP_FIELDS.has("attachments")).toBe(false);
  });

  test("v1.13 Phase 1b — does NOT add Calendar user-visible content fields (summary / description / location)", () => {
    // Defense-in-depth: these are the most attacker-controllable fields on
    // a Calendar event (anyone who can send the user a calendar invite can
    // populate them). They MUST remain wrapped via the default tree-walk.
    for (const key of ["summary", "description", "location"]) {
      expect(SKIP_FIELDS.has(key)).toBe(false);
    }
  });

  test("v1.15 Phase 1b — contains People (Contacts) API opaque key + closed enum (resourceName / objectType)", () => {
    // Google-controlled opaque identifier + closed enum. See
    // docs/v1.15-contacts-api.md §6. Each key is either Google-controlled
    // opaque (resource handle) or a closed enum the caller cannot extend
    // via the API — wrapping them would block downstream programmatic use
    // (`contacts_get({ resource_name })`, `objectType === "PERSON"`).
    for (const key of ["resourceName", "objectType"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.15 Phase 1b — does NOT add user-controllable Person fields (ABSENCE sentinel, sec-rev hook #7)", () => {
    // Per docs/v1.15-contacts-api.md §6 + §11 hook #7 — these are the
    // user-typed (or third-party-imported) content surfaces on a Person
    // resource. They MUST remain wrapped via the default tree-walk.
    //
    // Sentinel: a future "tidying" PR that accidentally adds any of these
    // to SKIP_FIELDS would silently un-wrap user-controllable content,
    // re-introducing an injection surface. Mirror v1.12 + v1.13 patterns.
    const forbidden = [
      "displayName",     // names[*].displayName (also Calendar attendees[*].displayName)
      "givenName",       // names[*].givenName
      "familyName",      // names[*].familyName
      "value",           // emailAddresses[*].value, phoneNumbers[*].value, urls[*].value,
                         //   userDefined[*].value, biographies[*].value — CROSS-API invariant
      "formattedValue",  // addresses[*].formattedValue
      "biographies",     // top-level biographies array — bio free-text
      "organizations",   // top-level organizations array — org name / title / department
      "title",           // organizations[*].title
      "department",      // organizations[*].department
    ];
    for (const k of forbidden) {
      expect(SKIP_FIELDS.has(k)).toBe(false);
    }
  });

  test("v1.15 Phase 1b — `value` ABSENCE is a project-wide cross-API invariant (Person / Calendar / Drive / Gmail)", () => {
    // Per docs/v1.15-contacts-api.md §6 "Cross-API invariant" — `value`
    // appears under Person `emailAddresses[].value` / `phoneNumbers[].value`,
    // Calendar `extendedProperties[*].value`, Drive `properties.value`,
    // Gmail header `value`. Adding `value` to SKIP_FIELDS would silently
    // unwrap user-controllable strings across 4 Google APIs simultaneously.
    //
    // This test exists as a dedicated guard so the cross-API rationale is
    // visible to any future contributor who looks at "why isn't `value`
    // skipped, surely it's an opaque key like `id`?".
    expect(SKIP_FIELDS.has("value")).toBe(false);
  });

  test("v1.15 Phase 1b — `id` / `etag` / `kind` / `nextPageToken` already covered by cross-API set (not re-added per-API)", () => {
    // The four "shared opaque" keys were added in the early cross-API
    // SKIP_FIELDS blocks (lines ~112-128). v1.15 People API uses all four
    // (e.g., metadata.sources[*].id, metadata.sources[*].etag), but the
    // single entries cover all APIs. Sentinel ensures no duplicates slipped
    // in via the v1.15 Phase 1b block.
    for (const key of ["id", "etag", "kind", "nextPageToken"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.16 Phase 1b — contains YouTube Data API opaque keys (videoId / channelId / playlistId / subscriptionId / commentId / authorChannelId)", () => {
    // YouTube programmatic identifiers — opaque, server-assigned, never
    // user-supplied free text. Wrapping them blocks Claude from using the
    // value as a follow-up tool input (`youtube_video_get({video_id})`,
    // etc.). See docs/v1.16-youtube-api.md §6.
    for (const key of [
      "videoId",
      "channelId",
      "playlistId",
      "subscriptionId",
      "commentId",
      "authorChannelId",
    ]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.16 Phase 1b — contains YouTube closed-enum keys (liveBroadcastContent / privacyStatus / uploadStatus / license)", () => {
    // Closed enums per YouTube API spec. Caller cannot extend via the API.
    // Same rationale as Calendar's `status` / `transparency` / `eventType`.
    // Wrapping blocks programmatic comparison (`privacyStatus === "public"`).
    for (const key of [
      "liveBroadcastContent",
      "privacyStatus",
      "uploadStatus",
      "license",
    ]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.16 Phase 1b — does NOT add user-controllable YouTube fields (ABSENCE sentinel, sec-rev hook #2)", () => {
    // Per docs/v1.16-youtube-api.md §6 + §11 hook #2 — these are the
    // attacker-controlled UGC surfaces on a YouTube response. They MUST
    // remain wrapped via the default tree-walk.
    //
    // Sentinel: catches a future "tidying" PR that accidentally adds any
    // of these to SKIP_FIELDS — would silently unwrap user-controllable
    // content and re-introduce an injection surface. Mirror v1.12 / v1.13 /
    // v1.15 patterns.
    const forbidden = [
      // Video / playlist / channel uploader-controlled display
      "title",          // video / playlist / channel title
      "description",    // video / playlist / channel description (multi-line free text)
      "channelTitle",   // channel display name (NOT channelId, which IS skipped)
      "tags",           // video tags array (free text)
      "customUrl",      // channel custom URL
      "keywords",       // channel branding keywords
      "country",        // closed-enum-per-spec BUT has documented variance — WRAP
      // Comment UGC — HIGHEST priority; comments are public attacker-controlled UGC
      "textDisplay",        // formatted comment text
      "textOriginal",       // raw comment text
      "authorDisplayName",  // commenter display name
      "authorChannelUrl",   // commenter channel URL (vanity-redirect surface)
      "authorProfileImageUrl",  // commenter avatar URL (same)
      // Thumbnail / video URLs (defense-in-depth; Google CDN but conservative)
      "url",
    ];
    for (const k of forbidden) {
      expect(SKIP_FIELDS.has(k)).toBe(false);
    }
  });

  test("v1.16 Phase 1b — bare `url` ABSENCE is a project-wide cross-API invariant (YouTube thumbnails + future APIs)", () => {
    // Per docs/v1.16-youtube-api.md §6 "Cross-API invariant for `url`":
    // YouTube `thumbnails.maxres.url` AND any future Google API that uses
    // `url` as a key name would silently unwrap if bare `url` entered
    // SKIP_FIELDS. Drive `webViewLink` and Calendar `htmlLink` are
    // DIFFERENT key names (different SKIP_FIELDS entries) — they don't
    // share `url`. Adding bare `url` to SKIP_FIELDS would silently unwrap
    // user-controllable URL strings across multiple APIs in one config
    // change.
    //
    // This dedicated test exists so the rationale stays visible to any
    // future contributor who looks at "surely `url` is opaque, like `id`?".
    expect(SKIP_FIELDS.has("url")).toBe(false);
  });

  test("v1.16 Phase 1b — `title` ABSENCE protects Docs / YouTube + the cross-API uploader-display invariant", () => {
    // `title` appears in Docs (`documents.title`), YouTube (snippet.title
    // everywhere). Drive uses `name` and Calendar uses `summary` (different
    // keys, but same role). All MUST wrap. The ABSENCE sentinel locks the
    // `title` key across the project — adding it to SKIP_FIELDS would
    // unwrap user-controllable display strings in Docs + YouTube
    // simultaneously.
    //
    // v1.19 Phase 1b update: `title` is ALSO the primary user-typed field on
    // a Google Tasks Task resource. Same ABSENCE-sentinel logic — adding
    // `title` would unwrap Tasks alongside Docs + YouTube in one config
    // change. Cross-API invariant remains.
    expect(SKIP_FIELDS.has("title")).toBe(false);
  });

  test("v1.19 Phase 1b — contains Google Tasks API opaque keys (selfLink / position)", () => {
    // Google-controlled opaque identifiers. See docs/v1.19-tasks-api.md §5.
    //   - `selfLink` — opaque Google API URL pointing back to the resource;
    //     same rationale as Calendar `htmlLink` / People `resourceName`.
    //   - `position` — opaque large-integer-as-string sort key; same
    //     rationale as Calendar `recurringEventId` (Google-controlled, not
    //     user-influenced text).
    for (const key of ["selfLink", "position"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.19 Phase 1b — does NOT add user-controllable Task fields (ABSENCE sentinel, design §5)", () => {
    // Per docs/v1.19-tasks-api.md §5 — these are the user-typed (or third-
    // party-imported) content surfaces on a Task resource. They MUST remain
    // wrapped via the default tree-walk.
    //
    // Sentinel: a future "tidying" PR that accidentally adds any of these
    // to SKIP_FIELDS would silently un-wrap user-controllable content,
    // re-introducing an injection surface. Mirror v1.12 / v1.13 / v1.15 /
    // v1.16 patterns. `title` is also covered by the cross-API uploader-
    // display invariant above (Docs / YouTube / Tasks).
    const forbidden = [
      "title",          // task title — primary user-typed field
      "notes",          // task notes — multi-line free text
      "due",            // user-supplied RFC 3339 datetime (value is user-controlled)
      "link",           // links[*].link — free-text URL embedded in task
      "description",    // links[*].description — free-text label
    ];
    for (const k of forbidden) {
      expect(SKIP_FIELDS.has(k)).toBe(false);
    }
  });

  test("v1.19 Phase 1b — `id` / `etag` / `kind` / `nextPageToken` / `webViewLink` already covered by cross-API set (not re-added per-API)", () => {
    // The five "shared opaque" keys were added in the early cross-API
    // SKIP_FIELDS blocks. v1.19 Tasks API uses all five (e.g., `id` on
    // every task / tasklist; `etag` / `kind` on every response;
    // `nextPageToken` on `tasks.list`; `webViewLink` on individual tasks
    // since 2024). The single entries cover all APIs. Sentinel ensures no
    // duplicates slipped in via the v1.19 Phase 1b block.
    for (const key of ["id", "etag", "kind", "nextPageToken", "webViewLink"]) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.20 Phase 1b-1 + 1b-2 — contains Google Sheets API opaque IDs (13 NEW keys)", () => {
    // Google-controlled opaque identifiers per docs/v1.20-sheets-api.md §6.
    // 12 NEW keys from Phase 1b-1 + 1 (spreadsheetUrl) deferred to Phase
    // 1b-2 carry-forward M1. `id` / `etag` / `kind` / `nextPageToken`
    // already covered by the cross-API block above. `sheetType` /
    // `majorDimension` (closed enums) deferred to primitive-only walker
    // semantics per the v1.19 `completed` decision precedent.
    const sheetsOpaqueKeys = [
      "spreadsheetId",
      "sheetId",
      "dataSourceId",
      "developerMetadataId",
      "dimensionGroupId",
      "bandedRangeId",
      "conditionalFormatRuleId",
      "chartId",
      "filterId",
      "protectedRangeId",
      "dataSourceTableId",
      "namedRangeId",
      // v1.20 Phase 1b-2 — server-assigned URL (mirrors Calendar `htmlLink`).
      "spreadsheetUrl",
    ];
    expect(sheetsOpaqueKeys.length).toBe(13);
    for (const key of sheetsOpaqueKeys) {
      expect(SKIP_FIELDS.has(key)).toBe(true);
    }
  });

  test("v1.20 Phase 1b-1 — does NOT add user-controllable Sheets fields (ABSENCE sentinel, design §6)", () => {
    // Per docs/v1.20-sheets-api.md §6 — these are the user-controllable
    // content surfaces on a Sheets resource. They MUST remain wrapped via
    // the default tree-walk.
    //
    // Sentinel: a future "tidying" PR that accidentally adds any of these
    // to SKIP_FIELDS would silently un-wrap user-controllable content,
    // re-introducing an injection surface. Mirror v1.12 / v1.13 / v1.15 /
    // v1.16 / v1.19 patterns.
    //
    //   `title` — already covered by cross-API uploader-display invariant
    //     (Docs / YouTube / Tasks / Sheets).
    //   `value` — already covered by cross-API invariant (Calendar / Drive /
    //     Gmail / People / Sheets cell content).
    //   `formattedValue` — NEW for Sheets (rendered cell value; highest
    //     user-visible surface on `sheets_get_values` responses).
    //   `note` — NEW for Sheets (per-cell comment / annotation).
    //   `text` — NEW for Sheets (structured text-run content).
    //   `description` — already covered by Tasks `links[*].description`;
    //     Sheets `namedRanges[*].description` reuses the same key shape.
    //   `customSubtotalCalculationFormula` — NEW for Sheets (user-supplied
    //     formula string in pivot-table custom subtotals; MUST wrap to
    //     prevent injection-via-display).
    const forbidden = [
      "title",
      "value",
      "formattedValue",
      "note",
      "text",
      "description",
      "customSubtotalCalculationFormula",
    ];
    expect(forbidden.length).toBe(7);
    for (const k of forbidden) {
      expect(SKIP_FIELDS.has(k)).toBe(false);
    }
  });
});

describe("constants", () => {
  test("ZERO_WIDTH_RE matches all six covered invisible chars", () => {
    expect("­".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // SOFT HYPHEN (M1)
    expect("​".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // ZWSP
    expect("‌".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // ZWNJ
    expect("‍".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // ZWJ
    expect("⁠".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // WORD JOINER
    expect("﻿".replace(ZERO_WIDTH_RE, "X")).toBe("X"); // BOM
  });

  test("ZERO_WIDTH_RE leaves normal ASCII untouched", () => {
    expect("hello world".replace(ZERO_WIDTH_RE, "X")).toBe("hello world");
  });

  test("TRUNCATE_THRESHOLD is 50_000", () => {
    expect(TRUNCATE_THRESHOLD).toBe(50_000);
  });

  test("TRUNCATE_MARKER is distinct from <untrusted-source> prefix", () => {
    expect(TRUNCATE_MARKER.startsWith("<untrusted-source")).toBe(false);
    expect(TRUNCATE_MARKER).toBe("<safespace-truncated/>");
  });
});
