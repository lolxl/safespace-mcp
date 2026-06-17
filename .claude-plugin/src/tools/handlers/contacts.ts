// Contacts / People — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { peopleClientFromToken } from "../../google-api/client";
import { mapGoogleError, toGoogleError } from "../../google-api/errors";
import { isContactLookupEnabled } from "../../policy/contact-lookup";
import * as crypto from "node:crypto";
import type { ToolContext } from "../types";

import { requireGoogle, EMAIL_RECIPIENT_RE } from "./shared";

/** Per-process Set<account_email> of accounts whose People API cache has been
 * warmed in this process lifetime. Keyed by email (per-account-isolated; see
 * sec-rev hook #12). Subsequent calls for the same account skip the warming
 * dance.
 *
 * Module-level singleton intentionally — proxy lifetime = single MCP session
 * = single Claude conversation. Resetting per-call would defeat the purpose. */
const peopleWarmedAccounts = new Set<string>();

/** Per-process singleflight Map for in-flight warming Promises, keyed by
 * account email. Prevents two concurrent first-calls for the same (process,
 * account) from BOTH issuing the empty-query SDK call + BOTH `await sleep(3000)`
 * — which would burn 2x quota + 6s aggregate wall-clock. Phase 3 will amplify
 * this race surface (to/cc/bcc lookups dispatched in parallel from gmail_send).
 *
 * Map populated BEFORE the first await inside `warmPeopleCache` so concurrent
 * callers join the same Promise instead of double-warming. Entry deleted in
 * `finally` regardless of success/failure: on failure the Set stays empty so
 * the next call retries the full ceremony; on success the Set has the email
 * so subsequent calls take the fast path. */
const peopleWarmingInFlight = new Map<string, Promise<void>>();

/** Fixed sleep duration after the warming empty-query call. Locked at 3000ms
 * per design §4 "Warming-call shape (locked)". Phase 1b probe may PR a tuned
 * value with empirical evidence; for now, do NOT change without re-evaluating
 * the warming-call shape contract.
 *
 * Sec-rev hook #1: unconditional — do NOT short-circuit even if Google
 * appears to respond fast. Timing variance from caller perspective MUST be
 * constant on cold path. */
const PEOPLE_WARM_SLEEP_MS = 3000;

/** Internal helper exposed for tests to reset cache-warming state between
 * test cases. NOT exported in the production tool surface — exclusively for
 * `handlers.test.ts` (cache-warming sentinel tests #warm-1..#warm-6) to
 * validate warm-once + cross-account isolation + concurrent singleflight.
 *
 * Runtime-guarded against accidental production invocation (code-M1 / sec-L1).
 * Bun's `bun test` sets `NODE_ENV=test` automatically; if you ever run this
 * helper outside the test runner you'll see the guard throw.
 *
 * Clears BOTH `peopleWarmedAccounts` (Set of warmed-account emails) AND
 * `peopleWarmingInFlight` (Map of in-flight singleflight Promises) so a
 * test starting cold doesn't inherit either piece of state. */
export function __resetPeopleWarmingForTest(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetPeopleWarmingForTest is for tests only");
  }
  peopleWarmedAccounts.clear();
  peopleWarmingInFlight.clear();
}

/** @deprecated Renamed to `__resetPeopleWarmingForTest` (now clears the
 * singleflight Map too). Kept as alias for any in-flight references; remove
 * after PR #127 patch lands. */
export const __resetPeopleWarmedAccountsForTest = __resetPeopleWarmingForTest;

/** People API resource_name format gate (design §4).
 *
 *   - Literal prefix `people/c`.
 *   - Decimal digits, 1-32 chars (max bounded as defense-in-depth against
 *     10MB-string DoS; Google's actual IDs are ~20 digits).
 *
 * Rejects path traversal (`people/../etc`), CRLF injection (`people/c1\n`),
 * non-numeric IDs, and any prefix other than the literal `people/c`.
 * Sec-rev hook #11: validated BEFORE the SDK sees the input so a malformed
 * value cannot reach the URL path and produce an opaque 400/404. */
const PEOPLE_RESOURCE_NAME_RE = /^people\/c[0-9]{1,32}$/;

/** Hard upper bound on `max_results` for contacts_search. Anti-DoS + anti-
 * context-flood — design §4: clamp 30 is intentionally lower than Gmail
 * (50) / Drive (100). A 30-result contact lookup already implies the query
 * is too broad. */
const CONTACTS_SEARCH_MAX_RESULTS_CAP = 30;
const CONTACTS_SEARCH_DEFAULT_MAX_RESULTS = 10;

/** readMask passed to `people.searchContacts` for `contacts_search`. Locked
 * to the design's user-visible-field allowlist (design §4 + §6). Sanitize
 * wraps every string leaf naturally; opaque Google keys (`resourceName` /
 * `objectType`) are in SKIP_FIELDS. */
const CONTACTS_SEARCH_READ_MASK =
  "names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses";

/** readMask for `contacts_lookup_email` — narrowed to names + emails since
 * the tool only surfaces display_name + email_addresses in its response
 * shape. Narrower readMask = smaller response payload = less sanitize work
 * + less prompt-injection surface. */
const CONTACTS_LOOKUP_READ_MASK = "names,emailAddresses";

/** personFields for `contacts_get` — broader than search, since the caller
 * has explicitly requested a single contact's full detail. `birthdays` is
 * added here (not in search readMask) because per-contact birthday lookup
 * is a legitimate use-case (calendar planning); search-result birthday
 * surfaces would be context-flood. */
const CONTACTS_GET_PERSON_FIELDS =
  "names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses,birthdays";

/** Hard upper bound on `max_results` for contacts_lookup_email. Lower than
 * contacts_search (10 vs 30) because lookup is for disambiguation, not
 * browse — if >10 contacts share a name, the right path is `contacts_search`
 * with more specific criteria. Design §4. */
const CONTACTS_LOOKUP_MAX_RESULTS_CAP = 10;
const CONTACTS_LOOKUP_DEFAULT_MAX_RESULTS = 5;

/** Warm the People API cache for `email` (per-account-keyed) if not already
 * warmed in this process. First call per (process, account) tuple triggers
 * an empty-query searchContacts call + fixed PEOPLE_WARM_SLEEP_MS sleep.
 *
 * The warming call is constructed INSIDE this helper, NOT via the caller-
 * facing handler — so the empty query never re-enters the caller's input
 * validator (which rejects empty queries). Design §4 + §11 hook #1.
 *
 * Singleflight (patch H1): two concurrent first-calls for the same (process,
 * account) would otherwise both pass the `has(email)` check, both issue the
 * empty-query SDK call, both `await sleep(3000)` — burning 2x quota + 6s
 * aggregate wall-clock. Phase 3 amplifies this race surface (to/cc/bcc
 * recipient lookups dispatched in parallel from `gmail_send`). The
 * `peopleWarmingInFlight` Map seeds a shared Promise BEFORE the first await
 * so concurrent callers join it instead of double-warming.
 *
 * Warming-error attribution (patch sec-L2): if the warm SDK call throws, we
 * route through `mapGoogleError(..., { tool: "contacts_search_warm" })` so
 * audit/error logs distinguish "warming failed" from "real query failed"
 * for forensic clarity. The caller-side outer try/catch (patch H2) re-throws
 * the already-mapped MCPError untouched via `instanceof MCPError`.
 */
async function warmPeopleCache(
  email: string,
  people: ReturnType<typeof peopleClientFromToken>,
): Promise<void> {
  // Fast path: this account has already been warmed in this process.
  if (peopleWarmedAccounts.has(email)) return;

  // Singleflight: another concurrent first-call is already mid-warm. Join
  // that Promise — we get its eventual resolution OR rejection identically.
  const inFlight = peopleWarmingInFlight.get(email);
  if (inFlight) return inFlight;

  // Seed the singleflight Promise BEFORE any await. If we awaited before
  // populating the Map, a sibling first-call could race past the .get() check
  // above and both flights would proceed independently — defeating the lock.
  const promise = (async () => {
    try {
      try {
        // Empty-query warming call — bypasses the caller-facing validator
        // (which would reject empty query). Per design §4 "Warming-call
        // shape (locked)".
        await people.people.searchContacts({
          query: "",
          readMask: "names,emailAddresses",
          pageSize: 1,
        });
      } catch (err) {
        // Sec-L2: tag warming-call failures distinctly from real-query
        // failures so audit/error logs can split forensically. Outer
        // callers' `instanceof MCPError` re-throws preserve the tag.
        if (err instanceof MCPError) throw err;
        mapGoogleError(err, { tool: "contacts_search_warm", email });
      }
      await new Promise<void>((resolve) =>
        setTimeout(resolve, PEOPLE_WARM_SLEEP_MS),
      );
      // Mark warmed AFTER both calls succeed — partial-failure leaves the
      // account un-warmed so the next call re-tries the full ceremony.
      // Defense-in-depth against transient warming-call failure leading
      // to permanently-cold cache.
      peopleWarmedAccounts.add(email);
    } finally {
      // Always clear the in-flight entry, success OR failure. On failure
      // the Set stays empty so the next call re-tries; on success the
      // Set has the email so subsequent calls take the fast path above.
      peopleWarmingInFlight.delete(email);
    }
  })();

  peopleWarmingInFlight.set(email, promise);
  return promise;
}

export async function contactsSearch(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validate query — must be a non-empty trimmed string. Empty query is the
  // warming-call shape (constructed INSIDE warmPeopleCache); caller MUST NOT
  // be able to invoke the warming path via the public tool surface (would
  // bypass the per-call audit row for the warming call and produce confusing
  // 0-result responses).
  if (typeof args.query !== "string") {
    throw new Error("contacts_search: 'query' must be a string");
  }
  if (!args.query.trim()) {
    throw new Error("contacts_search requires a non-empty 'query' string");
  }
  const query = args.query;

  // Defense-in-depth: schema declares max:30 + integer, but non-conforming
  // MCP clients can slip NaN / Infinity / -Infinity past `typeof === "number"`.
  // Match v1.14 driveSearchAll's finite-and-positive guard exactly.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : CONTACTS_SEARCH_DEFAULT_MAX_RESULTS;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : CONTACTS_SEARCH_DEFAULT_MAX_RESULTS;
  const pageSize = Math.floor(Math.min(requested, CONTACTS_SEARCH_MAX_RESULTS_CAP));

  const people = peopleClientFromToken(requireGoogle(ctx).getAccessToken());

  try {
    // Patch H2: warming is INSIDE the try so warming-call failures get the
    // same error mapping path as real-query failures. sec-L2 already tagged
    // warming errors as `contacts_search_warm` inside `warmPeopleCache`;
    // the `instanceof MCPError` check below re-throws it untouched, so the
    // forensic split survives.
    await warmPeopleCache(requireGoogle(ctx).accountId, people);
    const res = await people.people.searchContacts({
      query,
      readMask: CONTACTS_SEARCH_READ_MASK,
      pageSize,
    });
    // Return shape: `{ results: [...] }` — SDK returns `{ results?: [...] }`.
    // Normalize the undefined case so callers always see an array.
    return { results: res.data.results ?? [] };
  } catch (err) {
    throw toGoogleError(err, { tool: "contacts_search", email: requireGoogle(ctx).accountId });
  }
}

export async function contactsLookupEmail(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validate `name`. Same shape as contactsSearch — string + non-empty trim.
  if (typeof args.name !== "string") {
    throw new Error("contacts_lookup_email: 'name' must be a string");
  }
  if (!args.name.trim()) {
    throw new Error("contacts_lookup_email requires a non-empty 'name' string");
  }
  const name = args.name;

  // Defense-in-depth clamp identical to contactsSearch — different cap.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : CONTACTS_LOOKUP_DEFAULT_MAX_RESULTS;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : CONTACTS_LOOKUP_DEFAULT_MAX_RESULTS;
  const pageSize = Math.floor(Math.min(requested, CONTACTS_LOOKUP_MAX_RESULTS_CAP));

  const people = peopleClientFromToken(requireGoogle(ctx).getAccessToken());

  try {
    // Patch H2 — see contactsSearch for explanation. Warming is inside the
    // try so warm-call failures get mapGoogleError-mapped (tagged
    // `contacts_search_warm`); the outer catch's `instanceof MCPError`
    // re-throw preserves the warming-specific tag.
    await warmPeopleCache(requireGoogle(ctx).accountId, people);
    const res = await people.people.searchContacts({
      query: name,
      readMask: CONTACTS_LOOKUP_READ_MASK,
      pageSize,
    });

    // Filter to results that actually have at least one email address.
    // A contact with no email cannot satisfy the lookup-for-recipient
    // use-case; surfacing them would only flood the disambiguation prompt.
    const matches = (res.data.results ?? [])
      .map((r) => r.person)
      .filter(
        (p): p is NonNullable<typeof p> =>
          p != null &&
          Array.isArray(p.emailAddresses) &&
          p.emailAddresses.length > 0,
      );

    if (matches.length === 0) {
      // 0 matches → empty result; Phase 3 will wrap this in
      // `recipient_lookup_failed` (-32022) at the gmail_send / calendar
      // call site. Phase 1b returns the shape; ambiguous: false makes the
      // caller's branching explicit.
      return { matches: [], ambiguous: false };
    }

    if (matches.length > 1) {
      // SEC-REV HOOK #6 (design §11) — LOCKED ERROR DATA SHAPE.
      // Ambiguity response MUST contain ONLY { ambiguous: true, match_count }.
      // NEVER echo display_name / email / any contact-identifying string —
      // echoing converts the rejection into a contact-enumeration oracle
      // (caller learns ALL contact emails matching the queried name).
      //
      // Claude that needs disambiguation must call `contacts_search`
      // separately (which IS audited as its own tool invocation, preserving
      // the forensic trail).
      return { ambiguous: true, match_count: matches.length };
    }

    // Exactly 1 match — return display_name + email_addresses (plaintext
    // to the caller; per-call audit row hashes via args_hash, not by
    // matched contact email).
    const p = matches[0];
    if (!p) {
      // Defensive — should be unreachable given the .length checks above.
      return { matches: [], ambiguous: false };
    }
    return {
      matches: [
        {
          display_name: p.names?.[0]?.displayName ?? null,
          email_addresses: (p.emailAddresses ?? [])
            .map((e) => e.value)
            .filter((v): v is string => typeof v === "string" && v.length > 0),
        },
      ],
      ambiguous: false,
    };
  } catch (err) {
    throw toGoogleError(err, { tool: "contacts_lookup_email", email: requireGoogle(ctx).accountId });
  }
}

export async function contactsGet(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validate resource_name — design §4 regex /^people\/c[0-9]{1,32}$/.
  // Echo the rule, NOT the bad value — same posture as calendar_get_event
  // (sec-rev §11 hook #11: error paths must not reflect user-supplied
  // content back to the caller verbatim).
  if (typeof args.resource_name !== "string") {
    throw new Error("contacts_get: 'resource_name' must be a string");
  }
  if (!PEOPLE_RESOURCE_NAME_RE.test(args.resource_name)) {
    throw new Error(
      "contacts_get: 'resource_name' must match /^people\\/c[0-9]{1,32}$/ (e.g., 'people/c1234567890123456789')",
    );
  }
  const resourceName = args.resource_name;

  // No cache-warming needed for `people.get` — only `searchContacts` is
  // affected by the search-index cold-cache quirk. `get` reads directly
  // from the contact storage layer.

  try {
    const people = peopleClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await people.people.get({
      resourceName,
      personFields: CONTACTS_GET_PERSON_FIELDS,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "contacts_get", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.50 (backlog B5) — Contacts WRITE tier ─────────
 *
 * Two tools on the full `contacts` scope (min_tier=write):
 *   - contacts_create → people.createContact
 *   - contacts_update → people.updateContact (read-modify-write; requires the
 *     contact's current `etag` for optimistic concurrency)
 *
 * NO contacts_delete — People API delete is PERMANENT (no trash) and is
 * deferred to its own sec-rev cycle (v1.15 §13 / personal-complete-plan lock).
 *
 * SECURITY MODEL (docs/v1.50-contacts-write.md §2-4, inheriting v1.15 §9):
 *
 *   1. ALLOWLIST construction — the handler builds the People `Person` body
 *      field-by-field from a fixed ALLOWED set; ANY top-level field outside
 *      that set is REJECTED (the NEGATIVE-sentinel enforcement — covers
 *      photos/metadata/externalIds/relations/… generically). Forbidden fields
 *      can never reach the SDK because the body is constructed, not passed
 *      through.
 *   2. Per-field leaf-property allowlist — each allowed array item is rebuilt
 *      from a fixed property set, so a smuggled nested key (e.g.
 *      names[*].metadata) is likewise rejected, never copied.
 *   3. Free-text byte caps — biographies.value ≤2048, urls.value ≤512,
 *      userDefined.value ≤512, all other string leaves ≤1024 (DoS guard).
 *   4. urls[*].value URL-scheme allowlist — http/https/mailto ONLY (defense
 *      against javascript:/data:/file: payloads stored then surfaced by a
 *      future user-visible field). Parse via new URL(); reject parse failure.
 *   5. Tier defense-in-depth — registry min_tier="write" hides these at
 *      tier=read; the handler re-checks ctx.tier as belt-and-suspenders
 *      (mirrors the youtube/tasks write handlers).
 *
 * NO new audit channel — create/update are non-destructive (create adds;
 * update is recoverable via re-update; no permanent delete), so the standard
 * auditEnd() row (tool name + args_hash) suffices, matching v1.15 §8 + the
 * v1.46 drive-write precedent. NO new error code — field validation is plain
 * Error, scope/tier denial reuses scope_mismatch. NO allowlist gate — contacts
 * are private (not a public-blast surface like YouTube comments), and any email
 * later resolved into gmail_send STILL passes isRecipientAllowed (the output
 * gate; v1.15 §14 trust boundary). */

/** Top-level Person fields accepted by contacts_create / contacts_update.
 * Exactly the v1.15 §9 ALLOWED set. Any other top-level field is rejected —
 * this IS the NEGATIVE sentinel (photos/metadata/externalIds/relations/etc.). */
const ALLOWED_CONTACT_FIELDS = [
  "names",
  "emailAddresses",
  "phoneNumbers",
  "organizations",
  "addresses",
  "biographies",
  "urls",
  "userDefined",
  "birthdays",
] as const;

/** Per-field leaf-property allowlist. Each allowed array item is rebuilt from
 * ONLY these properties — a smuggled nested key (e.g. names[*].metadata) is
 * rejected, never copied into the SDK body. MUST stay in lockstep with the
 * inputSchema item `properties` in registry/contacts.ts. */
const CONTACT_LEAF_PROPS: Record<string, readonly string[]> = {
  names: ["givenName", "familyName", "middleName", "displayName", "honorificPrefix", "honorificSuffix"],
  emailAddresses: ["value", "type", "displayName"],
  phoneNumbers: ["value", "type"],
  organizations: ["name", "title", "department"],
  addresses: ["formattedValue", "type", "streetAddress", "extendedAddress", "city", "region", "postalCode", "country", "countryCode", "poBox"],
  biographies: ["value", "contentType"],
  urls: ["value", "type"],
  userDefined: ["key", "value"],
  birthdays: ["date", "text"],
};

/** Generic per-leaf byte cap (10MB-string DoS guard) + field-specific caps
 * locked in v1.15 §9. */
const CONTACT_STR_MAX_BYTES = 1024;
const CONTACT_BIO_MAX_BYTES = 2048;
const CONTACT_URL_VALUE_MAX_BYTES = 512;
const CONTACT_USERDEFINED_VALUE_MAX_BYTES = 512;
/** etag is short (~50 chars); bound it as DoS defense before it reaches the
 * SDK body. */
const CONTACT_ETAG_MAX_BYTES = 512;
/** urls[*].value scheme allowlist (v1.15 §9 sec-M4). `new URL(...).protocol`
 * includes the trailing colon. */
const CONTACT_URL_SCHEME_ALLOW = new Set(["http:", "https:", "mailto:"]);

/** Validate + rebuild a single birthday `date` object → integer year/month/day
 * only (no free-text leak via the date object). */
function validateBirthdayDate(value: unknown, idx: number, tool: string): Record<string, number> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${tool}: birthdays[${idx}].date must be an object {year?, month?, day?}`);
  }
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(value)) {
    if (k !== "year" && k !== "month" && k !== "day") {
      throw new Error(`${tool}: birthdays[${idx}].date.${k} is not allowed (year/month/day only)`);
    }
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new Error(`${tool}: birthdays[${idx}].date.${k} must be an integer`);
    }
    if (k === "month" && (v < 1 || v > 12)) {
      throw new Error(`${tool}: birthdays[${idx}].date.month must be 1-12`);
    }
    if (k === "day" && (v < 1 || v > 31)) {
      throw new Error(`${tool}: birthdays[${idx}].date.day must be 1-31`);
    }
    if (k === "year" && (v < 1 || v > 9999)) {
      throw new Error(`${tool}: birthdays[${idx}].date.year must be 1-9999`);
    }
    out[k] = v;
  }
  return out;
}

/** Validate + rebuild a single array item for `field` from CONTACT_LEAF_PROPS,
 * applying byte caps + url-scheme allowlist. Rejects any property not in the
 * leaf allowlist. */
function validateContactItem(
  field: string,
  item: unknown,
  idx: number,
  tool: string,
): Record<string, unknown> {
  if (typeof item !== "object" || item === null || Array.isArray(item)) {
    throw new Error(`${tool}: ${field}[${idx}] must be an object`);
  }
  const props = CONTACT_LEAF_PROPS[field]!;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(item)) {
    if (!props.includes(k)) {
      throw new Error(`${tool}: ${field}[${idx}].${k} is not an allowed property`);
    }
    if (field === "birthdays" && k === "date") {
      out.date = validateBirthdayDate(v, idx, tool);
      continue;
    }
    if (typeof v !== "string") {
      throw new Error(`${tool}: ${field}[${idx}].${k} must be a string`);
    }
    let cap = CONTACT_STR_MAX_BYTES;
    if (field === "biographies" && k === "value") cap = CONTACT_BIO_MAX_BYTES;
    else if (field === "urls" && k === "value") cap = CONTACT_URL_VALUE_MAX_BYTES;
    else if (field === "userDefined" && k === "value") cap = CONTACT_USERDEFINED_VALUE_MAX_BYTES;
    if (Buffer.byteLength(v, "utf8") > cap) {
      throw new Error(`${tool}: ${field}[${idx}].${k} exceeds ${cap} bytes UTF-8`);
    }
    if (field === "urls" && k === "value") {
      let parsed: URL;
      try {
        parsed = new URL(v);
      } catch {
        throw new Error(`${tool}: ${field}[${idx}].value is not a valid URL`);
      }
      if (!CONTACT_URL_SCHEME_ALLOW.has(parsed.protocol)) {
        // Echo the RULE, not the value (not even the normalized scheme) —
        // matches the resource_name posture (sec-rev v1.50 LOW).
        throw new Error(
          `${tool}: ${field}[${idx}].value has a URL scheme that is not allowed (http / https / mailto only)`,
        );
      }
    }
    out[k] = v;
  }
  // userDefined requires a non-empty key (a value with no key is meaningless).
  if (field === "userDefined" && (typeof out.key !== "string" || out.key.length === 0)) {
    throw new Error(`${tool}: userDefined[${idx}] requires a non-empty 'key'`);
  }
  return out;
}

/** Build a validated People `Person` body from caller args, copying ONLY the
 * v1.15 §9 allowlisted field groups and their allowlisted leaf properties.
 * `controlKeys` are non-Person top-level args to skip (account_id, and for
 * update resource_name/etag). Throws on any field outside the allowlist (the
 * NEGATIVE sentinel) and requires ≥1 field group (an empty write is rejected). */
function buildValidatedPerson(
  args: Record<string, unknown>,
  tool: string,
  controlKeys: ReadonlySet<string>,
): Record<string, unknown> {
  const person: Record<string, unknown> = {};
  for (const key of Object.keys(args)) {
    if (controlKeys.has(key)) continue;
    if (!(ALLOWED_CONTACT_FIELDS as readonly string[]).includes(key)) {
      throw new Error(
        `${tool}: field '${key}' is not allowed (allowed: ${ALLOWED_CONTACT_FIELDS.join(", ")})`,
      );
    }
    const arr = args[key];
    if (!Array.isArray(arr)) {
      throw new Error(`${tool}: '${key}' must be an array`);
    }
    if (arr.length === 0) continue; // empty array — nothing to write for this group
    person[key] = arr.map((item, idx) => validateContactItem(key, item, idx, tool));
  }
  if (Object.keys(person).length === 0) {
    throw new Error(
      `${tool} requires at least one non-empty contact field group (${ALLOWED_CONTACT_FIELDS.join(", ")})`,
    );
  }
  return person;
}

export async function contactsCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Tier defense-in-depth (registry min_tier="write" is the primary gate;
  // this re-check mirrors the youtube/tasks write handlers). No mutation-meta
  // channel exists for contacts, so the denial is NOT recorded to a meta
  // sidecar — the standard auditEnd() row already captures tool + args_hash.
  if (ctx.tier === "read") {
    throw new MCPError("scope_mismatch", {
      tool: "contacts_create",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  const requestBody = buildValidatedPerson(args, "contacts_create", new Set(["account_id"]));

  try {
    const people = peopleClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await people.people.createContact({
      personFields: CONTACTS_GET_PERSON_FIELDS,
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "contacts_create", email: requireGoogle(ctx).accountId });
  }
}

export async function contactsUpdate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (ctx.tier === "read") {
    throw new MCPError("scope_mismatch", {
      tool: "contacts_update",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // resource_name — same format gate as contacts_get (echo the rule, not the
  // bad value).
  if (typeof args.resource_name !== "string") {
    throw new Error("contacts_update: 'resource_name' must be a string");
  }
  if (!PEOPLE_RESOURCE_NAME_RE.test(args.resource_name)) {
    throw new Error(
      "contacts_update: 'resource_name' must match /^people\\/c[0-9]{1,32}$/ (obtain via contacts_search / contacts_get)",
    );
  }
  const resourceName = args.resource_name;

  // etag — REQUIRED. People API updateContact uses it for optimistic
  // concurrency; Google rejects the call (400) if it is missing or stale.
  // Requiring it here (vs silently fetching the latest) preserves lost-update
  // protection: the caller must read-modify-write via contacts_get first.
  if (typeof args.etag !== "string" || args.etag.trim().length === 0) {
    throw new Error(
      "contacts_update requires the contact's current 'etag' (obtain via contacts_get) — People API uses it for optimistic concurrency",
    );
  }
  if (Buffer.byteLength(args.etag, "utf8") > CONTACT_ETAG_MAX_BYTES) {
    throw new Error(`contacts_update: 'etag' exceeds ${CONTACT_ETAG_MAX_BYTES} bytes UTF-8`);
  }
  const etag = args.etag;

  // Build the validated Person from the same allowlist as create. ≥1 field
  // group required (an update must change something).
  const person = buildValidatedPerson(
    args,
    "contacts_update",
    new Set(["account_id", "resource_name", "etag"]),
  );

  // updatePersonFields = the field GROUPS present in the body. Groups not
  // supplied are absent from the mask → left unchanged by Google. The etag goes
  // in the body (People API contract), NOT in the mask. Derived from the fixed
  // ALLOWED_CONTACT_FIELDS order (not Object.keys order) so the mask string is
  // deterministic regardless of caller field order (sec-rev v1.50 code-review).
  const updatePersonFields = ALLOWED_CONTACT_FIELDS.filter((f) => f in person).join(",");

  try {
    const people = peopleClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await people.people.updateContact({
      resourceName,
      updatePersonFields,
      personFields: CONTACTS_GET_PERSON_FIELDS,
      requestBody: { ...person, etag },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "contacts_update", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.15 Phase 3 — contact-lookup recipient resolver ─────────
 *
 * Shared helper used by `gmail_send` and `calendar_create_event` to convert
 * caller-supplied recipient strings (which may be either emails OR human
 * names) into resolved email addresses.
 *
 * Per design §9 + sec-rev hooks #3 / #5 / #6:
 *
 *   - Email-shaped input (matches EMAIL_RECIPIENT_RE) → passes through
 *     UNCHANGED, no contactsLookupEmail call observed (defense-in-depth:
 *     prevents `account-name@trusted.com` from being silently rewritten if
 *     a contact happens to be named "account-name").
 *
 *   - Non-email input:
 *     * If env var `SAFESPACE_RECIPIENT_ALLOW_CONTACTS` is NOT exactly the
 *       literal lowercase "true" → DO NOT attempt resolution. Caller's own
 *       email-format gate will fire next and reject the malformed input.
 *       This preserves v1.14 behaviour exactly when the env var is unset
 *       or set to anything other than "true".
 *     * If enabled → call `contactsLookupEmail({name})`:
 *         - 1 match → use the FIRST email_addresses[] entry (the primary
 *           per People API conventions).
 *         - 0 matches → throw MCPError("recipient_lookup_failed") with
 *           NO PII in errorData (sec-rev hook #6).
 *         - ≥2 matches → throw MCPError("recipient_lookup_failed") with
 *           errorData {ambiguous: true, match_count: N}. NEVER echoes the
 *           name or matched emails (would convert into a contact-enumeration
 *           oracle reachable by a prompt-injected Claude).
 *
 * The resolved emails are returned in 1-to-1 order with the input array so
 * the caller can splice them back into to/cc/bcc/attendees positions.
 *
 * **Allowlist semantics (sec-rev hook #5)**: this helper does NOT apply the
 * `isRecipientAllowed` gate. The CALLER must run resolved emails through
 * `isRecipientAllowed` to preserve the v2.2 allowlist contract — contact
 * lookup is an INPUT-shape change (name → email), NOT an OUTPUT-gate bypass.
 * `gmail_send` does this; `calendar_create_event` deliberately does NOT (per
 * v1.13 design — `sendUpdates="none"` means no outbound mail, so no allowlist
 * gate on attendees in the first place).
 *
 * **Audit hash (sec-rev hook H1)**: caller-provided `recordResolvedEmails`
 * callback receives the FULL list of resolved emails when AT LEAST ONE name
 * was actually resolved (i.e., at least one input was non-email). The caller
 * then computes the SHA-256 hash and emits it via
 * `ctx.audit.record("resolvedRecipientHash", ...)`. We don't compute the hash here so the
 * caller can use the SAME hash for both gmail_send (3 recipient fields) and
 * calendar_create_event (1 attendee field) with consistent semantics:
 * canonical form = sorted-emails.join(",").
 *
 * **NO PER-PROCESS CACHE** (per design §11 hook #12 sec-M5 carry-forward):
 * resolution goes through `contactsLookupEmail` every time across CALLS.
 * A module-level name→email cache here would re-introduce the cross-account
 * leak risk Phase 1b deliberately avoided — the per-process warming cache in
 * handlers.ts only stores a Set<account_email>, never query results.
 *
 * v1.15.1 Phase 4a M1 — a PER-CALL `Map<name, Promise<lookupResult>>` cache
 * IS used inside the function body to dedup repeated names within the SAME
 * resolver invocation (e.g., `to: "alice", cc: "alice"`). The cache lives in
 * function-local scope and dies with the call — it CANNOT bridge accounts.
 * Do NOT lift to module-level under any future refactor.
 */

/** Resolve a list of recipient strings (emails OR names) to emails, optionally
 *  via contactsLookupEmail when the opt-in env var is set.
 *
 *  Returns:
 *    - `resolvedEmails`: full resolved recipient list in 1:1 input order
 *      (pass-through emails + looked-up emails). This is the canonical
 *      recipient set the caller passes to the SDK AND uses as the input to
 *      `hashResolvedRecipientEmails` for the audit-row hash.
 *    - `lookedUpEmails`: ONLY the emails that came from contact-lookup
 *      resolution (subset of `resolvedEmails`; excludes pass-through emails).
 *      Used by the caller to decide IF a hash should be emitted at all — only
 *      when `lookedUpEmails.length > 0` does the audit row include
 *      `resolved_recipient_hash`. The hash ITSELF is computed over
 *      `resolvedEmails` (i.e., the FULL recipient list, not just the
 *      looked-up subset) per audit.ts `AuditEndContext.resolvedRecipientHash`
 *      spec: ONE hash per CALL covering all recipients.
 *
 *  Throws MCPError("recipient_lookup_failed") on 0-match or ≥2-match. */
export async function resolveRecipientsViaContactLookup(
  ctx: ToolContext,
  inputs: string[],
  tool: "gmail_send" | "calendar_create_event" | "calendar_update_event",
): Promise<{ resolvedEmails: string[]; lookedUpEmails: string[] }> {
  const resolved: string[] = new Array(inputs.length);
  const lookedUp: string[] = [];

  // v1.15.1 Phase 4a M1 — PER-CALL name dedup cache.
  //
  // Maps name → in-flight Promise<lookupResult> so repeated names within the
  // SAME resolver invocation (e.g. `to: ["alice", "alice"]` or `to: "alice" +
  // cc: "alice"` after the caller concatenates the fields) share a single
  // People API call. Saves quota + reduces warming-cache race surface.
  //
  // **CRITICAL — per-CALL ONLY, NOT module-level.** A module-level cache here
  // would re-introduce the cross-account leak class Phase 1b deliberately
  // avoided (sec-M5 carry-forward): contact-lookup results from account A
  // could surface in a subsequent call as account B. Keeping the Map in this
  // function's local scope means it dies with the call and can never bridge
  // accounts. Do NOT lift this Map to a module-level `const` under any future
  // refactor — re-validate with an independent security review
  // before changing its lifetime.
  type LookupResult =
    | { ambiguous: true; match_count: number }
    | {
        matches: Array<{ display_name: string | null; email_addresses: string[] }>;
        ambiguous: false;
      };
  const lookupCache = new Map<string, Promise<LookupResult>>();

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i]!;
    // Pass-through path: already-email inputs go through unchanged. We MUST
    // check this before the opt-in env var — an email is always an email,
    // regardless of whether contact-lookup is enabled. Defense-in-depth:
    // prevents a name like "alice@example.com" (someone literally named that)
    // from being silently rewritten when a contact uses that string as a
    // display name.
    if (EMAIL_RECIPIENT_RE.test(input)) {
      resolved[i] = input;
      continue;
    }

    // Non-email path: only attempted when the opt-in env var is set to the
    // literal lowercase "true". Otherwise we fall through and let the
    // caller's existing email-format gate reject the malformed input — same
    // failure surface as pre-Phase-3 behaviour.
    if (!isContactLookupEnabled()) {
      // Caller's `EMAIL_RECIPIENT_RE.test()` loop will throw a clear "not a
      // valid email address: <addr>" error. Just leave the value in place.
      resolved[i] = input;
      continue;
    }

    // Opt-in enabled: attempt contacts_lookup_email (de-duped per-call).
    // Errors from this call bubble up as MCPError or UpstreamError — the
    // catch below tags scope_mismatch with via_tool, then the caller's
    // try/catch handles the rest (`instanceof MCPError` re-throw preserves
    // the typed error data shape).
    let lookupPromise = lookupCache.get(input);
    if (lookupPromise === undefined) {
      lookupPromise = (async (): Promise<LookupResult> => {
        try {
          return (await contactsLookupEmail(ctx, { name: input })) as LookupResult;
        } catch (err) {
          // v1.15.1 Phase 4a M3 — scope_mismatch attribution wrap.
          //
          // If the caller (e.g. `gmail_send`) doesn't itself need
          // `contacts.readonly` but the resolver hits it via the env-opt-in
          // path, a `scope_mismatch` from `contactsLookupEmail` confuses the
          // caller — the error attributes the failure to a tool they didn't
          // invoke. Preserve the original `tool` (for the recovery-message
          // join) and add `via_tool` so forensic + UX messaging can show
          // BOTH the leaf tool that hit the scope check AND the parent tool
          // the user actually invoked. Pure attribution; recovery action is
          // unchanged (re-run consent for the missing scope).
          if (err instanceof MCPError && err.errorName === "scope_mismatch") {
            throw new MCPError("scope_mismatch", {
              ...err.errorData,
              via_tool: tool,
            });
          }
          throw err;
        }
      })();
      lookupCache.set(input, lookupPromise);
    }
    const lookupResult = await lookupPromise;

    // ≥2 matches → ambiguity rejection. Per sec-rev hook #6 the errorData
    // MUST contain ONLY {ambiguous, match_count} — NEVER echoes the queried
    // name or any matched contact identifier (would convert into a contact-
    // enumeration oracle reachable by a prompt-injected Claude).
    if ("ambiguous" in lookupResult && lookupResult.ambiguous === true) {
      throw new MCPError("recipient_lookup_failed", {
        tool,
        ambiguous: true,
        match_count: lookupResult.match_count,
      });
    }

    // 0 matches → not-found rejection. Same posture as ambiguity: NO PII in
    // errorData. Caller fingerprint of "which name failed" is recoverable
    // ONLY by re-running contacts_lookup_email or correlating against the
    // request's `args_hash` (covers original input including the name).
    if (lookupResult.matches.length === 0) {
      throw new MCPError("recipient_lookup_failed", {
        tool,
        ambiguous: false,
        match_count: 0,
      });
    }

    // 1 match (the only remaining case after .length === 0 and ambiguous=true
    // both ruled out). Pick the primary email (index 0) — People API returns
    // emails primary-first. Defensive: if email_addresses[0] is somehow not
    // a string (shouldn't happen given Phase 1b's filter, but caller-facing
    // contract belongs here), throw the same lookup-failed shape.
    const match = lookupResult.matches[0]!;
    const email = match.email_addresses[0];
    if (typeof email !== "string" || email.length === 0) {
      throw new MCPError("recipient_lookup_failed", {
        tool,
        ambiguous: false,
        match_count: 0,
      });
    }
    resolved[i] = email;
    lookedUp.push(email);
  }

  return { resolvedEmails: resolved, lookedUpEmails: lookedUp };
}

/** Compute the plain SHA-256 hex of the comma-joined sorted resolved emails.
 *
 *  Matches the `args_hash` algorithm convention (plain SHA-256, NOT HMAC).
 *  See `audit.ts` `AuditEndContext.resolvedRecipientHash` comment for the
 *  full rationale — divergence from HMAC-based `target_email_hash` /
 *  `rejected_recipient_hashes` is intentional. */
export function hashResolvedRecipientEmails(emails: string[]): string {
  const canonical = [...emails].sort().join(",");
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/* ───────── v1.16 Phase 1b: YouTube Data API v3 read-tier (5 tools) ─────────
 *
 * Tools:
 *   - youtube_subscriptions_all (CROSS-ACCOUNT _all; cheap 1u/call/account)
 *   - youtube_channel_uploads (single-account; uses UU-playlist trick)
 *   - youtube_video_get (single-account; parts ALLOWLIST default-deny)
 *   - youtube_search (single-account; 100u/call + per-session burst limit)
 *   - youtube_video_comments_list (single-account; UGC sanitize-criticality;
 *     500-leaf cap with <safespace-truncated/> marker injection)
 *
 * See docs/v1.16-youtube-api.md §4 (tool surface), §8 (error codes),
 * §11 (sec-rev hooks). All 5 handlers call `youtubeClientFromToken`
 * (factory in src/google-api/client.ts) and route errors through
 * `mapGoogleError` (errors.ts), which now detects 403 reason=`quotaExceeded`
 * and throws MCPError("youtube_quota_exceeded") (-32024). */

