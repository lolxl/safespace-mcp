// v1.77/v1.78 — the Notion read handlers. v1.78 — Notion is now the 3rd OAuth source
// (was a class-B service-token connector in v1.77; the handlers are unchanged — only the
// credential acquisition + routing changed).
//
// docs/v1.78-notion-oauth.md. Seven READ tools over api.notion.com:
//   notion_search · notion_get_page · notion_get_block_children ·
//   notion_query_database · notion_get_database  (database WRAPPERS)
//   notion_get_data_source · notion_query_data_source  (Notion-Version 2026-03-11)
//
// DATA SOURCES (Notion-Version 2025-09-03+): a database is a container of 0..N data sources;
// the schema + rows live on the data source. The two database tools are COMPATIBILITY
// WRAPPERS that go through ONE shared resolver (`resolveSoleDataSource`): exactly one
// data source → use it; 0 or >1 → an error (NEVER pick one, NEVER fall back to another).
//
// OAUTH (provider notion): each handler reads the bearer via requireNotion(ctx)
// (handlers/shared.ts) — the cross-provider narrow that throws if the credential is not a
// notion OAuth credential (a Google/GitHub bearer can never reach api.notion.com) — and
// uses it ONLY inline in the `Authorization: Bearer` header (passed to notionApiGet/Post),
// never stored, logged, or echoed. The cross-cutting envelope (account resolve / tier /
// sanitize wrap / audit) is applied by withToolContext around it.
//
// THE ENVELOPE IS THE POINT: Notion is the richest inbound injection surface — page +
// block rich text, titles, database column names AND values, people names are all
// attacker-influenced free text. These handlers return a CURATED shape (never the raw
// Notion object), and the choke point runs the source's sanitize tree-walk with
// NOTION_SKIP_FIELDS (tools/source.ts): only opaque/structural keys (id / object / type /
// parent_type / url / timestamps / next_cursor) skip; EVERY other string wraps in
// `<untrusted-source>`. Properties are returned as an ARRAY of {name,type,value} — NOT a
// keyed map — so an attacker-controlled column NAME wraps (a value, not an object key).
//
// ALLOWLIST RECONSTRUCTION: a skipped key passes its WHOLE subtree through unwrapped
// (sanitize/index.ts walk invariant), so every skipped LEAF this file emits (id /
// *_id / object / type / parent_type / next_cursor) is rebuilt from a validated value —
// a canonical UUID string, a closed enum member, or null — never the raw upstream value.
//
// IDs: every Notion id is NOTION_ID_RE-validated (32 hex, dashed or not) BEFORE it is
// interpolated into the api.notion.com path — a hex-only id can never traverse the path.

import { notionApiGet, notionApiPatch, notionApiPost } from "../../auth/notion/client";
import { outboundSanitize } from "../../sanitize/outbound";
// B6.1 wave A — the notion egress gate (enforceNotionWriteEgressGates) is now PIPELINE-FIRED
// by with-context.ts via each write tool's egress descriptor (tools/egress-pipeline.ts); the
// handlers no longer import/call it (anti-double-fire).
import type { ToolContext } from "../types";
import { requireNotion } from "./shared";

/** Test-injection seam — production leaves it undefined (→ the real global fetch).
 *  Mirrors GithubReadDeps; the handler forwards it to notionApiGet/Post. */
export interface NotionReadDeps {
  fetchImpl?: typeof fetch;
}

/** A Notion id: 32 hex chars, dashed (8-4-4-4-12) or undashed. Hex-only → URL-safe, so a
 *  validated id can never traverse the api.notion.com path or inject a query/fragment. */
const NOTION_ID_RE =
  /^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/;
const PAGE_SIZE_DEFAULT = 30;
const PAGE_SIZE_MAX = 100;
const QUERY_MAX = 256; // notion_search query (caller intent — bounded)
const CURSOR_MAX = 1024; // opaque pagination cursor — bounded
const FILTER_TYPES: ReadonlySet<string> = new Set(["page", "database", "data_source"]);
const DATA_SOURCES_MAX = 100; // Notion's documented maxItems for a database's data_sources[]

function requireNotionId(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || !NOTION_ID_RE.test(v)) {
    throw new Error(`notion: '${key}' must be a Notion id (32 hex chars, dashed or not)`);
  }
  return v;
}

function clampPageSize(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : PAGE_SIZE_DEFAULT;
  return Math.floor(Math.min(n, PAGE_SIZE_MAX));
}

/* Pagination cursors are OPAQUE to the agent and carry NO upstream text: on output the upstream
 * cursor is encoded as `ssc1.` + base64url(utf8) (reversible, no server state); on input only that
 * exact shape is accepted and the DECODED value is what goes upstream. `next_cursor` is a skipped
 * sanitize key, so it must never carry readable upstream text. */
const CURSOR_PREFIX = "ssc1.";
const BAD_CURSOR_MSG =
  "notion: 'start_cursor' must be the 'next_cursor' value returned by a previous SafeSpace Notion response, passed back unchanged";

/** True iff `v` is well-formed UTF-16 (no lone surrogate): a lone surrogate would be silently
 *  replaced by U+FFFD on the UTF-8 round trip, so such a cursor could not be sent back intact. */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** `ssc1.<base64url>` body → the exact upstream string, or null if it is not a CANONICAL
 *  base64url of valid non-empty UTF-8 (≤ 1024 chars). `ignoreBOM: true` keeps a leading U+FEFF
 *  (the default decoder would silently STRIP it, corrupting the cursor). */
function decodeCursorBody(body: string): string | null {
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  const bytes = Buffer.from(body, "base64url");
  if (bytes.toString("base64url") !== body) return null; // non-canonical
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  return decoded.length === 0 || decoded.length > CURSOR_MAX ? null : decoded;
}

/** upstream cursor → the agent-facing opaque cursor, or null (not a non-empty, well-formed string
 *  ≤ 1024 chars, or one that would not survive decode(encode(c)) === c LOSSLESSLY). */
function encodeCursor(v: unknown): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > CURSOR_MAX || LONE_SURROGATE_RE.test(v)) return null;
  const body = Buffer.from(v, "utf8").toString("base64url");
  return decodeCursorBody(body) === v ? CURSOR_PREFIX + body : null;
}

/** An optional agent-supplied cursor → the DECODED upstream cursor. Anything but a canonical
 *  `ssc1.`+base64url of valid non-empty UTF-8 (≤ 1024 chars) is rejected BEFORE any network. */
function optionalCursor(args: Record<string, unknown>): string | undefined {
  const v = args.start_cursor;
  if (v === undefined) return undefined;
  if (typeof v !== "string" || !v.startsWith(CURSOR_PREFIX) || v.length > CURSOR_PREFIX.length + 4400) {
    throw new Error(BAD_CURSOR_MSG);
  }
  const decoded = decodeCursorBody(v.slice(CURSOR_PREFIX.length));
  if (decoded === null) throw new Error(BAD_CURSOR_MSG);
  return decoded;
}

/* ── curated response shapers (pick ONLY safe fields; never the raw object) ── */

type Obj = Record<string, unknown>;
const asObj = (v: unknown): Obj | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null;

/** A string, or null. Skipped leaves are always PRIMITIVES (a skipped key passes its whole
 *  subtree through unwrapped, so an object/array under one would escape the wrap). */
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** A Notion id normalised to its canonical form (lowercase, dashed 8-4-4-4-12), or null for
 *  anything that is not a UUID string. Every id/`*_id` this file emits goes through here —
 *  and every comparison of two ids does too (case / hyphen differences must not matter). */
function canonId(v: unknown): string | null {
  if (typeof v !== "string" || !NOTION_ID_RE.test(v)) return null;
  const h = v.replace(/-/g, "").toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** True iff both values are Notion ids naming the SAME object (case / hyphen-insensitive). */
function sameId(a: unknown, b: unknown): boolean {
  const x = canonId(a);
  return x !== null && x === canonId(b);
}

/* CLOSED enums for the skipped `object` / `type` / `parent_type` leaves: a value outside the
 * set is dropped (null / "unknown"), never echoed. */
const OBJECT_KINDS: ReadonlySet<string> = new Set(["page", "data_source", "database", "block", "list", "user"]);
const PARENT_TYPES: ReadonlySet<string> = new Set([
  "page_id",
  "database_id",
  "data_source_id",
  "workspace",
  "block_id",
]);
const PROPERTY_TYPES: ReadonlySet<string> = new Set([
  "title", "rich_text", "number", "select", "multi_select", "status", "date", "people", "files",
  "checkbox", "url", "email", "phone_number", "formula", "relation", "rollup", "created_time",
  "created_by", "last_edited_time", "last_edited_by", "unique_id", "button", "verification", "place",
]);
const BLOCK_TYPES: ReadonlySet<string> = new Set([
  "paragraph", "heading_1", "heading_2", "heading_3", "heading_4", "bulleted_list_item",
  "numbered_list_item", "to_do", "toggle", "quote", "callout", "code", "divider", "image", "table",
  "table_row", "table_of_contents", "bookmark", "embed", "equation", "file", "pdf", "video", "audio",
  "child_page", "child_database", "column_list", "column", "link_preview", "link_to_page",
  "synced_block", "template", "breadcrumb", "meeting_notes", "transcription", "tab", "unsupported",
]);
const REQUEST_STATUS_TYPES: ReadonlySet<string> = new Set(["complete", "incomplete"]);
const INCOMPLETE_REASONS: ReadonlySet<string> = new Set(["query_result_limit_reached"]);

const inSet = (set: ReadonlySet<string>, v: unknown): string | null =>
  typeof v === "string" && set.has(v) ? v : null;

/** A Notion timestamp (`created_time` / `last_edited_time` are skipped keys): ISO-8601 with a
 *  `Z` / ±HH:MM offset whose every component is in range and which round-trips through
 *  `Date.parse`; else null. */
const ISO_TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/;
function timestamp(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const m = ISO_TIMESTAMP_RE.exec(v);
  if (m === null) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [number, number, number, number, number, number];
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate(); // day 0 of next month
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth || h > 23 || mi > 59 || se > 59) return null;
  if (m[8] !== "Z" && (Number(m[10]) > 23 || Number(m[11]) > 59)) return null;
  return Number.isNaN(Date.parse(v)) ? null : v;
}

/** An object URL REBUILT from an already-validated canonical id: `https://www.notion.so/<32
 *  lowercase hex>`. The upstream `url` is never emitted (it embeds the page TITLE in its path,
 *  plus query / fragment), so the skipped `url` key carries no upstream text. null without an id. */
const idUrl = (id: string | null): string | null => (id === null ? null : `https://www.notion.so/${id.replace(/-/g, "")}`);

/** `request_status` (search / data-source query): ONLY the documented closed set —
 *  `{ type: complete|incomplete, incomplete_reason?: query_result_limit_reached }`. Anything
 *  else (an unknown value, extra nested keys) is dropped → the field is omitted. */
function shapeRequestStatus(v: unknown): Obj | null {
  const o = asObj(v);
  const type = o ? inSet(REQUEST_STATUS_TYPES, o.type) : null;
  if (o === null || type === null) return null;
  const reason = inSet(INCOMPLETE_REASONS, o.incomplete_reason);
  return reason === null ? { type } : { type, incomplete_reason: reason };
}

/** The pagination envelope shared by every list tool: `next_cursor`, `has_more`, and (only
 *  when valid) `request_status`. */
function listMeta(data: Obj): Obj {
  const next = encodeCursor(data.next_cursor);
  const hasMore = data.has_more === true;
  const meta: Obj = { next_cursor: next, has_more: hasMore };
  // has_more but no usable cursor (dropped by encodeCursor): say so — never report "done".
  if (hasMore && next === null) {
    meta.pagination_note = "More results exist but Notion's next_cursor was not a usable token, so paging stops here.";
  }
  const rs = shapeRequestStatus(data.request_status);
  if (rs !== null) meta.request_status = rs;
  return meta;
}

/** Join the `plain_text` of a Notion rich_text array into one string (wraps). */
function extractRichText(v: unknown): string {
  if (!Array.isArray(v)) return "";
  return v
    .map((rt) => {
      const o = asObj(rt);
      return o && typeof o.plain_text === "string" ? o.plain_text : "";
    })
    .join("");
}

/** A page's title (the property whose type is "title") or a database / data source's
 *  top-level title. */
function extractTitle(o: Obj): string {
  if (Array.isArray(o.title)) return extractRichText(o.title); // database / data source
  const props = asObj(o.properties);
  if (props) {
    for (const v of Object.values(props)) {
      const p = asObj(v);
      if (p && p.type === "title") return extractRichText(p.title);
    }
  }
  return "";
}

/** The parent kind — a closed enum (skip). */
function parentType(o: Obj): string | null {
  return inSet(PARENT_TYPES, asObj(o.parent)?.type);
}

/** The parent's ids (2026-03-11: a page in a data source has `parent.data_source_id` AND
 *  `parent.database_id`). Each is emitted ONLY when present and a valid UUID — these keys are
 *  skipped leaves (tools/source.ts), so they must be validated here. */
function parentIds(o: Obj): Obj {
  const p = asObj(o.parent);
  const out: Obj = {};
  if (p === null) return out;
  const ds = canonId(p.data_source_id);
  if (ds !== null) out.parent_data_source_id = ds;
  const db = canonId(p.database_id);
  if (db !== null) out.parent_database_id = db;
  const pg = canonId(p.page_id);
  if (pg !== null) out.parent_page_id = pg;
  return out;
}

/** Notion 2026-03-11 renamed `archived` → `in_trash`. The TOOL contract keeps the key
 *  `archived` (agent-facing); only the wire field changed. */
const trashed = (o: Obj): boolean | undefined => (typeof o.in_trash === "boolean" ? o.in_trash : undefined);

/** Extract a simplified value per Notion property type — scalar / text / array. The
 *  envelope wraps every emitted string. Unknown/complex types (files / relation / rollup)
 *  → null (only the controlled `type` label is kept). Every branch returns a PRIMITIVE (or an
 *  array / {start,end} of primitives) — never a raw upstream object. */
function shapePropertyValue(p: Obj): unknown {
  const num = (x: unknown): number | null => (typeof x === "number" && Number.isFinite(x) ? x : null);
  const bool = (x: unknown): boolean | null => (typeof x === "boolean" ? x : null);
  const range = (x: unknown): { start: string | null; end: string | null } | null => {
    const d = asObj(x);
    return d ? { start: str(d.start), end: str(d.end) } : null;
  };
  switch (p.type) {
    case "title":
      return extractRichText(p.title);
    case "rich_text":
      return extractRichText(p.rich_text);
    case "number":
      return num(p.number);
    case "checkbox":
      return bool(p.checkbox);
    case "url":
      return str(p.url);
    case "email":
      return str(p.email);
    case "phone_number":
      return str(p.phone_number);
    case "select":
      return str(asObj(p.select)?.name);
    case "status":
      return str(asObj(p.status)?.name);
    case "multi_select":
      return Array.isArray(p.multi_select) ? p.multi_select.map((s) => str(asObj(s)?.name)) : [];
    case "date":
      return range(p.date);
    case "people":
      return Array.isArray(p.people)
        ? p.people.map((u) => {
            const o = asObj(u);
            return o ? (str(o.name) ?? str(o.id)) : null;
          })
        : [];
    case "created_time":
      return str(p.created_time);
    case "last_edited_time":
      return str(p.last_edited_time);
    case "formula": {
      // Closed-set switch on the formula result type — NOT a dynamic f[f.type] read
      // (which would use an attacker-influenced string as a property key).
      const f = asObj(p.formula);
      if (!f) return null;
      switch (f.type) {
        case "string":
          return str(f.string);
        case "number":
          return num(f.number);
        case "boolean":
          return bool(f.boolean);
        case "date":
          return range(f.date);
        default:
          return null;
      }
    }
    default:
      return null;
  }
}

/** Properties as an ARRAY of {name, type, value} so the attacker-controlled column NAME
 *  wraps (it is a value, not an object key — the sanitize tree-walk wraps values, not
 *  keys). `type` is a closed enum (skip); `value` wraps. */
function shapeProperties(v: unknown): Array<{ name: string; type: string; value: unknown }> {
  const props = asObj(v);
  if (!props) return [];
  return Object.entries(props).map(([name, raw]) => {
    const p = asObj(raw) ?? {};
    return { name, type: inSet(PROPERTY_TYPES, p.type) ?? "unknown", value: shapePropertyValue(p) };
  });
}

/** A search hit. 2026-03-11 `/v1/search` returns PAGES and DATA SOURCES (never databases):
 *  a page → the page summary; a data source → `{ object:"data_source", id (= the DATA SOURCE
 *  id), title, database_id (the CONTAINER database) }`. The two ids are NOT interchangeable:
 *  `id` feeds the data-source tools / `parent_data_source_id`, `database_id` the database
 *  tools. Anything else is dropped. */
function shapeSearchResult(v: unknown): Obj | null {
  const o = asObj(v);
  if (o === null) return null;
  if (o.object === "page") {
    return {
      object: "page",
      id: canonId(o.id),
      title: extractTitle(o),
      url: idUrl(canonId(o.id)),
      parent_type: parentType(o),
      ...parentIds(o),
      archived: trashed(o),
      last_edited_time: timestamp(o.last_edited_time),
    };
  }
  if (o.object === "data_source") {
    return {
      object: "data_source",
      id: canonId(o.id),
      title: extractRichText(o.title),
      database_id: canonId(asObj(o.parent)?.database_id),
    };
  }
  return null;
}

function shapePage(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: inSet(OBJECT_KINDS, o.object),
    id: canonId(o.id),
    url: idUrl(canonId(o.id)),
    archived: trashed(o),
    parent_type: parentType(o),
    ...parentIds(o),
    created_time: timestamp(o.created_time),
    last_edited_time: timestamp(o.last_edited_time),
    title: extractTitle(o),
    properties: shapeProperties(o.properties),
  };
}

/** A data-source query result row: a page → {@link shapePage}; a data source (a WIKI database
 *  returns its child data sources, mixed with pages) → `{object, id, title}`; anything else is
 *  dropped. Dispatches on `object`, never on shape. */
function shapeQueryResult(v: unknown): Obj | null {
  const o = asObj(v);
  if (o === null) return null;
  if (o.object === "page") return shapePage(o);
  if (o.object === "data_source") {
    return { object: "data_source", id: canonId(o.id), title: extractRichText(o.title) };
  }
  return null;
}

/** Block types whose payload object carries a `rich_text` array (the readable content).
 *  A CLOSED set — so the per-block lookup is NOT a dynamic `o[o.type]` read with an
 *  attacker-influenced key (mirrors the shapePropertyValue formula fix). Any other block
 *  type (image / divider / table / meeting_notes / a future type) → text "" (same as the old
 *  fallback). `meeting_notes` (2026-03-11's rename of `transcription`) is deliberately NOT
 *  here — a follow-up. */
const RICH_TEXT_BLOCK_TYPES: ReadonlySet<string> = new Set([
  "paragraph",
  "heading_1",
  "heading_2",
  "heading_3",
  "bulleted_list_item",
  "numbered_list_item",
  "to_do",
  "toggle",
  "quote",
  "callout",
  "code",
]);

function shapeBlock(v: unknown): Obj {
  const o = asObj(v) ?? {};
  const blockType = typeof o.type === "string" ? o.type : "";
  const inner = RICH_TEXT_BLOCK_TYPES.has(blockType) ? asObj(o[blockType]) : null;
  return {
    id: canonId(o.id),
    type: inSet(BLOCK_TYPES, o.type) ?? "unknown",
    has_children: typeof o.has_children === "boolean" ? o.has_children : undefined,
    text: inner ? extractRichText(inner.rich_text) : "",
  };
}

/** A data source's schema: [{ name, type }] (the column NAME is attacker-controlled → it is a
 *  wrapped value; `type` is a closed enum). */
function shapeSchema(v: unknown): Array<{ name: string; type: string }> {
  const props = asObj(v);
  if (!props) return [];
  return Object.entries(props).map(([name, raw]) => ({
    name,
    type: inSet(PROPERTY_TYPES, asObj(raw)?.type) ?? "unknown",
  }));
}

/** A database's data-source references `[{ id, name }]`. STRICT: a non-array, more than Notion's
 *  documented 100, or ANY entry that is not an object with a valid id fails closed (no silent
 *  dropping — a partial list would hide a source from the agent). */
function dataSourceRefs(v: unknown): Array<{ id: string; name: string }> {
  if (!Array.isArray(v) || v.length > DATA_SOURCES_MAX) throw new Error(DS_LIST_MALFORMED_MSG);
  return v.map((r) => {
    const o = asObj(r);
    const id = o ? canonId(o.id) : null;
    if (o === null || id === null) throw new Error(DS_LIST_MALFORMED_MSG);
    return { id, name: str(o.name) ?? "" };
  });
}

/** A 2026-03-11 DATABASE: metadata + its data-source list only (the schema lives on the data
 *  source — see {@link shapeDataSource}). */
function shapeDatabase(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: inSet(OBJECT_KINDS, o.object),
    id: canonId(o.id),
    url: idUrl(canonId(o.id)),
    title: extractRichText(o.title),
    archived: trashed(o),
    created_time: timestamp(o.created_time),
    last_edited_time: timestamp(o.last_edited_time),
    data_sources: dataSourceRefs(o.data_sources),
  };
}

/** A DATA SOURCE (`GET /v1/data_sources/{id}`): its schema + the container database id. A
 *  PARTIAL data source (only object/id/properties) simply has no title / database_id. */
function shapeDataSource(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: "data_source",
    id: canonId(o.id),
    title: extractRichText(o.title),
    database_id: canonId(asObj(o.parent)?.database_id),
    archived: trashed(o),
    created_time: timestamp(o.created_time),
    last_edited_time: timestamp(o.last_edited_time),
    properties: shapeSchema(o.properties),
  };
}

/* ── the database → data source RESOLVER (Q3: never pick) ───────────────────────────────── */

// FIXED messages — never an id, name, or any upstream text.
const DS_LIST_MALFORMED_MSG = "notion: the database's data source list is malformed, so it cannot be trusted — nothing was read or written";
const DS_NONE_MSG = "notion: this database has no data source, so there is nothing to read or write";
const DS_MANY_MSG =
  "notion: this database has more than one data source (or its data source could not be " +
  "resolved) — SafeSpace never picks one. Call notion_get_database to list its data sources, " +
  "then use notion_get_data_source / notion_query_data_source or parent_data_source_id with " +
  "the one you want";

/** The sole data source id of a retrieved database, or THROW. The decision is made on the TOTAL
 *  `data_sources` count, BEFORE any filtering or per-source retrieval: exactly 1 → its id;
 *  0 → error; >1 → error (even if only one of them is readable). A malformed single candidate
 *  (or a missing / non-array `data_sources`) fails closed — it never falls through to
 *  "choose another". */
function soleDataSourceId(db: unknown): string {
  const refs = asObj(db)?.data_sources;
  if (!Array.isArray(refs)) throw new Error(DS_MANY_MSG);
  if (refs.length === 0) throw new Error(DS_NONE_MSG);
  if (refs.length > 1) throw new Error(DS_MANY_MSG);
  const id = canonId(asObj(refs[0])?.id);
  if (id === null) throw new Error(DS_MANY_MSG);
  return id;
}

const DB_UNVERIFIED_MSG = "notion: the database response could not be verified as the requested database — nothing was read or written";

/** A retrieved database must BE the requested one: `object === "database"` and the canonical
 *  id equal to the requested id (an `object:"error"` body, a different id or missing fields
 *  fail closed). Returns the body. */
function verifyDatabase(db: unknown, requestedId: string): Obj {
  const o = asObj(db);
  if (o === null || o.object !== "database" || !sameId(o.id, requestedId)) throw new Error(DB_UNVERIFIED_MSG);
  return o;
}

const DS_UNVERIFIED_MSG = "notion: the data source response could not be confirmed as the requested data source — nothing was read or written";

/** READ-path identity: a retrieved data source must BE the requested one — `object ===
 *  "data_source"` and canonical id === `expectedId`. `parent` is OPTIONAL (Notion omits it without
 *  read-content capability, and an externally synced source has `parent.type:"data_source_id"`),
 *  but when present it must be an object. Membership for get_database is already established by
 *  the database's own data_sources listing. */
function verifyDataSourceRead(ds: unknown, expectedId: string): Obj {
  const o = asObj(ds);
  if (
    o === null ||
    o.object !== "data_source" ||
    !sameId(o.id, expectedId) ||
    (o.parent !== undefined && asObj(o.parent) === null)
  ) {
    throw new Error(DS_UNVERIFIED_MSG);
  }
  return o;
}

/** WRITE-path identity (create_page pre-write re-check): object + id as above, AND a parent that
 *  PROVES membership — `parent.type` of `database_id` or `data_source_id` with a valid
 *  `parent.database_id` equal to the requested database. A missing parent cannot prove membership
 *  → fail closed (zero POSTs). */
function verifyDataSourceWrite(ds: unknown, expectedId: string, expectedDatabaseId: string): Obj {
  const o = verifyDataSourceRead(ds, expectedId);
  const parent = asObj(o.parent);
  if (
    parent === null ||
    (parent.type !== "database_id" && parent.type !== "data_source_id") ||
    !sameId(parent.database_id, expectedDatabaseId)
  ) {
    throw new Error(DS_UNVERIFIED_MSG);
  }
  return o;
}

/** `GET /v1/databases/{id}` → the sole data source id (see {@link soleDataSourceId}). One GET,
 *  no retry, no fallback: a 403/404/429 from Notion surfaces as `notion_api_failed` as-is. */
async function resolveSoleDataSource(
  token: string,
  databaseId: string,
  deps: NotionReadDeps,
): Promise<string> {
  const db = await notionApiGet({ token, path: `/v1/databases/${databaseId}`, fetchImpl: deps.fetchImpl });
  return soleDataSourceId(verifyDatabase(db, databaseId));
}

/* ── handlers ── */

/** POST /v1/search — find pages / data sources by title. The legacy `filter_type: "database"`
 *  is still accepted and sent as `"data_source"` (2025-09-03+ only knows page | data_source). */
export async function notionSearch(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const query = args.query;
  if (query !== undefined && (typeof query !== "string" || query.length > QUERY_MAX)) {
    throw new Error(`notion: 'query' must be a string ≤ ${QUERY_MAX} chars`);
  }
  const filterType = args.filter_type;
  if (filterType !== undefined && (typeof filterType !== "string" || !FILTER_TYPES.has(filterType))) {
    throw new Error("notion: 'filter_type' must be 'page', 'data_source' or 'database' (an alias of data_source)");
  }
  const body: Obj = { page_size: clampPageSize(args.page_size) };
  if (typeof query === "string") body.query = query;
  if (typeof filterType === "string") {
    body.filter = { value: filterType === "database" ? "data_source" : filterType, property: "object" };
  }
  const cursor = optionalCursor(args);
  if (cursor !== undefined) body.start_cursor = cursor;
  const data = asObj(await notionApiPost({ token, path: "/v1/search", body, fetchImpl: deps.fetchImpl })) ?? {};
  return {
    results: Array.isArray(data.results)
      ? data.results.map(shapeSearchResult).filter((r): r is Obj => r !== null)
      : [],
    ...listMeta(data),
  };
}

/** GET /v1/pages/{id} — a page's properties. */
export async function notionGetPage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "page_id");
  const data = await notionApiGet({ token, path: `/v1/pages/${id}`, fetchImpl: deps.fetchImpl });
  return shapePage(data);
}

/** GET /v1/blocks/{id}/children — the page CONTENT (child blocks' rich text). */
export async function notionGetBlockChildren(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "block_id");
  const cursor = optionalCursor(args);
  const data =
    asObj(
      await notionApiGet({
        token,
        path: `/v1/blocks/${id}/children`,
        query: { page_size: clampPageSize(args.page_size), start_cursor: cursor },
        fetchImpl: deps.fetchImpl,
      }),
    ) ?? {};
  return {
    blocks: Array.isArray(data.results) ? data.results.map(shapeBlock) : [],
    ...listMeta(data),
  };
}

/** The ONE query core (both query tools): POST /v1/data_sources/{id}/query with an
 *  allowlist-constructed body (page_size + optional start_cursor — no filter/sorts/result_type).
 *  Results dispatch on `object` (pages + a wiki's data sources); `request_status` passes
 *  through only from its closed set. */
async function queryDataSource(
  token: string,
  dataSourceId: string,
  args: Record<string, unknown>,
  deps: NotionReadDeps,
): Promise<Obj> {
  const body: Obj = { page_size: clampPageSize(args.page_size) };
  const cursor = optionalCursor(args);
  if (cursor !== undefined) body.start_cursor = cursor;
  const data =
    asObj(
      await notionApiPost({
        token,
        path: `/v1/data_sources/${dataSourceId}/query`,
        body,
        fetchImpl: deps.fetchImpl,
      }),
    ) ?? {};
  return {
    results: Array.isArray(data.results)
      ? data.results.map(shapeQueryResult).filter((r): r is Obj => r !== null)
      : [],
    ...listMeta(data),
  };
}

/** POST /v1/data_sources/{id}/query — a data source's rows, paginated (max 10,000 results per
 *  query; `request_status` reports a truncated listing). v1: no filter/sorts. */
export async function notionQueryDataSource(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "data_source_id");
  return queryDataSource(token, id, args, deps);
}

/** COMPAT WRAPPER over {@link notionQueryDataSource}: resolves the database's SOLE data source
 *  (0 or >1 → error, never picks) then queries it; the output carries the resolved
 *  `data_source_id`. It does NOT accept `start_cursor` — a cursor is only meaningful for an
 *  EXPLICIT source, so continuation goes through `notion_query_data_source` with the returned
 *  `data_source_id` (no server-side state binds a cursor to a source). */
export async function notionQueryDatabase(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "database_id");
  if (args.start_cursor !== undefined) {
    throw new Error(
      "notion_query_database: 'start_cursor' is not accepted here — to continue paging, call " +
        "notion_query_data_source with the 'data_source_id' returned by the first call and that call's next_cursor",
    );
  }
  const dataSourceId = await resolveSoleDataSource(token, id, deps);
  return { data_source_id: dataSourceId, ...(await queryDataSource(token, dataSourceId, args, deps)) };
}

/** GET /v1/data_sources/{id} — a data source's schema (columns) + its container database id. */
export async function notionGetDataSource(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "data_source_id");
  const data = await notionApiGet({ token, path: `/v1/data_sources/${id}`, fetchImpl: deps.fetchImpl });
  return shapeDataSource(verifyDataSourceRead(data, canonId(id)!));
}

/** GET /v1/databases/{id} — the database metadata + `data_sources:[{id,name}]`. COMPAT: when the
 *  database has EXACTLY ONE data source, that source's schema (`properties:[{name,type}]`) is
 *  included too (what this tool returned before data sources existed); with 0 or >1 sources
 *  only the list is returned — use notion_get_data_source for a specific one. */
export async function notionGetDatabase(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "database_id");
  const db = verifyDatabase(await notionApiGet({ token, path: `/v1/databases/${id}`, fetchImpl: deps.fetchImpl }), id);
  const refs = db.data_sources;
  // A missing / non-array data_sources is a malformed response, NOT "no data sources".
  if (!Array.isArray(refs)) throw new Error(DB_UNVERIFIED_MSG);
  const out = shapeDatabase(db);
  if (refs.length === 1) {
    // soleDataSourceId fails closed on a malformed single entry (no schema fetch, no fallback).
    const dataSourceId = soleDataSourceId(db);
    const ds = verifyDataSourceRead(
      await notionApiGet({ token, path: `/v1/data_sources/${dataSourceId}`, fetchImpl: deps.fetchImpl }),
      dataSourceId,
    );
    out.properties = shapeSchema(ds.properties);
  }
  return out;
}

/* ── WRITE (v1.96) — TEXT-only, allowlist-constructed bodies ───────────────────────────
 * Each write: requireNotion (R8 — a Google/GitHub bearer can never reach api.notion.com)
 * → validate id(s) + title/text → [PIPELINE-FIRED egress: F3a secret-shape; model B — NO
 * target allowlist, Notion's integration-sharing IS the natural bound; B6.1 wave A] →
 * per-field outboundSanitize REJECT (-32027) + byte cap → ALLOWLIST-CONSTRUCTED Notion body
 * (only parent / properties.title / paragraph children — never raw block JSON from the agent)
 * → notionApiPost / notionApiPatch → curated shape. TEXT-only: title is a string and content
 * is plain text rendered as paragraph blocks, so the agent cannot construct arbitrary
 * Notion structures. */

const NOTION_TITLE_MAX_BYTES = 2000; // byte cap (≈ Notion's 2000-char rich_text limit; conservative for multi-byte text)
const NOTION_TEXT_MAX_BYTES = 65536; // bounded page content (blast-radius cap; mirrors github body)
const NOTION_RICH_TEXT_MAX = 2000; // Notion's hard per-rich_text-item char limit
const NOTION_MAX_BLOCKS = 100; // Notion's per-request children cap

/** A Notion `properties` object that sets ONLY the page's title (a page-parented page's
 *  title property is literally named "title"). Allowlist-constructed from a plain string. */
function titleProperties(title: string): Obj {
  return { title: { title: [{ type: "text", text: { content: title } }] } };
}

/* ── WRITE deepening (v1.105) — arbitrary type-tagged properties, db-parent, archive ────────
 * The agent passes a TYPE-TAGGED map { "Name": { type, value } }; buildNotionProperties turns
 * it into an ALLOWLIST-CONSTRUCTED Notion `properties` body via a CLOSED per-type table (the
 * read-side shapePropertyValue closed-switch idiom, write direction). REJECTED types (plain
 * Error, echoes only the allowed-set list, never the agent value): relation (link injection),
 * people (mention/notify + PII write), formula/rollup/created_time/last_edited_time (server-
 * computed), files (high-risk), any unknown type. It returns the built body AND the `scan`
 * array of the RAW (pre-sanitize) agent string values, so the egress secret-shape body can't
 * drift from what's written (security review I4 — scan is built INSIDE the builder). */

const NOTION_PROP_NAME_MAX = 512; // cap the agent-supplied property NAME (the Notion key)
const NOTION_PROP_VALUE_MAX = 2000; // per-string-value byte cap (Notion's rich_text item limit)
const NOTION_MULTI_SELECT_MAX = 100; // bounded multi_select array
/** Notion's three accepted date forms: date-only, or RFC3339 datetime with a Z / ±HH:MM offset. */
const NOTION_DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2}))?$/;

/** True iff the type-tagged map has at least one `type:"title"` entry (a db row's title column,
 *  whose NAME varies per schema). Used for the db-parent-create requirement + the update
 *  title double-path guard — a pre-scan, so buildNotionProperties stays create/update-agnostic. */
function hasTitleTypedProperty(raw: unknown): boolean {
  const map = asObj(raw);
  return map !== null && Object.values(map).some((s) => asObj(s)?.type === "title");
}

function buildNotionProperties(
  raw: unknown,
  tool: "notion_create_page" | "notion_update_page",
): { properties: Obj; scan: string[] } {
  const map = asObj(raw);
  if (!map || Object.keys(map).length === 0) {
    throw new Error("notion: 'properties' must be a non-empty object of { name: { type, value } }");
  }
  const properties: Obj = {};
  const scan: string[] = []; // RAW pre-sanitize string values (for the secret-shape scan)
  // Collect the RAW value (secret-shape sees it un-stripped), return the sanitized value for
  // the body (outboundSanitize REJECTs zero-width / wrapper-escape with -32027 + byte-caps).
  const clean = (v: unknown, t: string): string => {
    if (typeof v !== "string") throw new Error(`notion: a '${t}' property needs a string value`);
    scan.push(v);
    return outboundSanitize(v, { tool, maxBytes: NOTION_PROP_VALUE_MAX });
  };
  for (const [name, specRaw] of Object.entries(map)) {
    if (name.length === 0 || Buffer.byteLength(name, "utf8") > NOTION_PROP_NAME_MAX) {
      throw new Error(`notion: a property name must be 1–${NOTION_PROP_NAME_MAX} bytes`);
    }
    const spec = asObj(specRaw);
    if (spec === null || typeof spec.type !== "string") {
      throw new Error("notion: each property needs a string 'type'");
    }
    const type = spec.type;
    const value = spec.value;
    switch (type) {
      case "title":
        properties[name] = { title: [{ type: "text", text: { content: clean(value, "title") } }] };
        break;
      case "rich_text":
        properties[name] = { rich_text: [{ type: "text", text: { content: clean(value, "rich_text") } }] };
        break;
      case "number":
        if (value !== null && (typeof value !== "number" || !Number.isFinite(value))) {
          throw new Error("notion: a 'number' property needs a finite number (or null to clear)");
        }
        properties[name] = { number: value };
        break;
      case "checkbox":
        if (typeof value !== "boolean") throw new Error("notion: a 'checkbox' property needs a boolean");
        properties[name] = { checkbox: value };
        break;
      case "url": {
        // http(s) only — reject javascript:/data:/etc. (SafeSpace never follows the URL, so
        // no SSRF here, but a Notion client renders it as a clickable link → scheme-XSS guard).
        const u = clean(value, "url");
        if (!/^https?:\/\//i.test(u)) throw new Error("notion: a 'url' property needs an http(s) URL");
        properties[name] = { url: u };
        break;
      }
      case "email":
      case "phone_number":
        properties[name] = { [type]: clean(value, type) };
        break;
      case "select":
      case "status": {
        const optName = clean(value, type);
        if (optName.length === 0) throw new Error(`notion: a '${type}' property needs a non-empty option name`);
        properties[name] = { [type]: { name: optName } };
        break;
      }
      case "multi_select": {
        if (!Array.isArray(value)) throw new Error("notion: a 'multi_select' property needs a string array");
        if (value.length > NOTION_MULTI_SELECT_MAX) {
          throw new Error(`notion: a 'multi_select' allows ≤ ${NOTION_MULTI_SELECT_MAX} options`);
        }
        properties[name] = {
          multi_select: value.map((opt) => {
            const optName = clean(opt, "multi_select");
            if (optName.length === 0) throw new Error("notion: each 'multi_select' option must be a non-empty string");
            return { name: optName };
          }),
        };
        break;
      }
      case "date": {
        const d = asObj(value);
        if (d === null || typeof d.start !== "string" || !NOTION_DATE_RE.test(d.start)) {
          throw new Error("notion: a 'date' property needs { start } as a YYYY-MM-DD or RFC3339 string");
        }
        const end = d.end;
        if (end !== undefined && end !== null && (typeof end !== "string" || !NOTION_DATE_RE.test(end))) {
          throw new Error("notion: a 'date' end must be a YYYY-MM-DD or RFC3339 string");
        }
        // Date strings are RFC3339-constrained (can't encode a secret), but add them to the
        // scan anyway so the secret-shape invariant "every agent string is scanned" is literal.
        scan.push(d.start);
        if (typeof end === "string") scan.push(end);
        properties[name] = { date: { start: d.start, end: end ?? null } };
        break;
      }
      default:
        // REJECT relation / people / formula / rollup / files / created_time /
        // last_edited_time / any unknown type. NEVER echo the agent-supplied type string.
        throw new Error(
          "notion: that property type is not writable (allowed: title, rich_text, number, " +
            "checkbox, url, email, phone_number, select, status, multi_select, date)",
        );
    }
  }
  return { properties, scan };
}

/** One Notion paragraph block from plain text (an empty string → an empty paragraph). */
function paragraphBlock(content: string): Obj {
  return {
    object: "block",
    type: "paragraph",
    paragraph: { rich_text: content === "" ? [] : [{ type: "text", text: { content } }] },
  };
}

/** Build paragraph blocks from plain text: split on newlines, chunk each line to Notion's
 *  2000-char rich_text limit. Throws if it would exceed NOTION_MAX_BLOCKS (too large for
 *  one request — the caller splits across calls). */
function textToParagraphBlocks(text: string): Obj[] {
  const blocks: Obj[] = [];
  for (const line of text.split("\n")) {
    if (line.length === 0) {
      blocks.push(paragraphBlock(""));
    } else {
      for (let i = 0; i < line.length; i += NOTION_RICH_TEXT_MAX) {
        blocks.push(paragraphBlock(line.slice(i, i + NOTION_RICH_TEXT_MAX)));
      }
    }
    if (blocks.length > NOTION_MAX_BLOCKS) {
      throw new Error(
        `notion: content is too large (> ${NOTION_MAX_BLOCKS} paragraph blocks) — split it across calls`,
      );
    }
  }
  return blocks;
}

/** A required non-empty agent-authored text field (title / content). */
function requireWriteText(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || v.trim().length === 0) {
    throw new Error(`notion: '${key}' must be a non-empty string`);
  }
  return v;
}

/* ── B6.1 wave A — exported prepare/validate helpers (SINGLE SOURCE for the egress
 * descriptor's `extract` + the handler). Each reproduces the tool's former pre-gate
 * validation + scan assembly VERBATIM (same order, same plain-Error messages) and returns
 * the egress `body` (what the F3a secret-shape scan sees) PLUS the request-body pieces. The
 * descriptor's extract calls the helper and takes `.egressBody`; the handler calls it and
 * consumes the pieces (re-runs it — cheap, pure, identical result). The egress gate is now
 * PIPELINE-FIRED (with-context.ts), so no notion handler calls enforceNotionWriteEgressGates
 * (anti-double-fire — egress-callsite.test.ts enforces both directions). Order note: for a
 * PAGE-parent create the raw title is NOT sanitized here (the handler sanitizes it AFTER the
 * gate, byte-identical to the pre-A ordering: gate → titleS → children); for a DB-parent
 * create / an update the sanitize happens INSIDE buildNotionProperties, which ran before the
 * gate pre-A too — so the -32027 vs -32035 order is preserved. ── */

export interface NotionCreatePagePrep {
  /** The combined agent text the F3a secret-shape scan sees (SafeSpace-authored `\n` join). */
  readonly egressBody: string;
  /** WHICH parent the agent named (exactly one) + its id as the agent gave it (validated). A
   *  "database" parent is resolved to its sole data source by the HANDLER (network) — never here
   *  (this helper is pure: the egress descriptor's `extract` runs it before the gate). */
  readonly parent: { readonly kind: "page" | "database" | "data_source"; readonly id: string };
  /** page-parent only — the RAW title (the handler sanitizes it after the gate). */
  readonly title: string | undefined;
  /** database / data-source parent — the already-built (sanitized) allowlist-constructed properties. */
  readonly properties: Obj | undefined;
  /** RAW page content (the handler sanitizes it into paragraph blocks). */
  readonly text: string | undefined;
}

export function prepareNotionCreatePage(args: Record<string, unknown>): NotionCreatePagePrep {
  // Presence = "not undefined" (a null / "" / wrong-typed value still COUNTS as given, so a
  // pair like { parent_page_id, parent_data_source_id: null } is rejected, not silently ignored;
  // the id itself is then validated by requireNotionId).
  const hasPageParent = args.parent_page_id !== undefined;
  const hasDbParent = args.parent_database_id !== undefined;
  const hasDsParent = args.parent_data_source_id !== undefined;
  if ([hasPageParent, hasDbParent, hasDsParent].filter(Boolean).length !== 1) {
    throw new Error(
      "notion_create_page: provide exactly one of 'parent_page_id', 'parent_database_id' or 'parent_data_source_id'",
    );
  }
  const text = args.text === undefined ? undefined : requireWriteText(args, "text");

  if (hasPageParent) {
    if (args.properties !== undefined) {
      throw new Error("notion_create_page: 'properties' is only valid under 'parent_database_id' or 'parent_data_source_id' (a page-parented page has only a title)");
    }
    const parentId = requireNotionId(args, "parent_page_id");
    const title = requireWriteText(args, "title");
    return {
      egressBody: text === undefined ? title : `${title}\n${text}`,
      parent: { kind: "page", id: parentId },
      title,
      properties: undefined,
      text,
    };
  }

  // database / data-source parent (a row)
  if (args.title !== undefined) {
    throw new Error("notion_create_page: under 'parent_database_id' or 'parent_data_source_id' the title goes in 'properties' (the data source's title column), not the 'title' param");
  }
  if (!hasTitleTypedProperty(args.properties)) {
    throw new Error("notion_create_page: under 'parent_database_id' or 'parent_data_source_id' 'properties' must include the data source's title column (a type 'title' entry)");
  }
  const kind = hasDsParent ? "data_source" : "database";
  const parentId = requireNotionId(args, hasDsParent ? "parent_data_source_id" : "parent_database_id");
  const { properties, scan } = buildNotionProperties(args.properties, "notion_create_page");
  if (text !== undefined) scan.push(text); // raw page content into the secret-shape scan
  return {
    egressBody: scan.join("\n"),
    parent: { kind, id: parentId },
    title: undefined,
    properties,
    text,
  };
}

export function validateNotionAppendBlocksArgs(args: Record<string, unknown>): {
  pageId: string;
  text: string;
} {
  const pageId = requireNotionId(args, "page_id");
  const text = requireWriteText(args, "text");
  return { pageId, text };
}

export interface NotionUpdatePagePrep {
  /** The combined RAW agent strings the F3a secret-shape scan sees. */
  readonly egressBody: string;
  readonly pageId: string;
  /** The already-built (sanitized) allowlist-constructed properties (may be empty). */
  readonly properties: Obj;
  readonly archived: boolean | undefined;
}

export function prepareNotionUpdatePage(args: Record<string, unknown>): NotionUpdatePagePrep {
  const pageId = requireNotionId(args, "page_id");
  const hasTitle = args.title !== undefined;
  const hasProps = args.properties !== undefined;
  const hasArchived = args.archived !== undefined;
  if (!hasTitle && !hasProps && !hasArchived) {
    throw new Error("notion_update_page: provide at least one of 'title', 'properties', or 'archived'");
  }
  if (hasTitle && hasTitleTypedProperty(args.properties)) {
    throw new Error("notion_update_page: set the title via EITHER 'title' OR a type 'title' entry in 'properties', not both");
  }
  let archived: boolean | undefined;
  if (hasArchived) {
    if (typeof args.archived !== "boolean") throw new Error("notion_update_page: 'archived' must be a boolean");
    archived = args.archived;
  }

  const properties: Obj = {};
  const scan: string[] = []; // RAW agent strings for the secret-shape scan
  if (hasProps) {
    const built = buildNotionProperties(args.properties, "notion_update_page");
    Object.assign(properties, built.properties);
    scan.push(...built.scan);
  }
  if (hasTitle) {
    const title = requireWriteText(args, "title");
    scan.push(title);
    properties.title = titleProperties(
      outboundSanitize(title, { tool: "notion_update_page", maxBytes: NOTION_TITLE_MAX_BYTES }),
    ).title;
  }
  return { egressBody: scan.join("\n"), pageId, properties, archived };
}

/** Resolve the create-page PARENT to its wire shape. page → `{page_id}`. data source →
 *  `{type:"data_source_id", data_source_id}` as given. database → the sole data source (the
 *  resolver, 0 / >1 → error) then — because the 2026-03-11 reference documents the
 *  `data_source_id` parent as the page parent and says nothing about how a `database_id`
 *  parent behaves — a data_source_id parent, guarded by RE-RETRIEVING that data source with the
 *  same credential immediately before the POST and requiring its parent database to be the
 *  database the agent asked for (any mismatch / malformed → fail closed, zero POSTs). The one
 *  residual race (the source moves between this check and the POST) is bounded in SECURITY.md. */
async function resolveCreateParent(
  token: string,
  parent: NotionCreatePagePrep["parent"],
  deps: NotionReadDeps,
): Promise<Obj> {
  if (parent.kind === "page") return { page_id: parent.id };
  if (parent.kind === "data_source") return { type: "data_source_id", data_source_id: parent.id };
  const dataSourceId = await resolveSoleDataSource(token, parent.id, deps);
  // Identity, not just parentage: the re-retrieved body must BE the resolved data source and
  // its parent must be exactly the requested database (any other shape → zero POSTs).
  verifyDataSourceWrite(
    await notionApiGet({ token, path: `/v1/data_sources/${dataSourceId}`, fetchImpl: deps.fetchImpl }),
    dataSourceId,
    parent.id,
  );
  return { type: "data_source_id", data_source_id: dataSourceId };
}

/** POST /v1/pages — create a page under a PAGE parent (title + optional text) OR a row under a
 *  DATABASE / DATA SOURCE parent (a type-tagged `properties` map that MUST carry the title
 *  column). Exactly one parent. The `\n` join in every egress `body` is a SafeSpace-authored scan
 *  separator (NOT agent input) — it only shapes what the secret-shape scanner sees, never the
 *  request body. Arbitrary `properties` are row-only — a page-parented page has only a title. */
export async function notionCreatePage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  // Egress (model B — F3a secret-shape on the combined text) is PIPELINE-FIRED before this
  // handler (with-context.ts via notionCreatePageEgressDescriptor); prep reproduces the same
  // validation + scan assembly the pre-A handler ran (single source with the descriptor's
  // extract). The handler must NOT call the gate (anti-double-fire).
  const prep = prepareNotionCreatePage(args);
  // Sanitize order preserved 1:1 with pre-A: the title (page-parent) before the children,
  // and the row-parent properties were sanitized inside prepareNotionCreatePage's
  // buildNotionProperties (matching the pre-A "buildNotionProperties before the gate" order).
  const properties =
    prep.properties !== undefined
      ? prep.properties
      : titleProperties(
          outboundSanitize(prep.title!, { tool: "notion_create_page", maxBytes: NOTION_TITLE_MAX_BYTES }),
        );
  const children =
    prep.text === undefined
      ? []
      : textToParagraphBlocks(
          outboundSanitize(prep.text, { tool: "notion_create_page", maxBytes: NOTION_TEXT_MAX_BYTES }),
        );
  // ALL local validation + sanitize is done; the only network before the POST is the
  // read-only parent resolution (database parent only).
  const parent = await resolveCreateParent(token, prep.parent, deps);
  const data = await notionApiPost({
    token,
    path: "/v1/pages",
    body: { parent, properties, children },
    fetchImpl: deps.fetchImpl,
  });
  return shapePage(data);
}

/** PATCH /v1/blocks/{id}/children — append paragraph blocks (text) to an existing page. */
export async function notionAppendBlocks(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  // Egress PIPELINE-FIRED before this handler (notionAppendBlocksEgressDescriptor; the gate
  // scans the RAW text). The handler must NOT call the gate (anti-double-fire).
  const { pageId, text } = validateNotionAppendBlocksArgs(args);

  const children = textToParagraphBlocks(
    outboundSanitize(text, { tool: "notion_append_blocks", maxBytes: NOTION_TEXT_MAX_BYTES }),
  );
  const data =
    asObj(
      await notionApiPatch({
        token,
        path: `/v1/blocks/${pageId}/children`,
        body: { children },
        fetchImpl: deps.fetchImpl,
      }),
    ) ?? {};
  return { id: canonId(pageId), appended_blocks: children.length, has_more: data.has_more === true };
}

/** PATCH /v1/pages/{id} — rename (set `title`), update arbitrary `properties` (v1.105:
 *  type-tagged, db rows only), and/or `archived` (archive true / restore false — a REVERSIBLE
 *  Trash move, NOT an F4 permanent delete). At least one of title/properties/archived. The
 *  `title` convenience param sets the literal "title" property (page-parented pages); a db
 *  row's title column has its own name → set it via `properties` (and NOT both at once). */
export async function notionUpdatePage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  // Egress (model B — F3a secret-shape on the combined RAW agent strings, empty for an
  // archive-only call → no-op) is PIPELINE-FIRED before this handler
  // (notionUpdatePageEgressDescriptor). The handler must NOT call the gate.
  const { pageId, properties, archived } = prepareNotionUpdatePage(args);

  const body: Obj = {};
  if (Object.keys(properties).length > 0) body.properties = properties;
  // The tool key stays `archived`; the 2026-03-11 wire field is `in_trash` (true = Trash, false = restore).
  if (archived !== undefined) body.in_trash = archived;
  const data = await notionApiPatch({ token, path: `/v1/pages/${pageId}`, body, fetchImpl: deps.fetchImpl });
  return shapePage(data);
}
