// v1.77/v1.78 — the Notion read handlers. v1.78 — Notion is now the 3rd OAuth source
// (was a class-B service-token connector in v1.77; the handlers are unchanged — only the
// credential acquisition + routing changed).
//
// docs/v1.78-notion-oauth.md. Five READ tools over api.notion.com:
//   notion_search · notion_get_page · notion_get_block_children ·
//   notion_query_database · notion_get_database
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
const FILTER_TYPES: ReadonlySet<string> = new Set(["page", "database"]);

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

/** An optional opaque pagination cursor (Notion-issued; the agent passes it back). */
function optionalCursor(args: Record<string, unknown>): string | undefined {
  const v = args.start_cursor;
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length === 0 || v.length > CURSOR_MAX) {
    throw new Error(`notion: 'start_cursor' must be a non-empty string ≤ ${CURSOR_MAX} chars`);
  }
  return v;
}

/* ── curated response shapers (pick ONLY safe fields; never the raw object) ── */

type Obj = Record<string, unknown>;
const asObj = (v: unknown): Obj | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null;

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

/** A page's title (the property whose type is "title") or a database's top-level title. */
function extractTitle(o: Obj): string {
  if (Array.isArray(o.title)) return extractRichText(o.title); // database
  const props = asObj(o.properties);
  if (props) {
    for (const v of Object.values(props)) {
      const p = asObj(v);
      if (p && p.type === "title") return extractRichText(p.title);
    }
  }
  return "";
}

/** The parent kind ("page_id" | "database_id" | "workspace") — a controlled enum (skip). */
function parentType(o: Obj): string | null {
  const p = asObj(o.parent);
  return p && typeof p.type === "string" ? p.type : null;
}

/** Extract a simplified value per Notion property type — scalar / text / array. The
 *  envelope wraps every emitted string. Unknown/complex types (files / relation / rollup)
 *  → null (only the controlled `type` label is kept). */
function shapePropertyValue(p: Obj): unknown {
  switch (p.type) {
    case "title":
      return extractRichText(p.title);
    case "rich_text":
      return extractRichText(p.rich_text);
    case "number":
      return p.number ?? null;
    case "checkbox":
      return p.checkbox ?? null;
    case "url":
      return p.url ?? null;
    case "email":
      return p.email ?? null;
    case "phone_number":
      return p.phone_number ?? null;
    case "select": {
      const s = asObj(p.select);
      return s ? (s.name ?? null) : null;
    }
    case "status": {
      const s = asObj(p.status);
      return s ? (s.name ?? null) : null;
    }
    case "multi_select":
      return Array.isArray(p.multi_select)
        ? p.multi_select.map((s) => asObj(s)?.name ?? null)
        : [];
    case "date": {
      const d = asObj(p.date);
      return d ? { start: d.start ?? null, end: d.end ?? null } : null;
    }
    case "people":
      return Array.isArray(p.people)
        ? p.people.map((u) => {
            const o = asObj(u);
            return o ? (o.name ?? o.id ?? null) : null;
          })
        : [];
    case "created_time":
      return p.created_time ?? null;
    case "last_edited_time":
      return p.last_edited_time ?? null;
    case "formula": {
      // Closed-set switch on the formula result type — NOT a dynamic f[f.type] read
      // (which would use an attacker-influenced string as a property key).
      const f = asObj(p.formula);
      if (!f) return null;
      switch (f.type) {
        case "string":
          return f.string ?? null;
        case "number":
          return f.number ?? null;
        case "boolean":
          return f.boolean ?? null;
        case "date": {
          const d = asObj(f.date);
          return d ? { start: d.start ?? null, end: d.end ?? null } : null;
        }
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
 *  keys). `type` is a controlled enum (skip); `value` wraps. */
function shapeProperties(v: unknown): Array<{ name: string; type: unknown; value: unknown }> {
  const props = asObj(v);
  if (!props) return [];
  return Object.entries(props).map(([name, raw]) => {
    const p = asObj(raw) ?? {};
    return { name, type: p.type, value: shapePropertyValue(p) };
  });
}

function shapeSearchResult(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: o.object,
    id: o.id,
    title: extractTitle(o),
    url: o.url,
    parent_type: parentType(o),
    archived: o.archived,
    last_edited_time: o.last_edited_time,
  };
}

function shapePage(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: o.object,
    id: o.id,
    url: o.url,
    archived: o.archived,
    parent_type: parentType(o),
    created_time: o.created_time,
    last_edited_time: o.last_edited_time,
    title: extractTitle(o),
    properties: shapeProperties(o.properties),
  };
}

/** Block types whose payload object carries a `rich_text` array (the readable content).
 *  A CLOSED set — so the per-block lookup is NOT a dynamic `o[o.type]` read with an
 *  attacker-influenced key (mirrors the shapePropertyValue formula fix). Any other block
 *  type (image / divider / table / a future type) → text "" (same as the old fallback). */
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
    id: o.id,
    type: o.type,
    has_children: o.has_children,
    text: inner ? extractRichText(inner.rich_text) : "",
  };
}

function shapeDatabaseSchema(v: unknown): Array<{ name: string; type: unknown }> {
  const props = asObj(v);
  if (!props) return [];
  return Object.entries(props).map(([name, raw]) => ({ name, type: asObj(raw)?.type ?? null }));
}

function shapeDatabase(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    object: o.object,
    id: o.id,
    url: o.url,
    title: extractRichText(o.title),
    created_time: o.created_time,
    last_edited_time: o.last_edited_time,
    properties: shapeDatabaseSchema(o.properties),
  };
}

/* ── handlers ── */

/** POST /v1/search — find pages / databases by title. */
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
    throw new Error("notion: 'filter_type' must be 'page' or 'database'");
  }
  const body: Obj = { page_size: clampPageSize(args.page_size) };
  if (typeof query === "string") body.query = query;
  if (typeof filterType === "string") body.filter = { value: filterType, property: "object" };
  const cursor = optionalCursor(args);
  if (cursor !== undefined) body.start_cursor = cursor;
  const data = asObj(await notionApiPost({ token, path: "/v1/search", body, fetchImpl: deps.fetchImpl })) ?? {};
  return {
    results: Array.isArray(data.results) ? data.results.map(shapeSearchResult) : [],
    next_cursor: data.next_cursor ?? null,
    has_more: data.has_more ?? false,
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
    next_cursor: data.next_cursor ?? null,
    has_more: data.has_more ?? false,
  };
}

/** POST /v1/databases/{id}/query — a database's rows (pages), paginated. v1: no
 *  filter/sorts → an allowlist-constructed body (page_size + optional start_cursor). */
export async function notionQueryDatabase(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "database_id");
  const body: Obj = { page_size: clampPageSize(args.page_size) };
  const cursor = optionalCursor(args);
  if (cursor !== undefined) body.start_cursor = cursor;
  const data =
    asObj(await notionApiPost({ token, path: `/v1/databases/${id}/query`, body, fetchImpl: deps.fetchImpl })) ?? {};
  return {
    results: Array.isArray(data.results) ? data.results.map(shapePage) : [],
    next_cursor: data.next_cursor ?? null,
    has_more: data.has_more ?? false,
  };
}

/** GET /v1/databases/{id} — the database schema (columns). */
export async function notionGetDatabase(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: NotionReadDeps = {},
): Promise<unknown> {
  const token = requireNotion(ctx).getAccessToken();
  const id = requireNotionId(args, "database_id");
  const data = await notionApiGet({ token, path: `/v1/databases/${id}`, fetchImpl: deps.fetchImpl });
  return shapeDatabase(data);
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
  readonly parent: { page_id: string } | { database_id: string };
  /** page-parent only — the RAW title (the handler sanitizes it after the gate). */
  readonly title: string | undefined;
  /** db-parent only — the already-built (sanitized) allowlist-constructed properties. */
  readonly properties: Obj | undefined;
  /** RAW page content (the handler sanitizes it into paragraph blocks). */
  readonly text: string | undefined;
}

export function prepareNotionCreatePage(args: Record<string, unknown>): NotionCreatePagePrep {
  const hasPageParent = args.parent_page_id !== undefined;
  const hasDbParent = args.parent_database_id !== undefined;
  if (hasPageParent === hasDbParent) {
    throw new Error("notion_create_page: provide exactly one of 'parent_page_id' or 'parent_database_id'");
  }
  const text = args.text === undefined ? undefined : requireWriteText(args, "text");

  if (hasPageParent) {
    if (args.properties !== undefined) {
      throw new Error("notion_create_page: 'properties' is only valid under 'parent_database_id' (a page-parented page has only a title)");
    }
    const parentId = requireNotionId(args, "parent_page_id");
    const title = requireWriteText(args, "title");
    return {
      egressBody: text === undefined ? title : `${title}\n${text}`,
      parent: { page_id: parentId },
      title,
      properties: undefined,
      text,
    };
  }

  // db-parent
  if (args.title !== undefined) {
    throw new Error("notion_create_page: under 'parent_database_id' the title goes in 'properties' (the db's title column), not the 'title' param");
  }
  if (!hasTitleTypedProperty(args.properties)) {
    throw new Error("notion_create_page: under 'parent_database_id' 'properties' must include the database's title column (a type 'title' entry)");
  }
  const databaseId = requireNotionId(args, "parent_database_id");
  const { properties, scan } = buildNotionProperties(args.properties, "notion_create_page");
  if (text !== undefined) scan.push(text); // raw page content into the secret-shape scan
  return {
    egressBody: scan.join("\n"),
    parent: { database_id: databaseId },
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

/** POST /v1/pages — create a page under a PAGE parent (title + optional text) OR a DATABASE
 *  parent (v1.105: a type-tagged `properties` map that MUST carry the db's title column).
 *  Exactly one parent. The `\n` join in every egress `body` is a SafeSpace-authored scan
 *  separator (NOT agent input) — it only shapes what the secret-shape scanner sees, never the
 *  request body. Arbitrary `properties` are db-only — a page-parented page has only a title. */
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
  // and the db-parent properties were sanitized inside prepareNotionCreatePage's
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
  const data = await notionApiPost({
    token,
    path: "/v1/pages",
    body: { parent: prep.parent, properties, children },
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
  return { id: pageId, appended_blocks: children.length, has_more: data.has_more ?? false };
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
  if (archived !== undefined) body.archived = archived;
  const data = await notionApiPatch({ token, path: `/v1/pages/${pageId}`, body, fetchImpl: deps.fetchImpl });
  return shapePage(data);
}
