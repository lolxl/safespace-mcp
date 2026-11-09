// v1.96 — Notion WRITE handlers: text-only paragraph-block construction, allowlist-
// constructed bodies, the requireNotion narrow (R8 cross-provider backstop), the egress
// gate (model B: F3a secret-shape, no target allowlist), the per-field outboundSanitize
// REJECT (-32027), id validation, and the token-never-leaks guard. The Notion REST API is
// mocked at the fetch seam (no network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { NOOP_AUDIT } from "../test-audit";
import { notionRouter } from "../test-notion-router";
import type { Credential, ToolContext } from "../types";
import { TOOL_REGISTRY } from "../registry";
import { notionAppendBlocks, notionCreatePage, notionUpdatePage } from "./notion";

// B6.1 wave A — the notion egress gate is now PIPELINE-FIRED (with-context.ts via each
// write tool's egress descriptor), not handler-called. The gate-DENIAL / F3a cases below
// drive the SAME registry-carried descriptor (extract → gate), the choke-point sequence.
async function fireGate(tool: string, gctx: ToolContext, args: Record<string, unknown>): Promise<void> {
  const d = TOOL_REGISTRY[tool]?.egress;
  if (d === undefined) throw new Error(`no egress descriptor on ${tool}`);
  await d.gate(gctx, d.extract(args));
}

const PARENT = "11111111-1111-1111-1111-111111111111";
const PAGE = "22222222-2222-2222-2222-222222222222";
const WS = "44444444-4444-4444-4444-444444444444";

function notionCred(token = "ntn_SECRET"): Credential {
  return { kind: "oauth", provider: "notion", accountId: WS, getAccessToken: () => token };
}
function ctx(token = "ntn_SECRET"): ToolContext {
  return { credential: notionCred(token), tier: "write", audit: NOOP_AUDIT };
}

/** A fetch stub returning `body` (JSON) with `status`; records url + init. */
function fetchStub(body: unknown = { object: "page", id: PAGE, url: "https://notion.so/x" }, status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const ENV = ["SAFESPACE_AUTONOMOUS"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("notionCreatePage — construction", () => {
  test("POSTs /v1/pages with the Bearer header + an allowlist-constructed body", async () => {
    const f = fetchStub();
    const out = await notionCreatePage(
      ctx("secret-tok"),
      { parent_page_id: PARENT, title: "Hello", text: "line one\nline two" },
      { fetchImpl: f.impl },
    );
    expect((out as { id?: unknown }).id).toBe(PAGE);
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe("https://api.notion.com/v1/pages");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer secret-tok");
    const body = JSON.parse(init.body as string);
    // ONLY parent + properties.title + children paragraph blocks (no raw block JSON).
    expect(Object.keys(body).sort()).toEqual(["children", "parent", "properties"]);
    expect(body.parent).toEqual({ page_id: PARENT });
    expect(body.properties).toEqual({ title: { title: [{ type: "text", text: { content: "Hello" } }] } });
    expect(body.children).toHaveLength(2); // two lines → two paragraph blocks
    expect(body.children[0]).toEqual({
      object: "block",
      type: "paragraph",
      paragraph: { rich_text: [{ type: "text", text: { content: "line one" } }] },
    });
  });

  test("no text → children: [] (title-only page)", async () => {
    const f = fetchStub();
    await notionCreatePage(ctx(), { parent_page_id: PARENT, title: "T" }, { fetchImpl: f.impl });
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.children).toEqual([]);
  });

  test("a > 2000-char line is chunked across paragraph blocks (Notion rich_text limit)", async () => {
    const f = fetchStub();
    await notionCreatePage(ctx(), { parent_page_id: PARENT, title: "T", text: "x".repeat(4500) }, { fetchImpl: f.impl });
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.children).toHaveLength(3); // 4500 / 2000 → 3 blocks
    expect(body.children[0].paragraph.rich_text[0].text.content.length).toBe(2000);
  });

  test("an empty line → an empty paragraph (rich_text: []), preserving spacing", async () => {
    const f = fetchStub();
    await notionCreatePage(ctx(), { parent_page_id: PARENT, title: "T", text: "one\n\nthree" }, { fetchImpl: f.impl });
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.children).toHaveLength(3);
    expect(body.children[1].paragraph.rich_text).toEqual([]); // the blank middle line
  });

  test("content exceeding NOTION_MAX_BLOCKS (100) throws (never hits Notion)", async () => {
    const f = fetchStub();
    const tooMany = Array.from({ length: 101 }, (_, i) => `line ${i}`).join("\n");
    await expect(
      notionCreatePage(ctx(), { parent_page_id: PARENT, title: "T", text: tooMany }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/too large/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("notionAppendBlocks / notionUpdatePage", () => {
  test("append PATCHes /v1/blocks/{id}/children with paragraph blocks", async () => {
    const f = fetchStub({ results: [], has_more: false });
    const out = await notionAppendBlocks(ctx(), { page_id: PAGE, text: "appended" }, { fetchImpl: f.impl });
    expect(out).toMatchObject({ id: PAGE, appended_blocks: 1 });
    const { url, init } = f.calls[0]!;
    expect(url).toBe(`https://api.notion.com/v1/blocks/${PAGE}/children`);
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(Object.keys(body)).toEqual(["children"]);
  });

  test("update PATCHes /v1/pages/{id} with only the title property", async () => {
    const f = fetchStub();
    await notionUpdatePage(ctx(), { page_id: PAGE, title: "Renamed" }, { fetchImpl: f.impl });
    const { url, init } = f.calls[0]!;
    expect(url).toBe(`https://api.notion.com/v1/pages/${PAGE}`);
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ properties: { title: { title: [{ type: "text", text: { content: "Renamed" } }] } } });
  });
});

describe("notion write — input validation (plain Error, fail-fast, never hits Notion)", () => {
  test("rejects a malformed parent/page id", async () => {
    const f = fetchStub();
    await expect(
      notionCreatePage(ctx(), { parent_page_id: "not-an-id", title: "T" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/must be a Notion id/);
    await expect(
      notionAppendBlocks(ctx(), { page_id: "nope", text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/must be a Notion id/);
    await expect(
      notionUpdatePage(ctx(), { page_id: "bad/id", title: "T" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/must be a Notion id/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects empty title / text", async () => {
    const f = fetchStub();
    await expect(
      notionCreatePage(ctx(), { parent_page_id: PARENT, title: "  " }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty/);
    await expect(
      notionAppendBlocks(ctx(), { page_id: PAGE, text: "" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("notion write — egress gate (model B: F3a secret-shape) + outbound REJECT", () => {
  test("autonomous + secret-shape body → outbound_secret_rejected (pipeline gate)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const secret = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";
    await expect(
      fireGate("notion_create_page", ctx(), { parent_page_id: PARENT, title: "T", text: secret }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });

  test("a zero-width char in the title → outbound_sanitize_rejected (-32027, never hits Notion)", async () => {
    const f = fetchStub();
    await expect(
      notionUpdatePage(ctx(), { page_id: PAGE, title: "evil​title" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
    expect(f.calls).toHaveLength(0);
  });
});

describe("notion write — credential narrow (R8) + token-no-leak", () => {
  test("a non-Notion OAuth credential (google) is refused before any write", async () => {
    const googleCtx: ToolContext = {
      credential: { kind: "oauth", provider: "google", accountId: "a@b.com", getAccessToken: () => "g" },
      tier: "write",
      audit: NOOP_AUDIT,
    };
    const f = fetchStub();
    await expect(
      notionCreatePage(googleCtx, { parent_page_id: PARENT, title: "T" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "credential_mismatch" } });
    expect(f.calls).toHaveLength(0);
  });

  test("a non-ok status → notion_api_failed, no token echoed", async () => {
    const f = fetchStub({ message: "err" }, 403);
    const err = (await notionCreatePage(ctx("super-secret-token"), { parent_page_id: PARENT, title: "T" }, { fetchImpl: f.impl }).catch((e) => e)) as {
      errorName?: string;
      errorData?: unknown;
      message?: unknown;
    };
    expect(err.errorName).toBe("notion_api_failed");
    expect(JSON.stringify({ d: err.errorData, m: String(err.message) })).not.toContain("super-secret-token");
  });
});

/* ── v1.105 — db-parent create, arbitrary type-tagged properties, archive ── */

const DB = "33333333-3333-3333-3333-333333333333";
const DS = "55555555-5555-5555-5555-555555555555";

describe("notion_create_page — db-parent + properties (v1.105; data sources 2026-03-11)", () => {
  test("POSTs a row under a database (resolved to its sole data source) with allowlist-constructed properties", async () => {
    const f = notionRouter([
      { method: "GET", path: `/v1/databases/${DB}`, body: { object: "database", id: DB, data_sources: [{ id: DS, name: "Tasks" }] } },
      { method: "GET", path: `/v1/data_sources/${DS}`, body: { object: "data_source", id: DS, parent: { type: "database_id", database_id: DB } } },
      { method: "POST", path: "/v1/pages", body: { object: "page", id: PAGE } },
    ]);
    await notionCreatePage(
      ctx(),
      {
        parent_database_id: DB,
        properties: {
          Name: { type: "title", value: "Task A" },
          Status: { type: "select", value: "Done" },
          Priority: { type: "number", value: 3 },
          Done: { type: "checkbox", value: true },
          Tags: { type: "multi_select", value: ["x", "y"] },
          Due: { type: "date", value: { start: "2026-07-01" } },
          Site: { type: "url", value: "https://example.com" },
        },
        text: "body line",
      },
      { fetchImpl: f.impl },
    );
    expect(f.trace()).toEqual([`GET /v1/databases/${DB}`, `GET /v1/data_sources/${DS}`, "POST /v1/pages"]);
    expect(f.unexpected).toEqual([]);
    const body = f.calls[2]!.body as Record<string, any>;
    expect(Object.keys(body).sort()).toEqual(["children", "parent", "properties"]);
    expect(body.parent).toEqual({ type: "data_source_id", data_source_id: DS });
    expect(body.properties.Name).toEqual({ title: [{ type: "text", text: { content: "Task A" } }] });
    expect(body.properties.Status).toEqual({ select: { name: "Done" } });
    expect(body.properties.Priority).toEqual({ number: 3 });
    expect(body.properties.Done).toEqual({ checkbox: true });
    expect(body.properties.Tags).toEqual({ multi_select: [{ name: "x" }, { name: "y" }] });
    expect(body.properties.Due).toEqual({ date: { start: "2026-07-01", end: null } });
    expect(body.properties.Site).toEqual({ url: "https://example.com" });
    expect(body.children).toHaveLength(1);
  });

  test("rejects db-parent missing a title-typed column (never hits Notion)", async () => {
    const f = fetchStub();
    await expect(
      notionCreatePage(ctx(), { parent_database_id: DB, properties: { Status: { type: "select", value: "X" } } }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/title column/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects the four illegal parent/field combinations (never hits Notion)", async () => {
    const f = fetchStub();
    const titleProp = { Name: { type: "title", value: "x" } };
    await expect(notionCreatePage(ctx(), { parent_page_id: PARENT, parent_database_id: DB, title: "T" }, { fetchImpl: f.impl })).rejects.toThrow(/exactly one/);
    await expect(notionCreatePage(ctx(), { title: "T" }, { fetchImpl: f.impl })).rejects.toThrow(/exactly one/);
    await expect(notionCreatePage(ctx(), { parent_page_id: PARENT, title: "T", properties: titleProp }, { fetchImpl: f.impl })).rejects.toThrow(/only valid under 'parent_database_id'/);
    await expect(notionCreatePage(ctx(), { parent_database_id: DB, title: "T", properties: titleProp }, { fetchImpl: f.impl })).rejects.toThrow(/title goes in 'properties'/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("notion properties — type allowlist + value-shape validation (v1.105)", () => {
  const mk = (props: Record<string, unknown>) => ({
    parent_data_source_id: DS,
    properties: { Name: { type: "title", value: "t" }, ...props },
  });

  for (const type of ["relation", "people", "formula", "rollup", "files", "created_time", "last_edited_time", "bogus"]) {
    test(`rejects the non-writable type '${type}' (never hits Notion)`, async () => {
      const f = fetchStub();
      await expect(notionCreatePage(ctx(), mk({ X: { type, value: "v" } }), { fetchImpl: f.impl })).rejects.toThrow(/not writable/);
      expect(f.calls).toHaveLength(0);
    });
  }

  test("rejects a wrong value shape for each type (never hits Notion)", async () => {
    const f = fetchStub();
    const cases: Array<Record<string, unknown>> = [
      { X: { type: "number", value: "3" } },
      { X: { type: "checkbox", value: "yes" } },
      { X: { type: "select", value: 1 } },
      { X: { type: "multi_select", value: "a" } },
      { X: { type: "date", value: "2026-07-01" } },
      { X: { type: "date", value: { start: "soon" } } },
      { X: { type: "url", value: "javascript:alert(1)" } }, // non-http(s) scheme rejected
    ];
    for (const props of cases) {
      await expect(notionCreatePage(ctx(), mk(props), { fetchImpl: f.impl })).rejects.toThrow();
    }
    expect(f.calls).toHaveLength(0);
  });

  test("multi_select > 100 options + an over-long property NAME are rejected", async () => {
    const f = fetchStub();
    await expect(
      notionCreatePage(ctx(), mk({ Tags: { type: "multi_select", value: Array.from({ length: 101 }, (_, i) => `o${i}`) } }), { fetchImpl: f.impl }),
    ).rejects.toThrow(/multi_select/);
    await expect(
      notionCreatePage(ctx(), mk({ ["x".repeat(513)]: { type: "rich_text", value: "v" } }), { fetchImpl: f.impl }),
    ).rejects.toThrow(/property name/);
    expect(f.calls).toHaveLength(0);
  });

  test("number:null clears the value; date accepts an end", async () => {
    const f = fetchStub();
    await notionCreatePage(
      ctx(),
      mk({ N: { type: "number", value: null }, D: { type: "date", value: { start: "2026-07-01", end: "2026-07-02" } } }),
      { fetchImpl: f.impl },
    );
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.properties.N).toEqual({ number: null });
    expect(body.properties.D).toEqual({ date: { start: "2026-07-01", end: "2026-07-02" } });
  });

  test("a zero-width property value → outbound_sanitize_rejected (-32027)", async () => {
    const f = fetchStub();
    await expect(
      notionCreatePage(ctx(), mk({ S: { type: "select", value: "ev​il" } }), { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "outbound_sanitize_rejected" });
    expect(f.calls).toHaveLength(0);
  });

  test("a secret-shaped property value is caught by the egress gate (autonomous, pipeline gate)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const secret = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";
    await expect(
      fireGate("notion_create_page", ctx(), mk({ Note: { type: "rich_text", value: secret } })),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
  });
});

describe("notion_update_page — properties + archived (v1.105)", () => {
  test("properties-only update PATCHes { properties }", async () => {
    const f = fetchStub();
    await notionUpdatePage(ctx(), { page_id: PAGE, properties: { Status: { type: "select", value: "Done" } } }, { fetchImpl: f.impl });
    expect(JSON.parse(f.calls[0]!.init.body as string)).toEqual({ properties: { Status: { select: { name: "Done" } } } });
  });

  test("archived true / false PATCHes { in_trash } (reversible)", async () => {
    const f = fetchStub();
    await notionUpdatePage(ctx(), { page_id: PAGE, archived: true }, { fetchImpl: f.impl });
    // 2026-03-11: the tool key stays `archived`; the WIRE field is `in_trash`.
    expect(JSON.parse(f.calls[0]!.init.body as string)).toEqual({ in_trash: true });
    const f2 = fetchStub();
    await notionUpdatePage(ctx(), { page_id: PAGE, archived: false }, { fetchImpl: f2.impl });
    expect(JSON.parse(f2.calls[0]!.init.body as string)).toEqual({ in_trash: false });
  });

  test("title + properties + archived combine into one PATCH", async () => {
    const f = fetchStub();
    await notionUpdatePage(
      ctx(),
      { page_id: PAGE, title: "Renamed", properties: { P: { type: "number", value: 1 } }, archived: false },
      { fetchImpl: f.impl },
    );
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.in_trash).toBe(false);
    expect(body.archived).toBeUndefined();
    expect(body.properties.title).toEqual({ title: [{ type: "text", text: { content: "Renamed" } }] });
    expect(body.properties.P).toEqual({ number: 1 });
  });

  test("none-of-the-three / title+title-property collision / non-boolean archived → reject (never hits Notion)", async () => {
    const f = fetchStub();
    await expect(notionUpdatePage(ctx(), { page_id: PAGE }, { fetchImpl: f.impl })).rejects.toThrow(/at least one/);
    await expect(
      notionUpdatePage(ctx(), { page_id: PAGE, title: "X", properties: { Name: { type: "title", value: "Y" } } }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/EITHER 'title' OR/);
    await expect(
      notionUpdatePage(ctx(), { page_id: PAGE, archived: "yes" as unknown as boolean }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/'archived' must be a boolean/);
    expect(f.calls).toHaveLength(0);
  });
});
