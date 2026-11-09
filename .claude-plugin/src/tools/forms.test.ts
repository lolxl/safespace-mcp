// v1.62 — Forms read-only handler tests (forms_get / forms_list_responses /
// forms_get_response), through the SDK-level setGaxiosHandler seam. Pins the
// form_id / response_id format gates, the page_size clamp, the page_token opaque
// pass-through, and the allowlist-constructed time_after filter (no raw filter
// string). Response untrusted-content wrapping is the withToolContext pipeline's
// job (covered by the sanitize suite), not the handler — so it is not re-tested
// here; these tests pin the handler's input gates + request construction.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { currentTier } from "../tier";
import {
  formsCreate,
  formsGet,
  formsGetResponse,
  formsListResponses,
  formsModify,
  formsUnpublish,
} from "./handlers";
import { TOOL_REGISTRY } from "./registry";
import { tierSatisfies } from "../tier";
import { classifyWriteTool } from "../policy/write-burst";
import type { Tier } from "../tier";
import { FORMS_MODIFY_ALLOWED_REQUEST_TYPES } from "./handlers/forms";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
  audit: NOOP_AUDIT,
  get tier() {
    return currentTier();
  },
};

interface CapturedOpts {
  url?: string;
  method?: string;
  params?: Record<string, unknown>;
  data?: unknown; // request body (forms_create / forms_modify, v1.63)
}
let captured: CapturedOpts | undefined;

beforeEach(async () => {
  const { resetGaxiosHandler, setGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  captured = undefined;
  setGaxiosHandler(async (o) => {
    captured = o as CapturedOpts;
    return { data: { formId: "FORM1", responses: [{ responseId: "R1" }] }, status: 200 };
  });
});
afterEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

const FID = "1AbcDEF_-ghiJKLmnop";

describe("forms_get", () => {
  test("valid id → forms.get; bad id → reject (rule not value); missing → reject", async () => {
    await formsGet(CTX, { form_id: FID });
    expect(captured?.url).toContain(`/forms/${FID}`);
    await expect(formsGet(CTX, { form_id: "bad id/space" })).rejects.toThrow(/must match/);
    await expect(formsGet(CTX, {})).rejects.toThrow(/must be a string/);
  });
});

describe("forms_list_responses", () => {
  test("valid → responses.list with formId in the path; returns data", async () => {
    const res = (await formsListResponses(CTX, { form_id: FID })) as { responses: unknown };
    expect(res.responses).toEqual([{ responseId: "R1" }]);
    expect(captured?.url).toContain(`/forms/${FID}/responses`);
  });

  test("page_size clamped [1,5000] (over-cap → 5000; valid passes; below-min → 1)", async () => {
    await formsListResponses(CTX, { form_id: FID, page_size: 99999 });
    expect(captured?.params?.pageSize).toBe(5000);
    await formsListResponses(CTX, { form_id: FID, page_size: 50 });
    expect(captured?.params?.pageSize).toBe(50);
    await formsListResponses(CTX, { form_id: FID, page_size: 0 });
    expect(captured?.params?.pageSize).toBe(1);
  });

  test("page_size non-integer → reject", async () => {
    await expect(formsListResponses(CTX, { form_id: FID, page_size: 2.5 })).rejects.toThrow(/page_size.*integer/);
    await expect(formsListResponses(CTX, { form_id: FID, page_size: "10" })).rejects.toThrow(/page_size.*integer/);
  });

  test("page_token opaque pass-through; non-string → reject", async () => {
    await formsListResponses(CTX, { form_id: FID, page_token: "CAEItoken" });
    expect(captured?.params?.pageToken).toBe("CAEItoken");
    await expect(formsListResponses(CTX, { form_id: FID, page_token: 123 })).rejects.toThrow(/page_token.*string/);
  });

  test("time_after → allowlist-constructed filter `timestamp >= <RFC3339>`; bad value → reject", async () => {
    await formsListResponses(CTX, { form_id: FID, time_after: "2026-01-31T00:00:00Z" });
    expect(captured?.params?.filter).toBe("timestamp >= 2026-01-31T00:00:00Z");
    // millis + numeric offset variants accepted
    await formsListResponses(CTX, { form_id: FID, time_after: "2026-01-31T08:30:00.500+08:00" });
    expect(captured?.params?.filter).toBe("timestamp >= 2026-01-31T08:30:00.500+08:00");
    // a raw filter-string smuggle attempt is NOT a valid RFC3339 instant → rejected
    await expect(
      formsListResponses(CTX, { form_id: FID, time_after: "timestamp >= 2020 OR 1==1" }),
    ).rejects.toThrow(/RFC3339/);
    await expect(formsListResponses(CTX, { form_id: FID, time_after: "yesterday" })).rejects.toThrow(/RFC3339/);
  });

  test("bad form_id → reject", async () => {
    await expect(formsListResponses(CTX, { form_id: "bad id" })).rejects.toThrow(/must match/);
  });
});

describe("forms_get_response", () => {
  test("valid → responses.get with formId + responseId; bad/missing response_id → reject", async () => {
    await formsGetResponse(CTX, { form_id: FID, response_id: "R_abc-123" });
    expect(captured?.url).toContain(`/forms/${FID}/responses/R_abc-123`);
    await expect(formsGetResponse(CTX, { form_id: FID, response_id: "bad id" })).rejects.toThrow(/response_id.*must match/);
    await expect(formsGetResponse(CTX, { form_id: FID })).rejects.toThrow(/response_id.*must be a string/);
    await expect(formsGetResponse(CTX, { response_id: "R1" })).rejects.toThrow(/form_id.*must be a string/);
  });
});

/* ═════════════ v1.63 — WRITE slice ═════════════ */

describe("forms_create", () => {
  test("valid title → forms.create with {info:{title}} (trimmed); gates reject", async () => {
    await formsCreate(CTX, { title: "  Signup form  " });
    expect((captured?.data as { info?: { title?: string } })?.info?.title).toBe("Signup form"); // trimmed
    // explicit unpublished:true query param (Forms treats unset as published)
    expect(captured?.params?.unpublished).toBe(true);
    await expect(formsCreate(CTX, { title: "   " })).rejects.toThrow(/non-empty/);
    await expect(formsCreate(CTX, { title: "bad\r\ntitle" })).rejects.toThrow(/CR\/LF/);
    await expect(formsCreate(CTX, { title: "x".repeat(1001) })).rejects.toThrow(/exceeds 1000 bytes/);
    await expect(formsCreate(CTX, {})).rejects.toThrow(/must be a string/);
  });
});

const REQ = (over: object) => ({ form_id: FID, requests: [over] });

describe("forms_modify — allowlist gate + DEEP SSRF/fileUpload exclusion", () => {
  test("happy path — an allowlisted createItem (text question) → batchUpdate with the requests", async () => {
    await formsModify(
      CTX,
      REQ({ createItem: { item: { title: "Q1", questionItem: { question: { textQuestion: {} } } }, location: { index: 0 } } }),
    );
    expect(captured?.url).toContain(`/forms/${FID}:batchUpdate`);
    const sent = (captured?.data as { requests?: unknown[] })?.requests;
    expect(sent).toHaveLength(1);
  });

  test("every ALLOWED top-level request type passes the gate", async () => {
    for (const t of FORMS_MODIFY_ALLOWED_REQUEST_TYPES) {
      // minimal text-only body per type (structural correctness is Google's job)
      const body = t === "updateFormInfo" ? { info: { title: "x" }, updateMask: "title" } : {};
      await expect(formsModify(CTX, REQ({ [t]: body }))).resolves.toBeDefined();
    }
  });

  test("SECURITY: image/video/file-upload content is DEEP-rejected wherever nested", async () => {
    // sourceUri nested inside a standalone imageItem
    await expect(
      formsModify(CTX, REQ({ createItem: { item: { imageItem: { image: { sourceUri: "https://evil/x.png" } } } } })),
    ).rejects.toThrow(/sourceUri|forbidden field/);
    // sourceUri nested DEEP inside a questionItem.image (not a top-level imageItem)
    await expect(
      formsModify(CTX, REQ({ createItem: { item: { questionItem: { image: { sourceUri: "https://evil/x.png" } } } } })),
    ).rejects.toThrow(/sourceUri|forbidden field/);
    // videoItem (external embed)
    await expect(
      formsModify(CTX, REQ({ createItem: { item: { videoItem: { video: { youtubeUri: "https://youtu.be/x" } } } } })),
    ).rejects.toThrow(/videoItem|forbidden field/);
    // fileUploadQuestion (Drive-artifact)
    await expect(
      formsModify(CTX, REQ({ createItem: { item: { questionItem: { question: { fileUploadQuestion: {} } } } } })),
    ).rejects.toThrow(/fileUploadQuestion|forbidden field/);
    // the same gate applies to updateItem
    await expect(
      formsModify(CTX, REQ({ updateItem: { item: { imageItem: { image: { sourceUri: "https://evil/x" } } }, updateMask: "*", location: { index: 0 } } })),
    ).rejects.toThrow(/forbidden field|sourceUri/);
    expect(captured).toBeUndefined(); // no SDK call on any rejected request
  });

  test("request shape gates: bad form_id, 0-key, 2-key, non-object, empty, over-cap, unlisted type", async () => {
    await expect(formsModify(CTX, { form_id: "bad id", requests: [{ deleteItem: {} }] })).rejects.toThrow(/must match/);
    await expect(formsModify(CTX, REQ({}))).rejects.toThrow(/exactly ONE key/);
    await expect(formsModify(CTX, REQ({ deleteItem: {}, moveItem: {} }))).rejects.toThrow(/exactly ONE key/);
    await expect(formsModify(CTX, { form_id: FID, requests: ["notanobject"] })).rejects.toThrow(/must be an object/);
    await expect(formsModify(CTX, { form_id: FID, requests: [] })).rejects.toThrow(/non-empty/);
    const tooMany = Array.from({ length: 51 }, () => ({ deleteItem: {} }));
    await expect(formsModify(CTX, { form_id: FID, requests: tooMany })).rejects.toThrow(/at most 50/);
    // a non-allowlisted top-level request type (Google could add one) → reject
    await expect(formsModify(CTX, REQ({ someFutureRequest: {} }))).rejects.toThrow(/not in allowlist/);
  });

  test("content byte cap on item/info free-text fields", async () => {
    await expect(
      formsModify(CTX, REQ({ createItem: { item: { title: "x".repeat(10 * 1024 + 1) } } })),
    ).rejects.toThrow(/exceeds 10240 bytes/);
    await expect(
      formsModify(CTX, REQ({ updateFormInfo: { info: { description: "x".repeat(10 * 1024 + 1) }, updateMask: "description" } })),
    ).rejects.toThrow(/exceeds 10240 bytes/);
  });

  test("anti-DoS: a pathologically deep item tree trips the deep-scan node budget", async () => {
    // Build a > FORMS_SCAN_MAX_NODES (5000) deep chain → the bounded scan throws
    // before exhausting CPU/stack (the budget is the DoS guard, not a forbidden key).
    let deep: Record<string, unknown> = { leaf: "x" };
    for (let i = 0; i < 5001; i++) deep = { wrap: deep };
    await expect(formsModify(CTX, REQ({ createItem: { item: deep } }))).rejects.toThrow(/node budget exceeded/);
    expect(captured).toBeUndefined(); // rejected before any SDK call
  });
});

/* ═════════════ forms_publish / forms_unpublish (setPublishSettings) ═════════════ */

const UNPUBLISHED_RESPONSE = {
  formId: FID,
  publishSettings: { publishState: { isPublished: false, isAcceptingResponses: false } },
};

async function respondWith(data: unknown): Promise<void> {
  const { setGaxiosHandler } = await import("../google-api/test-utils");
  setGaxiosHandler(async (o) => {
    captured = o as CapturedOpts;
    return { data, status: 200 };
  });
}

describe("forms_unpublish", () => {
  test("POST :setPublishSettings with {false,false}; injected args ignored; returns the API state", async () => {
    await respondWith(UNPUBLISHED_RESPONSE);
    const res = await formsUnpublish(CTX, { form_id: FID, updateMask: "*", requestBody: { x: 1 } });
    expect(captured?.method).toBe("POST");
    expect(captured?.url).toContain(`/forms/${FID}:setPublishSettings`);
    expect(captured?.data).toEqual({
      publishSettings: { publishState: { isPublished: false, isAcceptingResponses: false } },
      updateMask: "publish_state",
    });
    expect(res).toEqual({ form_id: FID, published: false, accepting_responses: false });
  });

  test("recovery > policy: works at write tier with a deny-all whitelist and send-approval ON (no gate fires)", async () => {
    const fs = await import("node:fs/promises");
    const os = await import("node:os");
    const path = await import("node:path");
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-forms-unpub-"));
    const saved = { dir: process.env.SAFESPACE_CONFIG_DIR, appr: process.env.SAFESPACE_REQUIRE_SEND_APPROVAL };
    process.env.SAFESPACE_CONFIG_DIR = tmp;
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await fs.writeFile(
      path.join(tmp, "drive-whitelist.json"),
      JSON.stringify({ schema_version: 1, updated_at: "x", entries: [] }),
      { mode: 0o600 },
    );
    try {
      await respondWith(UNPUBLISHED_RESPONSE);
      const res = await formsUnpublish({ ...CTX, tier: "write" }, { form_id: FID });
      expect(res).toEqual({ form_id: FID, published: false, accepting_responses: false });
      expect(captured?.url).toContain(":setPublishSettings");
    } finally {
      if (saved.dir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
      else process.env.SAFESPACE_CONFIG_DIR = saved.dir;
      if (saved.appr === undefined) delete process.env.SAFESPACE_REQUIRE_SEND_APPROVAL;
      else process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = saved.appr;
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  test("invalid form_id rejected before any request; API error carries the unpublish tool name", async () => {
    await expect(formsUnpublish(CTX, { form_id: "bad id" })).rejects.toThrow(/forms_unpublish: 'form_id' must match/);
    expect(captured).toBeUndefined();
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 404, errorMessage: "Form not found" });
    });
    await expect(formsUnpublish(CTX, { form_id: FID })).rejects.toThrow(/google_api_404_forms_unpublish/);
  });
});

describe("forms_publish / forms_unpublish — tier visibility", () => {
  const visible = (tool: string, tier: Tier): boolean =>
    tierSatisfies(tier, TOOL_REGISTRY[tool]!.min_tier);
  test("forms_publish is hidden at read+write, shown at share; forms_unpublish shown at write+share, hidden at read", () => {
    expect(visible("forms_publish", "read")).toBe(false);
    expect(visible("forms_publish", "write")).toBe(false);
    expect(visible("forms_publish", "share")).toBe(true);
    expect(visible("forms_unpublish", "read")).toBe(false);
    expect(visible("forms_unpublish", "write")).toBe(true);
    expect(visible("forms_unpublish", "share")).toBe(true);
  });
});

describe("forms_publish / forms_unpublish — burst bucket", () => {
  test("both count in the WRITE bucket (neither is a permanent delete)", () => {
    expect(classifyWriteTool("forms_publish", TOOL_REGISTRY.forms_publish!.min_tier)).toBe("write");
    expect(classifyWriteTool("forms_unpublish", TOOL_REGISTRY.forms_unpublish!.min_tier)).toBe("write");
  });
});
