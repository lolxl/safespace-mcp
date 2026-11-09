// forms_publish — the outbound share. It follows the drive_share_file anyone-link
// path (a Form id IS a Drive file id): handler tier re-check -> drive-whitelist ->
// supervised send-approval -> setPublishSettings. Every denial must leave the wire
// untouched (no setPublishSettings request).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { driveShareFile, formsPublish } from "./handlers";
import { approvePending, loadPendingSends, pendingSendsPath } from "../auth/send-approval-store";
import type { ToolContext } from "./types";
import type { Tier } from "../tier";

const FID = "1AbcDEF_-ghiJKLmnopQRSTUV";
const OTHER = "1ZzzzzzzzzzzzzzzzzzzzzzzzzZ";
const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_REQUIRE_SEND_APPROVAL", "SAFESPACE_AUTONOMOUS"];
const PUBLISHED = {
  formId: FID,
  publishSettings: { publishState: { isPublished: true, isAcceptingResponses: true } },
};

const ctxAt = (tier: Tier): ToolContext => ({
  credential: oauthCred("alice@example.com", () => "ya29.fake"),
  audit: NOOP_AUDIT,
  tier,
});

interface Req {
  url?: string;
  method?: string;
  data?: unknown;
}
let reqs: Req[];
const publishReqs = (): Req[] => reqs.filter((r) => r.url?.includes(":setPublishSettings"));

let tmp: string;
const saved: Record<string, string | undefined> = {};

async function resetWhitelist(): Promise<void> {
  const { __internal } = await import("../policy/drive-whitelist");
  __internal.resetSingletons();
}
async function writeWhitelist(entries: unknown[]): Promise<void> {
  await fs.writeFile(
    path.join(tmp, "drive-whitelist.json"),
    JSON.stringify({ schema_version: 1, updated_at: "x", entries }),
    { mode: 0o600 },
  );
}
const entry = (type: "file" | "folder", id: string) => ({
  type,
  id,
  label: "t",
  added_at: "2026-01-01T00:00:00.000Z",
});

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-forms-pub-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  delete process.env.SAFESPACE_REQUIRE_SEND_APPROVAL;
  delete process.env.SAFESPACE_AUTONOMOUS;
  await resetWhitelist();
  const { resetGaxiosHandler, setGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  reqs = [];
  setGaxiosHandler(async (o) => {
    reqs.push(o as Req);
    // Drive ancestry lookup (files.get) -> a file with no parents; else the publish reply.
    if ((o as Req).url?.includes("/drive/")) return { data: { parents: [] }, status: 200 };
    return { data: PUBLISHED, status: 200 };
  });
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  await resetWhitelist();
  await fs.rm(tmp, { recursive: true, force: true });
});

describe("forms_publish — request shape (share tier, policy off)", () => {
  test("POST :setPublishSettings with the exact allowlist-constructed body; returns the API state", async () => {
    const res = await formsPublish(ctxAt("share"), { form_id: FID });
    expect(reqs).toHaveLength(1); // policy off -> no ancestry walk
    expect(reqs[0]!.method).toBe("POST");
    expect(reqs[0]!.url).toContain(`/forms/${FID}:setPublishSettings`);
    expect(reqs[0]!.data).toEqual({
      publishSettings: { publishState: { isPublished: true, isAcceptingResponses: true } },
      updateMask: "publish_state",
    });
    expect(res).toEqual({ form_id: FID, published: true, accepting_responses: true });
  });

  test("SECURITY: injected extra args never reach the request body", async () => {
    await formsPublish(ctxAt("share"), {
      form_id: FID,
      requestBody: { publishSettings: { publishState: { isPublished: false } } },
      publishSettings: {},
      updateMask: "*",
      is_published: false,
    });
    expect(publishReqs()).toHaveLength(1);
    expect(publishReqs()[0]!.data).toEqual({
      publishSettings: { publishState: { isPublished: true, isAcceptingResponses: true } },
      updateMask: "publish_state",
    });
  });

  test("reports what the API says, not what was asked", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({
      data: {
        formId: FID,
        publishSettings: { publishState: { isPublished: true, isAcceptingResponses: false } },
      },
      status: 200,
    }));
    expect(await formsPublish(ctxAt("share"), { form_id: FID })).toEqual({
      form_id: FID,
      published: true,
      accepting_responses: false,
    });
  });

  test("invalid / missing form_id rejected BEFORE any request (rule, not value)", async () => {
    for (const bad of ["bad id/space", "../etc", "a".repeat(201), "x\r\ny", ""]) {
      await expect(formsPublish(ctxAt("share"), { form_id: bad })).rejects.toThrow(
        /forms_publish: 'form_id' must match/,
      );
    }
    await expect(formsPublish(ctxAt("share"), {})).rejects.toThrow(/must be a string/);
    await expect(formsPublish(ctxAt("share"), { form_id: 123 })).rejects.toThrow(/must be a string/);
    expect(reqs).toEqual([]);
  });

  test("API errors map like the other forms tools", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    const run = async (status: number, errorMessage: string): Promise<{ message: string }> => {
      setGaxiosHandler(async () => {
        throw makeGaxiosError({ status, errorMessage });
      });
      try {
        await formsPublish(ctxAt("share"), { form_id: FID });
      } catch (e) {
        return e as { message: string };
      }
      throw new Error("expected throw");
    };
    expect((await run(404, "Form not found")).message).toContain("google_api_404_forms_publish");
    expect((await run(401, "Token expired")).message).toContain("google_api_unauthorized_forms_publish");
    expect((await run(500, "boom")).message).toContain("google_api_upstream_500_forms_publish");
    expect((await run(429, "slow down")).message).toContain("rate_limited");
  });
});

describe("forms_publish — gate 1: tier re-check (closes `safespace exec`)", () => {
  test("tier read/write -> share_target_forbidden{anyone_requires_share_tier}; no request at all", async () => {
    for (const tier of ["read", "write"] as const) {
      await expect(formsPublish(ctxAt(tier), { form_id: FID })).rejects.toMatchObject({
        errorName: "share_target_forbidden",
        errorData: { reason: "anyone_requires_share_tier", current_tier: tier, required_tier: "share" },
      });
    }
    expect(reqs).toEqual([]);
  });
});

describe("forms_publish — gate 2: drive-whitelist (same function as drive_share_file)", () => {
  test("default-deny (entries=[]) -> share_denied_by_policy; NO setPublishSettings sent", async () => {
    await writeWhitelist([]);
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(publishReqs()).toEqual([]);
  });

  test("form id not under a whitelisted folder/file -> denied; no setPublishSettings", async () => {
    await writeWhitelist([entry("folder", OTHER), entry("file", OTHER)]);
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(reqs.some((r) => r.url?.includes("/drive/"))).toBe(true); // ancestry was walked
    expect(publishReqs()).toEqual([]);
  });

  test("whitelisted by file id -> allowed, then published", async () => {
    await writeWhitelist([entry("file", FID)]);
    const res = await formsPublish(ctxAt("share"), { form_id: FID });
    expect(res).toEqual({ form_id: FID, published: true, accepting_responses: true });
    expect(publishReqs()).toHaveLength(1);
  });

  test("whitelisted by ancestor folder (files.get parents) -> allowed", async () => {
    await writeWhitelist([entry("folder", OTHER)]);
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async (o) => {
      reqs.push(o as Req);
      if ((o as Req).url?.includes("/drive/")) return { data: { parents: [OTHER] }, status: 200 };
      return { data: PUBLISHED, status: 200 };
    });
    await formsPublish(ctxAt("share"), { form_id: FID });
    expect(publishReqs()).toHaveLength(1);
  });

  test("fail-closed: malformed whitelist file -> denied; no setPublishSettings", async () => {
    await fs.writeFile(path.join(tmp, "drive-whitelist.json"), "{not json", { mode: 0o600 });
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(publishReqs()).toEqual([]);
  });

  test("fail-closed: ancestry lookup failure (403) -> denied; no setPublishSettings", async () => {
    await writeWhitelist([entry("folder", OTHER)]);
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async (o) => {
      reqs.push(o as Req);
      throw makeGaxiosError({ status: 403, errorMessage: "nope" });
    });
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(publishReqs()).toEqual([]);
  });

  test("autonomous mode + no whitelist file -> deny-by-default (F2); no setPublishSettings", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    await resetWhitelist();
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(publishReqs()).toEqual([]);
  });
});

describe("forms_publish — gate 3: supervised send-approval", () => {
  beforeEach(() => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
  });

  test("flag on -> send_approval_required; pending bound to the form id; NO setPublishSettings", async () => {
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "awaiting_approval" },
    });
    expect(publishReqs()).toEqual([]);
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs).toHaveLength(1);
    expect(recs[0]!.tool).toBe("forms_publish");
    expect(recs[0]!.body).toBe(""); // fixed summary: no form content
    expect(recs[0]!.recipients).toEqual([]);
    expect(recs[0]!.target).toEqual({
      kind: "drive_share",
      file_id: FID,
      share_type: "anyone",
      role: "reader",
    });
  });

  test("order: a whitelist denial happens BEFORE approval (no pending created)", async () => {
    await writeWhitelist([]);
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_denied_by_policy",
    });
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("order: a tier denial happens BEFORE approval (no pending created)", async () => {
    await expect(formsPublish(ctxAt("write"), { form_id: FID })).rejects.toMatchObject({
      errorName: "share_target_forbidden",
    });
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("owner-approved retry is consumed and the publish goes through", async () => {
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "send_approval_required",
    });
    const [rec] = await loadPendingSends(pendingSendsPath(), Date.now());
    await approvePending(pendingSendsPath(), rec!.pending_id, Date.now());
    const res = await formsPublish(ctxAt("share"), { form_id: FID });
    expect(res).toEqual({ form_id: FID, published: true, accepting_responses: true });
    expect(publishReqs()).toHaveLength(1);
  });
});

// Both tools bind the SAME typed approval target ({kind:"drive_share", file_id, share_type:"anyone",
// role:"reader"}); isolation rests solely on `tool` being part of the fingerprint. These reciprocal
// tests pin that at the handler level: an approval for one tool must never release the other.
describe("forms_publish <-> drive_share_file — approvals are NOT interchangeable", () => {
  const permReqs = (): Req[] => reqs.filter((r) => r.url?.includes("/permissions"));
  const shareArgs = { file_id: FID, share_type: "anyone", role: "reader" };
  const approveTool = async (tool: string): Promise<void> => {
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    const rec = recs.find((r) => r.tool === tool);
    expect(rec).toBeDefined();
    await approvePending(pendingSendsPath(), rec!.pending_id, Date.now());
  };
  const statusOf = async (tool: string): Promise<string | undefined> =>
    (await loadPendingSends(pendingSendsPath(), Date.now())).find((r) => r.tool === tool)?.status;

  beforeEach(async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await writeWhitelist([entry("file", FID)]); // the id passes the whitelist for BOTH tools
  });

  test("approved forms_publish does not release drive_share_file on the same id; it stays consumable by forms_publish", async () => {
    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "send_approval_required",
    });
    await approveTool("forms_publish");

    await expect(driveShareFile(ctxAt("share"), shareArgs)).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "awaiting_approval" },
    });
    expect(permReqs()).toEqual([]); // no permissions.create reached Google
    expect(publishReqs()).toEqual([]);
    expect(await statusOf("forms_publish")).toBe("approved"); // untouched, not consumed
    expect(await statusOf("drive_share_file")).toBe("pending"); // its own, separate record

    const res = await formsPublish(ctxAt("share"), { form_id: FID });
    expect(res).toEqual({ form_id: FID, published: true, accepting_responses: true });
    expect(publishReqs()).toHaveLength(1);
    expect(permReqs()).toEqual([]);
  });

  test("approved drive_share_file does not release forms_publish on the same id; it stays consumable by drive_share_file", async () => {
    await expect(driveShareFile(ctxAt("share"), shareArgs)).rejects.toMatchObject({
      errorName: "send_approval_required",
    });
    await approveTool("drive_share_file");

    await expect(formsPublish(ctxAt("share"), { form_id: FID })).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "awaiting_approval" },
    });
    expect(publishReqs()).toEqual([]); // setPublishSettings never sent
    expect(permReqs()).toEqual([]);
    expect(await statusOf("drive_share_file")).toBe("approved"); // untouched, not consumed
    expect(await statusOf("forms_publish")).toBe("pending");

    await driveShareFile(ctxAt("share"), shareArgs);
    expect(permReqs()).toHaveLength(1);
    expect(publishReqs()).toEqual([]);
  });
});
