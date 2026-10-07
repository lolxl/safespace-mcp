// v1.128 Q3-B — drive_share_file share_type=anyone is approval-gated; share_type=user is not.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { oauthCred, NOOP_AUDIT } from "../test-audit";
import { currentTier } from "../../tier";
import { driveShareFile } from "./drive";
import { loadPendingSends, pendingSendsPath } from "../../auth/send-approval-store";
import type { ToolContext } from "../types";

const VALID_FILE_ID = "1ABCdefGHIjklMNOpqrSTUvwxYZ012345";
const ENV = ["SAFESPACE_REQUIRE_SEND_APPROVAL", "SAFESPACE_CONFIG_DIR", "SAFESPACE_TIER", "SAFESPACE_RECIPIENT_ALLOW"];

describe("drive_share_file — supervised approval (Q3-B)", () => {
  const saved: Record<string, string | undefined> = {};
  let tmpDir: string;
  const ctx: ToolContext = {
    credential: oauthCred("alice@example.com", () => "tok"),
    audit: NOOP_AUDIT,
    get tier() {
      return currentTier();
    },
  };

  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-drive-appr-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
    process.env.SAFESPACE_TIER = "share";
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    delete process.env.SAFESPACE_RECIPIENT_ALLOW;
    const { __internal: whitelistInternal } = await import("../../policy/drive-whitelist");
    whitelistInternal.resetSingletons();
    const { __internal: allowlistInternal } = await import("../../policy/recipient-allowlist");
    allowlistInternal.resetSingletons();
    const { resetGaxiosHandler } = await import("../../google-api/test-utils");
    resetGaxiosHandler();
  });
  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    const { __internal: whitelistInternal } = await import("../../policy/drive-whitelist");
    whitelistInternal.resetSingletons();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  test("share_type=anyone + flag on → send_approval_required; no SDK call; target stored", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      driveShareFile(ctx, { file_id: VALID_FILE_ID, share_type: "anyone", role: "reader" }),
    ).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "awaiting_approval" },
    });
    expect(handlerCalled).toBe(false);
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs).toHaveLength(1);
    expect(recs[0]!.target).toEqual({
      kind: "drive_share",
      file_id: VALID_FILE_ID,
      share_type: "anyone",
      role: "reader",
    });
  });

  test("share_type=user + flag on is NOT approval-gated (SDK still runs)", async () => {
    const { setGaxiosHandler } = await import("../../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: "perm_user" }, status: 200 }));
    const out = (await driveShareFile(ctx, {
      file_id: VALID_FILE_ID,
      share_type: "user",
      role: "reader",
      target_email: "bob@example.com",
      expiration_days: 7,
    })) as { id: string };
    expect(out.id).toBe("perm_user");
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });
});
