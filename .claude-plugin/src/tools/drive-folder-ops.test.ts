// v1.42 A3 + A4 — drive_create_folder / drive_move_file / drive_list_permissions.
// SDK-level mock via setGaxiosHandler (same surface as handlers.test.ts).
// Security-critical assertion: drive_move_file clears the drive-whitelist
// ancestor cache on success (§3.1 — stale false-allow prevention).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { driveCreateFolder, driveListPermissions, driveMoveFile } from "./handlers";
import { __internal, getAncestorCache } from "../policy/drive-whitelist";
import { MCPError } from "../errors";
import type { ToolContext } from "./types";

const FAKE_CTX: ToolContext = { allowedAccounts: null,
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};

// Valid Drive ids: ^[A-Za-z0-9_-]{20,}$
const FILE_ID = "1FileAAAAAAAAAAAAAAAAAA";
const PARENT_OLD = "1FolderOldAAAAAAAAAAAAA";
const PARENT_NEW = "1FolderNewAAAAAAAAAAAAA";

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  __internal.resetSingletons();
});

describe("drive_create_folder", () => {
  test("happy path (root) — returns created File resource", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let hitUrl = "";
    setGaxiosHandler(async (opts) => {
      hitUrl = opts.url ?? "";
      return {
        data: { id: "1NewFolderAAAAAAAAAAAAA", name: "Reports", mimeType: "application/vnd.google-apps.folder", parents: [] },
        status: 200,
      };
    });
    const res = (await driveCreateFolder(FAKE_CTX, { name: "Reports" })) as { id: string; mimeType: string };
    expect(res.id).toBe("1NewFolderAAAAAAAAAAAAA");
    expect(res.mimeType).toBe("application/vnd.google-apps.folder");
    expect(hitUrl).toContain("/drive/v3/files");
  });

  test("happy path with parent_id", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({
      data: { id: "1NewFolderAAAAAAAAAAAAA", name: "Sub", mimeType: "application/vnd.google-apps.folder", parents: [PARENT_NEW] },
      status: 200,
    }));
    const res = (await driveCreateFolder(FAKE_CTX, { name: "Sub", parent_id: PARENT_NEW })) as { parents: string[] };
    expect(res.parents).toEqual([PARENT_NEW]);
  });

  test("rejects empty name", async () => {
    await expect(driveCreateFolder(FAKE_CTX, { name: "" })).rejects.toThrow(/non-empty 'name'/);
  });

  test("rejects control characters in name (CRLF injection class)", async () => {
    await expect(driveCreateFolder(FAKE_CTX, { name: "Reports\r\nX" })).rejects.toThrow(/control characters/);
    await expect(driveCreateFolder(FAKE_CTX, { name: "a b" })).rejects.toThrow(/control characters/);
  });

  test("rejects name over 1000 bytes UTF-8", async () => {
    await expect(driveCreateFolder(FAKE_CTX, { name: "a".repeat(1001) })).rejects.toThrow(/exceeds 1000 bytes/);
  });

  test("rejects invalid parent_id (URL paste)", async () => {
    await expect(
      driveCreateFolder(FAKE_CTX, { name: "x", parent_id: "https://drive.google.com/foo" }),
    ).rejects.toThrow(/'parent_id' invalid/);
  });

  test("maps upstream Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 500 });
    });
    await expect(driveCreateFolder(FAKE_CTX, { name: "x" })).rejects.toBeDefined();
  });
});

describe("drive_move_file", () => {
  test("happy path (add + remove parents) — returns {id,name,parents}", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let method = "";
    let url = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      url = opts.url ?? "";
      return { data: { id: FILE_ID, name: "moved.txt", parents: [PARENT_NEW] }, status: 200 };
    });
    const res = (await driveMoveFile(FAKE_CTX, {
      file_id: FILE_ID,
      add_parents: [PARENT_NEW],
      remove_parents: [PARENT_OLD],
    })) as { parents: string[] };
    expect(res.parents).toEqual([PARENT_NEW]);
    expect(method).toBe("PATCH");
    expect(url).toContain(`/drive/v3/files/${FILE_ID}`);
  });

  test("happy path (add only, no remove)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: FILE_ID, name: "f", parents: [PARENT_OLD, PARENT_NEW] }, status: 200 }));
    const res = (await driveMoveFile(FAKE_CTX, { file_id: FILE_ID, add_parents: [PARENT_NEW] })) as { id: string };
    expect(res.id).toBe(FILE_ID);
  });

  test("SECURITY §3.1 — clears the ancestor cache on successful move", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    // Seed a stale ancestor-cache entry: FILE_ID's prior walk found PARENT_OLD.
    const cache = getAncestorCache();
    cache.set(FILE_ID, new Set([PARENT_OLD]));
    expect(cache.size()).toBe(1);

    setGaxiosHandler(async () => ({ data: { id: FILE_ID, name: "f", parents: [PARENT_NEW] }, status: 200 }));
    await driveMoveFile(FAKE_CTX, { file_id: FILE_ID, add_parents: [PARENT_NEW], remove_parents: [PARENT_OLD] });

    // Same singleton — must be empty so a later drive_share_file re-walks.
    expect(getAncestorCache().size()).toBe(0);
  });

  test("does NOT clear cache when the move fails", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    const cache = getAncestorCache();
    cache.set(FILE_ID, new Set([PARENT_OLD]));
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 404 });
    });
    await expect(
      driveMoveFile(FAKE_CTX, { file_id: FILE_ID, add_parents: [PARENT_NEW] }),
    ).rejects.toBeDefined();
    // Cache untouched — the file did not actually move.
    expect(getAncestorCache().size()).toBe(1);
  });

  test("rejects invalid file_id", async () => {
    await expect(driveMoveFile(FAKE_CTX, { file_id: "bad/id", add_parents: [PARENT_NEW] })).rejects.toThrow(/valid 'file_id'/);
  });

  test("rejects missing add_parents", async () => {
    await expect(driveMoveFile(FAKE_CTX, { file_id: FILE_ID })).rejects.toThrow(/'add_parents' is required/);
  });

  test("rejects empty add_parents array", async () => {
    await expect(driveMoveFile(FAKE_CTX, { file_id: FILE_ID, add_parents: [] })).rejects.toThrow(/non-empty array/);
  });

  test("rejects invalid parent id inside add_parents", async () => {
    await expect(driveMoveFile(FAKE_CTX, { file_id: FILE_ID, add_parents: ["short"] })).rejects.toThrow(/invalid folder id/);
  });
});

describe("drive_list_permissions", () => {
  test("happy path — returns permissions with displayName + emailAddress in raw output", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      return {
        data: {
          permissions: [
            { id: "p1", type: "user", role: "reader", emailAddress: "bob@example.com", displayName: "Bob" },
            { id: "anyoneWithLink", type: "anyone", role: "reader" },
          ],
        },
        status: 200,
      };
    });
    const res = (await driveListPermissions(FAKE_CTX, { file_id: FILE_ID })) as {
      permissions: Array<{ emailAddress?: string; displayName?: string }>;
    };
    expect(url).toContain(`/drive/v3/files/${FILE_ID}/permissions`);
    // Handler returns RAW — sanitize tree-walk wraps displayName/emailAddress downstream.
    expect(res.permissions[0]?.emailAddress).toBe("bob@example.com");
    expect(res.permissions[0]?.displayName).toBe("Bob");
  });

  test("rejects invalid file_id", async () => {
    await expect(driveListPermissions(FAKE_CTX, { file_id: "not a real id" })).rejects.toThrow(/valid 'file_id'/);
  });

  test("maps upstream Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 403 });
    });
    await expect(driveListPermissions(FAKE_CTX, { file_id: FILE_ID })).rejects.toBeDefined();
  });
});
