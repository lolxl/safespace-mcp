// v1.46 B1 — drive_create_file / drive_copy_file / drive_rename_file.
// SDK-level mock via setGaxiosHandler (same surface as drive-folder-ops.test.ts).
// Security-relevant assertions: text-only MIME allowlist on create, name
// control-char + byte caps, and that rename sends NO addParents/removeParents
// (so the drive-whitelist ancestor cache is never invalidated by a rename).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { driveCopyFile, driveCreateFile, driveRenameFile } from "./handlers";
import type { ToolContext } from "./types";

const FAKE_CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};

// Valid Drive ids: ^[A-Za-z0-9_-]{20,}$
const FILE_ID = "1FileAAAAAAAAAAAAAAAAAA";
const PARENT_NEW = "1FolderNewAAAAAAAAAAAAA";

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("drive_create_file", () => {
  test("happy path (root, text/plain) — multipart upload, returns File resource", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let hitUrl = "";
    let method = "";
    setGaxiosHandler(async (opts) => {
      hitUrl = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      return {
        data: { id: "1NewFileAAAAAAAAAAAAAAA", name: "notes.txt", mimeType: "text/plain", size: "5" },
        status: 200,
      };
    });
    const res = (await driveCreateFile(FAKE_CTX, { name: "notes.txt", content: "hello" })) as {
      id: string;
      mimeType: string;
    };
    expect(res.id).toBe("1NewFileAAAAAAAAAAAAAAA");
    expect(res.mimeType).toBe("text/plain");
    expect(method).toBe("POST");
    // Media uploads route to the /upload/drive/v3/files endpoint.
    expect(hitUrl).toContain("/drive/v3/files");
  });

  test("happy path with parent_id + custom text mime_type", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({
      data: { id: "1NewFileAAAAAAAAAAAAAAA", name: "data.json", mimeType: "application/json", parents: [PARENT_NEW] },
      status: 200,
    }));
    const res = (await driveCreateFile(FAKE_CTX, {
      name: "data.json",
      content: '{"k":1}',
      mime_type: "application/json",
      parent_id: PARENT_NEW,
    })) as { parents: string[] };
    expect(res.parents).toEqual([PARENT_NEW]);
  });

  test("rejects empty name", async () => {
    await expect(driveCreateFile(FAKE_CTX, { name: "", content: "x" })).rejects.toThrow(/non-empty 'name'/);
  });

  test("rejects control characters in name (CRLF injection class)", async () => {
    await expect(driveCreateFile(FAKE_CTX, { name: "a\r\nb", content: "x" })).rejects.toThrow(/control characters/);
  });

  test("rejects name over 1000 bytes UTF-8", async () => {
    await expect(driveCreateFile(FAKE_CTX, { name: "a".repeat(1001), content: "x" })).rejects.toThrow(/exceeds 1000 bytes/);
  });

  test("rejects missing / non-string content", async () => {
    await expect(driveCreateFile(FAKE_CTX, { name: "x" })).rejects.toThrow(/requires a 'content' string/);
    await expect(driveCreateFile(FAKE_CTX, { name: "x", content: 123 })).rejects.toThrow(/requires a 'content' string/);
  });

  test("accepts empty-string content (empty text file)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: "1NewFileAAAAAAAAAAAAAAA", name: "empty.txt", mimeType: "text/plain" }, status: 200 }));
    const res = (await driveCreateFile(FAKE_CTX, { name: "empty.txt", content: "" })) as { id: string };
    expect(res.id).toBe("1NewFileAAAAAAAAAAAAAAA");
  });

  test("rejects content over 5 MB", async () => {
    const big = "a".repeat(5 * 1024 * 1024 + 1);
    await expect(driveCreateFile(FAKE_CTX, { name: "x", content: big })).rejects.toThrow(/exceeds .* bytes \(5 MB/);
  });

  test("rejects binary mime_type (application/pdf)", async () => {
    await expect(
      driveCreateFile(FAKE_CTX, { name: "x", content: "y", mime_type: "application/pdf" }),
    ).rejects.toThrow(/must be a text MIME type/);
  });

  test("rejects mime_type with trailing injection (anchored regex)", async () => {
    await expect(
      driveCreateFile(FAKE_CTX, { name: "x", content: "y", mime_type: "text/plain evil" }),
    ).rejects.toThrow(/must be a text MIME type/);
  });

  test("rejects invalid parent_id (URL paste)", async () => {
    await expect(
      driveCreateFile(FAKE_CTX, { name: "x", content: "y", parent_id: "https://drive.google.com/foo" }),
    ).rejects.toThrow(/'parent_id' invalid/);
  });

  test("maps upstream Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 500 });
    });
    await expect(driveCreateFile(FAKE_CTX, { name: "x", content: "y" })).rejects.toBeDefined();
  });
});

describe("drive_copy_file", () => {
  test("happy path (rename + reparent) — hits files/{id}/copy", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      return { data: { id: "1CopyAAAAAAAAAAAAAAAAAA", name: "Copy", mimeType: "text/plain", parents: [PARENT_NEW] }, status: 200 };
    });
    const res = (await driveCopyFile(FAKE_CTX, { file_id: FILE_ID, name: "Copy", parent_id: PARENT_NEW })) as {
      id: string;
      parents: string[];
    };
    expect(res.id).toBe("1CopyAAAAAAAAAAAAAAAAAA");
    expect(res.parents).toEqual([PARENT_NEW]);
    expect(method).toBe("POST");
    expect(url).toContain(`/drive/v3/files/${FILE_ID}/copy`);
  });

  test("happy path (bare copy, no name/parent)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: "1CopyAAAAAAAAAAAAAAAAAA", name: "Copy of x" }, status: 200 }));
    const res = (await driveCopyFile(FAKE_CTX, { file_id: FILE_ID })) as { id: string };
    expect(res.id).toBe("1CopyAAAAAAAAAAAAAAAAAA");
  });

  test("rejects invalid file_id", async () => {
    await expect(driveCopyFile(FAKE_CTX, { file_id: "bad/id" })).rejects.toThrow(/valid 'file_id'/);
  });

  test("rejects control characters in name", async () => {
    await expect(driveCopyFile(FAKE_CTX, { file_id: FILE_ID, name: "a\nb" })).rejects.toThrow(/control characters/);
  });

  test("rejects name over 1000 bytes UTF-8", async () => {
    await expect(driveCopyFile(FAKE_CTX, { file_id: FILE_ID, name: "a".repeat(1001) })).rejects.toThrow(/exceeds 1000 bytes/);
  });

  test("rejects invalid parent_id (URL paste)", async () => {
    await expect(
      driveCopyFile(FAKE_CTX, { file_id: FILE_ID, parent_id: "https://drive.google.com/foo" }),
    ).rejects.toThrow(/'parent_id' invalid/);
  });

  test("maps upstream Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 404 });
    });
    await expect(driveCopyFile(FAKE_CTX, { file_id: FILE_ID })).rejects.toBeDefined();
  });
});

describe("drive_rename_file", () => {
  test("happy path (name) — PATCH files/{id}, NO addParents/removeParents", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    let params: Record<string, unknown> | undefined;
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      params = opts.params;
      return { data: { id: FILE_ID, name: "renamed.txt" }, status: 200 };
    });
    const res = (await driveRenameFile(FAKE_CTX, { file_id: FILE_ID, name: "renamed.txt" })) as { name: string };
    expect(res.name).toBe("renamed.txt");
    expect(method).toBe("PATCH");
    expect(url).toContain(`/drive/v3/files/${FILE_ID}`);
    // SECURITY: rename must NOT manipulate parents (that's drive_move_file's job,
    // which is the only Drive write that invalidates the whitelist cache).
    expect(params?.addParents).toBeUndefined();
    expect(params?.removeParents).toBeUndefined();
  });

  test("happy path (description only)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: FILE_ID, name: "x", description: "new desc" }, status: 200 }));
    const res = (await driveRenameFile(FAKE_CTX, { file_id: FILE_ID, description: "new desc" })) as { description: string };
    expect(res.description).toBe("new desc");
  });

  test("rejects when neither name nor description provided", async () => {
    await expect(driveRenameFile(FAKE_CTX, { file_id: FILE_ID })).rejects.toThrow(/at least one of \{name, description\}/);
  });

  test("rejects control characters in name", async () => {
    await expect(driveRenameFile(FAKE_CTX, { file_id: FILE_ID, name: "a\r\nb" })).rejects.toThrow(/control characters/);
  });

  test("rejects name over 1000 bytes UTF-8", async () => {
    await expect(driveRenameFile(FAKE_CTX, { file_id: FILE_ID, name: "a".repeat(1001) })).rejects.toThrow(/exceeds 1000 bytes/);
  });

  test("rejects description over 8000 bytes UTF-8", async () => {
    await expect(
      driveRenameFile(FAKE_CTX, { file_id: FILE_ID, description: "a".repeat(8001) }),
    ).rejects.toThrow(/'description' exceeds 8000 bytes/);
  });

  test("allows empty-string description (clears it)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { id: FILE_ID, name: "x", description: "" }, status: 200 }));
    const res = (await driveRenameFile(FAKE_CTX, { file_id: FILE_ID, description: "" })) as { id: string };
    expect(res.id).toBe(FILE_ID);
  });

  test("rejects invalid file_id", async () => {
    await expect(driveRenameFile(FAKE_CTX, { file_id: "not a real id", name: "x" })).rejects.toThrow(/valid 'file_id'/);
  });

  test("maps upstream Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 403 });
    });
    await expect(driveRenameFile(FAKE_CTX, { file_id: FILE_ID, name: "x" })).rejects.toBeDefined();
  });
});
