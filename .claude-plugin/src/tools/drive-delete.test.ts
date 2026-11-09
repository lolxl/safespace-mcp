// drive_trash_file / drive_delete_file — handler tests. SDK-level mock via
// setGaxiosHandler. Security-relevant assertions: the SAFESPACE_DRIVE_DELETE_TARGETS
// gate fires BEFORE any mutating request, the denial never echoes the file id, a
// permanent delete of a FOLDER is refused, and trash of a folder is allowed.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { driveDeleteFile, driveTrashFile } from "./handlers";
import type { ToolContext } from "./types";
import { MAX_WALK_DEPTH } from "../policy/drive-whitelist";
import {
  __internal as policyInternal,
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
} from "../policy/drive-delete-targets";
import { MCPError } from "../errors";
import { TOOL_REGISTRY } from "./registry";

const CTX_WRITE: ToolContext = {
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};

const FILE_ID = "1FileAAAAAAAAAAAAAAAAAA";
const FOLDER_ID = "1FolderAAAAAAAAAAAAAAAA"; // the allowlisted folder
const OTHER_FOLDER = "1FolderBBBBBBBBBBBBBBBB";
const FOLDER_MIME = "application/vnd.google-apps.folder";

interface Req {
  method: string;
  id: string;
  fields: unknown;
  body: unknown;
}

/** Install a Drive mock. `tree` maps id → parents (or "ERR" → 500 / "404"; unknown ids → parentless). `mime`
 *  maps id → mimeType (null / "" allowed to exercise fail-closed); `extra` merges
 *  more metadata (e.g. shortcutDetails) per id. Returns the request log. */
async function installDrive(
  tree: Record<string, string[] | "ERR" | "404">,
  mime: Record<string, string | null> = {},
  extra: Record<string, Record<string, unknown>> = {},
): Promise<Req[]> {
  const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
  const log: Req[] = [];
  setGaxiosHandler(async (opts) => {
    const method = (opts.method ?? "GET").toUpperCase();
    const id = decodeURIComponent((opts.url ?? "").split("/files/")[1]?.split("?")[0] ?? "");
    log.push({ method, id, fields: opts.params?.fields, body: opts.data });
    if (method === "GET") {
      const entry = tree[id];
      if (entry === "ERR") throw makeGaxiosError({ status: 500 });
      if (entry === "404") throw makeGaxiosError({ status: 404 });
      // Unknown ids resolve as parentless (root-level) files.
      return {
        data: { parents: entry ?? [], mimeType: id in mime ? mime[id] : "text/plain", ...extra[id] },
        status: 200,
      };
    }
    if (method === "PATCH") return { data: { id }, status: 200 };
    return { data: "", status: 204 }; // DELETE
  });
  return log;
}

const mutations = (log: Req[]): Req[] => log.filter((r) => r.method !== "GET");

const saved: Record<string, string | undefined> = {};
beforeEach(async () => {
  for (const k of [ENV_TARGETS, ENV_TARGETS_EXTRA, "SAFESPACE_AUTONOMOUS"]) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  policyInternal.resetSingletons();
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});
afterEach(() => {
  for (const k of Object.keys(saved)) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  policyInternal.resetSingletons();
});

async function denial(p: Promise<unknown>): Promise<MCPError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(MCPError);
    return e as MCPError;
  }
  throw new Error("expected a denial");
}

describe("registry + validation", () => {
  test("both tools are min_tier=write, Drive-scoped, additionalProperties:false", () => {
    for (const name of ["drive_trash_file", "drive_delete_file"]) {
      const def = TOOL_REGISTRY[name]!;
      expect(def.min_tier).toBe("write");
      expect(def.inputSchema).toMatchObject({ required: ["file_id"], additionalProperties: false });
    }
    expect(TOOL_REGISTRY.drive_delete_file!.description).toContain("PERMANENTLY DESTRUCTIVE");
    expect(TOOL_REGISTRY.drive_trash_file!.description).toContain("RECOVERABLE");
  });

  for (const [name, fn] of [
    ["drive_trash_file", driveTrashFile],
    ["drive_delete_file", driveDeleteFile],
  ] as const) {
    test(`${name}: missing / non-string / short / URL file_id → validation error, no request`, async () => {
      const log = await installDrive({});
      await expect(fn(CTX_WRITE, {})).rejects.toThrow(/file_id/);
      await expect(fn(CTX_WRITE, { file_id: 42 })).rejects.toThrow(/file_id/);
      await expect(fn(CTX_WRITE, { file_id: "short" })).rejects.toThrow(/did you paste a URL/);
      await expect(
        fn(CTX_WRITE, { file_id: "https://drive.google.com/file/d/abc/view" }),
      ).rejects.toThrow(/did you paste a URL/);
      expect(log).toEqual([]);
    });

    test(`${name}: read tier → scope_mismatch, no request`, async () => {
      const log = await installDrive({});
      const e = await denial(fn({ ...CTX_WRITE, tier: "read" }, { file_id: FILE_ID }));
      expect(e.errorName).toBe("scope_mismatch");
      expect(log).toEqual([]);
    });
  }
});

describe("drive_trash_file", () => {
  test("allowlist OFF → files.update trashed:true, returns {file_id, trashed:true}", async () => {
    const log = await installDrive({});
    const res = await driveTrashFile(CTX_WRITE, { file_id: FILE_ID });
    expect(res).toEqual({ file_id: FILE_ID, trashed: true });
    expect(log).toHaveLength(1); // no ancestry walk when OFF
    expect(log[0]).toMatchObject({ method: "PATCH", id: FILE_ID, body: { trashed: true } });
  });

  test("active + file entry hit → proceeds", async () => {
    process.env[ENV_TARGETS] = `file:${FILE_ID}`;
    const log = await installDrive({});
    await driveTrashFile(CTX_WRITE, { file_id: FILE_ID });
    expect(mutations(log)).toHaveLength(1);
  });

  test("active + folder-ancestor hit (grandparent) → proceeds", async () => {
    process.env[ENV_TARGETS_EXTRA] = `folder:${FOLDER_ID}`;
    const log = await installDrive({
      [FILE_ID]: [OTHER_FOLDER],
      [OTHER_FOLDER]: [FOLDER_ID],
    });
    const res = await driveTrashFile(CTX_WRITE, { file_id: FILE_ID });
    expect(res).toEqual({ file_id: FILE_ID, trashed: true });
    expect(mutations(log)).toHaveLength(1);
  });

  test("active + MISS → -32060 not_in_allowlist, NO id anywhere, NO mutating request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: [OTHER_FOLDER], [OTHER_FOLDER]: [] });
    const e = await denial(driveTrashFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(e.code).toBe(-32060);
    expect(e.errorData).toEqual({ reason: "not_in_allowlist" });
    const wire = JSON.stringify(e.toJsonRpc()) + e.message;
    expect(wire).not.toContain(FILE_ID);
    expect(wire).not.toContain(OTHER_FOLDER);
    expect(wire).not.toContain(FOLDER_ID);
    expect(mutations(log)).toEqual([]);
  });

  test("ancestor fetch error → deny (ancestry_unverifiable), NO mutating request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: "ERR" });
    const e = await denial(driveTrashFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(mutations(log)).toEqual([]);
  });

  test("ancestor 404 → deny, NO mutating request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: "404" });
    const e = await denial(driveTrashFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(mutations(log)).toEqual([]);
  });

  test("depth exceeded → deny, fetches bounded, NO mutating request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const ids = Array.from({ length: MAX_WALK_DEPTH + 4 }, (_, i) => `1Deep${String(i).padStart(2, "0")}AAAAAAAAAAAAAAAAA`);
    const tree: Record<string, string[]> = {};
    ids.forEach((id, i) => {
      tree[id] = [i + 1 < ids.length ? ids[i + 1]! : FOLDER_ID];
    });
    const log = await installDrive(tree);
    const e = await denial(driveTrashFile(CTX_WRITE, { file_id: ids[0]! }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(log.length).toBe(MAX_WALK_DEPTH);
    expect(mutations(log)).toEqual([]);
  });

  test("trash of a FOLDER is allowed (recoverable) — no mimeType refusal", async () => {
    const log = await installDrive({}, { [OTHER_FOLDER]: FOLDER_MIME });
    const res = await driveTrashFile(CTX_WRITE, { file_id: OTHER_FOLDER });
    expect(res).toEqual({ file_id: OTHER_FOLDER, trashed: true });
    expect(mutations(log)).toHaveLength(1);
  });

  test("autonomous + unset allowlist → deny-all (F2), NO mutating request", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const log = await installDrive({ [FILE_ID]: [] });
    const e = await denial(driveTrashFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(mutations(log)).toEqual([]);
  });

  test("SDK failure after the gate → mapped Google error", async () => {
    const { setGaxiosHandler, makeGaxiosError } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      throw makeGaxiosError({ status: 403 });
    });
    const e = await driveTrashFile(CTX_WRITE, { file_id: FILE_ID }).then(
      () => undefined,
      (err: unknown) => err,
    );
    expect(e).toBeInstanceOf(Error);
    // A mapped Google error (NOT the allowlist denial).
    expect(e).not.toBeInstanceOf(MCPError);
    expect(String((e as Error).message)).toMatch(/403|drive_trash_file/);
  });
});

describe("drive_delete_file", () => {
  test("allowlist OFF, regular file → get(parents,mimeType) then files.delete; returns {file_id, deleted:true}", async () => {
    const log = await installDrive({});
    const res = await driveDeleteFile(CTX_WRITE, { file_id: FILE_ID });
    expect(res).toEqual({ file_id: FILE_ID, deleted: true });
    expect(log.map((r) => r.method)).toEqual(["GET", "DELETE"]);
    expect(log[0]!.fields).toBe("parents,mimeType");
  });

  test("FOLDER → refused with a drive_trash_file hint, NO delete request", async () => {
    const log = await installDrive({}, { [OTHER_FOLDER]: FOLDER_MIME });
    await expect(driveDeleteFile(CTX_WRITE, { file_id: OTHER_FOLDER })).rejects.toThrow(
      /drive_trash_file/,
    );
    expect(mutations(log)).toEqual([]);
  });

  test("allowlisted FOLDER is still refused (allowlist does not lift the folder rule)", async () => {
    process.env[ENV_TARGETS] = `folder:${OTHER_FOLDER}`;
    const log = await installDrive({}, { [OTHER_FOLDER]: FOLDER_MIME });
    await expect(driveDeleteFile(CTX_WRITE, { file_id: OTHER_FOLDER })).rejects.toThrow(
      /folder/i,
    );
    expect(mutations(log)).toEqual([]);
  });

  test("missing mimeType → fail closed, NO delete request", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    const methods: string[] = [];
    setGaxiosHandler(async (opts) => {
      methods.push((opts.method ?? "GET").toUpperCase());
      return { data: {}, status: 200 };
    });
    await expect(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID })).rejects.toThrow(
      /could not determine/,
    );
    expect(methods).toEqual(["GET"]);
  });

  for (const [label, mimeValue] of [["null", null], ["empty string", ""]] as const) {
    test(`mimeType ${label} → fail closed, NO delete request`, async () => {
      const log = await installDrive({}, { [FILE_ID]: mimeValue });
      await expect(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID })).rejects.toThrow(
        /could not determine/,
      );
      expect(mutations(log)).toEqual([]);
    });
  }

  test("request sequence is exactly [GET target(parents,mimeType), ...ancestor GETs, DELETE] — no GET after the gate", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({
      [FILE_ID]: [OTHER_FOLDER],
      [OTHER_FOLDER]: [FOLDER_ID],
    });
    await driveDeleteFile(CTX_WRITE, { file_id: FILE_ID });
    expect(log.map((r) => `${r.method} ${r.id} ${String(r.fields ?? "")}`.trim())).toEqual([
      `GET ${FILE_ID} parents,mimeType`,
      `GET ${OTHER_FOLDER} parents`,
      `DELETE ${FILE_ID}`,
    ]);
    // the target is fetched exactly once (the gate reuses the first read)
    expect(log.filter((r) => r.id === FILE_ID && r.method === "GET")).toHaveLength(1);
  });

  test("active + folder-ancestor hit → proceeds to delete", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: [FOLDER_ID] });
    const res = await driveDeleteFile(CTX_WRITE, { file_id: FILE_ID });
    expect(res).toEqual({ file_id: FILE_ID, deleted: true });
    expect(mutations(log)).toHaveLength(1);
  });

  test("active + MISS → -32060, no id echo, gate fires BEFORE any further request (no mimeType get, no delete)", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: [OTHER_FOLDER], [OTHER_FOLDER]: [] });
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(JSON.stringify(e.toJsonRpc())).not.toContain(FILE_ID);
    expect(mutations(log)).toEqual([]);
    // GET target (parents,mimeType) then the ancestor walk; nothing after the gate.
    expect(log.map((r) => `${r.method} ${r.id}`)).toEqual([
      `GET ${FILE_ID}`,
      `GET ${OTHER_FOLDER}`,
    ]);
  });

  test("ancestor fetch error → deny, NO delete request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: [OTHER_FOLDER], [OTHER_FOLDER]: "ERR" });
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(mutations(log)).toEqual([]);
  });

  test("allowlist ACTIVE + target GET 404 → -32060 ancestry_unverifiable, no id anywhere, NO delete request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: "404" });
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(JSON.stringify(e.toJsonRpc()) + e.message).not.toContain(FILE_ID);
    expect(mutations(log)).toEqual([]);
  });

  test("allowlist ACTIVE + target GET 500 → same -32060 (never a Google-mapped error)", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive({ [FILE_ID]: "ERR" });
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(mutations(log)).toEqual([]);
  });

  test("allowlist OFF + target GET 404 → Google-mapped error, NO delete request", async () => {
    const log = await installDrive({ [FILE_ID]: "404" });
    const e = await driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }).then(
      () => undefined,
      (err: unknown) => err,
    );
    expect(e).toBeInstanceOf(Error);
    expect(e).not.toBeInstanceOf(MCPError);
    expect(String((e as Error).message)).toMatch(/404/);
    expect(mutations(log)).toEqual([]);
  });

  test("active-EMPTY allowlist (deny-all) → -32060 with ZERO requests issued", async () => {
    process.env[ENV_TARGETS] = "";
    const log = await installDrive({});
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "not_in_allowlist" });
    expect(log).toEqual([]);
  });

  test("file-only allowlist, target not listed → -32060 with ZERO requests", async () => {
    process.env[ENV_TARGETS] = `file:${OTHER_FOLDER}`;
    const log = await installDrive({});
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorData).toEqual({ reason: "not_in_allowlist" });
    expect(log).toEqual([]);
  });

  test("SAFESPACE_AUTONOMOUS=true + allowlist unset → -32060 from the handler itself (F4 bypassed), ZERO requests", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const log = await installDrive({});
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: FILE_ID }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(e.errorData).toEqual({ reason: "not_in_allowlist" });
    expect(log).toEqual([]);
  });

  test("depth exceeded → deny, NO delete request", async () => {
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const ids = Array.from({ length: MAX_WALK_DEPTH + 2 }, (_, i) => `1Deep${String(i).padStart(2, "0")}AAAAAAAAAAAAAAAAA`);
    const tree: Record<string, string[]> = {};
    ids.forEach((id, i) => {
      tree[id] = [i + 1 < ids.length ? ids[i + 1]! : FOLDER_ID];
    });
    const log = await installDrive(tree);
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: ids[0]! }));
    expect(e.errorData).toEqual({ reason: "ancestry_unverifiable" });
    expect(mutations(log)).toEqual([]);
  });

  test("a REAL shortcut outside the folder cannot authorize itself via its target inside the folder", async () => {
    const SHORTCUT = FILE_ID; // lives in OTHER_FOLDER
    const TARGET = "1TargetInsideAAAAAAAAAA"; // lives inside the allowlisted folder
    process.env[ENV_TARGETS] = `folder:${FOLDER_ID}`;
    const log = await installDrive(
      { [SHORTCUT]: [OTHER_FOLDER], [OTHER_FOLDER]: [], [TARGET]: [FOLDER_ID] },
      { [SHORTCUT]: "application/vnd.google-apps.shortcut" },
      { [SHORTCUT]: { shortcutDetails: { targetId: TARGET } } },
    );
    const e = await denial(driveDeleteFile(CTX_WRITE, { file_id: SHORTCUT }));
    expect(e.errorName).toBe("drive_delete_denied_by_policy");
    expect(e.errorData).toEqual({ reason: "not_in_allowlist" });
    expect(log.some((r) => r.id === TARGET)).toBe(false); // target never fetched
    expect(mutations(log)).toEqual([]);
  });
});
