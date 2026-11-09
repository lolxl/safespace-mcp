// Drive trash / delete — `drive_trash_file` (recoverable) + `drive_delete_file`
// (PERMANENT). Split out of drive.ts (already >1000 lines); re-exported via
// ./index.ts so `./handlers` import paths are unchanged.
//
// Both tools are gated FIRST by the opt-in SAFESPACE_DRIVE_DELETE_TARGETS
// allowlist (policy/drive-delete-targets.ts; default OFF = allow, fail-closed when
// active). The gate fires BEFORE any mutating SDK call. The denial NEVER echoes the
// file id (errorData carries only a closed-set `reason`).
//
// The ancestor fetcher here is the drive_share_file shape (drive.ts) with two
// deliberate differences: it does NOT follow shortcuts (deleting a shortcut deletes
// the shortcut itself, so only ITS parents count) and the walk is FRESH per call
// (the share-gate AncestorCache is never consulted — a stale cached ancestry must
// never authorize a delete).

import { MCPError } from "../../errors";
import { driveClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import { type AncestorFetcher } from "../../policy/drive-whitelist";
import {
  checkDriveDeleteAllowed,
  getDriveDeleteAllowlistState,
} from "../../policy/drive-delete-targets";
import { requireGoogle } from "./shared";
import type { ToolContext } from "../types";

const DRIVE_FILE_ID_RE = /^[a-zA-Z0-9_-]{20,}$/;
const DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder";

type DriveClient = ReturnType<typeof driveClientFromToken>;

function validateFileId(tool: string, args: Record<string, unknown>): string {
  if (typeof args.file_id !== "string" || !args.file_id) {
    throw new Error(`${tool} requires non-empty 'file_id' string`);
  }
  if (!DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      `${tool}: 'file_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?`,
    );
  }
  return args.file_id;
}

function requireWriteTier(ctx: ToolContext, tool: string): void {
  if (ctx.tier === "read") {
    throw new MCPError("scope_mismatch", {
      tool,
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }
}

/** Parent-chain fetcher for the delete gate. Shortcut targets are intentionally NOT
 *  resolved (see file header). Any SDK failure (404 / 403 / network) THROWS, which
 *  checkDriveDeleteAllowed converts into a fail-closed `ancestry_unverifiable`. */
function buildDeleteAncestorFetcher(drive: DriveClient): AncestorFetcher {
  return async (id: string) => {
    const metaRes = await drive.files.get({
      fileId: id,
      fields: "parents",
      supportsAllDrives: true,
    });
    const meta = metaRes.data as { parents?: string[] } | null;
    if (meta === null || meta === undefined) return { kind: "not_found" };
    return { kind: "ok", parents: Array.isArray(meta.parents) ? meta.parents : [] };
  };
}

/** Allowlist gate shared by both tools — runs BEFORE any mutating call. */
async function enforceDriveDeleteGate(
  drive: DriveClient,
  fileId: string,
  fetcher: AncestorFetcher = buildDeleteAncestorFetcher(drive),
): Promise<void> {
  const decision = await checkDriveDeleteAllowed(fileId, getDriveDeleteAllowlistState(), fetcher);
  if (!decision.allowed) {
    // Closed-set reason only — NO file id echo (PII-oracle defense).
    throw new MCPError("drive_delete_denied_by_policy", {
      reason: decision.reason === "ancestry_unverifiable" ? "ancestry_unverifiable" : "not_in_allowlist",
    });
  }
}

/** `drive_trash_file` — move a file/folder to the Drive trash (RECOVERABLE,
 *  ~30 days). WRITE TIER. Folders are allowed (trash is reversible). */
export async function driveTrashFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const fileId = validateFileId("drive_trash_file", args);
  requireWriteTier(ctx, "drive_trash_file");

  const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
  await enforceDriveDeleteGate(drive, fileId);

  try {
    await drive.files.update({
      fileId,
      requestBody: { trashed: true },
      fields: "id",
      supportsAllDrives: true,
    });
    return { file_id: fileId, trashed: true };
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_trash_file", email: requireGoogle(ctx).accountId });
  }
}

/** `drive_delete_file` — PERMANENTLY delete a file (bypasses the trash). WRITE
 *  TIER; member of PERMANENT_DELETE_TOOLS (delete burst bucket + F4 autonomous
 *  hard-deny). Folders are REFUSED: a permanent folder delete cascades to an
 *  unbounded subtree — use drive_trash_file. */
export async function driveDeleteFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const fileId = validateFileId("drive_delete_file", args);
  requireWriteTier(ctx, "drive_delete_file");

  const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());

  // ONE metadata read of the target FIRST (parents + mimeType), so the sequence is
  // [GET target, ...ancestor GETs, DELETE] with no GET between the gate and the
  // delete (no extra TOCTOU window). The gate reuses the target's first-level
  // parents from this read instead of fetching the target again.
  //
  // Allowlist ACTIVE: decide locally first (zero requests) when possible, and map
  // ANY failure of this pre-gate read to the policy denial — never toGoogleError,
  // which would echo the id / leak existence (an oracle drive_trash_file lacks).
  const state = getDriveDeleteAllowlistState();
  if (
    state.kind === "active" &&
    !state.files.has(fileId) &&
    !state.folders.has(fileId) &&
    state.folders.size === 0
  ) {
    throw new MCPError("drive_delete_denied_by_policy", { reason: "not_in_allowlist" });
  }
  let meta: { parents?: unknown; mimeType?: unknown } | null;
  try {
    const res = await drive.files.get({
      fileId,
      fields: "parents,mimeType",
      supportsAllDrives: true,
    });
    meta = (res.data ?? null) as { parents?: unknown; mimeType?: unknown } | null;
  } catch (err) {
    if (state.kind === "active") {
      // Same treatment for every active-allowlist case (incl. a directly listed id).
      throw new MCPError("drive_delete_denied_by_policy", { reason: "ancestry_unverifiable" });
    }
    throw toGoogleError(err, { tool: "drive_delete_file", email: requireGoogle(ctx).accountId });
  }

  const base = buildDeleteAncestorFetcher(drive);
  const seeded: AncestorFetcher = async (id: string) => {
    if (id !== fileId) return base(id);
    if (meta === null) return { kind: "not_found" };
    return { kind: "ok", parents: Array.isArray(meta.parents) ? (meta.parents as string[]) : [] };
  };
  await enforceDriveDeleteGate(drive, fileId, seeded);

  const mimeType = meta?.mimeType;
  if (typeof mimeType !== "string" || mimeType.length === 0) {
    // Fail closed: cannot prove it is not a folder (null / "" / missing / non-string).
    throw new Error("drive_delete_file: could not determine the file type; refusing to delete.");
  }
  if (mimeType === DRIVE_FOLDER_MIME) {
    throw new Error(
      "drive_delete_file: refusing to permanently delete a folder (unbounded blast radius — it removes the whole subtree). Use drive_trash_file instead (recoverable).",
    );
  }

  try {
    await drive.files.delete({ fileId, supportsAllDrives: true });
    return { file_id: fileId, deleted: true };
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_delete_file", email: requireGoogle(ctx).accountId });
  }
}
