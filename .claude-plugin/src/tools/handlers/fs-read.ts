// v1.75 — the fs_read handler (class-C KEYLESS connector, mirrors web-fetch.ts).
//
// docs/v1.75-fs-read-connector.md. fs_read returns the UTF-8 text content of a host
// file that passes the path gate (policy/fs-gate.ts) — a default-deny root allowlist
// + lexical-containment + realpath/symlink re-check + size/UTF-8 caps.
//
// KEYLESS: never reads `ctx.credential` (no account/token/requireOAuth). The
// cross-cutting envelope (tier / write-burst[no-op for a read] / sanitize wrap /
// audit) is applied by `withNonOAuthContext`; ALL connector-specific security lives
// in the gate. The handler is thin: validate the one arg, call the gate, map a stray
// error. The returned `{ path, bytes, content }` is attacker-influenced file data →
// sanitize-wrapped by the fs-read Source's EMPTY skipFields (every field wraps).

import { mapFsReadError, readThroughGate } from "../../policy/fs-gate";
import type { ToolContext } from "../types";

/** Test-injection seam — production leaves it undefined (→ the real gated read).
 *  Tests inject a stub to assert the handler's validation + error mapping. */
export interface FsReadDeps {
  read?: typeof readThroughGate;
}

export async function fsReadHandler(
  _ctx: ToolContext,
  args: Record<string, unknown>,
  deps: FsReadDeps = {},
): Promise<unknown> {
  const path = args.path;
  if (typeof path !== "string" || path.trim() === "") {
    throw new Error("fs_read: 'path' must be a non-empty string");
  }
  const reader = deps.read ?? readThroughGate;
  try {
    return await reader(path.trim());
  } catch (err) {
    // The gate throws MCPErrors (-32043 / -32044); mapFsReadError passes those
    // through and wraps any unexpected non-MCPError as a generic fs_read_failed
    // (never leaks the raw error string / the requested path).
    throw mapFsReadError(err);
  }
}
