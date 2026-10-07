// Drive — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { auditRecipientDeniedEvent, auditShareDeniedEvent, auditShareEvent, hashTargetEmail } from "../../audit";
import { configDir as resolveConfigDir } from "../../auth/keychain";
import { MCPError } from "../../errors";
import { recordTaintedFromText } from "../../policy/tainted-source";
import { driveClientFromToken } from "../../google-api/client";
import { readCappedStream } from "../../google-api/download";
import { toGoogleError } from "../../google-api/errors";
import { type AncestorFetcher, checkShareAllowed, getAncestorCache, getWhitelistState } from "../../policy/drive-whitelist";
import { isAutonomousMode } from "../../policy/autonomous-mode";
import { getAllowlistState, isRecipientAllowed } from "../../policy/recipient-allowlist";
import { requireSendApproval } from "../../policy/send-approval";
import { requireGoogle, HEADER_INJECTION_RE } from "./shared";
import type { ToolContext } from "../types";

export async function driveSearch(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const query = typeof args.query === "string" ? args.query : "";
  if (!query) {
    throw new Error("drive_search requires a non-empty 'query' string");
  }
  // Defense-in-depth: schema declares max:50; clamp at handler boundary so a
  // non-conforming MCP client can't request an oversized Drive response.
  const requested = typeof args.max_results === "number" ? args.max_results : 10;
  const pageSize = Math.min(requested, 50);
  // Drive's list API parameter is `q` (same letter as Gmail's `q` but DIFFERENT syntax).
  // Gmail: `from:foo subject:bar`. Drive: `name contains 'foo' and mimeType = 'text/plain'`.
  // The registry description must guide Claude to the right grammar.
  //
  // `fields` projection keeps the response small. Drive's default is only id+name;
  // we ask for the structural fields Claude needs to pick a file (mimeType for
  // dispatching to the right reader, modifiedTime for recency, size for caps,
  // parents for folder context, webViewLink as a fallback URL).
  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.list({
      q: query,
      pageSize,
      fields: "files(id,name,mimeType,modifiedTime,webViewLink,size,iconLink,parents),nextPageToken",
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_search", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── 5.4 drive_get_file_content ─────────
 *
 * Per DESIGN.md §P1(c): Drive has a HARD 5 MB cap for file content reads.
 * v1 supports text/* + Google-native (Docs/Sheets/Slides) only — explicitly
 * NOT PDF/image/binary attachments. The sanitize pipeline can't reason about
 * arbitrary binary; surfacing them as text would be a lie.
 *
 * Flow:
 *   1. Pre-flight `files get` for {mimeType, size, name}
 *      → reject `file_too_large` if size > 5 MB BEFORE the download
 *   2. Dispatch on mimeType:
 *      - `application/vnd.google-apps.document`     → export text/plain
 *      - `application/vnd.google-apps.spreadsheet`  → export text/csv
 *      - `application/vnd.google-apps.presentation` → export text/plain
 *      - text/*, application/json                   → files get --alt media (UTF-8 text)
 *      - everything else                            → throw `file_unsupported_binary`
 *
 * Returns { id, name, mimeType, size, content }. The `content` field is the
 * UTF-8-decoded text body, which sanitize will then wrap (user content).
 */

const DRIVE_MAX_BYTES = 5 * 1024 * 1024; // 5 MB per DESIGN.md §P1(c)

const GOOGLE_DOCS_EXPORTS: Record<string, string> = {
  "application/vnd.google-apps.document": "text/plain",
  "application/vnd.google-apps.spreadsheet": "text/csv",
  "application/vnd.google-apps.presentation": "text/plain",
};

// MIME types treated as plain UTF-8 text. Anything not in here AND not a
// Google-native type → throw file_unsupported_binary.
//
// text/* covers text/plain, text/csv, text/markdown, text/html, etc.
// text/html is INTENTIONALLY included — sanitize wraps the response as
// untrusted content, so inline script tags are not executable; they're
// just text inside the wrapper (sec-rev 5.4 confirmation).
//
// Application-level text types: registered IANA (RFC 9512 / RFC 9592, 2024)
// for yaml/toml, plus the legacy `x-` variants still common in older files.
//
// End-anchor `($|;)` prevents matching `application/jsonpatch+json` etc.
// where the prefix overlaps a real text MIME but the suffix indicates a
// different content type (code-rev 5.4 LOW).
const TEXT_MIME_RE = /^(text\/|application\/(json|xml|javascript|yaml|toml|x-yaml|x-toml)($|;))/;

export async function driveGetFileContent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("drive_get_file_content requires a non-empty 'id' string");
  }

  // Binding size cap lives in `readCappedStream`; pre-flight `size` is
  // advisory and TOCTOU-bound by the streaming cap (see
  // `docs/v1.11-drive-streaming-cap.md`).
  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());

    // Step 1 — pre-flight metadata.
    const metaRes = await drive.files.get({
      fileId: id,
      fields: "id,name,mimeType,size",
    });
    const meta = metaRes.data;
    if (!meta.id || !meta.name || !meta.mimeType) {
      throw new Error("drive_get_file_content: pre-flight returned no metadata");
    }
    if (meta.size && Number(meta.size) > DRIVE_MAX_BYTES) {
      throw new MCPError("file_too_large", {
        id: meta.id,
        size: meta.size,
        max: DRIVE_MAX_BYTES,
      });
    }

    // Step 2 — dispatch on mimeType.
    const exportMime = GOOGLE_DOCS_EXPORTS[meta.mimeType];
    let downloadStream: NodeJS.ReadableStream;
    if (exportMime) {
      const exportRes = await drive.files.export(
        { fileId: id, mimeType: exportMime },
        { responseType: "stream" },
      );
      downloadStream = exportRes.data as NodeJS.ReadableStream;
    } else if (TEXT_MIME_RE.test(meta.mimeType)) {
      const getRes = await drive.files.get(
        { fileId: id, alt: "media" },
        { responseType: "stream" },
      );
      downloadStream = getRes.data as NodeJS.ReadableStream;
    } else {
      // PDF, image, zip, video, etc. — out of scope per DESIGN.md.
      throw new MCPError("file_unsupported_binary", {
        id: meta.id,
        mimeType: meta.mimeType,
      });
    }

    // Step 3 — capped stream read. Binding security gate.
    const { bytes } = await readCappedStream(
      downloadStream as unknown as import("node:stream").Readable,
      {
        maxBytes: DRIVE_MAX_BYTES,
        toolName: "drive_get_file_content",
        email: requireGoogle(ctx).accountId,
        fileId: meta.id,
      },
    );

    // UTF-8 decode after FULL assembly. Per design §5, per-chunk sanitization
    // is forbidden — patterns straddling chunk boundaries would be missed.
    const content = new TextDecoder("utf-8").decode(bytes);

    // v1.56 F3b — record email/URL tokens from this (untrusted) file body as
    // tainted-source for the session. `content` is the pure file body — no
    // header-address fields — so this honors the locked body-only scope (Q3). A
    // later gmail_send to an address that appeared here gets `tainted_source` on
    // its audit row. Observability only; does not alter the read result.
    recordTaintedFromText(content);

    return {
      id: meta.id,
      name: meta.name,
      mimeType: meta.mimeType,
      size: bytes.byteLength,
      content,
    };
  } catch (err) {
    // Sec-rev §9 #5: MCPErrors thrown by us (file_too_large /
    // file_unsupported_binary / download_stalled) pass through unmapped
    // (toGoogleError returns an MCPError as-is); only Gaxios-shaped upstream
    // errors are mapped.
    throw toGoogleError(err, { tool: "drive_get_file_content", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.2 drive_share_file (write tool) ─────────
 *
 * Creates a Drive permission (share file with anyone-with-link or specific
 * email; reader / commenter roles only). Highest blast-radius tool in the
 * codebase — a successful `type: anyone` share lets anyone with the URL
 * read the file, with no expiration possible (Google API restriction). The
 * defense layers below are the cost of admitting this capability:
 *
 *   1. Tier gating — v2.0 replaced SAFESPACE_ENABLE_DRIVE_SHARE=1 with
 *      SAFESPACE_TIER=share (a tier strictly broader than write, because
 *      anyone-with-link can leak externally). Registry min_tier="share"
 *      is the authoritative gate. The v1.2 SAFESPACE_DRIVE_SHARE_ALLOWED_OWNERS
 *      owner allowlist was also removed in v2.0 — replaced by v2.1's
 *      drive-whitelist.json (per-folder/file ancestor walk, see checkShareAllowed)
 *      and v2.2's SAFESPACE_RECIPIENT_ALLOW (per-recipient email allowlist,
 *      see isRecipientAllowed). Both gates fail-closed on lookup failure.
 *   2. Type-aware expiration: user → 1-365 days mandatory; anyone → must
 *      omit (Google rejects expirationTime on anyone permissions anyway)
 *   3. Single file per call (file_id is a string, not an array)
 *   4. v2.2 recipient gate (share_type=user only) — target_email must
 *      match SAFESPACE_RECIPIENT_ALLOW (.env baseline) ∪ EXTRA (shell)
 *      ∪ accounts.json (self-implicit). Runs BEFORE the v2.1 whitelist
 *      gate (cheap-before-expensive ordering: env-string check vs Drive
 *      API ancestor walk).
 *   5. File-id regex (rejects URL paste)
 *   6. Param hardcoding: role limited to reader/commenter at validation
 *      layer; transferOwnership / pendingOwner / writer/owner/organizer/
 *      fileOrganizer NEVER sent. Body fields are a fixed literal
 *      (not derived from caller input beyond what's pre-validated).
 *   7. Audit forensic line via audit.ts auditShareEvent — records
 *      target_email_hash (HMAC-SHA256 full digest), file_id, role,
 *      share_type, expiration_iso, granted_permission_id. The audit is
 *      what makes "recovery" possible: knowing exactly which permission
 *      to revoke after-the-fact (PR-3 drive_unshare_file uses the same
 *      log path).
 *
 * Risk that defense does NOT mitigate: once a `type: anyone` permission
 * is created, the URL can be archived / forwarded / cached. Revoking the
 * permission with drive_unshare_file removes future access via the
 * permission, but cached / mirrored content elsewhere is gone. DESIGN.md
 * v1.2 Addendum documents this risk explicitly. */
// Google Drive file ids are URL-safe base64-ish: alphanumerics + `_` + `-`,
// typically 25-44 chars but no documented minimum. We require 20+ to reject
// obvious garbage and URL paste (which always contains `/`, `.`, or `?`).
const DRIVE_FILE_ID_RE = /^[a-zA-Z0-9_-]{20,}$/;
// Loose RFC-5321 validation. Not a security boundary (Google validates
// server-side); the goal is to fail fast on obvious typos rather than burn
// an API round-trip.
const TARGET_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_SHARE_ROLES: ReadonlySet<string> = new Set(["reader", "commenter"]);
const MIN_EXPIRATION_DAYS = 1;
const MAX_EXPIRATION_DAYS = 365;

export async function driveShareFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // v2.0: env-var kill switch removed; tier-based tools/list filter (proxy.ts)
  // gates exposure at the `write` tier. The `share_type="anyone"` variant —
  // public-link blast radius — requires the `share` tier specifically. This
  // is the only remaining per-invocation tier check in the handler layer.

  // Param validation (Layers 3, 5, 6 + share_type).
  if (typeof args.file_id !== "string" || !args.file_id) {
    throw new Error("drive_share_file requires non-empty 'file_id' string");
  }
  if (!DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      `drive_share_file: 'file_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?`,
    );
  }
  const fileId = args.file_id;

  if (args.share_type !== "anyone" && args.share_type !== "user") {
    throw new Error("drive_share_file: 'share_type' must be 'anyone' or 'user'");
  }
  const shareType = args.share_type;

  // v2.0: anyone-share (public link) requires `share` tier — strictly above
  // the tool's min_tier=`write`. The tool itself IS exposed at `write` tier
  // (both share_type values declared in the schema), but only the user-share
  // *code path* is reachable until the operator lifts the tier to `share`.
  // Map the refusal to the existing `share_target_forbidden` family
  // (cf. v1.2 sec-rev allowlist_empty pattern) so callers don't need to
  // learn a new error code.
  if (shareType === "anyone" && ctx.tier !== "share") {
    throw new MCPError("share_target_forbidden", {
      reason: "anyone_requires_share_tier",
      current_tier: ctx.tier,
      required_tier: "share",
    });
  }

  // Layer 6: role allowlist — only reader / commenter.
  if (typeof args.role !== "string" || !ALLOWED_SHARE_ROLES.has(args.role)) {
    throw new MCPError("share_role_forbidden", { got: args.role });
  }
  const role = args.role as "reader" | "commenter";

  let targetEmail: string | null = null;
  if (shareType === "user") {
    if (typeof args.target_email !== "string" || !args.target_email) {
      throw new Error("drive_share_file: 'target_email' required when share_type='user'");
    }
    if (!TARGET_EMAIL_RE.test(args.target_email)) {
      throw new Error(`drive_share_file: 'target_email' is not a valid email`);
    }
    targetEmail = args.target_email;
  } else if (args.target_email !== undefined) {
    throw new Error("drive_share_file: 'target_email' must be omitted when share_type='anyone'");
  }

  // Layer 2: type-aware expiration.
  let expirationIso: string | null = null;
  if (shareType === "user") {
    if (typeof args.expiration_days !== "number" || !Number.isInteger(args.expiration_days)) {
      throw new MCPError("share_expiration_required");
    }
    if (args.expiration_days < MIN_EXPIRATION_DAYS || args.expiration_days > MAX_EXPIRATION_DAYS) {
      throw new MCPError("share_expiration_required", {
        got: args.expiration_days,
        min: MIN_EXPIRATION_DAYS,
        max: MAX_EXPIRATION_DAYS,
      });
    }
    const expirationMs = Date.now() + args.expiration_days * 86_400_000;
    expirationIso = new Date(expirationMs).toISOString();
  } else if (args.expiration_days !== undefined) {
    // Google API rejects expirationTime on anyone permissions; we pre-reject
    // for a clearer error message.
    throw new MCPError("share_expiration_forbidden");
  }

  // Optional notify (default true for user, ignored for anyone).
  const notify = typeof args.notify === "boolean" ? args.notify : true;

  // v2.2: Recipient allowlist gate. ORDER MATTERS — runs BEFORE the v2.1
  // whitelist gate because (a) it's cheap (in-memory Set lookup, no API),
  // and (b) if the recipient is rejected there's no point paying for v2.1's
  // ancestor walk. See docs/DESIGN.md v2.2 Addendum "Check ordering inside
  // drive_share_file (architectural fix from review)".
  //
  // Only applies to share_type=user (anyone-share has no target_email).
  // The recipient was already validated for email format earlier in this
  // handler; here we structurally gate it against the operator's allowlist.
  if (shareType === "user" && targetEmail !== null) {
    const recipientStartMs = Date.now();
    const allowlistState = await getAllowlistState();
    // Every consented account keeps the implicit self exemption (one operator per
    // process).
    if (!isRecipientAllowed(targetEmail, allowlistState)) {
      const hash = await hashTargetEmail(targetEmail).catch(() => null);
      await auditRecipientDeniedEvent({
        tool: "drive_share_file",
        email: requireGoogle(ctx).accountId,
        rejected_recipient_hashes: hash !== null ? [hash] : [],
        rejected_count: 1,
        total_recipients: 1,
        duration_ms: Date.now() - recipientStartMs,
      });
      throw new MCPError("recipient_denied_by_policy", {
        tool: "drive_share_file",
        rejected_count: 1,
        total_recipients: 1,
      });
    }
  }

  // v2.1: Drive share whitelist gate. Runs AFTER all client-side validation
  // (so we don't burn a Drive ancestor walk on a request that would have
  // failed schema validation anyway) and BEFORE the permissions.create call
  // (so denied requests never reach Google). See docs/DESIGN.md v2.1
  // Addendum for spec; src/policy/drive-whitelist.ts for the gate.
  //
  // State semantics:
  //   - drive-whitelist.json absent → policy OFF (decision.allowed === true,
  //     reason "policy_off") → identical to pre-v2.1 behavior.
  //   - File present, entries=[] → default-deny.
  //   - File present, entries=[...] → walk parents up to MAX_WALK_DEPTH=10
  //     via Drive API; permit if any ancestor folder (or file ID itself)
  //     matches.
  //
  // On deny we record one `share_denied_by_policy` audit event with NO
  // target_email or share_type — those were never validated, and we don't
  // want to leak target intent for a refused call.
  const whitelistStartMs = Date.now();
  // resolveConfigDir() returns the same value for the lifetime of the proxy
  // process (env var read at module load + a stable default fallback), so
  // the getWhitelistState singleton's "first-call wins" contract is safe.
  // Tests that exercise multiple configDirs must call
  // __internal.resetSingletons in beforeEach.
  const whitelistState = await getWhitelistState(resolveConfigDir());
  const ancestorCache = getAncestorCache();

  // Both the parent-walk metadata lookup AND the final permissions.create
  // use the same SDK client. Whitelist LRU cache + walk depth-limit
  // semantics live in policy/drive-whitelist.ts.
  const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());

  const ancestorFetcher: AncestorFetcher = async (id: string) => {
    try {
      const metaRes = await drive.files.get({
        fileId: id,
        fields: "parents,mimeType,shortcutDetails",
        supportsAllDrives: true,
      });
      const meta = metaRes.data as {
        parents?: string[];
        mimeType?: string;
        shortcutDetails?: { targetId?: string };
      } | null;
      if (meta === null) return { kind: "not_found" };
      const isShortcut = meta.mimeType === "application/vnd.google-apps.shortcut";
      const resolvedTargetId =
        isShortcut && typeof meta.shortcutDetails?.targetId === "string"
          ? meta.shortcutDetails.targetId
          : undefined;
      return {
        kind: "ok",
        parents: Array.isArray(meta.parents) ? meta.parents : [],
        ...(resolvedTargetId !== undefined && { resolvedTargetId }),
      };
    } catch (err) {
      // 404 = file not visible to this account (or gone). Convert to a
      // typed result so checkShareAllowed returns walk_failed without
      // caching (retry possible after the user re-shares to this account).
      // GaxiosError.response.status carries the 404; UpstreamError shape kept
      // as a fallback for callers that route through mapGoogleError first.
      const httpStatus =
        (err as { httpStatus?: number }).httpStatus ??
        (err as { response?: { status?: number } }).response?.status;
      if (httpStatus === 404) return { kind: "not_found" };
      // Other errors (auth, network, 5xx, GaxiosError without status)
      // propagate. checkShareAllowed catches the throw and returns
      // walk_failed without caching. Do NOT add a timeout-specific branch
      // that converts to not_found — timeouts should not poison the
      // negative cache.
      throw err;
    }
  };

  const decision = await checkShareAllowed(
    fileId,
    whitelistState,
    ancestorFetcher,
    ancestorCache,
    isAutonomousMode(),
  );
  if (!decision.allowed) {
    // Best-effort audit append (mirrors auditShareEvent pattern — never
    // block on append failure).
    await auditShareDeniedEvent({
      email: requireGoogle(ctx).accountId,
      file_id: fileId,
      ancestors_walked: decision.ancestorsWalked,
      duration_ms: Date.now() - whitelistStartMs,
    });
    throw new MCPError("share_denied_by_policy", {
      file_id: fileId,
      reason: decision.reason,
    });
  }

  // v1.128 Q3-B — supervised approval for share_type=anyone only (user shares stay
  // on the recipient allowlist). LAST before the SDK so a whitelist miss never
  // creates a pending. No-op when the flag is off.
  if (shareType === "anyone") {
    await requireSendApproval(ctx, {
      tool: "drive_share_file",
      recipients: [],
      body: "",
      target: { kind: "drive_share", file_id: fileId, share_type: "anyone", role },
    });
  }

  // v2.0 PR-2a: SAFESPACE_DRIVE_SHARE_ALLOWED_OWNERS allowlist removed.
  // Rationale: tier=share gates anyone-share already (handler check above)
  // and Claude Code's per-call approve UI is the operational confirmation
  // layer. The old allowlist was defense-in-depth against prompt-injection
  // sharing files from procurement accounts — that defense now lives in
  // "don't load high-risk accounts into a process running at tier=share"
  // (DESIGN v2.0 Addendum use-pattern constraint, sec-rev v2.0 PR-2a M5).
  //
  // Build requestBody. Body fields are a fixed literal — caller input was
  // pre-validated above, and we explicitly do NOT pass `transferOwnership`,
  // `pendingOwner`, or any field outside the allowlist.
  const requestBody: Record<string, unknown> = { type: shareType, role };
  if (shareType === "user") {
    requestBody.emailAddress = targetEmail;
    requestBody.expirationTime = expirationIso;
  }

  // MCPError pass-through (recipient_denied_by_policy + share_denied_by_policy
  // + share_target_forbidden + share_role_forbidden + share_expiration_*
  // raised above) is already caught BEFORE we reach this try-catch, so the
  // instanceof check here is defensive — guarding against any future MCPError
  // throws inside the SDK call boundary (e.g., a downstream layer raising a
  // typed error we should not reshape into an upstream_error).
  let result: unknown;
  try {
    const createRes = await drive.permissions.create({
      fileId,
      supportsAllDrives: true,
      // sendNotificationEmail only meaningful for user shares; Google ignores
      // it for anyone shares so we omit it there.
      ...(shareType === "user" ? { sendNotificationEmail: notify } : {}),
      requestBody,
    });
    result = createRes.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_share_file", email: requireGoogle(ctx).accountId });
  }

  // Layer 7: audit forensic line. Best-effort — auditShareEvent swallows
  // its own errors (audit.ts logs to stderr). Don't let an audit append
  // failure undo a successful share, but DO record everything we can
  // before returning so the standard auditEnd line and this forensic
  // line are interleaved in source order.
  const permissionId = (result as { id?: string } | undefined)?.id ?? null;
  const targetEmailHash = await hashTargetEmail(targetEmail).catch(() => null);
  await auditShareEvent({
    tool: "drive_share_file",
    email: requireGoogle(ctx).accountId,
    file_id: fileId,
    share_type: shareType,
    role,
    target_email_hash: targetEmailHash,
    expiration_iso: expirationIso,
    granted_permission_id: permissionId,
  });

  return result;
}

/* ───────── v1.2 drive_unshare_file (recovery tool) ─────────
 *
 * Removes a Drive permission previously created by drive_share_file (or by
 * Drive web UI). Recovery operation — deliberately lighter defense than
 * share so it remains usable when something has gone wrong:
 *
 *   - NO kill switch (recovery should always work; brakes always work)
 *   - NO owner allowlist (we're REMOVING access, not granting; can't
 *     leak data by unsharing)
 *   - NO v2.1 drive-whitelist gate (DESIGN.md v2.1 — recovery > policy;
 *     if a wrong share was made, the operator must be able to undo it
 *     even if the whitelist is misconfigured or would block the file)
 *   - NO v2.2 recipient-allowlist gate (no recipient — we are DELETING
 *     an existing permission, not granting a new one)
 *   - min_tier="read" (registry.ts) — recovery is exposed at the lowest
 *     tier so brakes run even when write/share are locked down
 *   - Audit forensic line records the deleted permission for after-the-fact
 *     correlation with the share log
 *
 * Defenses kept (since they're cheap and prevent operator error):
 *   - file_id regex (reuses DRIVE_FILE_ID_RE)
 *   - target_email validation when share_type=user
 *
 * The handler internally calls permissions.list to find the matching
 * permission by (type, emailAddress) tuple, then permissions.delete by id.
 * The list step is bounded at pageSize=100 — files with >100 user
 * permissions may not surface the target via this tool; fall back to
 * Drive web UI in that case (DESIGN.md v1.2 Addendum notes the limit).
 *
 * For share_type=anyone, Google enforces at most one anyone permission per
 * file, so pagination is moot.
 *
 */
export async function driveUnshareFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.file_id !== "string" || !args.file_id) {
    throw new Error("drive_unshare_file requires non-empty 'file_id' string");
  }
  if (!DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      `drive_unshare_file: 'file_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?`,
    );
  }
  const fileId = args.file_id;

  if (args.share_type !== "anyone" && args.share_type !== "user") {
    throw new Error("drive_unshare_file: 'share_type' must be 'anyone' or 'user'");
  }
  const shareType = args.share_type;

  let targetEmail: string | null = null;
  if (shareType === "user") {
    if (typeof args.target_email !== "string" || !args.target_email) {
      throw new Error("drive_unshare_file: 'target_email' required when share_type='user'");
    }
    if (!TARGET_EMAIL_RE.test(args.target_email)) {
      throw new Error("drive_unshare_file: 'target_email' is not a valid email");
    }
    targetEmail = args.target_email;
  } else if (args.target_email !== undefined) {
    throw new Error("drive_unshare_file: 'target_email' must be omitted when share_type='anyone'");
  }

  // Intentionally NO call to checkShareAllowed / getWhitelistState here.
  // The v2.1 drive-whitelist gate is BYPASSED unconditionally (DESIGN.md
  // v2.1 — recovery > policy). Likewise NO recipient-allowlist check
  // (no recipient — we are deleting an existing permission, not creating
  // a new one).
  const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());

  // List permissions on the file. Default page (100) covers the common case;
  // files with >100 user permissions need Drive web UI (documented in DESIGN
  // v1.2 Addendum). For share_type=anyone, Google enforces ≤1 anyone
  // permission per file, so the page-bound is moot.
  let listResult: { permissions?: Array<{ id?: string; type?: string; emailAddress?: string }> };
  try {
    const listRes = await drive.permissions.list({
      fileId,
      fields: "permissions(id,type,emailAddress)",
      pageSize: 100,
      supportsAllDrives: true,
    });
    listResult = (listRes.data ?? {}) as {
      permissions?: Array<{ id?: string; type?: string; emailAddress?: string }>;
    };
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_unshare_file", email: requireGoogle(ctx).accountId });
  }

  const permissions = listResult.permissions ?? [];

  let matched: { id: string; emailAddress?: string } | null = null;
  for (const p of permissions) {
    if (!p.id || p.type !== shareType) continue;
    if (shareType === "user") {
      // Case-insensitive email match — Gmail canonicalizes user@gmail.com
      // and User@gmail.com to the same identity. Both forms must match.
      if ((p.emailAddress ?? "").toLowerCase() !== (targetEmail ?? "").toLowerCase()) continue;
    }
    matched = { id: p.id, ...(p.emailAddress !== undefined && { emailAddress: p.emailAddress }) };
    break;
  }

  if (!matched) {
    const detail = shareType === "user" ? ` for ${targetEmail}` : "";
    throw new Error(
      `drive_unshare_file: no matching ${shareType}${detail} permission found on file ${fileId}`,
    );
  }

  // permissions.delete returns HTTP 204 → SDK resolves with empty body.
  try {
    await drive.permissions.delete({
      fileId,
      permissionId: matched.id,
      supportsAllDrives: true,
    });
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_unshare_file", email: requireGoogle(ctx).accountId });
  }

  const targetEmailHash = await hashTargetEmail(targetEmail).catch(() => null);
  await auditShareEvent({
    tool: "drive_unshare_file",
    email: requireGoogle(ctx).accountId,
    file_id: fileId,
    share_type: shareType,
    // role intentionally omitted — not meaningful for delete (the deleted
    // permission's role isn't echoed back by Google's delete endpoint).
    target_email_hash: targetEmailHash,
    expiration_iso: null,
    granted_permission_id: matched.id,
  });

  return { deleted_permission_id: matched.id, file_id: fileId };
}

/* ───────── v1.42 A3 drive_create_folder (write tool) ─────────
 *
 * Create an empty Drive folder via files.create with the folder mimeType.
 * Lowest-risk write in the Drive surface — an empty folder shares nothing
 * and exfiltrates nothing, so there is NO drive-whitelist gate (unlike
 * drive_share_file). Defense = tier=write (registry) + name validation +
 * additionalProperties:false (registry). See
 * docs/v1.42-drive-folder-ops-permissions.md §1.1 / §3.4.
 */
const DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder";
const FOLDER_NAME_MAX_BYTES = 1000;

export async function driveCreateFolder(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const name = typeof args.name === "string" ? args.name : "";
  if (!name) {
    throw new Error("drive_create_folder requires a non-empty 'name' string");
  }
  // Same header-injection character class as gmail_send / calendar summary.
  if (HEADER_INJECTION_RE.test(name)) {
    throw new Error(
      "drive_create_folder: 'name' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
    );
  }
  if (Buffer.byteLength(name, "utf8") > FOLDER_NAME_MAX_BYTES) {
    throw new Error(
      `drive_create_folder: 'name' exceeds ${FOLDER_NAME_MAX_BYTES} bytes UTF-8`,
    );
  }

  let parentId: string | undefined;
  if (args.parent_id !== undefined) {
    if (typeof args.parent_id !== "string" || !DRIVE_FILE_ID_RE.test(args.parent_id)) {
      throw new Error(
        "drive_create_folder: 'parent_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
      );
    }
    parentId = args.parent_id;
  }

  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.create({
      requestBody: {
        name,
        mimeType: DRIVE_FOLDER_MIME,
        ...(parentId !== undefined && { parents: [parentId] }),
      },
      fields: "id,name,mimeType,parents,webViewLink",
      supportsAllDrives: true,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_create_folder", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.42 A3 drive_move_file (write tool) ─────────
 *
 * Move a file/folder by changing its parents (files.update +
 * addParents/removeParents). Two security interactions documented in
 * docs/v1.42-drive-folder-ops-permissions.md:
 *
 *   §3.1 — On a successful move, CLEAR the per-process drive-whitelist
 *     ancestor cache. The cache is keyed by fileId and stores the ancestor
 *     set from a prior parent-walk (TTL 10 min). Without this clear, moving a
 *     file OUT of a whitelisted folder and re-sharing it within the TTL would
 *     hit a STALE ancestor set still containing the whitelisted folder →
 *     false-ALLOW. Whole-cache clear is the simplest correct fix (Q1 LOCKED);
 *     moves are rare so the rebuild cost is negligible.
 *
 *   §3.2 — Moving a file INTO a whitelisted folder makes it shareable via
 *     drive_share_file (the ancestor walk then finds the whitelisted folder).
 *     The whitelist constrains share-ability by LOCATION, not which files may
 *     exist where; this is a bounded Model-A assumption documented in
 *     SECURITY.md and gated in depth by SAFESPACE_RECIPIENT_ALLOW + the
 *     tier=share requirement for anyone-shares (Q2 LOCKED = accept+document).
 */
function validateMoveParents(
  raw: unknown,
  field: string,
  required: boolean,
): string[] {
  if (raw === undefined) {
    if (required) {
      throw new Error(`drive_move_file: '${field}' is required (array of ≥1 folder id)`);
    }
    return [];
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(`drive_move_file: '${field}' must be a non-empty array of folder ids`);
  }
  for (const p of raw) {
    if (typeof p !== "string" || !DRIVE_FILE_ID_RE.test(p)) {
      throw new Error(
        `drive_move_file: '${field}' contains an invalid folder id (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?`,
      );
    }
  }
  return raw as string[];
}

export async function driveMoveFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.file_id !== "string" || !DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      "drive_move_file requires a valid 'file_id' (^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
    );
  }
  const fileId = args.file_id;

  const addParents = validateMoveParents(args.add_parents, "add_parents", true);
  const removeParents = validateMoveParents(args.remove_parents, "remove_parents", false);

  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.update({
      fileId,
      addParents: addParents.join(","),
      ...(removeParents.length > 0 && { removeParents: removeParents.join(",") }),
      fields: "id,name,parents",
      supportsAllDrives: true,
    });
    // §3.1 — invalidate the ancestor cache AFTER the move succeeds (a failed
    // update leaves the parent chain unchanged, so the cache stays valid).
    getAncestorCache().clear();
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_move_file", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.42 A4 drive_list_permissions (read tool) ─────────
 *
 * Expose permissions.list directly (drive_unshare_file already calls it
 * internally with a narrower field set). Read-only — discloses the current
 * sharing state so the operator can decide what to drive_unshare_file.
 *
 * PII: sharee displayName + emailAddress are user content (a sharee can set a
 * prompt-injection display name). They wrap via the standard sanitize
 * tree-walk DOWNSTREAM — NO handler-side sanitize. Q3 LOCKED: both fields
 * wrap; carving emailAddress out would require a global SKIP_FIELDS change
 * that un-wraps emails across calendar/contacts/gmail (a cross-API
 * regression). id/type/role are opaque/closed-enum. pageSize bounded at 100
 * (same as drive_unshare_file); >100-permission files need Drive web UI.
 */
const DRIVE_PERMISSIONS_PAGE_SIZE = 100;

export async function driveListPermissions(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.file_id !== "string" || !DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      "drive_list_permissions requires a valid 'file_id' (^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
    );
  }
  const fileId = args.file_id;

  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.permissions.list({
      fileId,
      fields:
        "permissions(id,type,role,emailAddress,displayName,domain,expirationTime,deleted)",
      pageSize: DRIVE_PERMISSIONS_PAGE_SIZE,
      supportsAllDrives: true,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_list_permissions", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.46 B1 — Drive file-write (create / copy / rename) ─────────
 *
 * Three NON-destructive WRITE tools, all on the existing full DRIVE scope:
 *   - drive_create_file  → files.create + multipart media (UTF-8 TEXT only)
 *   - drive_copy_file    → files.copy
 *   - drive_rename_file  → files.update (name/description ONLY; no parents)
 *
 * No trash/delete. No drive-whitelist gate (creating/copying/renaming shares
 * nothing — see docs/v1.46-drive-file-write.md §3.1 + SECURITY.md §3). No new
 * OAuth scope / error code / audit channel. Name validation + file-id regex
 * reuse the v1.42 drive_create_folder / drive_move_file patterns verbatim.
 */
// FOLDER_NAME_MAX_BYTES (1000) is the shared Drive name byte-cap — reused here
// for file names so create/copy/rename match drive_create_folder exactly.
const DRIVE_DESCRIPTION_MAX_BYTES = 8000; // mirrors CALENDAR_DESCRIPTION_MAX_BYTES

// Text-only MIME allowlist for drive_create_file. Fully anchored so trailing
// garbage is rejected; restricted to the text family + a small set of
// structured-text application types. This ENFORCES the "UTF-8 TEXT content
// only" contract (v1.46 Q2) — binary types (PDF/image/zip/Office/Google-native)
// fail the match. Optional `; charset=…` parameter tolerated.
const CREATE_FILE_MIME_RE =
  /^(text\/[a-z0-9][a-z0-9.+-]*|application\/(json|xml|xhtml\+xml|yaml|x-yaml|csv|markdown|x-ndjson))(; ?charset=[a-z0-9-]+)?$/i;

export async function driveCreateFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const name = typeof args.name === "string" ? args.name : "";
  if (!name) {
    throw new Error("drive_create_file requires a non-empty 'name' string");
  }
  if (HEADER_INJECTION_RE.test(name)) {
    throw new Error(
      "drive_create_file: 'name' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
    );
  }
  if (Buffer.byteLength(name, "utf8") > FOLDER_NAME_MAX_BYTES) {
    throw new Error(
      `drive_create_file: 'name' exceeds ${FOLDER_NAME_MAX_BYTES} bytes UTF-8`,
    );
  }

  if (typeof args.content !== "string") {
    throw new Error("drive_create_file requires a 'content' string (UTF-8 text)");
  }
  const content = args.content;
  // 5 MB cap reusing DRIVE_MAX_BYTES (value only — this is a client-side input
  // validation, NOT the download `file_too_large` code; see design §4).
  if (Buffer.byteLength(content, "utf8") > DRIVE_MAX_BYTES) {
    throw new Error(
      `drive_create_file: 'content' exceeds ${DRIVE_MAX_BYTES} bytes (5 MB UTF-8 text cap)`,
    );
  }

  const mimeType = args.mime_type === undefined
    ? "text/plain"
    : typeof args.mime_type === "string"
      ? args.mime_type
      : "";
  if (!mimeType || !CREATE_FILE_MIME_RE.test(mimeType)) {
    throw new Error(
      "drive_create_file: 'mime_type' must be a text MIME type (text/*, application/json, application/xml, text/csv, text/markdown, …); binary/base64 upload is not supported",
    );
  }

  let parentId: string | undefined;
  if (args.parent_id !== undefined) {
    if (typeof args.parent_id !== "string" || !DRIVE_FILE_ID_RE.test(args.parent_id)) {
      throw new Error(
        "drive_create_file: 'parent_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
      );
    }
    parentId = args.parent_id;
  }

  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.create({
      requestBody: {
        name,
        mimeType,
        ...(parentId !== undefined && { parents: [parentId] }),
      },
      media: { mimeType, body: content },
      fields: "id,name,mimeType,parents,webViewLink,size",
      supportsAllDrives: true,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_create_file", email: requireGoogle(ctx).accountId });
  }
}

export async function driveCopyFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.file_id !== "string" || !DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      "drive_copy_file requires a valid 'file_id' (^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
    );
  }
  const fileId = args.file_id;

  let name: string | undefined;
  if (args.name !== undefined) {
    if (typeof args.name !== "string" || !args.name) {
      throw new Error("drive_copy_file: 'name' must be a non-empty string when provided");
    }
    if (HEADER_INJECTION_RE.test(args.name)) {
      throw new Error(
        "drive_copy_file: 'name' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
      );
    }
    if (Buffer.byteLength(args.name, "utf8") > FOLDER_NAME_MAX_BYTES) {
      throw new Error(`drive_copy_file: 'name' exceeds ${FOLDER_NAME_MAX_BYTES} bytes UTF-8`);
    }
    name = args.name;
  }

  let parentId: string | undefined;
  if (args.parent_id !== undefined) {
    if (typeof args.parent_id !== "string" || !DRIVE_FILE_ID_RE.test(args.parent_id)) {
      throw new Error(
        "drive_copy_file: 'parent_id' invalid (expected ^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
      );
    }
    parentId = args.parent_id;
  }

  // No ancestor-cache clear: copy mints a brand-new file id never present in the
  // whitelist cache, so no stale entry can exist (contrast drive_move_file §3.1).
  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.copy({
      fileId,
      requestBody: {
        ...(name !== undefined && { name }),
        ...(parentId !== undefined && { parents: [parentId] }),
      },
      fields: "id,name,mimeType,parents,webViewLink",
      supportsAllDrives: true,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_copy_file", email: requireGoogle(ctx).accountId });
  }
}

export async function driveRenameFile(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.file_id !== "string" || !DRIVE_FILE_ID_RE.test(args.file_id)) {
    throw new Error(
      "drive_rename_file requires a valid 'file_id' (^[a-zA-Z0-9_-]{20,}$); did you paste a URL?",
    );
  }
  const fileId = args.file_id;

  const hasName = args.name !== undefined;
  const hasDescription = args.description !== undefined;
  if (!hasName && !hasDescription) {
    throw new Error("drive_rename_file requires at least one of {name, description}");
  }

  let name: string | undefined;
  if (hasName) {
    if (typeof args.name !== "string" || !args.name) {
      throw new Error("drive_rename_file: 'name' must be a non-empty string when provided");
    }
    if (HEADER_INJECTION_RE.test(args.name)) {
      throw new Error(
        "drive_rename_file: 'name' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
      );
    }
    if (Buffer.byteLength(args.name, "utf8") > FOLDER_NAME_MAX_BYTES) {
      throw new Error(`drive_rename_file: 'name' exceeds ${FOLDER_NAME_MAX_BYTES} bytes UTF-8`);
    }
    name = args.name;
  }

  let description: string | undefined;
  if (hasDescription) {
    if (typeof args.description !== "string") {
      throw new Error("drive_rename_file: 'description' must be a string when provided");
    }
    // NO HEADER_INJECTION_RE — description is body content (mirrors
    // calendar_create_event); sanitize-on-read wraps any echoed text. Byte cap only.
    if (Buffer.byteLength(args.description, "utf8") > DRIVE_DESCRIPTION_MAX_BYTES) {
      throw new Error(
        `drive_rename_file: 'description' exceeds ${DRIVE_DESCRIPTION_MAX_BYTES} bytes UTF-8`,
      );
    }
    description = args.description;
  }

  // files.update with name/description ONLY — NO addParents/removeParents, so
  // the parent chain is unchanged and the drive-whitelist ancestor cache stays
  // valid (no clear needed; contrast drive_move_file §3.1).
  try {
    const drive = driveClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await drive.files.update({
      fileId,
      requestBody: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
      },
      fields: "id,name,description",
      supportsAllDrives: true,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "drive_rename_file", email: requireGoogle(ctx).accountId });
  }
}

