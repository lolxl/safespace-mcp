// Drive tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  DRIVE_READONLY,
  DRIVE,
} from "./scopes";

export const driveTools: Record<string, ToolDef> = {
  drive_search: {
    name: "drive_search",
    description:
      "Search Google Drive files in the active account. Uses Drive query grammar (NOT Gmail's `from:` syntax): e.g. `name contains 'invoice'`, `mimeType = 'application/pdf'`, `'parentFolderId' in parents`, `modifiedTime > '2024-01-01T00:00:00Z'`. Multiple clauses joined with `and`/`or`. Returns files[{id, name, mimeType, modifiedTime, webViewLink, size, iconLink, parents}] + nextPageToken. Use drive_get_file_content to read body.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "Drive query, e.g. `name contains 'invoice' and mimeType = 'application/pdf'`. See https://developers.google.com/drive/api/guides/search-files for syntax.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 10,
          description: "Maximum number of files to return (capped at 50).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE_READONLY],
    handler: handlers.driveSearch,
    min_tier: "read",
  },
  drive_get_file_content: {
    name: "drive_get_file_content",
    description:
      "Read a Drive file's text body. Pre-flights metadata; rejects files > 5 MB (file_too_large) and PDF/image/binary types (file_unsupported_binary). Google Docs/Sheets/Slides are exported to text/plain or text/csv. text/* and JSON/XML/YAML pass through as UTF-8. Returns {id, name, mimeType, size, content} — content wraps via sanitize.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "File id from drive_search (e.g. '1ABC_def-XYZ').",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE_READONLY],
    handler: handlers.driveGetFileContent,
    min_tier: "read",
  },
  drive_share_file: {
    name: "drive_share_file",
    description:
      "Share a Drive file with anyone-with-link or a specific email (WRITE OPERATION, externally visible — once a public link is created and accessed, archived / mirrored content cannot be revoked). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=share in the proxy environment (the `share` tier is broader than `write` because anyone-with-link permissions can leak externally; users are expected to load only low-risk accounts in tier=share). When `drive-whitelist.json` (v2.1) is present, only files whose ancestors include a whitelisted folder ID (or files whose own ID is whitelisted) can be shared — `drive_unshare_file` bypasses this gate (recovery > policy). When `SAFESPACE_RECIPIENT_ALLOW` (v2.2) is set, share_type=user is additionally gated by target_email matching the allowlist. Roles limited to 'reader' or 'commenter' — 'writer' / 'owner' rejected. share_type='user' requires target_email AND expiration_days (1-365); share_type='anyone' must omit both (Google API does not support expiration on anyone permissions, so anyone shares are effectively permanent — drive_unshare_file is the recovery path). Returns the created Permission resource — record .id for later unshare. Every successful call produces one audit JSONL line with target_email_hash (HMAC-SHA256), file_id, role, and granted_permission_id.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Drive file id (e.g. '1ABC_def-XYZ', 20+ url-safe chars). NOT a URL — paste just the id segment.",
        },
        share_type: {
          type: "string",
          enum: ["anyone", "user"],
          description: "'anyone' = anyone with the link can access (permanent, no expiration); 'user' = invite a specific email (expiration required).",
        },
        role: {
          type: "string",
          enum: ["reader", "commenter"],
          description: "Permission role. 'writer' / 'owner' / 'organizer' / 'fileOrganizer' are blocked.",
        },
        target_email: {
          type: "string",
          description: "Email to invite. REQUIRED when share_type='user'. MUST BE OMITTED when share_type='anyone'.",
        },
        expiration_days: {
          type: "integer",
          minimum: 1,
          maximum: 365,
          description: "Days until permission expires (1-365). REQUIRED when share_type='user'. MUST BE OMITTED when share_type='anyone' (Google API rejects expiration on anyone permissions).",
        },
        notify: {
          type: "boolean",
          default: true,
          description: "Whether Google should email the target (only meaningful for share_type='user'). Default true.",
        },
        account_id: {
          type: "string",
          description: "Email of the sharing account; defaults to the most recently used account.",
        },
      },
      required: ["file_id", "share_type", "role"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveShareFile,
    min_tier: "write",
  },
  drive_unshare_file: {
    name: "drive_unshare_file",
    description:
      "Revoke a Drive permission previously created by drive_share_file (or by Drive web UI). Recovery counterpart to drive_share_file — available at SAFESPACE_TIER=read (the lowest tier, so brakes can run even when share + write are locked down) and bypasses v2.1 drive-whitelist / v2.2 recipient gates unconditionally (recovery > policy). Internally calls permissions.list, matches by (share_type, target_email) tuple, then deletes the matching permission. Returns {deleted_permission_id, file_id}. For share_type='user', target_email is required and matched case-insensitively. For share_type='anyone', target_email must be omitted (Google enforces at most one anyone permission per file). NOTE: cached / mirrored content from a previously-leaked anyone-link is NOT recoverable — unsharing only stops future access via the permission. List step is bounded at 100 permissions; files with more user permissions need Drive web UI.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Drive file id (e.g. '1ABC_def-XYZ', 20+ url-safe chars). NOT a URL.",
        },
        share_type: {
          type: "string",
          enum: ["anyone", "user"],
          description: "Which kind of permission to remove. Must match how the share was created.",
        },
        target_email: {
          type: "string",
          description: "Email of the user permission to revoke. REQUIRED when share_type='user'. MUST BE OMITTED when share_type='anyone'. Case-insensitive match.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["file_id", "share_type"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveUnshareFile,
    min_tier: "read",
  },
  // ───────── v1.42 A3 + A4 — folder-ops + permissions-list ─────────
  // Zero new OAuth scope: create/move covered by DRIVE, permissions.list by
  // DRIVE_READONLY. Security analysis: docs/v1.42-drive-folder-ops-permissions.md.
  drive_create_folder: {
    name: "drive_create_folder",
    description:
      "Create a new folder in Google Drive (WRITE OPERATION). Requires SAFESPACE_TIER=write. Uses files.create with the folder mimeType. 'name' is required (rejects CR/LF/NUL/NEL/U+2028/U+2029 control chars; capped at 1000 bytes UTF-8). 'parent_id' is optional — when omitted the folder is created in My Drive root; when present it must be a Drive folder id (^[a-zA-Z0-9_-]{20,}$, NOT a URL). Creating an empty folder shares nothing, so there is NO drive-whitelist gate. Fields outside {name, parent_id, account_id} are REJECTED (additionalProperties:false). Returns the created File resource {id, name, mimeType, parents, webViewLink}.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Folder name. Control chars (CR/LF/NUL/NEL/U+2028/U+2029) rejected; max 1000 bytes UTF-8.",
        },
        parent_id: {
          type: "string",
          description: "Optional parent folder id (20+ url-safe chars). Omit to create in My Drive root. NOT a URL.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveCreateFolder,
    min_tier: "write",
  },
  drive_move_file: {
    name: "drive_move_file",
    description:
      "Move a Drive file or folder by changing its parents (WRITE OPERATION). Requires SAFESPACE_TIER=write. Uses files.update with addParents/removeParents. 'file_id' + 'add_parents' (≥1 folder id) are required; 'remove_parents' is optional (the current parent[s], to relocate rather than add a second parent). All ids must be ^[a-zA-Z0-9_-]{20,}$ (NOT URLs). SECURITY: after a successful move the per-process drive-whitelist ancestor cache is cleared so a subsequent drive_share_file re-walks the new parent chain (prevents a stale cache from sharing a file moved OUT of a whitelisted folder). NOTE: moving a file INTO a whitelisted folder makes it shareable via drive_share_file — the whitelist constrains share-ability by LOCATION; pair it with SAFESPACE_RECIPIENT_ALLOW (see SECURITY.md). Returns {id, name, parents}.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Drive file/folder id to move (20+ url-safe chars). NOT a URL.",
        },
        add_parents: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          description: "Folder id(s) to add as parents. At least one required.",
        },
        remove_parents: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          description: "Optional folder id(s) to remove (the current parent, for a true move). Omit to add a parent without removing the old one.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["file_id", "add_parents"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveMoveFile,
    min_tier: "write",
  },
  drive_list_permissions: {
    name: "drive_list_permissions",
    description:
      "List who currently has access to a Drive file or folder (READ OPERATION). Requires SAFESPACE_TIER=read. Uses permissions.list. Returns permissions[{id, type, role, emailAddress, displayName, domain, expirationTime, deleted}] (up to 100; files with more permissions need Drive web UI). Use before drive_unshare_file to find which permission to revoke. Sharee displayName + emailAddress are sanitize-wrapped (a sharee can set a prompt-injection display name). Returns the raw permissions list.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Drive file/folder id (20+ url-safe chars). NOT a URL.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["file_id"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE_READONLY],
    handler: handlers.driveListPermissions,
    min_tier: "read",
  },
  // ───────── v1.46 B1 — file-write (create / copy / rename) ─────────
  // Zero new OAuth scope: all three are files.* mutations covered by the full
  // DRIVE scope (already requested for drive_share_file / drive_create_folder /
  // drive_move_file). Non-destructive — NO trash/delete. Security analysis:
  // docs/v1.46-drive-file-write.md.
  drive_create_file: {
    name: "drive_create_file",
    description:
      "Create a new Drive file with UTF-8 TEXT content (WRITE OPERATION). Requires SAFESPACE_TIER=write. Uses files.create with a multipart media upload. 'name' is required (rejects CR/LF/NUL/NEL/U+2028/U+2029 control chars; capped at 1000 bytes UTF-8). 'content' is required and must be UTF-8 text (capped at 5 MB) — there is NO base64/binary upload path. 'mime_type' is optional (default 'text/plain') and is restricted to text types (text/*, application/json, application/xml, text/csv, text/markdown, application/yaml, …); binary types (PDF/image/zip/Office/Google-native) are REJECTED. 'parent_id' is optional — when omitted the file is created in My Drive root; when present it must be a Drive folder id (^[a-zA-Z0-9_-]{20,}$, NOT a URL). Creating a file shares nothing, so there is NO drive-whitelist gate (but note: a file created INSIDE a whitelisted folder becomes shareable via drive_share_file — see SECURITY.md §3). Fields outside {name, content, mime_type, parent_id, account_id} are REJECTED (additionalProperties:false). Returns the created File resource {id, name, mimeType, parents, webViewLink, size}.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "File name. Control chars (CR/LF/NUL/NEL/U+2028/U+2029) rejected; max 1000 bytes UTF-8.",
        },
        content: {
          type: "string",
          description: "UTF-8 text body. Max 5 MB. Binary/base64 upload is NOT supported.",
        },
        mime_type: {
          type: "string",
          default: "text/plain",
          description: "Text MIME type (default 'text/plain'). Must be text/* or a structured-text type (json/xml/xhtml+xml/yaml/csv/markdown/x-ndjson). Binary types rejected.",
        },
        parent_id: {
          type: "string",
          description: "Optional parent folder id (20+ url-safe chars). Omit to create in My Drive root. NOT a URL.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["name", "content"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveCreateFile,
    min_tier: "write",
  },
  drive_copy_file: {
    name: "drive_copy_file",
    description:
      "Copy an existing Drive file (WRITE OPERATION). Requires SAFESPACE_TIER=write. Uses files.copy. 'file_id' (the source) is required (^[a-zA-Z0-9_-]{20,}$, NOT a URL). 'name' is optional (the new file's name; same control-char + 1000-byte rules as drive_create_file). 'parent_id' is optional (the destination folder; default = same parent as the source). Copy mints a BRAND-NEW file id, so there is no drive-whitelist ancestor-cache interaction (unlike drive_move_file). Note: copying INTO a whitelisted folder makes the copy shareable via drive_share_file — see SECURITY.md §3. Fields outside {file_id, name, parent_id, account_id} are REJECTED (additionalProperties:false). Returns the new File resource {id, name, mimeType, parents, webViewLink}.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Source Drive file id to copy (20+ url-safe chars). NOT a URL.",
        },
        name: {
          type: "string",
          description: "Optional new name for the copy. Control chars rejected; max 1000 bytes UTF-8. Omit to let Drive name it.",
        },
        parent_id: {
          type: "string",
          description: "Optional destination folder id (20+ url-safe chars). Omit to copy into the source's parent. NOT a URL.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["file_id"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveCopyFile,
    min_tier: "write",
  },
  drive_rename_file: {
    name: "drive_rename_file",
    description:
      "Rename a Drive file/folder or update its description (WRITE OPERATION). Requires SAFESPACE_TIER=write. Uses files.update with name/description ONLY — it does NOT change parents (use drive_move_file for that), so the drive-whitelist ancestor cache is unaffected. 'file_id' is required (^[a-zA-Z0-9_-]{20,}$, NOT a URL). At least one of 'name' / 'description' is required. 'name' rejects CR/LF/NUL/NEL/U+2028/U+2029 and is capped at 1000 bytes UTF-8; 'description' is body content (no header-char check, mirrors calendar event descriptions) capped at 8000 bytes UTF-8 (pass an empty string to clear it). Fields outside {file_id, name, description, account_id} are REJECTED (additionalProperties:false). Returns {id, name, description}.",
    inputSchema: {
      type: "object",
      properties: {
        file_id: {
          type: "string",
          description: "Drive file/folder id (20+ url-safe chars). NOT a URL.",
        },
        name: {
          type: "string",
          description: "New name. Control chars (CR/LF/NUL/NEL/U+2028/U+2029) rejected; max 1000 bytes UTF-8.",
        },
        description: {
          type: "string",
          description: "New description (body content; max 8000 bytes UTF-8). Empty string clears it.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["file_id"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE],
    handler: handlers.driveRenameFile,
    min_tier: "write",
  },
};
