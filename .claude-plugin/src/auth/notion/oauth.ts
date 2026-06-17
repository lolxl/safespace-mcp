// v1.78 (Notion B) / v1.79 (multi-workspace) — the Notion OAuth account + token store.
// Notion is SafeSpace's 3rd OAuth source; as of v1.79 it is MULTI-account (multiple
// consented workspaces, one active), mirroring Google. The workspaces + the active pointer
// live in a single `notion-account.json` ({ workspaces:[{workspaceId, workspaceName}],
// active }); each TOKEN lives in the SAME swappable SecretBackend the Google OAuth tokens +
// the class-B service tokens use, under a RESERVED key `notion:<workspaceId>` — it contains
// ":" and no "@", so it can never collide with a Google email key (the keying discipline of
// auth/github/store.ts + auth/service-token-store.ts).
//
// BACK-COMPAT: the v1.78 single-object shape (top-level `workspaceId`) is read as a
// one-element index with that workspace active — a read-only fallback (never written); the
// first new consent persists the new shape forward.
//
// The token is NEVER logged, echoed, or stored as a field — handlers read it via the
// `oauth` Credential's getter, inline when building the Authorization header.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { resolveOperatorId } from "../../identity/operator-id";
import { configDir } from "../keychain";
import type { SecretBackend } from "../secret-backend";
import { selectBackend } from "../select-backend";

/** A Notion workspace id: a dashed UUID (8-4-4-4-12 hex). Anchored — rejects path
 *  separators / CRLF / "@" / ":" — so it is safe as a SecretBackend key segment. */
export const NOTION_WORKSPACE_ID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The workspace name is the operator's own label — display-only (never a key/URL/tool
 *  field). Length-capped defensively. Exported so consent.ts caps with the same value. */
export const WORKSPACE_NAME_MAX = 256;

const ACCOUNT_FILE = "notion-account.json";

/** A consented Notion workspace: its id + display name. */
export interface NotionAccount {
  readonly workspaceId: string;
  readonly workspaceName: string;
}

/** The persisted multi-workspace store (v1.79): the consented workspaces + the active one. */
export interface NotionStore {
  readonly workspaces: NotionAccount[];
  readonly active: string | null;
}

function accountPath(): string {
  return path.join(configDir(), ACCOUNT_FILE);
}

const EMPTY: NotionStore = { workspaces: [], active: null };

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** A valid workspace entry: a UUID id + a string name (name capped on read). */
function parseAccount(v: unknown): NotionAccount | null {
  if (
    isObj(v) &&
    typeof v.workspaceId === "string" &&
    NOTION_WORKSPACE_ID_RE.test(v.workspaceId) &&
    typeof v.workspaceName === "string"
  ) {
    return { workspaceId: v.workspaceId, workspaceName: v.workspaceName.slice(0, WORKSPACE_NAME_MAX) };
  }
  return null;
}

/** Read the multi-workspace store, or an empty store if missing/corrupt. Tolerates a
 *  hand-edited file (drops invalid entries). BACK-COMPAT: a v1.78 single-object shape
 *  (top-level `workspaceId`) → a one-element index with that workspace active. */
export async function readNotionStore(): Promise<NotionStore> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await fs.readFile(accountPath(), "utf8"));
  } catch {
    return EMPTY;
  }
  if (!isObj(parsed)) return EMPTY;
  // v1.78 back-compat: a top-level workspaceId is the old single-account shape.
  if (typeof parsed.workspaceId === "string") {
    const one = parseAccount(parsed);
    return one ? { workspaces: [one], active: one.workspaceId } : EMPTY;
  }
  // v1.79 shape: { workspaces:[...], active }.
  const raw = Array.isArray(parsed.workspaces) ? parsed.workspaces : [];
  const workspaces: NotionAccount[] = [];
  const seen = new Set<string>();
  for (const e of raw) {
    const a = parseAccount(e);
    if (a && !seen.has(a.workspaceId)) {
      seen.add(a.workspaceId);
      workspaces.push(a);
    }
  }
  // active is honoured only if it still names a stored workspace.
  const active =
    typeof parsed.active === "string" && seen.has(parsed.active) ? parsed.active : null;
  return { workspaces, active };
}

/** Persist the store (mode 0o600, dir 0o700). Rejects an invalid active/workspace id
 *  before any filesystem work. */
export async function writeNotionStore(store: NotionStore): Promise<void> {
  for (const a of store.workspaces) {
    if (!NOTION_WORKSPACE_ID_RE.test(a.workspaceId)) {
      throw new Error("writeNotionStore: invalid notion workspace id");
    }
  }
  if (store.active != null && !store.workspaces.some((a) => a.workspaceId === store.active)) {
    throw new Error("writeNotionStore: active is not a stored workspace");
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const out = {
    workspaces: store.workspaces.map((a) => ({
      workspaceId: a.workspaceId,
      workspaceName: a.workspaceName.slice(0, WORKSPACE_NAME_MAX),
    })),
    active: store.active,
  };
  await fs.writeFile(accountPath(), `${JSON.stringify(out, null, 2)}\n`, { mode: 0o600 });
}

/** The consented workspaces (the index). */
export async function readNotionAccounts(): Promise<NotionAccount[]> {
  return (await readNotionStore()).workspaces;
}

/** The active workspace id (validated to still be in the index), or null. */
export async function readNotionActiveWorkspace(): Promise<string | null> {
  return (await readNotionStore()).active;
}

/** Upsert a workspace (replace if its id already exists — a re-consent updates the name)
 *  and make it active. Returns whether it was NEWLY added (vs an upsert of an existing
 *  workspace). NOTE: the consent flow computes its own `wasNew` BEFORE the token write (to
 *  arm cleanup even if this call fails), so it does not consume this return value. */
export async function addNotionAccount(account: NotionAccount): Promise<{ wasNew: boolean }> {
  if (!NOTION_WORKSPACE_ID_RE.test(account.workspaceId)) {
    throw new Error("addNotionAccount: invalid notion workspace id");
  }
  const store = await readNotionStore();
  const wasNew = !store.workspaces.some((a) => a.workspaceId === account.workspaceId);
  const workspaces = store.workspaces.filter((a) => a.workspaceId !== account.workspaceId);
  workspaces.push({ workspaceId: account.workspaceId, workspaceName: account.workspaceName });
  await writeNotionStore({ workspaces, active: account.workspaceId });
  return { wasNew };
}

/** Remove a workspace from the index; clears `active` if it pointed there. Idempotent. */
export async function removeNotionAccount(workspaceId: string): Promise<void> {
  const store = await readNotionStore();
  const workspaces = store.workspaces.filter((a) => a.workspaceId !== workspaceId);
  const active = store.active === workspaceId ? null : store.active;
  if (workspaces.length === 0) {
    await fs.unlink(accountPath()).catch(() => undefined);
    return;
  }
  await writeNotionStore({ workspaces, active });
}

/** Set the active workspace (must already be in the index). */
export async function setNotionActiveWorkspace(workspaceId: string): Promise<void> {
  const store = await readNotionStore();
  if (!store.workspaces.some((a) => a.workspaceId === workspaceId)) {
    throw new Error("setNotionActiveWorkspace: not a stored workspace");
  }
  await writeNotionStore({ workspaces: store.workspaces, active: workspaceId });
}

/** Resolve `idOrName` against the consented workspaces: an exact workspace id (UUIDs are
 *  case-insensitive) first, else a UNIQUE case-insensitive name match. Returns the match,
 *  "ambiguous" (>1 name match), or null (no match). PURE — reused by resolveAccount + CLI. */
export function findNotionWorkspace(
  idOrName: string,
  accounts: NotionAccount[],
): NotionAccount | "ambiguous" | null {
  const lc = idOrName.toLowerCase();
  const byId = accounts.find((a) => a.workspaceId.toLowerCase() === lc);
  if (byId) return byId;
  const byName = accounts.filter((a) => a.workspaceName.toLowerCase() === lc);
  if (byName.length === 1) return byName[0]!;
  if (byName.length > 1) return "ambiguous";
  return null;
}

/* ── token (SecretBackend, reserved key `notion:<workspaceId>`) ────────────── */

let cachedBackend: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cachedBackend === null) cachedBackend = selectBackend();
  return cachedBackend;
}

/** Test-only: drop the cached backend so a test can flip the backend selection (mirror
 *  github-store.__resetGithubBackendForTests). */
export function __resetNotionBackendForTests(): void {
  cachedBackend = null;
}

function reservedKey(workspaceId: string): string {
  // Defense-in-depth: validate BEFORE constructing the SecretBackend key. The consent
  // flow calls writeNotionToken with a workspace id from the OAuth response; an
  // unvalidated id (a `:` / path separator) could shape an unexpected key.
  if (!NOTION_WORKSPACE_ID_RE.test(workspaceId)) {
    throw new Error("notion store: invalid notion workspace id");
  }
  return `notion:${workspaceId}`;
}

/** Read the stored Notion token for `workspaceId`, or null if none. */
export async function readNotionToken(workspaceId: string): Promise<string | null> {
  return backend().getToken(resolveOperatorId(), reservedKey(workspaceId));
}

/** Persist the Notion token (the consent writer). Opaque to the backend. */
export async function writeNotionToken(workspaceId: string, token: string): Promise<void> {
  await backend().setToken(resolveOperatorId(), reservedKey(workspaceId), token);
}

/** Remove the stored Notion token (account-revoke; idempotent at the backend). */
export async function clearNotionToken(workspaceId: string): Promise<void> {
  await backend().deleteToken(resolveOperatorId(), reservedKey(workspaceId));
}
