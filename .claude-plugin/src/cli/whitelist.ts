// v2.3 — `safespace whitelist {add,remove,list}` CLI.
//
// PR-C deferred from v2.1: gives users a way to inspect / mutate
// drive-whitelist.json without hand-editing JSON. Loads + saves via the
// same `policy/drive-whitelist.ts` module the proxy reads at startup, so
// the CLI cannot produce a file shape the proxy can't load.
//
// Per the v2.1 load-once-at-startup model: CLI edits take effect on the
// NEXT proxy restart (not the running session). This is documented in the
// success messages.

import { configDir } from "../auth/keychain";
import { CliError, type CliIO } from "../cli";
import {
  isValidDriveId,
  loadWhitelist,
  saveWhitelist,
  type WhitelistEntryType,
  type WhitelistFile,
} from "../policy/drive-whitelist";

const USAGE =
  "usage: safespace whitelist <list|add|remove> ...\n" +
  "       safespace whitelist list\n" +
  "       safespace whitelist add <drive-id> --type <folder|file> [--label <text>]\n" +
  "       safespace whitelist remove <drive-id>";

export async function runWhitelistCmd(rest: string[], io: CliIO): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "list") return runList(args, io);
  if (sub === "add") return runAdd(args, io);
  if (sub === "remove") return runRemove(args, io);
  throw new CliError(`unknown whitelist subcommand: ${sub}\n       ${USAGE}`);
}

async function runList(args: string[], io: CliIO): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'list'\n       ${USAGE}`);
  }
  const state = await loadWhitelist(configDir());
  if (state.kind === "absent") {
    io.out("(no drive-whitelist.json; policy is OFF — all share_type=user calls bypass v2.1 gate)");
    return;
  }
  if (state.kind === "malformed") {
    io.err(`error: drive-whitelist.json is malformed (${state.error})`);
    io.err("       file present but unparseable → policy is in default-deny (all rejected).");
    throw new CliError("whitelist load failed");
  }
  const entries = state.file.entries;
  if (entries.length === 0) {
    io.out("(empty entries; policy is in default-deny — all share_type=user calls rejected)");
    return;
  }
  const TYPE_W = 7, ID_W = 44, LABEL_W = 28, DATE_W = 20;
  const row = (t: string, id: string, lab: string, added: string) =>
    `${t.padEnd(TYPE_W).slice(0, TYPE_W)} ${id.padEnd(ID_W).slice(0, ID_W)} ${lab.padEnd(LABEL_W).slice(0, LABEL_W)} ${added.padEnd(DATE_W).slice(0, DATE_W)}`;
  io.out(row("TYPE", "ID", "LABEL", "ADDED"));
  for (const e of entries) {
    io.out(row(e.type, e.id, e.label, e.added_at.slice(0, 19)));
  }
  io.out(
    `\n${entries.length} entr${entries.length === 1 ? "y" : "ies"} • updated_at ${state.file.updated_at.slice(0, 19)}`,
  );
}

async function runAdd(args: string[], io: CliIO): Promise<void> {
  const { id, type, label } = parseAddArgs(args);

  const state = await loadWhitelist(configDir());
  if (state.kind === "malformed") {
    throw new CliError(
      `drive-whitelist.json is malformed (${state.error}); please fix or delete it before adding entries.`,
    );
  }

  const existing = state.kind === "loaded" ? state.file : freshFile();

  // Dedup: same id (regardless of type) → no-op + stderr warn. Why "regardless
  // of type": two entries with the same id but different `type` would create a
  // confusing config — if a user wants to switch type, removeWhitelist then
  // re-add. The doctor would still show both as "loaded" so silently allowing
  // both invites a foot-gun.
  const existingEntry = existing.entries.find((e) => e.id === id);
  if (existingEntry !== undefined) {
    io.err(
      `warning: ${id} already in whitelist (type=${existingEntry.type}, label=${quote(existingEntry.label)}); not modified.`,
    );
    return;
  }

  const next: WhitelistFile = {
    schema_version: 1,
    updated_at: new Date().toISOString(),
    entries: [
      ...existing.entries,
      {
        type,
        id,
        label: label ?? "",
        added_at: new Date().toISOString(),
      },
    ],
  };

  try {
    await saveWhitelist(configDir(), next);
  } catch (e) {
    throw new CliError(`save failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  io.out(`added: type=${type} id=${id}${label ? ` label=${quote(label)}` : ""}`);
  io.out(`(restart Claude Code to pick up — proxy reads whitelist once at startup)`);
}

async function runRemove(args: string[], io: CliIO): Promise<void> {
  const id = args[0];
  if (!id) {
    throw new CliError(`usage: safespace whitelist remove <drive-id>\n       ${USAGE}`);
  }
  if (args.length > 1) {
    throw new CliError(`unexpected argument(s) for 'remove'\n       ${USAGE}`);
  }
  if (!isValidDriveId(id)) {
    throw new CliError(
      `invalid Drive ID format: must be 20+ alphanumeric/_/- characters`,
    );
  }

  const state = await loadWhitelist(configDir());
  if (state.kind === "absent") {
    throw new CliError("no drive-whitelist.json exists — nothing to remove.");
  }
  if (state.kind === "malformed") {
    throw new CliError(
      `drive-whitelist.json is malformed (${state.error}); please fix or delete it before removing entries.`,
    );
  }

  const before = state.file.entries.length;
  const kept = state.file.entries.filter((e) => e.id !== id);
  if (kept.length === before) {
    throw new CliError(
      `id not found in whitelist: ${id}\n       run \`safespace whitelist list\` to see registered entries`,
    );
  }

  const next: WhitelistFile = {
    schema_version: 1,
    updated_at: new Date().toISOString(),
    entries: kept,
  };
  try {
    await saveWhitelist(configDir(), next);
  } catch (e) {
    throw new CliError(`save failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  io.out(`removed: ${id} (${before - kept.length} entry; ${kept.length} remaining)`);
  io.out(`(restart Claude Code to pick up — proxy reads whitelist once at startup)`);
}

interface AddArgs {
  id: string;
  type: WhitelistEntryType;
  label: string | undefined;
}

function parseAddArgs(args: string[]): AddArgs {
  if (args.length === 0) {
    throw new CliError(
      `usage: safespace whitelist add <drive-id> --type <folder|file> [--label <text>]`,
    );
  }
  const id = args[0]!;
  if (!isValidDriveId(id)) {
    throw new CliError(
      `invalid Drive ID format: must be 20+ alphanumeric/_/- characters`,
    );
  }
  let type: WhitelistEntryType | undefined;
  let label: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const f = args[i];
    if (f === "--type") {
      const v = args[++i];
      if (v !== "folder" && v !== "file") {
        throw new CliError(`--type must be 'folder' or 'file'`);
      }
      type = v;
    } else if (f === "--label") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--label requires a string argument`);
      if (/[\r\n\0]/.test(v)) {
        throw new CliError(`--label must not contain newlines or NUL`);
      }
      if (v.length > 100) throw new CliError(`--label exceeds 100-character cap`);
      label = v;
    } else {
      throw new CliError(`unknown flag: ${f}`);
    }
  }
  if (type === undefined) {
    throw new CliError(`--type <folder|file> is required`);
  }
  return { id, type, label };
}

function freshFile(): WhitelistFile {
  return {
    schema_version: 1,
    updated_at: new Date().toISOString(),
    entries: [],
  };
}

function quote(s: string): string {
  return `'${s.replace(/'/g, "\\'")}'`;
}
