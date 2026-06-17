// v2.3 — `safespace recipient {add,remove,list}` CLI.
//
// PR-C deferred from v2.2: lets users mutate SAFESPACE_RECIPIENT_ALLOW in
// the persistent .env baseline without hand-editing the file. Tokens are
// validated through the same parser the policy module uses, so the CLI
// cannot produce a value the proxy can't load.
//
// Surface decisions (locked in v2.3 PR-A spec):
//   - Modifies SAFESPACE_RECIPIENT_ALLOW only. The _EXTRA companion is
//     shell-additive (session-only by design) — persisting it through a
//     CLI would defeat its purpose.
//   - `list` shows the full ALLOW + EXTRA + self-implicit picture. Doctor
//     intentionally hides values (forensic-safe); CLI is operator-driven,
//     showing real values is appropriate.
//   - CLI edits take effect on the NEXT Claude Code restart, since the
//     proxy reads .env at launch via `bun --env-file=`.

import * as path from "node:path";
import { configDir, loadIndex } from "../auth/keychain";
import { CliError, type CliIO } from "../cli";
import {
  ENV_ALLOW,
  ENV_ALLOW_EXTRA,
  parseAllowlistTokens,
  type AllowlistEntry,
} from "../policy/recipient-allowlist";
import { EnvFileError, readEnvKey, writeEnvKey } from "./atomic-env";

const USAGE =
  "usage: safespace recipient <list|add|remove> ...\n" +
  "       safespace recipient list\n" +
  "       safespace recipient add <email|@domain> [<email|@domain> ...]\n" +
  "       safespace recipient remove <email|@domain> [<email|@domain> ...]";

function envFilePath(): string {
  return path.join(configDir(), ".env");
}

export async function runRecipientCmd(rest: string[], io: CliIO): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "list") return runList(args, io);
  if (sub === "add") return runAdd(args, io);
  if (sub === "remove") return runRemove(args, io);
  throw new CliError(`unknown recipient subcommand: ${sub}\n       ${USAGE}`);
}

async function runList(args: string[], io: CliIO): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'list'\n       ${USAGE}`);
  }

  const fp = envFilePath();
  let allowRaw: string | undefined;
  try {
    allowRaw = await readEnvKey(fp, ENV_ALLOW);
  } catch (e) {
    throw new CliError(formatEnvError(e));
  }

  // EXTRA is read from process.env, NOT from .env — it's intentionally a
  // shell-only var. Show whether the caller's shell currently has it set
  // so the user can spot "stale EXTRA" cases.
  const extraRaw = process.env[ENV_ALLOW_EXTRA];

  // Self-implicit: accounts.json emails.
  let selfEmails: string[] = [];
  try {
    const idx = await loadIndex();
    selfEmails = idx.accounts.map((a) => a.email);
  } catch {
    // No accounts file → no implicit allow. Surfaced as "0 self-emails".
  }

  if (allowRaw === undefined) {
    io.out(`${ENV_ALLOW}: <unset> — policy OFF (all recipients allowed except by other gates)`);
  } else if (allowRaw === "") {
    io.out(`${ENV_ALLOW}: <empty> — default-deny baseline (only self-emails + EXTRA pass)`);
  } else {
    const parsed = parseAllowlistTokens(allowRaw);
    io.out(`${ENV_ALLOW}: ${parsed.ok.length} entr${parsed.ok.length === 1 ? "y" : "ies"}`);
    for (const e of parsed.ok) io.out(`  ${formatEntry(e)}`);
    if (parsed.rejected.length > 0) {
      io.err(`warning: ${parsed.rejected.length} unparseable token(s) in .env — they will be ignored at runtime`);
    }
  }

  if (extraRaw === undefined) {
    io.out(`${ENV_ALLOW_EXTRA}: <unset>`);
  } else if (extraRaw === "") {
    io.out(`${ENV_ALLOW_EXTRA}: <empty>`);
  } else {
    const parsed = parseAllowlistTokens(extraRaw);
    io.out(`${ENV_ALLOW_EXTRA}: ${parsed.ok.length} entr${parsed.ok.length === 1 ? "y" : "ies"} (current shell only; not persisted)`);
    for (const e of parsed.ok) io.out(`  ${formatEntry(e)}`);
  }

  io.out(`self-send implicit: ${selfEmails.length} account email${selfEmails.length === 1 ? "" : "s"}`);
  for (const e of selfEmails) io.out(`  ${e}`);
}

async function runAdd(args: string[], io: CliIO): Promise<void> {
  if (args.length === 0) {
    throw new CliError(`usage: safespace recipient add <email|@domain> [...]\n       ${USAGE}`);
  }
  const fp = envFilePath();

  let current: string | undefined;
  try {
    current = await readEnvKey(fp, ENV_ALLOW);
  } catch (e) {
    throw new CliError(formatEnvError(e));
  }

  const currentParsed = parseAllowlistTokens(current);
  // Validate the new tokens by parsing exactly the same way the policy
  // module will. Any unparseable input is rejected here (all-or-nothing)
  // so the user never ends up with a partially-applied add.
  const newParsed = parseAllowlistTokens(args.join(","));
  if (newParsed.rejected.length > 0) {
    throw new CliError(
      `invalid recipient token(s) (must be 'localpart@domain.tld' or '@domain.tld'): ${newParsed.rejected.length} rejected`,
    );
  }

  const seenKeys = new Set(currentParsed.ok.map(entryKey));
  const added: AllowlistEntry[] = [];
  const skipped: AllowlistEntry[] = [];
  for (const e of newParsed.ok) {
    const k = entryKey(e);
    if (seenKeys.has(k)) {
      skipped.push(e);
    } else {
      seenKeys.add(k);
      added.push(e);
    }
  }

  if (added.length === 0) {
    io.err(
      `warning: all ${skipped.length} token(s) already in ${ENV_ALLOW}; .env not modified.`,
    );
    return;
  }

  const merged = [...currentParsed.ok, ...added];
  const value = merged.map(serializeEntry).join(",");

  try {
    await writeEnvKey(fp, ENV_ALLOW, value);
  } catch (e) {
    throw new CliError(formatEnvError(e));
  }

  io.out(
    `added ${added.length} entr${added.length === 1 ? "y" : "ies"} to ${ENV_ALLOW}` +
      (skipped.length > 0 ? ` (${skipped.length} already-present skipped)` : "") +
      `; ${merged.length} total.`,
  );
  io.out(`(restart Claude Code to pick up — .env is loaded at proxy launch)`);
}

async function runRemove(args: string[], io: CliIO): Promise<void> {
  if (args.length === 0) {
    throw new CliError(`usage: safespace recipient remove <email|@domain> [...]\n       ${USAGE}`);
  }
  const fp = envFilePath();

  let current: string | undefined;
  try {
    current = await readEnvKey(fp, ENV_ALLOW);
  } catch (e) {
    throw new CliError(formatEnvError(e));
  }

  if (current === undefined) {
    throw new CliError(`${ENV_ALLOW} is not set in .env — nothing to remove.`);
  }

  const currentParsed = parseAllowlistTokens(current);
  const targetParsed = parseAllowlistTokens(args.join(","));
  if (targetParsed.rejected.length > 0) {
    throw new CliError(
      `invalid recipient token(s) (must be 'localpart@domain.tld' or '@domain.tld'): ${targetParsed.rejected.length} rejected`,
    );
  }

  const removeKeys = new Set(targetParsed.ok.map(entryKey));
  const kept: AllowlistEntry[] = [];
  const removed: AllowlistEntry[] = [];
  for (const e of currentParsed.ok) {
    if (removeKeys.has(entryKey(e))) removed.push(e);
    else kept.push(e);
  }

  if (removed.length === 0) {
    throw new CliError(
      `no matching entries in ${ENV_ALLOW}: ${targetParsed.ok.length} requested, 0 found.\n       run \`safespace recipient list\` to see current entries`,
    );
  }

  // Surface partial-match cases so the user knows not all input applied.
  // Proceed anyway (consistent with `rm` semantics on mixed-existence input).
  const requestedKeys = new Set(targetParsed.ok.map(entryKey));
  const removedKeys = new Set(removed.map(entryKey));
  const missing = [...requestedKeys].filter((k) => !removedKeys.has(k));

  try {
    const value = kept.map(serializeEntry).join(",");
    // If everything was removed, write the empty-value baseline (= explicit
    // default-deny). Keep the line so the policy stays "active" not "off" —
    // going active→off would be a surprising side effect of `remove`.
    await writeEnvKey(fp, ENV_ALLOW, value);
  } catch (e) {
    throw new CliError(formatEnvError(e));
  }

  io.out(
    `removed ${removed.length} entr${removed.length === 1 ? "y" : "ies"} from ${ENV_ALLOW}; ${kept.length} remaining.`,
  );
  if (missing.length > 0) {
    io.err(`warning: ${missing.length} requested token(s) not present; ignored.`);
  }
  if (kept.length === 0) {
    io.out(`(${ENV_ALLOW} is now empty — default-deny baseline. Self-emails + EXTRA still pass.)`);
  }
  io.out(`(restart Claude Code to pick up — .env is loaded at proxy launch)`);
}

/** Canonical key for dedup + lookup. Domain is lowercased per RFC 5321
 *  §2.4; localpart kept case-sensitive (matches policy module). */
function entryKey(e: AllowlistEntry): string {
  if (e.kind === "domain") return `@${e.domain}`;
  return `${e.localpart}@${e.domain}`;
}

function serializeEntry(e: AllowlistEntry): string {
  return entryKey(e);
}

function formatEntry(e: AllowlistEntry): string {
  if (e.kind === "domain") return `@${e.domain} (any address at this domain)`;
  return `${e.localpart}@${e.domain}`;
}

function formatEnvError(e: unknown): string {
  if (e instanceof EnvFileError) {
    return `.env ${e.code}: ${e.message}`;
  }
  return e instanceof Error ? e.message : String(e);
}
