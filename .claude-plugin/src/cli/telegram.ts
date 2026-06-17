// v1.68 — `safespace telegram {set-token,status,clear-token}` CLI.
//
// Manages the Telegram Bot token (the second class-B service-token connector secret,
// after LINE) in the SecretBackend, plus a read-only status view.
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell
//     history / `ps` output). It is written via the service-token store (SecretBackend
//     — Keychain / encrypted FileBackend) and NEVER echoed back.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The env override SAFESPACE_TELEGRAM_BOT_TOKEN is shell-only and is NOT written by
//     this CLI (mirrors the recipient-allowlist EXTRA convention); status reports
//     whether it is currently set in the shell.

import {
  deleteServiceToken,
  hasServiceToken,
  serviceTokenEnvVar,
  setServiceToken,
} from "../auth/service-token-store";
import { CliError, type CliIO } from "../cli";
import { telegramAllowlistSummary } from "../policy/telegram-recipient-allowlist";

const USAGE =
  "usage: safespace telegram <set-token|status|clear-token>\n" +
  "       safespace telegram set-token    (reads the bot token from stdin)\n" +
  "       safespace telegram status\n" +
  "       safespace telegram clear-token";

// Single source of truth (avoids drift if the env var is ever renamed).
const ENV_TELEGRAM_BOT_TOKEN = serviceTokenEnvVar("telegram");

/** Injection seams (tests override; production uses the real store + stdin). */
export interface TelegramCmdDeps {
  /** Read the secret token (default: a trimmed line from process.stdin). */
  readSecret?: () => Promise<string>;
  setToken?: (token: string) => Promise<void>;
  hasToken?: () => Promise<boolean>;
  deleteToken?: () => Promise<void>;
}

async function defaultReadSecret(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Uint8Array);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

export async function runTelegramCmd(
  rest: string[],
  io: CliIO,
  deps: TelegramCmdDeps = {},
): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "set-token") return runSetToken(args, io, deps);
  if (sub === "status") return runStatus(args, io, deps);
  if (sub === "clear-token") return runClearToken(args, io, deps);
  throw new CliError(`unknown telegram subcommand: ${sub}\n       ${USAGE}`);
}

async function runSetToken(
  args: string[],
  io: CliIO,
  deps: TelegramCmdDeps,
): Promise<void> {
  if (args.length > 0) {
    // The token must NOT be an argv arg (shell history / ps leak). Reject it.
    throw new CliError(
      "safespace telegram set-token takes NO arguments — the token is read from stdin\n" +
        "       (e.g. `pbpaste | safespace telegram set-token`, or run it and paste then Ctrl-D).\n" +
        "       Passing the token on the command line would leak it into shell history.",
    );
  }
  const read = deps.readSecret ?? defaultReadSecret;
  const token = (await read()).trim();
  if (token === "") {
    throw new CliError("no token read from stdin (empty input) — nothing saved.");
  }
  const set = deps.setToken ?? ((t: string) => setServiceToken("telegram", t));
  await set(token);
  // NEVER echo the token. Report only that it was saved + a length hint.
  io.out(`Telegram bot token saved (${token.length} chars). It is never displayed.`);
  io.out("(restart Claude Code to pick up if the proxy is already running)");
}

async function runStatus(
  args: string[],
  io: CliIO,
  deps: TelegramCmdDeps,
): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'status'\n       ${USAGE}`);
  }
  const has = deps.hasToken ?? (() => hasServiceToken("telegram"));
  const configured = await has();
  io.out(`Telegram bot token: ${configured ? "configured" : "not configured"}`);
  // Surface whether the shell env override is currently set (not its value).
  const envSet = (process.env[ENV_TELEGRAM_BOT_TOKEN] ?? "").trim() !== "";
  io.out(`${ENV_TELEGRAM_BOT_TOKEN}: ${envSet ? "set (shell override, takes precedence)" : "<unset>"}`);
  const allow = telegramAllowlistSummary();
  io.out(
    allow.kind === "off"
      ? "Telegram recipient allowlist: OFF (interactive: all valid chat ids allowed; autonomous: deny-all)"
      : `Telegram recipient allowlist: ${allow.id_count} id${allow.id_count === 1 ? "" : "s"}`,
  );
}

async function runClearToken(
  args: string[],
  io: CliIO,
  deps: TelegramCmdDeps,
): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'clear-token'\n       ${USAGE}`);
  }
  const del = deps.deleteToken ?? (() => deleteServiceToken("telegram"));
  await del();
  io.out("Telegram bot token removed from the secret store.");
  io.out(`(the ${ENV_TELEGRAM_BOT_TOKEN} shell override, if set, still resolves.)`);
}
