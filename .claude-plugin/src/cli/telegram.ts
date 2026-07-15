// v1.68 — `safespace telegram {set-token,status,clear-token}` CLI.
//
// Thin pack instantiation: command names, help text, every user-facing output string,
// exit codes, and the SecretBackend storeKey are derived from TELEGRAM_PACK via
// makeServiceTokenCommands. Public surface (runTelegramCmd / TelegramCmdDeps) is
// unchanged so import sites stay untouched.
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell
//     history / `ps` output). It is written via the service-token store (SecretBackend
//     — Keychain / encrypted FileBackend) and NEVER echoed back.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The env override SAFESPACE_TELEGRAM_BOT_TOKEN is shell-only and is NOT written by
//     this CLI (mirrors the recipient-allowlist EXTRA convention); status reports
//     whether it is currently set in the shell.

import type { CliIO } from "../cli";
import { telegramAllowlistSummary } from "../policy/telegram-recipient-allowlist";
import { TELEGRAM_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenCommands,
  type ServiceTokenCmdDeps,
} from "./service-token-cli";

/** Injection seams (tests override; production uses the real store + stdin). */
export type TelegramCmdDeps = ServiceTokenCmdDeps;

const commands = makeServiceTokenCommands(TELEGRAM_PACK, {
  allowlistSummary: telegramAllowlistSummary,
});

export async function runTelegramCmd(
  rest: string[],
  io: CliIO,
  deps: TelegramCmdDeps = {},
): Promise<void> {
  return commands.run(rest, io, deps);
}
