// v1.69 — `safespace discord {set-token,status,clear-token}` CLI.
//
// Thin pack instantiation: command names, help text, every user-facing output string,
// exit codes, and the SecretBackend storeKey are derived from DISCORD_PACK via
// makeServiceTokenCommands. Public surface (runDiscordCmd / DiscordCmdDeps) is
// unchanged so import sites stay untouched.
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell
//     history / `ps` output). It is written via the service-token store (SecretBackend
//     — Keychain / encrypted FileBackend) and NEVER echoed back.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The env override SAFESPACE_DISCORD_BOT_TOKEN is shell-only and is NOT written by
//     this CLI (mirrors the recipient-allowlist EXTRA convention); status reports
//     whether it is currently set in the shell.

import type { CliIO } from "../cli";
import { discordAllowlistSummary } from "../policy/discord-recipient-allowlist";
import { DISCORD_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenCommands,
  type ServiceTokenCmdDeps,
} from "./service-token-cli";

/** Injection seams (tests override; production uses the real store + stdin). */
export type DiscordCmdDeps = ServiceTokenCmdDeps;

const commands = makeServiceTokenCommands(DISCORD_PACK, {
  allowlistSummary: discordAllowlistSummary,
});

export async function runDiscordCmd(
  rest: string[],
  io: CliIO,
  deps: DiscordCmdDeps = {},
): Promise<void> {
  return commands.run(rest, io, deps);
}
