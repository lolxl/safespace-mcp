// v1.95 — `safespace slack {set-token,status,clear-token}` CLI.
//
// Thin pack instantiation: command names, help text, every user-facing output string,
// exit codes, and the SecretBackend storeKey are derived from SLACK_PACK via
// makeServiceTokenCommands. Public surface (runSlackCmd / SlackCmdDeps) is
// unchanged so import sites stay untouched.
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell
//     history / `ps` output). It is written via the service-token store (SecretBackend
//     — Keychain / encrypted FileBackend) and NEVER echoed back.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The env override SAFESPACE_SLACK_BOT_TOKEN is shell-only and is NOT written by
//     this CLI (mirrors the recipient-allowlist EXTRA convention); status reports
//     whether it is currently set in the shell.

import type { CliIO } from "../cli";
import { slackAllowlistSummary } from "../policy/slack-recipient-allowlist";
import { SLACK_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenCommands,
  type ServiceTokenCmdDeps,
} from "./service-token-cli";

/** Injection seams (tests override; production uses the real store + stdin). */
export type SlackCmdDeps = ServiceTokenCmdDeps;

const commands = makeServiceTokenCommands(SLACK_PACK, {
  allowlistSummary: slackAllowlistSummary,
});

export async function runSlackCmd(
  rest: string[],
  io: CliIO,
  deps: SlackCmdDeps = {},
): Promise<void> {
  return commands.run(rest, io, deps);
}
