// v1.107 — `safespace mattermost {set-token,status,clear-token}` CLI.
//
// Thin pack instantiation: command names, help text, every user-facing output string,
// exit codes, and the SecretBackend storeKey are derived from MATTERMOST_PACK via
// makeServiceTokenCommands. Public surface (runMattermostCmd / MattermostCmdDeps) is
// unchanged so import sites stay untouched. The Mattermost-specific delta — its
// self-hosted server URL is NOT a fixed constant — is surfaced two ways WITHOUT forking
// the shared trio: the static USAGE trailer rides MATTERMOST_PACK.cli.usageNote, and the
// dynamic server-URL status line is injected via the factory's `extraStatusLines` runtime
// seam (the pack cannot import auth/mattermost/base-url — leaf-types + config-consts only).
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell history
//     / `ps` output). Written via the service-token store (SecretBackend), NEVER echoed.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The server URL is CONFIG (env SAFESPACE_MATTERMOST_SERVER_URL), not a secret — status
//     reports whether it is set + valid (and its host, to help the operator verify); it is
//     NOT written by this CLI (an env var, like the recipient-allowlist EXTRA convention).

import type { CliIO } from "../cli";
import { mattermostAllowlistSummary } from "../policy/mattermost-recipient-allowlist";
import { MATTERMOST_PACK } from "../tools/service-token-pack";
import { getMattermostServer } from "../auth/mattermost/base-url";
import { ENV_MATTERMOST_SERVER_URL } from "../config";
import {
  makeServiceTokenCommands,
  type ServiceTokenCmdDeps,
} from "./service-token-cli";

/** Injection seams (tests override; production uses the real store + stdin). */
export type MattermostCmdDeps = ServiceTokenCmdDeps;

const commands = makeServiceTokenCommands(MATTERMOST_PACK, {
  allowlistSummary: mattermostAllowlistSummary,
  // Server URL (config, not a secret) — its presence + validity gate the whole connector.
  extraStatusLines: () => {
    const server = getMattermostServer();
    return [
      server === null
        ? `${ENV_MATTERMOST_SERVER_URL}: not configured or invalid (must be an https:// URL) — Mattermost egress is BLOCKED until set`
        : `${ENV_MATTERMOST_SERVER_URL}: configured (host: ${server.host})`,
    ];
  },
});

export async function runMattermostCmd(
  rest: string[],
  io: CliIO,
  deps: MattermostCmdDeps = {},
): Promise<void> {
  return commands.run(rest, io, deps);
}
