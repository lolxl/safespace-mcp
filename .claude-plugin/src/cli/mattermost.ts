// v1.107 — `safespace mattermost {set-token,status,clear-token}` CLI.
//
// Manages the Mattermost bot/personal-access token (the fifth class-B service-token
// connector secret) in the SecretBackend, plus a read-only status view that ALSO reports
// the self-hosted server URL config (the Mattermost-specific delta — its host is not a
// fixed constant).
//
// SECURITY:
//   - set-token reads the token from STDIN, never argv (so it never lands in shell history
//     / `ps` output). Written via the service-token store (SecretBackend), NEVER echoed.
//   - status / clear-token never display the token (only configured: yes|no).
//   - The server URL is CONFIG (env SAFESPACE_MATTERMOST_SERVER_URL), not a secret — status
//     reports whether it is set + valid (and its host, to help the operator verify); it is
//     NOT written by this CLI (an env var, like the recipient-allowlist EXTRA convention).

import {
  deleteServiceToken,
  hasServiceToken,
  serviceTokenEnvVar,
  setServiceToken,
} from "../auth/service-token-store";
import { CliError, type CliIO } from "../cli";
import { mattermostAllowlistSummary } from "../policy/mattermost-recipient-allowlist";
import { getMattermostServer } from "../auth/mattermost/base-url";
import { ENV_MATTERMOST_SERVER_URL } from "../config";

const USAGE =
  "usage: safespace mattermost <set-token|status|clear-token>\n" +
  "       safespace mattermost set-token    (reads the bot token from stdin)\n" +
  "       safespace mattermost status\n" +
  "       safespace mattermost clear-token\n" +
  "       (the server URL is set via the SAFESPACE_MATTERMOST_SERVER_URL env var, not this CLI)";

const ENV_MATTERMOST_BOT_TOKEN = serviceTokenEnvVar("mattermost");

/** Injection seams (tests override; production uses the real store + stdin). */
export interface MattermostCmdDeps {
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

export async function runMattermostCmd(
  rest: string[],
  io: CliIO,
  deps: MattermostCmdDeps = {},
): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "set-token") return runSetToken(args, io, deps);
  if (sub === "status") return runStatus(args, io, deps);
  if (sub === "clear-token") return runClearToken(args, io, deps);
  throw new CliError(`unknown mattermost subcommand: ${sub}\n       ${USAGE}`);
}

async function runSetToken(args: string[], io: CliIO, deps: MattermostCmdDeps): Promise<void> {
  if (args.length > 0) {
    throw new CliError(
      "safespace mattermost set-token takes NO arguments — the token is read from stdin\n" +
        "       (e.g. `pbpaste | safespace mattermost set-token`, or run it and paste then Ctrl-D).\n" +
        "       Passing the token on the command line would leak it into shell history.",
    );
  }
  const read = deps.readSecret ?? defaultReadSecret;
  const token = (await read()).trim();
  if (token === "") {
    throw new CliError("no token read from stdin (empty input) — nothing saved.");
  }
  const set = deps.setToken ?? ((t: string) => setServiceToken("mattermost", t));
  await set(token);
  io.out(`Mattermost bot token saved (${token.length} chars). It is never displayed.`);
  io.out("(restart Claude Code to pick up if the proxy is already running)");
}

async function runStatus(args: string[], io: CliIO, deps: MattermostCmdDeps): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'status'\n       ${USAGE}`);
  }
  const has = deps.hasToken ?? (() => hasServiceToken("mattermost"));
  const configured = await has();
  io.out(`Mattermost bot token: ${configured ? "configured" : "not configured"}`);
  const envSet = (process.env[ENV_MATTERMOST_BOT_TOKEN] ?? "").trim() !== "";
  io.out(`${ENV_MATTERMOST_BOT_TOKEN}: ${envSet ? "set (shell override, takes precedence)" : "<unset>"}`);
  // Server URL (config, not a secret) — its presence + validity gate the whole connector.
  const server = getMattermostServer();
  io.out(
    server === null
      ? `${ENV_MATTERMOST_SERVER_URL}: not configured or invalid (must be an https:// URL) — Mattermost egress is BLOCKED until set`
      : `${ENV_MATTERMOST_SERVER_URL}: configured (host: ${server.host})`,
  );
  const allow = mattermostAllowlistSummary();
  io.out(
    allow.kind === "off"
      ? "Mattermost recipient allowlist: OFF (interactive: all valid channel ids allowed; autonomous: deny-all)"
      : `Mattermost recipient allowlist: ${allow.id_count} id${allow.id_count === 1 ? "" : "s"}`,
  );
}

async function runClearToken(args: string[], io: CliIO, deps: MattermostCmdDeps): Promise<void> {
  if (args.length > 0) {
    throw new CliError(`unexpected argument(s) for 'clear-token'\n       ${USAGE}`);
  }
  const del = deps.deleteToken ?? (() => deleteServiceToken("mattermost"));
  await del();
  io.out("Mattermost bot token removed from the secret store.");
  io.out(`(the ${ENV_MATTERMOST_BOT_TOKEN} shell override, if set, still resolves.)`);
}
