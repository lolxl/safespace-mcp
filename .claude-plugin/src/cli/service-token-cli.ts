// Pack-aware factory for the class-B `safespace <cmd> {set-token,status,clear-token}` trio.
//
// The 5 CLI modules were byte-identical modulo command name, token labels, store
// key, env override name, allowlist summary import, and the OFF-message id noun.
// This collapses that surface so a connector's cli/{id}.ts is a thin instantiate
// preserving every user-facing string via the pack's `cli` + `env` fields.
//
// SECURITY (preserved from the hand-written modules):
//   - set-token reads the token from STDIN, never argv (shell history / `ps` leak).
//   - status / clear-token never display the token (only configured: yes|no).
//   - The env override is shell-only and is NOT written by this CLI; status reports
//     whether it is currently set in the shell (not its value).

import {
  deleteServiceToken,
  hasServiceToken,
  setServiceToken,
} from "../auth/service-token-store";
import { CliError, type CliIO } from "../cli";
import type { ServiceTokenPack } from "../tools/service-token-pack";

/** Injection seams (tests override; production uses the real store + stdin). */
export interface ServiceTokenCmdDeps {
  /** Read the secret token (default: a trimmed line from process.stdin). */
  readSecret?: () => Promise<string>;
  setToken?: (token: string) => Promise<void>;
  hasToken?: () => Promise<boolean>;
  deleteToken?: () => Promise<void>;
}

/** Minimal pack surface the CLI factory reads. */
export type ServiceTokenCliSpec = Pick<ServiceTokenPack, "storeKey" | "env" | "cli">;

export interface ServiceTokenCommands {
  /** Dispatch `set-token` / `status` / `clear-token` (and usage errors). */
  run(rest: string[], io: CliIO, deps?: ServiceTokenCmdDeps): Promise<void>;
}

async function defaultReadSecret(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Uint8Array);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

/** Build the set-token / status / clear-token trio for one service-token connector.
 *  `allowlistSummary` is injected so this module never imports a policy surface
 *  (avoids a cli↔policy cycle and keeps the pack free of summary wiring). */
export function makeServiceTokenCommands(
  packOrSpec: ServiceTokenCliSpec,
  opts: {
    allowlistSummary: () => { kind: "off" | "active"; id_count: number };
    /** OPTIONAL runtime seam for connector-specific status lines that need auth/config
     *  the pack cannot import (leaf-types + config-consts only). Injected here so the
     *  factory stays pure; the lines are printed BETWEEN the env-override line and the
     *  allowlist line (mattermost's server-URL state is the sole current user). */
    extraStatusLines?: () => string[];
  },
): ServiceTokenCommands {
  const { storeKey, env, cli } = packOrSpec;
  const cmd = cli.commandName;
  const envToken = env.token;

  const USAGE =
    `usage: safespace ${cmd} <set-token|status|clear-token>\n` +
    `       safespace ${cmd} set-token    (reads the ${cli.tokenKind} from stdin)\n` +
    `       safespace ${cmd} status\n` +
    `       safespace ${cmd} clear-token` +
    (cli.usageNote ? `\n       ${cli.usageNote}` : "");

  async function runSetToken(
    args: string[],
    io: CliIO,
    deps: ServiceTokenCmdDeps,
  ): Promise<void> {
    if (args.length > 0) {
      // The token must NOT be an argv arg (shell history / ps leak). Reject it.
      throw new CliError(
        `safespace ${cmd} set-token takes NO arguments — the token is read from stdin\n` +
          `       (e.g. \`pbpaste | safespace ${cmd} set-token\`, or run it and paste then Ctrl-D).\n` +
          "       Passing the token on the command line would leak it into shell history.",
      );
    }
    const read = deps.readSecret ?? defaultReadSecret;
    const token = (await read()).trim();
    if (token === "") {
      throw new CliError("no token read from stdin (empty input) — nothing saved.");
    }
    const set = deps.setToken ?? ((t: string) => setServiceToken(storeKey, t));
    await set(token);
    // NEVER echo the token. Report only that it was saved + a length hint.
    io.out(`${cli.tokenLabel} saved (${token.length} chars). It is never displayed.`);
    io.out("(restart Claude Code to pick up if the proxy is already running)");
  }

  async function runStatus(
    args: string[],
    io: CliIO,
    deps: ServiceTokenCmdDeps,
  ): Promise<void> {
    if (args.length > 0) {
      throw new CliError(`unexpected argument(s) for 'status'\n       ${USAGE}`);
    }
    const has = deps.hasToken ?? (() => hasServiceToken(storeKey));
    const configured = await has();
    io.out(`${cli.tokenLabel}: ${configured ? "configured" : "not configured"}`);
    // Surface whether the shell env override is currently set (not its value).
    const envSet = (process.env[envToken] ?? "").trim() !== "";
    io.out(
      `${envToken}: ${envSet ? "set (shell override, takes precedence)" : "<unset>"}`,
    );
    // Connector-specific runtime status lines (e.g. mattermost's server-URL state),
    // printed between the env-override line and the allowlist line.
    for (const line of opts.extraStatusLines?.() ?? []) io.out(line);
    const allow = opts.allowlistSummary();
    io.out(
      allow.kind === "off"
        ? `${cli.displayName} recipient allowlist: OFF (interactive: all valid ${cli.allowlistIdNoun} allowed; autonomous: deny-all)`
        : `${cli.displayName} recipient allowlist: ${allow.id_count} id${allow.id_count === 1 ? "" : "s"}`,
    );
  }

  async function runClearToken(
    args: string[],
    io: CliIO,
    deps: ServiceTokenCmdDeps,
  ): Promise<void> {
    if (args.length > 0) {
      throw new CliError(`unexpected argument(s) for 'clear-token'\n       ${USAGE}`);
    }
    const del = deps.deleteToken ?? (() => deleteServiceToken(storeKey));
    await del();
    io.out(`${cli.tokenLabel} removed from the secret store.`);
    io.out(`(the ${envToken} shell override, if set, still resolves.)`);
  }

  return {
    async run(rest, io, deps = {}): Promise<void> {
      const [sub, ...args] = rest;
      if (!sub) throw new CliError(USAGE);
      if (sub === "set-token") return runSetToken(args, io, deps);
      if (sub === "status") return runStatus(args, io, deps);
      if (sub === "clear-token") return runClearToken(args, io, deps);
      throw new CliError(`unknown ${cmd} subcommand: ${sub}\n       ${USAGE}`);
    },
  };
}
