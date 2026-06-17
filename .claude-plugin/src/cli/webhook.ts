// v1.102 (W0) — `safespace webhook {set-secret,status,clear-secret} <provider>` CLI.
//
// Manages the inbound-webhook SIGNING SECRET (the HMAC key the listener verifies each
// pushed request against) per provider, plus a read-only status view. W0 wires only the
// Slack Events listener, so the CLI accepts only `slack`; W1/W2 widen it.
//
// SECURITY (mirrors `safespace slack set-token`):
//   - set-secret reads the secret from STDIN, never argv (no shell-history / `ps` leak).
//     It is written via the SecretBackend and NEVER echoed back.
//   - status / clear-secret never display the secret (only configured: yes|no).
//   - The env override SAFESPACE_<PROVIDER>_WEBHOOK_SECRET is shell-only and is NOT
//     written by this CLI; status reports whether it is currently set in the shell.

import {
  deleteWebhookSigningSecret,
  hasWebhookSigningSecret,
  setWebhookSigningSecret,
  webhookSecretEnvVar,
} from "../auth/webhook-secret-store";
import { CliError, type CliIO } from "../cli";
import type { WebhookProvider } from "../webhook/types";

/** The providers the listener wires (the CLI accepts only these). W0 slack + W1 line. */
const PROVIDERS: readonly WebhookProvider[] = ["slack", "line"];

const USAGE =
  "usage: safespace webhook <set-secret|status|clear-secret> [<provider>]\n" +
  "       safespace webhook set-secret <slack|line>    (reads the signing secret from stdin)\n" +
  "       safespace webhook status [<slack|line>]\n" +
  "       safespace webhook clear-secret <slack|line>\n" +
  "       providers: slack, line";

/** Injection seams (tests override; production uses the real store + stdin). */
export interface WebhookCmdDeps {
  readSecret?: () => Promise<string>;
  setSecret?: (p: WebhookProvider, secret: string) => Promise<void>;
  hasSecret?: (p: WebhookProvider) => Promise<boolean>;
  deleteSecret?: (p: WebhookProvider) => Promise<void>;
}

async function defaultReadSecret(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Uint8Array);
  return Buffer.concat(chunks).toString("utf8").trim();
}

function parseProvider(arg: string | undefined): WebhookProvider {
  if (!arg) throw new CliError(`a <provider> is required\n       ${USAGE}`);
  if (!(PROVIDERS as readonly string[]).includes(arg)) {
    throw new CliError(`unknown webhook provider '${arg}' (expected: ${PROVIDERS.join(", ")})`);
  }
  return arg as WebhookProvider;
}

export async function runWebhookCmd(rest: string[], io: CliIO, deps: WebhookCmdDeps = {}): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "set-secret") return runSetSecret(args, io, deps);
  if (sub === "status") return runStatus(args, io, deps);
  if (sub === "clear-secret") return runClearSecret(args, io, deps);
  throw new CliError(`unknown webhook subcommand: ${sub}\n       ${USAGE}`);
}

async function runSetSecret(args: string[], io: CliIO, deps: WebhookCmdDeps): Promise<void> {
  const provider = parseProvider(args[0]);
  if (args.length > 1) {
    throw new CliError(
      "safespace webhook set-secret takes ONLY the provider — the secret is read from stdin\n" +
        "       (e.g. `pbpaste | safespace webhook set-secret slack`).\n" +
        "       Passing the secret on the command line would leak it into shell history.",
    );
  }
  const read = deps.readSecret ?? defaultReadSecret;
  const secret = (await read()).trim();
  if (secret === "") throw new CliError("no signing secret read from stdin (empty input) — nothing saved.");
  const set = deps.setSecret ?? setWebhookSigningSecret;
  await set(provider, secret);
  io.out(`${provider} webhook signing secret saved (${secret.length} chars). It is never displayed.`);
  io.out("(restart the server to pick up if it is already running)");
}

async function runStatus(args: string[], io: CliIO, deps: WebhookCmdDeps): Promise<void> {
  // status with no provider shows every wired provider; with one, just that one.
  const targets = args.length === 0 ? PROVIDERS : [parseProvider(args[0])];
  if (args.length > 1) throw new CliError(`unexpected argument(s) for 'status'\n       ${USAGE}`);
  const has = deps.hasSecret ?? hasWebhookSigningSecret;
  for (const provider of targets) {
    const configured = await has(provider);
    io.out(`${provider} webhook signing secret: ${configured ? "configured" : "not configured"}`);
    const envVar = webhookSecretEnvVar(provider);
    if (envVar) {
      const envSet = (process.env[envVar] ?? "").trim() !== "";
      io.out(`${envVar}: ${envSet ? "set (shell override, takes precedence)" : "<unset>"}`);
    }
  }
}

async function runClearSecret(args: string[], io: CliIO, deps: WebhookCmdDeps): Promise<void> {
  const provider = parseProvider(args[0]);
  if (args.length > 1) throw new CliError(`unexpected argument(s) for 'clear-secret'\n       ${USAGE}`);
  const del = deps.deleteSecret ?? deleteWebhookSigningSecret;
  await del(provider);
  io.out(`${provider} webhook signing secret removed from the secret store.`);
  const envVar = webhookSecretEnvVar(provider);
  if (envVar) io.out(`(the ${envVar} shell override, if set, still resolves.)`);
}
