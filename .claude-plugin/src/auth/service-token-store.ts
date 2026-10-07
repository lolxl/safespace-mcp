// v1.66 Phase C (PR 2) — service-token store (class-B connector secrets).
//
// docs/safety-gateway-thesis.md §2: SafeSpace's `SecretBackend` "holds a secret; it
// does not care if that secret is an OAuth refresh token … or a LINE channel token."
// A class-B connector (LINE Official Account) authenticates with ONE long-lived
// channel access token — no OAuth, no per-user refresh. This facade stores that
// token in the SAME swappable `SecretBackend` the OAuth tokens use (Keychain /
// encrypted FileBackend), keyed under a RESERVED non-email account string so it can
// never collide with a Google account key.
//
// Resolution order (mirrors the recipient-allowlist two-layer idiom): an env var
// (shell-only, ephemeral, NOT at-rest in a file — F6-clean for CI) takes precedence
// over the persistent SecretBackend value.
//
// SECURITY: the token is NEVER logged, echoed, put in args, or serialized. The CLI
// writes it via setServiceToken (reads from stdin, never argv); handlers read it via
// the `service-token` Credential's getter (tools/types.ts), inline when building the
// Authorization header — never as a stored field.

import type { SecretBackend } from "./secret-backend";
import { selectBackend } from "./select-backend";
import {
  ENV_DISCORD_BOT_TOKEN,
  ENV_LINE_CHANNEL_TOKEN,
  ENV_MATTERMOST_BOT_TOKEN,
  ENV_SLACK_BOT_TOKEN,
  ENV_TELEGRAM_BOT_TOKEN,
} from "../config";

/** The class-B connectors with a service token. Extend as connectors are added.
 *  (v1.78: notion retired from this list — it became an OAuth source, see
 *  auth/notion/oauth.ts.) */
export type ServiceName = "line" | "telegram" | "discord" | "slack" | "mattermost";

/** Shell-only env override per service (ephemeral; precedence over SecretBackend). */
const ENV: Record<ServiceName, string> = {
  line: ENV_LINE_CHANNEL_TOKEN,
  telegram: ENV_TELEGRAM_BOT_TOKEN,
  discord: ENV_DISCORD_BOT_TOKEN,
  slack: ENV_SLACK_BOT_TOKEN,
  mattermost: ENV_MATTERMOST_BOT_TOKEN,
};

/** Reserved SecretBackend account key per service. Contains ":" and no "@", so it
 *  can never equal a Google email key (the OAuth token-store keying). */
const RESERVED_KEY: Record<ServiceName, string> = {
  line: "line:channel-access-token",
  telegram: "telegram:bot-token",
  discord: "discord:bot-token",
  slack: "slack:bot-token",
  mattermost: "mattermost:bot-token",
};

/** The shell-only env-override var name for a service (the single source of truth —
 *  the CLI `status` view reads it via this, never a re-declared literal). */
export function serviceTokenEnvVar(svc: ServiceName): string {
  return ENV[svc];
}

let cached: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cached === null) cached = selectBackend();
  return cached;
}

/** Test-only: drop the cached backend so a test can flip $SAFESPACE_SECRET_BACKEND
 *  / process.platform and re-select. Mirrors token-store.__resetBackendForTests. */
export function __resetServiceTokenBackendForTests(): void {
  cached = null;
}

function envToken(svc: ServiceName): string | null {
  const v = process.env[ENV[svc]];
  return v != null && v.trim() !== "" ? v.trim() : null;
}

/** Resolve the service token: env (shell-only) → SecretBackend (persistent).
 *  Returns null when neither is configured. */
export async function readServiceToken(svc: ServiceName): Promise<string | null> {
  const env = envToken(svc);
  if (env !== null) return env;
  return backend().getToken(RESERVED_KEY[svc]);
}

/** Persist the service token to the SecretBackend (the CLI `safespace line
 *  set-token` writer). The value is stored as an opaque string (the backend does
 *  not parse it). */
export async function setServiceToken(svc: ServiceName, token: string): Promise<void> {
  await backend().setToken(RESERVED_KEY[svc], token);
}

/** Remove the persisted service token. (The env override, if set, still resolves.) */
export async function deleteServiceToken(svc: ServiceName): Promise<void> {
  await backend().deleteToken(RESERVED_KEY[svc]);
}

/** Presence probe for CLI `status` / `doctor` (configured: yes|no). True when EITHER
 *  the env override or a SecretBackend value resolves. Never returns the token. */
export async function hasServiceToken(svc: ServiceName): Promise<boolean> {
  return (await readServiceToken(svc)) !== null;
}
