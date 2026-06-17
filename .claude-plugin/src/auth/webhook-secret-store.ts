// v1.102 (W0) — the inbound webhook SIGNING-SECRET store.
//
// docs/v1.102-webhook-listener.md §5.4: the listener verifies each pushed request's
// signature against a per-provider signing secret (Slack signing secret / LINE channel
// secret / Telegram secret_token). Those secrets ride the SAME swappable SecretBackend
// the bot tokens use, under RESERVED non-email keys that contain ":" and no "@" (so they
// can never collide with a Google email key) — the established service-token-store
// pattern (security LOW-2: reuse the intermediary, don't call getToken with a non-email
// key ad-hoc).
//
// Resolution order mirrors the service-token idiom: a shell-only env var (ephemeral,
// F6-clean for CI) takes precedence over the persistent SecretBackend value. The secret
// is read PER REQUEST by the listener (never cached into a process var) so a
// `clear-secret` / rotation bites immediately (security HIGH-2a).
//
// SECURITY: the secret is NEVER logged, echoed, put in args, or serialized. The CLI
// writes it via setWebhookSigningSecret (reads from stdin, never argv).

import { resolveOperatorId } from "../identity/operator-id";
import type { SecretBackend } from "./secret-backend";
import { selectBackend } from "./select-backend";
import { ENV_LINE_WEBHOOK_SECRET, ENV_SLACK_WEBHOOK_SECRET } from "../config";
import type { WebhookProvider } from "../webhook/types";

/** Reserved SecretBackend key per provider. Contains ":" and no "@" → never collides
 *  with a Google email key, nor with the bot-token reserved keys (which use the
 *  connector name, e.g. "slack:bot-token", not "webhook:…"). */
const RESERVED_KEY: Record<WebhookProvider, string> = {
  slack: "webhook:slack-signing-secret",
  line: "webhook:line-channel-secret",
  telegram: "webhook:telegram-secret-token",
};

/** Shell-only env override per provider. W0+W1 wire slack + line; telegram (W2) adds
 *  its override if/when wired. A provider without an override resolves from the
 *  SecretBackend alone. */
const ENV: Partial<Record<WebhookProvider, string>> = {
  slack: ENV_SLACK_WEBHOOK_SECRET,
  line: ENV_LINE_WEBHOOK_SECRET,
};

/** The shell-only env-override var name for a provider (the single source of truth for
 *  the CLI `status` view), or undefined if this provider has no override yet. */
export function webhookSecretEnvVar(provider: WebhookProvider): string | undefined {
  return ENV[provider];
}

let cached: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cached === null) cached = selectBackend();
  return cached;
}

/** Test-only: drop the cached backend so a test can flip the backend selector. */
export function __resetWebhookSecretBackendForTests(): void {
  cached = null;
}

function envSecret(provider: WebhookProvider): string | null {
  const name = ENV[provider];
  if (name == null) return null;
  const v = process.env[name];
  return v != null && v.trim() !== "" ? v.trim() : null;
}

/** Resolve the signing secret: env (shell-only) → SecretBackend (persistent). Returns
 *  null when neither is configured. Called PER REQUEST by the listener. */
export async function readWebhookSigningSecret(provider: WebhookProvider): Promise<string | null> {
  const env = envSecret(provider);
  if (env !== null) return env;
  return backend().getToken(resolveOperatorId(), RESERVED_KEY[provider]);
}

/** Persist the signing secret (the CLI `safespace webhook set-secret` writer). */
export async function setWebhookSigningSecret(provider: WebhookProvider, secret: string): Promise<void> {
  await backend().setToken(resolveOperatorId(), RESERVED_KEY[provider], secret);
}

/** Remove the persisted signing secret. (An env override, if set, still resolves.) */
export async function deleteWebhookSigningSecret(provider: WebhookProvider): Promise<void> {
  await backend().deleteToken(resolveOperatorId(), RESERVED_KEY[provider]);
}

/** Presence probe for CLI `status` / `doctor --posture` / the bootstrap fail-loud.
 *  True when EITHER the env override or a SecretBackend value resolves. Never returns
 *  the secret. */
export async function hasWebhookSigningSecret(provider: WebhookProvider): Promise<boolean> {
  return (await readWebhookSigningSecret(provider)) !== null;
}
