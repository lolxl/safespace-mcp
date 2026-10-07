// Settings whose feature has been removed. A deployment that still sets one expects
// behavior SafeSpace no longer provides (e.g. a listening inbound webhook socket), so
// startup refuses and names each one instead of silently running without it. Called
// from proxy.ts's guarded startup sequence; settings marked `cli` also stop every CLI
// subcommand (cli.ts). Messages name the variable only, never its value.

interface Retired {
  name: string;
  why: string;
  /** True when this value would have turned the removed feature on. Default: any
   *  non-empty value. */
  active?: (value: string) => boolean;
  /** Also refuse every CLI subcommand (the setting changed which stored secrets the
   *  CLI would read or write). */
  cli?: boolean;
}

const WEBHOOK = "the inbound webhook listener (and inbox_read) was removed";
const HTTP = "the multi-operator HTTP transport (Model B) was removed; SafeSpace runs over stdio only";

const OPERATOR_ID =
  "removed: secrets are no longer stored per operator and audit rows no longer carry " +
  "an operator. Unset it. If it held a valid id (letters, digits, `_`, `.`, `-`; at " +
  "most 64), secrets saved while it was set are no longer read: first revoke the old " +
  "grants and rotate the service tokens at each provider (revoking AFTER re-authorizing " +
  "can invalidate the new grant too), then run `safespace consent <email> --re-auth` " +
  "for each Google account, `safespace consent <login> --provider github`, " +
  "`safespace consent --provider notion`, `safespace consent --provider x`, and " +
  "`safespace <service> set-token` with each new service token";

const ENFORCED =
  "enforced mode was removed. Keep its checks with SAFESPACE_AUTONOMOUS=true and a " +
  "Keychain or passphrase-mode token store (its HTTP-bind check went with the HTTP " +
  "transport); `safespace doctor --posture` reports them, plus the separate opt-in " +
  "SAFESPACE_REQUIRE_SEND_APPROVAL";

const RETIRED: readonly Retired[] = [
  { name: "SAFESPACE_OPERATOR_ID", why: OPERATOR_ID, cli: true },
  // Only the literal "true" ever turned it on.
  { name: "SAFESPACE_ENFORCED", why: ENFORCED, active: (v) => v === "true" },
  { name: "SAFESPACE_WEBHOOK_PORT", why: WEBHOOK },
  { name: "SAFESPACE_WEBHOOK_BIND", why: WEBHOOK },
  { name: "SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT", why: WEBHOOK },
  // Only "http" ever selected the removed transport; any other value meant stdio.
  { name: "SAFESPACE_TRANSPORT", why: HTTP, active: (v) => v === "http" },
  { name: "SAFESPACE_HTTP_PORT", why: HTTP },
  { name: "SAFESPACE_HTTP_BIND", why: HTTP },
  { name: "SAFESPACE_AUTH", why: HTTP },
  { name: "SAFESPACE_AGENT_TOKENS_FILE", why: HTTP },
  { name: "SAFESPACE_OPERATORS_FILE", why: HTTP },
  { name: "SAFESPACE_TAILSCALE_SOCKET", why: HTTP },
  { name: "SAFESPACE_TLS_TERMINATED", why: HTTP },
];

function activeRetired(env: NodeJS.ProcessEnv): Retired[] {
  return RETIRED.filter(({ name, active }) => {
    const value = env[name] ?? "";
    return value !== "" && (active === undefined || active(value));
  });
}

/** Names (never values) of the retired variables currently set — for `doctor`. */
export function retiredSettingsSet(env: NodeJS.ProcessEnv = process.env): string[] {
  return activeRetired(env).map(({ name }) => name);
}

/** The refusal message when any retired variable is set (non-empty); null otherwise. */
export function retiredSettingsRefusal(env: NodeJS.ProcessEnv = process.env): string | null {
  const hits = activeRetired(env);
  if (hits.length === 0) return null;
  return (
    "Refusing to start: these settings belong to removed features — unset them:\n" +
    hits.map(({ name, why }) => `  - ${name}: ${why}`).join("\n")
  );
}

/** CLI refusal when a `cli` retired setting is set (non-empty); null otherwise. */
export function retiredCliRefusal(env: NodeJS.ProcessEnv = process.env): string | null {
  const hits = activeRetired(env).filter(({ cli }) => cli === true);
  if (hits.length === 0) return null;
  return (
    "Refusing to run: these settings belong to removed features — unset them:\n" +
    hits.map(({ name, why }) => `  - ${name}: ${why}`).join("\n")
  );
}

/** Startup enforcement: throws with `retiredSettingsRefusal()`'s message. */
export function enforceNoRetiredSettings(): void {
  const reason = retiredSettingsRefusal();
  if (reason !== null) throw new Error(reason);
}
