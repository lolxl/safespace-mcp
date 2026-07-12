// v1.113 — the `--provider x` variants of the OAuth-account commands
// (`consent` / `account-list` / `account-switch` / `account-revoke`).
// Mirrors cli/notion.ts.
//
// X is SafeSpace's 4th OAuth source and shares the `consent` mental model (a
// `--provider x` FLAG on the existing account commands). cli.ts parses the flag and
// routes the four commands here.
//
// Multi-account (mirror Notion multi-workspace): `consent --provider x` ADDS a
// user (no positional — discovered from users/me) + makes it active;
// `account-list` shows all + the active marker; `account-switch <id-or-username>`
// sets the active account; `account-revoke <id-or-username>` removes one account
// + its token.
//
// SECURITY: account-revoke clears the LOCAL x account + token only. X OAuth
// tokens have no SafeSpace-side remote-revoke endpoint; the user severs the grant
// in the X developer portal. The token is never displayed by any command.

import { CliError, type CliIO } from "../cli";
import { xConsent } from "../auth/x/consent";
import {
  clearXToken,
  findXAccount,
  readXAccounts,
  readXActiveAccount,
  removeXAccount,
  setXActiveAccount,
} from "../auth/x/oauth";

/** `safespace consent --provider x` (no positional — the user is discovered via
 *  users/me). ADDS the account to the index + makes it active. */
export async function runXConsent(io: CliIO): Promise<void> {
  const result = await xConsent();
  io.out(`x consent saved + activated: @${result.username} (${result.userId})`);
}

/** `safespace account-list --provider x` — all consented accounts + the active one. */
export async function runXAccountList(io: CliIO): Promise<void> {
  const accounts = await readXAccounts();
  if (accounts.length === 0) {
    io.out("(no x account; run `safespace consent --provider x` to add one)");
    return;
  }
  const active = await readXActiveAccount();
  io.out(`x accounts (${accounts.length}):`);
  for (const a of accounts) {
    const marker = a.id === active ? " [active]" : "";
    io.out(`  @${a.username} (${a.id})${marker}`);
  }
}

/** Resolve a `<id-or-username>` positional to a unique stored account, or throw a
 *  CliError (unknown / ambiguous / missing-arg) — shared by account-switch + account-revoke. */
async function resolveOrThrow(
  idOrUsername: string | undefined,
): Promise<{ id: string; username: string }> {
  if (!idOrUsername) {
    throw new CliError(
      "specify an account: safespace account-<switch|revoke> <id-or-username> --provider x\n" +
        "       (run `safespace account-list --provider x` to see them)",
    );
  }
  const accounts = await readXAccounts();
  if (accounts.length === 0) {
    throw new CliError("no x account; run `safespace consent --provider x` to add one");
  }
  const match = findXAccount(idOrUsername, accounts);
  if (match === "ambiguous") {
    throw new CliError(
      `ambiguous x username: ${idOrUsername}\n       use the user id (\`safespace account-list --provider x\`)`,
    );
  }
  if (match == null) {
    throw new CliError(
      `x account not found: ${idOrUsername}\n       run \`safespace account-list --provider x\` to check`,
    );
  }
  return match;
}

/** `safespace account-switch <id-or-username> --provider x` — set the active account. */
export async function runXAccountSwitch(
  idOrUsername: string | undefined,
  io: CliIO,
): Promise<void> {
  const acct = await resolveOrThrow(idOrUsername);
  await setXActiveAccount(acct.id);
  io.out(`active x account: @${acct.username} (${acct.id})`);
}

/** `safespace account-revoke <id-or-username> --provider x` — remove one account + its
 *  token (clears active if it was active). No remote revoke. */
export async function runXAccountRevoke(
  idOrUsername: string | undefined,
  io: CliIO,
): Promise<void> {
  const acct = await resolveOrThrow(idOrUsername);
  // Clear the token (keyed by the user id) before the index entry so a crash between
  // leaves a recoverable account-without-token, not the reverse.
  await clearXToken(acct.id);
  await removeXAccount(acct.id);
  io.out(
    `revoked x account: @${acct.username} (${acct.id}) (sever the grant in the X developer portal to fully revoke it)`,
  );
}
