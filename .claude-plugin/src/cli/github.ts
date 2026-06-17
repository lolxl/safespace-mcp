// v1.70 (G3) — the `--provider github` variants of the OAuth-account commands
// (`consent` / `account-list` / `account-switch` / `account-revoke`).
//
// GitHub is SafeSpace's 2nd OAuth source and shares the `consent` mental model
// (Q4 LOCKED: a `--provider github` FLAG on the existing account commands, NOT new
// subcommands — class-B `line/telegram/discord set-token` are correctly separate
// because they manage a TOKEN, not an account). cli.ts parses the flag and routes
// the four commands here.
//
// The v1 github connector is SINGLE-ACCOUNT (one consented login; no accounts.json
// index, no active-account file — the github Source always resolves the one stored
// login). So `account-switch` is a confirm-the-stored-login (there is nothing to
// switch BETWEEN), and `account-list` shows the single account or none.
//
// SECURITY: account-revoke clears the LOCAL github account + token only. GitHub
// OAuth-App tokens have no SafeSpace-side remote-revoke endpoint (unlike Google's
// refresh-token revoke); the user revokes the app grant in GitHub settings. The
// token is never displayed by any of these commands.

import { CliError, type CliIO } from "../cli";
import { githubConsent } from "../auth/github/consent";
import {
  clearGithubAccount,
  clearGithubToken,
  readGithubAccount,
} from "../auth/github/store";

/** `safespace consent <login> --provider github` */
export async function runGithubConsent(expectedLogin: string, io: CliIO): Promise<void> {
  const result = await githubConsent(expectedLogin);
  io.out(`github consent saved for ${result.login} (scopes: ${result.scopes.join(", ") || "none"})`);
}

/** `safespace account-list --provider github` */
export async function runGithubAccountList(io: CliIO): Promise<void> {
  const account = await readGithubAccount();
  if (!account) {
    io.out("(no github account; run `safespace consent <login> --provider github` to add one)");
    return;
  }
  io.out(`github account: ${account.login}`);
  io.out(`scopes: ${account.scopes.join(", ") || "none"}`);
}

/** `safespace account-switch <login> --provider github`. Single-account: confirm
 *  the stored login matches; there is nothing to switch between. */
export async function runGithubAccountSwitch(login: string, io: CliIO): Promise<void> {
  const account = await readGithubAccount();
  if (!account) {
    throw new CliError(
      "no github account; run `safespace consent <login> --provider github` to add one",
    );
  }
  if (account.login.toLowerCase() !== login.toLowerCase()) {
    throw new CliError(
      `github account not found: ${login}\n       the consented github account is ${account.login} (github is single-account)`,
    );
  }
  io.out(`active github account: ${account.login} (github is single-account)`);
}

/** `safespace account-revoke <login> --provider github`. Clears the LOCAL github
 *  account file + the stored token (idempotent). No remote revoke. */
export async function runGithubAccountRevoke(login: string, io: CliIO): Promise<void> {
  const account = await readGithubAccount();
  if (!account) {
    throw new CliError(
      `github account not found: ${login}\n       run \`safespace account-list --provider github\` to check`,
    );
  }
  if (account.login.toLowerCase() !== login.toLowerCase()) {
    throw new CliError(
      `github account not found: ${login}\n       the consented github account is ${account.login}`,
    );
  }
  // Clear the token (keyed by the canonical stored login) before the account file
  // so a crash between leaves a recoverable account-without-token, not the reverse.
  await clearGithubToken(account.login);
  await clearGithubAccount();
  io.out(`revoked github account: ${account.login} (revoke the app grant at github.com/settings/applications to fully sever it)`);
}
