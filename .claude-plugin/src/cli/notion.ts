// v1.78 (Notion B) / v1.79 (multi-workspace) — the `--provider notion` variants of the
// OAuth-account commands (`consent` / `account-list` / `account-switch` / `account-revoke`).
// Mirrors cli/github.ts.
//
// Notion is SafeSpace's 3rd OAuth source and shares the `consent` mental model (a
// `--provider notion` FLAG on the existing account commands). cli.ts parses the flag and
// routes the four commands here. (The v1.77 `safespace notion {set-token,…}` token
// subcommands were superseded by OAuth in v1.78.)
//
// As of v1.79 notion is MULTI-workspace (mirror Google): `consent --provider notion` ADDS a
// workspace (no positional — discovered from the OAuth response) + makes it active;
// `account-list` shows all + the active marker; `account-switch <id-or-name>` sets the
// active workspace; `account-revoke <id-or-name>` removes one workspace + its token.
//
// SECURITY: account-revoke clears the LOCAL notion account + token only. Notion OAuth
// tokens have no SafeSpace-side remote-revoke endpoint; the user severs the grant in the
// Notion workspace's integration settings. The token is never displayed by any command.

import { CliError, type CliIO } from "../cli";
import { notionConsent } from "../auth/notion/consent";
import {
  clearNotionToken,
  findNotionWorkspace,
  readNotionAccounts,
  readNotionActiveWorkspace,
  removeNotionAccount,
  setNotionActiveWorkspace,
} from "../auth/notion/oauth";

/** `safespace consent --provider notion` (no positional — the workspace is discovered).
 *  ADDS the workspace to the index + makes it active. */
export async function runNotionConsent(io: CliIO): Promise<void> {
  const result = await notionConsent();
  io.out(
    `notion consent saved + activated: ${result.workspaceName || "(unnamed)"} (${result.workspaceId})`,
  );
}

/** `safespace account-list --provider notion` — all consented workspaces + the active one. */
export async function runNotionAccountList(io: CliIO): Promise<void> {
  const accounts = await readNotionAccounts();
  if (accounts.length === 0) {
    io.out("(no notion workspace; run `safespace consent --provider notion` to add one)");
    return;
  }
  const active = await readNotionActiveWorkspace();
  io.out(`notion workspaces (${accounts.length}):`);
  for (const a of accounts) {
    const marker = a.workspaceId === active ? " [active]" : "";
    io.out(`  ${a.workspaceName || "(unnamed)"} (${a.workspaceId})${marker}`);
  }
}

/** Resolve a `<id-or-name>` positional to a unique stored workspace, or throw a CliError
 *  (unknown / ambiguous / missing-arg) — shared by account-switch + account-revoke. */
async function resolveOrThrow(idOrName: string | undefined): Promise<{ workspaceId: string; workspaceName: string }> {
  if (!idOrName) {
    throw new CliError(
      "specify a workspace: safespace account-<switch|revoke> <id-or-name> --provider notion\n" +
        "       (run `safespace account-list --provider notion` to see them)",
    );
  }
  const accounts = await readNotionAccounts();
  if (accounts.length === 0) {
    throw new CliError("no notion workspace; run `safespace consent --provider notion` to add one");
  }
  const match = findNotionWorkspace(idOrName, accounts);
  if (match === "ambiguous") {
    throw new CliError(
      `ambiguous notion workspace name: ${idOrName}\n       use the workspace id (\`safespace account-list --provider notion\`)`,
    );
  }
  if (match == null) {
    throw new CliError(
      `notion workspace not found: ${idOrName}\n       run \`safespace account-list --provider notion\` to check`,
    );
  }
  return match;
}

/** `safespace account-switch <id-or-name> --provider notion` — set the active workspace. */
export async function runNotionAccountSwitch(idOrName: string | undefined, io: CliIO): Promise<void> {
  const ws = await resolveOrThrow(idOrName);
  await setNotionActiveWorkspace(ws.workspaceId);
  io.out(`active notion workspace: ${ws.workspaceName || "(unnamed)"} (${ws.workspaceId})`);
}

/** `safespace account-revoke <id-or-name> --provider notion` — remove one workspace + its
 *  token (clears active if it was active). No remote revoke. */
export async function runNotionAccountRevoke(idOrName: string | undefined, io: CliIO): Promise<void> {
  const ws = await resolveOrThrow(idOrName);
  // Clear the token (keyed by the workspace id) before the index entry so a crash between
  // leaves a recoverable account-without-token, not the reverse.
  await clearNotionToken(ws.workspaceId);
  await removeNotionAccount(ws.workspaceId);
  io.out(
    `revoked notion workspace: ${ws.workspaceName || "(unnamed)"} (${ws.workspaceId}) (sever the grant in the Notion workspace's integration settings to fully revoke it)`,
  );
}
