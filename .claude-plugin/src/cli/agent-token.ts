// v1.93 A1 — `safespace agent-token <mint|revoke|list>`: manage the bearer-token
// store for `SAFESPACE_AUTH=token` (Model B off-tailnet operator auth). The store
// (agent-tokens.json) holds only each token's HMAC HASH; `mint` prints the
// plaintext ONCE — SafeSpace cannot recover it afterward. A minted token's login
// must also be a registered operator in operators.json (default-deny): the token
// authenticates WHO, the registry authorizes (tier / allowedAccounts).

import { CliError, type CliIO } from "../cli";
import { ENV_AGENT_TOKENS_FILE } from "../config";
import {
  getOrCreateAgentTokenSalt,
  listAgentTokens,
  mintAgentToken,
  revokeAgentTokensForLogin,
} from "../auth/agent-token-store";

const USAGE =
  "usage: safespace agent-token <mint|revoke|list> [args]\n" +
  "       safespace agent-token mint <login> [--expires <ISO8601>]\n" +
  "       safespace agent-token revoke <login>\n" +
  "       safespace agent-token list";

/** The store path is operator-supplied (same env the http server reads). */
function tokensPath(): string {
  const p = process.env[ENV_AGENT_TOKENS_FILE];
  if (p === undefined || p === "") {
    throw new CliError(`${ENV_AGENT_TOKENS_FILE} must be set (the agent-tokens.json path)`);
  }
  return p;
}

export async function runAgentTokenCmd(rest: string[], io: CliIO): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "mint") return mint(args, io);
  if (sub === "revoke") return revoke(args, io);
  if (sub === "list") return list(args, io);
  throw new CliError(`unknown agent-token subcommand: ${sub}\n       ${USAGE}`);
}

async function mint(args: string[], io: CliIO): Promise<void> {
  let login: string | undefined;
  let expires: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--expires") {
      expires = args[++i];
      if (expires === undefined) throw new CliError(`--expires requires a value\n       ${USAGE}`);
    } else if (!a.startsWith("--") && login === undefined) {
      login = a;
    } else {
      throw new CliError(`unexpected argument: ${a}\n       ${USAGE}`);
    }
  }
  if (login === undefined) throw new CliError(`mint requires <login>\n       ${USAGE}`);
  const salt = await getOrCreateAgentTokenSalt();
  let token: string;
  try {
    token = await mintAgentToken(tokensPath(), login, salt, expires);
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  io.out(`minted agent token for ${login}${expires ? ` (expires ${expires})` : ""}`);
  io.out("");
  io.out(`  ${token}`);
  io.out("");
  io.out("This is the ONLY time the token is shown — store it now and send it to the");
  io.out("agent as the `Authorization: Bearer <token>` header. Only its HMAC hash is");
  io.out("kept on disk; SafeSpace cannot recover the plaintext.");
}

async function revoke(args: string[], io: CliIO): Promise<void> {
  const [login, ...extra] = args;
  if (login === undefined || login.startsWith("--") || extra.length > 0) {
    throw new CliError(`revoke requires exactly <login>\n       ${USAGE}`);
  }
  let removed: number;
  try {
    removed = await revokeAgentTokensForLogin(tokensPath(), login);
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  io.out(removed === 0 ? `no tokens found for ${login}` : `revoked ${removed} token(s) for ${login}`);
}

async function list(args: string[], io: CliIO): Promise<void> {
  if (args.length > 0) throw new CliError(`list takes no arguments\n       ${USAGE}`);
  let rows: Array<{ login: string; hashPrefix: string; expiresAt: string | null }>;
  try {
    rows = await listAgentTokens(tokensPath());
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  if (rows.length === 0) {
    io.out("(no agent tokens)");
    return;
  }
  for (const r of rows) {
    // Show an explicit … when a long login is clipped (don't silently truncate).
    const loginCol = r.login.length > 32 ? `${r.login.slice(0, 31)}…` : r.login.padEnd(32);
    io.out(
      `${loginCol} ${r.hashPrefix}…  ${r.expiresAt ? `expires ${r.expiresAt}` : "no expiry"}`,
    );
  }
}
