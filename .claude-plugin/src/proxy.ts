// Entry point: the MCP server bootstrap. Builds the server (./server.ts) +
// runs the startup guards, then connects the CONFIGURED transport:
//   - default (SAFESPACE_TRANSPORT unset / "stdio") → stdio, byte-identical to
//     the pre-v1.73 bootstrap (Model A);
//   - opt-in (SAFESPACE_TRANSPORT=http) → the loopback Streamable HTTP transport
//     (v1.73, Model B PR-1; see docs/v1.73-model-b-transport.md).
//
// The server DEFINITION lives in ./server.ts (`createMcpServer`) so it can be
// connected once (stdio) or per-session (http) and imported by tests without
// triggering this file's startup side effects.
import type { IncomingMessage } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { configDir, loadIndex } from "./auth/keychain";
import { enforceAutonomousTokenStorage } from "./auth/select-backend";
import { enforceEnforcedMode } from "./policy/enforced-mode";
import { ENV_AUTH, ENV_AGENT_TOKENS_FILE } from "./config";
import {
  type AgentTokenRecord,
  extractBearerToken,
  getOrCreateAgentTokenSalt,
  loadAgentTokens,
  lookupTokenLogin,
} from "./auth/agent-token-store";
import { createMcpServer } from "./server";
import {
  createRegistryProvider,
  type OperatorRegistryProvider,
} from "./identity/operator-registry";
import { writeStartupMarker } from "./startup-marker";
import {
  resolveHttpConfigFromEnv,
  startHttpServer,
  transportMode,
} from "./transport/http";
import {
  enforceWebhookSecretsPresent,
  resolveWebhookConfigFromEnv,
  startWebhookListener,
  webhookEnabled,
} from "./transport/webhook";

// Startup hardening guards — fail loud + EARLY, before the MCP handshake, so a
// misconfigured deployment never serves a single tool. The catch prints the
// refusal to stderr and exits non-zero.
//
// v1.86 — enforced mode (docs/SOLE-EGRESS.md) runs FIRST. When
// SAFESPACE_ENFORCED=true it generalizes F6's refuse-to-start to the full
// SafeSpace-side hardening checklist (autonomous on / non-keyfile token store /
// non-all-interfaces bind), naming every failing precondition at once. It is a
// STRICT SUPERSET of F6's token check, so it must run before F6: an enforced
// deployment on key-file storage should see enforced mode's message (which
// correctly says the SAFESPACE_ALLOW_KEYFILE_AT_REST hatch is NOT honored), not
// F6's (which would wrongly advise setting that hatch). No-op when
// SAFESPACE_ENFORCED is unset (Model A / today's posture, byte-identical).
//
// v1.55 F6 — refuse to start an autonomous deployment on key-beside-ciphertext
// token storage (FileBackend KEY-FILE mode) unless the operator set a passphrase
// or the SAFESPACE_ALLOW_KEYFILE_AT_REST escape hatch. Still runs (defense in
// depth + the not-enforced-but-autonomous case); a no-op when enforced mode
// already passed the token check. No-op when not autonomous, in passphrase mode,
// on Keychain, or with the escape hatch set.
try {
  enforceEnforcedMode();
  enforceAutonomousTokenStorage();
} catch (e) {
  console.error(`[safespace] ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}

// v1.102 (W0) — inbound webhook listener startup guards (Model B only; fail-loud
// BEFORE serving). The listener is a SEPARATE public surface that must be reachable by
// the provider, so it needs the hosted HTTP transport; and a public listener with no
// verification key is the worst failure mode — refuse to start without the signing
// secret(s). Unset SAFESPACE_WEBHOOK_PORT → no listener → Model A byte-identical.
if (webhookEnabled()) {
  if (transportMode() !== "http") {
    console.error(
      "[safespace] SAFESPACE_WEBHOOK_PORT is set but SAFESPACE_TRANSPORT is not \"http\" — " +
        "the inbound webhook listener requires the Model B HTTP transport (it needs a hosted, " +
        "publicly reachable host). Set SAFESPACE_TRANSPORT=http, or unset SAFESPACE_WEBHOOK_PORT.",
    );
    process.exit(1);
  }
  try {
    resolveWebhookConfigFromEnv(); // validate the port (throws fail-loud)
    await enforceWebhookSecretsPresent(); // every enabled provider's signing secret must be present
  } catch (e) {
    console.error(`[safespace] ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}

// v1.73 — transport dispatch. The DEFAULT branch connects ONE server over stdio,
// byte-identical to the pre-v1.73 bootstrap; http is strictly opt-in (Model B PR-1).
if (transportMode() === "http") {
  const { port, bind } = resolveHttpConfigFromEnv();
  // v1.74 PR-2b — http = Model B = operator auth is MANDATORY. Load + validate the
  // operators registry BEFORE listening; a missing/invalid registry fails LOUD
  // (exit 1) so a misconfigured deployment never serves a single request without
  // per-connection identity. (The Tailscale WhoIs lookup itself runs per session.)
  // v1.80 PR-3 — the registry is now a hot-reloading PROVIDER: the INITIAL load
  // keeps this fail-loud posture; a RUNTIME edit re-validates lazily (keep-last-
  // good on failure) and the transport re-resolves every session per request.
  let registry: OperatorRegistryProvider;
  try {
    registry = await createRegistryProvider({
      // v1.74 PR-2c — the consented-account index lets the registry fail-loud on a
      // typo'd `allowedAccounts` entry (an account no operator could ever resolve),
      // rather than that operator hitting a silent runtime account_not_found.
      // Re-read on every reload, so an account consented AFTER startup is known.
      loadKnownAccounts: async () => {
        const idx = await loadIndex();
        return new Set(idx.accounts.map((a) => a.email));
      },
    });
  } catch (e) {
    console.error(`[safespace] ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
  // v1.93 A1 — operator-auth source. Default `tailscale` (WhoIs, byte-identical);
  // `token` adds a bearer-token resolver over the agent-tokens store. LOOPBACK-ONLY
  // this cycle — the enforced-mode bind gate is unchanged. A token resolves to a
  // login that STILL must be a registered operator (default-deny registry), so a
  // token authenticates WHO and the registry authorizes.
  const authMode = process.env[ENV_AUTH] === "token" ? "token" : "tailscale";
  let resolveTokenLogin:
    | ((req: IncomingMessage) => Promise<string | null>)
    | undefined;
  if (authMode === "token") {
    const tokensPath = process.env[ENV_AGENT_TOKENS_FILE];
    if (!tokensPath) {
      console.error(`[safespace] ${ENV_AGENT_TOKENS_FILE} must be set when ${ENV_AUTH}=token`);
      process.exit(1);
    }
    const tokenSalt = await getOrCreateAgentTokenSalt();
    try {
      await loadAgentTokens(tokensPath); // initial fail-loud parse (mirrors the registry)
    } catch (e) {
      console.error(`[safespace] ${e instanceof Error ? e.message : String(e)}`);
      process.exit(1);
    }
    resolveTokenLogin = async (req: IncomingMessage): Promise<string | null> => {
      const hdr = req.headers.authorization;
      const bearer = extractBearerToken(Array.isArray(hdr) ? hdr[0] : hdr);
      if (!bearer) return null;
      let store: Map<string, AgentTokenRecord>;
      try {
        // Re-read per session-init so a mint/revoke bites the NEXT connection (the
        // A1 revocation path). A parse failure → fail CLOSED (refuse all token auth).
        store = await loadAgentTokens(tokensPath);
      } catch {
        return null;
      }
      return lookupTokenLogin(bearer, store, tokenSalt, Date.now());
    };
  }
  await startHttpServer(createMcpServer, { port, bind, registry, authMode, resolveTokenLogin });
  // v1.102 (W0) — start the inbound webhook listener (a SEPARATE node:http server on its
  // own port, same process). Guards above already validated the port + signing secrets.
  if (webhookEnabled()) {
    const wh = resolveWebhookConfigFromEnv();
    await startWebhookListener({ port: wh.port, bind: wh.bind });
  }
} else {
  await createMcpServer().connect(new StdioServerTransport());
}

// v1.8.2 #7 / cold-path: write the startup marker AFTER the transport is
// connected (stdio) / listening (http + webhook), not before the handshake.
// `safespace doctor` reads it to detect "policy file modified after proxy
// started"; marking "serving began" a few ms later is equally valid and keeps
// the 2 best-effort disk syscalls (mkdir + write) off the time-to-first-tool
// path. Best-effort — write failure is logged to stderr and swallowed; never
// blocks proxy startup.
await writeStartupMarker(configDir());
