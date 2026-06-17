# Making SafeSpace the sole egress (company deployment hardening)

SafeSpace gates everything that flows **through** it. But it is an MCP server — a
**cooperative** gateway: the agent *chooses* to call its tools. SafeSpace cannot, by
itself, stop an agent from reaching an external API some other way.

> **"SafeSpace is the only exit" is a property of the deployment, not a feature of
> SafeSpace.** SafeSpace provides the *safe lane* (gated tools + credential custody +
> audit). The deployment must remove every *other* lane.

For a single trusted operator on their own machine (**Model A**) this doesn't matter —
you trust the human. For a **company deployment**, where an agent acts semi-autonomously
and a compromised or buggy agent is in the threat model, you make SafeSpace an *enforced*
chokepoint by locking the three ways an agent could go around it.

## The three bypass paths — lock all three

An agent can only reach an external API directly if it has **(1) a credential**, **(2) a
network route**, and **(3) a way to make the call**. Remove any one and the bypass fails;
remove all three for defense in depth.

### Layer 1 — Credential custody: the agent holds ZERO secrets

The only reason an agent could call Gmail / GitHub directly is that it holds the token.
SafeSpace already keeps **all** credentials in its `SecretBackend` (macOS Keychain /
encrypted file / a vault in a hosted deployment); the agent never sees them. Enforce it:

- Run SafeSpace as a **separate process / user / container** from the agent. The agent's
  environment must not be able to read SafeSpace's keychain / encrypted token file /
  vault (no shared filesystem, no shared user).
- **No API keys, OAuth tokens, or bot tokens in the agent's environment** (env vars,
  config, mounted files). The agent's *only* credential is its authenticated connection
  to SafeSpace.

→ For every credentialed source, the agent now simply **cannot authenticate** on its own.

### Layer 2 — Network egress: the agent's runtime can't reach the outside

This is the enforcement teeth. Run the agent in a sandbox (container / VM / network
namespace) whose **egress is deny-all except to SafeSpace's address**. The provider
endpoints (`googleapis.com`, `api.github.com`, `api.line.me`, …) and arbitrary HTTP are
**unroutable** from the agent. Only SafeSpace's process has an egress allowlist to those
endpoints.

Mechanisms (pick what fits the platform):

- **Kubernetes** — a default-deny `NetworkPolicy` on the agent pod, egress allowed only
  to the SafeSpace service; SafeSpace's own egress policy allows only the provider hosts.
- **Plain host / Docker** — a firewall rule: the agent's subnet may reach **only**
  SafeSpace's `IP:port`; SafeSpace reaches the internet.
- **Forced egress proxy** — only SafeSpace is permitted to use the outbound proxy; the
  agent has no direct route.
- **Network namespace** — the agent runs in a netns with no default route except the
  SafeSpace socket.

Model B already runs SafeSpace on a **Tailscale tailnet** with a loopback/tailnet-only
bind (`SAFESPACE_HTTP_BIND` ≠ `0.0.0.0`). Extend it: the agent reaches SafeSpace over the
tailnet, and the agent's host has **no other internet route**.

→ This is what turns "cooperative" into "enforced": even if the agent *wanted* to call
Gmail directly, the packet does not route.

### Layer 3 — Runtime / tool surface: the agent can't build its own exit

The agent must not have an **unrestricted shell, code-exec, or arbitrary-fetch** that can
open its own sockets. If the agent runtime (Claude Code, a custom harness) exposes
bash/exec, that runtime must live in the **same network-denied sandbox** so Layer 2 backs
it up. Give the agent **only** the MCP tools you intend (SafeSpace's) — not a raw
`curl` / `web_fetch`.

→ This is the thesis's *axis-3 = agent-runtime sandbox*. Layer 2 is the backstop: even
arbitrary code can't leave a netns with no route out.

### Layer 4 — Provider-side pinning (defense in depth)

Where the provider supports it, restrict the credential so it is **only usable from
SafeSpace's egress IP**. Support varies by provider, so check what *your* credential type
allows: a **GitHub organization IP allowlist** applies to OAuth tokens; for keyless /
API-key connectors, issue an **IP-restricted API key**. (Note: a standard Google OAuth
*access token* can't be IP-pinned — this layer isn't available everywhere, which is why
it is defense-in-depth, not a primary control.) Where it does apply, a stolen token is
useless from anywhere but SafeSpace's egress, so a bypass fails **at the provider** even
if Layers 1–3 had a hole.

### Layer 5 — Detection: catch what leaks

SafeSpace's `run_id` audit trail is the record of everything that went **through** the
gate. To detect a **bypass**, monitor the network: any connection from the agent's subnet
to an external API that did **not** originate from SafeSpace is a misconfiguration or an
attack → **alert**.

→ SafeSpace audit + an egress monitor = *everything that left, and an alarm if something
left another way.*

## Two postures

| | **Model A** — single trusted operator, local | **Company** — enforced sole egress |
|---|---|---|
| SafeSpace role | cooperative gateway; gates + audits what flows through it | a true chokepoint |
| You add | nothing (your own machine, your own trust) | ① credential isolation · ② network egress lockdown (the load-bearing one) · ③ runtime sandbox · ④ provider IP pinning · ⑤ egress monitoring |

## What SafeSpace gives vs. what the deployment must add

| SafeSpace provides | The deployment must add |
|---|---|
| The gated tool surface (tier / scope / recipient / target / SSRF gates) | The network walls that delete every other route (Layer 2) |
| Credential custody (`SecretBackend`, F6 token-at-rest hardening) | Isolation so the agent can't read that store (Layer 1) |
| The `run_id` audit trail | An egress monitor to detect bypass + a SIEM sink (Layer 5) |
| Loopback / tailnet-only transport + verified operator identity (Model B) | A sandboxed agent runtime with no DIY egress (Layer 3) |

**Bottom line:** SafeSpace is *necessary but not sufficient* for "sole exit." It is the
safe lane, the credential custody, and the audit; the company deployment builds the walls
— above all the **network egress lockdown (Layer 2)** — that remove every other lane.

## Enforcing the SafeSpace-side knobs — `SAFESPACE_ENFORCED`

SafeSpace can't verify the *external* walls (Layers 2–4 are the deployment's job), but it
*can* refuse to run when its **own** hardening knobs are misconfigured. Set
`SAFESPACE_ENFORCED=true` on a company deployment and the bootstrap **refuses to start**
(exits before serving a single tool, naming every failing precondition at once) unless:

- **autonomous mode is on** (`SAFESPACE_AUTONOMOUS=true`) — so the egress allowlists are
  deny-by-default and permanent-deletes are hard-denied (F2/F4);
- **the OAuth token store is not offline-capturable** — OS keychain, or an encrypted
  FileBackend in passphrase mode. This is *stricter than F6*: the
  `SAFESPACE_ALLOW_KEYFILE_AT_REST` escape hatch is **not** honored under enforced mode;
- **the HTTP listener does not bind all interfaces** (`SAFESPACE_HTTP_BIND` ≠ `0.0.0.0`/`::`)
  — N/A under stdio. **One deliberate hatch (v1.94 A2):** the listener is plaintext
  `node:http` and SafeSpace does **not** terminate TLS in-process, so a deployment that must
  bind all interfaces inside its netns (a container behind a TLS-terminating proxy) sets
  **`SAFESPACE_TLS_TERMINATED=true`** to *attest* that the proxy fronts the listener and
  restricts who can reach it. SafeSpace cannot verify the upstream TLS — the attestation makes
  that deployment-external responsibility explicit, exactly like the egress lockdown. The
  asymmetry with the keyfile hatch is principled: SafeSpace *can* fix key-at-rest in-process
  (a passphrase), so it refuses the weaker option; it *cannot* terminate TLS for a plaintext
  listener without becoming a cert-managing proxy, so the attestation is the honest boundary.
  The hatch relaxes **only** the bind gate; it never weakens operator auth.

It is **opt-in and fail-safe**: unset (the Model A default) is byte-identical to today, and
a typo evaluates false (you stay in the non-enforced posture rather than bricking startup);
`SAFESPACE_TLS_TERMINATED` is the same strict-truthy shape (a typo leaves the bind gate a hard
fail).

`safespace doctor --posture` reports these gate states **without** starting the server. It
also enumerates every connector's egress/access allowlist — `restricted (N)` / `deny-all` /
`OPEN` — so you can see exactly what can reach or leave through the deployment (counts only,
never the allowlist contents), plus the **egress-destination registry** — the external hosts
SafeSpace's own process connects to, each `enforced` (runtime-gated at the fetch chokepoint
against a host-injection escape) or `declared` (listed but ungatable — the googleapis SDK
owns its socket, web-fetch is the dynamic SSRF-gated path). And it always prints the honest reminder that the network
egress lockdown, the agent sandbox, and provider IP-pinning are **deployment-external**: a
green posture confirms SafeSpace's own knobs, never that SafeSpace is the *sole* exit. Build
the walls above; enforced mode only guarantees you didn't leave SafeSpace's own door open.

## See also

- [`DEPLOY.md`](DEPLOY.md) — the Model B operator runbook (Docker / Compose / Tailscale).
- [`docs/model-b-deployment.md`](model-b-deployment.md) — the deployment design + rationale.
- [`SECURITY.md`](../SECURITY.md) — the trust boundary and threat model.
