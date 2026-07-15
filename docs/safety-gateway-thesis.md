# SafeSpace as the AI Safety Gateway — thesis + enabling architecture

> **Status:** Thesis / north-star design — **Q1–Q8 LOCKED (owner "all-as-recommended",
> 2026-06-06) + TWO architecture reviews incorporated (2026-06-06):
> (1) a seam review that re-cut §4/§6/§10, and (2) a whole-codebase audit that
> identified the missing pipeline abstraction (§4.3) + 12 structural deficiencies
> classified FOLD/ADJACENT/LEAVE (§6.1) — the FOLD set is the Phase-B bundle.**
> This is now the project's north star; future surface additions are evaluated as
> *connectors behind the envelope* (Q7). The thesis DIRECTION (Q1/Q3/Q6/Q7) was
> validated; the enabling architecture (§4) and the migration (§6) were **re-cut
> per the review** — the seam is a `Credential` discriminated union + resolver/
> authorizer strategies (NOT an `authModel` enum), Phase B is a choke-point
> **re-architecture** (NOT a relabel) that **includes centralizing the egress
> gates**, and the review's missed risks are folded into §10. Strategic
> positioning + the architecture that makes it real. NO code this cycle (the seam
> is built in the first-connector cycle). Companion to
> `docs/social-engineering-threat-analysis.md` (the threat thesis) and
> `docs/ARCHITECTURE.md` (the as-built structure). Verified against `f571695`
> (post-v1.63.0).

---

## 1. The thesis (one sentence)

**SafeSpace is not a Google Workspace proxy — it is a provider-agnostic safety
envelope that sits between an AI agent and *any source it touches*, and that
envelope is the product. Sources are connectors behind it.**

The forty-plus cycles that "added Google tools" were, in truth, repeatedly proving
one thing: the value lives in the **envelope** (sanitize, untrusted-content
wrapping, scope/tier/burst/recipient gates, autonomy hardening, audit) — none of
which is Google-specific in *concept*. Only the connectors are. Re-stated as the
product it actually is: **the AI safety gateway / policy layer for an agent's
external surface.**

---

## 2. Why this is already half-true (the envelope inventory)

Every security capability shipped to date is provider-agnostic in concept — the
Google specificity is only in the *connector*, never in the *gate*:

| Envelope capability | Built for | Generalizes to "any source"? |
|---|---|---|
| Inbound sanitize pipeline (`<untrusted-source>` wrap, zero-width strip, confusables, pattern-flag, truncate) | Gmail/Drive/Docs reads | ✅ It walks JSON/text leaves — it does not know or care that the bytes came from Google. Any inbound content (message, reply, mention, web page, file) is identical. |
| Outbound REJECT (SSRF / secret-shape / inbound-formula) | YouTube comments, Sheets, Slides | ✅ Any egress / public-surface write needs exactly this. |
| Recipient allowlist · write-burst · tier gate | gmail_send, writes | ✅ Any "send to / post to / act on" surface. |
| **Autonomy Hardening (F1–F6)** — universal write burst, autonomous deny, token-at-rest, tainted-source provenance, outbound secret reject | the OpenClaw confused-deputy phishing analysis | ✅ **This is the provider-agnostic safety FLOOR.** It keys off *operations* (read/write/delete/egress), not Google APIs. |
| `run_id` / session anomaly audit (F5) | CLI forensics | ✅ "What did the agent do, across all sources, in this run?" — this is literally the **"center"** in *safety center*. |
| Token storage behind `SecretBackend` (Keychain / encrypted FileBackend) | Google OAuth tokens | ✅ **Already abstracted** — it holds *a secret*; it does not care if that secret is an OAuth refresh token, a Telegram bot token, or a LINE channel token. |

**The connectors are commodity (anyone can call an API). The envelope is months of
security work that happens to be provider-agnostic. That is the moat.**

> ⚠️ **As-built caveat (architecture review).** The *primitives* above are
> provider-agnostic, but two are not yet wired the way the thesis pictures them:
> **(1) the outbound egress gates — recipient-allowlist, outbound-secret-shape,
> tainted-source — run INSIDE the gmail handler (`handlers/gmail.ts`), NOT at the
> choke point.** Only tier + write-burst + autonomous-delete + sanitize + audit
> run centrally today. So "the envelope auto-wraps any source" is the *target*,
> not the current code — a naively-added write connector would ship with ZERO
> recipient/secret/tainted protection while *looking* like it is behind the
> envelope (a security regression hiding inside a positive thesis). **Centralizing
> the egress gates is therefore part of the seam work (§6 Phase B), not an
> assumption.** **(2) `SKIP_FIELDS` (sanitize's opaque-passthrough set) is
> Google-keyed** — each connector needs its own opaque-key set or sanitize
> mis-wraps (e.g. a Telegram `file_id`/`chat.id`). Small, but real (§10 R6).

---

## 3. Two axes — and why this thesis is the cheap one

A persistent confusion in the roadmap collapsed two orthogonal axes into "Model B":

- **Axis 1 — Sources** (Google, Telegram, LINE, X, web, filesystem, …). The "all
  sources" axis. **This thesis.**
- **Axis 2 — Operators / tenancy** (one operator vs many co-managing). **Model B.**

The thesis is **axis 1 made the main line**, and it is **independent of axis 2**:
one operator (you, Model A) connecting many sources, all behind one envelope, is
the whole thesis — and needs *no* multi-tenancy. **This takes the stalled,
expensive multi-operator work off the critical path.** Model B stays paused;
adding sources does not require it.

(Axis 3 — the agent reaching an API *directly*, bypassing SafeSpace — remains the
agent runtime's sandbox job, exactly as `social-engineering-threat-analysis.md`
already records. SafeSpace is the gateway when used; it is not a kernel-level
interceptor.)

---

## 4. The enabling architecture — the Source seam (re-cut per architecture review)

The thesis demands one real refactor: **the envelope must stop assuming OAuth.**
Today `withToolContext` (the choke point) does this OAuth-only sequence
*unconditionally*: resolve a Google `email` → look it up in `accounts.json` →
`refreshAccessToken` → pre-check `requiredScopes` against `SCOPE_HIERARCHY` →
invoke → on 401 force-refresh-and-retry → on 403 map to `scope_mismatch -32004`
("`safespace consent --re-auth`"). A non-OAuth source (a bot token, a web fetch, a
file read) has **no email, no account, no token-refresh, no scopes, no
re-auth recovery** — so each of those steps is a Google-specific branch, not a
universal one.

> **Why NOT an `authModel` enum (review finding).** An earlier draft had each
> source declare `authModel: "oauth" | "service-token" | …` and the choke point
> `switch` on it. That is a polymorphism-shaped hole — it spreads source-type
> knowledge into the choke point and means every new auth model edits the choke
> point's `switch`. This codebase already prefers the open/closed cut (a getter
> not a field; `AUDIT_META_CHANNELS` a registry not a hand-list). So the seam is a
> **discriminated `Credential` union + two strategy interfaces**, dispatched by
> the source object — a new auth model = a new variant + two strategy impls, **zero
> choke-point edits.**

### 4.1 The `Credential` union + two strategies
- **`Credential`** (discriminated union — the 3-class taxonomy of §5 lives HERE,
  not as an enum):
  `{ kind: "oauth", email, getAccessToken } | { kind: "service-token", token } | { kind: "none" }`.
  `ToolContext` changes from `{ email, getAccessToken, tier, … }` to
  `{ credential: Credential, tier, … }`; handlers narrow on `credential.kind`.
- **`CredentialResolver`** — `resolve(source, ctx) → Credential`. OAuth impl = the
  *verbatim* current resolve-account + `refreshAccessToken` + the 401
  force-refresh-retry policy; service-token impl = read one secret from
  `SecretBackend` (already generic, §2); keyless impl = `{ kind: "none" }`.
- **`Authorizer`** — `authorize(source, toolDef, ctx) → void | throw`. OAuth impl =
  the *verbatim* current `scopeSatisfies` / `SCOPE_HIERARCHY` / `requiredScopes`
  check + the `scope_mismatch -32004` mapping; service-token = "holds the token" +
  tier; keyless = tier only.
- A **`Source`** declares: `id`, its `CredentialResolver` + `Authorizer`, an error
  mapper (replacing the per-handler `mapGoogleError`), an opaque-key set (its own
  `SKIP_FIELDS`), and its tools (each with `min_tier` + a **direction**:
  `inbound-read` / `outbound-write`).

### 4.2 The universal envelope (what every source flows through)
At the choke point, dispatched by the source's strategies, NOT a `switch`:
1. **tier gate** — universal. *(already central)*
2. **resolve credential** — `source.credentialResolver.resolve(...)`.
3. **authorize** — `source.authorizer.authorize(...)`.
4. **outbound gates on `direction: "outbound-write"`** — recipient-allowlist ·
   outbound-secret REJECT (SSRF/secret-shape) · tainted-source · write-burst ·
   autonomous deny. ⚠️ **These must be MOVED here from `handlers/gmail.ts`
   (centralization is Phase-B work, §2 caveat / §6) — they are not central today.**
5. **invoke** the connector.
6. **inbound sanitize** the response — `<untrusted-source>` wrap, using the
   source's opaque-key set. *(sanitize itself is already central + generic)*
7. **audit** — operator · `run_id` · **`source`** (NEW row field) · tool. *(already
   central; `source` is an additive field like `run_id`)*

**The OAuth machinery (`V1_SCOPES`, consent, `SCOPE_HIERARCHY`, `requiredScopes`)
becomes the google-workspace source's `Authorizer` + `CredentialResolver` impls —
not a property of the gateway.** What is genuinely universal = tier + the resolve/
authorize *dispatch* + the (to-be-centralized) egress gates + sanitize + audit.

> **`withAllAccounts` (the cross-account `_all` fan-out) is a SECOND, more
> Google-coupled choke point** (it bakes in N-Google-accounts, its own scope check,
> refresh, sanitize, audit). Per the review it is **explicitly scoped as an
> OAuth-account-class-only capability — NOT generalized.** Telegram has no `_all`
> equivalent; do not force it through this path — but it must call the SAME core
> pipeline (below), N times, instead of re-implementing it.

### 4.3 The keystone — build the 7 steps as a real pipeline, not bolt a union on
The whole-codebase architecture audit (§6.1) found that those 7 steps are **not an
abstraction today** — they are an inlined 951-line procedure in `with-context.ts`,
*plus* a 325-line near-duplicate in `with-all-accounts.ts` that has already drifted
(the `_all` path runs neither the egress gates nor the autonomy/burst gates and
writes a stripped audit row). The egress gates leaked DOWN into `handlers/gmail.ts`;
the 9 audit-recorder closures leaked UP into the `ToolContext` god-interface; error
mapping is smeared across 79 handler `catch` blocks.

So the **single missing abstraction** is a per-call **middleware chain assembled
from the `Source` descriptor**:

```
[ resolveCredential → authorize → egressGates(if outbound-write)
  → invoke → sanitize(source.skipFields) → audit(via ctx.audit) ]
```

Building Phase B *as this pipeline* (rather than bolting a `Credential` union onto
the existing inlined procedure) is what makes the refactor pay for itself: the one
chain resolves audit findings **D1** (two choke points → one core pipeline called
N× by the fan-out), **D2** (egress gates move INTO the chain), **D4** (error
mapping = one `catch` in the chain dispatching to `source.mapError`, deleting 79
boilerplate blocks + cutting a fragile circular `import type`), **D5** (sanitize
reads `source.skipFields`), and **D12** (the `cross_account` guard becomes a
dispatch property) — and makes **D3** (split `ToolContext` → `{credential, tier,
audit}`) and **D6** (one `ctx.audit.record(channel, meta)` sink instead of 9
closures) trivial. This is the difference between "Phase B adds a union" and "Phase
B is the structural cleanup the codebase already needs."

---

## 5. Source taxonomy (3 classes — pick reference connectors across them)

| Class | Auth | Examples | Envelope value | Cost |
|---|---|---|---|---|
| **A. OAuth-account** | per-user OAuth + refresh + scopes | Google Workspace (today) · Threads/IG/X (later) | full read+write of *your account* | HIGH (multi-issuer OAuth if >1; app-review; X is paid) |
| **B. Service-token** | one long-lived token in `SecretBackend` | Telegram Bot · LINE Messaging API | act as the bot/OA in *managed channels* | LOW (no per-user OAuth, no app-review, fits the secret seam) |
| **C. Keyless / local** | none | web-fetch · filesystem-read · clipboard | **pure inbound-sanitize** + outbound-SSRF-gate | LOW-MEDIUM (but expands the threat surface SafeSpace owns) |

The three classes ARE the variants of the `Credential` union (§4.1): A = `oauth`,
B = `service-token`, C = `none`. Class C is the **starkest demonstration** of the
thesis: an agent fetching a URL or reading a file *through SafeSpace* gets the
HTML/text sanitize-wrapped and the outbound URL SSRF-checked — pure safety value,
zero "API account." Class B is the **best first proof** because it forces the
non-OAuth (`service-token`) credential path while delivering a real use case
(channel co-management).

---

## 6. Migration — relabel (A), re-architect the choke point (B), connect (C)

The current Google-shaped code becomes the **reference connector**, not a rewrite
— but the review corrected the framing: **Phase B is NOT an "extraction"/relabel;
it is a contained re-architecture of the choke point + a `ToolContext` type
change.** Naming it honestly sets the right cost expectation.

- **Phase A — relabel (genuinely ~zero behavior change, reversible).** Add
  `source?` / `direction?` as OPTIONAL fields on `ToolDef` (defaulting
  google-workspace), thread `source` into the audit row (additive, exactly the
  `run_id`/`tainted_source` precedent). Low-risk; validates the registry plumbing.
- **Phase B — re-architect the choke point as a pipeline (a REFACTOR cycle, not a
  relabel).** Build the §4.3 middleware chain and migrate the Google path onto it;
  behavior-preserving *for Google* by construction (the 2487-test suite + scope
  sentinels are the net). The load-bearing changes are the **"Phase B+ bundle"
  (§6.1)** — they are folded together precisely because they all touch the same
  seam the pipeline cuts, and doing them in separate passes would re-open the choke
  point repeatedly. In dependency order: split `ToolContext` (D3) → centralize
  egress gates (D2) → lift error mapping (D4) → per-source `SKIP_FIELDS` (D5) →
  unify the two choke points into one core pipeline (D1, takes D12 with it). ⚠️ The
  `ToolContext` change is the real blast radius (R6): `email`/`getAccessToken` are
  required + read by ~every handler — doing it wrong = faking an `email`/empty
  token (a non-OAuth source masquerading as an account in the audit log; don't).
- **Phase C — first non-OAuth source (the real test).** A **service-token**
  connector (Telegram Bot). Because B already de-coupled `email`/token and
  centralized the egress gates, C is genuinely a thin connector — and it validates
  the seam instead of discovering a half-rewrite mid-flight.
- **Phase D+:** a class-C keyless source; the OAuth social fork (Threads/IG/X)
  *only if/when* bundled with the multi-issuer work (still its own big decision).

Each phase is its own PR. Phase A is small + reversible; **Phase B is budgeted as a
refactor cycle** (the §6.1 bundle); Phase C is the validation. **Before Phase B,
paper-audit the knowable "Google-bolted" details (§10 R6/R8) so they are
designed-for, not discovered mid-flight.**

### 6.1 Deficiencies folded into Phase B (whole-codebase architecture audit, 2026-06-06)

The audit classified 12 structural deficiencies by whether to bundle them into the
Phase-B pipeline refactor. **FOLD** = touches the same seam Phase B opens (cheap to
bundle, wasteful/risky to do twice). **ADJACENT** = real debt, own PR, NOT coupled
(would bloat the refactor). **LEAVE** = intentional / not worth it.

| # | Deficiency | Sev | Tag |
|---|---|---|---|
| **D1** | Two choke points (`with-context` / `with-all-accounts`) reimplement the pipeline; drifted on egress + audit-shape + error-mapping | HIGH | 🔧 FOLD |
| **D2** | Egress gates live in `handlers/gmail.ts`, not the pipeline (= R7) | HIGH | 🔧 FOLD |
| **D3** | `ToolContext` = 13-field god-interface (credential + tier + **9 audit-recorder closures**) | HIGH | 🔧 FOLD |
| **D4** | `mapGoogleError` repeated in 79 handler `catch` blocks (+ unreachable-return idiom + a fragile circular `import type`) | MED | 🔧 FOLD |
| **D5** | `SKIP_FIELDS` = one Google-keyed global (Telegram `file_id`/`chat.id` mis-wrap) | MED | 🔧 FOLD |
| **D12** | `cross_account` runtime guard compensating for the two-pipeline split | LOW | 🔧 FOLD (free w/ D1) |
| **D6** | Audit-recorder consumption = 4-layer hand-wiring per channel (~150 lines in the choke point) | MED | 🔁 ADJACENT (trivial once D3's `ctx.audit` lands) |
| **D7** | Registry = triple hand-listing (`TOOL_ORDER` / `IMPLEMENTED_TOOLS` / `FRAGMENTS`) + sorted sentinels every cycle | MED | 🔁 ADJACENT |
| **D8** | No `config.ts` — ~15 `SAFESPACE_*` vars parsed inline in 3 inconsistent idioms; the security conventions (strict-truthy-fails-permissive, no-PII-echo) re-documented per file | MED | 🔁 ADJACENT |
| **D9** | Lazy-singleton + `__internal.resetSingletons()` copy-pasted per policy module (the v1.57 test-pollution-bug shape) | MED | 🔁 ADJACENT |
| **D10** | `with-context.ts` 951 lines, ~250 logic + multi-version archaeology | LOW | 🟢 LEAVE (extract dead narration as a B side-effect) |
| **D11** | `EMAIL_RE` triplicated across layers (deliberate decoupling) | LOW | 🟢 LEAVE |

The **ADJACENT** items (D6–D9) are good follow-up PRs *after* Phase B — kept out of
the bundle to keep the refactor's blast radius honest. (Note D6 collapses to near-zero
once D3's `ctx.audit` facade exists; D8's `config.ts` would retire the per-file
security-convention duplication that risk R8/§10 names.)

---

## 7. Positioning / brand

"Security-first **Google Workspace** proxy" → "**the safety gateway for an AI
agent's external surface** — bring your sources, the envelope keeps the agent (and
your accounts) safe." Google Workspace becomes the flagship reference connector.

The **"center"** is deliberate: it is also the place you *see and constrain* what
the agent did across all sources (the `run_id`/session forensics already seed
this). The differentiator is **safety + visibility**, not connectivity — this is
explicitly **not** an iPaaS / Zapier (those compete on connector count; SafeSpace
competes on the envelope).

---

## 8. Decisions — proposed (Q1–Q8; awaiting owner)

- **Q1 — Adopt the thesis** as the north star (reframe to "AI safety gateway for
  any source"; Google = flagship reference connector)? *Rec: yes.*
- **Q2 — The Source seam (§4)** as the enabling architecture (the envelope stops
  assuming OAuth). *Rec: yes — **re-cut per the review** to a `Credential`
  discriminated union + `CredentialResolver`/`Authorizer` strategies (NOT an
  `authModel` enum the choke point branches on).*
- **Q3 — The 3-class source taxonomy** (§5: OAuth-account / service-token /
  keyless)? *Rec: yes — they are the `Credential` union's variants (§4.1).*
- **Q4 — Migration (§6)**, Google as the reference connector, no big-bang rewrite?
  *Rec: yes — **re-framed per the review**: Phase A relabel (cheap, reversible) →
  Phase B **re-architect the choke point** (a REFACTOR cycle: the `Credential`
  union + the `ToolContext` type change + **centralizing the egress gates**) →
  Phase C connect. Phase B is NOT a relabel; budget it as a refactor.*
- **Q5 — First non-Google connector to validate the seam:** a **service-token**
  source (Telegram Bot — real use case + forces the non-OAuth path) over a keyless
  class-C source? *Rec: service-token / Telegram Bot.*
- **Q6 — Axis separation:** this thesis is axis-1 (sources), decoupled from axis-2
  (Model B, multi-operator) which stays paused; adding sources does NOT require
  Model B? *Rec: yes.*
- **Q7 — This supersedes the "candidate-surface backlog" framing:** future
  additions are evaluated as *connectors behind the envelope*, classified by
  source-class, not as ad-hoc "more Google tools"? *Rec: yes.*
- **Q8 — Scope discipline / non-goals (§9):** a clean seam + 2–3 reference
  connectors across the classes — NOT 20 half-connectors, NOT an iPaaS, NOT Model
  B? *Rec: yes.*

---

## 9. Non-goals (scope guardrails)

- **NOT a general API gateway / iPaaS.** The product is the safety envelope, not
  connector breadth. Two or three reference connectors prove it; a marketplace
  does not.
- **NOT Model B.** Multi-operator tenancy is axis 2, orthogonal, still paused.
- **NOT a kernel interceptor.** Axis-3 (agent bypassing the gateway via a direct
  API call) stays the agent runtime's sandbox job. SafeSpace is the gateway *when
  used*.
- **NOT a big-bang rewrite.** The Google connector keeps working throughout;
  generalization is Phase A relabel → Phase B choke-point re-architecture (§6),
  behavior-preserving for the Google path by construction.
- **NOT 20 connectors.** Resist breadth until the seam is proven by one non-OAuth
  source.

---

## 10. Risks

- **R1 — Scope explosion ("all sources" → boil the ocean).** Mitigation: §9 + Q8;
  the seam + a single class-B proof is the whole near-term goal.
- **R2 — The envelope is more Google-bolted than it looks.** Mitigation: Phase C is
  designed to *surface* exactly this; the relabel (Phase A) is reversible and
  cheap, so we learn before committing.
- **R3 — Class-C keyless sources (web-fetch) expand the threat surface SafeSpace
  owns** (outbound SSRF becomes ours). Mitigation: defer class C until after the
  class-B proof; the existing SSRF-exclusion machinery (Sheets IMAGE / Slides /
  Forms) is the starting point.
- **R4 — Auth decoupling regresses the Google scope gates.** Mitigation: the OAuth
  path becomes the google-workspace `Authorizer`/`CredentialResolver` byte-for-byte;
  the scope sentinels + the 2487-test suite are the behavior-preserving net.
- **R5 — Brand dilution.** Mitigation: positioning stays *safety-first* (§7); the
  envelope, not the connector count, is the pitch.

### Risks the original thesis missed (architecture review, 2026-06-06)

- **R6 — `ToolContext.email` + `getAccessToken` are REQUIRED and read by ~every
  handler + `mapGoogleError`.** This is the real Phase-B blast radius (§6 B.2): the
  *handler-facing contract* assumes an email + a string token. Generalizing = a
  `Credential` union + a sweep of all handler call sites. NOT a relabel.
  **Worst-case failure to avoid:** a non-OAuth connector faking an `email`/empty
  token to fit the Google-shaped contract — a non-OAuth source masquerading as an
  account in the audit log.
- **R7 — The egress gates are NOT centralized today** (they live in
  `handlers/gmail.ts`). "The envelope auto-wraps any source" is the target, not the
  code. **A naively-added write connector would ship with ZERO
  recipient/outbound-secret/tainted-source protection while *looking* protected — a
  security regression hiding inside the thesis.** Mitigation: centralization is
  explicit Phase-B work (§6 B.3), not an assumption — this is the single most
  important correction.
- **R8 — Three "Google-bolted" details are knowable on paper NOW** (don't wait for
  Phase C to discover them): (a) **`mapGoogleError`** is per-handler + Google-shaped
  (each source needs its own error mapper); (b) **`SKIP_FIELDS`** is Google-keyed
  (each connector needs its own opaque-key set or sanitize mis-wraps); (c)
  **per-source quota** differs (YouTube units/day, Sheets/min, Telegram msg/s) —
  F1 write-burst is generic call-rate, but connector-specific quota guards are
  per-source. Mitigation: enumerate these in the connector cycle's design doc,
  designed-for not discovered.
- **R9 — `withAllAccounts` is a second, MORE Google-coupled choke point.**
  Mitigation: scope it as OAuth-account-class-only (§4); do NOT generalize the
  cross-account `_all` path.
- **R10 — the `_all` fan-out path ALREADY lacks the egress + autonomy gates**
  (`with-all-accounts.ts` runs neither `enforceWriteBurst` /
  `enforceAutonomousDeleteDeny` nor the recipient gate, and writes a stripped audit
  row with no operator/run_id/errorCode). It is latent today (the `_all` tools only
  fan out reads) — but **the moment a `*_all` write or delete is added behind it,
  it ships UN-GATED**: this is R7's "looks protected, isn't" failure hiding in the
  *second* choke point nobody is centralizing. Mitigation: D1 (unify both choke
  points onto one core pipeline) closes it — and it is a reason NOT to ship any
  `*_all` write until the pipeline lands. The whole-codebase audit named this the
  #1 structural risk.

---

## 11. The next step (after this thesis locks) — corrected cost

**Two cycles, not one** (the review's correction to "fold A+C into one"):

1. **The seam refactor cycle (Phase A + B).** Relabel + the `Credential` union +
   the `ToolContext` type change + **egress-gate centralization**. This is a
   **refactor cycle**, behavior-preserving for Google (the 2487-test suite + scope
   sentinels are the net), and it is the load-bearing work — calling it "minimal"
   would tempt leaving `email`/token required and faking them for the first
   connector (R6's worst case). Its own design doc should **paper-audit R8** (the
   three Google-bolted details) up front.
2. **The first-connector cycle (Phase C).** A **service-token** connector (Telegram
   Bot, channel co-management) behind the now-clean seam. *This* is the cheap, thin
   cycle — and because B already de-coupled `email`/token and centralized the
   egress gates, it **proves the seam** (does sanitize + the centralized
   outbound-reject + burst + audit wrap a non-OAuth, non-Google source cleanly?)
   instead of discovering a half-rewrite mid-flight. The Google tools come along
   for free as the reference `source: "google-workspace"`.

The original "one cycle proves it" was optimistic precisely because it hid Phase B
inside "minimal". Splitting B out is what makes C honest.

---

## 12. References
- `docs/social-engineering-threat-analysis.md` — the threat thesis (C1–C9); the
  envelope's *why*. Provider-agnostic by construction.
- `docs/ARCHITECTURE.md` — the as-built structure the Source seam layers over.
- The F1–F6 autonomy-hardening FLOOR (operation-keyed, not API-keyed) — the
  clearest proof the envelope is already provider-agnostic.
- The `run_id` / session-anomaly forensics = the "center" (cross-source
  visibility) seed.
- The candidate-surface backlog (Telegram/LINE = service-token class; Threads/IG/X
  = OAuth-account class) — reframed by this thesis as connectors-by-class.
- **Architecture review #2 — whole-codebase audit (2026-06-06)** —
  found the missing **pipeline abstraction** (§4.3) and 12 deficiencies (§6.1):
  FOLD = D1 two-choke-point unify · D2 egress · D3 ToolContext split · D4 error-map
  lift · D5 per-source SKIP_FIELDS · D12 cross_account guard; ADJACENT = D6 audit
  plumbing · D7 registry triple-list · D8 config sprawl · D9 singleton/reset; LEAVE
  = D10 comment-mass · D11 EMAIL_RE. #1 risk = R10 (the `_all` path ships un-gated).
- **Architecture review #1 — seam review (2026-06-06)** — validated
  the direction; re-cut §4 (`Credential` union, not `authModel` enum), re-framed §6
  (Phase B is a re-architecture, not a relabel; includes egress-gate centralization),
  and surfaced R6–R9. Key coupling files for the Phase-B design doc:
  `tools/with-context.ts` (6 OAuth coupling points), `tools/types.ts` (`ToolContext`
  → `Credential` union), `tools/handlers/gmail.ts` (egress gates + `mapGoogleError`
  to centralize), `tools/with-all-accounts.ts` (the OAuth-only second choke point),
  `sanitize/index.ts` (per-source `SKIP_FIELDS`), `tools/registry/types.ts` (where
  Phase A's optional fields land).
