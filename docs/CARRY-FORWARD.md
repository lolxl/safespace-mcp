# SafeSpace MCP — Security-Review Carry-Forward

> Each release cycle's design / dual-review / holistic-review surfaces deferred
> *security-review* items. Only the deduplicated **currently-open** list is kept
> here; per-cycle provenance lives in `git log` + each cycle's `docs/vX.Y-*.md`
> design doc. (v1.40 §3 removed the ~390-line verbatim per-cycle history that
> used to follow — it was a dozen restatements of the same items.)

## Currently open (post-v1.51.0)

These are the genuinely-unclosed items as of the last shipped release. All
earlier "NEW from v1.XX" items not listed here were closed in a subsequent cycle
(e.g. v1.30 INFO-2 forensic field → v1.32; v1.32 sec-L1 256-char cap + 4
audit-CLI forensic items → v1.33; **v1.21 §3.3 nested-formula bypass → v1.34**
via the STEP 5 string-literal-aware scanner; **Armenian homoglyph coverage →
v1.35**, n/h gap shut, Devanagari formally closed).

> **No change to the open list across v1.42 → v1.51** (10 feature cycles: Drive
> folder-ops/permissions → Gmail drafts → Gmail threads+attachments → Calendar
> freebusy/list → Drive file-write → Tasks move/clear → YouTube playlists
> non-destructive + destructive → Contacts write → Gmail filters). Each cycle's
> security review PASSed; every LOW/NIT was fixed in-cycle, and the two
> *accepted bounded Model-A assumptions* it produced — the v1.42
> `drive_move_file` relocation-into-whitelist escalation and the v1.44/v1.45
> enum/base64-unwrap trade-offs — are documented in **`SECURITY.md` §3 / the
> trust-boundary section**, which is their correct home (they are closed
> decisions, not deferred security work). Item 4 (closed v1.41) was the last
> *actionable* carry-forward; the open set has been items 1–3 since.

> **Note (open-source + multi-user pivot):** the 4 architectural BLOCKERs of the
> identity/tenancy layer are tracked in the private archive's design docs,
> NOT here — this file is the *security-review* deferred list. All four shipped
> behaviorally: BLOCKER 2 (audit actor) v1.36.0 · BLOCKER 1 (`SecretBackend` +
> encrypted Linux `FileBackend`) v1.37.0 · BLOCKER 3 (per-operator `ctx.tier`)
> v1.38.0 · BLOCKER 4 (tasks-delete target allowlist, `-32030`) v1.39.0. The
> formerly-deferred multi-tenant items all landed with the real Model B arc:
> **`OperatorContext` assembly** v1.74.0 · **`policyScope`** superseded by
> `allowedAccounts` (v1.74 Q8) · **`selfEmails` partition** v1.80.0 (see item 3).

1. **Full UTS #39 confusables vendoring** (v1.30 design-deferred; v1.35 Q5
   re-affirmed defer) — only if the hand-curated ~50-entry `HOMOGLYPH_MAP` proves
   insufficient. Cost: ~250KB Unicode table + yearly update cadence + hot-path
   perf re-eval. Re-evaluate only on a concrete observed bypass.
2. **Hebrew look-alikes** (v1.35 Q3 defer) — 4 RTL candidates (VAV/FINAL-NUN
   U+05D5/U+05DF → l, SAMEKH U+05E1 → o, TET U+05D8 → v), all RTL + low
   monospace confidence; re-evaluate only on a concrete observed bypass.
   (**v1.35 CLOSED:** Armenian — 6 graded `HOMOGLYPH_MAP` entries (OH
   U+0555/U+0585 → O/o, TIWN U+054F → S, VO U+0578 + RA U+057C → n, HO U+0570 →
   h), closing the n/h zero-coverage gap; Devanagari — ZERO in-scope Latin
   confusers in confusables.txt v17.0.0.)
3. ~~**Multi-tenant `policyScope` / `selfEmails` partition**~~ — **CLOSED across
   v1.39 → v1.74 → v1.80.** Was `SAFESPACE_TASKS_DELETE_TARGETS` (v1.19 NEW-2);
   the **tasks-delete target allowlist SHIPPED v1.39.0** (standalone, `-32030`,
   env two-layer, OFF=allow, Option L). The `OperatorContext` assembly SHIPPED
   v1.74.0 (Model B PR-2a); the broader `policyScope` (per-operator allowlists)
   was **SUPERSEDED by `allowedAccounts`** per the v1.74 design (Q8 LOCKED:
   per-operator allowlists stay GLOBAL for the trusted-group model — OAuth-
   account confinement is the per-operator scoping the envelope needs). The
   **`selfEmails` partition SHIPPED v1.80.0** (Model B PR-3): the recipient-
   allowlist implicit self-send exemption is confined to the calling operator's
   `allowedAccounts` at both consumers (gmail egress + drive_share), closing
   the last code-level Model-B confinement residue.
4. ~~**`rejected_formula_nested?` forensic discriminator**~~ — **CLOSED v1.41.0**
   (PR #237). The PRESENCE-as-signal boolean distinguishing a direct attack
   (STEP 4 outer-name match) from a nested-wrapper smuggle (STEP 5 scanner) now
   threads through `ValidateCellResult` + `SheetsMutationAuditMeta` serialize
   (Q3 order function → nested → homoglyph) + `-32029` MCPError data +
   `AUDIT_ERROR_FORENSIC_WHITELIST` gap-fill + `audit recent` `(nested)` marker,
   mirroring the v1.32 homoglyph-source field. security-reviewer PASS (6
   invariants). This was the **last *actionable* security-review carry-forward**
   — items 1–2 are design-deferred-pending-evidence, item 3 is a Model-B item.

5. **OAuth scope union is NOT narrowed by `SAFESPACE_CONNECTORS`** (NEW, v1.127 —
   raised by the pre-implementation review). `computeScopeUnion`
   (`src/tools/registry/index.ts`) unions `requiredScopes` across the WHOLE
   registry, so `SAFESPACE_CONNECTORS=gmail` still consents to Drive / YouTube /
   Sheets / Slides / Forms / Tasks / Contacts / Calendar. The v1.127 axis narrows
   the **agent's reach through SafeSpace**, not the **token's authority** — an
   operator will plausibly assume otherwise, so the gap is documented in
   `.env.example`, `docs/CLIENTS.md`, and the module header. Feeding the connector
   set into the scope union would turn the axis from an exposure filter into a real
   structural reduction (a smaller consent screen, a less powerful token at rest),
   but it interacts with the existing consent/re-consent flow and multi-account
   token store, so it is deliberately its own cycle. **Not a regression — a
   pre-existing property the new axis makes newly visible.**

6. **`SAFESPACE_CONNECTORS` does not stop the inbound webhook listener** (NEW,
   v1.127 — raised HIGH by the implementation security review). `proxy.ts` starts
   the public `node:http` listener on `webhookEnabled()` (`SAFESPACE_WEBHOOK_PORT`)
   alone. Omitting the `webhook` token hides `inbox_read` from the agent and refuses
   it at `tools/call`, but SafeSpace still binds the socket, still accepts signed
   Slack/LINE callbacks, and still persists that third-party content to the durable
   inbox. **This is the widest of the four non-coverage gaps** because it is
   SafeSpace's only unsolicited public surface — an operator reading "the webhook
   connector is off" would be wrong in the direction that matters most. Not an exfil
   path (the agent cannot read the inbox), but a listening socket the operator
   believes is closed. Mitigation today: unset `SAFESPACE_WEBHOOK_PORT`. Documented
   in the module header + `docs/DEPLOY.md`. A future cycle should decide whether
   `webhookEnabled()` should consult the axis, or whether the two knobs are
   deliberately independent (the listener is a Model-B deployment property, the axis
   is an agent-surface property — a case can be made either way).

7. **`SAFESPACE_CONNECTORS` does not stop the contacts connector being exercised
   internally** (NEW, v1.127 — raised MED by the same review). The People-API
   name→email lookup is a Source strategy (`resolveRecipients`, `tools/source.ts`)
   and is also called directly from `handlers/calendar.ts`; neither consults the
   axis. With `SAFESPACE_CONNECTORS=gmail,calendar` plus the separate
   `SAFESPACE_RECIPIENT_ALLOW_CONTACTS=true` opt-in, a name-shaped recipient still
   queries the address book. Bounded: the 5 `contacts_*` tools ARE hidden and
   blocked (the agent cannot browse contacts), the lookup is read-only and
   name→email only, and the opt-in defaults off. Same class as item 6 — the axis
   gates the agent's TOOL SURFACE, not internal helper calls between connectors.

> **CLOSED in v1.34:** the recursive-AST / nested-formula bypass (v1.21 §3.3)
> that occupied this list through v1.33 — closed via a string-literal-aware
> linear token scanner (depth-agnostic, ReDoS-free, lower blast radius) that
> FLIPPED the 3 documented-gap sentinels PASS → REJECT.

---

_Per-cycle provenance (the former verbatim history) lives in `git log` + each
cycle's `docs/vX.Y-*.md` design doc._
