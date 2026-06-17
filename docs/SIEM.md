# Shipping the audit log to a SIEM

`safespace audit export` streams the audit log to **stdout**, one formatted
record per line, so you can pipe it into whatever log shipper your SIEM already
uses (Vector, Fluentd, Filebeat, `logger`, …).

It is the **shipping half** of the audit story. The **integrity half** is
[`safespace audit verify`](AUDIT-CHAIN.md) (the v1.89 tamper-evident hash-chain):
verify proves the local log was not edited; export gets the rows off the box and
into a system where they can be retained, correlated, and alerted on.

```
safespace audit export [--format jsonl|cef] [--since YYYY-MM-DD]
```

## Why stdout-only (and not "ship to a syslog host")

SafeSpace deliberately does **not** open a network socket to a syslog / SIEM
collector. Doing so would:

- add a new **egress destination** — every external host SafeSpace's own
  process connects to is tracked in one auditable registry
  (`policy/egress-destinations.ts`, v1.88); a configurable "send audit to
  `$HOST:$PORT`" knob is an SSRF-shaped surface we would rather not own; and
- buy nothing — every SIEM pipeline already ingests a file tail or a piped
  stream.

So the boundary is honest: **SafeSpace formats; your shipper transports.** The
operator owns the network hop, exactly as with the rest of the
[SOLE-EGRESS](SOLE-EGRESS.md) "Layer 2–4 are deployment-external" posture.

## Formats

### `--format jsonl` (default)

Each audit row, verbatim, as one JSON object per line — including the
`row_mac` chain field (see *Integrity*, below). JSON encoding escapes every
control character, so no field value can forge a second line.

```
safespace audit export | vector
safespace audit export --since 2026-06-01 > audit-june.jsonl
```

This is the right choice when your SIEM ingests JSON natively (most do) — it
preserves every field with no lossy transformation.

### `--format cef` (ArcSight Common Event Format)

One CEF record per row, for SIEMs that parse CEF natively (ArcSight and the many
collectors that speak it):

```
CEF:0|SafeSpace|safespace-mcp|<version>|<signatureId>|<name>|<severity>|<extension>
```

- **signatureId / name** — the row's discriminator: a tool-call row uses its
  `tool` name; an event row (e.g. `share_denied_by_policy`) uses its `event`.
- **severity** (0–10), three buckets:

  | Severity | Meaning |
  |---------:|---------|
  | **8** | an explicit policy denial / formula reject (`*_denied_by_policy`, or a `policy_decision` that denied/rejected) — page-worthy |
  | **6** | the tool call errored (non-policy) |
  | **3** | a normal call, or a forensic / aggregate event row (informational) |

- **extension** — a **vetted allowlist** of fields rendered as `key=value`
  pairs (never a blind dump of the row). Every value is CEF-escaped: `\` → `\\`,
  `|` → `\|` (header), `=` → `\=` (extension), and every C0 control byte
  (CR / LF / NUL / …) collapses to a space — so no field value can forge a
  second record, an extra header field, or an extra `key=value` pair.

```
safespace audit export --format cef | logger -t safespace -n siem.corp -P 514 -T
```

## `--since`

`--since YYYY-MM-DD` (or a full ISO 8601 timestamp) emits only rows on or after
that instant — use it to resume after a shipper restart without re-sending the
whole log. A row whose timestamp is missing or unparseable is **kept** (an audit
export errs toward over-inclusion, never silently dropping a forensic row).

## Integrity: ship the chain, verify out-of-band

The hash-chain `row_mac` survives the export (it is just another field), so your
SIEM stores the chain tip alongside every record. To detect tampering of the
**local** log — including tail-truncation, which the chain alone cannot catch —
keep running, on the box, on a schedule:

```
safespace audit verify        # exit 0 = intact, 1 = broken (names the first bad row)
```

…and record the printed **tip MAC** somewhere off the box (your SIEM is a fine
place). Comparing the live tip against the last-shipped tip closes the
truncation gap. See [AUDIT-CHAIN.md](AUDIT-CHAIN.md) for the full threat model.

## What leaves the box

The export carries exactly what `audit.jsonl` already holds — **no new
exposure**:

- **No** tokens, raw arguments, or message/response content (the audit log never
  recorded them).
- `account` is the **plaintext** account email (its forensic value is "which
  account made this call").
- Recipient / target identifiers are **HMAC-SHA256 hashes** (salted per-install),
  not plaintext.
- `row_mac` is an HMAC (hex) — safe to emit; it is not a secret.

Treat the exported stream with the same care as `audit.jsonl` itself: it is
metadata-only, but the account emails are real.
