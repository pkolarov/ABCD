# DDS Audit Event Schema (JSONL)

**Status:** Phase B.4 of
[docs/observability-plan.md](../observability-plan.md). Pins the on-wire
contract that `dds-cli audit tail --format jsonl` produces and that
forwarders (Vector, fluent-bit, rsyslog) ship to a SIEM.

**Closes:** Z-3 documentation half — operators have no DDS-specific
plumbing on the SIEM side beyond the field map below.

---

## 1. Transport

`dds-cli audit tail` polls
`GET /v1/audit/entries?since=<unix-seconds>[&action=<vocabulary>]`
on the local `dds-node`, decodes each row's `entry_cbor_b64` field
against the embedded `node_public_key`, and prints **one JSON object per
line, terminated by a single `\n`**, to stdout. Empty lines are not
emitted. The CLI never writes to stderr on the happy path — log
forwarders can treat any stderr noise as a hard failure.

The decoder runs locally inside `dds-cli`, so the verified `sig_ok` flag
on each line reflects the exact bytes the node signed, not just the
fields the JSON object exposes. A SIEM that trusts `sig_ok=true` is
trusting the local CLI's verification, not the network — a tampered
intermediary cannot lift the flag.

## 2. Top-level fields (per line)

| Field | Type | Always present | Description |
|---|---|---|---|
| `ts` | integer (Unix seconds, UTC) | ✅ | When the local node *signed* the entry — i.e. the moment the audited action committed. Not when the SIEM received it. |
| `action` | string (controlled vocabulary, see §3) | ✅ | The audited action. `*.rejected` suffix marks a refused operation. |
| `node_urn` | string (`urn:dds:node:<hex>`) | ✅ | URN of the signing node. Stable for the life of the node identity. |
| `chain_hash` | string (lowercase hex, 64 chars / SHA-256) | ✅ on `dds-node ≥ 2026-04-26` | The entry's own chain hash. The *next* entry on this node will carry this value in `prev_hash`. |
| `prev_hash` | string (lowercase hex, 64 chars) | ✅ on `dds-node ≥ 2026-04-26` | The previous entry's `chain_hash`. Empty string `""` for the genesis entry. |
| `sig_ok` | boolean | ✅ | Set by the local `dds-cli`: `true` iff the embedded Ed25519 signature verifies *and* the URN binding holds. **A SIEM rule that drops `sig_ok=false` lines silently is wrong** — the line still represents what the node served, and a `false` value is itself an attack indicator. Alert on it instead. |
| `reason` | string \| null | optional (omitted on success) | Free-form rationale for `*.rejected` and `apply.failed` actions. See §4 for the rejection vocabulary the node currently emits. |
| `token_cbor_b64` | string (base64 standard, with padding) | ✅ | The exact CBOR-encoded `Token` the audited action operated on. SIEMs that need finer-grained search (per-JTI, per-issuer) decode this client-side; the audit row itself does **not** flatten token internals. |

`dds-cli` emits other fields under future minor versions only as
**additive** keys — existing keys are not removed, renamed, or retyped
without a major-version bump of the JSONL schema. Forwarders should
configure their parsers to ignore unknown keys.

### 2.1 Wire-level shape (illustrative)

```json
{"ts":1745625600,"action":"attest","reason":null,"node_urn":"urn:dds:node:7f3a…","chain_hash":"5b2c…","prev_hash":"a017…","sig_ok":true,"token_cbor_b64":"o2dwYXls…"}
{"ts":1745625612,"action":"attest.rejected","reason":"trust-graph-rejected: issuer is revoked","node_urn":"urn:dds:node:7f3a…","chain_hash":"e801…","prev_hash":"5b2c…","sig_ok":true,"token_cbor_b64":"o2dwYXls…"}
{"ts":1745625640,"action":"apply.failed","reason":"agent: registry write denied","node_urn":"urn:dds:node:7f3a…","chain_hash":"f9ab…","prev_hash":"e801…","sig_ok":true,"token_cbor_b64":"o2dwYXls…"}
```

The `…` truncations above are illustrative; real values are full hex /
base64 with no ellipsis.

## 3. Action vocabulary

The `action` field is a controlled vocabulary. Successful actions and
their rejected counterparts share a stem; `*.rejected` always means "the
node refused the action and did not change state, but logged the
attempt".

| `action` | Severity hint | Source path | Notes |
|---|---|---|---|
| `attest` | informational | gossip ingest, `node.rs::ingest_operation` | Attestation accepted into the trust graph. |
| `attest.rejected` | warning | same | See §4 for rejection reasons. |
| `vouch` | informational | `node.rs::ingest_operation` | Vouch accepted. |
| `vouch.rejected` | warning | same | |
| `revoke` | **notice** | `node.rs::ingest_revocation` | A revocation was applied. Operators usually want a non-default alert on bursts. |
| `revoke.rejected` | warning | same | |
| `burn` | **notice** | `node.rs::ingest_burn` | An identity was burned (terminal revocation). Same alerting posture as `revoke`. |
| `burn.rejected` | warning | same | |
| `enroll.user` | informational | `service.rs::enroll_user` | New user enrollment ceremony completed. |
| `enroll.device` | informational | `service.rs::enroll_device` | New device enrolled. |
| `admin.bootstrap` | **notice** | `service.rs::admin_setup` | Bootstrap admin established. Only emitted once per domain in steady state. A second occurrence is suspicious. |
| `admin.vouch` | informational | `service.rs::admin_vouch` | An admin vouched another principal. |
| `apply.applied` | informational | `service.rs::record_applied` | Agent reported a successful apply. `Skipped` reports carry `reason="skipped"`. |
| `apply.failed` | warning | same | Agent reported a failed apply. `reason` carries the agent's error string. |

Reserved (not yet emitted by `dds-node`, will appear in the same JSONL
shape when they land):

- `policy.applied` / `policy.failed` / `software.applied` /
  `software.failed` — finer-grained applier outcomes once
  `AppliedReport` grows a `kind` discriminator on the wire (today it
  does not, so v1 collapses these into the `apply.*` family).
- `admission.cert.issued` / `admission.cert.revoked` — admission cert
  lifecycle.
- `secret.released` — `SecretReleaseDocument` consumption (v2).

A SIEM rule that filters on `action` should treat unknown values as
informational (forward, do not drop) so a forward-compatible node can
introduce new actions without orphaning the SIEM pipeline.

## 4. Rejection-reason vocabulary

For `*.rejected` and `apply.failed`, `reason` is currently one of the
following stems. Free-form suffix text (after the `:`) is operator-
readable but **not** a stable contract — alert rules should match the
stem with a prefix predicate, not equality.

| Stem | Where emitted | What it means |
|---|---|---|
| `legacy-v1-refused` | gossip ingest (op / revocation) | Token signed under the retired v1 envelope; the node rejects on principle. |
| `validation-failed: <e>` | gossip ingest | `Token::validate` returned an error (signature, structural, expiry). |
| `publisher-capability-missing` | attestation ingest | Issuer lacked the `dds:policy-publisher-*` / `dds:software-publisher` capability. |
| `trust-graph-rejected: <e>` | gossip ingest | Trust-graph layer refused (e.g. revoked issuer, cycle). |
| `iat-outside-replay-window` | revocation ingest | Revocation `iat` outside the 7-day replay tolerance. |
| `skipped` | `apply.applied` only | Agent reported a no-op (target already in desired state). |

For `apply.failed`, `reason` is the agent's verbatim error string —
non-stable, useful for incident triage but not for alert matching.

## 5. Severity mapping (suggested)

For SIEMs that require a numeric severity (CEF / syslog) and operators
that have not built their own mapping yet, a sensible default is:

| `action` pattern | CEF severity (0-10) | Syslog severity (RFC 5424) |
|---|---|---|
| `*.rejected` | 4 (medium) | warning (4) |
| `apply.failed` | 4 (medium) | warning (4) |
| `revoke`, `burn`, `admin.bootstrap` | 3 (low-medium) | notice (5) |
| everything else | 2 (low) | informational (6) |
| any line with `sig_ok=false` | 8 (high) | alert (1) — override the action-based row |

Operators are expected to override these per their own runbook; the
mapping above is a starting point, not a contract.

## 6. CEF / syslog field maps (when implemented)

Phase B.1 ships JSONL only. CEF and syslog formats are tracked as B.1
follow-ups; when they land, they will use the field map below. Until
then, forwarders that need CEF / syslog should run a Vector / fluent-bit
transform (see [vector.toml](vector.toml) / [fluent-bit.conf](fluent-bit.conf)).

### CEF (ArcSight / Splunk)

```
CEF:0|Anthropic|DDS|<dds-node version>|<action>|<action>|<severity>|
  rt=<ts*1000> dvc=<node_urn> cs1Label=chainHash cs1=<chain_hash>
  cs2Label=prevHash cs2=<prev_hash> cs3Label=reason cs3=<reason>
  cs4Label=sigOk cs4=<sig_ok>
```

Bytes inside CEF extension values are escaped per the CEF
specification (`\\`, `\=`, `\|`, `\n`).

### Syslog (RFC 5424 STRUCTURED-DATA)

```
<priority>1 <ts-iso8601> <hostname> dds-cli - audit
[dds@32473 action="<action>" node_urn="<node_urn>"
 chain_hash="<chain_hash>" prev_hash="<prev_hash>"
 reason="<reason>" sig_ok="<sig_ok>"]
```

`<hostname>` is the host where `dds-cli audit tail` is running, not the
signing `node_urn` (the latter is in the structured data).

## 7. Forwarder integration

See:

- [vector.toml](vector.toml) — Vector reference config (source = `exec`
  running `dds-cli audit tail --format jsonl`, sinks = Loki / Splunk
  HEC / Elasticsearch / S3).
- [fluent-bit.conf](fluent-bit.conf) — fluent-bit reference config
  (same shape).

Both configs assume `dds-cli audit tail --follow-interval 5` so the
forwarder restarts the tail process if it exits. Vector / fluent-bit
own restart, backpressure, batching, and retry — DDS does not.

## 8. Verification posture

A SIEM that wants stronger guarantees than line-by-line `sig_ok` should
run `dds-cli audit verify` periodically against each node and compare
the chain head hash to what it received. A divergence between
`sig_ok=true` lines accumulated by the SIEM and the chain head reported
by `dds-cli audit verify` indicates either:

- a node-local audit-log truncation (chain head moved backwards), or
- a SIEM-side delivery gap (chain head moved forwards faster than the
  SIEM ingested).

Either case is alertable. The Alertmanager rule `DdsAuditChainStalled`
in [alerts/dds.rules.yml](alerts/dds.rules.yml) (Phase E) covers the
node-local half; the SIEM-side half is a customer-side rule against
their own ingestion lag.

## 9. Versioning

This schema is currently **v1**. Additive field changes (new keys, new
action values) are minor; removing a key, renaming a key, or changing a
key's type bumps the major version. The version is implicit — there is
no `version` field on each line — and tracked here.

Forwarder configs in this directory are pinned to v1.
