# DDS Observability Plan — Audit, Metrics, Alerts, SIEM Export

**Status:** Plan — open for implementation
**Date:** 2026-04-26
**Closes (when implemented):** Z-3 from
[Claude_sec_review.md](../Claude_sec_review.md) "2026-04-26 Zero-Trust
Principles Audit"; the P2 Monitoring/SIEM row in
[AD-drop-in-replacement-roadmap.md](AD-drop-in-replacement-roadmap.md)
§4.9 (line 194 — *"JSON/syslog/OpenTelemetry export; health checks;
audit query tooling"*).
**Owner:** TBD.

---

## 1. Goals

1. Every state-mutating action on a `dds-node` produces a signed,
   chain-hashed audit entry — closes Z-3.
2. Operators can ship the audit stream to any SIEM via standard log
   forwarders (Vector / fluent-bit / rsyslog) with no DDS-specific
   plumbing on the SIEM side.
3. Operators can build a fleet-wide operational dashboard from
   `dds-node /metrics` using off-the-shelf Prometheus + Grafana — no
   custom UI written or shipped.
4. Operators can wire alerts off the same `/metrics` using
   off-the-shelf Alertmanager rules.
5. Ad-hoc query, verification, and one-shot export work entirely
   through `dds-cli` — no server changes needed for one-off ops.

## 2. Non-goals (deferred)

- **Custom admin web UI / dashboard.** Use Grafana for ops, the CLI
  for ad-hoc admin. A bespoke web console is a separate plan that
  should not block monitoring.
- **OpenTelemetry traces / spans.** A Prometheus pull endpoint and a
  structured event log cover dashboards, alerts, and SIEM. OTel
  traces are a follow-up if request-flow debugging becomes a recurring
  pain point.
- **Customer-tenant multi-domain rollups.** Single-domain only for v1.
- **Long-term log retention inside DDS.** The audit log keeps a
  bounded chain on each node (existing pruning logic); long-term
  retention is the SIEM's job.

## 3. Architecture

```
                         ┌──────────────────────────────────┐
                         │            Operator              │
                         └──────┬─────────────┬─────────────┘
                                │             │
                       Grafana / Alertmgr   dds-cli (ad-hoc query,
                                │             SIEM export, verify)
                                │             │
              Prometheus scrape │             │ UDS / pipe / loopback
                                ▼             ▼
                  ┌────────────────────────────────────────┐
                  │              dds-node                  │
                  │  ┌─────────────┐    ┌────────────────┐ │
                  │  │ /metrics    │    │ HTTP API:      │ │
                  │  │ (prom expo) │    │ /v1/audit/...  │ │
                  │  │ /healthz    │    │ /v1/...        │ │
                  │  └─────▲───────┘    └────────▲───────┘ │
                  │        │                     │         │
                  │        │ metrics::counter!   │ existing│
                  │        │ metrics::histogram! │  routes │
                  │        │                     │         │
                  │  ┌─────┴─────────────────────┴───────┐ │
                  │  │   ingest paths: gossip / sync /  │ │
                  │  │   service::ingest_*              │ │
                  │  │      └─ emit_local_audit (Z-3)   │ │
                  │  └──────────────────────────────────┘ │
                  └────────────────────────────────────────┘
```

Two pipes out of `dds-node`:

- **Pull-based metrics** at `GET /metrics` for Prometheus → Grafana →
  Alertmanager.
- **Append-only audit log** in redb, signed + chain-hashed; tailed by
  `dds-cli audit tail` and forwarded to SIEM.

## 4. Phases

### Phase A — Wire audit emission (closes Z-3)

The audit chain mechanism (`AuditLogEntry`, signed, chain-hashed,
append-only enforced atomically in `RedbBackend`) is correct.
`DdsNode::emit_local_audit` is the production hook. **Zero
production call sites today.** Phase A wires the call sites.

**Action vocabulary** (the `AuditLogEntry::action` field — extend
the existing free-form string into a fixed set):

| `action` | When emitted | Site |
|---|---|---|
| `attest` | Attestation token accepted into trust graph | `service.rs::ingest_attestation` (success branch, after `add_token`) |
| `vouch` | Vouch token accepted | `service.rs::ingest_vouch` |
| `revoke` | Revocation token accepted | `service.rs::ingest_revocation` |
| `burn` | Burn token accepted | `service.rs::ingest_burn` |
| `enroll.user` | User enrollment ceremony completed | `service.rs::complete_enrollment` user branch |
| `enroll.device` | Device enrollment completed | same, device branch |
| `admin.bootstrap` | Bootstrap admin established | `service.rs::admin_setup` |
| `admin.vouch` | Admin vouches another principal | `service.rs::admin_vouch` |
| `admission.cert.issued` | Admission cert produced for a peer | `service.rs::issue_admission_cert` |
| `admission.cert.revoked` | Admission revocation accepted | `admission_revocation_store::merge` |
| `policy.applied` | Agent reports a policy successfully applied (via `POST /v1/.../applied`) | `http.rs::record_applied` |
| `policy.failed` | Agent reports a failed apply | same path, failure branch |
| `software.applied` | Agent reports software install success | same path |
| `software.failed` | Agent reports failure | same path |
| `secret.released` (deferred) | `SecretReleaseDocument` consumed | reserved for v2 |

**Failure paths must also emit.** A rejected-by-graph token still
emits an audit entry with action `attest.rejected` /
`vouch.rejected` etc., and the rejection reason in a sidecar field
(see Phase A.2).

**A.1 — Simple wiring (no schema change).** Each ingest path on
success calls `emit_local_audit(action, token_bytes, now)`. Action
strings come from the table above. The existing `AuditLogEntry`
struct accommodates this with no breaking change.

**A.2 — Reason field for rejections** *(small schema change)*. Add
`#[serde(default)] pub reason: Option<String>` to `AuditLogEntry`.
Backward-compatible (older entries deserialize with `reason = None`).
This lets the SIEM tell `attest` from `attest.rejected → revoked-issuer`
without parsing the embedded token. Update `AuditLogSignedFields` to
cover the new field so it stays inside the chain hash.

**A.3 — Tests.** One regression test per action confirming the entry
lands and the chain head advances. One test per rejection path
confirming `reason` is populated.

**Acceptance:** `dds-cli audit entries` returns non-empty after a
freshly bootstrapped domain has run a single attestation flow.

### Phase B — SIEM export

**B.1 — `dds-cli audit tail`.** Long-running follow command:

```bash
dds-cli audit tail \
    --since 2026-04-26T00:00:00Z \
    --format jsonl|cef|syslog \
    --output -          # stdout, or path
```

Implemented as a polling loop over `GET /v1/audit/entries?since=N`.
Output formats:

- `jsonl` (canonical) — one JSON object per line; key set
  `{ts, action, reason, subject_urn, issuer_urn, jti, node_urn,
    chain_hash, prev_hash, sig_ok}`.
- `cef` — ArcSight Common Event Format, RFC-tolerant. Header
  `CEF:0|DDS|dds-node|<version>|<action>|<action>|<severity>|<extensions>`.
- `syslog` — RFC 5424 with the JSON object as the structured-data
  payload.

The decoder runs locally, so the JTI / URNs in the output come from
the *verified* token, not a copy of the line.

**B.2 — `dds-cli audit verify`.** Walks the chain end-to-end. For
each entry: re-derives `chain_hash`, verifies signature against
`node_public_key`, checks `node_urn`-to-key binding. Reports the
first break with `(index, expected, actual)`.

**B.3 — Forwarder integration.** Ship two reference configs:

- `docs/observability/vector.toml` — Vector source =
  `exec` running `dds-cli audit tail --format jsonl`, sink = Loki /
  Splunk HEC / Elastic / S3.
- `docs/observability/fluent-bit.conf` — same shape, fluent-bit
  parsers.

Vector / fluent-bit handle restart, backpressure, batching,
retry — DDS does not.

**B.4 — Schema doc.** `docs/observability/audit-event-schema.md`
pinning the JSONL key set, action vocabulary, severity mapping,
and CEF/syslog field maps. SIEM teams need this without reading
Rust.

### Phase C — Prometheus exposition (`/metrics`)

**C.1 — Crate.** Add `metrics = "0.23"` and
`metrics-exporter-prometheus = "0.15"` to `dds-node/Cargo.toml`.
`metrics-util` for histograms. The `metrics` crate is light — no
runtime cost when the exporter isn't installed.

**C.2 — Endpoint.** New axum route `GET /metrics` on a
**separate listener** bound to a configurable address
(`metrics_addr` in `node.toml`, default `127.0.0.1:9495`). Separate
from the API listener so:
- ops can scope Prometheus scrape ACLs without touching the API
  surface;
- exposing it on `0.0.0.0` for fleet scrape doesn't open the API.

No auth on `/metrics` — Prometheus is expected to be on a trusted
scrape network. If exposed off-host, operators put a TLS sidecar in
front (same posture as kube-state-metrics).

**C.3 — Metric catalog.** Metrics are named `dds_<area>_<measure>`,
labels lower-snake. Counters reset on restart (Prometheus convention
— compute rates over them).

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `dds_build_info` | gauge | `version, git_sha, rust_version` | Static fingerprint, always 1 |
| `dds_uptime_seconds` | gauge | — | Process uptime |
| **Network** | | | |
| `dds_peers_admitted` | gauge | — | Currently admitted peer count |
| `dds_peers_connected` | gauge | — | libp2p-connected peers (admitted + un-admitted) |
| `dds_admission_handshakes_total` | counter | `result=ok|fail|revoked` | H-12 outcomes |
| `dds_gossip_messages_total` | counter | `topic, direction=in|out, kind` | Gossipsub volume |
| `dds_gossip_messages_dropped_total` | counter | `reason=unadmitted|invalid_token|duplicate|backpressure` | Why we threw a message away |
| `dds_sync_pulls_total` | counter | `result=ok|fail` | Anti-entropy pull count |
| `dds_sync_lag_seconds` | histogram | — | Time from peer's op timestamp to local apply |
| `dds_sync_payloads_rejected_total` | counter | `reason=signature|graph|duplicate_jti|window` | B-1-style guard hits |
| **Trust graph** | | | |
| `dds_attestations_total` | gauge | `kind=user|device|service` | Active count |
| `dds_attestations_revoked_total` | counter | — | Revocations applied since boot |
| `dds_burned_identities_total` | gauge | — | Total burned URNs |
| `dds_purpose_lookups_total` | counter | `result=ok|denied|not_found` | `has_purpose` outcomes |
| **FIDO2 / sessions** | | | |
| `dds_fido2_assertions_total` | counter | `result=ok|signature|rp_id|up|uv|sign_count` | Assertion outcomes |
| `dds_fido2_attestation_verify_total` | counter | `result, fmt=packed|none|tpm` | Enrollment-time verify |
| `dds_sessions_issued_total` | counter | `via=fido2|legacy` | Session minting |
| `dds_challenges_outstanding` | gauge | — | Live challenges (B-5 cap reference) |
| **Audit** | | | |
| `dds_audit_entries_total` | counter | `action` | Per-action emission rate |
| `dds_audit_chain_length` | gauge | — | Local chain entry count |
| `dds_audit_chain_head_age_seconds` | gauge | — | `now - last_entry.timestamp` (alert if > N) |
| **Storage** | | | |
| `dds_store_bytes` | gauge | `table=tokens|ops|audit|...` | redb table sizes |
| `dds_store_writes_total` | counter | `result=ok|conflict|fail` | redb txn outcomes |
| **HTTP API** | | | |
| `dds_http_requests_total` | counter | `route, method, status` | Route-level traffic |
| `dds_http_request_duration_seconds` | histogram | `route, method` | Latency |
| `dds_http_caller_identity_total` | counter | `kind=anonymous|uds|pipe|admin` | Who's calling — surfaces accidental loopback-TCP regressions |
| **Process** | | | |
| `dds_memory_resident_bytes` | gauge | — | RSS (procfs / mach) |
| `dds_thread_count` | gauge | — | OS thread count |

**C.4 — Wiring.** Each call site uses `metrics::counter!`,
`metrics::gauge!`, `metrics::histogram!` macros. A dedicated
`dds-node::telemetry` module owns metric names + describes them at
startup so operators get types/help text from
`/metrics`. No instrumentation in `dds-core` (`no_std` constraint).

**C.5 — Cardinality budget.** Every label set is bounded: no
free-form URNs, JTIs, or paths land in labels. Cardinality estimate
≤ 200 series per node — fits comfortably in a small Prometheus.

### Phase D — Health endpoints

**D.1 — `GET /healthz`.** Liveness. 200 if process is up. No
dependency checks. New route on the API listener.

**D.2 — `GET /readyz`.** Readiness. 200 only if:
- node identity loaded;
- domain pubkey loaded and admission cert verifies;
- redb writable;
- at least one inbound or outbound peer connection ever observed
  *or* `peers.bootstrap` is empty (lone-node deployment).

`/v1/node/info` already exists — keep it for content discovery, add
`/healthz` and `/readyz` as the orchestrator-friendly endpoints.

### Phase E — Reference dashboards & alert rules

Ship as files in the repo so operators can `kubectl apply` / Grafana
import without DDS-specific tooling.

- `docs/observability/grafana/dds-overview.json` — fleet view: peer
  count, admission failures, gossip rates, sync lag, audit emission
  rate, chain head age. One panel per area in the metric catalog.
- `docs/observability/grafana/dds-trust-graph.json` — attestations,
  vouches, revocations, FIDO2 verify outcomes.
- `docs/observability/alerts/dds.rules.yml` — Alertmanager rules:
  - `DdsAuditChainStalled` — `dds_audit_chain_head_age_seconds > 600`
    on a node that has accepted any token in the same window
    (catches Z-3 regressions).
  - `DdsAdmissionFailureSpike` —
    `rate(dds_admission_handshakes_total{result="fail"}[5m]) > 0.1`.
  - `DdsSyncLagHigh` —
    `histogram_quantile(0.99, ...dds_sync_lag_seconds...) > 60`.
  - `DdsLoopbackTcpAdminUsed` —
    `rate(dds_http_caller_identity_total{kind="anonymous"}[5m]) > 0`
    on a host where `trust_loopback_tcp_admin=false` is the policy
    (regression alarm for H-7 cutover).
  - `DdsFido2AssertionFailureSpike` — flags brute-force / replay.
  - `DdsRevocationsSurge` — operator awareness during incidents.
  - `DdsStoreWriteFailures` —
    `rate(dds_store_writes_total{result!="ok"}[5m]) > 0`.

### Phase F — CLI surface for ad-hoc ops

Subcommands added to `dds-cli`:

| Command | Purpose |
|---|---|
| `dds-cli stats` | Single-shot snapshot of the most-asked metrics — peer count, attestation count, audit chain length + head age, last admission failure, store bytes. Pretty-prints; `--format json` for scripting. |
| `dds-cli audit tail` | (Phase B.1) |
| `dds-cli audit verify` | (Phase B.2) |
| `dds-cli audit export` | One-shot range dump (JSONL/CEF/syslog) for offline forensics. |
| `dds-cli health` | Calls `/readyz` + summarizes. |

## 5. Tradeoffs

- **No dashboard out-of-the-box for non-Prometheus shops.**
  Acknowledged. The Grafana dashboard JSON + Alertmanager rules
  shorten the path, but customers without an existing Prom/Grafana
  stack get a worse first-run experience than they would from a
  bundled web console. The fix is a thin admin web UI as a separate
  plan; it should not block this work.
- **`/metrics` unauth-on-loopback default.** Same posture as every
  Prometheus exporter ever shipped. Operators who expose it off-host
  carry the standard responsibility (ACL, mTLS sidecar). Documented
  in the metric-endpoint section of `DDS-Admin-Guide.md` (to add).
- **Audit chain on a single node is the source of truth for that
  node.** Cross-node consistency comes from gossip; a node that's
  been offline returns audit gaps for the offline window. The SIEM
  is responsible for fleet rollup. This is the same model as Linux
  auditd in a fleet — operators are used to it.
- **`metrics` crate adds a process-wide registry.** No `no_std`
  break — the registry only lives in `dds-node`, and `dds-core` /
  `dds-domain` continue to compile `no_std`.

## 6. Out of scope (explicit follow-ups)

- **OpenTelemetry trace export.** The `tracing` crate already gives
  span coverage; an OTel exporter is one extra crate when needed.
  Defer until somebody is debugging cross-node request flow.
- **Audit log gossip / quorum / witness.** The current threat model
  treats the local audit chain as authoritative; a malicious node
  can suppress its own entries. A future phase could gossip audit
  entries to N peers as a witness layer; deferred.
- **Hardware-bound `dds-cli audit verify` keys.** `verify` checks
  signatures against the embedded `node_public_key`. If Z-2 ships,
  the verifier could additionally require the key to match an
  attested per-node hardware-bound key. Deferred to land alongside
  Z-2.

## 7. Definition of done

- Fresh single-node bootstrap → run one attestation, one vouch, one
  revocation, one FIDO2 enrollment → `dds-cli audit verify` reports
  six entries, chain intact.
- `curl http://127.0.0.1:9495/metrics` returns ≥ 30 metric families
  matching the catalog; `dds_audit_entries_total{action="attest"}`
  ticks during the previous step.
- Vector reference config tails the audit log into a local Loki
  container and the entries appear in Grafana within 10 s.
- The two reference Grafana dashboards import cleanly and render
  non-empty panels against the local node.
- `DdsAuditChainStalled` Alertmanager rule fires when audit
  emission is artificially disabled (test mode).
- Cross-link from STATUS.md, the AD-replacement-roadmap §4.9
  Monitoring/SIEM row, and the README docs table to this plan.

## 8. Cross-references

- [Claude_sec_review.md](../Claude_sec_review.md) Z-3 — closed by
  Phase A.
- [docs/AD-drop-in-replacement-roadmap.md](AD-drop-in-replacement-roadmap.md)
  §4.9 line 194 — implementation tracked here.
- [docs/threat-model-review.md](threat-model-review.md) §8 item 16
  — closed by Phase A; item 8 (data-dir DACL) is a sibling concern,
  closed in 2026-04-26 install-time pass.
- [docs/hardware-bound-admission-plan.md](hardware-bound-admission-plan.md)
  — Z-2; the audit-verify HW-binding follow-up depends on it.
