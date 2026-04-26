# DDS Observability Plan — Audit, Metrics, Alerts, SIEM Export

**Status:** Phase A landed 2026-04-26 follow-up #17 (closes Z-3);
Phase D (`/healthz` + `/readyz`) landed 2026-04-26 follow-up #18;
Phase B sub-tasks B.1 (`dds-cli audit tail` JSONL stream) and B.2
(`dds-cli audit verify` chain walk) landed 2026-04-26 follow-up #19;
Phase B sub-tasks B.3 (Vector / fluent-bit reference configs) and
B.4 (`audit-event-schema.md`) landed 2026-04-26 follow-up #20 — Phase
B is now complete. Phase F (`dds-cli stats`, `dds-cli health`,
`dds-cli audit export`) landed 2026-04-26 follow-up #21. Phase C
audit-metrics subset (`dds_build_info`, `dds_uptime_seconds`,
`dds_audit_entries_total{action}`, `dds_audit_chain_length`,
`dds_audit_chain_head_age_seconds` — opt-in via `metrics_addr`)
landed 2026-04-26 follow-up #22. Phase E **audit-tier subset**
(reference Grafana dashboards + Alertmanager rules keyed off the
metrics shipped in #22, plus commented-out reference rules for the
not-yet-shipped catalog) landed 2026-04-26 follow-up #23; the rest
of the C catalog (network / FIDO2 / store / HTTP / process) plus
the Phase E rules/panels that depend on those metrics remain open.
**Date:** 2026-04-26
**Closes (when implemented):** Z-3 from
[Claude_sec_review.md](../Claude_sec_review.md) "2026-04-26 Zero-Trust
Principles Audit" — **closed by Phase A**; the P2 Monitoring/SIEM
row in
[AD-drop-in-replacement-roadmap.md](AD-drop-in-replacement-roadmap.md)
§4.9 (line 194 — *"JSON/syslog/OpenTelemetry export; health checks;
audit query tooling"*) — health-checks half closed by Phase D
(2026-04-26 follow-up #18); SIEM export closed by Phase B
(follow-ups #19/#20); audit query tooling closed by Phase F
(follow-up #21).
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

### Phase A — Wire audit emission (closes Z-3) ✅

**Status: landed 2026-04-26 follow-up #17.** The audit chain
mechanism (`AuditLogEntry`, signed, chain-hashed, append-only
enforced atomically in `RedbBackend`) was already correct. The
production hook is now `LocalService::emit_local_audit` (HTTP /
admin paths) and `DdsNode::emit_audit_from_ingest` (gossip paths);
both delegate to the existing `AuditLogEntry::sign_ed25519_chained_with_reason`
helper added in Phase A.2. See "Acceptance" below for verified
behaviour. The wiring matrix shipped looks like this:

**Action vocabulary** (the `AuditLogEntry::action` field — extend
the existing free-form string into a fixed set):

| `action` | When emitted | Site | Status |
|---|---|---|---|
| `attest` | Attestation token accepted into trust graph | `node.rs::ingest_operation` (success branch, after `add_token`) | ✅ shipped 2026-04-26 |
| `attest.rejected` | Attestation refused (bad sig, missing publisher capability, replay window, etc.) | same path, rejection branches | ✅ shipped 2026-04-26 |
| `vouch` | Vouch token accepted | `node.rs::ingest_operation` (Vouch kind) | ✅ shipped 2026-04-26 |
| `vouch.rejected` | Vouch refused | same path, rejection branches | ✅ shipped 2026-04-26 |
| `revoke` | Revocation token accepted | `node.rs::ingest_revocation` | ✅ shipped 2026-04-26 |
| `revoke.rejected` | Revocation refused | same path, rejection branches | ✅ shipped 2026-04-26 |
| `burn` | Burn token accepted | `node.rs::ingest_burn` | ✅ shipped 2026-04-26 |
| `burn.rejected` | Burn refused | same path, rejection branches | ✅ shipped 2026-04-26 |
| `enroll.user` | User enrollment ceremony completed | `service.rs::enroll_user` | ✅ shipped 2026-04-26 |
| `enroll.device` | Device enrollment completed | `service.rs::enroll_device` | ✅ shipped 2026-04-26 |
| `admin.bootstrap` | Bootstrap admin established | `service.rs::admin_setup` | ✅ shipped 2026-04-26 |
| `admin.vouch` | Admin vouches another principal | `service.rs::admin_vouch` | ✅ shipped 2026-04-26 |
| `apply.applied` | Agent reports a successful or skipped apply (via `POST /v1/.../applied`); `Skipped` carries `reason="skipped"` | `service.rs::record_applied` | ✅ shipped 2026-04-26 |
| `apply.failed` | Agent reports a failed apply; `reason` carries the agent's error string | same path, failure branch | ✅ shipped 2026-04-26 |
| `policy.applied` / `policy.failed` / `software.applied` / `software.failed` | Finer-grained applier outcomes | reserved for when `AppliedReport` grows a `kind` discriminator on the wire (today the report does not distinguish policy vs. software, so v1 collapses them into the `apply.*` family) | 🔲 deferred |
| `admission.cert.issued` | Admission cert produced for a peer | `service.rs::issue_admission_cert` | 🔲 deferred (cert issuance is a domain-level operation today) |
| `admission.cert.revoked` | Admission revocation accepted | `admission_revocation_store::merge` | 🔲 deferred |
| `secret.released` (deferred) | `SecretReleaseDocument` consumed | reserved for v2 | 🔲 deferred |

**Failure paths must also emit.** A rejected-by-graph token still
emits an audit entry with action `attest.rejected` /
`vouch.rejected` etc., and the rejection reason in a sidecar field
(see Phase A.2).

**A.1 — Simple wiring (no schema change). ✅** Each ingest path on
success calls `emit_local_audit(action, token_bytes, reason=None)`.
LocalService got a public `emit_local_audit` helper; DdsNode got a
private `emit_audit_from_ingest` plus an `Option<Identity>` field
populated from a second `identity_store::load_or_create` call in
`main.rs` (the L-1 "single Ed25519 copy" invariant precludes
cloning the existing identity, so the swarm event loop opens the
same on-disk identity store independently). Trust-graph write
locks are dropped before the audit emit fires.

**A.2 — Reason field for rejections (small schema change). ✅**
`AuditLogEntry` gained `pub reason: Option<String>` with
`#[serde(default, skip_serializing_if = "Option::is_none")]`.
Backward-compatible: missing field on older entries deserialises to
`None` and existing chains keep verifying. `AuditLogSignedFields`
gained the matching field so the reason stays inside the
chain-hash. Two new round-trip tests in
[dds-core/src/audit.rs](../dds-core/src/audit.rs)
(`audit_entry_reason_is_signed`, `audit_entry_no_reason_roundtrips`)
prove tampering with the reason invalidates verify and that an
absent field round-trips through CBOR cleanly.

**A.3 — Tests. ✅** Seven new audit-emission regression tests in
[dds-node/src/service.rs](../dds-node/src/service.rs)
(`audit_enroll_user_advances_chain`,
`audit_enroll_device_advances_chain`,
`audit_apply_applied_advances_chain_with_no_reason`,
`audit_apply_failed_carries_error_as_reason`,
`audit_apply_skipped_marks_reason`,
`audit_chain_links_three_actions_in_order`,
`audit_rejection_vocabulary_signs_reason`) confirm each action's
chain advance, the per-entry signature verify, and the rejection
vocabulary consumed by the gossip-ingest paths. The two new
audit-schema tests in dds-core lock the on-wire contract.

**Acceptance:** `dds-cli audit entries` returns non-empty after a
freshly bootstrapped domain has run a single attestation flow.
Verified locally: a `setup() + enroll_user + enroll_device +
record_applied` sequence produces three chain-linked entries with
`prev_hash` matching each predecessor's `chain_hash()`, every entry
verifies, and the chain head advances after every emission.

### Phase B — SIEM export

**B.1 — `dds-cli audit tail`. ✅** Long-running follow command:

```bash
dds-cli audit tail \
    --since <unix-seconds> \
    --format jsonl \
    [--follow-interval <seconds>] \
    [--action attest|attest.rejected|...]
```

Implemented as a polling loop over `GET /v1/audit/entries?since=N`
in [dds-cli/src/main.rs](../dds-cli/src/main.rs) `run_audit_tail`.
Output format shipped: `jsonl` — one JSON object per line, key set
`{ts, action, reason, node_urn, chain_hash, prev_hash, sig_ok,
token_cbor_b64}`. `sig_ok` is computed locally by CBOR-decoding
`entry_cbor_b64` (Phase B.2 wire field) and running
`AuditLogEntry::verify()` so a SIEM forwarder cannot be tricked
into trusting a tampered line.

`cef` and `syslog` formats are tracked as B.1 follow-ups — the JSONL
canonical form is enough for Vector / fluent-bit / rsyslog
forwarders, which all consume `--source exec` JSONL natively. The
CLI errors with a clear message on any unknown format so an
operator on an old build does not silently emit nothing.

The decoder runs locally, so the JTI / URNs in the output come from
the *verified* token, not a copy of the line.

**B.2 — `dds-cli audit verify`. ✅** Walks the chain end-to-end. For
each entry: re-derives `chain_hash`, verifies signature against
`node_public_key` (which carries the URN-binding check), and checks
that `prev_hash` matches the previous entry's `chain_hash`. Reports
the first break with the offending index + entry action and exits 1.

Implemented in [dds-cli/src/main.rs](../dds-cli/src/main.rs)
`run_audit_verify`. The `/v1/audit/entries` endpoint now returns a
new field `entry_cbor_b64` per row — the full CBOR-encoded
`AuditLogEntry` (signed fields + signature) — so the verifier
reconstructs the exact bytes the node signed without re-deriving
them from the structured fields. New per-row fields
`chain_hash_hex`, `prev_hash_hex`, and `reason` let SIEM consumers
chain-link without CBOR decoding when they only want the structured
shape.

**B.3 — Forwarder integration. ✅** Two reference configs landed:

- [docs/observability/vector.toml](observability/vector.toml) —
  Vector source = `exec` running
  `dds-cli audit tail --format jsonl --follow-interval 5`, with
  `respawn_on_exit=true` for hard exits and an inline `remap`
  transform that promotes the node-signed `ts` to the canonical
  Vector timestamp and stamps a default severity per
  `audit-event-schema.md` §5. Four sink shapes documented (Loki
  default, Splunk HEC, Elasticsearch with daily index pattern, S3
  archival).
- [docs/observability/fluent-bit.conf](observability/fluent-bit.conf)
  + [docs/observability/parsers.conf](observability/parsers.conf) —
  same shape on fluent-bit 2.2+. `[FILTER] modify` blocks encode
  the action → severity mapping; a one-line Lua filter promotes
  `ts` to the fluent-bit native timestamp; `sig_ok=false` lines
  are escalated to `alert` rather than dropped (per
  `audit-event-schema.md` §2). Loki / Splunk / Elasticsearch /
  rsyslog outputs documented.

Vector / fluent-bit handle restart, backpressure, batching, and
retry — DDS does not. `dds-cli` runs the Ed25519 verify *before*
emitting each line, so neither forwarder is in a position to be
tricked into shipping a line the node did not actually sign.

**B.4 — Schema doc. ✅** Landed at
[docs/observability/audit-event-schema.md](observability/audit-event-schema.md).
Pins the JSONL field set (top-level `ts` / `action` / `node_urn` /
`chain_hash` / `prev_hash` / `sig_ok` / `reason` / `token_cbor_b64`),
the action vocabulary (with explicit reserved/deferred actions),
the rejection-reason vocabulary, a default severity map for SIEMs
that need one, and CEF + RFC 5424 syslog field templates for the
B.1 follow-up formats. SIEM teams can integrate without reading
Rust.

### Phase C — Prometheus exposition (`/metrics`)

**Status: audit subset landed 2026-04-26 follow-up #22; HTTP-tier
caller-identity counter landed in follow-up #24; rest of the catalog
(network / FIDO2 / store / process, plus the HTTP request /
duration families) remains open.** The audit-metrics first slice
exposed the five families needed to alert on Z-3 regressions
(`dds_build_info`, `dds_uptime_seconds`,
`dds_audit_entries_total{action}`, `dds_audit_chain_length`,
`dds_audit_chain_head_age_seconds`); follow-up #24 added
`dds_http_caller_identity_total{kind}` so the `DdsLoopbackTcpAdminUsed`
H-7 cutover regression alarm has a real metric to key off.
[dds-node/src/telemetry.rs](../dds-node/src/telemetry.rs) is a
hand-rolled exposition over `Mutex<BTreeMap<String, u64>>` counters
plus on-demand audit-store reads, served on a separate axum listener
bound to the new `metrics_addr` field on
[`NetworkConfig`](../dds-node/src/config.rs) (default `None` —
opt-in). When the rest of the catalog (network / FIDO2 / store /
process) lands the histograms become worth their weight and the
module will be folded into `metrics-exporter-prometheus`.

**C.1 — Crate.** Add `metrics = "0.24"` and
`metrics-exporter-prometheus = "0.18"` to `dds-node/Cargo.toml`.
`metrics-util` for histograms. The `metrics` crate is light — no
runtime cost when the exporter isn't installed. **Deferred until
the histogram-bearing metrics in C.3 ship** — the audit subset in
follow-up #22 is hand-rolled because three counters and two gauges
do not justify the dependency yet.

**C.2 — Endpoint. ✅** New axum route `GET /metrics` on a
**separate listener** bound to a configurable address
(`metrics_addr` in `node.toml`, default `None` so the endpoint is
opt-in for existing deployments — recommended value
`127.0.0.1:9495` once an operator wants Prometheus scrape).
Separate from the API listener so:
- ops can scope Prometheus scrape ACLs without touching the API
  surface;
- exposing it on `0.0.0.0` for fleet scrape doesn't open the API.

The metrics router answers only `GET /metrics`; every other path
returns 404 so the second listener cannot be confused with the API
surface.

No auth on `/metrics` — Prometheus is expected to be on a trusted
scrape network. If exposed off-host, operators put a TLS sidecar in
front (same posture as kube-state-metrics).

**C.3 — Metric catalog.** Metrics are named `dds_<area>_<measure>`,
labels lower-snake. Counters reset on restart (Prometheus convention
— compute rates over them). ✅ rows shipped in follow-up #22; 🔲
rows remain open.

| Metric | Type | Labels | Purpose | Status |
|---|---|---|---|---|
| `dds_build_info` | gauge | `version` | Static fingerprint, always 1 (`git_sha`, `rust_version` deferred until a build-time env var pipeline lands) | ✅ |
| `dds_uptime_seconds` | gauge | — | Process uptime | ✅ |
| **Network** | | | | |
| `dds_peers_admitted` | gauge | — | Currently admitted peer count | 🔲 |
| `dds_peers_connected` | gauge | — | libp2p-connected peers (admitted + un-admitted) | 🔲 |
| `dds_admission_handshakes_total` | counter | `result=ok|fail|revoked` | H-12 outcomes | 🔲 |
| `dds_gossip_messages_total` | counter | `topic, direction=in|out, kind` | Gossipsub volume | 🔲 |
| `dds_gossip_messages_dropped_total` | counter | `reason=unadmitted|invalid_token|duplicate|backpressure` | Why we threw a message away | 🔲 |
| `dds_sync_pulls_total` | counter | `result=ok|fail` | Anti-entropy pull count | 🔲 |
| `dds_sync_lag_seconds` | histogram | — | Time from peer's op timestamp to local apply | 🔲 |
| `dds_sync_payloads_rejected_total` | counter | `reason=signature|graph|duplicate_jti|window` | B-1-style guard hits | 🔲 |
| **Trust graph** | | | | |
| `dds_attestations_total` | gauge | `kind=user|device|service` | Active count | 🔲 |
| `dds_attestations_revoked_total` | counter | — | Revocations applied since boot | 🔲 |
| `dds_burned_identities_total` | gauge | — | Total burned URNs | 🔲 |
| `dds_purpose_lookups_total` | counter | `result=ok|denied|not_found` | `has_purpose` outcomes | 🔲 |
| **FIDO2 / sessions** | | | | |
| `dds_fido2_assertions_total` | counter | `result=ok|signature|rp_id|up|uv|sign_count` | Assertion outcomes | 🔲 |
| `dds_fido2_attestation_verify_total` | counter | `result, fmt=packed|none|tpm` | Enrollment-time verify | 🔲 |
| `dds_sessions_issued_total` | counter | `via=fido2|legacy` | Session minting | 🔲 |
| `dds_challenges_outstanding` | gauge | — | Live challenges (B-5 cap reference) | 🔲 |
| **Audit** | | | | |
| `dds_audit_entries_total` | counter | `action` | Per-action emission rate | ✅ |
| `dds_audit_chain_length` | gauge | — | Local chain entry count | ✅ |
| `dds_audit_chain_head_age_seconds` | gauge | — | `now - last_entry.timestamp` (alert if > N) | ✅ |
| **Storage** | | | | |
| `dds_store_bytes` | gauge | `table=tokens|ops|audit|...` | redb table sizes | 🔲 |
| `dds_store_writes_total` | counter | `result=ok|conflict|fail` | redb txn outcomes | 🔲 |
| **HTTP API** | | | | |
| `dds_http_requests_total` | counter | `route, method, status` | Route-level traffic | 🔲 |
| `dds_http_request_duration_seconds` | histogram | `route, method` | Latency | 🔲 |
| `dds_http_caller_identity_total` | counter | `kind=anonymous|uds|pipe|admin` | Who's calling — surfaces accidental loopback-TCP regressions; transport buckets (anonymous/uds/pipe) partition the request count, `admin` is bumped orthogonally when the caller passes the admin policy | ✅ |
| **Process** | | | | |
| `dds_memory_resident_bytes` | gauge | — | RSS (procfs / mach) | 🔲 |
| `dds_thread_count` | gauge | — | OS thread count | 🔲 |

**C.4 — Wiring.** Each call site uses `metrics::counter!`,
`metrics::gauge!`, `metrics::histogram!` macros. A dedicated
`dds-node::telemetry` module owns metric names + describes them at
startup so operators get types/help text from
`/metrics`. No instrumentation in `dds-core` (`no_std` constraint).

**C.5 — Cardinality budget.** Every label set is bounded: no
free-form URNs, JTIs, or paths land in labels. Cardinality estimate
≤ 200 series per node — fits comfortably in a small Prometheus.

### Phase D — Health endpoints ✅

**Status: landed 2026-04-26 follow-up #18.** Both routes are wired
into the public sub-router (no admin gate, no FIDO2 — orchestrator
probes must work without caller credentials) and the response signer
(H-6) wraps them, so a MITM cannot manufacture a bogus 200/503.

**D.1 — `GET /healthz`. ✅** Liveness. Returns `200 ok` whenever the
axum task is scheduling. No dependency checks — a poisoned redb
still answers liveness so the orchestrator does not flap a recovering
node before it can serve `/readyz`. Implemented in
[dds-node/src/http.rs](../dds-node/src/http.rs) `healthz`.

**D.2 — `GET /readyz`. ✅** Readiness. Returns
`{"ready": true|false, "checks": {...}}` with HTTP 200 when ready and
503 otherwise. Checks performed:
- **node_identity** — `LocalService` exists, so identity is loaded by
  construction (the router is only built after `LocalService::new`
  returns).
- **store** — `LocalService::readiness_smoketest` round-trips
  `audit_chain_head()`. A redb open / DACL regression surfaces here
  as 503 rather than as a stack of 500s from real traffic.
- **peers** — `peer_seen` (`Arc<AtomicBool>` shared with the swarm
  event loop, flipped sticky on the first `ConnectionEstablished`)
  is `true`, **or** `bootstrap_empty` is `true` (lone-node
  deployment).

Domain-pubkey / admission-cert verification is implicit: if either
failed, `DdsNode::init` errored before `http::serve` ever bound to a
port, so a process answering `/readyz` necessarily passed those
gates at startup.

`/v1/node/info` is preserved for content discovery; `/healthz` and
`/readyz` are the orchestrator-friendly endpoints.

**D.3 — Tests. ✅** Six new regression tests in
[dds-node/src/http.rs](../dds-node/src/http.rs) `tests`:
`healthz_returns_200_ok_body`,
`healthz_via_production_router_is_unauthenticated`,
`readyz_is_ready_when_bootstrap_empty_and_store_ok`,
`readyz_returns_503_when_bootstrap_nonempty_and_no_peer_seen`,
`readyz_flips_to_ready_when_peer_seen_set` (proves the swarm /
handler share the same `AtomicBool`),
`readyz_via_production_router_is_unauthenticated`. The two
unauthenticated-router tests pin the no-admin-gate property even
under a strict `AdminPolicy`.

### Phase E — Reference dashboards & alert rules

**Status: audit-tier subset landed 2026-04-26 follow-up #23.** The
three reference assets ship today:
- [`docs/observability/alerts/dds.rules.yml`](observability/alerts/dds.rules.yml)
- [`docs/observability/grafana/dds-overview.json`](observability/grafana/dds-overview.json)
- [`docs/observability/grafana/dds-trust-graph.json`](observability/grafana/dds-trust-graph.json)

The rules and panels keyed off the Phase C audit subset (the five
metrics shipped in follow-up #22 plus the Prometheus-built-in `up`
series) are active and ready to load. Rules whose source metric is
still open under Phase C (network / FIDO2 / store / HTTP) ship as
**commented-out reference blocks** inside `dds.rules.yml` so each
Phase C follow-up can uncomment its tier atomically — the rule
expressions are the spec the metric must satisfy. Operators must
not uncomment those blocks without confirming the underlying metric
ships in the deployed `dds-node` build; an inert rule on a missing
series silently never fires, which is worse than no rule at all.

Active rules (`dds.rules.yml` groups `dds-audit` and `dds-process`):

- `DdsAuditChainStalled` — `dds_audit_chain_head_age_seconds > 600`
  for 5 m. Z-3 regression tripwire.
- `DdsAuditEmissionsFlat` —
  `sum without(action) (increase(dds_audit_entries_total[30m])) == 0`
  on a node up > 30 m. Pairs with `DdsAuditChainStalled` to
  disambiguate genuinely-idle from emit-broken.
- `DdsAuditRejectionSpike` — rejection share > 50 % for 10 m.
  Either active probing or a peer with a regressed build.
- `DdsNodeDown` — `up{job="dds-node"} == 0` for 2 m.
- `DdsNodeFlapping` — `dds_uptime_seconds < 300` for 15 m.
- `DdsBuildSkew` — `count(count by(version) (dds_build_info)) > 1`
  for 1 h.

Active HTTP-tier rule (group `dds-http`, landed follow-up #24):
- `DdsLoopbackTcpAdminUsed` — fires on
  `rate(dds_http_caller_identity_total{kind="anonymous"}[5m]) > 0`
  for 5 m, the H-7 cutover regression alarm flagged in
  [Claude_sec_review.md](../Claude_sec_review.md). `kind="anonymous"`
  corresponds to `CallerIdentity::Anonymous` (no peer credentials,
  i.e. loopback TCP), so post-cutover any non-zero rate indicates a
  forgotten config flag or a client still on TCP.

Reference (commented) rules — uncomment when Phase C lands the
metric:
- `DdsAdmissionFailureSpike` (needs `dds_admission_handshakes_total`).
- `DdsSyncLagHigh` (needs `dds_sync_lag_seconds_bucket`).
- `DdsSyncRejectsSpike` (needs `dds_sync_payloads_rejected_total`).
- `DdsFido2AssertionFailureSpike` (needs `dds_fido2_assertions_total`).
- `DdsStoreWriteFailures` (needs `dds_store_writes_total`).

`DdsRevocationsSurge` is implicitly covered by the Trust-Graph
dashboard's Revocations panel and the rejection-ratio alert; a
dedicated rate alert is deferred until operators have a baseline
for what "surge" means in their fleet.

Dashboards:
- `dds-overview.json` — node count, build-version count, audit
  chain head age, scrape health, audit emission rate by action,
  chain length per instance, head-age per instance, uptime per
  instance. All eight panels render today against the audit
  subset.
- `dds-trust-graph.json` — attestation / vouch / revocation / burn
  ingest activity (success vs `*.rejected` per family), enrollment
  & admin actions, apply outcomes, and an aggregate rejection-ratio
  panel matching the `DdsAuditRejectionSpike` alert. All panels
  render today; FIDO2-specific panels (assertion outcomes,
  attestation verify) are deferred until the Phase C FIDO2 metrics
  ship.

### Phase F — CLI surface for ad-hoc ops ✅

**Status: landed 2026-04-26 follow-up #21.** All four subcommands
shipped; `last admission failure` and `store bytes` are deferred to
Phase C because both depend on the Prometheus metrics catalog
(`dds_admission_handshakes_total{result="fail"}` and
`dds_store_bytes`) — neither is exposed by `/v1/status` today.

Subcommands added to `dds-cli`:

| Command | Status | Purpose |
|---|---|---|
| `dds-cli stats` | ✅ | Composes `/v1/status` + `/v1/audit/entries` into one snapshot — peer ID + uptime, connected peers, trust-graph + store sizes, audit chain length + head age + head action. Pretty-prints by default; `--format json` emits a single JSON object for scripting / Prometheus textfile fallbacks. `last admission failure` and `store bytes` deferred to Phase C (need the `/metrics` catalog). |
| `dds-cli audit tail` | ✅ | (Phase B.1) |
| `dds-cli audit verify` | ✅ | (Phase B.2) |
| `dds-cli audit export` | ✅ | One-shot range dump — `--since` / `--until` / `--action` filters, `--out <file>` for incident-response bundles, otherwise stdout. JSONL only in this build (cef and syslog tracked under Phase B.1 follow-ups). Each line is verified locally before emission so a tampered entry surfaces as `sig_ok=false` rather than being silently trusted. |
| `dds-cli health` | ✅ | Calls `/readyz` and prints the `{ready, checks}` body. Exits 0 when ready, 1 otherwise — orchestrator-friendly. `--format json` for scripting; `--format text` (default) for humans. Returns the HTTP status code so a 503-with-body looks distinct from a network failure. |

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
