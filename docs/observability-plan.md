# DDS Observability Plan — Audit, Metrics, Alerts, SIEM Export

**Status:** Phase C and Phase E **complete** as of 2026-05-02 follow-up
#47. `DdsSyncLagHigh` alert rule activated in
[`observability/alerts/dds.rules.yml`](observability/alerts/dds.rules.yml)
new `dds-sync-lag` group — the last remaining Phase E reference rule is
now active. All Phase C catalog rows are ✅; all Phase E alert rules are
active. Phase C **histogram metrics** (`dds_sync_lag_seconds`,
`dds_http_request_duration_seconds`) landed 2026-05-02 follow-up #46 —
the two remaining 🔲 rows in the metric catalog are now fully
implemented. `dds_sync_lag_seconds` is a hand-rolled histogram
(buckets 1s–86400s) observing one sample per token in
`DdsNode::handle_sync_response` after the pre-apply filter; the
sample value is `now_unix.saturating_sub(token.payload.iat)` seconds.
`dds_http_request_duration_seconds` is a hand-rolled histogram
(buckets 5ms–5s) observing one sample per matched HTTP request in
`http_request_observer_middleware` via `Instant::elapsed()`. Both are
rendered in Prometheus histogram text format (cumulative `_bucket`
lines + `_sum` + `_count`) by the existing hand-rolled exposition in
`dds-node/src/telemetry.rs`. Two new unit tests
(`render_emits_sync_lag_histogram`, `render_emits_http_duration_histogram`)
pin the exposition output. Phase E **PQC alert rules**
(`DdsPqcDecryptFailureSpike`, `DdsPqcKeyRequestSpike`) landed
2026-05-02 follow-up #45 — the two deferred B.11 alert rules are now
active in `dds-pqc` group. Phase E **network + FIDO2 reference rules
promoted to active** (`DdsAdmissionFailureSpike`, `DdsSyncRejectsSpike`,
`DdsFido2AssertionFailureSpike`) landed follow-up #43. All eight alert
groups are now active: `dds-audit`, `dds-process`, `dds-storage`,
`dds-http`, `dds-network`, `dds-fido2`, `dds-pqc`, and `dds-sync-lag`.
Phase C **`dds_build_info` git_sha + rust_version
labels** landed 2026-04-27 follow-up #44 — the catalog row's
deferred build-time env-var pipeline shipped via a new
[`dds-node/build.rs`](../dds-node/build.rs) that captures
`git rev-parse --short HEAD` into `DDS_GIT_SHA` and
`rustc --version` into `DDS_RUST_VERSION`, with literal `unknown`
fallbacks for tarball / sandboxed builds; the `dds_build_info`
gauge now ships with the documented label triple
(`version`, `git_sha`, `rust_version`). The `DdsBuildSkew`
Alertmanager rule continues to aggregate by `version` only so its
firing semantics are unchanged; an annotation in the rule now
documents the per-SHA / per-rustc copy-and-tune option.
Phase E **network + FIDO2 reference rules promoted to
active** (`DdsAdmissionFailureSpike`, `DdsSyncRejectsSpike`,
`DdsFido2AssertionFailureSpike`) landed 2026-04-27 follow-up #43 —
all three move out of the commented reference section in
[`observability/alerts/dds.rules.yml`](observability/alerts/dds.rules.yml)
into active groups (`dds-network` and `dds-fido2`) keyed off the
`> 0` "any failure is suspicious" pattern already used by
`DdsStoreWriteFailures` (#39) and `DdsLoopbackTcpAdminUsed` (#24).
The original spec thresholds (0.1/s, 0.5/s, 0.05/s) were spec
placeholders and are dropped; the catalog metrics shipped under
follow-ups #29, #37/#41, and #34 respectively. Phase C
**thread-count gauge** (`dds_thread_count`) landed
2026-04-27 follow-up #42 — the natural sibling of the memory-resident
bytes gauge from #40, sourced via a small platform-specific shim
(`/proc/self/status` parse on Linux, `proc_pidinfo` `PROC_PIDTASKINFO`
on macOS, `TH32CS_SNAPTHREAD` walk filtered to the current pid on
Windows). Phase C **sync-payloads-rejected post-apply partition**
(`dds_sync_payloads_rejected_total{reason=signature|duplicate_jti|graph}`)
landed 2026-04-27 follow-up #41 — closing the post-apply gap that
`#37` left open. Phase A landed 2026-04-26 follow-up #17 (closes Z-3);
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
not-yet-shipped catalog) landed 2026-04-26 follow-up #23. Phase C
**HTTP-tier caller-identity counter** (`dds_http_caller_identity_total{kind}`)
landed 2026-04-26 follow-up #24, also activating the
`DdsLoopbackTcpAdminUsed` H-7 cutover regression rule. Phase C
**trust-graph subset** (`dds_trust_graph_attestations`,
`dds_trust_graph_vouches`, `dds_trust_graph_revocations`,
`dds_trust_graph_burned` — scrape-time gauges read under one
read-lock acquisition) landed 2026-04-26 follow-up #25. Phase C
**FIDO2 outstanding-challenges gauge**
(`dds_challenges_outstanding` — scrape-time read of the existing
[`ChallengeStore::count_challenges`](../dds-store/src/traits.rs)
trait method, B-5 backstop reference) landed 2026-04-26 follow-up
#26. Phase C **sessions-issuance counter**
(`dds_sessions_issued_total{via=fido2|legacy}` — bumped from the
two [`LocalService`](../dds-node/src/service.rs) entry points after
a session token is signed successfully) landed 2026-04-27 follow-up
#27. Phase C **purpose-lookup counter**
(`dds_purpose_lookups_total{result=ok|denied}` — bumped from the
shared [`LocalService::has_purpose_observed`](../dds-node/src/service.rs)
helper at every trust-graph capability gate, including the
gossip-ingest publisher-capability filter
[`node::publisher_capability_ok`](../dds-node/src/node.rs)) landed
2026-04-27 follow-up #28. Phase C **admission-handshakes counter**
(`dds_admission_handshakes_total{result=ok|fail|revoked}` — bumped
from [`DdsNode::verify_peer_admission`](../dds-node/src/node.rs)
at every outcome branch) landed 2026-04-27 follow-up #29. Phase C
**network peer-count gauges**
(`dds_peers_admitted` + `dds_peers_connected` — refreshed by the
swarm task in [`DdsNode::refresh_peer_count_gauges`](../dds-node/src/node.rs)
on every connection lifecycle event and every successful H-12
admission handshake; the metrics scrape reads via a shared
[`NodePeerCounts`](../dds-node/src/node.rs) handle plumbed from
`main.rs` into `telemetry::serve`) landed 2026-04-27 follow-up #30.
Phase C **gossip-messages counter**
(`dds_gossip_messages_total{kind=op|revocation|burn|audit}` — bumped
from [`DdsNode::handle_gossip_message`](../dds-node/src/node.rs)
after the inbound envelope clears topic identification and CBOR
decode, just before dispatch to the matching `ingest_*` path) landed
2026-04-27 follow-up #31. Phase C **gossip-messages-dropped counter**
(`dds_gossip_messages_dropped_total{reason=unadmitted|unknown_topic|decode_error|topic_kind_mismatch}` —
bumped from the four pre-decode drop sites in
[`DdsNode::handle_swarm_event`](../dds-node/src/node.rs) and
[`DdsNode::handle_gossip_message`](../dds-node/src/node.rs)) landed
2026-04-27 follow-up #32. Phase C **FIDO2 attestation-verify counter**
(`dds_fido2_attestation_verify_total{result=ok|fail, fmt=packed|none|unknown}` —
bumped from the shared
[`LocalService::verify_attestation_observed`](../dds-node/src/service.rs)
helper at every enrollment-time call to
[`dds_domain::fido2::verify_attestation`], i.e. the two call sites in
[`LocalService::enroll_user`](../dds-node/src/service.rs) and
[`LocalService::admin_setup`](../dds-node/src/service.rs); the
credential-lookup re-parse inside `verify_assertion_common` is
*not* counted because the catalog scopes the counter to
enrollment-time only) landed 2026-04-27 follow-up #33. Phase C
**FIDO2 assertions counter**
(`dds_fido2_assertions_total{result=ok|signature|rp_id|up|sign_count|other}` —
bumped from the single drop-guarded exit funnel in
[`LocalService::verify_assertion_common`](../dds-node/src/service.rs)
consumed by both `issue_session_from_assertion` (the
`/v1/session/assert` HTTP path) and `admin_vouch`; the catalog's
`uv` bucket is reserved for a future UV-required gate and `other`
collapses non-named error exits — challenge / origin / cdj
mismatch, clock regression, credential-lookup miss, COSE parse,
store errors — so the per-attempt total stays accurate) landed
2026-04-27 follow-up #34. Phase C **sync-pulls counter**
(`dds_sync_pulls_total{result=ok|fail}` — bumped at the outcome
branches of [`DdsNode::handle_sync_event`](../dds-node/src/node.rs):
`ok` when an admitted peer's `Message::Response` is processed by
`handle_sync_response` (zero payloads still counts as `ok`), `fail`
on `OutboundFailure` and on the H-12 unadmitted-peer response
drop) landed 2026-04-27 follow-up #35. Phase C **HTTP-requests
counter** (`dds_http_requests_total{route, method, status}` —
bumped from the new `route_layer`-applied
[`http_request_observer_middleware`](../dds-node/src/http.rs) wired
into the merged production router built by
[`crate::http::router`](../dds-node/src/http.rs); the middleware
reads `axum::extract::MatchedPath` from the per-route handler stack
before calling `next.run`, captures the method, then bumps once
with the inner handler's status. Unmatched 404s served by the
default fallback are *not* counted because `route_layer` does not
wrap the fallback — those remain visible via
`dds_http_caller_identity_total`) landed 2026-04-27 follow-up #36.
Phase C **sync-payloads-rejected counter (pre-apply subset)**
(`dds_sync_payloads_rejected_total{reason=legacy_v1|publisher_capability|replay_window}`
— bumped from the three pre-apply skip sites inside
[`DdsNode::handle_sync_response`](../dds-node/src/node.rs): the
M-1/M-2 wire-version-1 token guard, the C-3 publisher-capability
filter, and the M-9 revoke/burn replay-window guard) landed
2026-04-27 follow-up #37. The pre-apply catalog gained a fourth
`reason=publisher_identity` bucket on 2026-04-29 alongside the SC-5
Phase B.1 ingest-time fail-closed gate
[`software_publisher_identity_ok`](../dds-node/src/node.rs) — same
helper runs on the gossip-ingest path
([`DdsNode::ingest_operation`](../dds-node/src/node.rs)) and on the
sync apply path; sync-side rejections bump the new bucket while
gossip-side rejections emit a `*.rejected` audit entry with reason
`publisher-identity-invalid`. Phase C **sync-payloads-rejected
post-apply partition**
(`dds_sync_payloads_rejected_total{reason=signature|duplicate_jti|graph}`)
landed 2026-04-27 follow-up #41 — the new
[`SyncRejectReason`](../dds-net/src/sync.rs) enum plus a
[`SyncResult::rejected_by_reason`](../dds-net/src/sync.rs) map carry
the categorical reason out of the apply funnel; the `dds-node` sync
handler iterates the map after `apply_sync_payloads_with_graph`
returns and bumps the same counter family. `signature` covers
`Token::validate()` failures, `duplicate_jti` partitions the B-1
replay indicator, and `graph` collects every other
`TrustError`. Decode failures and store-side write errors stay in
`SyncResult.errors` only — already covered by
`dds_store_writes_total{result=fail}`. Phase C **store-bytes gauge**
(`dds_store_bytes{table=tokens|revoked|burned|operations|audit_log|challenges|credential_state}` —
scrape-time read of [`dds_store::traits::StoreSizeStats::table_stored_bytes`]
through [`LocalService::store_byte_sizes`](../dds-node/src/service.rs);
RedbBackend reports `redb::TableStats::stored_bytes()` per table,
MemoryBackend returns an empty map so harnesses scrape a discoverable
family with no series) landed 2026-04-27 follow-up #38. Phase C
**store-writes counter**
(`dds_store_writes_total{result=ok|conflict|fail}` — scrape-time
read of [`dds_store::traits::StoreWriteStats::store_write_counts`](../dds-store/src/traits.rs)
through [`LocalService::store_write_counts`](../dds-node/src/service.rs);
both RedbBackend and MemoryBackend keep three monotonic
`AtomicU64` counters bumped from every write-path method exit;
`result="ok"` counts committed writes, `result="conflict"` counts
the two caller-visible domain rejections (`put_operation`
duplicate id, `bump_sign_count` `SignCountReplay`), and
`result="fail"` collects every other unsuccessful write including
the audit chain-break path which v1 collapses into the `fail`
bucket. The Phase E `DdsStoreWriteFailures` reference rule in
[`docs/observability/alerts/dds.rules.yml`](observability/alerts/dds.rules.yml)
moves out of the commented-reference section and ships active
under the new `dds-storage` group keyed off
`rate(dds_store_writes_total{result!="ok"}[5m]) > 0`) landed
2026-04-27 follow-up #39. Phase C **memory-resident-bytes gauge**
(`dds_memory_resident_bytes` — scrape-time read of
[`sysinfo::Process::memory`](https://docs.rs/sysinfo/0.32/sysinfo/struct.Process.html#method.memory)
for our own pid via the private `process_resident_bytes()` helper
in [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs)) landed
2026-04-27 follow-up #40 — sister `dds_thread_count` gauge landed in
2026-04-27 follow-up #42 via a small platform-specific shim. Phase C **sync-payloads-rejected post-apply
partition**
(`dds_sync_payloads_rejected_total{reason=signature|duplicate_jti|graph}`) —
landed 2026-04-27 follow-up #41 — the new
[`dds_net::sync::SyncRejectReason`](../dds-net/src/sync.rs) enum
plus a [`SyncResult::rejected_by_reason: BTreeMap<SyncRejectReason, usize>`](../dds-net/src/sync.rs)
field carry the categorical rejection reason out of the apply funnel;
[`DdsNode::handle_sync_response`](../dds-node/src/node.rs) iterates
the map after `apply_sync_payloads_with_graph` returns and bumps the
existing counter through `record_sync_payloads_rejected`. `signature`
covers `Token::validate()` failures (ed25519 / issuer-binding);
`duplicate_jti` covers `TrustError::DuplicateJti`; `graph` covers
every other `TrustError` from `TrustGraph::add_token`. Decode
failures and store-side write errors stay in `SyncResult.errors`
only — they are corruption / transient signals already covered by
`dds_store_writes_total{result=fail}`. The rest of the C catalog
(`dds_sync_lag_seconds` histogram plus the
`dds_http_request_duration_seconds` histogram sibling) **landed
2026-05-02 follow-up #46** — Phase C is now fully complete; the
`metrics-exporter-prometheus` rollover is no longer a blocker since
histograms ship hand-rolled in the existing exposition (see §C.1).
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
| `policy.applied` / `policy.failed` / `software.applied` / `software.failed` | Finer-grained applier outcomes | `service.rs::record_applied` keyed off the new `AppliedReport.kind` field (`policy` / `software`); `Reconciliation` and `HostState` heartbeats stay on the `apply.*` family because they don't tie to a single document. Wire field is optional (`#[serde(default, skip_serializing_if = "Option::is_none")]`) so a pre-2026-04-28 agent that never sends `kind` keeps emitting under the legacy `apply.*` actions. | ✅ shipped 2026-04-28 |
| `admission.cert.issued` | Admission cert produced for a peer | `service.rs::issue_admission_cert` | 🔲 deferred (cert issuance is a domain-level operation today) |
| `admission.cert.revoked` | Admission revocation accepted | `node.rs::merge_piggybacked_revocations` (piggy-backed H-12 distribution path, per-newly-added entry) | ✅ shipped 2026-04-28 |
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

`cef` (ArcSight / Splunk Common Event Format, single line) and
`syslog` (RFC 5424 with the audit fields in STRUCTURED-DATA `dds@32473`)
formats now ship alongside the canonical `jsonl` — see
[audit-event-schema.md §6](observability/audit-event-schema.md) for
the field templates. CEF Device Version is the `dds-cli` build
(workspace-versioned 1:1 with `dds-node`); syslog hostname comes from
`HOSTNAME` / `COMPUTERNAME` / `/etc/hostname` with RFC 5424 `NILVALUE`
`-` as fallback so the line still parses on hosts where the lookup
fails. Severity is fixed by [audit-event-schema.md §5](observability/audit-event-schema.md).
Operators that already run a Vector / fluent-bit transform can keep
that pipeline; `--format cef` / `--format syslog` are for deployments
that prefer the canonical line shape directly out of the CLI without
a forwarder-side rewrite. The CLI errors with a clear message naming
the supported set on any unknown format so an operator on an old
build does not silently emit nothing.

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
caller-identity counter landed in follow-up #24; trust-graph
read-side subset landed in follow-up #25; FIDO2 outstanding-challenges
gauge landed in follow-up #26; sessions-issuance counter
(`dds_sessions_issued_total{via}`) landed 2026-04-27 follow-up #27;
purpose-lookups counter (`dds_purpose_lookups_total{result}`) landed
2026-04-27 follow-up #28; admission-handshakes counter
(`dds_admission_handshakes_total{result}`) landed 2026-04-27
follow-up #29; network peer-count gauges
(`dds_peers_admitted` + `dds_peers_connected`) landed 2026-04-27
follow-up #30; gossip-messages counter
(`dds_gossip_messages_total{kind}`) landed 2026-04-27 follow-up
#31; gossip-messages-dropped counter
(`dds_gossip_messages_dropped_total{reason}`) landed 2026-04-27
follow-up #32; FIDO2 attestation-verify counter
(`dds_fido2_attestation_verify_total{result, fmt}`) landed
2026-04-27 follow-up #33; FIDO2 assertions counter
(`dds_fido2_assertions_total{result}`) landed 2026-04-27 follow-up
#34; sync-pulls counter
(`dds_sync_pulls_total{result=ok|fail}`) landed 2026-04-27
follow-up #35; HTTP-requests counter
(`dds_http_requests_total{route, method, status}`) landed
2026-04-27 follow-up #36; sync-payloads-rejected counter
(`dds_sync_payloads_rejected_total{reason=legacy_v1|publisher_capability|publisher_identity|replay_window|signature|duplicate_jti|graph}` —
pre-apply surface landed 2026-04-27 follow-up #37; the post-apply
`signature|duplicate_jti|graph` partition landed 2026-04-27
follow-up #41 once `SyncResult` grew the
[`SyncRejectReason`](../dds-net/src/sync.rs) categorical enum +
[`rejected_by_reason`](../dds-net/src/sync.rs) `BTreeMap` field
that the dds-node sync handler iterates after every apply; the
fourth pre-apply `publisher_identity` reason landed 2026-04-29
alongside the SC-5 Phase B.1 ingest-time fail-closed gate
[`software_publisher_identity_ok`](../dds-node/src/node.rs)); store-bytes gauge
(`dds_store_bytes{table=tokens|revoked|burned|operations|audit_log|challenges|credential_state}`)
landed 2026-04-27 follow-up #38 — scrape-time read of
[`dds_store::traits::StoreSizeStats::table_stored_bytes`] through
[`LocalService::store_byte_sizes`](../dds-node/src/service.rs);
RedbBackend reports `redb::TableStats::stored_bytes()` per table and
MemoryBackend returns an empty map so harnesses scrape a
discoverable family with no series; thread-count gauge
(`dds_thread_count`) landed 2026-04-27 follow-up #42 via the
platform-specific shim alongside the memory-resident-bytes helper;
rest of the catalog (`dds_sync_lag_seconds` histogram plus the
`dds_http_request_duration_seconds` histogram sibling) **landed
2026-05-02 follow-up #46 — Phase C is now fully complete.** The
audit-metrics first slice exposed the five families needed to alert on
Z-3 regressions (`dds_build_info`, `dds_uptime_seconds`,
`dds_audit_entries_total{action}`, `dds_audit_chain_length`,
`dds_audit_chain_head_age_seconds`); follow-up #24 added
`dds_http_caller_identity_total{kind}` so the `DdsLoopbackTcpAdminUsed`
H-7 cutover regression alarm has a real metric to key off; follow-up
#25 added the four `dds_trust_graph_*` gauges (attestations / vouches
/ revocations / burned) read under a single read-lock acquisition at
scrape time; follow-up #26 added `dds_challenges_outstanding` (FIDO2
challenge-store row count, B-5 backstop reference) using the same
single-svc-lock-per-scrape pattern as the audit / trust-graph reads;
follow-up #28 added `dds_purpose_lookups_total{result=ok|denied}`,
bumped through the shared [`LocalService::has_purpose_observed`](../dds-node/src/service.rs)
helper from every capability gate (publisher / device-scope /
admin-vouch) plus the gossip-ingest publisher-capability filter in
`node::publisher_capability_ok`; follow-up #29 added
`dds_admission_handshakes_total{result=ok|fail|revoked}`, bumped
from [`DdsNode::verify_peer_admission`](../dds-node/src/node.rs) at
every exit branch so the H-12 inbound-handshake outcome distribution
becomes graphable (revoked baseline = peers attempting to rejoin
after revocation; fail baseline = cert pipeline regression);
follow-up #30 added the network peer-count gauges
`dds_peers_admitted` and `dds_peers_connected`, sourced from a
shared [`NodePeerCounts`](../dds-node/src/node.rs) snapshot
(two `Arc<AtomicU64>`) refreshed by the swarm task in
[`DdsNode::refresh_peer_count_gauges`](../dds-node/src/node.rs)
on every connection lifecycle event and after every successful
admission handshake — the metrics scrape reads two `Relaxed`
atomics with no lock acquisition, and operators compute the
unadmitted share as `dds_peers_connected - dds_peers_admitted` to
flag handshake stalls; follow-up #31 added the
`dds_gossip_messages_total{kind=op|revocation|burn|audit}` counter,
bumped from [`DdsNode::handle_gossip_message`](../dds-node/src/node.rs)
after the inbound envelope clears topic identification and CBOR
decode, just before dispatch to the matching `ingest_*` path —
operators get the per-kind inbound rate that pairs with the
existing `dds_audit_entries_total{action=*.rejected}` counter for
post-ingest rejection rates. The trust-graph series are renamed from the original
catalog spelling (`dds_attestations_total` → `dds_trust_graph_attestations`,
`dds_burned_identities_total` → `dds_trust_graph_burned`) to match
Prometheus convention — `_total` is reserved for monotonic counters,
and these are gauges of current state.
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
| `dds_build_info` | gauge | `version`, `git_sha`, `rust_version` | Static fingerprint, always 1 — labels captured at build time by [`dds-node/build.rs`](../dds-node/build.rs): `version` from `CARGO_PKG_VERSION`, `git_sha` from `git rev-parse --short HEAD` (literal `unknown` outside a git tree), `rust_version` from `rustc --version` (literal `unknown` if rustc fails). The `DdsBuildSkew` alert continues to key off `count by(version)` so adding the extra labels does not change alert semantics; operators wanting per-SHA or per-rustc skew detection mirror the same query against `git_sha` / `rust_version`. | ✅ |
| `dds_uptime_seconds` | gauge | — | Process uptime | ✅ |
| **Network** | | | | |
| `dds_peers_admitted` | gauge | — | Currently admitted peer count — refreshed from [`DdsNode::admitted_peers`](../dds-node/src/node.rs) by `refresh_peer_count_gauges` after every connection lifecycle event and every successful H-12 admission handshake. | ✅ |
| `dds_peers_connected` | gauge | — | libp2p-connected peers (admitted + un-admitted) — refreshed from `swarm.connected_peers().count()` at the same call sites. The unadmitted share is `dds_peers_connected - dds_peers_admitted`. | ✅ |
| `dds_admission_handshakes_total` | counter | `result=ok|fail|revoked` | H-12 inbound-handshake outcomes — bumped from [`DdsNode::verify_peer_admission`](../dds-node/src/node.rs) at every exit branch. `ok` = peer cert verified and peer added to `admitted_peers`; `revoked` = peer is on the local admission revocation list (rejected before signature work); `fail` = no cert / decode error / clock error / cert verify rejected (signature, domain id, peer id, or expiry mismatch). Outbound-side handshake initiation is not counted (would be redundant with the libp2p connection counter). | ✅ |
| `dds_admission_handshake_last_failure_seconds` | gauge | — | Unix-seconds timestamp of the most recent inbound H-12 admission handshake whose outcome was *not* `ok` (i.e. the latest moment `dds_admission_handshakes_total{result="fail"}` or `{result="revoked"}` was bumped). Stamped from the same [`DdsNode::verify_peer_admission`](../dds-node/src/node.rs) call sites as the counter, read at scrape time off the process-global [`Telemetry`](../dds-node/src/telemetry.rs) handle. Sentinel `0` before the first failure / revocation lands so the family is always discoverable in the catalog. Pairs with the since-boot counter to surface "how long ago was the last admission failure" without an alerting rate window — also surfaced through `/v1/status::last_admission_failure_ts` so `dds-cli stats` can render it without scraping `/metrics`, closing the second deferred Phase F row. | ✅ |
| `dds_gossip_messages_total` | counter | `kind=op|revocation|burn|audit` | Inbound gossip volume — bumped from [`DdsNode::handle_gossip_message`](../dds-node/src/node.rs) after the envelope clears topic identification and CBOR decode, just before dispatch to the matching `ingest_*` path. The catalog originally named `topic` + `direction` labels; `kind` is 1:1 with the originating [`DdsTopic`](../dds-net/src/gossip.rs) so a separate `topic` label would be redundant cardinality, and outbound-side publish is not currently instrumented (the production event loop has no centralised publish funnel — the [`dds-macos-e2e`](../dds-node/src/bin/dds-macos-e2e.rs) harness and the loadtest publisher both call `gossipsub.publish` directly), so v1 ships inbound-only. A future follow-up that lands a `LocalService::publish_gossip` funnel can add the `direction=out` label without renaming the metric. | ✅ |
| `dds_gossip_messages_dropped_total` | counter | `reason=unadmitted|unknown_topic|decode_error|topic_kind_mismatch` | Pre-decode drops — bumped from the H-12 unadmitted-relayer drop in [`DdsNode::handle_swarm_event`](../dds-node/src/node.rs) and the three early-exit branches of [`DdsNode::handle_gossip_message`](../dds-node/src/node.rs) (`unknown_topic` = topic hash not in the local subscription set; `decode_error` = `GossipMessage::from_cbor` rejected the payload; `topic_kind_mismatch` = decoded variant did not match the topic family). The catalog originally named the labels `unadmitted|invalid_token|duplicate|backpressure`; the latter three describe *post-decode* drop conditions inside the `ingest_*` paths and are already covered by `dds_audit_entries_total{action=*.rejected}` (signature / validation / duplicate-JTI rejections all funnel through the audit chain), so v1 partitions the pre-decode surface only. A future follow-up that wires a gossipsub backpressure hook can add `reason=backpressure` without renaming the metric. | ✅ |
| `dds_sync_pulls_total` | counter | `result=ok|fail` | Outbound anti-entropy pull outcomes — bumped from the resolution branches of [`DdsNode::handle_sync_event`](../dds-node/src/node.rs). `ok` = admitted peer's `Message::Response` was processed by `handle_sync_response` (zero payloads still counts as `ok` — the pull resolved, the network simply converged). `fail` = `OutboundFailure` event (timeout / connection closed / dial failure / codec error) or the H-12 unadmitted-peer response drop (response received but the peer is no longer in `admitted_peers`, so its payloads are discarded without applying any state). Per-peer cooldown skips inside `try_sync_with` are *not* counted — no request goes on the wire so there is no outcome to partition. Inbound responder-side outcomes are not counted; a future `dds_sync_serves_total{result}` family would split those out without renaming this metric. | ✅ |
| `dds_sync_lag_seconds` | histogram | — | Time from peer's op timestamp to local apply — **landed 2026-05-02 follow-up #46** (see status header). Hand-rolled histogram (buckets 1s–86400s) in [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs); bumped from [`DdsNode::handle_sync_response`](../dds-node/src/node.rs) after pre-apply filtering via [`record_sync_lag_seconds`]. | ✅ |
| `dds_sync_payloads_rejected_total` | counter | `reason=legacy_v1|publisher_capability|publisher_identity|replay_window|signature|duplicate_jti|graph` | Pre-apply skip sites inside [`DdsNode::handle_sync_response`](../dds-node/src/node.rs): `legacy_v1` = M-1/M-2 wire-version-1 token guard tripped while `network.allow_legacy_v1_tokens=false`; `publisher_capability` = C-3 filter — issuer lacks the matching `dds:policy-publisher-*` / `dds:software-publisher` capability vouch (same gate `node::publisher_capability_ok` runs on the gossip path); `publisher_identity` = SC-5 Phase B.1 fail-closed — `SoftwareAssignment.publisher_identity` is present but malformed (empty Authenticode subject, wrong-shape SHA-1 thumbprint, wrong-shape Apple Team ID); same gate `node::software_publisher_identity_ok` runs on the gossip path with `*.rejected` audit reason `publisher-identity-invalid`; `replay_window` = M-9 revoke/burn replay-window guard (catalog `window`). Post-apply categorical reasons returned by [`apply_sync_payloads_with_graph`](../dds-net/src/sync.rs) through the new [`SyncResult::rejected_by_reason`](../dds-net/src/sync.rs) field: `signature` = `Token::validate()` rejected the token (ed25519 signature / issuer-binding); `duplicate_jti` = trust graph rejected the token as a same-JTI duplicate (B-1 replay indicator); `graph` = every other `TrustError` from `TrustGraph::add_token` (`IdentityBurned`, `Unauthorized`, `VouchHashMismatch`, `NoValidChain`, `ChainTooDeep`, graph-layer `TokenValidation`). Decode failures (token / op CBOR), store-side write failures, and DAG missing-deps tally still flow into `SyncResult.errors` for diagnostic logging but are *not* partitioned through this counter — they are either corruption signals or transient store-layer failures already covered by `dds_store_writes_total{result=fail}`. Sync-applied post-apply rejections do *not* hit `dds_audit_entries_total` today (no audit emission inside the sync apply path), so this counter is the only signal an operator gets for sync-vs-gossip post-apply rejection rate parity. | ✅ |
| **Trust graph** | | | | |
| `dds_trust_graph_attestations` | gauge | `body_type=user-auth-attestation\|device-join\|windows-policy\|macos-policy\|macos-account-binding\|sso-identity-link\|software-assignment\|service-principal\|session\|unknown` | Active attestation tokens (renamed from `dds_attestations_total` — Prom convention reserves `_total` for counters). Partitioned by [`payload.body_type`](../dds-core/src/token.rs) mapped through the fixed [`dds_domain::body_types`](../dds-domain/src/lib.rs) catalog into a short label name (the `dds:` URI prefix is stripped). Tokens whose `body_type` is `None` or outside the catalog land in `body_type="unknown"` so the partition is total — `sum(dds_trust_graph_attestations) == previous_unlabeled_total`. Cardinality is bounded by the nine catalog constants plus `unknown` (10 values total). The catalog originally named `kind=user\|device\|service`; the `body_type` vocabulary is preferred because the catalog entries do not collapse cleanly to those three buckets (`windows-policy` / `software-assignment` are neither user nor device nor service). A future follow-up can land an additional aggregation label on top of `body_type` without renaming the metric. | ✅ |
| `dds_trust_graph_vouches` | gauge | — | Active vouch tokens | ✅ |
| `dds_trust_graph_revocations` | gauge | — | Currently tracked revoked JTIs (renamed from `dds_attestations_revoked_total` — semantically a current-state gauge, not a since-boot counter) | ✅ |
| `dds_trust_graph_burned` | gauge | — | Burned identity URNs (renamed from `dds_burned_identities_total`) | ✅ |
| `dds_purpose_lookups_total` | counter | `result=ok|denied` | `has_purpose` outcomes — bumped from [`LocalService::has_purpose_observed`](../dds-node/src/service.rs) at the five capability gates (`device_targeting_facts_gated`, `list_applicable_windows_policies`, `list_applicable_macos_policies`, `list_applicable_software`, `admin_vouch`) plus the gossip-ingest publisher gate `node::publisher_capability_ok`. The catalog originally named a third bucket `result=not_found`; partitioning denied further would require an extra trust-graph traversal per call site (the underlying [`TrustGraph::has_purpose`](../dds-core/src/trust.rs) returns `bool`), so v1 collapses the no-attestation case into `denied`. A future follow-up can introduce a `has_purpose_with_outcome` API on the graph and split the bucket without renaming the metric. | ✅ |
| **FIDO2 / sessions** | | | | |
| `dds_fido2_assertions_total` | counter | `result=ok|signature|rp_id|up|sign_count|other` | Assertion outcomes — bumped from the drop-guarded single-exit funnel in [`LocalService::verify_assertion_common`](../dds-node/src/service.rs) consumed by both `issue_session_from_assertion` (the `/v1/session/assert` HTTP path) and `admin_vouch`. `result="ok"` is set immediately before the `Ok(...)` return; `signature` covers `Fido2Error::BadSignature` from the cryptographic verify; `rp_id` covers the `parsed.rp_id_hash != SHA-256(enrolled_rp_id)` check; `up` covers the User-Present flag check; `sign_count` covers `StoreError::SignCountReplay`. The catalog originally named a `result=uv` bucket; `verify_assertion_common` does *not* currently gate on the User-Verified flag (UV is reported through `CommonAssertionOutput::user_verified` but never causes a reject), so v1 ships without `uv` — once a UV-required gate lands a future follow-up can split it out without renaming the metric. The `result=other` catch-all (added vs. the original catalog) collapses every non-named error exit — challenge invalid / expired, clientDataJSON parse / type / origin / challenge / cross-origin mismatches, `client_data_hash` ↔ clientDataJSON SHA-256 mismatch, wall-clock-regression precheck, credential-lookup miss, COSE-key parse failure, trust-graph lock poisoning, generic `Fido2Error::Format` / `KeyError` from `verify_assertion`, and store errors on `bump_sign_count` — so the per-attempt total equals one bump per assertion attempt. | ✅ |
| `dds_fido2_attestation_verify_total` | counter | `result=ok|fail, fmt=packed|none|unknown` | Enrollment-time verify — bumped from the shared [`LocalService::verify_attestation_observed`](../dds-node/src/service.rs) helper after every call to [`dds_domain::fido2::verify_attestation`] in [`LocalService::enroll_user`](../dds-node/src/service.rs) and [`LocalService::admin_setup`](../dds-node/src/service.rs). The credential-lookup re-parse inside `verify_assertion_common` does *not* go through the helper because the catalog row scopes the counter to enrollment-time only. The catalog originally named `fmt=packed|none|tpm`; the TPM bucket is forward-looking — the domain verifier today rejects TPM (and every other non-packed/non-none format) with `Fido2Error::Unsupported(format!("fmt={other}"))`, so v1 collapses TPM and every other unsupported format into `result=fail, fmt=unknown`. The `unknown` bucket also covers failures that reject before `fmt` is parsed (CBOR decode error, missing `fmt` field). A future follow-up that lands a TPM verifier can split out `fmt=tpm` without renaming the metric. Outcome buckets that fire *after* `verify_attestation` returns Ok (the AAGUID allow-list, the per-AAGUID attestation-root gate, the downstream `rp_id` hash equality check) are *not* counted as `fail` because the underlying verify itself succeeded; those gates surface through `dds_audit_entries_total{action=*.rejected}` instead. | ✅ |
| `dds_sessions_issued_total` | counter | `via=fido2|legacy` | Session minting — bumped at the tail of [`LocalService::issue_session`](../dds-node/src/service.rs) (`legacy`) and [`LocalService::issue_session_from_assertion`](../dds-node/src/service.rs) (`fido2`) after the session token is signed and CBOR-encoded successfully; the two entry points share a private inner helper so a FIDO2-driven session bumps `fido2` exactly once and does not also tick `legacy`. The unauthenticated `POST /v1/session` HTTP route was removed in the security review (see [security-gaps.md](../security-gaps.md)), so production `via="legacy"` traffic is now expected to be zero — non-zero rate is the regression signal. | ✅ |
| `dds_challenges_outstanding` | gauge | — | Live challenges (B-5 cap reference) — scrape-time read of [`ChallengeStore::count_challenges`](../dds-store/src/traits.rs) under the existing `LocalService` lock; counts live + expired-but-not-yet-swept rows (the [`expiry`](../dds-node/src/expiry.rs) sweeper clears expired rows on its own cadence). | ✅ |
| **Audit** | | | | |
| `dds_audit_entries_total` | counter | `action` | Per-action emission rate | ✅ |
| `dds_audit_chain_length` | gauge | — | Local chain entry count | ✅ |
| `dds_audit_chain_head_age_seconds` | gauge | — | `now - last_entry.timestamp` (alert if > N) | ✅ |
| **Storage** | | | | |
| `dds_store_bytes` | gauge | `table=tokens|revoked|burned|operations|audit_log|challenges|credential_state` | Per-redb-table stored-byte gauge — scrape-time read of [`dds_store::traits::StoreSizeStats::table_stored_bytes`](../dds-store/src/traits.rs) through [`LocalService::store_byte_sizes`](../dds-node/src/service.rs). RedbBackend opens a single read transaction and pulls `redb::TableStats::stored_bytes()` per table (the actual stored payload, excluding metadata and fragmentation overhead); MemoryBackend returns an empty map so harnesses / tests scrape a discoverable family with no series. The `table` label vocabulary is fixed by the seven redb `TableDefinition` constants in [`dds-store/src/redb_backend.rs`](../dds-store/src/redb_backend.rs). | ✅ |
| `dds_store_writes_total` | counter | `result=ok|conflict|fail` | Per-result store write-transaction outcome counter — scrape-time read of [`dds_store::traits::StoreWriteStats::store_write_counts`](../dds-store/src/traits.rs) through [`LocalService::store_write_counts`](../dds-node/src/service.rs). Backends keep three monotonic `AtomicU64` counters (one per [`WriteOutcome`] bucket) bumped from every write-path method exit. `result="ok"` counts committed writes that changed state; `result="conflict"` counts caller-visible domain rejections aborted before commit (`put_operation` duplicate id returning `Ok(false)`, `bump_sign_count` `SignCountReplay`); `result="fail"` collects every other unsuccessful write — redb plumbing (open / begin / commit / open_table / insert / remove failure), ciborium serialization, and audit chain break (`StoreError::Serde("audit chain break: …")`). v1 collapses the chain-break path into `fail` because `StoreError` does not yet have a `Conflict` variant; a future trait change can split the bucket without renaming the metric. The renderer always emits all three value lines (zero-initialised) so the family is discoverable on a fresh node before any write has happened. | ✅ |
| **HTTP API** | | | | |
| `dds_http_requests_total` | counter | `route, method, status` | Route-level traffic — bumped from the `route_layer`-applied [`http_request_observer_middleware`](../dds-node/src/http.rs) wired into the merged production router built by [`crate::http::router`](../dds-node/src/http.rs). The middleware reads `axum::extract::MatchedPath` from the per-route handler stack (DDS has no path parameters today, so the matched template equals the literal URI path), captures the method, then bumps once with the inner handler's status code on the way out. Unmatched 404s served by the default fallback are *not* counted because `route_layer` does not wrap the fallback — operators read the un-routed call rate off `dds_http_caller_identity_total`. The route layer sits inside the outer `caller_identity_observer_middleware` / `rate_limit_middleware` / `DefaultBodyLimit` stack, so requests rejected before they reach a matched handler (rate-limited 429s, body-too-big 413s) do not bump this counter — those remain visible only via `dds_http_caller_identity_total`. | ✅ |
| `dds_http_request_duration_seconds` | histogram | `route, method` | Latency — sibling of the `dds_http_requests_total` counter — **landed 2026-05-02 follow-up #46** (see status header). Hand-rolled histogram (buckets 5ms–5s) in [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs); bumped from [`http_request_observer_middleware`](../dds-node/src/http.rs) via [`record_http_request_duration`] using `Instant::elapsed()`. | ✅ |
| `dds_http_caller_identity_total` | counter | `kind=anonymous|uds|pipe|admin` | Who's calling — surfaces accidental loopback-TCP regressions; transport buckets (anonymous/uds/pipe) partition the request count, `admin` is bumped orthogonally when the caller passes the admin policy | ✅ |
| **Process** | | | | |
| `dds_memory_resident_bytes` | gauge | — | Process RSS in bytes — scrape-time read of [`sysinfo::Process::memory`](https://docs.rs/sysinfo/0.32/sysinfo/struct.Process.html#method.memory) for our own pid via the private `process_resident_bytes()` helper in [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs). On Linux this is `RSS` from `/proc/<pid>/status`; on macOS `task_info` `MACH_TASK_BASIC_INFO`; on Windows the working set from `K32GetProcessMemoryInfo`. Read failures (sandbox, transient race) degrade to 0; the family's `# HELP` / `# TYPE` headers always ship so the catalog stays discoverable. | ✅ |
| `dds_thread_count` | gauge | — | OS thread count — read at scrape time through the private [`process_thread_count()`](../dds-node/src/telemetry.rs) helper alongside the memory-resident-bytes shim. Linux parses the `Threads:` line out of `/proc/self/status`; macOS calls [`libc::proc_pidinfo`] with `PROC_PIDTASKINFO` and reads `pti_threadnum`; Windows walks a `TH32CS_SNAPTHREAD` snapshot via [`Thread32First`/`Thread32Next`] filtered to the current pid. Read failures (sandbox restrictions, transient race) and unsupported targets degrade to 0; the family's `# HELP` / `# TYPE` headers always ship so the catalog stays discoverable. | ✅ |

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

Active storage-tier rule (group `dds-storage`, landed follow-up #39):
- `DdsStoreWriteFailures` — fires on
  `rate(dds_store_writes_total{result!="ok"}[5m]) > 0` for 5 m.
  `result="conflict"` and `result="fail"` are partitioned at the
  metric so operators can split the rule into a hard-fail critical
  and a soft-conflict warning if their fleet shows a non-trivial
  background conflict rate; v1 keeps a single rule.

Active network-tier rules (group `dds-network`, landed follow-up #43):
- `DdsAdmissionFailureSpike` — fires on
  `rate(dds_admission_handshakes_total{result="fail"}[5m]) > 0` for
  5 m. Covers the four hard-error branches of
  [`DdsNode::verify_peer_admission`](../dds-node/src/node.rs)
  (missing cert / decode error / clock read error / cert verify
  rejected on signature, domain id, peer id, or expiry); the
  `result="revoked"` bucket is excluded because revoked peers
  legitimately try to rejoin and a non-zero rate there is normal
  background noise.
- `DdsSyncRejectsSpike` — fires on
  `rate(dds_sync_payloads_rejected_total[5m]) > 0` for 5 m. Any
  non-zero rate across the six reason buckets (`legacy_v1`,
  `publisher_capability`, `replay_window`, `signature`,
  `duplicate_jti`, `graph`) is suspicious; per-reason troubleshooting
  is in the rule annotations.

Active FIDO2-tier rule (group `dds-fido2`, landed follow-up #43):
- `DdsFido2AssertionFailureSpike` — fires on
  `rate(dds_fido2_assertions_total{result!="ok"}[5m]) > 0` for 5 m.
  Covers the five non-`ok` buckets (`signature`, `rp_id`, `up`,
  `sign_count`, `other`); operators wanting a per-bucket severity
  split can partition the rule by `result=` label without renaming
  it.

All Phase E reference rules are now active (follow-up #47):
- `DdsSyncLagHigh` — activated in new `dds-sync-lag` group (follow-up
  #47). `dds_sync_lag_seconds` histogram landed follow-up #46; rule
  fires when p99 sync lag > 60s for 10 min.

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
  & admin actions, apply outcomes, an aggregate rejection-ratio
  panel matching the `DdsAuditRejectionSpike` alert, plus three
  FIDO2-tier panels keyed off the Phase C catalog metrics shipped in
  follow-ups #27 / #33 / #34: assertion outcomes
  (`dds_fido2_assertions_total{result}`, the five non-`ok` result
  buckets coloured red and tracked by `DdsFido2AssertionFailureSpike`),
  attestation verify (`dds_fido2_attestation_verify_total{result, fmt}`,
  partitioned by result × fmt so an operator can spot AAGUID
  allow-list / unsupported-format rejection waves), and session
  minting (`dds_sessions_issued_total{via}`, with `via="legacy"`
  coloured red as the regression signal — production traffic should
  be `fido2`-only after the security review removed the
  unauthenticated `POST /v1/session` route). All ten panels render
  today.

### Phase F — CLI surface for ad-hoc ops ✅

**Status: landed 2026-04-26 follow-up #21.** All four subcommands
shipped. The two originally-deferred rows (`store bytes` and
`last admission failure`) are now both closed via the
`dds_store_bytes{table=...}` and
`dds_admission_handshake_last_failure_seconds` gauges plumbed through
`/v1/status` so the CLI does not have to scrape `/metrics`.

Subcommands added to `dds-cli`:

| Command | Status | Purpose |
|---|---|---|
| `dds-cli stats` | ✅ | Composes `/v1/status` + `/v1/audit/entries` into one snapshot — peer ID + uptime, connected peers, trust-graph + store sizes, **per-redb-table store bytes** (the same `dds_store_bytes{table=...}` snapshot the Prometheus gauge reads, plumbed through `/v1/status` so the CLI does not have to scrape `/metrics`), **last admission failure timestamp + age** (the same `dds_admission_handshake_last_failure_seconds` gauge, plumbed through `/v1/status::last_admission_failure_ts`), audit chain length + head age + head action. Pretty-prints by default; `--format json` emits a single JSON object for scripting / Prometheus textfile fallbacks. The text output draws `(unsupported)` for older nodes that omit the store-bytes field and `(none)` for backends that report an empty map (`MemoryBackend`); the admission section renders `(none since boot)` when no failure has stamped a timestamp yet (fresh process or older node). The JSON output omits the `store.bytes` and `admission.last_failure_ts` keys entirely on older nodes / fresh processes so existing scripts keep parsing. |
| `dds-cli audit tail` | ✅ | (Phase B.1) |
| `dds-cli audit verify` | ✅ | (Phase B.2) |
| `dds-cli audit export` | ✅ | One-shot range dump — `--since` / `--until` / `--action` filters, `--out <file>` for incident-response bundles, otherwise stdout. Output formats: `jsonl` (canonical, default), `cef` (ArcSight / Splunk single line), `syslog` (RFC 5424 with the audit fields in STRUCTURED-DATA `dds@32473`). Each line is verified locally before emission so a tampered entry surfaces as `sig_ok=false` rather than being silently trusted. |
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
  in the [Monitoring and Diagnostics](DDS-Admin-Guide.md#monitoring-and-diagnostics)
  section of the Admin Guide alongside `dds stats` / `dds health` /
  the reference dashboards & alert rules.
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
