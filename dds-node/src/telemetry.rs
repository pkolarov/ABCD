//! Prometheus `/metrics` endpoint — observability-plan.md Phase C
//! (audit-metrics subset).
//!
//! Exposes a small textual Prometheus exposition served on a separate
//! listener so operators can:
//!
//! - Scope Prometheus scrape ACLs without touching the API listener.
//! - Bind the metrics endpoint to `0.0.0.0` for fleet scrape without
//!   widening the API surface.
//!
//! Default `metrics_addr` in [`crate::config::NetworkConfig`] is
//! `None` — the endpoint is opt-in. When set (e.g.
//! `metrics_addr = "127.0.0.1:9495"`), [`crate::main`] spawns a
//! second axum server alongside the API listener.
//!
//! ## Metric catalog (this PR)
//!
//! Per the plan §4 Phase C.3 the audit subset (#22) plus the HTTP
//! caller-identity subset (this PR) ship; the rest of the catalog
//! (network / FIDO2 / store / process) remains deferred because each
//! block still requires its own call-site instrumentation pass.
//!
//! | Metric | Type | Labels | Source |
//! |---|---|---|---|
//! | `dds_build_info` | gauge | `version` | static, always 1 |
//! | `dds_uptime_seconds` | gauge | — | `now - process_start` |
//! | `dds_audit_entries_total` | counter | `action` | bumped by [`record_audit_entry`] |
//! | `dds_audit_chain_length` | gauge | — | [`AuditStore::count_audit_entries`] at scrape |
//! | `dds_audit_chain_head_age_seconds` | gauge | — | `now - head.timestamp` at scrape |
//! | `dds_http_caller_identity_total` | counter | `kind=anonymous\|uds\|pipe\|admin` | bumped by [`record_caller_identity`] |
//! | `dds_sessions_issued_total` | counter | `via=fido2\|legacy` | bumped by [`record_sessions_issued`] |
//! | `dds_purpose_lookups_total` | counter | `result=ok\|denied` | bumped by [`record_purpose_lookup`] |
//! | `dds_admission_handshakes_total` | counter | `result=ok\|fail\|revoked` | bumped by [`record_admission_handshake`] |
//! | `dds_trust_graph_attestations` | gauge | — | [`crate::service::LocalService::trust_graph_counts`] at scrape |
//! | `dds_trust_graph_vouches` | gauge | — | same |
//! | `dds_trust_graph_revocations` | gauge | — | same |
//! | `dds_trust_graph_burned` | gauge | — | same |
//! | `dds_challenges_outstanding` | gauge | — | [`crate::service::LocalService::challenges_outstanding`] at scrape |
//! | `dds_peers_admitted` | gauge | — | [`crate::node::NodePeerCounts::admitted`] refreshed by [`crate::node::DdsNode::refresh_peer_count_gauges`] |
//! | `dds_peers_connected` | gauge | — | [`crate::node::NodePeerCounts::connected`] refreshed at the same call sites |
//!
//! ### `dds_challenges_outstanding` semantics
//!
//! FIDO2 challenges live in the challenge store with an explicit
//! `expires_at` — the [`crate::expiry`] sweeper clears expired rows
//! on its own cadence, so a non-zero gauge between sweeps is normal
//! and a slowly rising baseline tracks request volume. The B-5
//! backstop alarm condition is *unbounded* growth (sweeper jammed,
//! attacker enumerating endpoints to exhaust storage); operators
//! key the alert off `dds_challenges_outstanding > N` for some
//! `N` derived from peak healthy traffic.
//!
//! ### Trust-graph gauges
//!
//! These four gauges report the *current* size of each trust-graph
//! partition under a single [`std::sync::RwLock`] read acquisition (one
//! acquire per scrape — no per-token locking). The catalog in
//! `observability-plan.md` Phase C names the same series with the
//! `dds_attestations_total` / `dds_burned_identities_total` shape;
//! these are gauges of *current* counts, not Prometheus counters, so
//! the rename drops the `_total` suffix to match Prometheus naming
//! conventions (`_total` is reserved for monotonic counters). The
//! plan tracker has been updated accordingly.
//!
//! `kind=user|device|service` partitioning of `dds_trust_graph_attestations`
//! is deferred until the body-type catalog ships a single mapping —
//! today the same `body_type` namespace covers user, device, *and*
//! domain-policy / software-assignment attestations, so a runtime
//! classifier would have to embed knowledge of every body type. A
//! future Phase C follow-up can add the label without changing the
//! metric name.
//!
//! ### `dds_sessions_issued_total` semantics
//!
//! Bumped exactly once per successfully minted session — the bump
//! site is at the tail of the issuance path, after the token has
//! been signed and the CBOR encoded successfully, so a token that
//! never reaches the caller does not advance the counter.
//!
//! - `via="fido2"` — session minted from a verified FIDO2 assertion
//!   via [`crate::service::LocalService::issue_session_from_assertion`]
//!   (the `/v1/session/assert` HTTP path).
//! - `via="legacy"` — session minted via direct
//!   [`crate::service::LocalService::issue_session`] entry without an
//!   accompanying assertion proof. The unauthenticated `POST /v1/session`
//!   HTTP route was removed in the security review (see
//!   [`security-gaps.md`](../../security-gaps.md)), so production
//!   `via="legacy"` traffic is now expected to be zero — a non-zero
//!   baseline indicates an in-process consumer (loadtest harness,
//!   Windows account-claim resolver, etc.) is issuing sessions
//!   without going through the FIDO2 path. Operators key any
//!   regression alarm off
//!   `rate(dds_sessions_issued_total{via="legacy"}[5m]) > 0`.
//!
//! The two entry points share a private inner helper
//! ([`crate::service::LocalService::issue_session_inner`]) so a
//! FIDO2-driven session bumps `fido2` exactly once and does not also
//! tick `legacy`.
//!
//! ### `dds_purpose_lookups_total` semantics
//!
//! Bumped exactly once per `TrustGraph::has_purpose` call funnelled
//! through [`crate::service::LocalService::has_purpose_observed`] —
//! the helper wraps the underlying graph read and partitions the
//! outcome on `ok|denied`. Today the call sites are:
//!
//! - publisher-capability gates inside
//!   [`crate::service::LocalService::list_applicable_windows_policies`],
//!   [`crate::service::LocalService::list_applicable_macos_policies`], and
//!   [`crate::service::LocalService::list_applicable_software`] (the
//!   per-attestation `dds:policy-publisher-*` /
//!   `dds:software-publisher` C-3 filter);
//! - the `dds:device-scope` gate inside
//!   `LocalService::device_targeting_facts_gated`;
//! - the per-purpose admin-vouch capability check inside
//!   `LocalService::admin_vouch`;
//! - the gossip-ingest publisher-capability gate inside
//!   `node::publisher_capability_ok` (the same C-3 filter applied
//!   to inbound attestations carrying a `WindowsPolicyDocument` /
//!   `MacOsPolicyDocument` / `SoftwareAssignment`).
//!
//! `result="ok"` is the grant-granted branch;
//! `result="denied"` is every other return path (subject burned,
//! no matching active vouch / attestation, vch_sum mismatch, expired,
//! revoked, or chain validation failed). The catalog in
//! `observability-plan.md` Phase C names a third bucket
//! `result="not_found"`; partitioning denied further would require an
//! extra trust-graph traversal per call site (the underlying
//! [`dds_core::trust::TrustGraph::has_purpose`] returns `bool`), so
//! v1 collapses the no-attestation case into `denied`. A future
//! follow-up can introduce a `has_purpose_with_outcome` API on the
//! graph and split the bucket without renaming the metric.
//!
//! ### `dds_peers_admitted` / `dds_peers_connected` semantics
//!
//! Two gauges sourced from a shared [`crate::node::NodePeerCounts`]
//! handle (two `Arc<AtomicU64>`). The swarm task is the *only* writer:
//! [`crate::node::DdsNode::refresh_peer_count_gauges`] re-reads
//! `admitted_peers.len()` and `swarm.connected_peers().count()` after
//! every `ConnectionEstablished` / `ConnectionClosed` event and after
//! every successful inbound H-12 admission handshake (the success
//! branch of [`crate::node::DdsNode::verify_peer_admission`]). The
//! metrics scrape reads two `Relaxed` atomics with no lock acquisition.
//!
//! Operators compute the *unadmitted share* as
//! `dds_peers_connected - dds_peers_admitted`. Sustained non-zero
//! delta is the H-12 cert-pipeline-stall signal (peer reachable on
//! libp2p but never made it through admission), distinct from the
//! `dds_admission_handshakes_total{result="fail"}` rate which counts
//! verify-rejected events. A peer that connects, fails verify, and
//! disconnects shows in the counter; one that connects and never
//! responds to the admission request shows in the gauge delta.
//!
//! When the metrics endpoint is started without a node handle (in
//! tests, harnesses, or deployments running only the HTTP API), both
//! gauges report zero but the `# HELP` / `# TYPE` headers still ship
//! so the families remain discoverable in the catalog.
//!
//! ### `dds_admission_handshakes_total` semantics
//!
//! Bumped exactly once per inbound H-12 admission handshake response
//! processed by [`crate::node::DdsNode::verify_peer_admission`] (i.e.
//! per remote-peer attempt to admit *us* into the domain), partitioned
//! by outcome:
//!
//! - `result="ok"` — peer's admission cert verified against our
//!   domain pubkey + domain id and the peer is now in
//!   `admitted_peers`.
//! - `result="revoked"` — peer is on our local admission revocation
//!   list (`admission_revocations`); the cert is rejected before any
//!   signature work runs.
//! - `result="fail"` — every other early-exit branch: the peer
//!   returned no cert, the cert failed CBOR decode, the local clock
//!   read failed, or `AdmissionCert::verify` rejected the cert
//!   (signature / domain-id / peer-id / expiry mismatch).
//!
//! `sum(rate(...))` therefore tracks the total inbound-handshake rate
//! for this node; a non-zero `revoked` rate is an operator signal
//! that previously-admitted peers are still attempting to rejoin
//! after a revocation, and a non-zero `fail` rate is the regression
//! tripwire that the domain-key / cert-issuance pipeline has drifted.
//!
//! Outbound-side handshake initiation is *not* counted here — the
//! caller is the node itself and the metric would be redundant with
//! the libp2p connection counter.
//!
//! ### `dds_http_caller_identity_total` semantics
//!
//! Each completed HTTP request bumps **two** buckets — its transport
//! kind, plus `admin` when the caller passes
//! `CallerIdentity::is_admin(&policy)`. So
//! `sum(rate(...{kind=~"anonymous|uds|pipe"}))` equals the total
//! request rate while `kind="admin"` is an orthogonal refinement.
//! [`crate::http::classify_caller_identity`] returns the transport
//! kind; [`crate::http::caller_identity_observer_middleware`] is
//! responsible for bumping `admin` separately.
//!
//! - `anonymous` — `CallerIdentity::Anonymous` (no peer credentials,
//!   i.e. loopback TCP). The expected bulk of post-cutover traffic
//!   should be `uds` / `pipe`; any `anonymous` baseline indicates
//!   loopback TCP is still in use, which is the
//!   `DdsLoopbackTcpAdminUsed` H-7 cutover regression signal.
//! - `uds` — UDS transport.
//! - `pipe` — named-pipe transport.
//! - `admin` — orthogonal: a caller (any transport) that
//!   `is_admin(policy)` returns `true` for. Useful for separating
//!   admin traffic share without re-keying the alert.
//!
//! [`record_audit_entry`] is called from the two audit-emit funnels —
//! [`crate::service::LocalService::emit_local_audit`] and
//! [`crate::node::DdsNode::emit_local_audit_with_reason`] — *after*
//! the redb append succeeds. A failed append does not bump the
//! counter so `dds_audit_entries_total` matches the on-disk chain.
//!
//! No external metrics crate is used. The plan suggested
//! `metrics-exporter-prometheus`, but for the audit subset a few
//! atomic counters and a hand-rolled exposition keep the dependency
//! graph small. When the rest of the catalog lands the exporter
//! crate becomes worth its cost (histograms, label-set hashing) and
//! this module will be folded into it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use dds_store::traits::{
    AuditStore, ChallengeStore, CredentialStateStore, RevocationStore, TokenStore,
};

use crate::http::SharedService;
use crate::node::NodePeerCounts;
use crate::service::TrustGraphCounts;

/// Process-global telemetry handle. Initialised once at process start
/// (idempotent) so call-sites do not need to thread the handle
/// through the swarm event loop or every HTTP handler.
static TELEMETRY: OnceLock<Arc<Telemetry>> = OnceLock::new();

/// In-process counters backing the Prometheus exposition. Holds a
/// per-action audit counter, a per-caller-kind HTTP counter, and a
/// process-start instant; the rest of the Phase C catalog will land
/// on this struct.
pub struct Telemetry {
    /// `now - start_at` is the `dds_uptime_seconds` gauge value.
    start_at: SystemTime,
    /// Per-action audit-emission counts. Bounded cardinality — the
    /// action vocabulary is fixed by `observability-plan.md` §4 Phase
    /// A.
    audit_entries: Mutex<BTreeMap<String, u64>>,
    /// Per-kind HTTP-caller-identity counts. Kind is one of
    /// `anonymous|uds|pipe|admin` — bounded by
    /// [`crate::http::classify_caller_identity`].
    caller_identity: Mutex<BTreeMap<String, u64>>,
    /// Per-`via` session-issuance counts. `via` is one of
    /// `fido2|legacy` — bounded by the two
    /// [`crate::service::LocalService`] entry points
    /// (`issue_session_from_assertion` → `fido2`,
    /// `issue_session` → `legacy`).
    sessions_issued: Mutex<BTreeMap<String, u64>>,
    /// Per-`result` purpose-lookup counts. `result` is one of
    /// `ok|denied` — bounded by
    /// [`crate::service::LocalService::has_purpose_observed`].
    purpose_lookups: Mutex<BTreeMap<String, u64>>,
    /// Per-`result` admission-handshake counts. `result` is one of
    /// `ok|fail|revoked` — bounded by the three outcome branches of
    /// [`crate::node::DdsNode::verify_peer_admission`].
    admission_handshakes: Mutex<BTreeMap<String, u64>>,
}

impl Telemetry {
    fn new() -> Self {
        Self {
            start_at: SystemTime::now(),
            audit_entries: Mutex::new(BTreeMap::new()),
            caller_identity: Mutex::new(BTreeMap::new()),
            sessions_issued: Mutex::new(BTreeMap::new()),
            purpose_lookups: Mutex::new(BTreeMap::new()),
            admission_handshakes: Mutex::new(BTreeMap::new()),
        }
    }

    fn bump_audit_entry(&self, action: &str) {
        let mut g = match self.audit_entries.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(), // poisoned: a bumped counter is still safer than a panic.
        };
        *g.entry(action.to_string()).or_insert(0) += 1;
    }

    fn audit_entries_snapshot(&self) -> BTreeMap<String, u64> {
        match self.audit_entries.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_audit_entries_total{action=...}`. Public
    /// so test code can take before/after snapshots without scraping
    /// the renderer; used by the
    /// `service::tests::audit_emit_advances_telemetry_counter` test.
    pub fn audit_entries_count(&self, action: &str) -> u64 {
        match self.audit_entries.lock() {
            Ok(g) => g.get(action).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(action).copied().unwrap_or(0),
        }
    }

    fn bump_caller_identity(&self, kind: &str) {
        let mut g = match self.caller_identity.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(kind.to_string()).or_insert(0) += 1;
    }

    fn caller_identity_snapshot(&self) -> BTreeMap<String, u64> {
        match self.caller_identity.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_http_caller_identity_total{kind=...}`.
    /// Public so integration tests can assert without scraping.
    pub fn caller_identity_count(&self, kind: &str) -> u64 {
        match self.caller_identity.lock() {
            Ok(g) => g.get(kind).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(kind).copied().unwrap_or(0),
        }
    }

    fn bump_sessions_issued(&self, via: &str) {
        let mut g = match self.sessions_issued.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(via.to_string()).or_insert(0) += 1;
    }

    fn sessions_issued_snapshot(&self) -> BTreeMap<String, u64> {
        match self.sessions_issued.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_sessions_issued_total{via=...}`. Public
    /// so the `LocalService` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn sessions_issued_count(&self, via: &str) -> u64 {
        match self.sessions_issued.lock() {
            Ok(g) => g.get(via).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(via).copied().unwrap_or(0),
        }
    }

    fn bump_purpose_lookup(&self, result: &str) {
        let mut g = match self.purpose_lookups.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn purpose_lookups_snapshot(&self) -> BTreeMap<String, u64> {
        match self.purpose_lookups.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_purpose_lookups_total{result=...}`.
    /// Public so the `LocalService` regression tests can take
    /// before/after snapshots without scraping the renderer.
    pub fn purpose_lookups_count(&self, result: &str) -> u64 {
        match self.purpose_lookups.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_admission_handshake(&self, result: &str) {
        let mut g = match self.admission_handshakes.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn admission_handshakes_snapshot(&self) -> BTreeMap<String, u64> {
        match self.admission_handshakes.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_admission_handshakes_total{result=...}`.
    /// Public so the `DdsNode` regression tests can take
    /// before/after snapshots without scraping the renderer.
    pub fn admission_handshakes_count(&self, result: &str) -> u64 {
        match self.admission_handshakes.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.start_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Initialise the process-global telemetry handle. Idempotent: the
/// second call returns the existing handle. Returned `Arc` lets the
/// caller keep a reference for tests or composition.
pub fn install() -> Arc<Telemetry> {
    TELEMETRY.get_or_init(|| Arc::new(Telemetry::new())).clone()
}

/// Bump `dds_audit_entries_total{action=...}` by one. No-op when
/// telemetry has not been installed (tests, harnesses) so audit
/// emission paths remain side-effect-free in fixture code.
pub fn record_audit_entry(action: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_audit_entry(action);
    }
}

/// Bump `dds_http_caller_identity_total{kind=...}` by one. Called
/// from [`crate::http::caller_identity_observer_middleware`] for
/// every request the API listener serves. No-op when telemetry has
/// not been installed (tests, harnesses).
pub fn record_caller_identity(kind: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_caller_identity(kind);
    }
}

/// Bump `dds_sessions_issued_total{via=...}` by one. Called from
/// [`crate::service::LocalService`] after a session token is signed
/// successfully. `via` is one of `fido2|legacy`. No-op when
/// telemetry has not been installed (tests, harnesses).
pub fn record_sessions_issued(via: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_sessions_issued(via);
    }
}

/// Bump `dds_purpose_lookups_total{result=...}` by one. Called from
/// [`crate::service::LocalService::has_purpose_observed`] after each
/// `TrustGraph::has_purpose` call. `result` is one of `ok|denied`.
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_purpose_lookup(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_purpose_lookup(result);
    }
}

/// Bump `dds_admission_handshakes_total{result=...}` by one. Called
/// from [`crate::node::DdsNode::verify_peer_admission`] at every
/// outcome branch of an inbound H-12 admission handshake. `result` is
/// one of `ok|fail|revoked`. No-op when telemetry has not been
/// installed (tests, harnesses).
pub fn record_admission_handshake(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_admission_handshake(result);
    }
}

/// Render the Prometheus textual exposition for the current state.
///
/// `chain_length` and `head_timestamp` are passed in by the caller
/// because they require an `AuditStore` lock and the lock is owned by
/// the `LocalService` mutex. `trust_graph` carries the four
/// `dds_trust_graph_*` gauges read under the trust-graph `RwLock` —
/// `None` means the lock was poisoned (or in tests, intentionally
/// omitted) and the renderer falls back to zeroes.
/// `challenges_outstanding` carries the FIDO2 challenge-store row
/// count read under the same `LocalService` lock; `None` means the
/// store read failed and the renderer reports zero rather than
/// panicking the scrape task. `peer_counts` carries the
/// `dds_peers_admitted` + `dds_peers_connected` gauges read from the
/// shared [`NodePeerCounts`] snapshot updated by the swarm task; `None`
/// means the metrics endpoint was started without a node handle (in
/// tests, or in deployments where only the HTTP API is wired) and both
/// gauges report zero.
/// Keeping the lock acquisition in the caller avoids forcing a
/// `where` bound on this function.
fn render_exposition(
    telemetry: &Telemetry,
    chain_length: usize,
    head_timestamp: Option<u64>,
    trust_graph: Option<TrustGraphCounts>,
    challenges_outstanding: Option<usize>,
    peer_counts: Option<&NodePeerCounts>,
) -> String {
    let mut out = String::with_capacity(1024);

    // `dds_build_info` — static fingerprint, always 1.
    out.push_str("# HELP dds_build_info DDS node build fingerprint (always 1).\n");
    out.push_str("# TYPE dds_build_info gauge\n");
    out.push_str(&format!(
        "dds_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    // `dds_uptime_seconds`.
    out.push_str("# HELP dds_uptime_seconds Seconds since dds-node process start.\n");
    out.push_str("# TYPE dds_uptime_seconds gauge\n");
    out.push_str(&format!(
        "dds_uptime_seconds {}\n",
        telemetry.uptime_seconds()
    ));

    // `dds_audit_entries_total` — per-action counter.
    out.push_str(
        "# HELP dds_audit_entries_total Audit-log entries appended since process start, \
         partitioned by action.\n",
    );
    out.push_str("# TYPE dds_audit_entries_total counter\n");
    let snapshot = telemetry.audit_entries_snapshot();
    if snapshot.is_empty() {
        // Prometheus tolerates an empty family; we still emit the
        // HELP/TYPE lines so the family is discoverable in the
        // catalog before the first audit emission.
    } else {
        for (action, count) in snapshot.iter() {
            out.push_str(&format!(
                "dds_audit_entries_total{{action=\"{}\"}} {}\n",
                escape_label_value(action),
                count
            ));
        }
    }

    // `dds_audit_chain_length`.
    out.push_str("# HELP dds_audit_chain_length Number of entries in the local audit chain.\n");
    out.push_str("# TYPE dds_audit_chain_length gauge\n");
    out.push_str(&format!("dds_audit_chain_length {chain_length}\n"));

    // `dds_audit_chain_head_age_seconds`.
    out.push_str(
        "# HELP dds_audit_chain_head_age_seconds Seconds since the last audit-chain entry was \
         appended. Empty chain reports 0.\n",
    );
    out.push_str("# TYPE dds_audit_chain_head_age_seconds gauge\n");
    let head_age = match head_timestamp {
        Some(ts) => {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_sub(ts)
        }
        None => 0,
    };
    out.push_str(&format!("dds_audit_chain_head_age_seconds {head_age}\n"));

    // Trust-graph gauges — read under a single RwLock acquisition by
    // the caller. `None` means the lock was poisoned; degrade to 0
    // rather than panicking the scrape task.
    let tg = trust_graph.unwrap_or_default();
    out.push_str(
        "# HELP dds_trust_graph_attestations Active attestation tokens currently in the trust graph.\n",
    );
    out.push_str("# TYPE dds_trust_graph_attestations gauge\n");
    out.push_str(&format!(
        "dds_trust_graph_attestations {}\n",
        tg.attestations
    ));
    out.push_str(
        "# HELP dds_trust_graph_vouches Active vouch tokens currently in the trust graph.\n",
    );
    out.push_str("# TYPE dds_trust_graph_vouches gauge\n");
    out.push_str(&format!("dds_trust_graph_vouches {}\n", tg.vouches));
    out.push_str(
        "# HELP dds_trust_graph_revocations Revoked JTIs currently tracked in the trust graph.\n",
    );
    out.push_str("# TYPE dds_trust_graph_revocations gauge\n");
    out.push_str(&format!("dds_trust_graph_revocations {}\n", tg.revocations));
    out.push_str(
        "# HELP dds_trust_graph_burned Burned identity URNs currently tracked in the trust graph.\n",
    );
    out.push_str("# TYPE dds_trust_graph_burned gauge\n");
    out.push_str(&format!("dds_trust_graph_burned {}\n", tg.burned));

    // `dds_peers_admitted` + `dds_peers_connected` — network gauges
    // refreshed by the swarm task in `DdsNode::refresh_peer_count_gauges`
    // on every connection lifecycle event and every successful H-12
    // admission handshake. `peer_counts == None` means the metrics
    // endpoint was started without a node handle (tests, harnesses); we
    // still emit HELP/TYPE so the family is discoverable in the catalog.
    let (peers_admitted, peers_connected) = match peer_counts {
        Some(c) => (
            c.admitted.load(std::sync::atomic::Ordering::Relaxed),
            c.connected.load(std::sync::atomic::Ordering::Relaxed),
        ),
        None => (0, 0),
    };
    out.push_str(
        "# HELP dds_peers_admitted Peers currently admitted to this node's domain (passed an H-12 \
         admission handshake on the live connection).\n",
    );
    out.push_str("# TYPE dds_peers_admitted gauge\n");
    out.push_str(&format!("dds_peers_admitted {peers_admitted}\n"));
    out.push_str(
        "# HELP dds_peers_connected Peers currently libp2p-connected (admitted plus \
         not-yet-handshaked). The unadmitted share is dds_peers_connected - dds_peers_admitted.\n",
    );
    out.push_str("# TYPE dds_peers_connected gauge\n");
    out.push_str(&format!("dds_peers_connected {peers_connected}\n"));

    // `dds_challenges_outstanding` — FIDO2 challenge-store row count.
    // `None` (store read failure) degrades to 0 rather than panic;
    // see the function-level doc for poison-tolerance rationale.
    out.push_str(
        "# HELP dds_challenges_outstanding FIDO2 challenges currently outstanding in the local \
         challenge store (live + expired-but-not-yet-swept). B-5 backstop reference: alert on \
         unbounded growth.\n",
    );
    out.push_str("# TYPE dds_challenges_outstanding gauge\n");
    out.push_str(&format!(
        "dds_challenges_outstanding {}\n",
        challenges_outstanding.unwrap_or(0)
    ));

    // `dds_http_caller_identity_total` — per-kind caller counter.
    out.push_str(
        "# HELP dds_http_caller_identity_total HTTP requests served, by caller kind \
         (anonymous|uds|pipe|admin). Each request bumps its transport bucket \
         (anonymous|uds|pipe) and additionally bumps `admin` when the caller passes \
         the admin-policy check; admin is orthogonal to transport.\n",
    );
    out.push_str("# TYPE dds_http_caller_identity_total counter\n");
    let caller_snapshot = telemetry.caller_identity_snapshot();
    for (kind, count) in caller_snapshot.iter() {
        out.push_str(&format!(
            "dds_http_caller_identity_total{{kind=\"{}\"}} {}\n",
            escape_label_value(kind),
            count
        ));
    }

    // `dds_sessions_issued_total` — per-`via` session-issuance counter.
    out.push_str(
        "# HELP dds_sessions_issued_total Sessions minted since process start, partitioned by \
         issuance path (fido2 = via /v1/session/assert; legacy = direct LocalService::issue_session).\n",
    );
    out.push_str("# TYPE dds_sessions_issued_total counter\n");
    let sessions_snapshot = telemetry.sessions_issued_snapshot();
    for (via, count) in sessions_snapshot.iter() {
        out.push_str(&format!(
            "dds_sessions_issued_total{{via=\"{}\"}} {}\n",
            escape_label_value(via),
            count
        ));
    }

    // `dds_purpose_lookups_total` — per-`result` capability-check counter.
    out.push_str(
        "# HELP dds_purpose_lookups_total TrustGraph::has_purpose calls funnelled through \
         LocalService::has_purpose_observed since process start, partitioned by outcome \
         (ok = grant satisfied; denied = burned subject, no active vouch/attestation, \
         vch_sum mismatch, expired, revoked, or chain validation failed).\n",
    );
    out.push_str("# TYPE dds_purpose_lookups_total counter\n");
    let purpose_snapshot = telemetry.purpose_lookups_snapshot();
    for (result, count) in purpose_snapshot.iter() {
        out.push_str(&format!(
            "dds_purpose_lookups_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_admission_handshakes_total` — per-`result` H-12 inbound
    // handshake counter. Bumped from `DdsNode::verify_peer_admission`
    // at every outcome branch.
    out.push_str(
        "# HELP dds_admission_handshakes_total Inbound H-12 admission handshakes processed since \
         process start, partitioned by outcome (ok = peer admitted; revoked = peer on local \
         admission revocation list; fail = no cert / decode error / clock error / cert verify \
         rejected).\n",
    );
    out.push_str("# TYPE dds_admission_handshakes_total counter\n");
    let admission_snapshot = telemetry.admission_handshakes_snapshot();
    for (result, count) in admission_snapshot.iter() {
        out.push_str(&format!(
            "dds_admission_handshakes_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    out
}

/// Escape a Prometheus label value: backslash, newline, and double
/// quote are the only forbidden characters in the textual exposition.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Serve the `/metrics` endpoint. Binds a TCP listener on `addr`
/// (intended for `127.0.0.1:9495` by default; operators can expose
/// to a scrape network if desired) and responds to `GET /metrics`
/// only — every other path returns 404.
///
/// `peer_counts` carries the swarm-task snapshot of
/// `dds_peers_admitted` + `dds_peers_connected`. Pass `None` when
/// running the metrics endpoint without a [`crate::node::DdsNode`]
/// (tests, harnesses) and both gauges report zero.
///
/// Loops forever; returns `Err` only on bind failure or fatal axum
/// error. The caller spawns this on its own tokio task.
pub async fn serve<S>(
    addr: &str,
    svc: SharedService<S>,
    telemetry: Arc<Telemetry>,
    peer_counts: Option<NodePeerCounts>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
{
    let parsed: SocketAddr = addr
        .parse()
        .map_err(|e| format!("metrics_addr is not a valid TCP socket addr `{addr}`: {e}"))?;
    let listener = tokio::net::TcpListener::bind(parsed).await?;
    tracing::info!(%addr, "metrics endpoint listening on TCP");

    let state = MetricsState {
        svc,
        telemetry,
        peer_counts,
    };
    let app = Router::new()
        .route("/metrics", get(metrics_handler::<S>))
        .with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

struct MetricsState<
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
> {
    svc: SharedService<S>,
    telemetry: Arc<Telemetry>,
    peer_counts: Option<NodePeerCounts>,
}

// Manual `Clone` impl mirrors the pattern in `http::AppState`: a
// derived impl would require `S: Clone`, but the store backends
// (`RedbBackend`, `MemoryBackend`) are non-Clone — the shared handle
// is the `Arc<Mutex<LocalService<S>>>` field, which is what we
// actually need to duplicate per-request.
impl<
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
> Clone for MetricsState<S>
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            telemetry: self.telemetry.clone(),
            peer_counts: self.peer_counts.clone(),
        }
    }
}

async fn metrics_handler<S>(State(state): State<MetricsState<S>>) -> impl IntoResponse
where
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
{
    let (chain_length, head_timestamp, trust_graph, challenges_outstanding) = {
        let svc = state.svc.lock().await;
        let len = svc.audit_chain_length().unwrap_or(0);
        let head = svc.audit_chain_head_timestamp().unwrap_or(None);
        let tg = svc.trust_graph_counts();
        let ch = svc.challenges_outstanding();
        (len, head, tg, ch)
    };
    let body = render_exposition(
        &state.telemetry,
        chain_length,
        head_timestamp,
        trust_graph,
        challenges_outstanding,
        state.peer_counts.as_ref(),
    );
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::sync::RwLock;

    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_core::trust::TrustGraph;
    use dds_store::MemoryBackend;
    use rand::rngs::OsRng;
    use tokio::sync::Mutex as TokioMutex;

    use crate::service::LocalService;

    /// Build a minimal `LocalService` with a memory store, the same
    /// shape used by `http::tests::make_state`. Only used by the
    /// `serve_returns_prometheus_text` integration test below.
    fn make_test_service() -> SharedService<MemoryBackend> {
        let node_ident = Identity::generate("test-node", &mut OsRng);
        let root = Identity::generate("root", &mut OsRng);
        let mut roots = BTreeSet::new();
        roots.insert(root.id.to_urn());
        let mut graph = TrustGraph::new();
        let attest = Token::sign(
            TokenPayload {
                iss: root.id.to_urn(),
                iss_key: root.public_key.clone(),
                jti: "attest-root-tel".into(),
                sub: root.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &root.signing_key,
        )
        .unwrap();
        graph.add_token(attest).unwrap();
        let shared_graph = Arc::new(RwLock::new(graph));
        let svc = LocalService::new(node_ident, shared_graph, roots, MemoryBackend::new());
        Arc::new(TokioMutex::new(svc))
    }

    #[test]
    fn render_includes_build_info_and_uptime_for_empty_telemetry() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("dds_build_info{version=\""));
        assert!(body.contains("} 1\n"));
        assert!(body.contains("# TYPE dds_uptime_seconds gauge\n"));
        assert!(body.contains("# TYPE dds_audit_entries_total counter\n"));
        assert!(body.contains("dds_audit_chain_length 0\n"));
        assert!(body.contains("dds_audit_chain_head_age_seconds 0\n"));
    }

    #[test]
    fn record_audit_entry_advances_per_action_counter_in_render() {
        let t = Telemetry::new();
        t.bump_audit_entry("attest");
        t.bump_audit_entry("attest");
        t.bump_audit_entry("revoke");

        let body = render_exposition(&t, 3, Some(0), None, None, None);
        assert!(body.contains("dds_audit_entries_total{action=\"attest\"} 2\n"));
        assert!(body.contains("dds_audit_entries_total{action=\"revoke\"} 1\n"));
        assert!(body.contains("dds_audit_chain_length 3\n"));
    }

    #[test]
    fn sessions_issued_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_sessions_issued("fido2");
        t.bump_sessions_issued("fido2");
        t.bump_sessions_issued("legacy");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_sessions_issued_total counter\n"));
        assert!(body.contains("dds_sessions_issued_total{via=\"fido2\"} 2\n"));
        assert!(body.contains("dds_sessions_issued_total{via=\"legacy\"} 1\n"));
        assert_eq!(t.sessions_issued_count("fido2"), 2);
        assert_eq!(t.sessions_issued_count("legacy"), 1);
        assert_eq!(t.sessions_issued_count("other"), 0);
    }

    #[test]
    fn sessions_issued_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE must always be emitted so the family is
        // discoverable by Prometheus before the first session is
        // minted; the value lines come once the first bump fires.
        assert!(body.contains("# TYPE dds_sessions_issued_total counter\n"));
        assert!(!body.contains("dds_sessions_issued_total{"));
    }

    #[test]
    fn purpose_lookups_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_purpose_lookup("ok");
        t.bump_purpose_lookup("ok");
        t.bump_purpose_lookup("denied");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_purpose_lookups_total counter\n"));
        assert!(body.contains("dds_purpose_lookups_total{result=\"ok\"} 2\n"));
        assert!(body.contains("dds_purpose_lookups_total{result=\"denied\"} 1\n"));
        assert_eq!(t.purpose_lookups_count("ok"), 2);
        assert_eq!(t.purpose_lookups_count("denied"), 1);
        assert_eq!(t.purpose_lookups_count("not_found"), 0);
    }

    #[test]
    fn purpose_lookups_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first lookup so
        // dashboards / alert expressions resolve the family on a
        // freshly booted node.
        assert!(body.contains("# TYPE dds_purpose_lookups_total counter\n"));
        assert!(!body.contains("dds_purpose_lookups_total{"));
    }

    #[test]
    fn admission_handshakes_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_admission_handshake("ok");
        t.bump_admission_handshake("ok");
        t.bump_admission_handshake("ok");
        t.bump_admission_handshake("fail");
        t.bump_admission_handshake("revoked");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_admission_handshakes_total counter\n"));
        assert!(body.contains("dds_admission_handshakes_total{result=\"ok\"} 3\n"));
        assert!(body.contains("dds_admission_handshakes_total{result=\"fail\"} 1\n"));
        assert!(body.contains("dds_admission_handshakes_total{result=\"revoked\"} 1\n"));
        assert_eq!(t.admission_handshakes_count("ok"), 3);
        assert_eq!(t.admission_handshakes_count("fail"), 1);
        assert_eq!(t.admission_handshakes_count("revoked"), 1);
        assert_eq!(t.admission_handshakes_count("other"), 0);
    }

    #[test]
    fn admission_handshakes_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first inbound
        // handshake fires so a freshly booted node still surfaces
        // the family in the catalog.
        assert!(body.contains("# TYPE dds_admission_handshakes_total counter\n"));
        assert!(!body.contains("dds_admission_handshakes_total{"));
    }

    #[test]
    fn caller_identity_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_caller_identity("anonymous");
        t.bump_caller_identity("anonymous");
        t.bump_caller_identity("admin");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_http_caller_identity_total counter\n"));
        assert!(body.contains("dds_http_caller_identity_total{kind=\"anonymous\"} 2\n"));
        assert!(body.contains("dds_http_caller_identity_total{kind=\"admin\"} 1\n"));
        assert_eq!(t.caller_identity_count("anonymous"), 2);
        assert_eq!(t.caller_identity_count("admin"), 1);
        assert_eq!(t.caller_identity_count("uds"), 0);
    }

    #[test]
    fn trust_graph_gauges_render_supplied_counts() {
        let t = Telemetry::new();
        let counts = TrustGraphCounts {
            attestations: 7,
            vouches: 3,
            revocations: 2,
            burned: 1,
        };
        let body = render_exposition(&t, 0, None, Some(counts), None, None);
        assert!(body.contains("# TYPE dds_trust_graph_attestations gauge\n"));
        assert!(body.contains("dds_trust_graph_attestations 7\n"));
        assert!(body.contains("dds_trust_graph_vouches 3\n"));
        assert!(body.contains("dds_trust_graph_revocations 2\n"));
        assert!(body.contains("dds_trust_graph_burned 1\n"));
    }

    #[test]
    fn trust_graph_gauges_default_to_zero_when_lock_poisoned() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("dds_trust_graph_attestations 0\n"));
        assert!(body.contains("dds_trust_graph_vouches 0\n"));
        assert!(body.contains("dds_trust_graph_revocations 0\n"));
        assert!(body.contains("dds_trust_graph_burned 0\n"));
    }

    #[test]
    fn peer_count_gauges_render_supplied_values() {
        let t = Telemetry::new();
        let counts = NodePeerCounts::default();
        counts
            .admitted
            .store(4, std::sync::atomic::Ordering::Relaxed);
        counts
            .connected
            .store(7, std::sync::atomic::Ordering::Relaxed);
        let body = render_exposition(&t, 0, None, None, None, Some(&counts));
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 4\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 7\n"));
    }

    #[test]
    fn peer_count_gauges_default_to_zero_when_no_handle_supplied() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable so the family resolves on a
        // freshly booted node before any peer connects (or in
        // deployments running the metrics endpoint without a swarm).
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 0\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 0\n"));
    }

    #[test]
    fn challenges_outstanding_renders_supplied_count() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, Some(12), None);
        assert!(body.contains("# TYPE dds_challenges_outstanding gauge\n"));
        assert!(body.contains("dds_challenges_outstanding 12\n"));
    }

    #[test]
    fn challenges_outstanding_defaults_to_zero_when_store_read_fails() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("dds_challenges_outstanding 0\n"));
    }

    #[test]
    fn head_age_is_now_minus_head_timestamp() {
        let t = Telemetry::new();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // A timestamp 30 seconds in the past should render head_age >= 30.
        let body = render_exposition(&t, 1, Some(now.saturating_sub(30)), None, None, None);
        // Parse out the head_age value to allow for clock drift /
        // sub-second rounding inside the renderer.
        let line = body
            .lines()
            .find(|l| l.starts_with("dds_audit_chain_head_age_seconds "))
            .expect("head_age line present");
        let n: u64 = line
            .split_whitespace()
            .last()
            .unwrap()
            .parse()
            .expect("integer head_age");
        assert!(n >= 30, "head_age {n} too low for ts now-30");
    }

    #[test]
    fn label_value_escape_handles_quotes_and_newlines() {
        assert_eq!(escape_label_value("attest"), "attest");
        assert_eq!(escape_label_value(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label_value("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn install_is_idempotent() {
        let a = install();
        let b = install();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn record_audit_entry_no_op_before_install_does_not_panic() {
        // Cannot reliably observe absence-of-effect in a test that may
        // run after `install` has fired in another test on the same
        // process — `OnceLock` is process-scoped — but the call must
        // not panic regardless of state.
        record_audit_entry("ignored.action");
    }

    /// Spin up the metrics server on a random port, scrape it, and
    /// verify the response is a valid Prometheus exposition. Uses a
    /// dedicated `Telemetry` (not the global) so the assertion on
    /// `dds_audit_entries_total{action=...}` does not race with other
    /// in-process tests.
    #[tokio::test]
    async fn serve_returns_prometheus_text_with_audit_metrics() {
        let svc = make_test_service();
        let telemetry = Arc::new(Telemetry::new());
        // Pre-bump a unique-action counter so we can assert the
        // exposition surfaces it. Bypasses the global `OnceLock`.
        telemetry.bump_audit_entry("attest");
        telemetry.bump_audit_entry("attest");
        telemetry.bump_audit_entry("revoke");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Hand-rolled `NodePeerCounts` so we can pin the rendered values
        // without spinning up a real swarm — the swarm-side update path
        // is tested separately in `tests/h12_admission.rs`.
        let peer_counts = NodePeerCounts::default();
        peer_counts
            .admitted
            .store(2, std::sync::atomic::Ordering::Relaxed);
        peer_counts
            .connected
            .store(3, std::sync::atomic::Ordering::Relaxed);
        let state = MetricsState {
            svc: svc.clone(),
            telemetry: telemetry.clone(),
            peer_counts: Some(peer_counts),
        };
        let app = Router::new()
            .route("/metrics", get(metrics_handler::<MemoryBackend>))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        assert!(
            ct.starts_with("text/plain"),
            "unexpected content-type: {ct}"
        );
        let body = resp.text().await.unwrap();

        assert!(body.contains("# TYPE dds_build_info gauge\n"));
        assert!(body.contains("dds_build_info{version=\""));
        assert!(body.contains("# TYPE dds_audit_entries_total counter\n"));
        assert!(body.contains("dds_audit_entries_total{action=\"attest\"} 2\n"));
        assert!(body.contains("dds_audit_entries_total{action=\"revoke\"} 1\n"));
        // Empty MemoryBackend audit chain → length 0, head_age 0.
        assert!(body.contains("dds_audit_chain_length 0\n"));
        assert!(body.contains("dds_audit_chain_head_age_seconds 0\n"));
        // `make_test_service` seeds one root self-attestation; vouches
        // / revocations / burned remain empty.
        assert!(body.contains("# TYPE dds_trust_graph_attestations gauge\n"));
        assert!(body.contains("dds_trust_graph_attestations 1\n"));
        assert!(body.contains("dds_trust_graph_vouches 0\n"));
        assert!(body.contains("dds_trust_graph_revocations 0\n"));
        assert!(body.contains("dds_trust_graph_burned 0\n"));
        // Empty challenge store on a freshly built service.
        assert!(body.contains("# TYPE dds_challenges_outstanding gauge\n"));
        assert!(body.contains("dds_challenges_outstanding 0\n"));
        // Sessions-issued family is always discoverable; no value
        // lines until the first session is minted.
        assert!(body.contains("# TYPE dds_sessions_issued_total counter\n"));
        // Purpose-lookups family is always discoverable; no value
        // lines until the first capability check fires.
        assert!(body.contains("# TYPE dds_purpose_lookups_total counter\n"));
        // Admission-handshakes family is always discoverable; no
        // value lines until the first inbound handshake completes.
        assert!(body.contains("# TYPE dds_admission_handshakes_total counter\n"));
        // Peer-count gauges round-trip through the served exposition.
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 2\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 3\n"));
    }

    #[tokio::test]
    async fn serve_returns_404_for_unknown_paths() {
        let svc = make_test_service();
        let telemetry = Arc::new(Telemetry::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = MetricsState {
            svc: svc.clone(),
            telemetry: telemetry.clone(),
            peer_counts: None,
        };
        let app = Router::new()
            .route("/metrics", get(metrics_handler::<MemoryBackend>))
            .with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Other paths must not leak the API surface — only `/metrics`
        // is served here.
        let resp = reqwest::get(format!("http://{addr}/v1/status"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }
}
