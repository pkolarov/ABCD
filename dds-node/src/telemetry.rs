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
//! | `dds_gossip_messages_total` | counter | `kind=op\|revocation\|burn\|audit` | bumped by [`record_gossip_message`] |
//! | `dds_gossip_messages_dropped_total` | counter | `reason=unadmitted\|unknown_topic\|decode_error\|topic_kind_mismatch` | bumped by [`record_gossip_messages_dropped`] |
//! | `dds_fido2_attestation_verify_total` | counter | `result=ok\|fail`, `fmt=packed\|none\|unknown` | bumped by [`record_fido2_attestation_verify`] |
//! | `dds_fido2_assertions_total` | counter | `result=ok\|signature\|rp_id\|up\|sign_count\|other` | bumped by [`record_fido2_assertion`] |
//! | `dds_sync_pulls_total` | counter | `result=ok\|fail` | bumped by [`record_sync_pull`] |
//! | `dds_http_requests_total` | counter | `route, method, status` | bumped by [`record_http_request`] |
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
//! ### `dds_gossip_messages_total` semantics
//!
//! Bumped exactly once per inbound gossip message that survives topic
//! identification and CBOR decoding inside
//! [`crate::node::DdsNode::handle_gossip_message`], partitioned by
//! message variant (the `kind` label is 1:1 with the originating
//! [`dds_net::gossip::DdsTopic`] so a separate `topic` label would be
//! redundant cardinality):
//!
//! - `kind="op"` — [`dds_net::gossip::GossipMessage::DirectoryOp`] on a
//!   [`dds_net::gossip::DdsTopic::Operations`] topic, fed into
//!   [`crate::node::DdsNode::ingest_operation`].
//! - `kind="revocation"` — [`dds_net::gossip::GossipMessage::Revocation`]
//!   on a [`dds_net::gossip::DdsTopic::Revocations`] topic, fed into
//!   [`crate::node::DdsNode::ingest_revocation`].
//! - `kind="burn"` — [`dds_net::gossip::GossipMessage::Burn`] on a
//!   [`dds_net::gossip::DdsTopic::Burns`] topic, fed into
//!   [`crate::node::DdsNode::ingest_burn`].
//! - `kind="audit"` — [`dds_net::gossip::GossipMessage::AuditLog`] on a
//!   [`dds_net::gossip::DdsTopic::AuditLog`] topic, fed into
//!   [`crate::node::DdsNode::ingest_audit`].
//!
//! Counts the *post-decode* surface only — messages dropped earlier
//! are partitioned by `dds_gossip_messages_dropped_total{reason}`
//! (see below). Operators get the full inbound funnel from
//! `sum(rate(dds_gossip_messages_total[5m])) +
//! sum(rate(dds_gossip_messages_dropped_total[5m]))`. Per-token
//! rejections that happen *after* decode (signature, graph, duplicate
//! JTI, capability gate) remain visible via
//! `dds_audit_entries_total{action=*.rejected}`, and handshake-side
//! regressions via `dds_admission_handshakes_total{result="fail"}`.
//! Outbound-side publish (originating from the local node) is not
//! currently instrumented because the production event loop has no
//! centralised publish funnel — the [`crate::bin::dds_macos_e2e`]
//! harness and the loadtest publisher both call `gossipsub.publish`
//! directly. A future follow-up that lands a
//! `LocalService::publish_gossip` funnel can add the `direction=out`
//! label to this counter without renaming.
//!
//! ### `dds_gossip_messages_dropped_total` semantics
//!
//! Bumped exactly once per inbound gossip message that is rejected
//! before the matching `ingest_*` path runs, partitioned by the
//! drop site:
//!
//! - `reason="unadmitted"` — H-12 gate in
//!   [`crate::node::DdsNode::handle_swarm_event`]: the relayer
//!   (`propagation_source`) is not in `admitted_peers`, so the
//!   envelope is dropped without inspecting the payload. Pairs with
//!   `dds_admission_handshakes_total{result="fail"}` to disambiguate
//!   "peer reachable but never admitted" from "peer admitted but
//!   subsequently revoked".
//! - `reason="unknown_topic"` — the gossipsub `TopicHash` did not
//!   match any [`dds_net::gossip::DdsTopic`] this node subscribed to.
//!   A non-zero baseline indicates topic-id drift between peers
//!   (config skew, domain-id mismatch).
//! - `reason="decode_error"` — the payload bytes did not parse as a
//!   [`dds_net::gossip::GossipMessage`]. A non-zero rate is the
//!   gossip-tier wire-format-regression tripwire.
//! - `reason="topic_kind_mismatch"` — the message decoded
//!   successfully but its variant did not match the topic family
//!   (e.g. a `Burn` payload arriving on a `DdsTopic::Operations`
//!   topic). Indicates a misbehaving or downgraded peer.
//!
//! The catalog in `observability-plan.md` Phase C originally named
//! the labels `unadmitted|invalid_token|duplicate|backpressure`; the
//! latter three describe *post-decode* drop conditions inside the
//! `ingest_*` paths and are already covered by
//! `dds_audit_entries_total{action=*.rejected}` (signature /
//! validation / duplicate-JTI rejections all funnel through the
//! audit chain). This counter targets the *pre-decode* drop sites
//! that audit emission cannot reach because there is no decoded
//! token to attribute the drop to. A future follow-up that lands an
//! `invalid_token` / `duplicate` / `backpressure` partition (e.g.
//! once a gossipsub backpressure hook is wired) can add those
//! reasons without renaming the metric.
//!
//! ### `dds_fido2_attestation_verify_total` semantics
//!
//! Bumped exactly once per call to
//! [`dds_domain::fido2::verify_attestation`] funnelled through the
//! enrollment paths
//! [`crate::service::LocalService::enroll_user`] and
//! [`crate::service::LocalService::admin_setup`]. The shared helper
//! [`crate::service::LocalService::verify_attestation_observed`]
//! invokes the underlying verifier and accounts the outcome on the
//! way out, partitioned by:
//!
//! - `result="ok"` — `verify_attestation` returned `Ok(parsed)`. The
//!   `fmt` label carries `parsed.fmt` (today, one of `packed|none`).
//! - `result="fail"` — the verifier rejected the attestation
//!   (CBOR decode error, missing `fmt` field, unsupported format like
//!   `tpm` or `fido_u2f`, packed-attestation signature failure,
//!   unsupported COSE key type, etc.). The format that the
//!   authenticator advertised is not always reachable on the failure
//!   path (the verifier may reject before the `fmt` field is parsed,
//!   or the AAGUID gate may fire post-verify but before the bump
//!   site sees a parsed value), so the bump site uniformly emits
//!   `fmt="unknown"` for the failure bucket.
//!
//! The catalog in `observability-plan.md` Phase C names the labels
//! `fmt=packed|none|tpm`. The `tpm` bucket is forward-looking — the
//! domain verifier does not implement the TPM attestation format
//! today (it returns `Fido2Error::Unsupported(format!("fmt={other}"))`
//! for any non-`packed`/non-`none` format), so v1 collapses TPM and
//! every other unsupported format into the `result="fail",
//! fmt="unknown"` bucket. A future follow-up that lands a TPM
//! verifier (and the matching AAGUID-gate plumbing) can split out
//! `fmt="tpm"` without renaming the metric.
//!
//! The `verify_assertion_common` re-parse at
//! [`crate::service::LocalService::verify_assertion_common`] is *not*
//! counted here — it is a credential-lookup re-parse during assertion
//! verification, not an enrollment-time first-verify, and the
//! catalog row explicitly scopes the counter to enrollment.
//!
//! Outcome buckets that fire *after* `verify_attestation` returns
//! `Ok` (the AAGUID allow-list, the per-AAGUID attestation-root
//! gate, and the `rp_id` hash equality check downstream) are *not*
//! counted as `result="fail"` because the underlying
//! `verify_attestation` call itself succeeded; those gates surface
//! through the `enroll.user` / `admin.bootstrap` audit-rejection
//! actions instead and remain visible via
//! `dds_audit_entries_total{action=*.rejected}`.
//!
//! ### `dds_fido2_assertions_total` semantics
//!
//! Bumped exactly once per call to
//! [`crate::service::LocalService::verify_assertion_common`] — the
//! shared assertion verifier consumed by both
//! [`crate::service::LocalService::issue_session_from_assertion`]
//! (the `/v1/session/assert` HTTP path) and
//! [`crate::service::LocalService::admin_vouch`]. The bump site is
//! at the single `Ok` exit and at every `Err` exit so the total
//! equals one per assertion attempt that reached the verifier
//! (after the wall-clock-regression precheck).
//!
//! Result buckets:
//!
//! - `result="ok"` — every step (credential lookup, signature, UP
//!   flag, RP-ID, challenge freshness, sign-count monotonicity)
//!   returned successfully.
//! - `result="signature"` — [`dds_domain::fido2::verify_assertion`]
//!   rejected with `Fido2Error::BadSignature` (cryptographic
//!   verification failed). The COSE-decode and signature-byte
//!   parsing errors that surface as `Fido2Error::Format` /
//!   `Fido2Error::KeyError` are *not* in this bucket — those reach
//!   `result="other"` because they indicate a malformed authenticator
//!   payload rather than a signature mismatch on a parseable
//!   payload.
//! - `result="rp_id"` — `parsed.rp_id_hash` did not match
//!   `SHA-256(enrolled_rp_id)`. Cross-site replay signal.
//! - `result="up"` — User-Present (UP) flag was clear in the
//!   authenticator-data flags byte. The catalog's `uv` bucket
//!   (User-Verified flag clear) is *not* shipped: `verify_assertion_common`
//!   surfaces UV through the [`crate::service::CommonAssertionOutput::user_verified`]
//!   field (consumed downstream as the `mfa_verified` session
//!   property) but does not currently *gate* on it. Once a
//!   UV-required gate lands a future follow-up can split out
//!   `result="uv"` without renaming the metric.
//! - `result="sign_count"` — sign-count replay detected via
//!   [`dds_store::traits::CredentialStateStore::bump_sign_count`]
//!   (`StoreError::SignCountReplay`). Cloned-authenticator signal.
//! - `result="other"` — every other error exit: credential not
//!   found in the trust graph, COSE key parse failure, challenge
//!   invalid / expired, clientDataJSON parse failure, type /
//!   challenge / origin mismatch, cross-origin assertion rejected,
//!   client_data_hash / clientDataJSON SHA-256 mismatch, store
//!   error on `bump_sign_count`, trust-graph lock poisoned, format
//!   errors from `verify_assertion` (authenticatorData too short,
//!   etc.), and the wall-clock-regression precheck. Operators
//!   alarming on the `*.rejected` audit families catch these via a
//!   different lens; `result="other"` keeps the per-attempt total
//!   accurate without per-error-class cardinality blow-up. Future
//!   follow-ups can split sub-buckets (e.g. `result="challenge"`,
//!   `result="origin"`) out of the `other` partition without
//!   renaming the metric.
//!
//! The catalog in `observability-plan.md` Phase C names the labels
//! `result=ok|signature|rp_id|up|uv|sign_count`. The `uv` bucket is
//! deferred (see above); the `other` bucket is added so the
//! per-attempt total is preserved.
//!
//! ### `dds_sync_pulls_total` semantics
//!
//! Bumped exactly once per outbound anti-entropy pull this node
//! issues — i.e. per [`crate::node::DdsNode::try_sync_with`] request
//! whose outcome resolves through
//! [`crate::node::DdsNode::handle_sync_event`]. The bump fires at the
//! outcome event so the counter records *resolved* attempts, not
//! send-time attempts. Inbound requests served to *other* peers are
//! never counted here — those are responder-side and would skew the
//! pull-rate read.
//!
//! Result buckets:
//!
//! - `result="ok"` — the request received an
//!   [`libp2p::request_response::Event::Message`] response from an
//!   admitted peer and `handle_sync_response` was invoked. The
//!   response can carry zero payloads (peer reports no diff) and that
//!   still counts as `ok` — the pull succeeded, the network simply
//!   converged.
//! - `result="fail"` — every other resolution branch:
//!   [`libp2p::request_response::Event::OutboundFailure`] (timeout,
//!   stream / connection closed, dial-failure, codec error), and the
//!   H-12 unadmitted-peer drop where a `Response` arrives from a peer
//!   that is not in `admitted_peers` (the response is discarded
//!   without applying any payloads, so for the puller the pull did
//!   not yield usable state).
//!
//! Per-peer cooldown skips inside `try_sync_with` are *not* counted —
//! no request goes on the wire so there is no outcome to partition.
//! Operators reading the metric should pair it with the per-peer
//! `connected_peers()` gauge rather than the pull rate alone, since a
//! quiet network will naturally drive the pull rate to the periodic
//! `SYNC_PERIODIC_INTERVAL` floor.
//!
//! Inbound responder-side outcomes (request received, response sent
//! / not sent) are not counted here — a future
//! `dds_sync_serves_total{result}` family can split those out without
//! renaming this metric. The catalog row in `observability-plan.md`
//! Phase C names the `dds_sync_lag_seconds` histogram and
//! `dds_sync_payloads_rejected_total` counter as siblings; both still
//! ship as separate follow-ups since each requires a distinct
//! instrumentation pass (`lag_seconds` needs op-timestamp
//! plumbing; the rejection counter needs the
//! `apply_sync_payloads_with_graph` outcome to flow back through to
//! the swarm task).
//!
//! ### `dds_http_requests_total` semantics
//!
//! Bumped exactly once per HTTP request that resolves to a *matched*
//! axum route (i.e. one that hit a handler in the merged router built
//! by [`crate::http::router`]). Partitioned by three labels:
//!
//! - `route` — the axum route template the request matched on
//!   (e.g. `/v1/audit/entries`, `/healthz`). Bounded by the route
//!   table in [`crate::http::router`]; no path parameters in DDS
//!   today, so the template equals the literal URI path. The bump
//!   site reads
//!   [`axum::extract::MatchedPath`](https://docs.rs/axum/0.7/axum/extract/struct.MatchedPath.html)
//!   from the request extensions, which axum populates when the
//!   route layer wraps each per-route handler. Unmatched requests
//!   (404s served by the default fallback) are *not* counted — they
//!   do not pass through the route layer; operators key off
//!   `dds_http_caller_identity_total` for the un-routed call rate.
//! - `method` — the HTTP method as upper-case ASCII
//!   (`GET|POST|PUT|DELETE|...`). Bounded by the verb set the router
//!   actually exposes (today `GET` and `POST` only).
//! - `status` — the HTTP status code returned to the client
//!   (`200|400|401|403|404|...`), as a 3-digit integer. Bounded by
//!   the small set of status codes DDS handlers actually return; if a
//!   handler returns an unusual code (e.g. 451), it surfaces as its
//!   own series rather than being bucketed.
//!
//! The bump fires *after* the inner handler returns so the status
//! reflects what the client actually saw. Middleware that runs
//! *before* the route layer (rate-limit, body-size, response-MAC,
//! caller-identity) still counts the request because the route layer
//! sits inside that outer stack — but rate-limited / body-rejected
//! traffic that never reached a matched handler is *not* counted
//! here (it shows up only in `dds_http_caller_identity_total`).
//! Operators wanting the global request rate (matched + rejected +
//! 404s) sum across `dds_http_caller_identity_total{kind=~"anonymous|uds|pipe"}`;
//! `dds_http_requests_total` is the per-route refinement for routing
//! handler latency and per-route error-rate dashboards. Latency
//! itself ships separately as `dds_http_request_duration_seconds`
//! once the histogram-bearing metrics tier lands (catalog row still
//! open).
//!
//! Cardinality budget: 22 routes × 2 methods × ~6 typical statuses ≈
//! 250 series in the worst case; the actual production set is much
//! smaller because each route has a fixed verb and a small
//! distribution of status codes. Well within the per-node ≤ 200
//! budget the C.5 cardinality envelope targets, especially in
//! aggregate with the other label-bearing families.
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
    /// Per-`kind` inbound gossip-message counts. `kind` is one of
    /// `op|revocation|burn|audit` — bounded by the four message
    /// variants in [`dds_net::gossip::GossipMessage`].
    gossip_messages: Mutex<BTreeMap<String, u64>>,
    /// Per-`reason` inbound gossip-message drop counts. `reason` is one
    /// of `unadmitted|unknown_topic|decode_error|topic_kind_mismatch` —
    /// bounded by the four pre-decode drop sites in
    /// [`crate::node::DdsNode::handle_swarm_event`] and
    /// [`crate::node::DdsNode::handle_gossip_message`].
    gossip_messages_dropped: Mutex<BTreeMap<String, u64>>,
    /// Per-`(result, fmt)` enrollment-time FIDO2 attestation-verify
    /// counts. `result` is one of `ok|fail`; `fmt` is `packed|none` on
    /// the success branch (today's verifier supports those two formats)
    /// and the literal `unknown` on the failure branch — bounded by
    /// the [`dds_domain::fido2::verify_attestation`] outcome partition
    /// observed at the two call sites in
    /// [`crate::service::LocalService::enroll_user`] and
    /// [`crate::service::LocalService::admin_setup`].
    fido2_attestation_verifies: Mutex<BTreeMap<(String, String), u64>>,
    /// Per-`result` FIDO2 assertion-verify counts. `result` is one of
    /// `ok|signature|rp_id|up|sign_count|other` — bounded by the exit
    /// branches of [`crate::service::LocalService::verify_assertion_common`].
    /// The catalog's `uv` bucket is deferred (no UV-required gate ships
    /// today); `other` collapses every non-named error exit (challenge,
    /// origin / cdj, clock regression, lookup miss, COSE parse, store
    /// errors, etc.) so the per-attempt total stays accurate.
    fido2_assertions: Mutex<BTreeMap<String, u64>>,
    /// Per-`result` outbound anti-entropy pull counts. `result` is one
    /// of `ok|fail` — bounded by the outcome branches of
    /// [`crate::node::DdsNode::handle_sync_event`]
    /// (`Message::Response` → `ok` after the H-12 admitted-peer check,
    /// `OutboundFailure` → `fail`, H-12 unadmitted-peer response drop
    /// → `fail`).
    sync_pulls: Mutex<BTreeMap<String, u64>>,
    /// Per-`(route, method, status)` HTTP request counts. Bounded by
    /// the static route table in [`crate::http::router`] (no path
    /// parameters in DDS today) crossed with the verb set the router
    /// exposes and the status codes handlers actually return.
    /// Unmatched requests (404 from the default fallback) are not
    /// counted because the bump site sits inside the per-route layer
    /// stack — those still surface via `dds_http_caller_identity_total`.
    http_requests: Mutex<BTreeMap<(String, String, u16), u64>>,
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
            gossip_messages: Mutex::new(BTreeMap::new()),
            gossip_messages_dropped: Mutex::new(BTreeMap::new()),
            fido2_attestation_verifies: Mutex::new(BTreeMap::new()),
            fido2_assertions: Mutex::new(BTreeMap::new()),
            sync_pulls: Mutex::new(BTreeMap::new()),
            http_requests: Mutex::new(BTreeMap::new()),
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

    fn bump_gossip_message(&self, kind: &str) {
        let mut g = match self.gossip_messages.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(kind.to_string()).or_insert(0) += 1;
    }

    fn gossip_messages_snapshot(&self) -> BTreeMap<String, u64> {
        match self.gossip_messages.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_gossip_messages_total{kind=...}`. Public
    /// so the `DdsNode` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn gossip_messages_count(&self, kind: &str) -> u64 {
        match self.gossip_messages.lock() {
            Ok(g) => g.get(kind).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(kind).copied().unwrap_or(0),
        }
    }

    fn bump_gossip_messages_dropped(&self, reason: &str) {
        let mut g = match self.gossip_messages_dropped.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(reason.to_string()).or_insert(0) += 1;
    }

    fn gossip_messages_dropped_snapshot(&self) -> BTreeMap<String, u64> {
        match self.gossip_messages_dropped.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_gossip_messages_dropped_total{reason=...}`.
    /// Public so the `DdsNode` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn gossip_messages_dropped_count(&self, reason: &str) -> u64 {
        match self.gossip_messages_dropped.lock() {
            Ok(g) => g.get(reason).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(reason).copied().unwrap_or(0),
        }
    }

    fn bump_fido2_attestation_verify(&self, result: &str, fmt: &str) {
        let mut g = match self.fido2_attestation_verifies.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry((result.to_string(), fmt.to_string())).or_insert(0) += 1;
    }

    fn fido2_attestation_verifies_snapshot(&self) -> BTreeMap<(String, String), u64> {
        match self.fido2_attestation_verifies.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of
    /// `dds_fido2_attestation_verify_total{result=...,fmt=...}`. Public
    /// so the `LocalService` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn fido2_attestation_verify_count(&self, result: &str, fmt: &str) -> u64 {
        let key = (result.to_string(), fmt.to_string());
        match self.fido2_attestation_verifies.lock() {
            Ok(g) => g.get(&key).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(&key).copied().unwrap_or(0),
        }
    }

    fn bump_fido2_assertion(&self, result: &str) {
        let mut g = match self.fido2_assertions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn fido2_assertions_snapshot(&self) -> BTreeMap<String, u64> {
        match self.fido2_assertions.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_fido2_assertions_total{result=...}`. Public
    /// so the `LocalService` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn fido2_assertions_count(&self, result: &str) -> u64 {
        match self.fido2_assertions.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_sync_pull(&self, result: &str) {
        let mut g = match self.sync_pulls.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn sync_pulls_snapshot(&self) -> BTreeMap<String, u64> {
        match self.sync_pulls.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_sync_pulls_total{result=...}`. Public so
    /// the `DdsNode` regression tests can take before/after snapshots
    /// without scraping the renderer.
    pub fn sync_pulls_count(&self, result: &str) -> u64 {
        match self.sync_pulls.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_http_request(&self, route: &str, method: &str, status: u16) {
        let mut g = match self.http_requests.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry((route.to_string(), method.to_string(), status))
            .or_insert(0) += 1;
    }

    fn http_requests_snapshot(&self) -> BTreeMap<(String, String, u16), u64> {
        match self.http_requests.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of
    /// `dds_http_requests_total{route=...,method=...,status=...}`.
    /// Public so the HTTP integration tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn http_requests_count(&self, route: &str, method: &str, status: u16) -> u64 {
        let key = (route.to_string(), method.to_string(), status);
        match self.http_requests.lock() {
            Ok(g) => g.get(&key).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(&key).copied().unwrap_or(0),
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

/// Bump `dds_gossip_messages_total{kind=...}` by one. Called from
/// [`crate::node::DdsNode::handle_gossip_message`] after a gossip
/// envelope clears topic identification and CBOR decoding, just before
/// dispatch to the matching `ingest_*` path. `kind` is one of
/// `op|revocation|burn|audit`. No-op when telemetry has not been
/// installed (tests, harnesses).
pub fn record_gossip_message(kind: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_gossip_message(kind);
    }
}

/// Bump `dds_gossip_messages_dropped_total{reason=...}` by one. Called
/// from the four pre-decode drop sites in
/// [`crate::node::DdsNode::handle_swarm_event`] (H-12 unadmitted relayer
/// drop) and [`crate::node::DdsNode::handle_gossip_message`] (unknown
/// topic, CBOR decode failure, topic/kind mismatch). `reason` is one of
/// `unadmitted|unknown_topic|decode_error|topic_kind_mismatch`. No-op
/// when telemetry has not been installed (tests, harnesses).
pub fn record_gossip_messages_dropped(reason: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_gossip_messages_dropped(reason);
    }
}

/// Bump `dds_fido2_attestation_verify_total{result=...,fmt=...}` by
/// one. Called from
/// [`crate::service::LocalService::verify_attestation_observed`] after
/// every enrollment-time call to [`dds_domain::fido2::verify_attestation`]
/// (today: `enroll_user` and `admin_setup`). `result` is one of
/// `ok|fail`; `fmt` is `packed|none` on the success branch and
/// `unknown` on the failure branch (the verifier may reject before
/// the `fmt` field is parsed, so a fmt label is not always reachable
/// on failure). No-op when telemetry has not been installed (tests,
/// harnesses).
pub fn record_fido2_attestation_verify(result: &str, fmt: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_fido2_attestation_verify(result, fmt);
    }
}

/// Bump `dds_fido2_assertions_total{result=...}` by one. Called from
/// the single exit funnel in
/// [`crate::service::LocalService::verify_assertion_common`] (consumed
/// by `issue_session_from_assertion` and `admin_vouch`). `result` is
/// one of `ok|signature|rp_id|up|sign_count|other`. The catalog's
/// `uv` bucket is reserved for a future UV-required gate; `other`
/// collapses non-named error exits so the per-attempt total stays
/// accurate. No-op when telemetry has not been installed (tests,
/// harnesses).
pub fn record_fido2_assertion(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_fido2_assertion(result);
    }
}

/// Bump `dds_sync_pulls_total{result=...}` by one. Called from the
/// outbound-pull outcome branches of
/// [`crate::node::DdsNode::handle_sync_event`]. `result` is one of
/// `ok|fail` — `ok` when an admitted peer's
/// [`libp2p::request_response::Event::Message`] response is processed
/// by `handle_sync_response` (zero payloads still counts as `ok`);
/// `fail` for `OutboundFailure` (timeout, stream/connection closed,
/// dial failure, codec error) and for the H-12 unadmitted-peer
/// response drop (we received a response but the peer is no longer
/// admitted, so its payloads are discarded). No-op when telemetry has
/// not been installed (tests, harnesses).
pub fn record_sync_pull(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_sync_pull(result);
    }
}

/// Bump `dds_http_requests_total{route=...,method=...,status=...}` by
/// one. Called from
/// [`crate::http::http_request_observer_middleware`] after every
/// matched-route request returns. `route` is the `axum::extract::MatchedPath`
/// template (no path parameters in DDS today, so it equals the literal
/// URI path); `method` is the upper-case HTTP verb; `status` is the
/// 3-digit response code the inner handler emitted. Unmatched requests
/// (404s served by the default fallback) are not counted because the
/// route layer does not wrap the fallback. No-op when telemetry has not
/// been installed (tests, harnesses).
pub fn record_http_request(route: &str, method: &str, status: u16) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_http_request(route, method, status);
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

    // `dds_gossip_messages_total` — per-`kind` inbound gossip-message
    // counter. Bumped from `DdsNode::handle_gossip_message` after the
    // envelope clears topic identification and CBOR decode, just before
    // dispatch to the matching `ingest_*` path.
    out.push_str(
        "# HELP dds_gossip_messages_total Inbound gossip messages received since process start \
         (post-decode, pre-ingest), partitioned by message kind (op|revocation|burn|audit). \
         Drops earlier in the pipeline (unknown topic, CBOR decode failure, topic/kind mismatch, \
         or H-12 unadmitted-relayer drop) are counted in dds_gossip_messages_dropped_total.\n",
    );
    out.push_str("# TYPE dds_gossip_messages_total counter\n");
    let gossip_snapshot = telemetry.gossip_messages_snapshot();
    for (kind, count) in gossip_snapshot.iter() {
        out.push_str(&format!(
            "dds_gossip_messages_total{{kind=\"{}\"}} {}\n",
            escape_label_value(kind),
            count
        ));
    }

    // `dds_gossip_messages_dropped_total` — per-`reason` pre-decode
    // drop counter. Bumped from `DdsNode::handle_swarm_event` (the H-12
    // unadmitted-relayer drop) and `DdsNode::handle_gossip_message` (the
    // three pre-decode early-exit branches: unknown topic, CBOR decode
    // failure, topic/kind mismatch).
    out.push_str(
        "# HELP dds_gossip_messages_dropped_total Inbound gossip messages dropped before ingest, \
         partitioned by reason (unadmitted = H-12 unadmitted-relayer drop in handle_swarm_event; \
         unknown_topic = topic hash not in the local subscription set; decode_error = CBOR \
         decode of the GossipMessage envelope failed; topic_kind_mismatch = decoded variant did \
         not match the topic family).\n",
    );
    out.push_str("# TYPE dds_gossip_messages_dropped_total counter\n");
    let gossip_dropped_snapshot = telemetry.gossip_messages_dropped_snapshot();
    for (reason, count) in gossip_dropped_snapshot.iter() {
        out.push_str(&format!(
            "dds_gossip_messages_dropped_total{{reason=\"{}\"}} {}\n",
            escape_label_value(reason),
            count
        ));
    }

    // `dds_fido2_attestation_verify_total` — per-`(result, fmt)`
    // enrollment-time verifier outcome counter. Bumped from
    // `LocalService::verify_attestation_observed` after every call to
    // `dds_domain::fido2::verify_attestation` in `enroll_user` and
    // `admin_setup`.
    out.push_str(
        "# HELP dds_fido2_attestation_verify_total Enrollment-time \
         dds_domain::fido2::verify_attestation outcomes since process start, partitioned by \
         result (ok|fail) and the authenticator-advertised attestation format \
         (packed|none on success; unknown on failure — the verifier may reject before the fmt \
         field is parsed). The TPM attestation format is reserved by the catalog but not \
         implemented today; TPM authenticators surface as result=fail,fmt=unknown until a TPM \
         verifier ships.\n",
    );
    out.push_str("# TYPE dds_fido2_attestation_verify_total counter\n");
    let fido2_verify_snapshot = telemetry.fido2_attestation_verifies_snapshot();
    for ((result, fmt), count) in fido2_verify_snapshot.iter() {
        out.push_str(&format!(
            "dds_fido2_attestation_verify_total{{result=\"{}\",fmt=\"{}\"}} {}\n",
            escape_label_value(result),
            escape_label_value(fmt),
            count
        ));
    }

    // `dds_fido2_assertions_total` — per-`result` assertion-verify
    // outcome counter. Bumped from the single funnel in
    // `LocalService::verify_assertion_common` consumed by
    // `issue_session_from_assertion` and `admin_vouch`.
    out.push_str(
        "# HELP dds_fido2_assertions_total FIDO2 assertion-verify outcomes since process start, \
         partitioned by result (ok|signature|rp_id|up|sign_count|other). The catalog's `uv` \
         bucket is reserved for a future UV-required gate; `other` collapses non-named error \
         exits (challenge / origin / cdj mismatch, clock regression, credential lookup miss, \
         COSE key parse, store errors) so the per-attempt total stays accurate.\n",
    );
    out.push_str("# TYPE dds_fido2_assertions_total counter\n");
    let fido2_assertions_snapshot = telemetry.fido2_assertions_snapshot();
    for (result, count) in fido2_assertions_snapshot.iter() {
        out.push_str(&format!(
            "dds_fido2_assertions_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_sync_pulls_total` — per-`result` outbound anti-entropy pull
    // outcome counter. Bumped from `DdsNode::handle_sync_event` once
    // each pull resolves: `ok` for an admitted peer's response (zero
    // payloads still count as ok), `fail` for OutboundFailure or the
    // H-12 unadmitted-peer response drop.
    out.push_str(
        "# HELP dds_sync_pulls_total Outbound anti-entropy sync pulls resolved since process \
         start, partitioned by outcome (ok = admitted peer's response was processed; fail = \
         OutboundFailure / connection closed / codec error / H-12 unadmitted-peer response \
         drop). Per-peer cooldown skips do not bump the counter — no request goes on the wire.\n",
    );
    out.push_str("# TYPE dds_sync_pulls_total counter\n");
    let sync_pulls_snapshot = telemetry.sync_pulls_snapshot();
    for (result, count) in sync_pulls_snapshot.iter() {
        out.push_str(&format!(
            "dds_sync_pulls_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_http_requests_total` — per-`(route, method, status)` matched
    // HTTP request counter. Bumped from
    // `crate::http::http_request_observer_middleware` after every
    // matched-route request returns. Unmatched 404 traffic does not
    // bump the counter (the route layer wraps each handler, not the
    // default fallback); operators read the un-routed call rate off
    // `dds_http_caller_identity_total` instead.
    out.push_str(
        "# HELP dds_http_requests_total HTTP requests served by a matched axum route since \
         process start, partitioned by route template, method, and response status. Unmatched \
         requests (404 from the default fallback) do not bump this counter — they surface only \
         in dds_http_caller_identity_total. Latency ships separately as \
         dds_http_request_duration_seconds once the histogram-bearing tier lands.\n",
    );
    out.push_str("# TYPE dds_http_requests_total counter\n");
    let http_requests_snapshot = telemetry.http_requests_snapshot();
    for ((route, method, status), count) in http_requests_snapshot.iter() {
        out.push_str(&format!(
            "dds_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {}\n",
            escape_label_value(route),
            escape_label_value(method),
            status,
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
    fn gossip_messages_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_gossip_message("op");
        t.bump_gossip_message("op");
        t.bump_gossip_message("op");
        t.bump_gossip_message("revocation");
        t.bump_gossip_message("burn");
        t.bump_gossip_message("audit");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_gossip_messages_total counter\n"));
        assert!(body.contains("dds_gossip_messages_total{kind=\"op\"} 3\n"));
        assert!(body.contains("dds_gossip_messages_total{kind=\"revocation\"} 1\n"));
        assert!(body.contains("dds_gossip_messages_total{kind=\"burn\"} 1\n"));
        assert!(body.contains("dds_gossip_messages_total{kind=\"audit\"} 1\n"));
        assert_eq!(t.gossip_messages_count("op"), 3);
        assert_eq!(t.gossip_messages_count("revocation"), 1);
        assert_eq!(t.gossip_messages_count("burn"), 1);
        assert_eq!(t.gossip_messages_count("audit"), 1);
        assert_eq!(t.gossip_messages_count("other"), 0);
    }

    #[test]
    fn gossip_messages_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first inbound
        // gossip envelope is decoded so a freshly booted node still
        // surfaces the family in the catalog.
        assert!(body.contains("# TYPE dds_gossip_messages_total counter\n"));
        assert!(!body.contains("dds_gossip_messages_total{"));
    }

    #[test]
    fn gossip_messages_dropped_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_gossip_messages_dropped("unadmitted");
        t.bump_gossip_messages_dropped("unadmitted");
        t.bump_gossip_messages_dropped("unknown_topic");
        t.bump_gossip_messages_dropped("decode_error");
        t.bump_gossip_messages_dropped("topic_kind_mismatch");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_gossip_messages_dropped_total counter\n"));
        assert!(body.contains("dds_gossip_messages_dropped_total{reason=\"unadmitted\"} 2\n"));
        assert!(body.contains("dds_gossip_messages_dropped_total{reason=\"unknown_topic\"} 1\n"));
        assert!(body.contains("dds_gossip_messages_dropped_total{reason=\"decode_error\"} 1\n"));
        assert!(
            body.contains("dds_gossip_messages_dropped_total{reason=\"topic_kind_mismatch\"} 1\n")
        );
        assert_eq!(t.gossip_messages_dropped_count("unadmitted"), 2);
        assert_eq!(t.gossip_messages_dropped_count("unknown_topic"), 1);
        assert_eq!(t.gossip_messages_dropped_count("decode_error"), 1);
        assert_eq!(t.gossip_messages_dropped_count("topic_kind_mismatch"), 1);
        assert_eq!(t.gossip_messages_dropped_count("other"), 0);
    }

    #[test]
    fn gossip_messages_dropped_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first dropped
        // envelope is observed so a freshly booted node still surfaces
        // the family in the catalog (alert expressions resolve
        // immediately).
        assert!(body.contains("# TYPE dds_gossip_messages_dropped_total counter\n"));
        assert!(!body.contains("dds_gossip_messages_dropped_total{"));
    }

    #[test]
    fn fido2_attestation_verify_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_fido2_attestation_verify("ok", "packed");
        t.bump_fido2_attestation_verify("ok", "packed");
        t.bump_fido2_attestation_verify("ok", "none");
        t.bump_fido2_attestation_verify("fail", "unknown");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_fido2_attestation_verify_total counter\n"));
        assert!(
            body.contains("dds_fido2_attestation_verify_total{result=\"ok\",fmt=\"packed\"} 2\n")
        );
        assert!(
            body.contains("dds_fido2_attestation_verify_total{result=\"ok\",fmt=\"none\"} 1\n")
        );
        assert!(
            body.contains(
                "dds_fido2_attestation_verify_total{result=\"fail\",fmt=\"unknown\"} 1\n"
            )
        );
        assert_eq!(t.fido2_attestation_verify_count("ok", "packed"), 2);
        assert_eq!(t.fido2_attestation_verify_count("ok", "none"), 1);
        assert_eq!(t.fido2_attestation_verify_count("fail", "unknown"), 1);
        assert_eq!(t.fido2_attestation_verify_count("ok", "tpm"), 0);
    }

    #[test]
    fn fido2_attestation_verify_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first enrollment
        // verifier call so a freshly booted node still surfaces the
        // family in the catalog.
        assert!(body.contains("# TYPE dds_fido2_attestation_verify_total counter\n"));
        assert!(!body.contains("dds_fido2_attestation_verify_total{"));
    }

    #[test]
    fn fido2_assertions_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_fido2_assertion("ok");
        t.bump_fido2_assertion("ok");
        t.bump_fido2_assertion("signature");
        t.bump_fido2_assertion("rp_id");
        t.bump_fido2_assertion("up");
        t.bump_fido2_assertion("sign_count");
        t.bump_fido2_assertion("other");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_fido2_assertions_total counter\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"ok\"} 2\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"signature\"} 1\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"rp_id\"} 1\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"up\"} 1\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"sign_count\"} 1\n"));
        assert!(body.contains("dds_fido2_assertions_total{result=\"other\"} 1\n"));
        assert_eq!(t.fido2_assertions_count("ok"), 2);
        assert_eq!(t.fido2_assertions_count("signature"), 1);
        assert_eq!(t.fido2_assertions_count("rp_id"), 1);
        assert_eq!(t.fido2_assertions_count("up"), 1);
        assert_eq!(t.fido2_assertions_count("sign_count"), 1);
        assert_eq!(t.fido2_assertions_count("other"), 1);
        // The catalog's `uv` bucket is reserved for a future
        // UV-required gate and is not bumped today.
        assert_eq!(t.fido2_assertions_count("uv"), 0);
    }

    #[test]
    fn fido2_assertions_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first assertion
        // verify call so a freshly booted node still surfaces the
        // family in the catalog (alert expressions resolve immediately).
        assert!(body.contains("# TYPE dds_fido2_assertions_total counter\n"));
        assert!(!body.contains("dds_fido2_assertions_total{"));
    }

    #[test]
    fn sync_pulls_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_sync_pull("ok");
        t.bump_sync_pull("ok");
        t.bump_sync_pull("ok");
        t.bump_sync_pull("fail");

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_sync_pulls_total counter\n"));
        assert!(body.contains("dds_sync_pulls_total{result=\"ok\"} 3\n"));
        assert!(body.contains("dds_sync_pulls_total{result=\"fail\"} 1\n"));
        assert_eq!(t.sync_pulls_count("ok"), 3);
        assert_eq!(t.sync_pulls_count("fail"), 1);
        assert_eq!(t.sync_pulls_count("other"), 0);
    }

    #[test]
    fn sync_pulls_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first sync pull
        // resolves so a freshly booted node still surfaces the family
        // in the catalog (alert expressions resolve immediately).
        assert!(body.contains("# TYPE dds_sync_pulls_total counter\n"));
        assert!(!body.contains("dds_sync_pulls_total{"));
    }

    #[test]
    fn http_requests_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_http_request("/v1/status", "GET", 200);
        t.bump_http_request("/v1/status", "GET", 200);
        t.bump_http_request("/v1/audit/entries", "GET", 401);
        t.bump_http_request("/v1/admin/setup", "POST", 503);

        let body = render_exposition(&t, 0, None, None, None, None);
        assert!(body.contains("# TYPE dds_http_requests_total counter\n"));
        assert!(body.contains(
            "dds_http_requests_total{route=\"/v1/status\",method=\"GET\",status=\"200\"} 2\n"
        ));
        assert!(body.contains(
            "dds_http_requests_total{route=\"/v1/audit/entries\",method=\"GET\",status=\"401\"} 1\n"
        ));
        assert!(body.contains(
            "dds_http_requests_total{route=\"/v1/admin/setup\",method=\"POST\",status=\"503\"} 1\n"
        ));
        assert_eq!(t.http_requests_count("/v1/status", "GET", 200), 2);
        assert_eq!(t.http_requests_count("/v1/audit/entries", "GET", 401), 1);
        assert_eq!(t.http_requests_count("/v1/admin/setup", "POST", 503), 1);
        // Unrelated tuple defaults to zero.
        assert_eq!(t.http_requests_count("/v1/status", "POST", 200), 0);
    }

    #[test]
    fn http_requests_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(&t, 0, None, None, None, None);
        // HELP/TYPE always discoverable before the first matched
        // request so a freshly booted node still surfaces the family
        // in the catalog (alert expressions resolve immediately).
        assert!(body.contains("# TYPE dds_http_requests_total counter\n"));
        assert!(!body.contains("dds_http_requests_total{"));
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
        // Gossip-messages family is always discoverable; no value
        // lines until the first inbound gossip envelope is decoded.
        assert!(body.contains("# TYPE dds_gossip_messages_total counter\n"));
        // Gossip-messages-dropped family is always discoverable; no
        // value lines until the first envelope is dropped.
        assert!(body.contains("# TYPE dds_gossip_messages_dropped_total counter\n"));
        // FIDO2 attestation-verify family is always discoverable; no
        // value lines until the first enrollment verifier call fires.
        assert!(body.contains("# TYPE dds_fido2_attestation_verify_total counter\n"));
        // FIDO2 assertions family is always discoverable; no value
        // lines until the first assertion verify exits via the
        // `verify_assertion_common` drop-guard.
        assert!(body.contains("# TYPE dds_fido2_assertions_total counter\n"));
        // Sync-pulls family is always discoverable; no value lines
        // until the first outbound pull resolves via
        // `handle_sync_event`.
        assert!(body.contains("# TYPE dds_sync_pulls_total counter\n"));
        // HTTP-requests family is always discoverable; no value lines
        // until the first matched-route request returns through
        // `http_request_observer_middleware`.
        assert!(body.contains("# TYPE dds_http_requests_total counter\n"));
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
