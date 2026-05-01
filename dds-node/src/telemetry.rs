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
//! | `dds_build_info` | gauge | `version`, `git_sha`, `rust_version` | static, always 1 — labels captured at build time by [`dds-node/build.rs`](../../build.rs) |
//! | `dds_uptime_seconds` | gauge | — | `now - process_start` |
//! | `dds_audit_entries_total` | counter | `action` | bumped by [`record_audit_entry`] |
//! | `dds_audit_chain_length` | gauge | — | [`AuditStore::count_audit_entries`] at scrape |
//! | `dds_audit_chain_head_age_seconds` | gauge | — | `now - head.timestamp` at scrape |
//! | `dds_http_caller_identity_total` | counter | `kind=anonymous\|uds\|pipe\|admin` | bumped by [`record_caller_identity`] |
//! | `dds_sessions_issued_total` | counter | `via=fido2\|legacy` | bumped by [`record_sessions_issued`] |
//! | `dds_purpose_lookups_total` | counter | `result=ok\|denied` | bumped by [`record_purpose_lookup`] |
//! | `dds_admission_handshakes_total` | counter | `result=ok\|fail\|revoked` | bumped by [`record_admission_handshake`] |
//! | `dds_admission_handshake_last_failure_seconds` | gauge | — | Unix-seconds of the most recent non-`ok` outcome; bumped at the same call site as the counter; read at scrape via [`last_admission_failure_ts`] |
//! | `dds_gossip_messages_total` | counter | `kind=op\|revocation\|burn\|audit` | bumped by [`record_gossip_message`] |
//! | `dds_gossip_messages_dropped_total` | counter | `reason=unadmitted\|unknown_topic\|decode_error\|topic_kind_mismatch` | bumped by [`record_gossip_messages_dropped`] |
//! | `dds_fido2_attestation_verify_total` | counter | `result=ok\|fail`, `fmt=packed\|none\|unknown` | bumped by [`record_fido2_attestation_verify`] |
//! | `dds_fido2_assertions_total` | counter | `result=ok\|signature\|rp_id\|up\|sign_count\|other` | bumped by [`record_fido2_assertion`] |
//! | `dds_sync_pulls_total` | counter | `result=ok\|fail` | bumped by [`record_sync_pull`] |
//! | `dds_sync_payloads_rejected_total` | counter | `reason=legacy_v1\|publisher_capability\|publisher_identity\|replay_window\|signature\|duplicate_jti\|graph` | bumped by [`record_sync_payloads_rejected`] |
//! | `dds_pq_releases_installed_total` | counter | `result=ok\|schema\|recipient_mismatch\|replay_window\|kem_ct\|decap\|aead` | bumped by [`record_pq_release_installed`] at every exit branch of [`crate::node::DdsNode::install_epoch_key_release`] |
//! | `dds_pq_releases_emitted_total` | counter | `result=ok\|no_kem_pk\|malformed_kem_pk\|not_for_self\|clock_error\|mint_fail\|cbor_fail` | bumped by [`record_pq_releases_emitted`] at every exit branch of [`crate::node::DdsNode::build_epoch_key_response`] |
//! | `dds_pq_envelope_decrypt_total` | counter | `result=ok\|no_key\|aead_fail` | bumped by [`record_pq_envelope_decrypt`] at every exit branch of the gossip/sync envelope decrypt path in [`crate::node::DdsNode::handle_gossip_message`] and [`crate::node::DdsNode::handle_sync_response`] |
//! | `dds_pq_rotation_total` | counter | `reason=time\|revocation\|manual` | bumped by [`record_pq_rotation`] at every epoch-key rotation trigger in [`crate::node::DdsNode::rotate_and_fan_out`] |
//! | `dds_http_requests_total` | counter | `route, method, status` | bumped by [`record_http_request`] |
//! | `dds_trust_graph_attestations` | gauge | `body_type=user-auth-attestation\|device-join\|windows-policy\|macos-policy\|macos-account-binding\|sso-identity-link\|software-assignment\|service-principal\|session\|unknown` | [`crate::service::LocalService::trust_graph_counts`] at scrape, partitioned via [`crate::service::body_type_label`] |
//! | `dds_trust_graph_vouches` | gauge | — | same |
//! | `dds_trust_graph_revocations` | gauge | — | same |
//! | `dds_trust_graph_burned` | gauge | — | same |
//! | `dds_challenges_outstanding` | gauge | — | [`crate::service::LocalService::challenges_outstanding`] at scrape |
//! | `dds_peers_admitted` | gauge | — | [`crate::node::NodePeerCounts::admitted`] refreshed by [`crate::node::DdsNode::refresh_peer_count_gauges`] |
//! | `dds_peers_connected` | gauge | — | [`crate::node::NodePeerCounts::connected`] refreshed at the same call sites |
//! | `dds_store_writes_total` | counter | `result=ok\|conflict\|fail` | [`dds_store::traits::StoreWriteStats::store_write_counts`] read at scrape via [`crate::service::LocalService::store_write_counts`] |
//! | `dds_memory_resident_bytes` | gauge | — | [`process_resident_bytes`] (sysinfo `Process::memory`) read at scrape time |
//! | `dds_thread_count` | gauge | — | [`process_thread_count`] (platform-native syscall) read at scrape time |
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
//! `dds_trust_graph_attestations` is partitioned by the `body_type`
//! URI carried on each attestation token, mapped through the fixed
//! [`dds_domain::body_types`] catalog into a short label name (the
//! `dds:` URI prefix is stripped — `dds:user-auth-attestation` becomes
//! `body_type="user-auth-attestation"`). Tokens with no `body_type`
//! field, or with a value outside the catalog, fall into the
//! `body_type="unknown"` bucket so the partition's sum is always
//! equal to the previous (unlabeled) attestations total. Cardinality
//! is bounded by the nine catalog constants plus `unknown` (10
//! values total). A new domain document type added to
//! [`dds_domain::body_types`] also requires adding a matching arm in
//! [`crate::service::body_type_label`]; the
//! `body_type_label_covers_every_body_types_constant` test pins
//! that invariant. The catalog originally named
//! `kind=user|device|service` — the `body_type` vocabulary is
//! preferred over `kind` because the catalog entries do not cleanly
//! collapse to those three categories (e.g.,
//! `windows-policy` / `software-assignment` are neither user nor
//! device nor service). A future follow-up can land an additional
//! label (say `family=user|device|policy|service`) on top of
//! `body_type` without renaming the metric.
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
//! Phase C names the `dds_sync_lag_seconds` histogram as a sibling;
//! it still ships as a separate follow-up since it needs op-timestamp
//! plumbing.
//!
//! ### `dds_sync_payloads_rejected_total` semantics
//!
//! Bumped exactly once per inbound sync payload that
//! [`crate::node::DdsNode::handle_sync_response`] rejects, partitioned
//! across both the pre-apply skip sites and the post-apply categorical
//! reasons returned by
//! [`dds_net::sync::apply_sync_payloads_with_graph`]:
//!
//! Pre-apply (skipped before the apply funnel):
//!
//! - `legacy_v1` — M-1/M-2 downgrade guard. The payload's token is
//!   wire-version 1 and `network.allow_legacy_v1_tokens` is `false`.
//!   Persisted v1 already on disk is fine; fresh ingest from a peer
//!   is not.
//! - `publisher_capability` — C-3 filter. The payload carries a
//!   publisher-kind attestation (`WindowsPolicyDocument` /
//!   `MacOsPolicyDocument` / `SoftwareAssignment`) whose issuer
//!   lacks the matching `dds:policy-publisher-*` / `dds:software-publisher`
//!   capability vouch. Same gate the gossip ingest path runs via
//!   [`crate::node::publisher_capability_ok`].
//! - `publisher_identity` — SC-5 Phase B.1 follow-on. The payload
//!   carries a `SoftwareAssignment` whose `publisher_identity` is
//!   present but malformed (empty Authenticode subject, wrong-shape
//!   SHA-1 root thumbprint, wrong-shape Apple Team ID). Same gate
//!   the gossip ingest path runs via
//!   [`crate::node::software_publisher_identity_ok`]. A malformed
//!   `publisher_identity` would silently match nothing on the
//!   downstream agent — observationally identical to "no publisher
//!   pinning", which is exactly the silent downgrade the
//!   two-signature gate is meant to prevent.
//! - `replay_window` — M-9 guard. The payload is a `Revoke` or
//!   `Burn` token whose `iat` falls outside the configured replay
//!   window (the same check the gossip path runs via
//!   [`crate::node::revocation_within_replay_window`]).
//!
//! Post-apply (returned by `apply_sync_payloads_with_graph` through
//! [`dds_net::sync::SyncResult::rejected_by_reason`]):
//!
//! - `signature` — `Token::validate()` rejected the token. Covers
//!   ed25519 signature failures and the structural / issuer-binding
//!   mismatches the token's own self-validation catches before the
//!   trust graph is consulted.
//! - `duplicate_jti` — the trust graph rejected the token because a
//!   token with the same JTI is already in the graph (B-1 replay
//!   indicator). Surfaced as its own bucket so an operator can
//!   distinguish benign re-delivery rate from the other graph
//!   rejections.
//! - `graph` — every other `TrustError` from
//!   [`dds_core::trust::TrustGraph::add_token`] —
//!   `IdentityBurned`, `Unauthorized`, `VouchHashMismatch`,
//!   `NoValidChain`, `ChainTooDeep`, or a graph-layer
//!   `TokenValidation` re-derivation.
//!
//! Decode failures (token / op CBOR), store-side write failures
//! (`put_token`, `revoke`, `burn`), and DAG missing-deps tally still
//! flow into [`dds_net::sync::SyncResult::errors`] for diagnostic
//! logging but are *not* partitioned through this counter — they are
//! either corruption signals (operator should chase the source) or
//! transient store-layer failures already covered by
//! `dds_store_writes_total{result=fail}`.
//!
//! Per-peer cooldown skips inside
//! [`crate::node::DdsNode::try_sync_with`] are *not* counted — no
//! request goes on the wire and no payload is observed.
//! `OutboundFailure` and the H-12 unadmitted-peer response drop are
//! counted under `dds_sync_pulls_total{result="fail"}`, not here.
//!
//! The catalog in `observability-plan.md` Phase C names the labels
//! `reason=signature|graph|duplicate_jti|window`. The shipped vocabulary
//! adds the two pre-apply guards (`legacy_v1` / `publisher_capability`)
//! that the production node runs before the apply funnel; the catalog's
//! `window` aliases the pre-apply `replay_window` bucket. Sync-applied
//! token rejections do *not* emit audit entries today (no audit hook
//! inside the sync apply path), so this counter is the only signal an
//! operator gets for sync-vs-gossip post-apply rejection rate parity.
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
//! ### `dds_memory_resident_bytes` semantics
//!
//! Read at scrape time through the private
//! [`process_resident_bytes`] helper, which queries our own pid via
//! [`sysinfo::Process::memory`]. The gauge tracks resident set size
//! in bytes — what the OS would report as "physical memory pages
//! mapped to the process" (Linux RSS / macOS task-basic-info /
//! Windows working set). It does *not* track virtual size, swap, or
//! mmap'd-but-not-resident bytes; those would require additional
//! `ProcessRefreshKind` flags and are deferred until an operator
//! asks for them. Reading is best-effort: if sysinfo cannot see the
//! pid (sandbox restrictions, transient race) the helper returns 0
//! rather than panicking the scrape task — the family's
//! `# HELP` / `# TYPE` headers still ship so the catalog stays
//! discoverable.
//!
//! ### `dds_thread_count` semantics
//!
//! Read at scrape time through the private [`process_thread_count`]
//! helper. sysinfo 0.32 does not expose per-process thread counts
//! in a portable accessor, so the helper goes directly to each
//! platform's native API: `/proc/self/status` `Threads:` parse on
//! Linux, [`libc::proc_pidinfo`] with `PROC_PIDTASKINFO` on macOS,
//! and a `TH32CS_SNAPTHREAD` snapshot walk filtered to the current
//! pid on Windows. Read failures (sandbox restrictions, transient
//! race) and unsupported targets degrade to 0 rather than panicking
//! the scrape task; the family's `# HELP` / `# TYPE` headers always
//! ship so the catalog stays discoverable.
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
    AuditStore, ChallengeStore, CredentialStateStore, RevocationStore, StoreSizeStats,
    StoreWriteCounts, StoreWriteStats, TokenStore,
};

use crate::http::SharedService;
use crate::node::NodePeerCounts;
use crate::service::{StoreByteSizes, TrustGraphCounts};

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
    /// Unix-seconds timestamp of the most recent inbound H-12 admission
    /// handshake whose outcome was *not* `ok` — i.e. the latest moment
    /// [`crate::node::DdsNode::verify_peer_admission`] bumped
    /// `dds_admission_handshakes_total{result="fail"}` or
    /// `result="revoked"`. Backs the
    /// `dds_admission_handshake_last_failure_seconds` Prometheus gauge
    /// and the matching `last_admission_failure_ts` field on
    /// [`crate::service::NodeStatus`] consumed by `dds-cli stats`. `None`
    /// before the first failure / revocation lands; the renderer emits
    /// the literal `0` sentinel in that case so the family is always
    /// discoverable.
    admission_handshake_last_failure_ts: Mutex<Option<u64>>,
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
    /// Per-`reason` pre-apply sync-payload rejection counts. `reason`
    /// is one of
    /// `legacy_v1|publisher_capability|publisher_identity|replay_window`
    /// — bounded by the four pre-apply skip sites inside
    /// [`crate::node::DdsNode::handle_sync_response`]. Post-apply
    /// rejections from [`dds_net::sync::apply_sync_payloads_with_graph`]
    /// funnel into a single `Vec<String>` today and would need a
    /// `SyncResult` schema change to partition cleanly (deferred).
    sync_payloads_rejected: Mutex<BTreeMap<String, u64>>,
    /// Per-`(route, method, status)` HTTP request counts. Bounded by
    /// the static route table in [`crate::http::router`] (no path
    /// parameters in DDS today) crossed with the verb set the router
    /// exposes and the status codes handlers actually return.
    /// Unmatched requests (404 from the default fallback) are not
    /// counted because the bump site sits inside the per-route layer
    /// stack — those still surface via `dds_http_caller_identity_total`.
    http_requests: Mutex<BTreeMap<(String, String, u16), u64>>,
    /// **Z-1 Phase B.11 (partial)** — per-`result`
    /// `EpochKeyRelease` install outcomes from
    /// [`crate::node::DdsNode::install_epoch_key_release`]. `result` is
    /// one of `ok|schema|recipient_mismatch|replay_window|kem_ct|decap|aead`,
    /// the seven exit branches of the receive funnel. Bounded by that
    /// fixed return-string vocabulary; an `ok` bump means the schema
    /// gate, recipient binding, replay-window guard, KEM decap, and
    /// AEAD unwrap all succeeded (regardless of whether the resulting
    /// install was Inserted / Rotated / AlreadyCurrent / Stale at the
    /// store layer — those are storage-side outcomes, not crypto
    /// outcomes).
    pq_releases_installed: Mutex<BTreeMap<String, u64>>,
    /// **Z-1 Phase B.11** — per-`result` epoch-key release emit counter.
    /// Bumped from every exit branch of
    /// [`crate::node::DdsNode::build_epoch_key_response`]:
    /// - `ok` — a release was minted and CBOR-encoded successfully.
    /// - `no_kem_pk` — requester has no cached KEM pubkey; empty response.
    /// - `malformed_kem_pk` — cached KEM pubkey failed `from_bytes`; empty.
    /// - `not_for_self` — request didn't list our peer id; empty response.
    /// - `clock_error` — `SystemTime` failed; empty response.
    /// - `mint_fail` — `mint_epoch_key_release_for_recipient` returned `Err`.
    /// - `cbor_fail` — CBOR serialisation of the fresh release failed.
    pq_releases_emitted: Mutex<BTreeMap<String, u64>>,
    /// **Z-1 Phase B.7 / B.11** — per-`result` gossip/sync envelope
    /// decrypt outcomes. `result` is one of `ok|no_key|aead_fail`:
    /// - `ok` — epoch key looked up and AEAD decryption succeeded.
    /// - `no_key` — no cached epoch key for (publisher, epoch_id).
    /// - `aead_fail` — key present but AEAD tag verification failed.
    ///
    /// Bumped from [`crate::node::DdsNode::handle_gossip_message`]
    /// (gossip path) and eventually from the sync decrypt path (B.8).
    pq_envelope_decrypt: Mutex<BTreeMap<String, u64>>,
    /// **Z-1 Phase B.9 / B.11** — per-`reason` epoch-key rotation
    /// counter. `reason` is one of `time|revocation|new_peer|manual`:
    /// - `time` — scheduled 24h (configurable) rotation timer fired.
    /// - `revocation` — an admission revocation was received; the node
    ///   rotated immediately (with jitter) to exclude the revoked peer.
    /// - `new_peer` — reserved for a future "rotate on first new peer"
    ///   policy; not yet wired.
    /// - `manual` — operator issued `dds pq rotate`.
    pq_rotation: Mutex<BTreeMap<String, u64>>,
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
            admission_handshake_last_failure_ts: Mutex::new(None),
            gossip_messages: Mutex::new(BTreeMap::new()),
            gossip_messages_dropped: Mutex::new(BTreeMap::new()),
            fido2_attestation_verifies: Mutex::new(BTreeMap::new()),
            fido2_assertions: Mutex::new(BTreeMap::new()),
            sync_pulls: Mutex::new(BTreeMap::new()),
            sync_payloads_rejected: Mutex::new(BTreeMap::new()),
            http_requests: Mutex::new(BTreeMap::new()),
            pq_releases_installed: Mutex::new(BTreeMap::new()),
            pq_releases_emitted: Mutex::new(BTreeMap::new()),
            pq_envelope_decrypt: Mutex::new(BTreeMap::new()),
            pq_rotation: Mutex::new(BTreeMap::new()),
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
        // Stamp the last-failure timestamp on every non-`ok` outcome
        // so operators can surface "X seconds since last admission
        // failure" without scraping a since-boot counter rate. `fail`
        // and `revoked` are both partitioned because both carry
        // operational signal: `fail` is a verify regression, `revoked`
        // is a previously-admitted peer still attempting to rejoin.
        if result != "ok" {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut ts = match self.admission_handshake_last_failure_ts.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *ts = Some(now);
        }
    }

    /// Most recent Unix-seconds timestamp at which
    /// [`Self::bump_admission_handshake`] was called with a non-`ok`
    /// `result`. `None` before the first failure / revocation lands.
    /// Backs the `dds_admission_handshake_last_failure_seconds`
    /// Prometheus gauge and the `last_admission_failure_ts` field on
    /// [`crate::service::NodeStatus`].
    pub fn admission_handshake_last_failure_ts(&self) -> Option<u64> {
        match self.admission_handshake_last_failure_ts.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
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

    fn bump_sync_payloads_rejected(&self, reason: &str) {
        let mut g = match self.sync_payloads_rejected.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(reason.to_string()).or_insert(0) += 1;
    }

    fn sync_payloads_rejected_snapshot(&self) -> BTreeMap<String, u64> {
        match self.sync_payloads_rejected.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_sync_payloads_rejected_total{reason=...}`.
    /// Public so the `DdsNode` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn sync_payloads_rejected_count(&self, reason: &str) -> u64 {
        match self.sync_payloads_rejected.lock() {
            Ok(g) => g.get(reason).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(reason).copied().unwrap_or(0),
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

    fn bump_pq_release_installed(&self, result: &str) {
        let mut g = match self.pq_releases_installed.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn pq_releases_installed_snapshot(&self) -> BTreeMap<String, u64> {
        match self.pq_releases_installed.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_pq_releases_installed_total{result=...}`.
    /// Public so the `DdsNode` regression tests can take before/after
    /// snapshots without scraping the renderer.
    pub fn pq_releases_installed_count(&self, result: &str) -> u64 {
        match self.pq_releases_installed.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_pq_releases_emitted(&self, result: &str) {
        let mut g = match self.pq_releases_emitted.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn pq_releases_emitted_snapshot(&self) -> BTreeMap<String, u64> {
        match self.pq_releases_emitted.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_pq_releases_emitted_total{result=...}`.
    /// Public so regression tests can take before/after snapshots.
    pub fn pq_releases_emitted_count(&self, result: &str) -> u64 {
        match self.pq_releases_emitted.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_pq_envelope_decrypt(&self, result: &str) {
        let mut g = match self.pq_envelope_decrypt.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(result.to_string()).or_insert(0) += 1;
    }

    fn pq_envelope_decrypt_snapshot(&self) -> BTreeMap<String, u64> {
        match self.pq_envelope_decrypt.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_pq_envelope_decrypt_total{result=...}`.
    /// Public so regression tests can take before/after snapshots
    /// without scraping the renderer.
    pub fn pq_envelope_decrypt_count(&self, result: &str) -> u64 {
        match self.pq_envelope_decrypt.lock() {
            Ok(g) => g.get(result).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(result).copied().unwrap_or(0),
        }
    }

    fn bump_pq_rotation(&self, reason: &str) {
        let mut g = match self.pq_rotation.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g.entry(reason.to_string()).or_insert(0) += 1;
    }

    fn pq_rotation_snapshot(&self) -> BTreeMap<String, u64> {
        match self.pq_rotation.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Current value of `dds_pq_rotation_total{reason=...}`.
    /// Public so regression tests can take before/after snapshots
    /// without scraping the renderer.
    pub fn pq_rotation_count(&self, reason: &str) -> u64 {
        match self.pq_rotation.lock() {
            Ok(g) => g.get(reason).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(reason).copied().unwrap_or(0),
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

/// Read the `dds_admission_handshake_last_failure_seconds` gauge value
/// (Unix seconds of the most recent non-`ok` admission handshake
/// outcome). Returns `None` before the first failure / revocation
/// lands, or when telemetry has not been installed (tests, harnesses).
/// Surfaced through [`crate::service::NodeStatus::last_admission_failure_ts`]
/// so `dds-cli stats` can render "last admission failure: 12s ago"
/// without scraping `/metrics`.
pub fn last_admission_failure_ts() -> Option<u64> {
    TELEMETRY
        .get()
        .and_then(|t| t.admission_handshake_last_failure_ts())
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

/// Bump `dds_sync_payloads_rejected_total{reason=...}` by one. Called
/// from the pre-apply skip sites in
/// [`crate::node::DdsNode::handle_sync_response`] (the M-1/M-2 legacy
/// v1 token guard, the C-3 publisher-capability filter, the SC-5
/// Phase B.1 `software_publisher_identity_ok` shape gate, and the
/// M-9 revocation replay-window guard) plus the post-apply iteration
/// over [`dds_net::sync::SyncResult::rejected_by_reason`]. `reason`
/// is one of
/// `legacy_v1|publisher_capability|publisher_identity|replay_window`
/// (pre-apply) or `signature|duplicate_jti|graph` (post-apply,
/// sourced from the [`dds_net::sync::SyncRejectReason`] catalog).
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_sync_payloads_rejected(reason: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_sync_payloads_rejected(reason);
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

/// **Z-1 Phase B.11 (partial)** — bump
/// `dds_pq_releases_installed_total{result=...}` by one. Called from
/// every exit branch of
/// [`crate::node::DdsNode::install_epoch_key_release`]. `result` is one
/// of:
///
/// - `ok` — schema gate, recipient binding, replay-window guard, KEM
///   decap, and AEAD unwrap all succeeded; the unwrapped epoch key was
///   handed to [`crate::epoch_key_store::EpochKeyStore::install_peer_release`]
///   (the storage-side `Inserted` / `Rotated` / `AlreadyCurrent` /
///   `Stale` partition is not surfaced here — those are not crypto
///   outcomes and would expand the cardinality without adding security
///   signal).
/// - `schema` — [`dds_net::pq_envelope::EpochKeyRelease::validate`]
///   rejected the shape (empty publisher / recipient, invalid expiry,
///   wrong-length `kem_ct` / `aead_ciphertext` / signatures). Includes
///   the defensive length re-check that runs before destructuring into
///   fixed-length arrays.
/// - `recipient_mismatch` — `release.recipient != self.peer_id`. The
///   release was meant for a different peer.
/// - `replay_window` — `issued_at` is more than
///   [`dds_net::pq_envelope::EPOCH_RELEASE_REPLAY_WINDOW_SECS`] in the
///   past relative to local clock (M-9-style replay defence).
/// - `kem_ct` — [`dds_core::crypto::kem::KemCiphertext::from_bytes`]
///   rejected the ciphertext blob (wrong inner shape after the schema
///   length check passed — should be unreachable in practice but we
///   bump anyway so the budget stays accurate).
/// - `decap` — [`dds_core::crypto::kem::decap`] failed (wrong KEM
///   secret, tampered ciphertext, or — critically — the publisher
///   bound the encapsulation to a different `(publisher, recipient,
///   epoch_id)` tuple than the release advertises).
/// - `aead` — [`dds_core::crypto::epoch_key::unwrap`] failed (wrong
///   shared secret, tampered AEAD ciphertext / nonce / tag).
///
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_pq_release_installed(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_pq_release_installed(result);
    }
}

/// **Z-1 Phase B.11** — bump `dds_pq_releases_emitted_total{result=...}`
/// by one. Called from every exit branch of
/// [`crate::node::DdsNode::build_epoch_key_response`]:
///
/// - `ok` — a release was minted and CBOR-encoded successfully.
/// - `no_kem_pk` — requester has no cached KEM pubkey; empty response.
/// - `malformed_kem_pk` — cached KEM pubkey failed `from_bytes`; empty.
/// - `not_for_self` — request didn't list our peer id; empty response.
/// - `clock_error` — `SystemTime` failed; empty response.
/// - `mint_fail` — `mint_epoch_key_release_for_recipient` returned `Err`.
/// - `cbor_fail` — CBOR serialisation of the fresh release failed.
///
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_pq_releases_emitted(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_pq_releases_emitted(result);
    }
}

/// Bump `dds_pq_envelope_decrypt_total{result=...}` by one. Called
/// from [`crate::node::DdsNode::handle_gossip_message`] and
/// [`crate::node::DdsNode::handle_sync_response`] at every exit branch
/// of the per-envelope decrypt pipeline:
///
/// - `ok` — epoch key found and AEAD ciphertext verified cleanly.
/// - `no_key` — no cached epoch key for (publisher, epoch_id). The
///   envelope is dropped; the receiver should trigger an
///   `EpochKeyRequest` recovery (§4.5.1) for this publisher.
/// - `aead_fail` — key present but the AEAD tag did not verify
///   (tampered ciphertext, tampered nonce, wrong epoch_id, or
///   publisher used a stale key that the store already evicted from
///   the grace cache). Envelope is dropped.
///
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_pq_envelope_decrypt(result: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_pq_envelope_decrypt(result);
    }
}

/// Bump `dds_pq_rotation_total{reason=...}` by one. Called from
/// [`crate::node::DdsNode::rotate_and_fan_out`] at every rotation
/// trigger:
///
/// - `time` — scheduled 24h (configurable) rotation timer fired.
/// - `revocation` — an admission revocation arrived; the node
///   rotated immediately (with jitter) to exclude the revoked peer.
/// - `manual` — operator issued `dds pq rotate` via the HTTP API.
///
/// No-op when telemetry has not been installed (tests, harnesses).
pub fn record_pq_rotation(reason: &str) {
    if let Some(t) = TELEMETRY.get() {
        t.bump_pq_rotation(reason);
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
/// gauges report zero. `store_bytes` carries the
/// `dds_store_bytes{table=...}` per-redb-table snapshot read at scrape
/// time via [`crate::service::LocalService::store_byte_sizes`]; `None`
/// means the underlying store read failed and the renderer ships only
/// the family's `# HELP` / `# TYPE` headers so the catalog stays
/// discoverable. `store_write_counts` carries the three
/// `dds_store_writes_total{result}` counter buckets read at scrape
/// time via [`crate::service::LocalService::store_write_counts`];
/// the field is always present (the underlying read is a triple
/// `Relaxed` atomic load with no failure mode), so the value lines
/// always ship.
/// Keeping the lock acquisition in the caller avoids forcing a
/// `where` bound on this function.
#[allow(clippy::too_many_arguments)]
fn render_exposition(
    telemetry: &Telemetry,
    chain_length: usize,
    head_timestamp: Option<u64>,
    trust_graph: Option<TrustGraphCounts>,
    challenges_outstanding: Option<usize>,
    peer_counts: Option<&NodePeerCounts>,
    store_bytes: Option<&StoreByteSizes>,
    store_write_counts: StoreWriteCounts,
) -> String {
    let mut out = String::with_capacity(1024);

    // `dds_build_info` — static fingerprint, always 1. The label
    // triple (`version`, `git_sha`, `rust_version`) is captured at
    // build time by `dds-node/build.rs`; the env-var pipeline emits
    // `unknown` for either of the two non-cargo values when the build
    // happens outside a git checkout or without a usable rustc on
    // PATH, so the family is always discoverable. The `DdsBuildSkew`
    // alert is keyed off `count by(version)` so adding the extra
    // labels does not change the alert semantics — operators that
    // want to alarm on git-SHA skew can mirror the same query against
    // `git_sha`.
    out.push_str(
        "# HELP dds_build_info DDS node build fingerprint (always 1; labels: version, git_sha, rust_version).\n",
    );
    out.push_str("# TYPE dds_build_info gauge\n");
    out.push_str(&format!(
        "dds_build_info{{version=\"{}\",git_sha=\"{}\",rust_version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"),
        env!("DDS_GIT_SHA"),
        env!("DDS_RUST_VERSION"),
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
        "# HELP dds_trust_graph_attestations Active attestation tokens currently in the trust graph, partitioned by body_type.\n",
    );
    out.push_str("# TYPE dds_trust_graph_attestations gauge\n");
    // observability-plan.md Phase C — emit one labeled series per
    // non-zero body_type bucket. Vocabulary is bounded by the fixed
    // `dds_domain::body_types` catalog (mapped through
    // `service::body_type_label`); the `unknown` bucket catches
    // tokens whose `body_type` is missing or outside the catalog so
    // `sum(dds_trust_graph_attestations) == tg.attestations` always
    // holds. Empty graph still emits the family's HELP / TYPE
    // headers (above) so the catalog is discoverable on a fresh
    // node — Prometheus accepts a metric family with no value lines
    // as long as HELP and TYPE are present, and any subsequent
    // attestation-ingest will populate the buckets without renaming
    // the metric.
    if tg.attestations_by_body_type.is_empty() {
        // BTreeMap iteration is alphabetical so an empty graph emits
        // no value lines; emit a single zero-valued `unknown` series
        // so the family always has at least one anchor line for the
        // `serve_returns_prometheus_text_with_audit_metrics`
        // discoverability contract.
        out.push_str("dds_trust_graph_attestations{body_type=\"unknown\"} 0\n");
    } else {
        for (body_type, n) in &tg.attestations_by_body_type {
            out.push_str(&format!(
                "dds_trust_graph_attestations{{body_type=\"{body_type}\"}} {n}\n"
            ));
        }
    }
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

    // `dds_admission_handshake_last_failure_seconds` — Unix-seconds
    // timestamp of the most recent non-`ok` outcome bumped by
    // `bump_admission_handshake`. Sentinel `0` before the first failure
    // / revocation lands so the family is always discoverable.
    out.push_str(
        "# HELP dds_admission_handshake_last_failure_seconds Unix-seconds timestamp of the most \
         recent inbound H-12 admission handshake whose outcome was not ok (i.e. the latest moment \
         the fail or revoked bucket of dds_admission_handshakes_total was bumped). Sentinel 0 \
         before the first failure / revocation lands. Pairs with the since-boot counter to \
         surface how long ago without an alerting rate window.\n",
    );
    out.push_str("# TYPE dds_admission_handshake_last_failure_seconds gauge\n");
    out.push_str(&format!(
        "dds_admission_handshake_last_failure_seconds {}\n",
        telemetry.admission_handshake_last_failure_ts().unwrap_or(0),
    ));

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

    // `dds_sync_payloads_rejected_total` — per-`reason` sync-payload
    // rejection counter. Bumped from the pre-apply skip sites inside
    // `DdsNode::handle_sync_response` (M-1/M-2 legacy_v1, C-3
    // publisher_capability, SC-5 Phase B.1 publisher_identity,
    // M-9 replay_window) plus the post-apply iteration over
    // `SyncResult::rejected_by_reason` (signature, duplicate_jti,
    // graph) returned by `apply_sync_payloads_with_graph`.
    out.push_str(
        "# HELP dds_sync_payloads_rejected_total Inbound sync payloads rejected, partitioned by \
         reason. Pre-apply (skipped before the apply funnel): legacy_v1 = M-1/M-2 downgrade guard \
         tripped on a wire-version-1 token while allow_legacy_v1_tokens=false; \
         publisher_capability = C-3 filter — issuer lacks the matching dds:policy-publisher-* / \
         dds:software-publisher capability; publisher_identity = SC-5 Phase B.1 fail-closed — \
         SoftwareAssignment.publisher_identity is present but malformed (empty Authenticode \
         subject, wrong-shape SHA-1 thumbprint, wrong-shape Apple Team ID); replay_window = M-9 \
         guard — revoke/burn token's `iat` is outside the configured replay window. Post-apply \
         (returned by apply_sync_payloads_with_graph): signature = Token::validate() rejected the \
         token (ed25519 signature / issuer-binding); duplicate_jti = trust graph rejected the \
         token as a same-JTI duplicate (B-1 replay indicator); graph = every other TrustError \
         (burned, unauthorized, vouch hash mismatch, no valid chain, chain too deep, graph-layer \
         token re-validation). Decode failures and store-side write errors fall into \
         SyncResult.errors only and surface separately through dds_store_writes_total{result=fail}.\n",
    );
    out.push_str("# TYPE dds_sync_payloads_rejected_total counter\n");
    let sync_rejected_snapshot = telemetry.sync_payloads_rejected_snapshot();
    for (reason, count) in sync_rejected_snapshot.iter() {
        out.push_str(&format!(
            "dds_sync_payloads_rejected_total{{reason=\"{}\"}} {}\n",
            escape_label_value(reason),
            count
        ));
    }

    // `dds_pq_releases_installed_total` — per-`result` Phase B
    // EpochKeyRelease install outcome counter. Bumped from every exit
    // branch of `DdsNode::install_epoch_key_release` (the receive
    // funnel for both the H-12 piggy-backed releases and the
    // /dds/epoch-keys/1.0.0/<domain> request_response responses).
    out.push_str(
        "# HELP dds_pq_releases_installed_total Phase B EpochKeyRelease install outcomes since \
         process start, partitioned by result. ok = schema gate + recipient binding + replay-window \
         guard + KEM decap + AEAD unwrap all succeeded (storage-side Inserted / Rotated / \
         AlreadyCurrent / Stale collapsed into ok — those are not crypto outcomes); schema = \
         EpochKeyRelease::validate rejected the shape (empty publisher / recipient, invalid expiry, \
         wrong-length kem_ct / aead_ciphertext / signatures); recipient_mismatch = release.recipient \
         != self.peer_id; replay_window = issued_at older than EPOCH_RELEASE_REPLAY_WINDOW_SECS \
         (M-9-style replay defence); kem_ct = HybridKemCt::from_bytes rejected the inner shape; \
         decap = ml-kem decap failed (wrong KEM secret, tampered ciphertext, or — critically — the \
         publisher bound the encapsulation to a different (publisher, recipient, epoch_id) tuple \
         than the release advertises); aead = ChaCha20-Poly1305 unwrap failed (wrong shared secret \
         / tampered AEAD ciphertext or nonce / tag).\n",
    );
    out.push_str("# TYPE dds_pq_releases_installed_total counter\n");
    let pq_releases_snapshot = telemetry.pq_releases_installed_snapshot();
    for (result, count) in pq_releases_snapshot.iter() {
        out.push_str(&format!(
            "dds_pq_releases_installed_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_pq_releases_emitted_total` — per-`result` epoch-key release
    // emit counter. Bumped from every exit branch of
    // `DdsNode::build_epoch_key_response` (B.11 mint-side observability).
    out.push_str(
        "# HELP dds_pq_releases_emitted_total Phase B EpochKeyRelease mint outcomes since \
         process start, partitioned by result. ok = release minted and CBOR-encoded to the \
         requester; no_kem_pk = requester has no cached KEM pubkey (cert missing or v1/v2); \
         malformed_kem_pk = cached KEM pubkey failed from_bytes; not_for_self = request didn't \
         list this node's peer id; clock_error = SystemTime::now() failed; mint_fail = \
         mint_epoch_key_release_for_recipient returned Err; cbor_fail = release CBOR encode \
         failed.\n",
    );
    out.push_str("# TYPE dds_pq_releases_emitted_total counter\n");
    let pq_emitted_snapshot = telemetry.pq_releases_emitted_snapshot();
    for (result, count) in pq_emitted_snapshot.iter() {
        out.push_str(&format!(
            "dds_pq_releases_emitted_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_pq_envelope_decrypt_total` — per-`result` gossip/sync
    // envelope AEAD decrypt outcome counter. Bumped from
    // `DdsNode::handle_gossip_message` (gossip path, B.7) and
    // `DdsNode::handle_sync_response` (sync path, B.8).
    out.push_str(
        "# HELP dds_pq_envelope_decrypt_total Phase B gossip/sync envelope AEAD decrypt outcomes \
         since process start, partitioned by result. ok = epoch key found and AEAD ciphertext \
         verified cleanly; no_key = no cached epoch key for (publisher, epoch_id) — receiver \
         should trigger EpochKeyRequest recovery; aead_fail = key present but AEAD tag \
         verification failed (tampered ciphertext, wrong epoch_id, or stale key evicted from \
         grace cache).\n",
    );
    out.push_str("# TYPE dds_pq_envelope_decrypt_total counter\n");
    let pq_decrypt_snapshot = telemetry.pq_envelope_decrypt_snapshot();
    for (result, count) in pq_decrypt_snapshot.iter() {
        out.push_str(&format!(
            "dds_pq_envelope_decrypt_total{{result=\"{}\"}} {}\n",
            escape_label_value(result),
            count
        ));
    }

    // `dds_pq_rotation_total` — per-`reason` epoch-key rotation counter.
    // Bumped from `DdsNode::rotate_and_fan_out` (B.9).
    out.push_str(
        "# HELP dds_pq_rotation_total Phase B epoch-key rotations since process start, \
         partitioned by reason. time = scheduled 24h rotation timer; revocation = triggered by \
         an inbound admission revocation (rotates to exclude the revoked peer within 60 s, \
         with jitter); manual = operator-requested via POST /v1/pq/rotate.\n",
    );
    out.push_str("# TYPE dds_pq_rotation_total counter\n");
    let pq_rotation_snapshot = telemetry.pq_rotation_snapshot();
    for (reason, count) in pq_rotation_snapshot.iter() {
        out.push_str(&format!(
            "dds_pq_rotation_total{{reason=\"{}\"}} {}\n",
            escape_label_value(reason),
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

    // `dds_store_bytes` — per-table stored-byte gauge. Read at scrape
    // time through `LocalService::store_byte_sizes` which delegates to
    // `dds_store::traits::StoreSizeStats::table_stored_bytes`. The
    // RedbBackend impl reports `TableStats::stored_bytes()` per redb
    // table; the MemoryBackend impl returns an empty map so harnesses
    // and tests scrape a discoverable family with no series.
    out.push_str(
        "# HELP dds_store_bytes Bytes currently stored in each redb table (TableStats::stored_bytes \
         — actual stored payload, excluding metadata and fragmentation overhead). Backends that \
         do not have a meaningful byte size (in-memory test backend) report an empty family — the \
         HELP/TYPE headers still ship so the catalog stays discoverable.\n",
    );
    out.push_str("# TYPE dds_store_bytes gauge\n");
    if let Some(sizes) = store_bytes {
        for (table, bytes) in sizes.tables.iter() {
            out.push_str(&format!(
                "dds_store_bytes{{table=\"{}\"}} {}\n",
                escape_label_value(table),
                bytes
            ));
        }
    }

    // `dds_store_writes_total` — per-result write-transaction counter.
    // Read at scrape time through `LocalService::store_write_counts`
    // which delegates to `dds_store::traits::StoreWriteStats`.
    // RedbBackend tallies are bumped from every write-path method
    // exit; MemoryBackend tallies follow the same shape so the family
    // is uniform across backends. The three buckets are always
    // emitted (even when zero) so a fresh node scrape exposes the
    // counter family before any write has happened — matches the
    // Prometheus convention that a counter family present at zero is
    // distinguishable from an absent metric.
    out.push_str(
        "# HELP dds_store_writes_total Store write-transaction outcomes since process start. \
         result=\"ok\": committed write that changed state. result=\"conflict\": caller-visible \
         domain conflict aborted before commit (put_operation duplicate id, bump_sign_count \
         SignCountReplay). result=\"fail\": redb plumbing / serialization / audit chain break.\n",
    );
    out.push_str("# TYPE dds_store_writes_total counter\n");
    out.push_str(&format!(
        "dds_store_writes_total{{result=\"ok\"}} {}\n",
        store_write_counts.ok
    ));
    out.push_str(&format!(
        "dds_store_writes_total{{result=\"conflict\"}} {}\n",
        store_write_counts.conflict
    ));
    out.push_str(&format!(
        "dds_store_writes_total{{result=\"fail\"}} {}\n",
        store_write_counts.fail
    ));

    // `dds_memory_resident_bytes` — process RSS gauge. Read at scrape
    // time via `process_resident_bytes()` (sysinfo). Reading failures
    // (sysinfo doesn't see our own pid for some reason) degrade to 0
    // rather than panic the scrape task; the family's `# HELP` /
    // `# TYPE` headers always ship so the catalog stays discoverable.
    out.push_str(
        "# HELP dds_memory_resident_bytes Resident set size of the dds-node process in bytes \
         (from sysinfo at scrape time). 0 indicates the process query did not return a value \
         (sysinfo could not see this pid) — operators alarming on RSS should pair the gauge with \
         dds_uptime_seconds to disambiguate startup transients.\n",
    );
    out.push_str("# TYPE dds_memory_resident_bytes gauge\n");
    out.push_str(&format!(
        "dds_memory_resident_bytes {}\n",
        process_resident_bytes()
    ));

    // `dds_thread_count` — OS thread count gauge. Read at scrape time
    // via the platform-specific [`process_thread_count()`] shim; on
    // unsupported platforms (or read failures) the helper returns 0.
    // The `# HELP` / `# TYPE` headers always ship so the catalog stays
    // discoverable even when the read degrades.
    out.push_str(
        "# HELP dds_thread_count OS-level thread count of the dds-node process at scrape time. \
         Read via /proc/self/status (Linux), proc_pidinfo PROC_PIDTASKINFO (macOS), or a \
         CreateToolhelp32Snapshot walk filtered to the current pid (Windows). 0 indicates the \
         platform query did not return a value (sandbox restriction, transient race, or \
         unsupported target) — operators alarming on thread growth should pair the gauge with \
         dds_uptime_seconds to disambiguate startup transients.\n",
    );
    out.push_str("# TYPE dds_thread_count gauge\n");
    out.push_str(&format!("dds_thread_count {}\n", process_thread_count()));

    out
}

/// Resident set size of *this* process in bytes, read via sysinfo at
/// scrape time. Returns 0 if sysinfo could not query the pid (e.g. on
/// a sandbox that hides /proc-equivalents) so the scrape never
/// panics; the catalog's `# HELP` / `# TYPE` headers still ship.
///
/// Refresh strategy follows the [`crate::bin::dds_loadtest`] pattern:
/// build a fresh [`sysinfo::System`] per call, refresh just our own
/// pid with [`sysinfo::ProcessRefreshKind::with_memory`], and read
/// [`sysinfo::Process::memory`]. Per-call construction keeps the
/// telemetry module free of process-wide mutable state and bounds the
/// syscall surface to what the metric needs (one process query +
/// memory read). On macOS that is one `task_info` call and on Linux
/// it is one `/proc/<pid>/status` parse; on Windows it is one
/// `K32GetProcessMemoryInfo` call. None of these are hot enough at the
/// default 15 s Prometheus scrape interval to justify caching.
fn process_resident_bytes() -> u64 {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let mut sys = System::new();
    let pid = Pid::from_u32(std::process::id());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::new().with_memory(),
    );
    sys.process(pid).map(|p| p.memory()).unwrap_or(0)
}

/// OS-level thread count of *this* process, read at scrape time via a
/// platform-specific shim. Returns 0 if the platform query fails
/// (sandbox restrictions, transient race) or on an unsupported target
/// so the scrape never panics; the catalog's `# HELP` / `# TYPE`
/// headers still ship.
///
/// sysinfo 0.32 does not expose per-process thread counts in a
/// portable accessor (its `Process::tasks()` returns `Some` only on
/// Linux), so this helper goes directly to each platform's native
/// API:
///
/// - **Linux** — parse the `Threads:` line out of `/proc/self/status`.
///   Single small `read_to_string` + line scan; no directory
///   enumeration.
/// - **macOS** — call [`libc::proc_pidinfo`] with `PROC_PIDTASKINFO`
///   and read [`libc::proc_taskinfo::pti_threadnum`]. One syscall.
/// - **Windows** — walk a `TH32CS_SNAPTHREAD` snapshot via
///   [`windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32First`]
///   / `Thread32Next`, counting entries whose `th32OwnerProcessID`
///   matches our own pid. The snapshot is a one-shot point-in-time
///   capture so the gauge does not hold any cross-process locks for
///   its lifetime.
/// - **Other targets** — fall through to 0 (currently no DDS build
///   targets fall here, but the gauge stays discoverable).
fn process_thread_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/status carries a `Threads:` line that is the
        // kernel-maintained thread count for the current task group.
        // Cheaper than enumerating /proc/self/task entries.
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Threads:") {
                    if let Ok(n) = rest.trim().parse::<u64>() {
                        return n;
                    }
                }
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo with PROC_PIDTASKINFO returns a proc_taskinfo
        // whose pti_threadnum is the current thread count for our
        // task. The call returns the bytes written; anything other
        // than the full struct size is treated as a failure.
        let pid = std::process::id() as i32;
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written != size {
            return 0;
        }
        let info = unsafe { info.assume_init() };
        if info.pti_threadnum < 0 {
            0
        } else {
            info.pti_threadnum as u64
        }
    }

    #[cfg(target_os = "windows")]
    {
        // CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) gives a
        // one-shot point-in-time view of every thread on the system;
        // we filter to entries whose th32OwnerProcessID matches our
        // current pid. The snapshot handle is freed via CloseHandle
        // before the helper returns.
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        let pid = unsafe { GetCurrentProcessId() };
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return 0;
        }
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut count: u64 = 0;
        if unsafe { Thread32First(snapshot, &mut entry) } != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    count += 1;
                }
                if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot) };
        count
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        0
    }
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
        + StoreSizeStats
        + StoreWriteStats
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
        + StoreSizeStats
        + StoreWriteStats
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
        + StoreSizeStats
        + StoreWriteStats
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
        + StoreSizeStats
        + StoreWriteStats
        + Send
        + Sync
        + 'static,
{
    let (
        chain_length,
        head_timestamp,
        trust_graph,
        challenges_outstanding,
        store_bytes,
        store_write_counts,
    ) = {
        let svc = state.svc.lock().await;
        let len = svc.audit_chain_length().unwrap_or(0);
        let head = svc.audit_chain_head_timestamp().unwrap_or(None);
        let tg = svc.trust_graph_counts();
        let ch = svc.challenges_outstanding();
        let sb = svc.store_byte_sizes();
        let sw = svc.store_write_counts();
        (len, head, tg, ch, sb, sw)
    };
    let body = render_exposition(
        &state.telemetry,
        chain_length,
        head_timestamp,
        trust_graph,
        challenges_outstanding,
        state.peer_counts.as_ref(),
        store_bytes.as_ref(),
        store_write_counts,
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("dds_build_info{version=\""));
        // `git_sha` and `rust_version` labels (captured by build.rs)
        // round-trip through the exposition. Their values are
        // build-environment dependent (literal `unknown` outside a git
        // tree or sandboxed rustc), but the labels themselves are
        // always present.
        assert!(body.contains(",git_sha=\""));
        assert!(body.contains(",rust_version=\""));
        assert!(body.contains("} 1\n"));
        assert!(body.contains("# TYPE dds_uptime_seconds gauge\n"));
        assert!(body.contains("# TYPE dds_audit_entries_total counter\n"));
        assert!(body.contains("dds_audit_chain_length 0\n"));
        assert!(body.contains("dds_audit_chain_head_age_seconds 0\n"));
        // `dds_pq_releases_installed_total`, `dds_pq_releases_emitted_total`,
        // and `dds_pq_envelope_decrypt_total` families are always
        // discoverable (HELP + TYPE headers) even on a fresh node
        // where no EpochKeyRelease or gossip/sync envelope has been
        // processed yet.
        assert!(body.contains("# TYPE dds_pq_releases_installed_total counter\n"));
        assert!(body.contains("# TYPE dds_pq_releases_emitted_total counter\n"));
        assert!(body.contains("# TYPE dds_pq_envelope_decrypt_total counter\n"));
    }

    #[test]
    fn render_emits_pq_releases_installed_value_lines_after_bumps() {
        let t = Telemetry::new();
        // Drive a couple of result buckets through the bump path so the
        // renderer must emit the value lines (not just HELP / TYPE
        // headers).
        t.bump_pq_release_installed("ok");
        t.bump_pq_release_installed("ok");
        t.bump_pq_release_installed("aead");
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_pq_releases_installed_total counter\n"));
        assert!(body.contains("dds_pq_releases_installed_total{result=\"ok\"} 2\n"));
        assert!(body.contains("dds_pq_releases_installed_total{result=\"aead\"} 1\n"));
        // pq_releases_installed_count() reads the same Mutex<BTreeMap>
        // — pin that the public test hook agrees with the renderer.
        assert_eq!(t.pq_releases_installed_count("ok"), 2);
        assert_eq!(t.pq_releases_installed_count("aead"), 1);
        assert_eq!(t.pq_releases_installed_count("decap"), 0);
    }

    #[test]
    fn render_emits_pq_envelope_decrypt_value_lines_after_bumps() {
        let t = Telemetry::new();
        t.bump_pq_envelope_decrypt("ok");
        t.bump_pq_envelope_decrypt("ok");
        t.bump_pq_envelope_decrypt("ok");
        t.bump_pq_envelope_decrypt("no_key");
        t.bump_pq_envelope_decrypt("aead_fail");
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_pq_envelope_decrypt_total counter\n"));
        assert!(body.contains("dds_pq_envelope_decrypt_total{result=\"ok\"} 3\n"));
        assert!(body.contains("dds_pq_envelope_decrypt_total{result=\"no_key\"} 1\n"));
        assert!(body.contains("dds_pq_envelope_decrypt_total{result=\"aead_fail\"} 1\n"));
        assert_eq!(t.pq_envelope_decrypt_count("ok"), 3);
        assert_eq!(t.pq_envelope_decrypt_count("no_key"), 1);
        assert_eq!(t.pq_envelope_decrypt_count("aead_fail"), 1);
        assert_eq!(t.pq_envelope_decrypt_count("other"), 0);
    }

    #[test]
    fn render_emits_pq_releases_emitted_value_lines_after_bumps() {
        let t = Telemetry::new();
        t.bump_pq_releases_emitted("ok");
        t.bump_pq_releases_emitted("ok");
        t.bump_pq_releases_emitted("no_kem_pk");
        t.bump_pq_releases_emitted("mint_fail");
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_pq_releases_emitted_total counter\n"));
        assert!(body.contains("dds_pq_releases_emitted_total{result=\"ok\"} 2\n"));
        assert!(body.contains("dds_pq_releases_emitted_total{result=\"no_kem_pk\"} 1\n"));
        assert!(body.contains("dds_pq_releases_emitted_total{result=\"mint_fail\"} 1\n"));
        assert_eq!(t.pq_releases_emitted_count("ok"), 2);
        assert_eq!(t.pq_releases_emitted_count("no_kem_pk"), 1);
        assert_eq!(t.pq_releases_emitted_count("cbor_fail"), 0);
    }

    #[test]
    fn build_info_labels_are_in_documented_order_and_non_empty() {
        // Pin the on-wire label order — Phase E dashboards / alerts
        // already key off `dds_build_info{version=...}`, and an
        // accidental reorder would surface as a visual regression in
        // the Build-Skew panel even though Prometheus accepts label
        // order anywhere. Also pin that neither `git_sha` nor
        // `rust_version` empties out at runtime; build.rs falls back
        // to the literal `unknown` rather than an empty string when
        // the underlying `git` / `rustc` invocation fails, so an
        // empty value here would mean someone replaced the fallback
        // with `String::new()`.
        let body = render_exposition(
            &Telemetry::new(),
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        let line = body
            .lines()
            .find(|l| l.starts_with("dds_build_info{"))
            .expect("dds_build_info value line missing");
        assert!(
            line.contains("version=\""),
            "version label missing from {line}"
        );
        let version_idx = line.find(",git_sha=\"").expect("git_sha after version");
        let git_sha_idx = line
            .find(",rust_version=\"")
            .expect("rust_version after git_sha");
        assert!(
            version_idx < git_sha_idx,
            "labels out of documented order in {line}"
        );
        // Neither value should be empty — fallback is the literal
        // string `unknown`, never `""`.
        assert!(!line.contains("git_sha=\"\""), "git_sha is empty in {line}");
        assert!(
            !line.contains("rust_version=\"\""),
            "rust_version is empty in {line}"
        );
        assert!(line.ends_with("} 1"), "value line not `1` in {line}");
    }

    #[test]
    fn record_audit_entry_advances_per_action_counter_in_render() {
        let t = Telemetry::new();
        t.bump_audit_entry("attest");
        t.bump_audit_entry("attest");
        t.bump_audit_entry("revoke");

        let body = render_exposition(
            &t,
            3,
            Some(0),
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        // HELP/TYPE always discoverable before the first inbound
        // handshake fires so a freshly booted node still surfaces
        // the family in the catalog.
        assert!(body.contains("# TYPE dds_admission_handshakes_total counter\n"));
        assert!(!body.contains("dds_admission_handshakes_total{"));
        // The sibling last-failure-seconds gauge ships sentinel 0
        // before any failure lands so the family is still
        // discoverable in the catalog (matches the "always emit
        // HELP/TYPE" pattern we use for empty counter families).
        assert!(body.contains("# TYPE dds_admission_handshake_last_failure_seconds gauge\n"));
        assert!(body.contains("dds_admission_handshake_last_failure_seconds 0\n"));
        assert!(t.admission_handshake_last_failure_ts().is_none());
    }

    #[test]
    fn admission_handshake_last_failure_seconds_stamps_on_fail_and_revoked() {
        // `ok` outcomes do *not* advance the timestamp — the gauge is
        // a "last *failure*" surface, not a "last handshake" one.
        let t = Telemetry::new();
        t.bump_admission_handshake("ok");
        assert!(t.admission_handshake_last_failure_ts().is_none());

        // First non-`ok` outcome stamps a non-zero timestamp.
        t.bump_admission_handshake("fail");
        let after_fail = t
            .admission_handshake_last_failure_ts()
            .expect("fail outcome stamped a timestamp");
        assert!(after_fail > 0);

        // `revoked` is partitioned in the counter (so operators can
        // alert on cert-pipeline regressions vs. expected post-revoke
        // probing separately) but *both* feed the last-failure gauge
        // because both carry operational signal: a previously-admitted
        // peer still attempting to rejoin is a non-trivial event.
        t.bump_admission_handshake("revoked");
        let after_revoked = t
            .admission_handshake_last_failure_ts()
            .expect("revoked outcome stamped a timestamp");
        assert!(
            after_revoked >= after_fail,
            "revoked stamp ({after_revoked}) should not regress past fail stamp ({after_fail})"
        );

        // The exposition reflects whatever the Mutex currently
        // holds; we only assert it is non-zero (we cannot assert an
        // exact value because the bump uses wall-clock time).
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        let line = body
            .lines()
            .find(|l| l.starts_with("dds_admission_handshake_last_failure_seconds "))
            .expect("gauge line present in exposition");
        let value: u64 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("gauge value parses as u64");
        assert!(value >= after_fail);
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        // HELP/TYPE always discoverable before the first sync pull
        // resolves so a freshly booted node still surfaces the family
        // in the catalog (alert expressions resolve immediately).
        assert!(body.contains("# TYPE dds_sync_pulls_total counter\n"));
        assert!(!body.contains("dds_sync_pulls_total{"));
    }

    #[test]
    fn sync_payloads_rejected_counter_renders_in_exposition() {
        let t = Telemetry::new();
        // Pre-apply skip sites (M-1/M-2, C-3, M-9).
        t.bump_sync_payloads_rejected("legacy_v1");
        t.bump_sync_payloads_rejected("legacy_v1");
        t.bump_sync_payloads_rejected("publisher_capability");
        t.bump_sync_payloads_rejected("replay_window");
        // Post-apply categorical reasons sourced from
        // `SyncResult::rejected_by_reason`.
        t.bump_sync_payloads_rejected("signature");
        t.bump_sync_payloads_rejected("duplicate_jti");
        t.bump_sync_payloads_rejected("graph");
        t.bump_sync_payloads_rejected("graph");

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_sync_payloads_rejected_total counter\n"));
        assert!(body.contains("dds_sync_payloads_rejected_total{reason=\"legacy_v1\"} 2\n"));
        assert!(
            body.contains("dds_sync_payloads_rejected_total{reason=\"publisher_capability\"} 1\n")
        );
        assert!(body.contains("dds_sync_payloads_rejected_total{reason=\"replay_window\"} 1\n"));
        assert!(body.contains("dds_sync_payloads_rejected_total{reason=\"signature\"} 1\n"));
        assert!(body.contains("dds_sync_payloads_rejected_total{reason=\"duplicate_jti\"} 1\n"));
        assert!(body.contains("dds_sync_payloads_rejected_total{reason=\"graph\"} 2\n"));
        assert_eq!(t.sync_payloads_rejected_count("legacy_v1"), 2);
        assert_eq!(t.sync_payloads_rejected_count("publisher_capability"), 1);
        assert_eq!(t.sync_payloads_rejected_count("replay_window"), 1);
        assert_eq!(t.sync_payloads_rejected_count("signature"), 1);
        assert_eq!(t.sync_payloads_rejected_count("duplicate_jti"), 1);
        assert_eq!(t.sync_payloads_rejected_count("graph"), 2);
    }

    #[test]
    fn sync_payloads_rejected_renders_empty_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        // HELP/TYPE always discoverable before the first pre-apply
        // sync rejection fires so a freshly booted node still surfaces
        // the family in the catalog (alert expressions resolve
        // immediately).
        assert!(body.contains("# TYPE dds_sync_payloads_rejected_total counter\n"));
        assert!(!body.contains("dds_sync_payloads_rejected_total{"));
    }

    #[test]
    fn http_requests_counter_renders_in_exposition() {
        let t = Telemetry::new();
        t.bump_http_request("/v1/status", "GET", 200);
        t.bump_http_request("/v1/status", "GET", 200);
        t.bump_http_request("/v1/audit/entries", "GET", 401);
        t.bump_http_request("/v1/admin/setup", "POST", 503);

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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

        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let mut by_body_type = std::collections::BTreeMap::new();
        by_body_type.insert("user-auth-attestation", 4usize);
        by_body_type.insert("device-join", 2usize);
        by_body_type.insert("windows-policy", 1usize);
        let counts = TrustGraphCounts {
            attestations: 7,
            vouches: 3,
            revocations: 2,
            burned: 1,
            attestations_by_body_type: by_body_type,
        };
        let body = render_exposition(
            &t,
            0,
            None,
            Some(counts),
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_trust_graph_attestations gauge\n"));
        // observability-plan.md Phase C — the body_type partition
        // closes the deferred row from the original catalog. Sum
        // across labels equals the unlabeled attestations total
        // (4 + 2 + 1 == 7).
        assert!(
            body.contains("dds_trust_graph_attestations{body_type=\"user-auth-attestation\"} 4\n"),
        );
        assert!(body.contains("dds_trust_graph_attestations{body_type=\"device-join\"} 2\n"));
        assert!(body.contains("dds_trust_graph_attestations{body_type=\"windows-policy\"} 1\n"));
        // Old shape (unlabeled) must NOT appear — the metric is now
        // labeled. Operators query `sum(dds_trust_graph_attestations)`
        // for the previous total.
        assert!(!body.contains("\ndds_trust_graph_attestations 7\n"));
        assert!(body.contains("dds_trust_graph_vouches 3\n"));
        assert!(body.contains("dds_trust_graph_revocations 2\n"));
        assert!(body.contains("dds_trust_graph_burned 1\n"));
    }

    #[test]
    fn trust_graph_gauges_default_to_zero_when_lock_poisoned() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        // Empty graph emits a single zero-valued anchor series under
        // the `unknown` body_type bucket so the family always has at
        // least one value line — same discoverability pattern as the
        // other zero-state metrics.
        assert!(body.contains("# TYPE dds_trust_graph_attestations gauge\n"));
        assert!(body.contains("dds_trust_graph_attestations{body_type=\"unknown\"} 0\n"));
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
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            Some(&counts),
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 4\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 7\n"));
    }

    #[test]
    fn peer_count_gauges_default_to_zero_when_no_handle_supplied() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        // HELP/TYPE always discoverable so the family resolves on a
        // freshly booted node before any peer connects (or in
        // deployments running the metrics endpoint without a swarm).
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 0\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 0\n"));
    }

    #[test]
    fn store_bytes_family_is_discoverable_when_snapshot_is_empty() {
        // No `store_bytes` snapshot supplied (read failed or the backend
        // returned an empty map): the renderer must still ship the
        // family's HELP/TYPE headers so operators can see the catalog
        // entry on `/metrics` even before the first redb-backed
        // deployment scrapes. Pins the discoverability contract used
        // by every per-table snapshot.
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# HELP dds_store_bytes "));
        assert!(body.contains("# TYPE dds_store_bytes gauge\n"));
        assert!(
            !body.contains("dds_store_bytes{"),
            "no value lines expected when snapshot is None: {body}"
        );

        // Empty `tables` map (the `MemoryBackend` impl) renders the same
        // way — discoverable family, no value lines.
        let empty = StoreByteSizes::default();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            Some(&empty),
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_store_bytes gauge\n"));
        assert!(!body.contains("dds_store_bytes{"));
    }

    #[test]
    fn store_bytes_renders_one_series_per_supplied_table() {
        // A populated snapshot must produce one `dds_store_bytes{table=...}`
        // line per entry, with the bytes value on the right of the
        // exposition. Pins the spelling and label encoding the catalog
        // commits to (`table` label, gauge type, integer bytes).
        let t = Telemetry::new();
        let mut tables = std::collections::BTreeMap::new();
        tables.insert("tokens", 4096u64);
        tables.insert("audit_log", 65_536u64);
        tables.insert("operations", 0u64);
        let snap = StoreByteSizes { tables };
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            Some(&snap),
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_store_bytes gauge\n"));
        assert!(body.contains("dds_store_bytes{table=\"tokens\"} 4096\n"));
        assert!(body.contains("dds_store_bytes{table=\"audit_log\"} 65536\n"));
        // A zero-byte table still emits a series so an operator can
        // graph "table exists, currently empty" distinct from
        // "backend doesn't expose the table".
        assert!(body.contains("dds_store_bytes{table=\"operations\"} 0\n"));
    }

    #[test]
    fn challenges_outstanding_renders_supplied_count() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            Some(12),
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# TYPE dds_challenges_outstanding gauge\n"));
        assert!(body.contains("dds_challenges_outstanding 12\n"));
    }

    #[test]
    fn challenges_outstanding_defaults_to_zero_when_store_read_fails() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        let body = render_exposition(
            &t,
            1,
            Some(now.saturating_sub(30)),
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
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
        // `git_sha` and `rust_version` labels travel through the
        // served exposition the same way the `version` label does.
        assert!(body.contains(",git_sha=\""));
        assert!(body.contains(",rust_version=\""));
        assert!(body.contains("# TYPE dds_audit_entries_total counter\n"));
        assert!(body.contains("dds_audit_entries_total{action=\"attest\"} 2\n"));
        assert!(body.contains("dds_audit_entries_total{action=\"revoke\"} 1\n"));
        // Empty MemoryBackend audit chain → length 0, head_age 0.
        assert!(body.contains("dds_audit_chain_length 0\n"));
        assert!(body.contains("dds_audit_chain_head_age_seconds 0\n"));
        // `make_test_service` seeds one root self-attestation with
        // `body_type: None` → `body_type="unknown"` partition. Vouches /
        // revocations / burned remain empty.
        assert!(body.contains("# TYPE dds_trust_graph_attestations gauge\n"));
        assert!(body.contains("dds_trust_graph_attestations{body_type=\"unknown\"} 1\n"));
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
        // Sync-payloads-rejected family is always discoverable; no
        // value lines until the first pre-apply sync rejection fires
        // inside `handle_sync_response`.
        assert!(body.contains("# TYPE dds_sync_payloads_rejected_total counter\n"));
        // HTTP-requests family is always discoverable; no value lines
        // until the first matched-route request returns through
        // `http_request_observer_middleware`.
        assert!(body.contains("# TYPE dds_http_requests_total counter\n"));
        // Peer-count gauges round-trip through the served exposition.
        assert!(body.contains("# TYPE dds_peers_admitted gauge\n"));
        assert!(body.contains("dds_peers_admitted 2\n"));
        assert!(body.contains("# TYPE dds_peers_connected gauge\n"));
        assert!(body.contains("dds_peers_connected 3\n"));
        // `dds_store_bytes` family is always discoverable. The
        // MemoryBackend `StoreSizeStats` impl returns an empty map by
        // design, so no value lines are present until a
        // RedbBackend-backed deployment scrapes; the HELP/TYPE headers
        // still ship.
        assert!(body.contains("# TYPE dds_store_bytes gauge\n"));
        assert!(
            !body.contains("dds_store_bytes{table="),
            "MemoryBackend should not emit dds_store_bytes value lines (got: {body})"
        );
        // `dds_store_writes_total` family is always discoverable AND
        // always emits its three value lines (zero-initialised).
        // `make_test_service` builds the trust graph in-memory and
        // wires a fresh `MemoryBackend::new()` without touching the
        // store traits, so all three buckets render zero. The
        // freshly-bootstrapped scrape contract (zero counters
        // explicit, family present) is exactly what Prometheus
        // expects so a counter rate computation is well-defined from
        // the first scrape.
        assert!(body.contains("# TYPE dds_store_writes_total counter\n"));
        assert!(body.contains("dds_store_writes_total{result=\"ok\"} 0\n"));
        assert!(body.contains("dds_store_writes_total{result=\"conflict\"} 0\n"));
        assert!(body.contains("dds_store_writes_total{result=\"fail\"} 0\n"));
        // `dds_memory_resident_bytes` family ships HELP/TYPE on every
        // scrape and exactly one value line — no labels.
        assert!(body.contains("# TYPE dds_memory_resident_bytes gauge\n"));
        let value_lines = body
            .lines()
            .filter(|l| l.starts_with("dds_memory_resident_bytes "))
            .count();
        assert_eq!(
            value_lines, 1,
            "expected exactly one dds_memory_resident_bytes value line"
        );
        // `dds_thread_count` family ships HELP/TYPE on every scrape and
        // exactly one value line — no labels. The value itself depends
        // on the tokio test runtime's thread pool, so the test only
        // asserts the family contract.
        assert!(body.contains("# TYPE dds_thread_count gauge\n"));
        let thread_value_lines = body
            .lines()
            .filter(|l| l.starts_with("dds_thread_count "))
            .count();
        assert_eq!(
            thread_value_lines, 1,
            "expected exactly one dds_thread_count value line"
        );
    }

    /// Default (zero) [`StoreWriteCounts`] still ships the three value
    /// lines so a fresh node scrape exposes the family before any
    /// write has happened — pins the "counter present at zero" vs.
    /// "metric absent" distinction the Prometheus exposition uses.
    #[test]
    fn store_writes_emits_three_zero_lines_on_default_snapshot() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# HELP dds_store_writes_total "));
        assert!(body.contains("# TYPE dds_store_writes_total counter\n"));
        assert!(body.contains("dds_store_writes_total{result=\"ok\"} 0\n"));
        assert!(body.contains("dds_store_writes_total{result=\"conflict\"} 0\n"));
        assert!(body.contains("dds_store_writes_total{result=\"fail\"} 0\n"));
    }

    /// A populated [`StoreWriteCounts`] renders one value line per
    /// bucket with the supplied count — pins the per-`result`
    /// dispatch path the exposition commits to.
    #[test]
    fn store_writes_renders_per_result_value_lines() {
        let t = Telemetry::new();
        let snap = StoreWriteCounts {
            ok: 17,
            conflict: 4,
            fail: 1,
        };
        let body = render_exposition(&t, 0, None, None, None, None, None, snap);
        assert!(body.contains("dds_store_writes_total{result=\"ok\"} 17\n"));
        assert!(body.contains("dds_store_writes_total{result=\"conflict\"} 4\n"));
        assert!(body.contains("dds_store_writes_total{result=\"fail\"} 1\n"));
    }

    /// `dds_memory_resident_bytes` ships its `# HELP` / `# TYPE`
    /// header and a single value line on every render, even when the
    /// rest of the snapshot is empty — pins the "family always
    /// discoverable" contract the rest of the catalog also commits
    /// to. The value itself is whatever sysinfo returns for the test
    /// process (a positive RSS, or 0 in a sandbox that hides the
    /// pid); the test does not assert on a specific number because
    /// process RSS varies with the test runner.
    #[test]
    fn memory_resident_bytes_renders_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# HELP dds_memory_resident_bytes "));
        assert!(body.contains("# TYPE dds_memory_resident_bytes gauge\n"));
        // Exactly one value line — no labels on this gauge.
        let value_lines = body
            .lines()
            .filter(|l| l.starts_with("dds_memory_resident_bytes "))
            .count();
        assert_eq!(value_lines, 1, "expected exactly one value line");
    }

    /// Direct call to the scrape-time helper: the test process has
    /// non-trivial RSS by definition (it has loaded the dds-node test
    /// binary), so a healthy sysinfo should return a positive number.
    /// In sandbox environments where sysinfo cannot resolve the pid
    /// the helper degrades to 0; that's also acceptable, so the test
    /// only asserts the function does not panic and returns a `u64`.
    /// The "positive on a normal system" property is exercised by the
    /// adjacent assertion that the rendered value parses cleanly.
    #[test]
    fn process_resident_bytes_returns_a_finite_u64() {
        let bytes = process_resident_bytes();
        // u64::MAX would indicate a sysinfo overflow bug, not a real
        // RSS value; assert the read is in a sensible range.
        assert!(bytes < u64::MAX);
    }

    /// `dds_thread_count` ships its `# HELP` / `# TYPE` header and a
    /// single value line on every render — pins the "family always
    /// discoverable" contract the rest of the catalog also commits
    /// to. The value itself is whatever the platform shim returns
    /// for the test process (a positive thread count, or 0 in a
    /// sandbox that hides the count); the test does not assert on a
    /// specific number because the tokio test runtime spins a varying
    /// thread pool.
    #[test]
    fn thread_count_renders_family_with_help_and_type() {
        let t = Telemetry::new();
        let body = render_exposition(
            &t,
            0,
            None,
            None,
            None,
            None,
            None,
            StoreWriteCounts::default(),
        );
        assert!(body.contains("# HELP dds_thread_count "));
        assert!(body.contains("# TYPE dds_thread_count gauge\n"));
        // Exactly one value line — no labels on this gauge.
        let value_lines = body
            .lines()
            .filter(|l| l.starts_with("dds_thread_count "))
            .count();
        assert_eq!(value_lines, 1, "expected exactly one value line");
    }

    /// Direct call to the scrape-time helper. Every running process
    /// has at least its main thread, so on supported targets
    /// (Linux / macOS / Windows) the helper should report >= 1; on
    /// unsupported targets or under sandbox restrictions the helper
    /// returns 0. The test asserts it does not panic and that, on
    /// the supported targets we actually build for, the count is
    /// non-zero — that guards against a regression in the platform
    /// shim that would silently flat-line the gauge.
    #[test]
    fn process_thread_count_returns_a_finite_u64() {
        let n = process_thread_count();
        assert!(n < u64::MAX);
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            assert!(
                n >= 1,
                "expected at least the main thread on a supported target, got 0"
            );
        }
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
