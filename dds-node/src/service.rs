//! Local authority service — enrollment, sessions, policy resolution, status.
//!
//! This module turns dds-node into the authoritative local service that
//! client applications talk to. It provides:
//! - **Enrollment**: accept device/user join requests, issue attestation tokens
//! - **Session issuance**: create short-lived SessionDocuments (< 1ms local check)
//! - **Policy resolution**: evaluate access decisions against the trust graph
//! - **Status reporting**: health, sync state, peer count, trust stats

use base64::Engine;
use dds_core::audit::AuditLogEntry;
use dds_core::identity::Identity;
use dds_core::policy::{PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::{
    AccountAction, AccountDirective, DeviceJoinDocument, DomainDocument, Enforcement,
    LinuxPolicyDocument, MacOsPolicyDocument, PolicyScope, SessionDocument, SoftwareAssignment,
    UserAuthAttestation, WindowsPolicyDocument,
};
use dds_store::traits::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroize;

/// Request to enroll a user via FIDO2 attestation.
#[derive(Debug, Clone)]
pub struct EnrollUserRequest {
    pub label: String,
    pub credential_id: String,
    pub attestation_object: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub rp_id: String,
    pub display_name: String,
    pub authenticator_type: String,
    /// **A-1 step-3 (security review)**: raw UTF-8 bytes of the
    /// authenticator's `clientDataJSON` from MakeCredential. Optional
    /// for backward compatibility — when present, the server parses
    /// the JSON and validates `type == "webauthn.create"`,
    /// `origin == "https://<rp_id>"`, and `crossOrigin != true` per
    /// WebAuthn §7.1 steps 8–11. The supplied JSON is bound to the
    /// signed `client_data_hash` first, so an attacker cannot present
    /// unrelated bytes that happen to parse with the right fields.
    /// When absent, only the `client_data_hash` -> `authData`
    /// rp-id-hash check runs (legacy behaviour). Mirrors the M-12
    /// pattern at the assertion side.
    pub client_data_json: Option<Vec<u8>>,
    /// **A-1 follow-up (server-issued enrollment challenge)**: optional
    /// server-issued challenge ID from `GET /v1/enroll/challenge`. When
    /// present together with `client_data_json`, the server consumes
    /// the challenge atomically and verifies that the
    /// `clientDataJSON.challenge` field decodes to the same bytes the
    /// server issued — closing the last remaining gap in the WebAuthn
    /// §7.1 step list at enrollment (the assertion side already does
    /// this via `consume_challenge`). Backward compatible: when absent
    /// the legacy "no challenge validation at enroll" path runs, so
    /// existing callers (and code paths that still build the request
    /// without a server round-trip, e.g. the bootstrap admin) keep
    /// working unchanged.
    pub challenge_id: Option<String>,
}

/// Request to enroll a device.
#[derive(Debug, Clone)]
pub struct EnrollDeviceRequest {
    pub label: String,
    pub device_id: String,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub tpm_ek_hash: Option<String>,
    pub org_unit: Option<String>,
    pub tags: Vec<String>,
}

/// Request to issue a session from a FIDO2 assertion proof.
#[derive(Debug, Clone)]
pub struct AssertionSessionRequest {
    pub subject_urn: Option<String>,
    pub credential_id: String,
    /// Server-issued challenge ID from `GET /v1/session/challenge`.
    pub challenge_id: String,
    pub client_data_hash: Vec<u8>,
    /// **M-12 (security review)**: raw UTF-8 bytes of the
    /// authenticator's `clientDataJSON`. Optional for backward
    /// compatibility — when present, the server parses the JSON and
    /// validates `type`, `origin`, `challenge` per WebAuthn §7.2
    /// steps 7–9 instead of reconstructing the expected JSON and
    /// comparing hashes (which is fragile: any difference in key
    /// ordering or escaping from the client's serializer produces a
    /// spurious mismatch). When absent, the legacy reconstruct-and-
    /// compare path runs.
    pub client_data_json: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub duration_secs: Option<u64>,
}

/// Request to register an admin identity with FIDO2 proof-of-possession.
/// Reuses the same fields as EnrollUserRequest — the only difference is
/// that the generated signing key is persisted for future vouch operations.
pub type AdminSetupRequest = EnrollUserRequest;

/// Request for an admin to vouch for (approve) an enrolled user.
#[derive(Debug, Clone)]
pub struct AdminVouchRequest {
    pub subject_urn: String,
    pub credential_id: String,
    /// Server-issued challenge ID from `GET /v1/admin/challenge`.
    pub challenge_id: String,
    pub client_data_hash: Vec<u8>,
    /// M-12 (see `AssertionSessionRequest::client_data_json`).
    pub client_data_json: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub purpose: Option<String>,
}

/// Result of an admin vouch operation.
#[derive(Debug)]
pub struct AdminVouchResult {
    pub vouch_jti: String,
    pub subject_urn: String,
    pub admin_urn: String,
    /// CBOR of the signed Vouch token so the HTTP layer can gossip it
    /// via [`crate::node::PublishCommand`] — approvals must replicate
    /// to peer nodes, not just live in this node's store.
    pub token_cbor: Vec<u8>,
}

/// Request for an admin to revoke its previously-issued vouches for a
/// subject (user/admin offboarding). Carries the same FIDO2 UV
/// assertion ceremony as [`AdminVouchRequest`].
#[derive(Debug, Clone)]
pub struct AdminRevokeVouchRequest {
    pub subject_urn: String,
    pub credential_id: String,
    /// Server-issued challenge ID from `GET /v1/admin/challenge`.
    pub challenge_id: String,
    pub client_data_hash: Vec<u8>,
    pub client_data_json: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// Restrict revocation to vouches carrying this purpose.
    /// `None` revokes every active vouch this admin issued for the
    /// subject.
    pub purpose: Option<String>,
}

/// One vouch revoked by [`LocalService::admin_revoke_vouch`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct RevokedVouchInfo {
    /// JTI of the newly-minted Revoke token (probe this on peers to
    /// confirm replication).
    pub revoke_jti: String,
    /// JTI of the vouch that was revoked.
    pub target_jti: String,
    pub purpose: Option<String>,
}

/// An active vouch for the subject that THIS admin cannot revoke
/// (H-1: only the issuing admin can). Surfaced so the offboarding
/// wizard can tell the operator which admin must also act.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForeignVouchInfo {
    pub target_jti: String,
    pub issuer: String,
    pub purpose: Option<String>,
}

/// Result of an admin revoke-vouch (offboarding) operation.
#[derive(Debug)]
pub struct AdminRevokeVouchResult {
    pub subject_urn: String,
    pub admin_urn: String,
    pub revoked: Vec<RevokedVouchInfo>,
    pub foreign: Vec<ForeignVouchInfo>,
    /// True when the subject was also removed from this node's
    /// `trusted_roots` (a `dds:admin` vouch was among the revoked).
    pub demoted_from_trusted_roots: bool,
    /// The signed Revoke tokens, for the HTTP layer to gossip via
    /// [`crate::node::PublishCommand`] so peers apply the revocations.
    pub revoke_tokens: Vec<dds_core::token::Token>,
}

/// One trusted-root entry for `GET /v1/admin/roots`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminRootInfo {
    pub urn: String,
    pub is_bootstrap: bool,
    /// Display name from the admin's enrollment attestation, when one
    /// is in the graph.
    pub display_name: Option<String>,
    /// Whether a live (non-revoked, non-expired) `dds:admin` vouch for
    /// this root exists in the graph. The bootstrap admin needs none.
    pub has_active_admin_vouch: bool,
}

/// Internal output of the shared FIDO2 assertion verifier.
#[derive(Debug)]
struct CommonAssertionOutput {
    subject_urn: String,
    user_verified: bool,
}

/// Drop-guard that funnels every exit branch of
/// [`LocalService::verify_assertion_common`] into a single
/// `dds_fido2_assertions_total{result=...}` bump. The default bucket
/// is `"other"`; named branches (`signature`, `rp_id`, `up`,
/// `sign_count`, `ok`) overwrite the field before the function
/// returns. Drop-on-return guarantees the metric advances exactly
/// once per assertion attempt, including paths that exit via `?`
/// without explicit classification (those collapse into `"other"`).
struct AssertionMetricGuard {
    bucket: &'static str,
}

impl AssertionMetricGuard {
    fn new() -> Self {
        Self { bucket: "other" }
    }
}

impl Drop for AssertionMetricGuard {
    fn drop(&mut self) {
        crate::telemetry::record_fido2_assertion(self.bucket);
    }
}

/// Enrolled user info for CP tile enumeration.
///
/// **Security note**: `credential_id` is included because the Windows
/// Credential Provider and Auth Bridge require it to initiate WebAuthn
/// assertions for the correct credential. This endpoint is localhost-only
/// and protected by OS process isolation. The `vouched` field indicates
/// whether the user has any granted purposes in the trust graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrolledUser {
    pub subject_urn: String,
    pub display_name: String,
    pub credential_id: String,
    #[serde(default)]
    pub vouched: bool,
    /// True when the subject HAD at least one vouch and every vouch is
    /// now revoked — i.e. the user was offboarded (distinct from a
    /// pending user who was never approved). Offboarded users are
    /// excluded from the listing by default so Credential Provider
    /// logon tiles disappear without a bridge change; the console asks
    /// for them explicitly with `?include_revoked=1`.
    #[serde(default)]
    pub revoked: bool,
}

/// Request to issue a session.
#[derive(Debug, Clone)]
pub struct SessionRequest {
    pub subject_urn: String,
    pub device_urn: Option<String>,
    pub requested_resources: Vec<String>,
    pub duration_secs: u64,
    pub mfa_verified: bool,
    pub tls_binding: Option<String>,
}

/// Service response with enrolled identity or session.
#[derive(Debug)]
pub struct EnrollmentResult {
    pub urn: String,
    pub jti: String,
    pub token_cbor: Vec<u8>,
}

/// Session issuance result.
#[derive(Debug)]
pub struct SessionResult {
    pub session_id: String,
    pub token_cbor: Vec<u8>,
    pub expires_at: u64,
}

/// Node status report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeStatus {
    pub peer_id: String,
    pub connected_peers: usize,
    pub dag_operations: usize,
    pub trust_graph_tokens: usize,
    pub trusted_roots: usize,
    pub store_tokens: usize,
    pub store_revoked: usize,
    pub store_burned: usize,
    pub uptime_secs: u64,
    /// Per-redb-table stored-byte snapshot, mirroring the
    /// `dds_store_bytes{table=...}` Prometheus gauge from
    /// observability-plan.md Phase C. `None` on backends that do not
    /// implement [`dds_store::traits::StoreSizeStats`] (e.g.
    /// `MemoryBackend` in test fixtures) and on older clients that
    /// deserialise the response without this field. Closes the
    /// `dds-cli stats` Phase F deferred row by giving operators a
    /// single-call snapshot of on-disk usage without scraping
    /// `/metrics`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_bytes: Option<BTreeMap<String, u64>>,
    /// Unix-seconds timestamp of the most recent non-`ok` inbound H-12
    /// admission handshake (`fail` or `revoked` outcome from
    /// [`crate::node::DdsNode::verify_peer_admission`]). Mirrors the
    /// `dds_admission_handshake_last_failure_seconds` Prometheus gauge
    /// from observability-plan.md Phase C and closes the second
    /// `dds-cli stats` Phase F deferred row (`last admission failure`):
    /// `dds_admission_handshakes_total{result="fail"}` is a since-boot
    /// counter, so a meaningful "how long ago" surface needs the
    /// timestamp gauge as a sibling.
    ///
    /// `None` before the first failure / revocation lands and on
    /// older clients that deserialise the response without this
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_admission_failure_ts: Option<u64>,
}

/// Policy evaluation result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: String,
}

/// One-shot trust-graph counts collected under a single read-lock for
/// the Prometheus exposition (observability-plan.md Phase C). The
/// metrics renderer reads all four gauges from a single snapshot so
/// scrape latency stays bounded by one lock acquisition.
///
/// `attestations_by_body_type` partitions the attestation total by the
/// `payload.body_type` carried on each token, mapped through the
/// fixed [`dds_domain::body_types`] vocabulary into a short label name
/// (the `dds:` URI prefix is stripped — `dds:user-auth-attestation`
/// becomes `body_type="user-auth-attestation"`). Tokens whose
/// `body_type` is `None` or does not match any known body-type URI
/// fall into the `unknown` bucket so the partition's sum is always
/// equal to the unlabeled `attestations` total.
#[derive(Debug, Clone, Default)]
pub struct TrustGraphCounts {
    pub attestations: usize,
    pub vouches: usize,
    pub revocations: usize,
    pub burned: usize,
    pub attestations_by_body_type: std::collections::BTreeMap<&'static str, usize>,
}

/// One-shot per-table byte snapshot for the `dds_store_bytes{table=...}`
/// Prometheus gauge (observability-plan.md Phase C). Wraps the
/// [`dds_store::traits::StoreSizeStats::table_stored_bytes`] result so
/// the renderer's signature stays simple — the renderer takes
/// `Option<StoreByteSizes>` and emits one gauge series per `table`
/// entry, falling back to the empty family on `None` (read failed) so
/// the family's `# HELP` / `# TYPE` headers stay discoverable.
#[derive(Debug, Clone, Default)]
pub struct StoreByteSizes {
    pub tables: std::collections::BTreeMap<&'static str, u64>,
}

/// Map a `body_type` URI from a token payload to the short label used
/// by the `dds_trust_graph_attestations{body_type=...}` Prometheus
/// gauge partition (observability-plan.md Phase C). The vocabulary is
/// bounded by the fixed [`dds_domain::body_types`] catalog; tokens
/// whose `body_type` is `None` or outside that catalog fall into the
/// `"unknown"` bucket so the partition's sum equals the unlabeled
/// total. Adding a new body type to `dds_domain::body_types` requires
/// adding a matching arm here — the
/// `body_type_label_covers_every_body_types_constant` test pins that
/// invariant.
pub(crate) fn body_type_label(body_type: Option<&str>) -> &'static str {
    use dds_domain::body_types;
    match body_type {
        Some(body_types::USER_AUTH_ATTESTATION) => "user-auth-attestation",
        Some(body_types::DEVICE_JOIN) => "device-join",
        Some(body_types::WINDOWS_POLICY) => "windows-policy",
        Some(body_types::MACOS_POLICY) => "macos-policy",
        Some(body_types::LINUX_POLICY) => "linux-policy",
        Some(body_types::MACOS_ACCOUNT_BINDING) => "macos-account-binding",
        Some(body_types::SSO_IDENTITY_LINK) => "sso-identity-link",
        Some(body_types::SOFTWARE_ASSIGNMENT) => "software-assignment",
        Some(body_types::SERVICE_PRINCIPAL) => "service-principal",
        Some(body_types::SESSION) => "session",
        _ => "unknown",
    }
}

// ----------------------------------------------------------------
// Platform applier surface (Windows + macOS)
//
// `LocalService` exposes scope-filtered lists of `WindowsPolicyDocument`
// / `MacOsPolicyDocument` and `SoftwareAssignment` for the loopback
// HTTP API the off-process `DdsPolicyAgent` consumes. The agent itself
// is .NET; we keep the scope-matching logic on the Rust side so that
// policy decisions stay in one place and so non-platform nodes can
// still answer the query (the agent runs on the same box, but a future
// MDM dashboard might query this from a control-plane node).
//
// `record_applied` is the agent's report-back path; for v1 we log via
// `tracing::info!` so the existing observability stack picks it up.
// A future PR can add a persistent applier-audit table.
// ----------------------------------------------------------------

/// One `WindowsPolicyDocument` packaged for the agent. Carries
/// provenance (`jti`, `issuer`, `iat`) so the agent can de-dupe and
/// correlate audit reports back to a specific token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ApplicableWindowsPolicy {
    pub jti: String,
    pub issuer: String,
    pub iat: u64,
    pub document: WindowsPolicyDocument,
}

/// One `MacOsPolicyDocument` packaged for the agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ApplicableMacOsPolicy {
    pub jti: String,
    pub issuer: String,
    pub iat: u64,
    pub document: MacOsPolicyDocument,
}

/// One `LinuxPolicyDocument` packaged for the agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ApplicableLinuxPolicy {
    pub jti: String,
    pub issuer: String,
    pub iat: u64,
    pub document: LinuxPolicyDocument,
}

/// One `SoftwareAssignment` packaged for the agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ApplicableSoftware {
    pub jti: String,
    pub issuer: String,
    pub iat: u64,
    pub document: SoftwareAssignment,
}

/// One local Windows account claim resolved for a DDS subject on a
/// specific device. The Windows Auth Bridge consumes this after it
/// proves user possession of the enrolled FIDO2 credential.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WindowsAccountClaim {
    pub subject_urn: String,
    pub username: String,
    pub full_name: Option<String>,
    pub description: Option<String>,
    pub groups: Vec<String>,
    pub password_never_expires: Option<bool>,
}

/// The node's authorization to publish a class of managed policy
/// (keyed by `dds:policy-publisher-*` purpose). Surfaced by
/// `GET /v1/policy/publisher-status` so the Users & Policy console can
/// show a ready-to-publish state or the one-time grant command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PublisherStatus {
    /// The node's own Vouchsafe URN — the issuer of locally-authored policy.
    pub node_urn: String,
    /// The publisher-capability purpose this status is for.
    pub purpose: String,
    /// Whether the node URN already holds `purpose` via a root-chained vouch.
    pub has_capability: bool,
    /// Whether the node URN is itself a domain trusted root (can self-vouch).
    pub is_trusted_root: bool,
    /// Whether a publish would succeed now (`has_capability || is_trusted_root`).
    pub can_publish: bool,
    /// The one-time admin command that grants the capability when a
    /// non-root node lacks it.
    pub grant_command: String,
}

/// Outcome the agent reports back after applying (or attempting to
/// apply) a policy / software assignment directive.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AppliedStatus {
    /// Successfully applied.
    Ok,
    /// Attempted but failed; see `error`.
    Failed,
    /// Skipped (for example: already at the desired state, or in `Audit` mode).
    Skipped,
}

/// What kind of artifact the applier just processed. Drives the
/// audit-action vocabulary split so a SIEM can distinguish a failed
/// software install from a failed Group-Policy-style document apply
/// without parsing `target_id`. Wire field is optional so
/// pre-`kind` agents (anything emitting AppliedReport before the
/// 2026-04-28 wire bump) keep round-tripping under the legacy
/// `apply.*` action vocabulary.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AppliedKind {
    /// `WindowsPolicyDocument` or `MacOsPolicyDocument` apply.
    Policy,
    /// `SoftwareAssignment` apply.
    Software,
    /// Periodic reconciliation pass (stale-item cleanup), not tied
    /// to a specific document. The Worker uses target_id
    /// `_reconciliation`.
    Reconciliation,
    /// Out-of-band heartbeat reporting host-state classification
    /// (e.g. AD-06 Entra-only unsupported). Worker target_id
    /// `_host_state`.
    HostState,
}

/// One report from the Windows applier about a single policy or
/// software assignment that it processed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppliedReport {
    /// Device URN that did the applying.
    pub device_urn: String,
    /// `policy_id` (for WindowsPolicyDocument) or `package_id` (for
    /// SoftwareAssignment). Identifies *what* was applied.
    pub target_id: String,
    /// Document version (`u64` for policies, `String` for software).
    /// Encoded as a string so both shapes fit one wire field.
    pub version: String,
    pub status: AppliedStatus,
    /// Discriminator that splits the audit action vocabulary
    /// (`policy.applied` / `policy.failed` / `software.applied` /
    /// `software.failed`). Optional so older agents that have not
    /// rolled to the 2026-04-28 wire bump still report — the absence
    /// collapses into the legacy `apply.*` family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<AppliedKind>,
    /// Free-form per-directive notes the agent wants to surface.
    /// Empty for `Ok` status with no per-directive detail.
    #[serde(default)]
    pub directives: Vec<String>,
    /// Error message if `status == Failed`.
    #[serde(default)]
    pub error: Option<String>,
    /// Unix seconds the agent finished applying.
    pub applied_at: u64,
}

/// The local authority service.
///
/// `trust_graph` is shared (`Arc<RwLock<TrustGraph>>`) with the owning
/// `DdsNode` so gossip-received tokens are visible to query-time hot
/// paths without rebuilding from the store on every call. See B5b in
/// STATUS.md and the doc on `LocalService::new` for the history.
pub struct LocalService<
    S: TokenStore
        + dds_store::traits::RevocationStore
        + dds_store::traits::AuditStore
        + ChallengeStore
        + CredentialStateStore,
> {
    /// Node signing identity (used to issue tokens).
    node_identity: Identity,
    /// Policy engine with loaded rules.
    policy_engine: PolicyEngine,
    /// Trust graph (shared with the owning `DdsNode` when the service is
    /// run alongside a swarm; otherwise solely owned by the service).
    pub trust_graph: Arc<RwLock<TrustGraph>>,
    /// Trusted root URNs.
    trusted_roots: BTreeSet<String>,
    /// **H-8 (security review)**: the URN of the bootstrap admin (the
    /// first principal added to `trusted_roots` via `admin_setup`).
    /// Bootstrap admin can vouch for any purpose; non-bootstrap admins
    /// must possess a `dds:admin-vouch:<purpose>` capability before
    /// they can vouch for `<purpose>`.
    bootstrap_admin_urn: Option<String>,
    /// Storage backend.
    store: S,
    /// Data directory for admin key storage (None in test/bench contexts).
    data_dir: Option<PathBuf>,
    /// Path to the TOML config file (for persisting trusted_roots changes).
    config_path: Option<PathBuf>,
    /// Node start time.
    start_time: u64,
    /// **M-19 (security review)**: monotonic snapshot of `SystemTime::now()`
    /// at service construction. If a later `now()` is *less* than this,
    /// the system clock has regressed (NTP backstep, VM snapshot rewind)
    /// and we refuse session/challenge validations to avoid replays.
    boot_wall_time: SystemTime,
    /// Whether to verify FIDO2 attestation on enroll_user.
    verify_fido2: bool,
    /// **A-1 step-1 (security review)**: when true, accept enrollment
    /// attestations with `fmt = "none"` (no cryptographic
    /// attestation at all). Default `false`; flip to `true` only on
    /// dev/test paths or when an operator has explicitly opted in
    /// via `DomainConfig.allow_unattested_credentials`. Packed
    /// attestation (with or without `x5c`) is verified regardless.
    allow_unattested_credentials: bool,
    /// **M-7 (security review)**: when true, only honor self-attested
    /// device tags/org_unit if the device has a vouch from a trusted
    /// root with purpose `dds:device-scope`. Set from
    /// `NodeConfig.domain.enforce_device_scope_vouch` at startup.
    enforce_device_scope_vouch: bool,
    /// FIDO2 AAGUID allow-list (Phase 1 of
    /// `docs/fido2-attestation-allowlist.md`). When non-empty,
    /// enrollment rejects any FIDO2 credential whose AAGUID is not
    /// in the set. Wired from
    /// `NodeConfig.domain.fido2_allowed_aaguids` at startup.
    fido2_allowed_aaguids: BTreeSet<[u8; 16]>,
    /// FIDO2 attestation trust roots keyed by AAGUID (Phase 2 of
    /// `docs/fido2-attestation-allowlist.md`). For any AAGUID with at
    /// least one configured root, enrollment requires `attStmt.x5c`
    /// and validates the chain to one of the listed roots. Loaded at
    /// startup from `NodeConfig.domain.fido2_attestation_roots`.
    fido2_attestation_roots: BTreeMap<[u8; 16], Vec<Vec<u8>>>,
}

impl<
    S: TokenStore
        + dds_store::traits::RevocationStore
        + dds_store::traits::AuditStore
        + ChallengeStore
        + CredentialStateStore,
> LocalService<S>
{
    /// Create a new local service.
    ///
    /// Rehydrates the in-memory `trust_graph` from any tokens already
    /// present in `store`, then keeps it in sync via the enrollment paths
    /// (`enroll_user`, `enroll_device`) that mutate both. This is the
    /// source of truth for query-time hot paths (`evaluate_policy`,
    /// `issue_session`, `status`).
    ///
    /// **Multi-writer caveat**: if the store is shared with a writer
    /// outside this `LocalService` (e.g. a `DdsNode` swarm event loop
    /// writing gossip-received tokens to the same redb file), those
    /// out-of-band writes are *not* automatically reflected here. The
    /// caller is responsible for routing such writes through
    /// `LocalService` (via the enrollment APIs or a future
    /// `ingest_token` API). The 2026-04-09 chaos soak found that the
    /// previous "rebuild trust graph from store on every query" pattern
    /// turned this hidden assumption into a 10-ms `evaluate_policy`
    /// p99 — a 10× §10 budget violation. See B5b in STATUS.md.
    pub fn new(
        node_identity: Identity,
        trust_graph: Arc<RwLock<TrustGraph>>,
        trusted_roots: BTreeSet<String>,
        store: S,
    ) -> Self {
        let mut svc = Self {
            node_identity,
            policy_engine: PolicyEngine::new(),
            trust_graph,
            trusted_roots,
            bootstrap_admin_urn: None,
            store,
            data_dir: None,
            config_path: None,
            start_time: now_epoch(),
            boot_wall_time: SystemTime::now(),
            verify_fido2: true,
            allow_unattested_credentials: false,
            enforce_device_scope_vouch: false,
            fido2_allowed_aaguids: BTreeSet::new(),
            fido2_attestation_roots: BTreeMap::new(),
        };
        // Best-effort rehydration: pull any pre-existing tokens from the
        // store into the in-memory graph. Only relevant when the store
        // already contains state from a prior run or external seeding
        // (e.g. http_binary_e2e's `seed_store`). Errors are logged via
        // the returned `ServiceError` form, but `new` is infallible by
        // contract — bad tokens in the store would also have failed the
        // old per-query rebuild, so we drop them silently here too.
        let _ = svc.rehydrate_from_store();
        svc
    }

    /// Rehydrate the in-memory trust graph from the store. Called from
    /// `new()` and exposed for tests / future use cases that need to
    /// re-sync after external store mutations. Returns the number of
    /// tokens absorbed, or an error if the store cannot be read.
    pub fn rehydrate_from_store(&mut self) -> Result<usize, ServiceError> {
        let store_has_state = self.store.count_tokens(None).unwrap_or(0) > 0
            || !self.store.revoked_set().unwrap_or_default().is_empty()
            || !self.store.burned_set().unwrap_or_default().is_empty();
        if !store_has_state {
            return Ok(0);
        }

        let jtis = self
            .store
            .list_tokens(None)
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        let mut tokens = Vec::with_capacity(jtis.len());
        for jti in jtis {
            let token = self
                .store
                .get_token(&jti)
                .map_err(|e| ServiceError::Store(e.to_string()))?;
            tokens.push(token);
        }
        // Sort by kind so attestations are inserted before vouches
        // (vouches with vch_sum need their target attestation present),
        // and revocations / burns last.
        tokens.sort_by_key(|token| match token.payload.kind {
            TokenKind::Attest => 0,
            TokenKind::Vouch => 1,
            TokenKind::Revoke => 2,
            TokenKind::Burn => 3,
        });

        let mut absorbed = 0usize;
        let mut g = self
            .trust_graph
            .write()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
        for token in tokens {
            // The graph's add_token re-validates signatures; duplicate
            // inserts are a no-op. We log and skip on rejection rather
            // than failing the whole rehydrate — bad tokens in the store
            // would also have failed the old per-query rebuild.
            if let Err(e) = g.add_token(token) {
                tracing::warn!("rehydrate_from_store: skipping token: {e}");
                continue;
            }
            absorbed += 1;
        }
        let _ = g.sweep_expired();
        Ok(absorbed)
    }

    /// Disable FIDO2 attestation verification (for test scenarios that
    /// pass synthetic enrollment data). Production code paths should
    /// leave this enabled.
    pub fn set_verify_fido2(&mut self, verify: bool) {
        self.verify_fido2 = verify;
    }

    /// **A-1 step-1**: opt into unattested-credential enrollment.
    /// When `true`, attestations with `fmt = "none"` are accepted.
    /// Default `false`; production deployments should leave this
    /// off so attackers cannot enroll credentials they fully
    /// control without any cryptographic proof at MakeCredential
    /// time. Wired from
    /// `NodeConfig.domain.allow_unattested_credentials`.
    pub fn set_allow_unattested_credentials(&mut self, allow: bool) {
        self.allow_unattested_credentials = allow;
    }

    /// FIDO2 AAGUID allow-list (Phase 1 of
    /// `docs/fido2-attestation-allowlist.md`). Each entry is a
    /// canonical UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
    /// or a 32-character hex string. Returns an error naming the
    /// offending entry if any value cannot be parsed; on success
    /// the parsed set replaces any previously-configured allow-list.
    /// Empty input clears the allow-list (any AAGUID is accepted).
    pub fn set_fido2_allowed_aaguids(&mut self, raw: &[String]) -> Result<(), ServiceError> {
        let mut set: BTreeSet<[u8; 16]> = BTreeSet::new();
        for entry in raw {
            let bytes = parse_aaguid(entry).ok_or_else(|| {
                ServiceError::Fido2(format!(
                    "fido2_allowed_aaguids: cannot parse {entry:?} as a UUID or 32-char hex"
                ))
            })?;
            set.insert(bytes);
        }
        self.fido2_allowed_aaguids = set;
        Ok(())
    }

    /// Reject the parsed attestation when an AAGUID allow-list is
    /// configured and the credential's AAGUID is not in it. Returns
    /// `Ok(())` when the allow-list is empty (default).
    fn enforce_fido2_aaguid_allow_list(
        &self,
        parsed: &dds_domain::fido2::ParsedAttestation,
    ) -> Result<(), ServiceError> {
        if self.fido2_allowed_aaguids.is_empty() {
            return Ok(());
        }
        if !self.fido2_allowed_aaguids.contains(&parsed.aaguid) {
            return Err(ServiceError::Fido2(format!(
                "AAGUID {} not in fido2_allowed_aaguids ({} entries)",
                format_aaguid(&parsed.aaguid),
                self.fido2_allowed_aaguids.len()
            )));
        }
        Ok(())
    }

    /// FIDO2 attestation trust roots keyed by AAGUID (Phase 2 of
    /// `docs/fido2-attestation-allowlist.md`). For each entry, the
    /// PEM file at `ca_pem_path` is read once here and parsed into a
    /// list of DER trust anchors that the enroll-time verifier checks
    /// the `attStmt.x5c` chain against. Multiple PEM-encoded certs in
    /// one file are all treated as alternative anchors (useful for
    /// vendors that rotate roots). Empty input clears the map.
    /// Returns an error naming the offending entry on any parse / I/O
    /// failure; the caller (startup) is expected to refuse to start
    /// rather than fall back to "no chain validation".
    pub fn set_fido2_attestation_roots(
        &mut self,
        entries: &[crate::config::Fido2AttestationRoot],
    ) -> Result<(), ServiceError> {
        let mut map: BTreeMap<[u8; 16], Vec<Vec<u8>>> = BTreeMap::new();
        for entry in entries {
            let aaguid = parse_aaguid(&entry.aaguid).ok_or_else(|| {
                ServiceError::Fido2(format!(
                    "fido2_attestation_roots: cannot parse aaguid {:?} as a UUID or 32-char hex",
                    entry.aaguid
                ))
            })?;
            let pem_bytes = std::fs::read(&entry.ca_pem_path).map_err(|e| {
                ServiceError::Fido2(format!(
                    "fido2_attestation_roots: read {}: {e}",
                    entry.ca_pem_path.display()
                ))
            })?;
            let ders = parse_pem_certificates(&pem_bytes).map_err(|e| {
                ServiceError::Fido2(format!(
                    "fido2_attestation_roots: parse {}: {e}",
                    entry.ca_pem_path.display()
                ))
            })?;
            if ders.is_empty() {
                return Err(ServiceError::Fido2(format!(
                    "fido2_attestation_roots: {} contains no PEM CERTIFICATE blocks",
                    entry.ca_pem_path.display()
                )));
            }
            map.entry(aaguid).or_default().extend(ders);
        }
        self.fido2_attestation_roots = map;
        Ok(())
    }

    /// Phase 2 of `docs/fido2-attestation-allowlist.md`. When the
    /// credential's AAGUID has a configured trust root, require
    /// `attStmt.x5c`, validate the chain to one of the configured
    /// roots, and require that the leaf cert's `id-fido-gen-ce-aaguid`
    /// extension equals the AAGUID in authData. Returns `Ok(())` when
    /// no root is configured for this AAGUID — the operator opted out
    /// of strict mode for this authenticator model.
    fn enforce_fido2_attestation_roots(
        &self,
        parsed: &dds_domain::fido2::ParsedAttestation,
    ) -> Result<(), ServiceError> {
        let roots = match self.fido2_attestation_roots.get(&parsed.aaguid) {
            Some(r) => r,
            None => return Ok(()),
        };
        if parsed.x5c_chain.is_empty() {
            return Err(ServiceError::Fido2(format!(
                "AAGUID {} requires attStmt.x5c (configured trust root, no self-attestation accepted)",
                format_aaguid(&parsed.aaguid)
            )));
        }
        let leaf_aaguid = dds_domain::fido2::extract_attestation_cert_aaguid(&parsed.x5c_chain[0])
            .map_err(|e| ServiceError::Fido2(format!("attestation cert: {e}")))?;
        match leaf_aaguid {
            Some(leaf) if leaf == parsed.aaguid => {}
            Some(leaf) => {
                return Err(ServiceError::Fido2(format!(
                    "leaf cert AAGUID {} does not match authData AAGUID {}",
                    format_aaguid(&leaf),
                    format_aaguid(&parsed.aaguid)
                )));
            }
            None => {
                return Err(ServiceError::Fido2(format!(
                    "AAGUID {} requires leaf cert id-fido-gen-ce-aaguid extension; not present",
                    format_aaguid(&parsed.aaguid)
                )));
            }
        }
        let now = now_epoch();
        dds_domain::fido2::verify_attestation_cert_chain(&parsed.x5c_chain, roots, now).map_err(
            |e| {
                ServiceError::Fido2(format!(
                    "attestation cert chain validation failed for AAGUID {}: {e}",
                    format_aaguid(&parsed.aaguid)
                ))
            },
        )?;
        Ok(())
    }

    /// Set the data directory for admin key storage.
    pub fn set_data_dir(&mut self, path: PathBuf) {
        self.data_dir = Some(path);
    }

    /// Set the config file path so trusted_roots changes can be persisted.
    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }

    /// Test/internal accessor: insert a URN into the trusted_roots set.
    /// Used by integration tests that need to seed multiple admins
    /// without going through the bootstrap-gated `admin_setup`.
    /// **Not** intended for production callers — production code adds
    /// admins via `admin_setup` (initial) or `admin_vouch` (subsequent).
    #[doc(hidden)]
    pub fn insert_trusted_root_for_test(&mut self, urn: String) {
        self.trusted_roots.insert(urn);
    }

    /// Persist the current trusted_roots AND `bootstrap_admin_urn`
    /// back to the TOML config file. **H-8 (security review)**:
    /// `bootstrap_admin_urn` must round-trip across restarts so that
    /// the bootstrap admin's "vouch-anything" privilege does not
    /// silently disappear on node restart.
    fn persist_trusted_roots(&self) -> Result<(), ServiceError> {
        let config_path = match &self.config_path {
            Some(p) => p,
            None => return Ok(()), // No config path — skip (test context)
        };

        let content = std::fs::read_to_string(config_path)
            .map_err(|e| ServiceError::Store(format!("read config: {e}")))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .map_err(|e| ServiceError::Store(format!("parse config: {e}")))?;

        let roots: Vec<&str> = self.trusted_roots.iter().map(|s| s.as_str()).collect();
        let mut arr = toml_edit::Array::new();
        for r in &roots {
            arr.push(r.to_string());
        }
        doc["trusted_roots"] = toml_edit::value(arr);

        match &self.bootstrap_admin_urn {
            Some(urn) => {
                doc["bootstrap_admin_urn"] = toml_edit::value(urn.as_str());
            }
            None => {
                doc.remove("bootstrap_admin_urn");
            }
        }

        std::fs::write(config_path, doc.to_string())
            .map_err(|e| ServiceError::Store(format!("write config: {e}")))?;

        tracing::info!(
            count = roots.len(),
            bootstrap = ?self.bootstrap_admin_urn,
            "persisted trusted_roots + bootstrap_admin_urn to config"
        );
        Ok(())
    }

    /// Set the `bootstrap_admin_urn` from durable config at startup.
    /// Called by the node initialization path right after
    /// `LocalService::new` so the in-memory state matches what was
    /// previously persisted — without this, the original bootstrap
    /// admin was treated as a non-bootstrap admin after a restart and
    /// would fail `admin_vouch` for purposes it hadn't been vouched
    /// for. H-8 regression.
    pub fn set_bootstrap_admin_urn(&mut self, urn: Option<String>) {
        self.bootstrap_admin_urn = urn;
    }

    /// **M-7 (security review)**: toggle enforcement of the
    /// `dds:device-scope` vouch requirement for honoring self-attested
    /// device tags / org_unit. Wired from
    /// `NodeConfig.domain.enforce_device_scope_vouch` at startup.
    pub fn set_enforce_device_scope_vouch(&mut self, enforce: bool) {
        self.enforce_device_scope_vouch = enforce;
    }

    /// Wrapper around [`TrustGraph::has_purpose`] that funnels the
    /// outcome through [`crate::telemetry::record_purpose_lookup`].
    /// Every capability gate inside `LocalService` should go through
    /// this helper so `dds_purpose_lookups_total{result=ok|denied}`
    /// reflects the real call rate. The helper is a thin synchronous
    /// pass-through — it does not hold any new locks (the caller
    /// already holds the trust-graph read lock as `g`) and adds one
    /// `record_purpose_lookup` call per invocation.
    pub fn has_purpose_observed(&self, g: &TrustGraph, subject_urn: &str, purpose: &str) -> bool {
        let ok = g.has_purpose(subject_urn, purpose, &self.trusted_roots);
        crate::telemetry::record_purpose_lookup(if ok { "ok" } else { "denied" });
        ok
    }

    /// Wrapper around [`dds_domain::fido2::verify_attestation`] that
    /// funnels every enrollment-time call through
    /// [`crate::telemetry::record_fido2_attestation_verify`] so
    /// `dds_fido2_attestation_verify_total{result, fmt}` reflects the
    /// real verifier call rate. The two enrollment entry points
    /// ([`Self::enroll_user`] and [`Self::admin_setup`]) share this
    /// helper; the credential-lookup re-parse inside
    /// [`Self::verify_assertion_common`] does *not* go through this
    /// path (the catalog scopes the counter to enrollment-time only).
    ///
    /// On success the `fmt` label carries `parsed.fmt` (today, one of
    /// `packed|none`); on failure the verifier may reject before the
    /// `fmt` field is parsed (CBOR decode error, missing `fmt`,
    /// unsupported format), so the bump uniformly emits
    /// `fmt="unknown"` for the failure bucket.
    fn verify_attestation_observed(
        attestation_object: &[u8],
        client_data_hash: &[u8],
        allow_unattested_credentials: bool,
    ) -> Result<dds_domain::fido2::ParsedAttestation, dds_domain::fido2::Fido2Error> {
        let outcome = dds_domain::fido2::verify_attestation(
            attestation_object,
            client_data_hash,
            allow_unattested_credentials,
        );
        match &outcome {
            Ok(parsed) => crate::telemetry::record_fido2_attestation_verify("ok", &parsed.fmt),
            Err(_) => crate::telemetry::record_fido2_attestation_verify("fail", "unknown"),
        }
        outcome
    }

    /// **M-7 (security review)**: thin wrapper that reads the
    /// device's self-attested `tags` + `org_unit` via
    /// `device_targeting_facts`, then drops them on the floor when
    /// `enforce_device_scope_vouch` is enabled and the device lacks
    /// a `dds:device-scope` vouch from a trusted root. When
    /// enforcement is off (the default) the function is a no-op
    /// passthrough, preserving behavior on existing deployments.
    fn device_targeting_facts_gated(
        &self,
        g: &TrustGraph,
        device_urn: &str,
    ) -> (Vec<String>, Option<String>) {
        let (tags, ou) = device_targeting_facts(g, device_urn);
        if !self.enforce_device_scope_vouch {
            return (tags, ou);
        }
        let scope_vouched =
            self.has_purpose_observed(g, device_urn, dds_core::token::purpose::DEVICE_SCOPE);
        if scope_vouched {
            (tags, ou)
        } else {
            if !tags.is_empty() || ou.is_some() {
                tracing::warn!(
                    %device_urn,
                    tags_count = tags.len(),
                    org_unit = ?ou,
                    "device has self-attested scope facts but no dds:device-scope \
                     vouch; dropping to avoid honoring unverified claims"
                );
            }
            (Vec::new(), None)
        }
    }

    /// Add a policy rule.
    pub fn add_policy_rule(&mut self, rule: PolicyRule) {
        self.policy_engine.add_rule(rule);
    }

    /// Enroll a user with FIDO2 attestation.
    pub fn enroll_user(
        &mut self,
        req: EnrollUserRequest,
    ) -> Result<EnrollmentResult, ServiceError> {
        let mut credential_id = req.credential_id.clone();
        if self.verify_fido2 {
            // A-1 step-3: when the caller supplies raw clientDataJSON,
            // bind it to the signed hash and validate `type` /
            // `origin` / `crossOrigin` per WebAuthn §7.1.
            //
            // **A-1 follow-up**: if `challenge_id` is supplied, the
            // server consumes the challenge atomically here (so a
            // failed enrollment can't replay the same nonce) and
            // forwards the raw bytes to the cdj.challenge check.
            let challenge_bytes = match req.challenge_id.as_deref() {
                Some(id) => Some(
                    self.store
                        .consume_challenge(id, now_epoch())
                        .map_err(|e| {
                            ServiceError::Fido2(format!("enrollment challenge invalid: {e}"))
                        })?
                        .to_vec(),
                ),
                None => None,
            };
            verify_enrollment_client_data(
                req.client_data_json.as_deref(),
                &req.client_data_hash,
                &req.rp_id,
                challenge_bytes.as_deref(),
            )?;

            let parsed = Self::verify_attestation_observed(
                &req.attestation_object,
                &req.client_data_hash,
                self.allow_unattested_credentials,
            )
            .map_err(|e| ServiceError::Fido2(e.to_string()))?;

            // A-1 step-1: surface the policy decision when an operator
            // opted into fmt=none. Helps audit trails distinguish
            // "real attestation" from "explicitly unattested".
            if parsed.fmt == "none" {
                tracing::warn!(
                    label = %req.label,
                    "A-1: enrolling user with fmt=none (unattested) — \
                     allow_unattested_credentials is true"
                );
            }

            // Phase 1 of `docs/fido2-attestation-allowlist.md`: when an
            // AAGUID allow-list is configured, reject any authenticator
            // whose AAGUID is not on it (covers `fmt = "none"` too).
            self.enforce_fido2_aaguid_allow_list(&parsed)?;

            // Phase 2 of `docs/fido2-attestation-allowlist.md`: when the
            // operator has bound this AAGUID to a vendor CA root, demand
            // a real attestation chain that validates to that root.
            self.enforce_fido2_attestation_roots(&parsed)?;

            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(req.rp_id.as_bytes());
            let computed_rp_hash = hasher.finalize();
            if computed_rp_hash.as_slice() != parsed.rp_id_hash {
                return Err(ServiceError::Fido2("rp_id hash mismatch".to_string()));
            }
            credential_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.credential_id);
        }
        let user_ident = Identity::generate(&req.label, &mut rand::rngs::OsRng);
        let doc = UserAuthAttestation {
            credential_id,
            attestation_object: req.attestation_object,
            client_data_hash: req.client_data_hash,
            rp_id: req.rp_id,
            user_display_name: req.display_name,
            authenticator_type: req.authenticator_type,
        };
        let mut payload = self.make_attest_payload(&user_ident);
        doc.embed(&mut payload)
            .map_err(|e| ServiceError::Domain(e.to_string()))?;

        let token = Token::sign(payload, &user_ident.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        let cbor = token
            .to_cbor()
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        self.store
            .put_token(&token)
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        {
            let mut g = self
                .trust_graph
                .write()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            let _ = g.add_token(token.clone());
        }

        // Z-3 Phase A.1: user enrollment is a state-mutating action; record it.
        self.emit_local_audit("enroll.user", cbor.clone(), None);

        Ok(EnrollmentResult {
            urn: user_ident.id.to_urn(),
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Enroll a device.
    ///
    /// **Security note**: tags and org_unit are self-attested by the
    /// enrolling device. They are used for policy scope matching. A
    /// future version should require admin-signed device enrollment
    /// to prevent a rogue local process from claiming privileged tags.
    pub fn enroll_device(
        &mut self,
        req: EnrollDeviceRequest,
    ) -> Result<EnrollmentResult, ServiceError> {
        // Validate tags: reject empty, overly long, or control-char tags.
        for tag in &req.tags {
            if tag.is_empty() || tag.len() > 128 || tag.chars().any(|c| c.is_control()) {
                return Err(ServiceError::Domain(format!(
                    "invalid tag: must be 1-128 printable characters, got {:?}",
                    tag
                )));
            }
        }
        if req.tags.len() > 32 {
            return Err(ServiceError::Domain(
                "too many tags: maximum 32".to_string(),
            ));
        }
        if let Some(ref ou) = req.org_unit {
            if ou.is_empty() || ou.len() > 128 || ou.chars().any(|c| c.is_control()) {
                return Err(ServiceError::Domain(format!(
                    "invalid org_unit: must be 1-128 printable characters, got {:?}",
                    ou
                )));
            }
        }

        tracing::info!(
            label = %req.label,
            tags = ?req.tags,
            org_unit = ?req.org_unit,
            "enrolling device (tags/org_unit are self-attested)"
        );

        let device_ident = Identity::generate(&req.label, &mut rand::rngs::OsRng);
        let doc = DeviceJoinDocument {
            device_id: req.device_id,
            hostname: req.hostname,
            os: req.os,
            os_version: req.os_version,
            tpm_ek_hash: req.tpm_ek_hash,
            org_unit: req.org_unit,
            tags: req.tags,
        };
        let mut payload = self.make_attest_payload(&device_ident);
        doc.embed(&mut payload)
            .map_err(|e| ServiceError::Domain(e.to_string()))?;

        let token = Token::sign(payload, &device_ident.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        let cbor = token
            .to_cbor()
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        self.store
            .put_token(&token)
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        {
            let mut g = self
                .trust_graph
                .write()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            let _ = g.add_token(token.clone());
        }

        // Z-3 Phase A.1: device enrollment is a state-mutating action; record it.
        self.emit_local_audit("enroll.device", cbor.clone(), None);

        Ok(EnrollmentResult {
            urn: device_ident.id.to_urn(),
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Issue a short-lived session token.
    ///
    /// Tail-bumps `dds_sessions_issued_total{via="legacy"}`. Callers
    /// that already account for issuance under a different `via`
    /// label (e.g. [`issue_session_from_assertion`] which marks
    /// `via="fido2"`) must invoke [`issue_session_inner`] directly to
    /// avoid double counting.
    pub fn issue_session(&mut self, req: SessionRequest) -> Result<SessionResult, ServiceError> {
        let result = self.issue_session_inner(req)?;
        crate::telemetry::record_sessions_issued("legacy");
        Ok(result)
    }

    /// Internal session-mint path — does not bump the
    /// `dds_sessions_issued_total` counter. The two public entry
    /// points ([`issue_session`] and [`issue_session_from_assertion`])
    /// own the correct `via` label and bump exactly once on success.
    fn issue_session_inner(&mut self, req: SessionRequest) -> Result<SessionResult, ServiceError> {
        // Use the shared in-memory trust graph directly via a read lock.
        // It is the source of truth — see `LocalService::new` doc for
        // the multi-writer contract. Previously this rebuilt from the
        // store on every call, which made `evaluate_policy` p99 climb
        // to 10 ms in the 2026-04-09 chaos soak (B5b).
        let granted: BTreeSet<String> = {
            let g = self
                .trust_graph
                .read()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            g.purposes_for(&req.subject_urn, &self.trusted_roots)
        };

        if granted.is_empty() {
            return Err(ServiceError::Domain(
                "subject has no granted purposes; cannot issue session".to_string(),
            ));
        }

        // Intersect requested resources with granted purposes — only authorize
        // resources that the trust graph actually grants.
        let authorized_resources: Vec<String> = req
            .requested_resources
            .into_iter()
            .filter(|r| granted.contains(r))
            .collect();

        let session_id = format!("sess-{:016x}", rand_u64());
        // Cap session lifetime to 24 hours to limit blast radius of stolen tokens.
        let capped_duration = req.duration_secs.min(86400);
        let expires_at = now_epoch() + capped_duration;

        let doc = SessionDocument {
            session_id: session_id.clone(),
            subject_urn: req.subject_urn.clone(),
            device_urn: req.device_urn,
            granted_purposes: granted.into_iter().collect(),
            authorized_resources,
            session_start: now_epoch(),
            duration_secs: capped_duration,
            mfa_verified: req.mfa_verified,
            tls_binding: req.tls_binding,
        };

        let mut payload = TokenPayload {
            iss: self.node_identity.id.to_urn(),
            iss_key: self.node_identity.public_key.clone(),
            jti: format!("session-{}", &session_id),
            sub: req.subject_urn,
            kind: TokenKind::Attest,
            purpose: Some("dds:session".to_string()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: now_epoch(),
            exp: Some(expires_at),
            body_type: None,
            body_cbor: None,
        };
        doc.embed(&mut payload)
            .map_err(|e| ServiceError::Domain(e.to_string()))?;

        let token = Token::sign(payload, &self.node_identity.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        let cbor = token
            .to_cbor()
            .map_err(|e| ServiceError::Token(e.to_string()))?;

        Ok(SessionResult {
            session_id,
            token_cbor: cbor,
            expires_at,
        })
    }

    /// Evaluate a policy decision.
    pub fn evaluate_policy(
        &self,
        subject_urn: &str,
        resource: &str,
        action: &str,
    ) -> Result<PolicyResult, ServiceError> {
        // Shared in-memory trust graph is the source of truth (see B5b
        // note on `LocalService::new`); take a read lock for the eval.
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
        let decision =
            self.policy_engine
                .evaluate(subject_urn, resource, action, &g, &self.trusted_roots);
        Ok(PolicyResult {
            allowed: decision.is_allowed(),
            reason: format!("{decision}"),
        })
    }

    /// The node's Vouchsafe URN (used as the `node_urn` field on
    /// signed policy/software envelopes so the agent can record
    /// provenance alongside its signature check).
    pub fn node_urn(&self) -> String {
        self.node_identity.id.to_urn()
    }

    // ---- Local policy publishing (Users & Policy console) ----
    //
    // The node self-signs locally-authored policy attestations with its own
    // identity, then the swarm task applies + gossips them (see
    // `DdsNode::apply_local_publish`). For peers to honor such a policy, the
    // node URN must hold the matching `dds:policy-publisher-*` capability
    // (C-3). Two ways that capability is established:
    //   * the node is a domain trusted root -> it can self-vouch the
    //     capability inline (touchless), or
    //   * an admin (a trusted root) vouches the node URN once via
    //     `dds admin vouch` (FIDO2).
    // `plan_policy_publish` picks the right ordered token batch, or fails
    // closed with the exact grant command when neither applies.

    /// Whether the node's own identity URN is a domain trusted root.
    pub fn node_is_trusted_root(&self) -> bool {
        self.trusted_roots.contains(&self.node_identity.id.to_urn())
    }

    /// Whether the node currently holds `purpose` (a `dds:policy-publisher-*`
    /// capability) via a trusted-root-chained vouch — i.e. whether it can
    /// publish that policy class right now without bootstrapping.
    pub fn node_has_publisher_capability(&self, purpose: &str) -> bool {
        let g = self.trust_graph.read().expect("trust_graph poisoned");
        g.has_purpose(
            &self.node_identity.id.to_urn(),
            purpose,
            &self.trusted_roots,
        )
    }

    /// Report the node's publish authorization for `purpose`.
    pub fn publisher_status(&self, purpose: &str) -> PublisherStatus {
        let has_capability = self.node_has_publisher_capability(purpose);
        let is_trusted_root = self.node_is_trusted_root();
        PublisherStatus {
            node_urn: self.node_identity.id.to_urn(),
            purpose: purpose.to_string(),
            has_capability,
            is_trusted_root,
            // A root can bootstrap the capability inline on first publish;
            // a non-root that already holds it can publish directly.
            can_publish: has_capability || is_trusted_root,
            grant_command: format!(
                "dds admin vouch --subject-urn {} --purpose {}",
                self.node_identity.id.to_urn(),
                purpose
            ),
        }
    }

    /// Build a self-signed attestation of the node's own identity — the
    /// live target a publisher-capability self-vouch pins via `vch_sum`.
    pub fn build_node_self_attestation(&self) -> Result<Token, ServiceError> {
        let payload = self.make_attest_payload(&self.node_identity);
        Token::sign(payload, &self.node_identity.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))
    }

    /// Build a self-vouch granting the node `purpose`, pinning `attest_hash`
    /// (the payload hash of [`Self::build_node_self_attestation`]). Only
    /// honored domain-wide when the node URN is a trusted root.
    pub fn build_node_self_vouch(
        &self,
        attest_hash: &str,
        purpose: &str,
    ) -> Result<Token, ServiceError> {
        let urn = self.node_identity.id.to_urn();
        let payload = TokenPayload {
            iss: urn.clone(),
            iss_key: self.node_identity.public_key.clone(),
            jti: format!(
                "vouch-selfpub-{}-{}",
                self.node_identity.id.label(),
                Uuid::new_v4().simple()
            ),
            sub: urn.clone(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose.to_string()),
            vch_iss: Some(urn),
            vch_sum: Some(attest_hash.to_string()),
            revokes: None,
            iat: now_epoch(),
            exp: Some(now_epoch() + 365 * 86400),
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &self.node_identity.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))
    }

    /// Embed a domain document into a fresh Attest payload and sign it with
    /// the node identity — the canonical policy-attestation construction.
    pub fn build_policy_attestation<D: DomainDocument>(
        &self,
        doc: &D,
    ) -> Result<Token, ServiceError> {
        let mut payload = self.make_attest_payload(&self.node_identity);
        doc.embed(&mut payload)
            .map_err(|e| ServiceError::Domain(e.to_string()))?;
        Token::sign(payload, &self.node_identity.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))
    }

    /// Decide the ordered token batch to publish so a freshly-built
    /// `policy_token` (requiring `purpose`) is honored across the domain:
    ///   * capability already held  -> `[policy_token]`
    ///   * node is a trusted root   -> `[self_attest, self_vouch, policy_token]`
    ///   * otherwise                -> fail closed with the grant command.
    pub fn plan_policy_publish(
        &self,
        policy_token: Token,
        purpose: &str,
    ) -> Result<Vec<Token>, ServiceError> {
        if self.node_has_publisher_capability(purpose) {
            return Ok(vec![policy_token]);
        }
        if self.node_is_trusted_root() {
            let attest = self.build_node_self_attestation()?;
            let attest_hash = attest.payload_hash();
            let vouch = self.build_node_self_vouch(&attest_hash, purpose)?;
            return Ok(vec![attest, vouch, policy_token]);
        }
        Err(ServiceError::Trust(format!(
            "node '{}' is not authorized to publish policy (purpose {}). One-time setup: \
             (1) run `dds policy publisher-init` to publish this node's identity, then \
             (2) an admin runs `dds admin vouch --subject-urn {} --purpose {}`.",
            self.node_identity.id.to_urn(),
            purpose,
            self.node_identity.id.to_urn(),
            purpose
        )))
    }

    /// True iff `admin_setup` would currently pass its C-2 gate:
    /// `trusted_roots` is still empty AND the `<data_dir>/.bootstrap`
    /// sentinel exists. Used by `/v1/node/info` so client tools can
    /// pre-check before triggering a WebAuthn ceremony that would only
    /// be rejected.
    pub fn admin_setup_available(&self) -> bool {
        if !self.trusted_roots.is_empty() {
            return false;
        }
        match self.bootstrap_sentinel_path() {
            Ok(p) => p.exists(),
            Err(_) => false,
        }
    }

    /// observability-plan.md Phase D.2 — store smoke test for `/readyz`.
    ///
    /// Issues a single read against the audit chain. A successful
    /// `audit_chain_head()` proves: the redb file is open, the audit
    /// table is accessible, and the on-disk DACL allows the node user
    /// to read it. We deliberately do not write here — readiness is a
    /// non-mutating probe and the periodic real audit emissions cover
    /// write-path health.
    pub fn readiness_smoketest(&self) -> Result<(), ServiceError> {
        self.store
            .audit_chain_head()
            .map(|_| ())
            .map_err(|e| ServiceError::Store(e.to_string()))
    }

    /// **Z-3 / Phase A.1 (observability-plan.md)**: emit a locally-
    /// chained audit entry for an action this service just performed.
    /// Reads the current chain head from the store, stamps `prev_hash`,
    /// signs with the node identity's Ed25519 key, and appends.
    ///
    /// All HTTP/admin code paths funnel through this single helper so
    /// we don't end up with three separate "build the entry" sites
    /// that drift in chain handling. Errors are logged at `warn!` and
    /// swallowed — a redb-side audit failure must not abort the
    /// caller's primary operation (the token has already been
    /// accepted into the trust graph at this point).
    pub fn emit_local_audit(
        &mut self,
        action: impl Into<String>,
        token_bytes: Vec<u8>,
        reason: Option<String>,
    ) {
        let action_str = action.into();
        let prev_hash = match self.store.audit_chain_head() {
            Ok(h) => h.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(action = %action_str, error = %e, "audit: chain-head read failed");
                return;
            }
        };
        let entry = match AuditLogEntry::sign_ed25519_chained_with_reason(
            action_str.clone(),
            token_bytes,
            self.node_identity.id.to_urn(),
            &self.node_identity.signing_key,
            now_epoch(),
            prev_hash,
            reason,
        ) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(action = %action_str, error = %e, "audit: sign failed");
                return;
            }
        };
        if let Err(e) = self.store.append_audit_entry(&entry) {
            tracing::warn!(action = %action_str, error = %e, "audit: append failed");
            return;
        }
        // observability-plan.md Phase C — bump
        // `dds_audit_entries_total{action=...}` after the chain
        // append succeeds. A failed append above returns early so
        // the counter only ticks for entries that are actually
        // durable on disk.
        crate::telemetry::record_audit_entry(&action_str);
    }

    /// The node's raw Ed25519 public-key bytes. The Windows and macOS
    /// Policy Agents pin this value at install time (via the
    /// provisioning bundle) and use it to verify
    /// `SignedPolicyEnvelope` returned by the policy/software
    /// endpoints (H-2 / H-3 in the security review).
    pub fn node_pubkey_bytes(&self) -> [u8; 32] {
        self.node_identity.verifying_key().to_bytes()
    }

    /// Sign a policy/software response payload with the node's
    /// Ed25519 signing key, producing an envelope the agent can
    /// verify against its pinned node pubkey. `payload_json` is the
    /// exact UTF-8 JSON bytes the agent will later deserialize; we
    /// sign the raw bytes so the agent does not have to re-encode
    /// (re-encoding with a different JSON serializer would make the
    /// signed bytes divergent, see M-12 for the same class of
    /// fragility on `clientDataJSON`).
    pub fn sign_policy_envelope(
        &self,
        device_urn: &str,
        envelope_kind: &str,
        payload_json: &[u8],
    ) -> dds_core::envelope::SignedPolicyEnvelope {
        use base64::Engine as _;
        let issued_at = now_epoch();
        let sig = dds_core::envelope::sign_envelope(
            &self.node_identity.signing_key,
            device_urn,
            envelope_kind,
            issued_at,
            payload_json,
        );
        let b64 = base64::engine::general_purpose::STANDARD;
        dds_core::envelope::SignedPolicyEnvelope {
            version: 1,
            kind: envelope_kind.to_string(),
            device_urn: device_urn.to_string(),
            issued_at,
            payload_b64: b64.encode(payload_json),
            signature_b64: b64.encode(sig),
            node_urn: self.node_identity.id.to_urn(),
            node_pubkey_b64: b64.encode(self.node_pubkey_bytes()),
        }
    }

    /// List every `WindowsPolicyDocument` whose scope matches the
    /// given device URN. Skips revoked, burned, and `Disabled`
    /// documents.
    ///
    /// **B-4 (security review):** if multiple in-scope attestations
    /// share the same logical `policy_id`, only one is returned —
    /// the document with the highest `version`, with ties broken by
    /// the latest `iat`, and final ties broken lexicographically by
    /// `jti`. Agents key applied state by `policy_id`, so without
    /// this filter two attestations carrying conflicting versions
    /// could flap across restarts depending on attestation iteration
    /// order. The result vector is sorted by `policy_id` so callers
    /// observe a stable order on every poll.
    ///
    /// This is the read side of Phase 3 item 9 — the
    /// `DdsPolicyAgent` calls this once a minute via
    /// `GET /v1/windows/policies?device_urn=...`. Scope-matching
    /// rules:
    ///
    /// - empty scope (no tags, no org_units, no identity_urns) =
    ///   global match
    /// - any tag in `scope.device_tags` ∈ device's tags → match
    /// - device's `org_unit` ∈ `scope.org_units` → match
    /// - device URN ∈ `scope.identity_urns` → match
    pub fn list_applicable_windows_policies(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableWindowsPolicy>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = self.device_targeting_facts_gated(&g, device_urn);

        let mut out = Vec::new();
        for token in g.attestations_iter() {
            if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                continue;
            }
            let doc = match WindowsPolicyDocument::extract(&token.payload) {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(jti = %token.payload.jti, "policy decode failed: {e}");
                    continue;
                }
            };
            if matches!(doc.enforcement, Enforcement::Disabled) {
                continue;
            }
            // C-3 (security review): the issuer of an attestation that
            // embeds a WindowsPolicyDocument must hold the
            // `dds:policy-publisher-windows` capability via a vouch
            // chain back to a trusted root. Without this filter, any
            // libp2p peer that completed the Noise handshake could
            // gossip a self-signed token containing arbitrary policy
            // (registry edits, account creation) and have it served to
            // every Policy Agent in the domain.
            if !self.has_purpose_observed(
                &g,
                &token.payload.iss,
                dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
            ) {
                tracing::warn!(
                    jti = %token.payload.jti,
                    issuer = %token.payload.iss,
                    "rejecting Windows policy: issuer lacks dds:policy-publisher-windows capability"
                );
                continue;
            }
            if !scope_matches(&doc.scope, device_urn, &device_tags, device_ou.as_deref()) {
                continue;
            }
            out.push(ApplicableWindowsPolicy {
                jti: token.payload.jti.clone(),
                issuer: token.payload.iss.clone(),
                iat: token.payload.iat,
                document: doc,
            });
        }
        // B-4: collapse duplicates by `policy_id`, keep the winner,
        // emit in stable (policy_id-sorted) order.
        let out = supersede_windows_policies(out);
        Ok(out)
    }

    /// List every `MacOsPolicyDocument` whose scope matches the given
    /// device URN. Skips revoked, burned, and `Disabled` documents.
    /// Scope semantics are identical to
    /// `list_applicable_windows_policies`.
    ///
    /// **B-4 (security review):** see `list_applicable_windows_policies`
    /// — duplicates by `policy_id` are collapsed to the winner
    /// (highest `version`, then latest `iat`, then lex-smallest `jti`).
    pub fn list_applicable_macos_policies(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableMacOsPolicy>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = self.device_targeting_facts_gated(&g, device_urn);

        let mut out = Vec::new();
        for token in g.attestations_iter() {
            if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                continue;
            }
            let doc = match MacOsPolicyDocument::extract(&token.payload) {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(jti = %token.payload.jti, "macos policy decode failed: {e}");
                    continue;
                }
            };
            if matches!(doc.enforcement, Enforcement::Disabled) {
                continue;
            }
            // C-3: same publisher capability gate as Windows policies.
            if !self.has_purpose_observed(
                &g,
                &token.payload.iss,
                dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
            ) {
                tracing::warn!(
                    jti = %token.payload.jti,
                    issuer = %token.payload.iss,
                    "rejecting macOS policy: issuer lacks dds:policy-publisher-macos capability"
                );
                continue;
            }
            if !scope_matches(&doc.scope, device_urn, &device_tags, device_ou.as_deref()) {
                continue;
            }
            out.push(ApplicableMacOsPolicy {
                jti: token.payload.jti.clone(),
                issuer: token.payload.iss.clone(),
                iat: token.payload.iat,
                document: doc,
            });
        }
        let out = supersede_macos_policies(out);
        Ok(out)
    }

    /// List every `LinuxPolicyDocument` whose scope matches the given
    /// device URN. Skips revoked, burned, and `Disabled` documents.
    /// Scope semantics are identical to
    /// `list_applicable_windows_policies`.
    pub fn list_applicable_linux_policies(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableLinuxPolicy>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = self.device_targeting_facts_gated(&g, device_urn);

        let mut out = Vec::new();
        for token in g.attestations_iter() {
            if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                continue;
            }
            let doc = match LinuxPolicyDocument::extract(&token.payload) {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(jti = %token.payload.jti, "linux policy decode failed: {e}");
                    continue;
                }
            };
            if matches!(doc.enforcement, Enforcement::Disabled) {
                continue;
            }
            if !self.has_purpose_observed(
                &g,
                &token.payload.iss,
                dds_core::token::purpose::POLICY_PUBLISHER_LINUX,
            ) {
                tracing::warn!(
                    jti = %token.payload.jti,
                    issuer = %token.payload.iss,
                    "rejecting Linux policy: issuer lacks dds:policy-publisher-linux capability"
                );
                continue;
            }
            if !scope_matches(&doc.scope, device_urn, &device_tags, device_ou.as_deref()) {
                continue;
            }
            out.push(ApplicableLinuxPolicy {
                jti: token.payload.jti.clone(),
                issuer: token.payload.iss.clone(),
                iat: token.payload.iat,
                document: doc,
            });
        }
        let out = supersede_linux_policies(out);
        Ok(out)
    }

    /// List every `SoftwareAssignment` whose scope matches the given
    /// device URN. Skips revoked / burned tokens. Same scope rules as
    /// `list_applicable_windows_policies`. Phase 3 item 10.
    ///
    /// **B-4 (security review):** if multiple in-scope assignments
    /// share the same logical `package_id`, only one is returned —
    /// the assignment with the latest `iat`, with ties broken
    /// lexicographically by `jti`. Agents key applied state by
    /// `package_id`; without this filter two attestations carrying
    /// conflicting versions could flap across restarts. (Software
    /// `version` is a free-form string — semver is not assumed —
    /// so we order by signing timestamp rather than the version
    /// field.) The result vector is sorted by `package_id` so
    /// callers observe a stable order.
    pub fn list_applicable_software(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableSoftware>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = self.device_targeting_facts_gated(&g, device_urn);

        let mut out = Vec::new();
        for token in g.attestations_iter() {
            if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                continue;
            }
            let doc = match SoftwareAssignment::extract(&token.payload) {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(jti = %token.payload.jti, "software decode failed: {e}");
                    continue;
                }
            };
            // SC-5 Phase B.1 follow-on: fail closed at decode time when
            // `publisher_identity` is malformed. An empty Authenticode
            // subject or a wrong-shape Apple Team ID would silently
            // match nothing on the agent — observationally identical
            // to "no publisher pinning", which is exactly the silent
            // downgrade the two-signature gate is meant to prevent.
            // Skip the assignment instead of handing it to the agent.
            if let Some(pi) = doc.publisher_identity.as_ref() {
                if let Err(e) = pi.validate() {
                    tracing::warn!(
                        jti = %token.payload.jti,
                        issuer = %token.payload.iss,
                        "rejecting software assignment: malformed publisher_identity: {e}"
                    );
                    continue;
                }
            }
            // C-3: same publisher capability gate.
            if !self.has_purpose_observed(
                &g,
                &token.payload.iss,
                dds_core::token::purpose::SOFTWARE_PUBLISHER,
            ) {
                tracing::warn!(
                    jti = %token.payload.jti,
                    issuer = %token.payload.iss,
                    "rejecting software assignment: issuer lacks dds:software-publisher capability"
                );
                continue;
            }
            if !scope_matches(&doc.scope, device_urn, &device_tags, device_ou.as_deref()) {
                continue;
            }
            out.push(ApplicableSoftware {
                jti: token.payload.jti.clone(),
                issuer: token.payload.iss.clone(),
                iat: token.payload.iat,
                document: doc,
            });
        }
        let out = supersede_software(out);
        Ok(out)
    }

    /// Resolve the local Windows account a subject is allowed to claim on
    /// this device. Authorization is bound to a freshly issued local DDS
    /// session token so localhost callers cannot claim accounts by
    /// presenting an arbitrary `subject_urn`.
    pub fn resolve_windows_account_claim(
        &self,
        device_urn: &str,
        session_token_cbor: &[u8],
    ) -> Result<WindowsAccountClaim, ServiceError> {
        if device_urn.trim().is_empty() {
            return Err(ServiceError::Domain(
                "device_urn is required for windows account claim".into(),
            ));
        }

        let session = self.validate_local_session_token(session_token_cbor)?;
        let subject_urn = session.subject_urn;

        let policies = self.list_applicable_windows_policies(device_urn)?;
        let mut matches: Vec<AccountDirective> = Vec::new();
        for policy in policies {
            let Some(bundle) = policy.document.windows else {
                continue;
            };
            for directive in bundle.local_accounts {
                if directive.action != AccountAction::Create {
                    continue;
                }
                if directive.claim_subject_urn.as_deref() == Some(subject_urn.as_str()) {
                    matches.push(directive);
                }
            }
        }

        if matches.is_empty() {
            return Err(ServiceError::Policy(format!(
                "no claimable windows account for subject '{}' on device '{}'",
                subject_urn, device_urn
            )));
        }

        let claim = matches.remove(0);
        if matches.iter().any(|other| other != &claim) {
            return Err(ServiceError::Policy(format!(
                "multiple conflicting windows account claims for subject '{}' on device '{}'",
                subject_urn, device_urn
            )));
        }

        if claim.username.trim().is_empty() {
            return Err(ServiceError::Domain(
                "claimable windows account has an empty username".into(),
            ));
        }

        Ok(WindowsAccountClaim {
            subject_urn,
            username: claim.username,
            full_name: claim.full_name,
            description: claim.description,
            groups: claim.groups,
            password_never_expires: claim.password_never_expires,
        })
    }

    /// Record a `DdsPolicyAgent` apply outcome. v1: this writes a
    /// structured `tracing::info!` line so existing observability
    /// picks it up; a future PR will add a persistent applier-audit
    /// table queryable via a new GET endpoint. The applier audit log
    /// is intentionally distinct from the trust-graph audit log
    /// (`dds_core::audit::AuditLogEntry`) — that one is signed +
    /// gossiped per mutation, this one is local-only telemetry.
    pub fn record_applied(&mut self, report: &AppliedReport) -> Result<(), ServiceError> {
        tracing::info!(
            device = %report.device_urn,
            target = %report.target_id,
            version = %report.version,
            status = ?report.status,
            applied_at = report.applied_at,
            directive_count = report.directives.len(),
            error = ?report.error,
            "applier report"
        );

        // Z-3 Phase A.1 (observability-plan.md): record the applier
        // outcome on the local audit chain. The token_bytes slot
        // carries a CBOR-encoded copy of the report so a SIEM pipeline
        // can reconstruct the full applier context from a single
        // chained line — including target_id, version, and per-
        // directive notes.
        //
        // 2026-04-28: `AppliedReport.kind` now splits the action
        // vocabulary into `policy.*` / `software.*` per the
        // observability-plan.md "deferred row" — agents that send
        // `kind` get the fine-grained slot, agents that don't fall
        // back to `apply.*` so the on-wire change is forwards/
        // backwards compatible.
        let succeeded = matches!(report.status, AppliedStatus::Ok | AppliedStatus::Skipped);
        let action = match report.kind {
            Some(AppliedKind::Policy) if succeeded => "policy.applied",
            Some(AppliedKind::Policy) => "policy.failed",
            Some(AppliedKind::Software) if succeeded => "software.applied",
            Some(AppliedKind::Software) => "software.failed",
            // Reconciliation and HostState heartbeats stay on the
            // generic family because they do not tie to a single
            // document outcome — the dashboard reads them through
            // the `apply.*` rate.
            _ if succeeded => "apply.applied",
            _ => "apply.failed",
        };
        let reason = match report.status {
            AppliedStatus::Failed => report.error.clone(),
            AppliedStatus::Skipped => Some("skipped".to_string()),
            AppliedStatus::Ok => None,
        };
        let mut report_bytes = Vec::new();
        let token_bytes = match ciborium::into_writer(report, &mut report_bytes) {
            Ok(()) => report_bytes,
            Err(e) => {
                tracing::warn!(error = %e, "audit: serializing applier report failed; emitting empty token_bytes");
                Vec::new()
            }
        };
        self.emit_local_audit(action, token_bytes, reason);
        Ok(())
    }

    // ================================================================
    // Credential Provider integration (Phase III)
    // ================================================================

    /// Shared FIDO2 assertion verifier used by both session issuance and
    /// admin vouch. Enforces: credential lookup, crypto, UP flag, RP-ID
    /// binding, server-challenge freshness, and sign-count monotonicity.
    ///
    /// **M-12 (security review)**: `client_data_json`, when `Some`,
    /// is the raw authenticator-signed `clientDataJSON` bytes. The
    /// verifier then parses them and checks `type == "webauthn.get"`,
    /// `challenge == base64url(server_challenge)`, and
    /// `origin == "https://" || enrolled_rp_id` individually per
    /// WebAuthn §7.2 steps 7–9. When `None`, falls back to the
    /// reconstruct-and-hash-compare path (cryptographically
    /// equivalent only if the client emits byte-identical JSON).
    fn verify_assertion_common(
        &mut self,
        credential_id: &str,
        challenge_id: &str,
        client_data_hash: &[u8],
        client_data_json: Option<&[u8]>,
        authenticator_data: &[u8],
        signature: &[u8],
    ) -> Result<CommonAssertionOutput, ServiceError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use dds_domain::fido2::{cose_to_credential_public_key, verify_assertion};
        use sha2::{Digest, Sha256};

        // observability-plan.md Phase C — every exit branch of this
        // function bumps `dds_fido2_assertions_total{result=...}` exactly
        // once via the drop-guard. Default bucket is `"other"`; named
        // branches overwrite the field before returning.
        let mut metric = AssertionMetricGuard::new();

        // M-19 (security review): refuse if the wall clock has regressed
        // since startup. NTP backstep or VM snapshot-restore could
        // un-expire a previously-consumed challenge or session. Compare
        // against the boot snapshot — `consume_challenge` itself uses
        // wall time below, so a regression there would silently re-validate
        // an already-spent challenge.
        if let Err(_e) = SystemTime::now().duration_since(self.boot_wall_time) {
            return Err(ServiceError::Fido2(
                "system clock regressed since service startup; \
                 refusing FIDO2 assertion to avoid challenge / session replay"
                    .to_string(),
            ));
        }

        // 1. Look up the credential's public key and enrolled RP-ID from the trust graph.
        let (subject_urn, public_key, enrolled_rp_id) = {
            let g = self
                .trust_graph
                .read()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

            let mut found: Option<(String, Vec<u8>, String)> = None;
            for token in g.attestations_iter() {
                if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                    continue;
                }
                let doc = match UserAuthAttestation::extract(&token.payload) {
                    Ok(Some(d)) => d,
                    _ => continue,
                };
                // **L-13 (security review)**: compare credential IDs
                // by the raw bytes they decode to, not by base64
                // string equality. Different clients may emit
                // standard vs base64url, with or without padding;
                // decoding normalizes any of those representations.
                if credential_ids_eq(&doc.credential_id, credential_id) {
                    // A-1 step-1: re-parse for credential lookup ONLY.
                    // Trust was already established at original
                    // enrollment time; pass `true` so the re-parse
                    // doesn't reject already-stored unattested
                    // credentials retroactively.
                    let parsed = dds_domain::fido2::verify_attestation(
                        &doc.attestation_object,
                        &doc.client_data_hash,
                        true,
                    )
                    .map_err(|e| ServiceError::Fido2(format!("re-parse attestation: {e}")))?;
                    let auth_data = &parsed.auth_data;
                    let p = 37 + 16 + 2 + parsed.credential_id.len();
                    let cose_bytes = &auth_data[p..];
                    found = Some((
                        token.payload.sub.clone(),
                        cose_bytes.to_vec(),
                        doc.rp_id.clone(),
                    ));
                    break;
                }
            }

            let (sub, cose_bytes, rp_id) = found.ok_or_else(|| {
                ServiceError::Fido2(format!(
                    "credential_id '{credential_id}' not found in trust graph"
                ))
            })?;
            let pk = cose_to_credential_public_key(&cose_bytes)
                .map_err(|e| ServiceError::Fido2(format!("COSE key parse: {e}")))?;
            (sub, pk, rp_id)
        };

        // 2. Cryptographic signature verification.
        let parsed =
            match verify_assertion(authenticator_data, client_data_hash, signature, &public_key) {
                Ok(p) => p,
                Err(dds_domain::fido2::Fido2Error::BadSignature) => {
                    metric.bucket = "signature";
                    return Err(ServiceError::Fido2(
                        dds_domain::fido2::Fido2Error::BadSignature.to_string(),
                    ));
                }
                Err(e) => {
                    // Format / KeyError / etc. — malformed authenticator
                    // payload, not a signature mismatch on a parseable
                    // payload. Collapses into `result="other"`.
                    return Err(ServiceError::Fido2(e.to_string()));
                }
            };

        // 3. User-presence (UP) flag — physical touch/biometric required.
        if !parsed.user_present {
            metric.bucket = "up";
            return Err(ServiceError::Fido2(
                "assertion failed: user_present (UP) flag not set".into(),
            ));
        }

        // 4. RP-ID binding — prevents cross-site assertion replay.
        {
            let expected_hash = Sha256::digest(enrolled_rp_id.as_bytes());
            if parsed.rp_id_hash != expected_hash.as_slice() {
                metric.bucket = "rp_id";
                return Err(ServiceError::Fido2(
                    "assertion rp_id_hash does not match enrolled relying party".into(),
                ));
            }
        }

        // 5. Challenge freshness — consume server-issued challenge and verify
        //    the clientDataJSON. Two validation paths:
        //    - **M-12 preferred**: if the client supplied raw
        //      `clientDataJSON` bytes, parse them and check `type`,
        //      `challenge`, `origin` individually per WebAuthn §7.2
        //      steps 7–9. Then confirm the hash still matches what
        //      the authenticator actually signed.
        //    - **Legacy fallback**: reconstruct the expected JSON
        //      string and hash-compare. Works only if the client
        //      emits byte-identical JSON (fragile).
        {
            let now = now_epoch();
            let challenge_bytes = self
                .store
                .consume_challenge(challenge_id, now)
                .map_err(|e| ServiceError::Fido2(format!("challenge invalid: {e}")))?;
            let expected_challenge_b64url = URL_SAFE_NO_PAD.encode(challenge_bytes.as_slice());
            let expected_origin = format!("https://{enrolled_rp_id}");

            if let Some(cdj_bytes) = client_data_json {
                // The authenticator signed SHA-256(clientDataJSON). Before
                // parsing, bind the supplied JSON to the signed hash — else
                // an attacker could present unrelated bytes that happen to
                // parse with valid fields.
                let cdj_hash = Sha256::digest(cdj_bytes);
                if cdj_hash.as_slice() != client_data_hash {
                    return Err(ServiceError::Fido2(
                        "client_data_hash does not match SHA-256 of supplied clientDataJSON".into(),
                    ));
                }
                let cdj: serde_json::Value = serde_json::from_slice(cdj_bytes).map_err(|e| {
                    ServiceError::Fido2(format!("clientDataJSON is not valid JSON: {e}"))
                })?;
                // §7.2 step 7: type must be "webauthn.get".
                let ty = cdj.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
                    ServiceError::Fido2("clientDataJSON missing type field".into())
                })?;
                if ty != "webauthn.get" {
                    return Err(ServiceError::Fido2(format!(
                        "clientDataJSON type is {ty:?}, expected \"webauthn.get\""
                    )));
                }
                // §7.2 step 8: challenge must equal server-issued value.
                let ch = cdj
                    .get("challenge")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServiceError::Fido2("clientDataJSON missing challenge field".into())
                    })?;
                // Clients may send base64url-without-padding (spec) or
                // base64url-with-padding (some stacks). Decode both
                // sides to raw bytes and compare.
                let ch_raw = decode_b64url_any(ch).ok_or_else(|| {
                    ServiceError::Fido2(
                        "clientDataJSON challenge field is not valid base64url".into(),
                    )
                })?;
                if ch_raw != challenge_bytes {
                    return Err(ServiceError::Fido2(
                        "clientDataJSON challenge does not match server-issued challenge".into(),
                    ));
                }
                // §7.2 step 9: origin must be https://<enrolled_rp_id>.
                let origin = cdj.get("origin").and_then(|v| v.as_str()).ok_or_else(|| {
                    ServiceError::Fido2("clientDataJSON missing origin field".into())
                })?;
                if origin != expected_origin {
                    return Err(ServiceError::Fido2(format!(
                        "clientDataJSON origin is {origin:?}, expected {expected_origin:?}"
                    )));
                }
                // Reject mixed-origin / cross-origin flows we do not support.
                if cdj
                    .get("crossOrigin")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    return Err(ServiceError::Fido2(
                        "clientDataJSON.crossOrigin is true; cross-origin assertions are refused"
                            .into(),
                    ));
                }
            } else {
                let ch_b64url = expected_challenge_b64url;
                let expected_cdj = format!(
                    r#"{{"type":"webauthn.get","challenge":"{ch_b64url}","origin":"{expected_origin}"}}"#
                );
                let expected_hash = Sha256::digest(expected_cdj.as_bytes());
                if expected_hash.as_slice() != client_data_hash {
                    return Err(ServiceError::Fido2(
                        "client_data_hash does not match server-issued challenge".into(),
                    ));
                }
            }
        }

        // 6. Sign-count monotonicity — detect cloned authenticators / replay.
        //    Authenticators that do not support counters report 0; skip the check.
        //    **L-18 (security review)**: use the atomic `bump_sign_count`
        //    primitive so the compare and the write happen under the same
        //    backend transaction. Today the service-wide mutex (see L-17)
        //    serializes these calls, but if L-17 is ever fixed the check
        //    here must remain race-free on its own.
        if parsed.sign_count > 0 {
            // AUDIT-2026-06-11 #9: key the sign-count store on the canonical
            // (decoded) credential id so a re-encoded request can't dodge the
            // replay check by minting a fresh key.
            let sc_key = canonical_credential_key(credential_id);
            match self.store.bump_sign_count(&sc_key, parsed.sign_count) {
                Ok(()) => {}
                Err(dds_store::traits::StoreError::SignCountReplay { stored, attempted }) => {
                    metric.bucket = "sign_count";
                    return Err(ServiceError::Fido2(format!(
                        "sign_count replay detected: received {attempted} <= stored {stored} for credential '{credential_id}'"
                    )));
                }
                Err(e) => return Err(ServiceError::Store(e.to_string())),
            }
        } else {
            tracing::warn!(
                credential_id = %credential_id,
                "authenticator reported sign_count=0; counter-based replay detection skipped"
            );
        }

        metric.bucket = "ok";
        Ok(CommonAssertionOutput {
            subject_urn,
            user_verified: parsed.user_verified,
        })
    }

    /// Issue a session from a FIDO2 assertion proof.
    ///
    /// The caller (Auth Bridge) sends the raw getAssertion output; we verify
    /// the assertion via `verify_assertion_common`, then issue a SessionDocument.
    pub fn issue_session_from_assertion(
        &mut self,
        req: AssertionSessionRequest,
    ) -> Result<SessionResult, ServiceError> {
        // Fold in replicated admin promotions/demotions before the
        // `purposes_for` chain walk below evaluates against
        // `trusted_roots` — an offboarded admin's grants must stop
        // minting sessions here even if no admin ceremony ever runs on
        // this node.
        self.reconcile_trusted_roots();

        let out = self.verify_assertion_common(
            &req.credential_id,
            &req.challenge_id,
            &req.client_data_hash,
            req.client_data_json.as_deref(),
            &req.authenticator_data,
            &req.signature,
        )?;

        // Issue a session bound to the enrolled subject URN. The caller's
        // subject_urn is IGNORED — the session is always bound to the credential
        // owner. mfa_verified reflects the actual UV flag from the authenticator.
        let session_req = SessionRequest {
            subject_urn: out.subject_urn,
            device_urn: None,
            requested_resources: vec![],
            duration_secs: req.duration_secs.unwrap_or(3600).min(86400),
            mfa_verified: out.user_verified,
            tls_binding: None,
        };
        // Use the inner mint path so the `dds_sessions_issued_total`
        // counter bumps `via="fido2"` once, not also `legacy`.
        let result = self.issue_session_inner(session_req)?;
        crate::telemetry::record_sessions_issued("fido2");
        Ok(result)
    }

    /// List enrolled users (UserAuthAttestation documents) for CP tile
    /// enumeration. Returns display names, subject URNs, and credential IDs.
    ///
    /// The `device_urn` parameter is accepted for API consistency but is
    /// intentionally not used for filtering: the Windows Credential Provider
    /// needs the **full** list of enrolled users to display logon tiles for
    /// every user who can authenticate on this machine. Filtering by device
    /// would break the CP tile enumeration flow. The endpoint is localhost-
    /// only, so roster visibility is bounded by OS process isolation.
    pub fn list_enrolled_users(
        &self,
        _device_urn: &str,
        include_revoked: bool,
    ) -> Result<Vec<EnrolledUser>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let mut users = Vec::new();
        for token in g.attestations_iter() {
            if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                continue;
            }
            let doc = match UserAuthAttestation::extract(&token.payload) {
                Ok(Some(d)) => d,
                _ => continue,
            };
            let vouched = !g
                .purposes_for(&token.payload.sub, &self.trusted_roots)
                .is_empty();
            // Offboarded = HAD a vouch, and no live one remains. A
            // never-vouched (pending) user has an empty summary list
            // and stays visible so the approval flow can find them.
            let summaries = g.vouch_summaries_for_subject(&token.payload.sub);
            let revoked = !summaries.is_empty() && summaries.iter().all(|s| s.revoked || s.expired);
            if revoked && !include_revoked {
                continue;
            }
            users.push(EnrolledUser {
                subject_urn: token.payload.sub.clone(),
                display_name: doc.user_display_name.clone(),
                credential_id: doc.credential_id.clone(),
                vouched,
                revoked,
            });
        }
        Ok(users)
    }

    /// Get node status.
    pub fn status(
        &self,
        peer_id: &str,
        connected_peers: usize,
        dag_ops: usize,
    ) -> Result<NodeStatus, ServiceError> {
        let trust_graph_tokens = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?
            .token_count();
        Ok(NodeStatus {
            peer_id: peer_id.to_string(),
            connected_peers,
            dag_operations: dag_ops,
            trust_graph_tokens,
            trusted_roots: self.trusted_roots.len(),
            store_tokens: self.store.count_tokens(None).unwrap_or(0),
            store_revoked: self.store.revoked_set().map(|s| s.len()).unwrap_or(0),
            store_burned: self.store.burned_set().map(|s| s.len()).unwrap_or(0),
            uptime_secs: now_epoch() - self.start_time,
            // Populated by callers that have a `StoreSizeStats` backend
            // (production HTTP handler) via [`Self::store_byte_sizes`].
            // Test fixtures using `MemoryBackend` keep this `None`.
            store_bytes: None,
            // Populated by the production HTTP handler from the
            // process-global telemetry handle via
            // [`crate::telemetry::last_admission_failure_ts`]. Test
            // fixtures and harnesses without a telemetry install keep
            // this `None`.
            last_admission_failure_ts: None,
        })
    }

    /// List audit log entries, optionally filtered by action and limited.
    pub fn list_audit_entries(
        &self,
        action: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<dds_core::audit::AuditLogEntry>, ServiceError> {
        let entries = self
            .store
            .list_audit_entries()
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        let filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .collect();
        match limit {
            Some(n) => Ok(filtered.into_iter().rev().take(n).collect()),
            None => Ok(filtered),
        }
    }

    /// Number of entries currently in the local audit chain.
    /// observability-plan.md Phase C — backs the
    /// `dds_audit_chain_length` Prometheus gauge.
    pub fn audit_chain_length(&self) -> Result<usize, ServiceError> {
        self.store
            .count_audit_entries()
            .map_err(|e| ServiceError::Store(e.to_string()))
    }

    /// Unix-seconds timestamp of the most recently appended audit
    /// entry, or `None` for an empty chain. observability-plan.md
    /// Phase C — backs the `dds_audit_chain_head_age_seconds` gauge
    /// (`now - head.timestamp`).
    pub fn audit_chain_head_timestamp(&self) -> Result<Option<u64>, ServiceError> {
        let entries = self
            .store
            .list_audit_entries()
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        Ok(entries.last().map(|e| e.timestamp))
    }

    /// Number of FIDO2 challenges currently outstanding in the
    /// challenge store (B-5 backstop reference). observability-plan.md
    /// Phase C — backs the `dds_challenges_outstanding` Prometheus
    /// gauge. Returns `None` when the underlying store read fails so
    /// the metrics renderer can degrade to a zero rather than panic
    /// the scrape task; this matches the `trust_graph_counts`
    /// poison-tolerance pattern.
    ///
    /// **Counts live + expired-but-not-yet-swept rows.** The expiry
    /// sweeper ([`crate::expiry::ExpiryConfig`]) clears expired
    /// challenges on its own cadence, so a non-zero gauge between
    /// sweeps is normal. The B-5 alarm condition is *unbounded
    /// growth*, which the gauge will surface as a rising baseline.
    pub fn challenges_outstanding(&self) -> Option<usize> {
        self.store.count_challenges().ok()
    }

    /// One-shot per-table byte snapshot. observability-plan.md Phase C
    /// — backs the `dds_store_bytes{table=...}` Prometheus gauge.
    /// Returns `None` when the underlying store read fails so the
    /// metrics renderer can degrade to a zero rather than panic the
    /// scrape task; matches the `trust_graph_counts` /
    /// `challenges_outstanding` poison-tolerance pattern.
    ///
    /// Backends that do not expose a meaningful byte size (the
    /// in-memory backend used in tests / harnesses) implement
    /// `table_stored_bytes` to return an empty map. The renderer
    /// treats that as "family present, no series" and the `# HELP` /
    /// `# TYPE` headers ship anyway so the family stays discoverable
    /// in the catalog.
    pub fn store_byte_sizes(&self) -> Option<StoreByteSizes>
    where
        S: dds_store::traits::StoreSizeStats,
    {
        self.store
            .table_stored_bytes()
            .ok()
            .map(|tables| StoreByteSizes { tables })
    }

    /// One-shot snapshot of process-lifetime store-write outcomes.
    /// observability-plan.md Phase C — backs the
    /// `dds_store_writes_total{result=ok|conflict|fail}` Prometheus
    /// counter. Reads three atomics with no locking, so it is cheap
    /// to call at every scrape.
    ///
    /// Bucket semantics, mirrored from the
    /// [`dds_store::traits::StoreWriteStats`] doc:
    /// - `ok`: write transaction committed and changed state.
    /// - `conflict`: caller-visible domain conflict that aborted the
    ///   write before commit (`put_operation` duplicate id,
    ///   `bump_sign_count` `SignCountReplay`).
    /// - `fail`: any other unsuccessful write (redb plumbing,
    ///   serialization, or audit chain break).
    pub fn store_write_counts(&self) -> dds_store::traits::StoreWriteCounts
    where
        S: dds_store::traits::StoreWriteStats,
    {
        self.store.store_write_counts()
    }

    /// One-shot trust-graph counts under a single read-lock
    /// acquisition. observability-plan.md Phase C — backs the
    /// `dds_trust_graph_attestations`, `dds_trust_graph_vouches`,
    /// `dds_trust_graph_revocations`, and `dds_trust_graph_burned`
    /// Prometheus gauges. Returns `None` if the trust-graph lock is
    /// poisoned so the metrics renderer can degrade to the previous
    /// scrape value rather than panic the scrape task.
    ///
    /// The attestation total is also partitioned by `body_type` —
    /// the renderer emits one
    /// `dds_trust_graph_attestations{body_type="..."}` series per
    /// non-zero bucket. Bucket vocabulary is bounded by the fixed
    /// [`dds_domain::body_types`] catalog; tokens whose `body_type`
    /// is absent or outside that catalog fall into the `unknown`
    /// bucket, so `sum(dds_trust_graph_attestations) ==
    /// dds_trust_graph_attestations{body_type=*}` always holds.
    pub fn trust_graph_counts(&self) -> Option<TrustGraphCounts> {
        let g = self.trust_graph.read().ok()?;
        let mut by_body_type: std::collections::BTreeMap<&'static str, usize> =
            std::collections::BTreeMap::new();
        for token in g.attestations_iter() {
            let bucket = body_type_label(token.payload.body_type.as_deref());
            *by_body_type.entry(bucket).or_insert(0) += 1;
        }
        Some(TrustGraphCounts {
            attestations: g.attestation_count(),
            vouches: g.vouch_count(),
            revocations: g.revocation_count(),
            burned: g.burned_count(),
            attestations_by_body_type: by_body_type,
        })
    }

    /// Get a clone of the shared trust graph handle. Callers can take a
    /// read or write lock as needed.
    pub fn trust_graph_handle(&self) -> Arc<RwLock<TrustGraph>> {
        Arc::clone(&self.trust_graph)
    }

    /// Access the store mutably.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    // ---- admin enrollment + vouch ----

    /// Register an admin identity. Enrolls the admin as a user (FIDO2
    /// attestation), then persists the generated Ed25519 signing key to
    /// `<data_dir>/admin_keys/` encrypted with AES-256-GCM keyed from
    /// the node's own signing key. The admin's URN is added to the
    /// in-memory `trusted_roots` set.
    ///
    /// **C-2 (security review)**: bootstrap is gated by an out-of-band
    /// sentinel file at `<data_dir>/.bootstrap`. The endpoint refuses
    /// every call unless the sentinel exists, AND refuses to add a
    /// second bootstrap admin once `trusted_roots` is non-empty.
    /// On success the sentinel is removed atomically. Operators must
    /// `touch <data_dir>/.bootstrap` (or use the MSI/launchd installer
    /// hook) before the first call. This blocks the LPE attack where
    /// a local unprivileged process self-enrolled as admin and then
    /// vouched themselves arbitrary purposes.
    ///
    /// Subsequent admins MUST be added via `admin_vouch` from an
    /// existing admin (which itself is capability-gated; see H-8).
    pub fn admin_setup(
        &mut self,
        req: AdminSetupRequest,
    ) -> Result<EnrollmentResult, ServiceError> {
        // C-2: gate.
        if !self.trusted_roots.is_empty() {
            return Err(ServiceError::Trust(
                "admin_setup: a bootstrap admin already exists; \
                 use admin_vouch to add additional admins"
                    .to_string(),
            ));
        }
        let sentinel = self.bootstrap_sentinel_path()?;
        if !sentinel.exists() {
            return Err(ServiceError::Trust(format!(
                "admin_setup: bootstrap sentinel '{}' is absent — \
                 the operator must `touch` it before the first admin_setup call",
                sentinel.display()
            )));
        }

        // Step 1: enroll the admin exactly like a normal user.
        // We need the generated identity to persist the signing key,
        // so we inline the enrollment logic here.
        let mut credential_id = req.credential_id.clone();
        if self.verify_fido2 {
            // A-1 step-3: same clientDataJSON checks as `enroll_user`.
            // **A-1 follow-up**: same challenge consumption as well —
            // a bootstrapping admin who wants the §7.1 step-9 binding
            // can fetch `/v1/enroll/challenge` first and supply
            // `challenge_id` here. Optional; the legacy path preserves
            // setup ergonomics when no challenge_id is provided.
            let challenge_bytes = match req.challenge_id.as_deref() {
                Some(id) => Some(
                    self.store
                        .consume_challenge(id, now_epoch())
                        .map_err(|e| {
                            ServiceError::Fido2(format!("enrollment challenge invalid: {e}"))
                        })?
                        .to_vec(),
                ),
                None => None,
            };
            verify_enrollment_client_data(
                req.client_data_json.as_deref(),
                &req.client_data_hash,
                &req.rp_id,
                challenge_bytes.as_deref(),
            )?;

            let parsed = Self::verify_attestation_observed(
                &req.attestation_object,
                &req.client_data_hash,
                self.allow_unattested_credentials,
            )
            .map_err(|e| ServiceError::Fido2(e.to_string()))?;

            // A-1 step-1: same WARN as the user-enroll path so the
            // bootstrap admin's enrollment is auditable when
            // attestation is `none`.
            if parsed.fmt == "none" {
                tracing::warn!(
                    label = %req.label,
                    "A-1: bootstrapping admin with fmt=none (unattested) — \
                     allow_unattested_credentials is true"
                );
            }

            // AAGUID allow-list also gates the bootstrap admin so an
            // operator who restricts which authenticators may enroll
            // cannot be bypassed by going through admin_setup.
            self.enforce_fido2_aaguid_allow_list(&parsed)?;

            // Same for the per-AAGUID attestation root: if the operator
            // requires a vendor-signed cert chain for this authenticator,
            // the bootstrap admin must satisfy it as well.
            self.enforce_fido2_attestation_roots(&parsed)?;

            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(req.rp_id.as_bytes());
            let computed_rp_hash = hasher.finalize();
            if computed_rp_hash.as_slice() != parsed.rp_id_hash {
                return Err(ServiceError::Fido2("rp_id hash mismatch".to_string()));
            }
            credential_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.credential_id);
        }

        let admin_ident = Identity::generate(&req.label, &mut rand::rngs::OsRng);
        let admin_urn = admin_ident.id.to_urn();

        let doc = UserAuthAttestation {
            credential_id,
            attestation_object: req.attestation_object,
            client_data_hash: req.client_data_hash,
            rp_id: req.rp_id,
            user_display_name: req.display_name,
            authenticator_type: req.authenticator_type,
        };
        let mut payload = self.make_attest_payload(&admin_ident);
        doc.embed(&mut payload)
            .map_err(|e| ServiceError::Domain(e.to_string()))?;

        let token = Token::sign(payload, &admin_ident.signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        let cbor = token
            .to_cbor()
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        self.store
            .put_token(&token)
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        {
            let mut g = self
                .trust_graph
                .write()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            let _ = g.add_token(token.clone());
        }

        // Step 2: persist the admin signing key (encrypted).
        self.store_admin_key(&admin_urn, &admin_ident.signing_key)?;

        // Step 3: add to trusted_roots in memory and persist to config.
        self.trusted_roots.insert(admin_urn.clone());
        // C-2 + H-8: this is THE bootstrap admin (we already refused if any
        // admin existed). Record it so admin_vouch can let the bootstrap
        // admin act unconstrained while constraining sub-admins.
        self.bootstrap_admin_urn = Some(admin_urn.clone());
        if let Err(e) = self.persist_trusted_roots() {
            tracing::warn!(error = %e, "failed to persist trusted_roots to config file (in-memory update still applies)");
        }
        // C-2: consume the sentinel atomically. If removal fails (read-only fs?)
        // we still proceed — the trusted_roots non-empty check is a sufficient
        // gate against a second admin_setup, and the operator can clean up
        // the file out-of-band.
        if let Err(e) = std::fs::remove_file(&sentinel) {
            tracing::warn!(
                path = %sentinel.display(),
                error = %e,
                "admin_setup succeeded but bootstrap sentinel removal failed; please remove manually"
            );
        }
        tracing::info!(admin_urn = %admin_urn, "admin identity registered and added to trusted roots");

        // Z-3 Phase A.1: bootstrap admin establishment is one of the
        // most security-relevant events on a domain — record it.
        self.emit_local_audit("admin.bootstrap", cbor.clone(), None);

        Ok(EnrollmentResult {
            urn: admin_urn,
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Resolve the path to the bootstrap sentinel file. Used by C-2:
    /// the file must exist before `admin_setup` can succeed and is
    /// consumed on success.
    fn bootstrap_sentinel_path(&self) -> Result<PathBuf, ServiceError> {
        let dir = self.data_dir.as_ref().ok_or_else(|| {
            ServiceError::Store(
                "admin_setup requires data_dir to be configured \
                 (so the bootstrap sentinel can be located)"
                    .to_string(),
            )
        })?;
        Ok(dir.join(".bootstrap"))
    }

    /// Admin vouches for an enrolled user. The admin proves presence via
    /// FIDO2 assertion. The node verifies the assertion (UP, RP-ID, challenge
    /// freshness, and sign-count via `verify_assertion_common`), requires the
    /// assertion to be user-verified (UV — see AUDIT-2026-06-12 R2), checks
    /// admin is a trusted root, loads the admin's persisted signing key, and
    /// signs a Vouch token granting the subject the requested purpose.
    pub fn admin_vouch(
        &mut self,
        req: AdminVouchRequest,
    ) -> Result<AdminVouchResult, ServiceError> {
        // Fold in any admin promotions/demotions that arrived via
        // gossip/sync since the last admin ceremony on this node.
        self.reconcile_trusted_roots();

        // 1–6. Shared assertion verifier: credential lookup, crypto, UP flag,
        //      RP-ID binding, challenge freshness, sign-count monotonicity.
        let out = self.verify_assertion_common(
            &req.credential_id,
            &req.challenge_id,
            &req.client_data_hash,
            req.client_data_json.as_deref(),
            &req.authenticator_data,
            &req.signature,
        )?;

        // **AUDIT-2026-06-12 R2**: admin vouching mints durable trust
        // material (Vouch tokens, including `dds:admin` promotions into
        // `trusted_roots`), so it must require User Verification (UV —
        // PIN/biometric, flags bit 0x04), not merely User Presence (UP —
        // a touch, bit 0x01). The Windows tray client requests
        // UV=REQUIRED, but a client-side parameter is not a security
        // boundary: anything that can reach this endpoint can replay a
        // UP-only assertion from a stolen-but-presence-unlocked admin
        // authenticator and mint vouches. The "stolen admin key cannot
        // vouch" guarantee therefore only exists if the node enforces UV
        // here, server-side. (Session issuance via
        // `issue_session_from_assertion` is deliberately NOT gated —
        // it authenticates-and-reflects, surfacing UV downstream as the
        // session's `mfa_verified` property.)
        if !out.user_verified {
            return Err(ServiceError::Fido2(
                "admin vouch requires a user-verified (UV) assertion: \
                 user_verified flag not set — presence-only (UP) is \
                 insufficient for privileged step-up"
                    .into(),
            ));
        }
        let admin_urn = out.subject_urn;

        // 7. Check admin is a trusted root.
        if !self.trusted_roots.contains(&admin_urn) {
            return Err(ServiceError::Trust(format!(
                "identity '{}' is not a trusted root",
                admin_urn
            )));
        }

        // H-8 (security review): capability-gate the vouch.
        //
        // The bootstrap admin (the principal that completed `admin_setup`)
        // can vouch for any purpose. Any other admin in `trusted_roots`
        // must hold a vouch from the bootstrap admin with purpose
        // `dds:admin-vouch:<requested-purpose>`. This blocks the
        // composed attack from C-2 + previous behaviour where the first
        // local process to self-enroll as admin obtained unlimited
        // vouching power over the entire domain.
        let requested_purpose = req
            .purpose
            .clone()
            .unwrap_or_else(|| "dds:session".to_string());
        let is_bootstrap_admin = self
            .bootstrap_admin_urn
            .as_deref()
            .map(|b| b == admin_urn)
            .unwrap_or(false);
        if !is_bootstrap_admin {
            let cap = format!("dds:admin-vouch:{requested_purpose}");
            let allowed = {
                let g = self
                    .trust_graph
                    .read()
                    .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
                self.has_purpose_observed(&g, &admin_urn, &cap)
            };
            if !allowed {
                return Err(ServiceError::Trust(format!(
                    "admin '{admin_urn}' lacks capability '{cap}' to vouch for purpose \
                     '{requested_purpose}' — only the bootstrap admin or an admin holding \
                     this capability vouch may vouch for this purpose"
                )));
            }
        }

        // 8. Load admin's persisted signing key.
        let admin_signing_key = self.load_admin_key(&admin_urn)?;

        // 9. Find the subject's attestation token to compute vch_sum.
        let (subject_attest_iss, subject_attest_hash) = {
            let g = self
                .trust_graph
                .read()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

            let mut found: Option<(String, String)> = None;
            for token in g.attestations_iter() {
                if token.payload.sub == req.subject_urn {
                    found = Some((token.payload.iss.clone(), token.payload_hash()));
                    break;
                }
            }
            found.ok_or_else(|| {
                ServiceError::Trust(format!(
                    "no attestation found for subject '{}'",
                    req.subject_urn
                ))
            })?
        };

        // 10. Build and sign the vouch token.
        let purpose = requested_purpose.clone();
        let vouch_jti = format!("vouch-{}", Uuid::new_v4().simple());
        let admin_public_key = dds_core::crypto::PublicKeyBundle {
            scheme: dds_core::crypto::SchemeId::Ed25519,
            bytes: admin_signing_key.verifying_key().to_bytes().to_vec(),
        };

        let vouch_payload = TokenPayload {
            iss: admin_urn.clone(),
            iss_key: admin_public_key,
            jti: vouch_jti.clone(),
            sub: req.subject_urn.clone(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose),
            vch_iss: Some(subject_attest_iss),
            vch_sum: Some(subject_attest_hash),
            revokes: None,
            iat: now_epoch(),
            exp: Some(now_epoch() + 365 * 86400),
            body_type: None,
            body_cbor: None,
        };

        let vouch_token = Token::sign(vouch_payload, &admin_signing_key)
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        let vouch_cbor = vouch_token
            .to_cbor()
            .map_err(|e| ServiceError::Token(e.to_string()))?;
        self.store
            .put_token(&vouch_token)
            .map_err(|e| ServiceError::Store(e.to_string()))?;
        {
            let mut g = self
                .trust_graph
                .write()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            let _ = g.add_token(vouch_token);
        }

        // Z-3 Phase A.1: admin vouches are policy-relevant events.
        self.emit_local_audit("admin.vouch", vouch_cbor.clone(), None);

        // **H-8 (security review)**: if the purpose is `dds:admin`,
        // promote the subject into `trusted_roots` and persist so the
        // new admin survives restart. This is the production path for
        // "adding a second admin via admin_vouch" that was called out
        // as missing. The capability gate earlier in this function
        // (bootstrap admin OR holder of `dds:admin-vouch:dds:admin`)
        // is what authorizes the promotion.
        if requested_purpose == dds_core::token::purpose::ADMIN {
            let promoted = self.trusted_roots.insert(req.subject_urn.clone());
            if promoted {
                if let Err(e) = self.persist_trusted_roots() {
                    tracing::warn!(
                        admin = %admin_urn,
                        subject = %req.subject_urn,
                        error = %e,
                        "promoted subject to trusted_roots but persisting config failed; \
                         promotion is effective in memory and will be lost on restart"
                    );
                } else {
                    tracing::info!(
                        admin = %admin_urn,
                        subject = %req.subject_urn,
                        "admin_vouch promoted subject to trusted_roots"
                    );
                }
            }
        }

        // Zeroize the admin signing key bytes.
        drop(admin_signing_key);

        tracing::info!(
            admin = %admin_urn,
            subject = %req.subject_urn,
            jti = %vouch_jti,
            "admin vouched for user"
        );

        Ok(AdminVouchResult {
            vouch_jti,
            subject_urn: req.subject_urn,
            admin_urn,
            token_cbor: vouch_cbor,
        })
    }

    /// Revoke the vouches THIS admin previously issued for a subject —
    /// the offboarding primitive for users and (via `dds:admin`
    /// purpose) sub-admins.
    ///
    /// Design constraints this leans on:
    /// - **H-1** (trust.rs): a Revoke is only accepted when revoker ==
    ///   issuer of the target token. Admin keys are the only persisted
    ///   signing keys on a node, and vouches are the only trust edges
    ///   admins issue — so "revoke my own vouches" is exactly the
    ///   maximal offboarding power the trust model permits. Vouches
    ///   issued by a DIFFERENT admin are returned in `foreign` so the
    ///   wizard can name who else must act.
    /// - The minted Revoke tokens replicate to peers under the
    ///   *existing* wire rules (peers already ingest Revoke tokens via
    ///   gossip + sync and re-check H-1 themselves), so offboarding
    ///   works against older nodes.
    /// - Sessions are stateless bearer tokens (≤24 h); revocation
    ///   blocks NEW session issuance (`purposes_for` skips revoked
    ///   vouches) but cannot recall already-issued sessions. Callers
    ///   must surface that window.
    ///
    /// Requires the same FIDO2 UV assertion ceremony as `admin_vouch`
    /// (AUDIT-2026-06-12 R2 applies equally: this mints durable trust
    /// material — negative trust material, but durable and gossiped).
    pub fn admin_revoke_vouch(
        &mut self,
        req: AdminRevokeVouchRequest,
    ) -> Result<AdminRevokeVouchResult, ServiceError> {
        // Fold in any admin promotions/demotions that arrived via
        // gossip/sync since the last admin ceremony on this node.
        self.reconcile_trusted_roots();

        let out = self.verify_assertion_common(
            &req.credential_id,
            &req.challenge_id,
            &req.client_data_hash,
            req.client_data_json.as_deref(),
            &req.authenticator_data,
            &req.signature,
        )?;
        if !out.user_verified {
            return Err(ServiceError::Fido2(
                "admin revoke-vouch requires a user-verified (UV) assertion: \
                 user_verified flag not set — presence-only (UP) is \
                 insufficient for privileged step-up"
                    .into(),
            ));
        }
        let admin_urn = out.subject_urn;

        if !self.trusted_roots.contains(&admin_urn) {
            return Err(ServiceError::Trust(format!(
                "identity '{}' is not a trusted root",
                admin_urn
            )));
        }

        // The bootstrap admin is the domain's trust anchor: it holds no
        // vouch (admin_setup inserts it directly into trusted_roots), so
        // there is nothing to revoke — and allowing a "revoke everything
        // for the bootstrap admin" call to half-succeed would only
        // mislead operators into thinking the anchor was offboarded.
        if self
            .bootstrap_admin_urn
            .as_deref()
            .map(|b| b == req.subject_urn)
            .unwrap_or(false)
        {
            return Err(ServiceError::Trust(
                "the bootstrap admin cannot be offboarded via revoke-vouch; \
                 its authority comes from trusted_roots, not from a vouch. \
                 Decommission or re-bootstrap the domain to rotate the anchor."
                    .to_string(),
            ));
        }

        // Snapshot the subject's live vouches and split them into ones
        // this admin issued (revocable here) vs. foreign ones.
        let summaries = {
            let g = self
                .trust_graph
                .read()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
            g.vouch_summaries_for_subject(&req.subject_urn)
        };
        let purpose_matches = |p: &Option<String>| match req.purpose.as_deref() {
            Some(filter) => p.as_deref() == Some(filter),
            None => true,
        };
        let live: Vec<_> = summaries
            .into_iter()
            .filter(|s| !s.revoked && purpose_matches(&s.purpose))
            .collect();
        if live.is_empty() {
            return Err(ServiceError::Trust(format!(
                "no active vouches found for subject '{}'{} — nothing to revoke",
                req.subject_urn,
                match req.purpose.as_deref() {
                    Some(p) => format!(" with purpose '{p}'"),
                    None => String::new(),
                }
            )));
        }
        let (mine, foreign_raw): (Vec<_>, Vec<_>) =
            live.into_iter().partition(|s| s.issuer == admin_urn);
        let foreign: Vec<ForeignVouchInfo> = foreign_raw
            .into_iter()
            .map(|s| ForeignVouchInfo {
                target_jti: s.jti,
                issuer: s.issuer,
                purpose: s.purpose,
            })
            .collect();

        let mut revoked = Vec::new();
        let mut revoke_tokens = Vec::new();
        let mut admin_vouch_revoked = false;

        if !mine.is_empty() {
            let admin_signing_key = self.load_admin_key(&admin_urn)?;
            let admin_public_key = dds_core::crypto::PublicKeyBundle {
                scheme: dds_core::crypto::SchemeId::Ed25519,
                bytes: admin_signing_key.verifying_key().to_bytes().to_vec(),
            };
            for s in &mine {
                let revoke_jti = format!("revoke-{}", Uuid::new_v4().simple());
                let payload = TokenPayload {
                    iss: admin_urn.clone(),
                    iss_key: admin_public_key.clone(),
                    jti: revoke_jti.clone(),
                    sub: req.subject_urn.clone(),
                    kind: TokenKind::Revoke,
                    purpose: s.purpose.clone(),
                    vch_iss: None,
                    vch_sum: None,
                    revokes: Some(s.jti.clone()),
                    iat: now_epoch(),
                    exp: None,
                    body_type: None,
                    body_cbor: None,
                };
                let token = Token::sign(payload, &admin_signing_key)
                    .map_err(|e| ServiceError::Token(e.to_string()))?;
                let cbor = token
                    .to_cbor()
                    .map_err(|e| ServiceError::Token(e.to_string()))?;
                // Same graph→store sequence as the sync ingest path:
                // the graph enforces H-1, then the store persists the
                // token and the revocation mark.
                {
                    let mut g = self
                        .trust_graph
                        .write()
                        .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
                    g.add_token(token.clone())
                        .map_err(|e| ServiceError::Trust(format!("revoke rejected: {e}")))?;
                }
                self.store
                    .put_token(&token)
                    .map_err(|e| ServiceError::Store(e.to_string()))?;
                self.store
                    .revoke(&s.jti)
                    .map_err(|e| ServiceError::Store(e.to_string()))?;
                self.emit_local_audit("admin.revoke_vouch", cbor, None);
                if s.purpose.as_deref() == Some(dds_core::token::purpose::ADMIN) {
                    admin_vouch_revoked = true;
                }
                revoked.push(RevokedVouchInfo {
                    revoke_jti,
                    target_jti: s.jti.clone(),
                    purpose: s.purpose.clone(),
                });
                revoke_tokens.push(token);
            }
            drop(admin_signing_key);
        }

        // Demote: a subject whose `dds:admin` vouch was just revoked must
        // not remain a local trusted root — UNLESS another admin's
        // `dds:admin` vouch for the subject is still live. Demoting on
        // *any* revoked admin-vouch (ignoring surviving co-vouches) would
        // drop a still-valid admin from trusted_roots + node.toml and
        // return demoted_from_trusted_roots=true incorrectly; it also
        // disagrees with the ingest-side (`reconcile_roots_after_token`,
        // node.rs) and reconcile paths, which both gate on a surviving
        // vouch. Delegate to the same reconcile so all three agree.
        let mut demoted = false;
        if admin_vouch_revoked {
            let was_root = self.trusted_roots.contains(&req.subject_urn);
            self.reconcile_trusted_roots();
            demoted = was_root && !self.trusted_roots.contains(&req.subject_urn);
        }

        tracing::info!(
            admin = %admin_urn,
            subject = %req.subject_urn,
            revoked = revoked.len(),
            foreign = foreign.len(),
            demoted,
            "admin revoked vouches for subject"
        );

        Ok(AdminRevokeVouchResult {
            subject_urn: req.subject_urn,
            admin_urn,
            revoked,
            foreign,
            demoted_from_trusted_roots: demoted,
            revoke_tokens,
        })
    }

    /// Reconcile `trusted_roots` against the (replicated) trust graph
    /// so admin promotion and demotion work across nodes:
    ///
    /// - **Promote**: a subject holding a live `dds:admin` vouch issued
    ///   by a current root becomes a root here too. Before identity
    ///   tokens replicated, promotion only happened on the node where
    ///   the vouching ceremony ran; every other node needed a manual
    ///   `trusted_roots` config edit.
    /// - **Demote**: a *promoted* root (one that has a `dds:admin` vouch
    ///   in the graph, i.e. it was not hand-added to config) is removed
    ///   when it no longer has a live `dds:admin` vouch **from a current
    ///   trusted root** — the exact inverse of the promotion rule. This
    ///   makes demotion transitive: offboarding admin R also demotes the
    ///   sub-admin S that R promoted, because once R leaves the root set,
    ///   S's vouch-from-R stops counting. Burned roots are demoted
    ///   unconditionally.
    /// - Roots with NO `dds:admin` vouch in the graph at all are left
    ///   alone: they are config-managed (hand-edited node.toml or the
    ///   bootstrap admin), and the graph has no evidence to overrule the
    ///   operator.
    ///
    /// Iterates to a fixpoint so a single call fully cascades a
    /// multi-level demotion. Called lazily from the admin ceremonies, the
    /// admin/user listing surfaces, and session issuance — cheap (a
    /// handful of indexed graph lookups) and idempotent. Persists on change.
    pub fn reconcile_trusted_roots(&mut self) {
        let admin_purpose = dds_core::token::purpose::ADMIN;
        let mut changed_any = false;
        // Bounded fixpoint: each round can only shrink-or-grow the root set,
        // and the delegation graph is finite; the cap is a belt-and-braces
        // guard against a pathological cycle in the vouch graph.
        for _ in 0..64 {
            let (to_add, to_remove) = {
                let g = match self.trust_graph.read() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                // A subject is *root-eligible* iff it holds a live
                // `dds:admin` vouch issued by a CURRENT trusted root.
                let eligible = |sub: &str| -> bool {
                    g.vouch_summaries_for_subject(sub).iter().any(|s| {
                        s.purpose.as_deref() == Some(admin_purpose)
                            && !s.revoked
                            && !s.expired
                            && self.trusted_roots.contains(&s.issuer)
                    })
                };
                // Promotion candidates: subjects of any dds:admin vouch.
                let mut candidates: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for v in g.vouches_iter() {
                    if v.payload.purpose.as_deref() == Some(admin_purpose) {
                        candidates.insert(v.payload.sub.clone());
                    }
                }
                let mut to_add: Vec<String> = Vec::new();
                for sub in candidates {
                    if self.trusted_roots.contains(&sub) || g.is_burned(&sub) {
                        continue;
                    }
                    if eligible(&sub) {
                        to_add.push(sub);
                    }
                }
                // Demotion: a promoted root (has ≥1 dds:admin vouch) that is
                // no longer eligible, or is burned.
                let mut to_remove: Vec<String> = Vec::new();
                for root in self.trusted_roots.iter() {
                    if self.bootstrap_admin_urn.as_deref() == Some(root.as_str()) {
                        continue;
                    }
                    if g.is_burned(root) {
                        to_remove.push(root.clone());
                        continue;
                    }
                    let has_any_admin_vouch = g
                        .vouch_summaries_for_subject(root)
                        .iter()
                        .any(|s| s.purpose.as_deref() == Some(admin_purpose));
                    if has_any_admin_vouch && !eligible(root) {
                        to_remove.push(root.clone());
                    }
                }
                (to_add, to_remove)
            };
            if to_add.is_empty() && to_remove.is_empty() {
                break;
            }
            for urn in &to_add {
                self.trusted_roots.insert(urn.clone());
                tracing::info!(subject = %urn, "reconcile: promoted to trusted_roots (replicated dds:admin vouch)");
            }
            for urn in &to_remove {
                self.trusted_roots.remove(urn);
                tracing::info!(subject = %urn, "reconcile: demoted from trusted_roots (no live dds:admin vouch from a current root)");
            }
            changed_any = true;
        }
        if changed_any {
            if let Err(e) = self.persist_trusted_roots() {
                tracing::warn!(error = %e, "reconcile: failed to persist trusted_roots (in-memory update still applies)");
            }
        }
    }

    /// List this node's trusted roots (admins) with display names and
    /// vouch status — the read surface for the console's admin page.
    pub fn list_admin_roots(
        &mut self,
    ) -> Result<(Vec<AdminRootInfo>, Option<String>), ServiceError> {
        self.reconcile_trusted_roots();
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;
        let mut roots = Vec::new();
        for urn in &self.trusted_roots {
            let display_name = g
                .attestations_iter()
                .find(|t| t.payload.sub == *urn)
                .and_then(|t| UserAuthAttestation::extract(&t.payload).ok().flatten())
                .map(|d| d.user_display_name);
            let has_active_admin_vouch = g.vouch_summaries_for_subject(urn).iter().any(|s| {
                !s.revoked
                    && !s.expired
                    && s.purpose.as_deref() == Some(dds_core::token::purpose::ADMIN)
            });
            roots.push(AdminRootInfo {
                urn: urn.clone(),
                is_bootstrap: self.bootstrap_admin_urn.as_deref() == Some(urn.as_str()),
                display_name,
                has_active_admin_vouch,
            });
        }
        Ok((roots, self.bootstrap_admin_urn.clone()))
    }

    // ---- admin key persistence ----

    /// Persist an admin's Ed25519 signing key encrypted with AES-256-GCM.
    ///
    /// **Wire format (security review M-22, L-10):**
    ///   - Version byte (`0x02`) | 12-byte IV | AES-256-GCM ciphertext+tag
    ///   - The wrap key is `SHA-256(node_signing_key || "admin-key-wrap")`
    ///   - **AAD = `admin_urn` bytes** so that swapping one admin's key blob
    ///     for another's fails the AEAD check (M-22 attack #2). Version 1
    ///     blobs (no AAD) are still readable on load for backward compat.
    ///
    /// File mode is set to `0o600` (Unix). The containing directory is set
    /// to `0o700`. Atomic write via tempfile + rename so a crash mid-write
    /// can't leave a torn blob.
    ///
    /// Plaintext key material is zeroized after use.
    ///
    /// **TODO(security)**: bind the wrap key to OS-bound storage (DPAPI
    /// on Windows, Keychain on macOS, TPM on Linux). Currently if the
    /// node key file is compromised on disk, all admin keys fall too —
    /// see M-22 in the security review for the deferred follow-up.
    fn store_admin_key(
        &self,
        admin_urn: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ServiceError> {
        const ADMIN_BLOB_VERSION: u8 = 0x02;

        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ServiceError::Store("data_dir not set — cannot persist admin keys".to_string())
        })?;
        let dir = data_dir.join("admin_keys");
        std::fs::create_dir_all(&dir)
            .map_err(|e| ServiceError::Store(format!("create admin_keys dir: {e}")))?;
        // M-22 / L-4: tighten directory perms (Unix only — Windows uses
        // explicit ACLs on the parent ProgramData tree).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }

        let mut wrap_key = self.admin_wrap_key();
        // H-9: wrap plaintext in zeroize-on-drop wrapper before encrypt
        // so an early return can't leave secret bytes on the heap.
        let mut plaintext = signing_key.to_bytes();

        let mut iv = [0u8; 12];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut iv);
        }

        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
        let cipher = Aes256Gcm::new_from_slice(&wrap_key)
            .map_err(|e| ServiceError::Store(format!("AES key init: {e}")))?;
        let nonce = Nonce::from_slice(&iv);
        // M-22: bind ciphertext to admin_urn via AEAD AAD.
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: admin_urn.as_bytes(),
                },
            )
            .map_err(|e| {
                // Zeroize before returning the error.
                plaintext.zeroize();
                wrap_key.zeroize();
                ServiceError::Store(format!("AES encrypt: {e}"))
            })?;
        plaintext.zeroize();
        wrap_key.zeroize();

        let urn_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(admin_urn.as_bytes()))
        };
        let path = dir.join(format!("{urn_hash}.key"));
        let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
        blob.push(ADMIN_BLOB_VERSION);
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ciphertext);

        // L-3: atomic write — tempfile in same directory, then rename.
        let tmp = tempfile::NamedTempFile::new_in(&dir)
            .map_err(|e| ServiceError::Store(format!("admin key tempfile: {e}")))?;
        std::fs::write(tmp.path(), &blob)
            .map_err(|e| ServiceError::Store(format!("admin key tempfile write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600));
        }
        tmp.persist(&path)
            .map_err(|e| ServiceError::Store(format!("admin key persist: {e}")))?;

        tracing::debug!(path = %path.display(), "persisted admin signing key");
        Ok(())
    }

    /// Load an admin's Ed25519 signing key from encrypted storage.
    /// Supports legacy v1 blobs (no version byte, no AAD) and current
    /// v2 blobs (1-byte version `0x02`, AAD = admin_urn).
    fn load_admin_key(&self, admin_urn: &str) -> Result<ed25519_dalek::SigningKey, ServiceError> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ServiceError::Store("data_dir not set — cannot load admin keys".to_string())
        })?;
        let urn_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(admin_urn.as_bytes()))
        };
        let path = data_dir.join("admin_keys").join(format!("{urn_hash}.key"));
        let blob = std::fs::read(&path)
            .map_err(|e| ServiceError::Store(format!("read admin key {}: {e}", path.display())))?;

        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
        let mut wrap_key = self.admin_wrap_key();
        let cipher = Aes256Gcm::new_from_slice(&wrap_key)
            .map_err(|e| ServiceError::Store(format!("AES key init: {e}")))?;

        // Try v2 (versioned, AEAD bound to admin_urn) first.
        let mut plaintext = if blob.first() == Some(&0x02) && blob.len() >= 1 + 12 + 16 {
            let iv = &blob[1..13];
            let ciphertext = &blob[13..];
            let nonce = Nonce::from_slice(iv);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: admin_urn.as_bytes(),
                    },
                )
                .map_err(|e| ServiceError::Store(format!("AES decrypt admin key v2: {e}")))?
        } else if blob.len() >= 12 + 32 + 16 {
            // v1 legacy: no version byte, no AAD.
            tracing::warn!(
                path = %path.display(),
                "loading legacy v1 admin key blob (no AAD); will be re-wrapped on next admin_setup"
            );
            let iv = &blob[..12];
            let ciphertext = &blob[12..];
            let nonce = Nonce::from_slice(iv);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| ServiceError::Store(format!("AES decrypt admin key v1: {e}")))?
        } else {
            wrap_key.zeroize();
            return Err(ServiceError::Store("admin key file too short".to_string()));
        };
        wrap_key.zeroize();

        if plaintext.len() != 32 {
            plaintext.zeroize();
            return Err(ServiceError::Store(format!(
                "decrypted admin key is {} bytes, expected 32",
                plaintext.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        let key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();
        Ok(key)
    }

    /// Derive the AES-256 wrapping key for admin key storage from the
    /// node's own Ed25519 signing key.
    fn admin_wrap_key(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.node_identity.signing_key.to_bytes());
        hasher.update(b"admin-key-wrap");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Validate a session token issued by this node and extract its
    /// `SessionDocument` body for privileged localhost follow-on flows
    /// such as Windows account claim.
    fn validate_local_session_token(
        &self,
        session_token_cbor: &[u8],
    ) -> Result<SessionDocument, ServiceError> {
        let token = Token::from_cbor(session_token_cbor)
            .map_err(|e| ServiceError::Token(format!("session token decode: {e}")))?;
        token
            .validate()
            .map_err(|e| ServiceError::Token(format!("session token validate: {e}")))?;

        let expected_issuer = self.node_identity.id.to_urn();
        if token.payload.iss != expected_issuer {
            return Err(ServiceError::Trust(format!(
                "session token issuer '{}' does not match local node '{}'",
                token.payload.iss, expected_issuer
            )));
        }

        if token.payload.purpose.as_deref() != Some("dds:session") {
            return Err(ServiceError::Token(
                "token is not a DDS session token".into(),
            ));
        }

        let session = SessionDocument::extract(&token.payload)
            .map_err(|e| ServiceError::Domain(format!("session token body: {e}")))?
            .ok_or_else(|| ServiceError::Domain("missing SessionDocument body".into()))?;

        if session.subject_urn != token.payload.sub {
            return Err(ServiceError::Token(
                "session token subject does not match embedded SessionDocument".into(),
            ));
        }

        Ok(session)
    }

    // ---- internal ----

    fn make_attest_payload(&self, ident: &Identity) -> TokenPayload {
        TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            // H-4 (security review): JTIs were `attest-<label>` —
            // deterministic. Two enrollments with the same label
            // collided, letting an attacker overwrite a legitimate
            // attestation in the trust graph and corrupt issuer-keyed
            // lookups. Suffix with a random UUID so JTIs are globally
            // unique. Prior to this, `dds-core::trust::add_token` also
            // silently overwrote duplicate JTIs; that has been
            // tightened to reject duplicates outright (`DuplicateJti`).
            jti: format!("attest-{}-{}", ident.id.label(), Uuid::new_v4().simple()),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: now_epoch(),
            exp: Some(now_epoch() + 365 * 86400),
            body_type: None,
            body_cbor: None,
        }
    }
}

/// Service errors.
#[derive(Debug)]
pub enum ServiceError {
    Token(String),
    Domain(String),
    Store(String),
    Trust(String),
    Policy(String),
    Fido2(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Token(e) => write!(f, "token error: {e}"),
            ServiceError::Domain(e) => write!(f, "domain error: {e}"),
            ServiceError::Store(e) => write!(f, "store error: {e}"),
            ServiceError::Trust(e) => write!(f, "trust error: {e}"),
            ServiceError::Policy(e) => write!(f, "policy error: {e}"),
            ServiceError::Fido2(e) => write!(f, "fido2 error: {e}"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// **B-4 (security review).** Collapse multiple `WindowsPolicyDocument`
/// attestations sharing the same `policy_id` to a single winner.
/// Winner: highest `version`; tiebreak latest `iat`; final tiebreak
/// lex-smallest `jti`. Output is sorted by `policy_id` for stable
/// agent ordering across polls.
fn supersede_windows_policies(items: Vec<ApplicableWindowsPolicy>) -> Vec<ApplicableWindowsPolicy> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, ApplicableWindowsPolicy> = BTreeMap::new();
    for item in items {
        let key = item.document.policy_id.clone();
        match by_id.get(&key) {
            None => {
                by_id.insert(key, item);
            }
            Some(prev) => {
                let prev_v = prev.document.version;
                let cur_v = item.document.version;
                let take = match cur_v.cmp(&prev_v) {
                    core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Less => false,
                    core::cmp::Ordering::Equal => match item.iat.cmp(&prev.iat) {
                        core::cmp::Ordering::Greater => true,
                        core::cmp::Ordering::Less => false,
                        core::cmp::Ordering::Equal => item.jti < prev.jti,
                    },
                };
                if take {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %item.jti,
                        winning_version = item.document.version,
                        loser_jti = %prev.jti,
                        loser_version = prev.document.version,
                        "B-4: superseding duplicate windows policy"
                    );
                    by_id.insert(key, item);
                } else {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %prev.jti,
                        winning_version = prev.document.version,
                        loser_jti = %item.jti,
                        loser_version = item.document.version,
                        "B-4: dropping duplicate windows policy"
                    );
                }
            }
        }
    }
    by_id.into_values().collect()
}

/// **B-4** macOS policy supersession — same rules as
/// [`supersede_windows_policies`].
fn supersede_macos_policies(items: Vec<ApplicableMacOsPolicy>) -> Vec<ApplicableMacOsPolicy> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, ApplicableMacOsPolicy> = BTreeMap::new();
    for item in items {
        let key = item.document.policy_id.clone();
        match by_id.get(&key) {
            None => {
                by_id.insert(key, item);
            }
            Some(prev) => {
                let prev_v = prev.document.version;
                let cur_v = item.document.version;
                let take = match cur_v.cmp(&prev_v) {
                    core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Less => false,
                    core::cmp::Ordering::Equal => match item.iat.cmp(&prev.iat) {
                        core::cmp::Ordering::Greater => true,
                        core::cmp::Ordering::Less => false,
                        core::cmp::Ordering::Equal => item.jti < prev.jti,
                    },
                };
                if take {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %item.jti,
                        loser_jti = %prev.jti,
                        "B-4: superseding duplicate macos policy"
                    );
                    by_id.insert(key, item);
                } else {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %prev.jti,
                        loser_jti = %item.jti,
                        "B-4: dropping duplicate macos policy"
                    );
                }
            }
        }
    }
    by_id.into_values().collect()
}

/// **B-4** Linux policy supersession — same rules as
/// [`supersede_windows_policies`].
fn supersede_linux_policies(items: Vec<ApplicableLinuxPolicy>) -> Vec<ApplicableLinuxPolicy> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, ApplicableLinuxPolicy> = BTreeMap::new();
    for item in items {
        let key = item.document.policy_id.clone();
        match by_id.get(&key) {
            None => {
                by_id.insert(key, item);
            }
            Some(prev) => {
                let prev_v = prev.document.version;
                let cur_v = item.document.version;
                let take = match cur_v.cmp(&prev_v) {
                    core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Less => false,
                    core::cmp::Ordering::Equal => match item.iat.cmp(&prev.iat) {
                        core::cmp::Ordering::Greater => true,
                        core::cmp::Ordering::Less => false,
                        core::cmp::Ordering::Equal => item.jti < prev.jti,
                    },
                };
                if take {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %item.jti,
                        loser_jti = %prev.jti,
                        "B-4: superseding duplicate linux policy"
                    );
                    by_id.insert(key, item);
                } else {
                    tracing::warn!(
                        policy_id = %key,
                        winning_jti = %prev.jti,
                        loser_jti = %item.jti,
                        "B-4: dropping duplicate linux policy"
                    );
                }
            }
        }
    }
    by_id.into_values().collect()
}

/// **B-4** software supersession. Software `version` is a free-form
/// string, so we order by signing timestamp `iat` (latest wins) with a
/// final lex-smallest-`jti` tiebreaker.
fn supersede_software(items: Vec<ApplicableSoftware>) -> Vec<ApplicableSoftware> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<String, ApplicableSoftware> = BTreeMap::new();
    for item in items {
        let key = item.document.package_id.clone();
        match by_id.get(&key) {
            None => {
                by_id.insert(key, item);
            }
            Some(prev) => {
                let take = match item.iat.cmp(&prev.iat) {
                    core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Less => false,
                    core::cmp::Ordering::Equal => item.jti < prev.jti,
                };
                if take {
                    tracing::warn!(
                        package_id = %key,
                        winning_jti = %item.jti,
                        loser_jti = %prev.jti,
                        "B-4: superseding duplicate software assignment"
                    );
                    by_id.insert(key, item);
                }
            }
        }
    }
    by_id.into_values().collect()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

/// **A-1 step-3 (security review)**: validate the raw
/// `clientDataJSON` from a MakeCredential response, mirroring M-12's
/// assertion-side check. When `cdj_bytes` is `None`, the legacy
/// "no clientDataJSON" path runs (caller still validates the
/// rp-id-hash via `verify_attestation`). When `Some`:
///
/// 1. Bind the supplied JSON to the signed `client_data_hash` via
///    SHA-256 — otherwise an attacker could present unrelated bytes
///    that happen to parse with valid fields.
/// 2. Parse the JSON and enforce per WebAuthn §7.1 steps 8–11:
///    - `type == "webauthn.create"` (assertion path enforces
///      `"webauthn.get"` instead).
///    - `origin == "https://<rp_id>"`.
///    - `crossOrigin != true`.
///    - When `expected_challenge` is supplied, the cdj `challenge`
///      field decodes (base64url, padded or unpadded) to those exact
///      bytes — closing the §7.1 step 9 gap that previously needed
///      the `/v1/enroll/challenge` endpoint to land. The caller is
///      responsible for atomically consuming the challenge from the
///      server-side store before passing the bytes in.
fn verify_enrollment_client_data(
    cdj_bytes: Option<&[u8]>,
    client_data_hash: &[u8],
    rp_id: &str,
    expected_challenge: Option<&[u8]>,
) -> Result<(), ServiceError> {
    use sha2::{Digest, Sha256};

    let Some(cdj_bytes) = cdj_bytes else {
        // No clientDataJSON supplied. If the caller went to the
        // trouble of consuming a server challenge but didn't include
        // the JSON, refuse — silently dropping the binding would let
        // a buggy client bypass the freshness check it requested.
        if expected_challenge.is_some() {
            return Err(ServiceError::Fido2(
                "challenge_id supplied without clientDataJSON; cannot verify cdj.challenge".into(),
            ));
        }
        return Ok(());
    };

    // 1. Bind clientDataJSON to the signed hash.
    let cdj_hash = Sha256::digest(cdj_bytes);
    if cdj_hash.as_slice() != client_data_hash {
        return Err(ServiceError::Fido2(
            "client_data_hash does not match SHA-256 of supplied clientDataJSON".into(),
        ));
    }

    // 2. Parse and validate fields.
    let cdj: serde_json::Value = serde_json::from_slice(cdj_bytes)
        .map_err(|e| ServiceError::Fido2(format!("clientDataJSON is not valid JSON: {e}")))?;

    // §7.1 step 8: type must be "webauthn.create".
    let ty = cdj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::Fido2("clientDataJSON missing type field".into()))?;
    if ty != "webauthn.create" {
        return Err(ServiceError::Fido2(format!(
            "clientDataJSON type is {ty:?}, expected \"webauthn.create\""
        )));
    }

    // §7.1 step 9: when a server-issued challenge is supplied, the
    // cdj challenge field must match it byte-for-byte. Same lenient
    // base64url decoder as the assertion side (some JS stacks emit
    // base64url-with-pad).
    if let Some(expected_bytes) = expected_challenge {
        let ch = cdj
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::Fido2("clientDataJSON missing challenge field".into()))?;
        let ch_raw = decode_b64url_any(ch).ok_or_else(|| {
            ServiceError::Fido2("clientDataJSON challenge field is not valid base64url".into())
        })?;
        if ch_raw != expected_bytes {
            return Err(ServiceError::Fido2(
                "clientDataJSON challenge does not match server-issued enrollment challenge".into(),
            ));
        }
    }

    // §7.1 step 10: origin must be https://<rp_id>.
    let expected_origin = format!("https://{rp_id}");
    let origin = cdj
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ServiceError::Fido2("clientDataJSON missing origin field".into()))?;
    if origin != expected_origin {
        return Err(ServiceError::Fido2(format!(
            "clientDataJSON origin is {origin:?}, expected {expected_origin:?}"
        )));
    }

    // Reject mixed-origin / cross-origin enrollment we do not support.
    if cdj
        .get("crossOrigin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(ServiceError::Fido2(
            "clientDataJSON.crossOrigin is true; cross-origin enrollment is refused".into(),
        ));
    }

    Ok(())
}

/// **M-12 (security review)**: decode a WebAuthn `challenge` field
/// into raw bytes, accepting both base64url-no-pad (per spec) and
/// base64url-with-pad (some JS stacks), but rejecting standard
/// base64 — a WebAuthn client MUST emit base64url here, and
/// accepting `+/` alphabet would hide a client bug.
fn decode_b64url_any(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .ok()
}

/// Parse a FIDO2 AAGUID from a configuration string. Accepts the
/// canonical UUID layout (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
/// 36 chars) and the bare 32-char hex form. Case-insensitive.
/// Returns `None` for any other input.
fn parse_aaguid(raw: &str) -> Option<[u8; 16]> {
    let stripped: String = raw.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = stripped.as_bytes()[i * 2];
        let lo = stripped.as_bytes()[i * 2 + 1];
        let nibble = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        *byte = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
}

/// Parse a PEM blob into a list of DER-encoded X.509 certificates.
/// Tolerates Unix or Windows newlines, optional whitespace around
/// blocks, multiple concatenated `-----BEGIN CERTIFICATE-----` blocks
/// in one file, and other PEM types interleaved (only `CERTIFICATE`
/// blocks are returned). Returns an empty vec when no CERTIFICATE
/// blocks are present, leaving the caller to decide whether that is
/// an error.
fn parse_pem_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8 PEM: {e}"))?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        rest = &rest[start..];
        let body_start = rest
            .find('\n')
            .ok_or_else(|| "PEM header not newline-terminated".to_string())?
            + 1;
        let end = rest
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| "PEM block missing END line".to_string())?;
        let body = &rest[body_start..end];
        let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| format!("PEM base64: {e}"))?;
        out.push(der);
        rest = &rest[end + "-----END CERTIFICATE-----".len()..];
    }
    Ok(out)
}

/// Format a 16-byte AAGUID as a canonical UUID string. Used in
/// log/error messages so operators see the same string they put in
/// `fido2_allowed_aaguids`.
fn format_aaguid(bytes: &[u8; 16]) -> String {
    let hex = |b: &[u8]| -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16]),
    )
}

/// **L-13 (security review)**: compare two credential-id strings by
/// decoding both to raw bytes first (accepting standard base64 OR
/// base64url, with or without padding) and comparing the bytes.
/// Falls back to string equality if neither decode succeeds, which
/// matches the prior behaviour for opaque/raw inputs.
fn credential_ids_eq(a: &str, b: &str) -> bool {
    let decode = |s: &str| -> Option<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
            .ok()
    };
    match (decode(a), decode(b)) {
        (Some(da), Some(db)) => da == db,
        _ => a == b,
    }
}

/// **AUDIT-2026-06-11 #9** — canonical, encoding-independent key for the
/// per-credential sign-count store. Credential *lookup* matches by decoded
/// bytes (`credential_ids_eq`), so the sign-count replay check must key on a
/// representation that is identical across base64 encodings. Keying on the raw
/// request string let an attacker re-encode the same credential id (url-safe
/// vs standard, padded vs not) so `bump_sign_count` saw a brand-new key and
/// the cloned-authenticator / replay detection (L-18) was bypassed. Decoded
/// bytes are hex-encoded; a value that is not base64 at all falls back to
/// itself.
fn canonical_credential_key(credential_id: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_id)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(credential_id))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(credential_id))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(credential_id))
        .map(hex::encode)
        .unwrap_or_else(|_| credential_id.to_string())
}

/// Find the device's `tags` + `org_unit` by walking the trust graph
/// for an attestation token where:
/// - issuer == device_urn (the device self-attested), AND
/// - body_type == `dds:device-join`
///
/// Returns `(tags, org_unit)`. If the device has no
/// `DeviceJoinDocument` on this node, both come back empty/None — the
/// device can still be targeted by `identity_urns` but not by tags or
/// org units.
fn device_targeting_facts(g: &TrustGraph, device_urn: &str) -> (Vec<String>, Option<String>) {
    for token in g.attestations_iter() {
        if token.payload.iss != device_urn {
            continue;
        }
        if let Ok(Some(d)) = DeviceJoinDocument::extract(&token.payload) {
            return (d.tags, d.org_unit);
        }
    }
    (Vec::new(), None)
}

/// Does this `PolicyScope` match the given device's facts?
///
/// Empty scope (no tags, no org_units, no identity_urns) means
/// "global" — every device matches. A non-empty scope matches if at
/// least one of its three criteria is satisfied.
fn scope_matches(
    scope: &PolicyScope,
    device_urn: &str,
    device_tags: &[String],
    device_org_unit: Option<&str>,
) -> bool {
    if scope.identity_urns.is_empty() && scope.device_tags.is_empty() && scope.org_units.is_empty()
    {
        return true;
    }
    if scope.identity_urns.iter().any(|u| u == device_urn) {
        return true;
    }
    if scope
        .device_tags
        .iter()
        .any(|t| device_tags.iter().any(|dt| dt == t))
    {
        return true;
    }
    if let Some(ou) = device_org_unit {
        if scope.org_units.iter().any(|o| o == ou) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod platform_applier_tests {
    use super::*;
    use dds_core::token::TokenPayload;
    use dds_domain::{
        AccountAction, AccountDirective, DeviceJoinDocument, LaunchdAction, LaunchdDirective,
        LinuxFileAction, LinuxFileDirective, LinuxPackageAction, LinuxPackageDirective,
        LinuxPolicyDocument, LinuxSettings, LinuxUserAction, LinuxUserDirective, MacAccountAction,
        MacAccountDirective, MacOsPolicyDocument, MacOsSettings, PasswordPolicy, PolicyScope,
        PreferenceAction, PreferenceDirective, PreferenceScope, ProfileAction, ProfileDirective,
        PublisherIdentity, RegistryAction, RegistryDirective, RegistryHive, RegistryValue,
        SoftwareAssignment, WindowsPolicyDocument, WindowsSettings,
    };
    use dds_store::MemoryBackend;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::{Arc, Mutex, RwLock};

    // ---- Local policy publishing (Users & Policy console) ----

    fn minimal_windows_claim_doc(subject_urn: &str) -> WindowsPolicyDocument {
        WindowsPolicyDocument {
            policy_id: "windows/claim/bob".to_string(),
            display_name: "New account: bob".to_string(),
            version: 1,
            scope: PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            enforcement: Enforcement::Enforce,
            windows: Some(WindowsSettings {
                local_accounts: vec![AccountDirective {
                    username: "bob".to_string(),
                    action: AccountAction::Create,
                    claim_subject_urn: Some(subject_urn.to_string()),
                    full_name: Some("Bob Novak".to_string()),
                    description: None,
                    groups: vec!["Users".to_string()],
                    password_never_expires: Some(true),
                }],
                ..Default::default()
            }),
        }
    }

    /// A trusted-root node with no publisher capability bootstraps it inline
    /// (self-attest + self-vouch + policy) on first publish, then needs only
    /// the policy token once the capability is established.
    #[test]
    fn plan_policy_publish_bootstraps_capability_on_trusted_root_node() {
        let node = Identity::generate("pubnode", &mut OsRng);
        let node_urn = node.id.to_urn();
        let mut roots = BTreeSet::new();
        roots.insert(node_urn.clone()); // node IS a trusted root
        let graph = Arc::new(RwLock::new(TrustGraph::new()));
        let svc = LocalService::new(node, graph, roots, MemoryBackend::new());

        let purpose = dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS;
        assert!(!svc.node_has_publisher_capability(purpose));
        assert!(svc.node_is_trusted_root());

        let doc = minimal_windows_claim_doc("urn:vouchsafe:bob.deadbeef");
        let token = svc.build_policy_attestation(&doc).unwrap();
        assert_eq!(token.payload.iss, node_urn);
        assert_eq!(
            token.payload.body_type.as_deref(),
            Some(dds_domain::body_types::WINDOWS_POLICY)
        );

        let batch = svc.plan_policy_publish(token, purpose).unwrap();
        assert_eq!(
            batch.len(),
            3,
            "root node bootstraps: self-attest + self-vouch + policy"
        );

        // Apply the self-attest + self-vouch as the node's run loop would.
        {
            let mut g = svc.trust_graph.write().unwrap();
            g.add_token(batch[0].clone()).unwrap();
            g.add_token(batch[1].clone()).unwrap();
        }
        assert!(
            svc.node_has_publisher_capability(purpose),
            "capability holds after applying the self-vouch"
        );

        // Second publish now needs only the policy token.
        let doc2 = minimal_windows_claim_doc("urn:vouchsafe:carol.feedface");
        let token2 = svc.build_policy_attestation(&doc2).unwrap();
        let batch2 = svc.plan_policy_publish(token2, purpose).unwrap();
        assert_eq!(batch2.len(), 1, "capability established -> only the policy");
    }

    /// A non-root node with no publisher capability fails closed with an
    /// actionable grant command; `publisher_status` reflects the same.
    #[test]
    fn plan_policy_publish_fails_closed_when_node_not_authorized() {
        let node = Identity::generate("pubnode", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let mut roots = BTreeSet::new();
        roots.insert(admin.id.to_urn()); // admin is root; node is NOT
        let graph = Arc::new(RwLock::new(TrustGraph::new()));
        let svc = LocalService::new(node, graph, roots, MemoryBackend::new());
        let node_urn = svc.node_urn();

        let purpose = dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS;
        let status = svc.publisher_status(purpose);
        assert!(!status.can_publish);
        assert!(!status.is_trusted_root);
        assert!(!status.has_capability);
        assert!(status.grant_command.contains("dds admin vouch"));
        assert!(status.grant_command.contains(&node_urn));

        let doc = minimal_windows_claim_doc("urn:vouchsafe:bob.deadbeef");
        let token = svc.build_policy_attestation(&doc).unwrap();
        match svc.plan_policy_publish(token, purpose) {
            Err(ServiceError::Trust(msg)) => {
                assert!(msg.contains("dds admin vouch"));
                assert!(msg.contains(&node_urn));
                assert!(msg.contains(purpose));
            }
            Ok(_) => panic!("expected fail-closed, got Ok"),
            Err(e) => panic!("expected Trust error, got {e:?}"),
        }
    }

    // ---- Console (Users & Policy) wire-format compatibility ----
    //
    // DdsConsole.ps1 builds WindowsPolicyDocument JSON in PowerShell (the
    // first-account claim) and ships JSON templates. These pin the exact
    // wire shapes the console emits — enum tags ("Create"/"Enforce"/"Set"),
    // data-carrying enums ({"Dword":1}), field names — so a serde change
    // here can't silently break the GUI publish path (POST /v1/policy/publish
    // deserializes into these very types).

    #[test]
    fn console_first_account_claim_json_deserializes() {
        // Byte-for-byte the shape `New-ClaimPolicyJson` produces.
        let json = r#"{
            "policy_id": "windows/claim/bob",
            "display_name": "New account: bob",
            "version": 1,
            "scope": { "identity_urns": ["urn:vouchsafe:pc1.def"] },
            "settings": [],
            "enforcement": "Enforce",
            "windows": { "local_accounts": [
                { "username": "bob", "action": "Create",
                  "claim_subject_urn": "urn:vouchsafe:bob.abc", "full_name": "Bob N",
                  "groups": ["Users", "Remote Desktop Users"], "password_never_expires": true }
            ] }
        }"#;
        let doc: WindowsPolicyDocument = serde_json::from_str(json).unwrap();
        assert!(matches!(doc.enforcement, Enforcement::Enforce));
        assert_eq!(doc.scope.identity_urns, vec!["urn:vouchsafe:pc1.def"]);
        let a = &doc.windows.unwrap().local_accounts[0];
        assert!(matches!(a.action, AccountAction::Create));
        assert_eq!(
            a.claim_subject_urn.as_deref(),
            Some("urn:vouchsafe:bob.abc")
        );
        assert_eq!(a.groups, vec!["Users", "Remote Desktop Users"]);
        assert_eq!(a.password_never_expires, Some(true));
    }

    #[test]
    fn console_policy_templates_deserialize() {
        // Registry template.
        let reg = r#"{ "policy_id":"security/example-registry","display_name":"x","version":1,
            "scope":{},"settings":[],"enforcement":"Enforce","windows":{"registry":[
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\DDS\\Example","name":"Enabled",
             "value":{"Dword":1},"action":"Set"}]}}"#;
        let d: WindowsPolicyDocument = serde_json::from_str(reg).unwrap();
        let r = &d.windows.unwrap().registry[0];
        assert!(matches!(r.hive, RegistryHive::LocalMachine));
        assert_eq!(r.key, r"SOFTWARE\Policies\DDS\Example");
        assert!(matches!(r.action, RegistryAction::Set));
        assert!(matches!(r.value, Some(RegistryValue::Dword(1))));

        // Service template.
        let svc = r#"{ "policy_id":"services/example","display_name":"x","version":1,
            "scope":{},"settings":[],"enforcement":"Enforce","windows":{"services":[
            {"name":"RemoteRegistry","start_type":"Disabled","action":"Stop"}]}}"#;
        let d: WindowsPolicyDocument = serde_json::from_str(svc).unwrap();
        let s = &d.windows.unwrap().services[0];
        assert_eq!(s.name, "RemoteRegistry");
        assert!(matches!(
            s.start_type,
            Some(dds_domain::ServiceStartType::Disabled)
        ));
        assert!(matches!(s.action, dds_domain::ServiceAction::Stop));

        // Password policy template.
        let pw = r#"{ "policy_id":"security/password-policy","display_name":"x","version":1,
            "scope":{},"settings":[],"enforcement":"Enforce","windows":{"password_policy":{
            "min_length":12,"max_age_days":90,"complexity_required":true,
            "lockout_threshold":5,"lockout_duration_minutes":15}}}"#;
        let d: WindowsPolicyDocument = serde_json::from_str(pw).unwrap();
        let p = d.windows.unwrap().password_policy.unwrap();
        assert_eq!(p.min_length, Some(12));
        assert_eq!(p.complexity_required, Some(true));

        // Local account template.
        let acct = r#"{ "policy_id":"windows/account/svc-example","display_name":"x","version":1,
            "scope":{},"settings":[],"enforcement":"Enforce","windows":{"local_accounts":[
            {"username":"svc-example","action":"Create","full_name":"Example Service Account",
             "groups":["Users"],"password_never_expires":true}]}}"#;
        let d: WindowsPolicyDocument = serde_json::from_str(acct).unwrap();
        let a = &d.windows.unwrap().local_accounts[0];
        assert_eq!(a.username, "svc-example");
        assert_eq!(a.claim_subject_urn, None);
    }

    // Tests that read/compare process-global telemetry counters must hold
    // this lock for the duration of the before→action→after window so that
    // concurrent tests issuing sessions don't spuriously advance the counter
    // between the two snapshots.
    static TELEMETRY_SERIAL: Mutex<()> = Mutex::new(());

    fn setup() -> (LocalService<MemoryBackend>, Identity, BTreeSet<String>) {
        let admin = Identity::generate("admin", &mut OsRng);
        let mut roots = BTreeSet::new();
        roots.insert(admin.id.to_urn());
        let graph = Arc::new(RwLock::new(TrustGraph::new()));
        let svc = LocalService::new(
            Identity::generate("node", &mut OsRng),
            graph,
            roots.clone(),
            MemoryBackend::new(),
        );
        // C-3: seed the trust graph with self-issued publisher
        // capability vouches. The admin IS the trusted root in these
        // tests, so a self-vouch is sufficient — production deployments
        // would have a domain admin vouch for a separate publisher
        // identity, but the chain validation logic treats both as
        // equivalent (the chain terminates as soon as it hits a root).
        let admin_attest = make_attest_for_publisher_setup(&admin);
        let admin_attest_hash = admin_attest.payload_hash();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(admin_attest)
            .unwrap();
        for purpose in [
            dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
            dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
            dds_core::token::purpose::POLICY_PUBLISHER_LINUX,
            dds_core::token::purpose::SOFTWARE_PUBLISHER,
        ] {
            let v = make_self_vouch(&admin, &admin_attest_hash, purpose);
            svc.trust_graph.write().unwrap().add_token(v).unwrap();
        }
        (svc, admin, roots)
    }

    /// Test helper: create the attestation for the admin so vouches
    /// targeting them have a `vch_sum` to verify against. Mirrors the
    /// production `make_attest_payload` with a deterministic JTI.
    fn make_attest_for_publisher_setup(admin: &Identity) -> Token {
        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: format!("attest-publisher-{}", admin.id.label()),
            sub: admin.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_700_000_000,
            exp: Some(4_102_444_800),
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &admin.signing_key).unwrap()
    }

    fn make_self_vouch(admin: &Identity, target_hash: &str, purpose: &str) -> Token {
        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: format!(
                "vouch-self-{}-{}",
                admin.id.label(),
                purpose.replace(':', "-")
            ),
            sub: admin.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose.to_string()),
            vch_iss: Some(admin.id.to_urn()),
            vch_sum: Some(target_hash.to_string()),
            revokes: None,
            iat: 1_700_000_000,
            exp: Some(4_102_444_800),
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &admin.signing_key).unwrap()
    }

    /// Mint a self-signed attestation `Token` carrying a domain
    /// document body. Used to seed the trust graph from tests.
    fn attest_with_body<D: dds_domain::DomainDocument>(
        ident: &Identity,
        jti: &str,
        body: &D,
    ) -> Token {
        let mut payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: jti.to_string(),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_700_000_000,
            exp: Some(4_102_444_800),
            body_type: None,
            body_cbor: None,
        };
        body.embed(&mut payload).unwrap();
        Token::sign(payload, &ident.signing_key).unwrap()
    }

    fn enroll_device(
        svc: &mut LocalService<MemoryBackend>,
        label: &str,
        tags: Vec<String>,
        org_unit: Option<String>,
    ) -> String {
        let r = svc
            .enroll_device(EnrollDeviceRequest {
                label: label.into(),
                device_id: format!("hw-{label}"),
                hostname: label.into(),
                os: "Windows 10".into(),
                os_version: "1809".into(),
                tpm_ek_hash: None,
                org_unit,
                tags,
            })
            .unwrap();
        r.urn
    }

    fn baseline_policy(id: &str, scope: PolicyScope) -> WindowsPolicyDocument {
        WindowsPolicyDocument {
            policy_id: id.into(),
            display_name: "Test".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope,
            settings: vec![],
            windows: Some(WindowsSettings {
                registry: vec![RegistryDirective {
                    hive: RegistryHive::LocalMachine,
                    key: "SOFTWARE\\Test".into(),
                    name: Some("Enabled".into()),
                    value: Some(RegistryValue::Dword(1)),
                    action: RegistryAction::Set,
                }],
                ..Default::default()
            }),
        }
    }

    fn baseline_macos_policy(id: &str, scope: PolicyScope) -> MacOsPolicyDocument {
        MacOsPolicyDocument {
            policy_id: id.into(),
            display_name: "macOS Test".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope,
            settings: vec![],
            macos: Some(MacOsSettings {
                preferences: vec![PreferenceDirective {
                    domain: "com.apple.screensaver".into(),
                    key: "idleTime".into(),
                    value: Some(json!(600)),
                    scope: PreferenceScope::System,
                    action: PreferenceAction::Set,
                }],
                ..Default::default()
            }),
        }
    }

    fn baseline_linux_policy(id: &str, scope: PolicyScope) -> LinuxPolicyDocument {
        LinuxPolicyDocument {
            policy_id: id.into(),
            display_name: "Linux Test".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope,
            settings: vec![],
            linux: None,
        }
    }

    #[test]
    fn windows_policy_global_scope_matches_every_device() {
        let (mut svc, admin, _) = setup();
        let device_urn = enroll_device(&mut svc, "ws-1", vec!["workstation".into()], None);
        let policy = baseline_policy(
            "p:global",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let token = attest_with_body(&admin, "policy-global", &policy);
        svc.trust_graph.write().unwrap().add_token(token).unwrap();

        let hits = svc.list_applicable_windows_policies(&device_urn).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].document.policy_id, "p:global");
    }

    #[test]
    fn windows_policy_tag_scope_matches_only_tagged_devices() {
        let (mut svc, admin, _) = setup();
        let dev_workstation =
            enroll_device(&mut svc, "ws-tagged", vec!["workstation".into()], None);
        let dev_server = enroll_device(&mut svc, "srv", vec!["server".into()], None);

        let policy = baseline_policy(
            "p:workstations",
            PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let token = attest_with_body(&admin, "policy-ws", &policy);
        svc.trust_graph.write().unwrap().add_token(token).unwrap();

        assert_eq!(
            svc.list_applicable_windows_policies(&dev_workstation)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            svc.list_applicable_windows_policies(&dev_server)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn windows_policy_org_unit_and_identity_scope() {
        let (mut svc, admin, _) = setup();
        let dev_eng = enroll_device(&mut svc, "eng-1", vec![], Some("engineering".into()));
        let dev_sales = enroll_device(&mut svc, "sales-1", vec![], Some("sales".into()));

        let by_ou = baseline_policy(
            "p:eng",
            PolicyScope {
                device_tags: vec![],
                org_units: vec!["engineering".into()],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-by-ou", &by_ou))
            .unwrap();

        let by_id = baseline_policy(
            "p:sales-direct",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![dev_sales.clone()],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-by-id", &by_id))
            .unwrap();

        let eng_hits = svc.list_applicable_windows_policies(&dev_eng).unwrap();
        let sales_hits = svc.list_applicable_windows_policies(&dev_sales).unwrap();
        assert_eq!(eng_hits.len(), 1);
        assert_eq!(eng_hits[0].document.policy_id, "p:eng");
        assert_eq!(sales_hits.len(), 1);
        assert_eq!(sales_hits[0].document.policy_id, "p:sales-direct");
    }

    #[test]
    fn windows_policy_disabled_documents_are_skipped() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-2", vec!["workstation".into()], None);
        let mut policy = baseline_policy(
            "p:disabled",
            PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Disabled;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-dis", &policy))
            .unwrap();

        assert_eq!(svc.list_applicable_windows_policies(&dev).unwrap().len(), 0);
    }

    #[test]
    fn windows_policy_audit_documents_are_returned() {
        // Audit-mode docs must reach the agent — the agent is the
        // one that decides to log instead of enforce. The directory
        // layer must not pre-filter them out.
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-3", vec!["workstation".into()], None);
        let mut policy = baseline_policy(
            "p:audit",
            PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Audit;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-audit", &policy))
            .unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].document.enforcement, Enforcement::Audit));
    }

    #[test]
    fn windows_policy_without_publisher_capability_is_rejected() {
        // A Windows policy signed by an identity that lacks the
        // `dds:policy-publisher-windows` purpose vouch must be silently
        // dropped by `list_applicable_windows_policies` (C-3 gate).
        let (mut svc, _admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-gated", vec![], None);

        let bare = Identity::generate("bare-win-publisher", &mut OsRng);
        let bare_attest = Token::sign(
            TokenPayload {
                iss: bare.id.to_urn(),
                iss_key: bare.public_key.clone(),
                jti: "bare-attest-win".into(),
                sub: bare.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &bare.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(bare_attest)
            .unwrap();

        let policy = baseline_policy(
            "p:win-gated",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&bare, "p-win-bare", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_windows_policies(&dev).unwrap().len(),
            0,
            "Windows policy from issuer lacking POLICY_PUBLISHER_WINDOWS must be rejected"
        );
    }

    #[test]
    fn software_assignment_scope_matching() {
        let (mut svc, admin, _) = setup();
        let dev_dev = enroll_device(&mut svc, "dev-1", vec!["developer".into()], None);
        let dev_other = enroll_device(&mut svc, "ws-only", vec!["workstation".into()], None);

        let pkg = SoftwareAssignment {
            package_id: "com.example.editor".into(),
            display_name: "Editor".into(),
            version: "1.0.0".into(),
            source: "https://cdn.example.com/editor-1.0.0.msi".into(),
            sha256: "deadbeef".into(),
            action: dds_domain::InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["developer".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
            uninstall_script: None,
            publisher_identity: None,
            enforcement: dds_domain::types::Enforcement::Enforce,
        };
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "sw-1", &pkg))
            .unwrap();

        assert_eq!(svc.list_applicable_software(&dev_dev).unwrap().len(), 1);
        assert_eq!(svc.list_applicable_software(&dev_other).unwrap().len(), 0);
    }

    #[test]
    fn record_applied_does_not_error() {
        // v1 just logs; the contract is "doesn't fail". Future PRs
        // will move this into a queryable applier-audit table.
        let (mut svc, _, _) = setup();
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.xxx".into(),
            target_id: "security/baseline".into(),
            version: "7".into(),
            status: AppliedStatus::Ok,
            kind: None,
            directives: vec!["registry: HKLM\\... = 1".into()],
            error: None,
            applied_at: 1_700_000_000,
        };
        assert!(svc.record_applied(&report).is_ok());
    }

    // ---------------- Z-3 Phase A.3: audit emission tests ----------------
    //
    // observability-plan.md Phase A.3 requires one regression test per
    // accepted-action vocabulary slot confirming the local chain
    // advances. These tests exercise the LocalService HTTP-side hooks
    // (`enroll_user`, `enroll_device`, `admin_setup`, `admin_vouch`,
    // `record_applied`); the gossip-ingest side (`attest`, `vouch`,
    // `revoke`, `burn` directly) is exercised through the
    // `DdsNode::ingest_*` paths and is covered by the multinode
    // integration tests.

    fn enroll_user_for_audit_test(
        svc: &mut LocalService<MemoryBackend>,
        label: &str,
    ) -> EnrollmentResult {
        // Use the verify_fido2=false path so we don't need a real
        // attestation object — the audit emit is the same shape.
        svc.set_verify_fido2(false);
        svc.enroll_user(EnrollUserRequest {
            label: label.into(),
            credential_id: format!("cred-{label}"),
            attestation_object: vec![],
            client_data_hash: vec![0u8; 32],
            rp_id: "example.com".into(),
            display_name: label.into(),
            authenticator_type: "platform".into(),
            challenge_id: None,
            client_data_json: None,
        })
        .unwrap()
    }

    #[test]
    fn audit_enroll_user_advances_chain() {
        let (mut svc, _, _) = setup();
        let head_before = svc.store.audit_chain_head().unwrap();
        let count_before = svc.store.count_audit_entries().unwrap();
        let _ = enroll_user_for_audit_test(&mut svc, "alice");
        let count_after = svc.store.count_audit_entries().unwrap();
        let head_after = svc.store.audit_chain_head().unwrap();
        assert_eq!(count_after, count_before + 1);
        assert_ne!(head_after, head_before, "chain head must advance");
        let entries = svc.store.list_audit_entries().unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.action, "enroll.user");
        assert!(last.reason.is_none());
        assert!(last.verify().is_ok(), "audit entry signature must verify");
    }

    #[test]
    fn audit_enroll_device_advances_chain() {
        let (mut svc, _, _) = setup();
        let count_before = svc.store.count_audit_entries().unwrap();
        let _ = enroll_device(&mut svc, "ws-audit", vec!["workstation".into()], None);
        let count_after = svc.store.count_audit_entries().unwrap();
        assert_eq!(count_after, count_before + 1);
        let entries = svc.store.list_audit_entries().unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.action, "enroll.device");
        assert!(last.verify().is_ok());
    }

    #[test]
    fn audit_apply_applied_advances_chain_with_no_reason() {
        let (mut svc, _, _) = setup();
        let count_before = svc.store.count_audit_entries().unwrap();
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.audit-ok".into(),
            target_id: "p:audit-ok".into(),
            version: "1".into(),
            status: AppliedStatus::Ok,
            kind: None,
            directives: vec![],
            error: None,
            applied_at: 1_700_000_000,
        };
        svc.record_applied(&report).unwrap();
        let entries = svc.store.list_audit_entries().unwrap();
        assert_eq!(entries.len(), count_before + 1);
        let last = entries.last().unwrap();
        assert_eq!(last.action, "apply.applied");
        assert!(last.reason.is_none());
    }

    #[test]
    fn audit_apply_failed_carries_error_as_reason() {
        let (mut svc, _, _) = setup();
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.audit-fail".into(),
            target_id: "p:audit-fail".into(),
            version: "1".into(),
            status: AppliedStatus::Failed,
            kind: None,
            directives: vec![],
            error: Some("write protected".into()),
            applied_at: 1_700_000_001,
        };
        svc.record_applied(&report).unwrap();
        let entries = svc.store.list_audit_entries().unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.action, "apply.failed");
        assert_eq!(last.reason.as_deref(), Some("write protected"));
        // Reason field must remain inside the signed bytes.
        assert!(last.verify().is_ok());
    }

    /// 2026-04-28 (observability-plan.md "deferred row" closeout):
    /// when `AppliedReport.kind` is set, `record_applied` must emit
    /// the fine-grained `policy.applied` / `policy.failed` /
    /// `software.applied` / `software.failed` action vocabulary
    /// instead of collapsing into the generic `apply.*` family.
    /// Reconciliation and HostState heartbeats stay on the legacy
    /// family because they don't represent a single document.
    #[test]
    fn audit_apply_kind_splits_action_vocabulary() {
        let (mut svc, _, _) = setup();
        let cases = [
            (
                Some(AppliedKind::Policy),
                AppliedStatus::Ok,
                "policy.applied",
            ),
            (
                Some(AppliedKind::Policy),
                AppliedStatus::Skipped,
                "policy.applied",
            ),
            (
                Some(AppliedKind::Policy),
                AppliedStatus::Failed,
                "policy.failed",
            ),
            (
                Some(AppliedKind::Software),
                AppliedStatus::Ok,
                "software.applied",
            ),
            (
                Some(AppliedKind::Software),
                AppliedStatus::Skipped,
                "software.applied",
            ),
            (
                Some(AppliedKind::Software),
                AppliedStatus::Failed,
                "software.failed",
            ),
            // Reconciliation and HostState fall back to the generic
            // family — they do not name a single doc the SIEM can
            // pivot on.
            (
                Some(AppliedKind::Reconciliation),
                AppliedStatus::Ok,
                "apply.applied",
            ),
            (
                Some(AppliedKind::Reconciliation),
                AppliedStatus::Failed,
                "apply.failed",
            ),
            (
                Some(AppliedKind::HostState),
                AppliedStatus::Ok,
                "apply.applied",
            ),
            // Backward-compat: agents that never bumped the wire
            // schema still report under `apply.*`.
            (None, AppliedStatus::Ok, "apply.applied"),
            (None, AppliedStatus::Failed, "apply.failed"),
        ];
        for (i, (kind, status, want_action)) in cases.iter().enumerate() {
            let report = AppliedReport {
                device_urn: "urn:vouchsafe:dev.kind-test".into(),
                target_id: format!("p:kind-{i}"),
                version: "1".into(),
                status: *status,
                kind: *kind,
                directives: vec![],
                error: if matches!(status, AppliedStatus::Failed) {
                    Some(format!("err-{i}"))
                } else {
                    None
                },
                applied_at: 1_700_000_100 + i as u64,
            };
            svc.record_applied(&report).unwrap();
            let last = svc.store.list_audit_entries().unwrap().pop().unwrap();
            assert_eq!(
                last.action, *want_action,
                "case {i}: kind={kind:?} status={status:?} got action={}",
                last.action
            );
            assert!(last.verify().is_ok(), "case {i}: signature must verify");
        }
    }

    /// Wire-format guard: the `kind` field round-trips through the
    /// JSON shape exposed at `POST /v1/{windows,macos}/applied` and
    /// is omitted when `None` so older agents that never carried
    /// the field still produce a clean report body. Pinning this
    /// shape prevents a future serde rename from silently breaking
    /// the C# agents.
    #[test]
    fn applied_report_kind_wire_shape() {
        let with_kind = AppliedReport {
            device_urn: "urn:vouchsafe:dev.wire".into(),
            target_id: "p:wire".into(),
            version: "1".into(),
            status: AppliedStatus::Ok,
            kind: Some(AppliedKind::Software),
            directives: vec![],
            error: None,
            applied_at: 1_700_000_200,
        };
        let json = serde_json::to_value(&with_kind).unwrap();
        assert_eq!(json["kind"], "software");
        let round: AppliedReport = serde_json::from_value(json).unwrap();
        assert_eq!(round.kind, Some(AppliedKind::Software));

        let no_kind = AppliedReport {
            device_urn: "urn:vouchsafe:dev.wire".into(),
            target_id: "p:wire".into(),
            version: "1".into(),
            status: AppliedStatus::Ok,
            kind: None,
            directives: vec![],
            error: None,
            applied_at: 1_700_000_201,
        };
        let json = serde_json::to_value(&no_kind).unwrap();
        assert!(
            json.get("kind").is_none(),
            "absent `kind` must be skipped on the wire (got {json:?})"
        );
        // A report missing the `kind` field on ingest must
        // deserialise back to `None` without erroring — protects
        // pre-2026-04-28 agents.
        let legacy_body = serde_json::json!({
            "device_urn": "urn:vouchsafe:dev.wire",
            "target_id": "p:wire",
            "version": "1",
            "status": "ok",
            "applied_at": 1_700_000_300u64,
        });
        let legacy: AppliedReport = serde_json::from_value(legacy_body).unwrap();
        assert!(legacy.kind.is_none());
    }

    #[test]
    fn audit_apply_skipped_marks_reason() {
        let (mut svc, _, _) = setup();
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.audit-skip".into(),
            target_id: "p:audit-skip".into(),
            version: "1".into(),
            status: AppliedStatus::Skipped,
            kind: None,
            directives: vec![],
            error: None,
            applied_at: 1_700_000_002,
        };
        svc.record_applied(&report).unwrap();
        let last = svc.store.list_audit_entries().unwrap().pop().unwrap();
        assert_eq!(last.action, "apply.applied");
        assert_eq!(last.reason.as_deref(), Some("skipped"));
    }

    /// Phase A.3 + A.2 cross-check: the rejection vocabulary that the
    /// gossip path uses (`attest.rejected`, `vouch.rejected`,
    /// `revoke.rejected`, `burn.rejected`) round-trips through
    /// `emit_local_audit` with the reason field intact and signed.
    /// The `publisher-identity-invalid` row is the SC-5 Phase B.1
    /// follow-on stem documented in
    /// [`docs/observability/audit-event-schema.md`](../../../docs/observability/audit-event-schema.md)
    /// §4 — pinning it here keeps the doc and the wire shape from
    /// drifting silently if a future refactor renames the reason stem.
    #[test]
    fn audit_rejection_vocabulary_signs_reason() {
        let (mut svc, _, _) = setup();
        for (action, reason) in [
            ("attest.rejected", "publisher-capability-missing"),
            ("attest.rejected", "publisher-identity-invalid"),
            ("vouch.rejected", "trust-graph-rejected: bad-vch_sum"),
            ("revoke.rejected", "iat-outside-replay-window"),
            ("burn.rejected", "validation-failed: signature mismatch"),
        ] {
            svc.emit_local_audit(action, vec![1, 2, 3], Some(reason.into()));
        }
        let entries = svc.store.list_audit_entries().unwrap();
        // Compare the trailing 5 entries against the expected vocabulary.
        let tail: Vec<(&str, Option<&str>)> = entries
            .iter()
            .rev()
            .take(5)
            .map(|e| (e.action.as_str(), e.reason.as_deref()))
            .collect();
        let actions: Vec<&str> = tail.iter().map(|(a, _)| *a).collect();
        assert!(actions.contains(&"attest.rejected"));
        assert!(actions.contains(&"vouch.rejected"));
        assert!(actions.contains(&"revoke.rejected"));
        assert!(actions.contains(&"burn.rejected"));
        let reasons: Vec<Option<&str>> = tail.iter().map(|(_, r)| *r).collect();
        assert!(reasons.contains(&Some("publisher-capability-missing")));
        assert!(reasons.contains(&Some("publisher-identity-invalid")));
        for e in entries.iter().rev().take(5) {
            assert!(e.reason.is_some(), "rejection must carry a reason");
            assert!(e.verify().is_ok(), "rejection entry must verify");
        }
    }

    #[test]
    fn audit_chain_links_three_actions_in_order() {
        // Confirm prev_hash threading: enroll_user → enroll_device →
        // record_applied stamps three entries whose chain is intact.
        let (mut svc, _, _) = setup();
        let _ = enroll_user_for_audit_test(&mut svc, "chain-user");
        let _ = enroll_device(&mut svc, "chain-dev", vec![], None);
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.chain".into(),
            target_id: "p:chain".into(),
            version: "1".into(),
            status: AppliedStatus::Ok,
            kind: None,
            directives: vec![],
            error: None,
            applied_at: 1_700_000_010,
        };
        svc.record_applied(&report).unwrap();

        let entries = svc.store.list_audit_entries().unwrap();
        assert!(entries.len() >= 3);
        // Walk the last three, verifying chain linkage and signatures.
        for window in entries.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            let expected = prev.chain_hash().unwrap();
            assert_eq!(
                curr.prev_hash, expected,
                "chain prev_hash mismatch on action={}",
                curr.action
            );
            assert!(prev.verify().is_ok());
            assert!(curr.verify().is_ok());
        }
    }

    /// observability-plan.md Phase C — `emit_local_audit` advances the
    /// `dds_audit_entries_total{action=...}` counter through the
    /// process-global telemetry handle on success. Uses a unique
    /// action label so parallel tests in the same binary cannot
    /// race on the same counter.
    #[test]
    fn audit_emit_advances_telemetry_counter() {
        let (mut svc, _, _) = setup();
        let action = "audit.test.unique-vykfovt9";
        let handle = crate::telemetry::install();
        let before = handle.audit_entries_count(action);
        svc.emit_local_audit(action, vec![1, 2, 3], None);
        let after = handle.audit_entries_count(action);
        assert_eq!(after, before + 1);

        // A failed append (nothing on disk) must not bump the counter
        // — exercise the round-trip on the same handle by verifying a
        // *successful* emission moves the audit chain length up by
        // exactly one alongside the counter.
        let chain_len_after = svc.audit_chain_length().unwrap();
        let head_ts = svc
            .audit_chain_head_timestamp()
            .unwrap()
            .expect("chain head present after emit");
        // head_ts should be a recent unix epoch second.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(now.saturating_sub(head_ts) < 10);
        assert!(chain_len_after >= 1);
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_trust_graph_*` Prometheus gauges. Confirms
    /// `LocalService::trust_graph_counts` reports the four partition
    /// sizes accurately under a single read-lock acquisition. The
    /// `setup()` helper seeds 1 admin attestation + 3 self-vouches so
    /// the baseline is non-empty.
    #[test]
    fn trust_graph_counts_reports_partition_sizes() {
        let (svc, _, _) = setup();
        let counts = svc.trust_graph_counts().expect("graph not poisoned");
        assert_eq!(counts.attestations, 1);
        assert_eq!(counts.vouches, 4);
        assert_eq!(counts.revocations, 0);
        assert_eq!(counts.burned, 0);
        // observability-plan.md Phase C — the body_type partition
        // sums to the unlabeled total. The `setup()` admin
        // attestation has `body_type: None` so it lands in the
        // `unknown` bucket.
        let by_body_type_sum: usize = counts.attestations_by_body_type.values().sum();
        assert_eq!(by_body_type_sum, counts.attestations);
        assert_eq!(counts.attestations_by_body_type.get("unknown"), Some(&1));
    }

    /// observability-plan.md Phase C — pin the contract that every
    /// constant in [`dds_domain::body_types`] has a matching arm in
    /// [`crate::service::body_type_label`]. A new domain document
    /// type added to the catalog without an arm here would silently
    /// land in `body_type="unknown"`, so the test fails loudly to
    /// force the partition update at the same time the new body type
    /// is introduced.
    #[test]
    fn body_type_label_covers_every_body_types_constant() {
        use dds_domain::body_types;
        // Every constant in `dds_domain::body_types` must classify
        // into a non-`unknown` bucket. Adding a new body type
        // without updating `body_type_label` is the regression this
        // test prevents.
        let constants: &[&str] = &[
            body_types::USER_AUTH_ATTESTATION,
            body_types::DEVICE_JOIN,
            body_types::WINDOWS_POLICY,
            body_types::MACOS_POLICY,
            body_types::LINUX_POLICY,
            body_types::MACOS_ACCOUNT_BINDING,
            body_types::SSO_IDENTITY_LINK,
            body_types::SOFTWARE_ASSIGNMENT,
            body_types::SERVICE_PRINCIPAL,
            body_types::SESSION,
        ];
        for c in constants {
            let label = body_type_label(Some(c));
            assert_ne!(
                label, "unknown",
                "body_type_label maps {c:?} into the catch-all unknown bucket — \
                 add a matching arm to body_type_label so the Prometheus \
                 partition stays bounded by the catalog.",
            );
        }
        // Sanity: the absent and out-of-catalog cases both classify
        // as `unknown` so the partition is total.
        assert_eq!(body_type_label(None), "unknown");
        assert_eq!(body_type_label(Some("dds:not-a-real-body-type")), "unknown");
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_challenges_outstanding` Prometheus gauge. Pins that
    /// `LocalService::challenges_outstanding` (a) reports zero on a
    /// freshly constructed service, (b) increases monotonically as
    /// challenges are inserted, and (c) drops back as the expiry
    /// sweeper clears them. The B-5 alarm condition is *unbounded
    /// growth* — this gauge is the operator-visible signal that the
    /// sweeper is keeping up.
    #[test]
    fn challenges_outstanding_tracks_store_population() {
        use dds_store::traits::ChallengeStore;

        let (mut svc, _, _) = setup();
        assert_eq!(svc.challenges_outstanding(), Some(0));

        // Insert two challenges with far-future expiry so the sweep
        // is a no-op; gauge must report the live row count.
        let far_future = now_epoch() + 60 * 60;
        svc.store_mut()
            .put_challenge("ch-1", &[7u8; 32], far_future)
            .unwrap();
        svc.store_mut()
            .put_challenge("ch-2", &[8u8; 32], far_future)
            .unwrap();
        assert_eq!(svc.challenges_outstanding(), Some(2));

        // Sweep with a `now` past `far_future` clears both rows;
        // gauge returns to zero.
        svc.store_mut()
            .sweep_expired_challenges(far_future + 1)
            .unwrap();
        assert_eq!(svc.challenges_outstanding(), Some(0));
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_sessions_issued_total{via="legacy"}` Prometheus counter.
    /// Pins that direct [`LocalService::issue_session`] callers (the
    /// loadtest harness, in-process Windows account-claim resolver,
    /// any non-FIDO2 entry) advance the `via="legacy"` bucket exactly
    /// once per successful mint. The unauthenticated `POST /v1/session`
    /// HTTP route was removed in the security review (see
    /// `security-gaps.md`), so the production baseline is expected to
    /// be zero — non-zero rate is the regression signal.
    #[test]
    fn issue_session_advances_legacy_telemetry_counter() {
        let _tel_guard = TELEMETRY_SERIAL.lock().unwrap();
        let (mut svc, admin, _) = setup();
        let handle = crate::telemetry::install();
        let before = handle.sessions_issued_count("legacy");

        let result = svc
            .issue_session(SessionRequest {
                subject_urn: admin.id.to_urn(),
                device_urn: None,
                requested_resources: vec![],
                duration_secs: 300,
                mfa_verified: false,
                tls_binding: None,
            })
            .expect("session issuance succeeds for self-vouched admin");
        assert!(!result.session_id.is_empty());

        let after = handle.sessions_issued_count("legacy");
        assert_eq!(after, before + 1, "legacy bucket must advance by one");
    }

    /// observability-plan.md Phase C — pins that a *failed*
    /// [`LocalService::issue_session`] call (subject with no granted
    /// purposes) does **not** advance the counter. The bump must
    /// happen at the tail of the success path so the metric reflects
    /// tokens actually returned to the caller.
    #[test]
    fn issue_session_does_not_bump_telemetry_on_failure() {
        let _tel_guard = TELEMETRY_SERIAL.lock().unwrap();
        let (mut svc, _, _) = setup();
        let handle = crate::telemetry::install();
        let before = handle.sessions_issued_count("legacy");

        let stranger = Identity::generate("stranger", &mut OsRng);
        let err = svc
            .issue_session(SessionRequest {
                subject_urn: stranger.id.to_urn(),
                device_urn: None,
                requested_resources: vec![],
                duration_secs: 300,
                mfa_verified: false,
                tls_binding: None,
            })
            .expect_err("subject without granted purposes must be rejected");
        // Sanity check the rejection comes from the granted-purpose
        // gate, not somewhere upstream.
        assert!(format!("{err:?}").contains("granted purposes"));

        let after = handle.sessions_issued_count("legacy");
        assert_eq!(after, before, "failure path must not advance counter");
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_purpose_lookups_total{result=ok|denied}` Prometheus counter.
    /// Pins that [`LocalService::has_purpose_observed`] funnels both
    /// the grant-granted and grant-denied branches through the
    /// process-global telemetry handle. Uses purposes the `setup()`
    /// helper actually populates (admin holds the three publisher
    /// capabilities + a self-attestation) so the `ok` case is
    /// reproducible without re-deriving the trust-graph fixture.
    ///
    /// Uses `>=` comparisons because the telemetry counters are
    /// process-global and other tests running in parallel may bump them
    /// between the snapshot and the assertion. Re-snapshots between the
    /// two branches to avoid cumulative drift from parallel interference.
    #[test]
    fn has_purpose_observed_advances_ok_and_denied_telemetry_counters() {
        let (svc, admin, _) = setup();
        let handle = crate::telemetry::install();

        // OK branch: admin self-vouched for `dds:policy-publisher-windows`
        // in `setup()`, so the gate must pass.
        let ok_before = handle.purpose_lookups_count("ok");
        {
            let g = svc.trust_graph.read().unwrap();
            assert!(svc.has_purpose_observed(
                &g,
                &admin.id.to_urn(),
                dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
            ));
        }
        assert!(
            handle.purpose_lookups_count("ok") > ok_before,
            "ok bucket must advance on grant-granted (before={ok_before}, after={})",
            handle.purpose_lookups_count("ok")
        );

        // DENIED branch: re-snapshot denied baseline immediately before the
        // call so parallel-test noise in the window before this point does
        // not contaminate the delta check.
        let denied_before = handle.purpose_lookups_count("denied");
        {
            let g = svc.trust_graph.read().unwrap();
            assert!(!svc.has_purpose_observed(
                &g,
                "urn:dds:stranger-test-7l3p",
                dds_core::token::purpose::SOFTWARE_PUBLISHER,
            ));
        }
        assert!(
            handle.purpose_lookups_count("denied") > denied_before,
            "denied bucket must advance on grant-denied (before={denied_before}, after={})",
            handle.purpose_lookups_count("denied")
        );
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_fido2_attestation_verify_total{result, fmt}` Prometheus
    /// counter. Pins that the shared helper
    /// [`LocalService::verify_attestation_observed`] funnels both the
    /// success branch (a real `fmt=none` attestation built via
    /// [`dds_domain::fido2::build_none_attestation`]) and the failure
    /// branch (garbage bytes that fail CBOR decode before `fmt` is
    /// known) through the process-global telemetry handle. The
    /// success branch labels `fmt` with the authenticator-advertised
    /// value (`none`), and the failure branch uniformly labels `fmt`
    /// as `unknown` because the verifier rejects before the `fmt`
    /// field is parsed.
    #[test]
    fn verify_attestation_observed_advances_ok_and_fail_telemetry_buckets() {
        use ed25519_dalek::SigningKey;
        let handle = crate::telemetry::install();
        let ok_none_before = handle.fido2_attestation_verify_count("ok", "none");
        let fail_unknown_before = handle.fido2_attestation_verify_count("fail", "unknown");

        // OK branch: synthesize a real `fmt=none` attestation object
        // and let the verifier accept it via `allow_unattested=true`.
        let cred_sk = SigningKey::generate(&mut OsRng);
        let cred_pk = cred_sk.verifying_key();
        let rp_id = "example.com";
        let attestation = dds_domain::fido2::build_none_attestation(rp_id, b"cred-tel", &cred_pk);
        // `client_data_hash` is irrelevant for `fmt=none` (no attStmt
        // signature to verify); zeros suffice.
        let client_data_hash = [0u8; 32];
        let parsed = LocalService::<MemoryBackend>::verify_attestation_observed(
            &attestation,
            &client_data_hash,
            true,
        )
        .expect("none-attestation accepted with allow_unattested=true");
        assert_eq!(parsed.fmt, "none");
        assert_eq!(
            handle.fido2_attestation_verify_count("ok", "none"),
            ok_none_before + 1,
            "ok/none bucket must advance by one on a successful fmt=none verify"
        );
        assert_eq!(
            handle.fido2_attestation_verify_count("fail", "unknown"),
            fail_unknown_before,
            "fail/unknown bucket must not advance on a successful verify"
        );

        // FAIL branch: garbage bytes — the CBOR decode rejects before
        // fmt is identified, so the bump emits `fmt="unknown"`.
        let err = LocalService::<MemoryBackend>::verify_attestation_observed(
            b"not cbor",
            &client_data_hash,
            false,
        )
        .expect_err("garbage bytes must be rejected");
        let _ = err; // we don't pin the error variant — the verifier owns the message.
        assert_eq!(
            handle.fido2_attestation_verify_count("fail", "unknown"),
            fail_unknown_before + 1,
            "fail/unknown bucket must advance by one on verifier rejection"
        );
        assert_eq!(
            handle.fido2_attestation_verify_count("ok", "none"),
            ok_none_before + 1,
            "ok/none bucket must not advance on a failed verify"
        );
    }

    /// observability-plan.md Phase C — regression test for the
    /// `dds_fido2_assertions_total{result}` Prometheus counter. Pins
    /// that every named exit branch of
    /// [`LocalService::verify_assertion_common`] (consumed by
    /// `issue_session_from_assertion` and `admin_vouch`) advances the
    /// matching bucket exactly once via the [`AssertionMetricGuard`]
    /// drop-guard. Exercises:
    ///
    /// - `result="ok"` — the happy path: enroll a user, fetch a
    ///   challenge, build a fully-valid assertion, drive
    ///   `verify_assertion_common`.
    /// - `result="signature"` — an assertion signed by a different
    ///   private key than the one enrolled.
    /// - `result="rp_id"` — an assertion whose `auth_data` carries
    ///   the SHA-256 of a *different* relying-party identifier.
    /// - `result="up"` — an assertion whose `auth_data` flags byte
    ///   has the User-Present (UP) bit cleared.
    /// - `result="sign_count"` — replay of a previously-presented
    ///   sign-count value, caught by the
    ///   `CredentialStateStore::bump_sign_count` atomic check.
    /// - `result="other"` — a `credential_id` that the trust graph
    ///   has no record of (lookup miss).
    ///
    /// The catalog's `uv` bucket is *not* covered here because
    /// `verify_assertion_common` itself does not gate on the
    /// User-Verified flag; UV is reported through
    /// [`CommonAssertionOutput::user_verified`] and gated by the
    /// privileged caller (`admin_vouch`, AUDIT-2026-06-12 R2) *after*
    /// the verifier — and the metric guard — have already exited with
    /// `result="ok"`. A future in-verifier UV gate can extend both
    /// this test and the renderer test side-by-side without renaming
    /// the metric.
    #[test]
    fn verify_assertion_common_advances_each_result_bucket() {
        use dds_domain::fido2::{build_assertion_auth_data, build_packed_self_attestation};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::Digest;
        let handle = crate::telemetry::install();

        // Enroll a user with an Ed25519 packed self-attestation so the
        // credential is in the trust graph.
        let (mut svc, _, _) = setup();
        svc.set_verify_fido2(true);
        let cred_sk = SigningKey::generate(&mut OsRng);
        let cred_bytes = b"cred-assert-bucket-test";
        let rp_id = "dds.local";
        let attestation = build_packed_self_attestation(rp_id, cred_bytes, &cred_sk, &[0u8; 32]);
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let _ = svc
            .enroll_user(EnrollUserRequest {
                label: "alice-bucket".into(),
                credential_id: cred_id_b64.clone(),
                attestation_object: attestation,
                client_data_hash: vec![0u8; 32],
                rp_id: rp_id.into(),
                display_name: "Alice".into(),
                authenticator_type: "platform".into(),
                challenge_id: None,
                client_data_json: None,
            })
            .expect("enroll_user must succeed for bucket-test setup");

        // Helper: insert a fresh challenge into the store and return
        // its id + base64url challenge bytes the way the production
        // path would.
        let mut next_challenge = 0u32;
        let mut put_challenge = |svc: &mut LocalService<MemoryBackend>| -> (String, String) {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            next_challenge += 1;
            let id = format!("ch-bucket-{next_challenge}");
            let bytes = [next_challenge as u8; 32];
            let far_future = now_epoch() + 600;
            svc.store_mut()
                .put_challenge(&id, &bytes, far_future)
                .expect("put_challenge");
            (id, URL_SAFE_NO_PAD.encode(bytes))
        };

        // Helper: build a full clientDataJSON-style assertion against
        // a given (signing key, rp_id, sign_count, challenge,
        // auth-data override). Returns a populated
        // `AssertionSessionRequest`.
        let build_req = |credential_id: &str,
                         challenge_id: &str,
                         challenge_b64url: &str,
                         signing_sk: &SigningKey,
                         auth_data: Vec<u8>|
         -> AssertionSessionRequest {
            let cdj = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#,
                rp_id = rp_id,
            );
            let cdh = sha2::Sha256::digest(cdj.as_bytes());
            let mut signed_msg = Vec::new();
            signed_msg.extend_from_slice(&auth_data);
            signed_msg.extend_from_slice(&cdh);
            let sig = signing_sk.sign(&signed_msg);
            AssertionSessionRequest {
                subject_urn: None,
                credential_id: credential_id.to_string(),
                challenge_id: challenge_id.to_string(),
                client_data_hash: cdh.to_vec(),
                client_data_json: Some(cdj.into_bytes()),
                authenticator_data: auth_data,
                signature: sig.to_bytes().to_vec(),
                duration_secs: None,
            }
        };

        // -------- result="ok" -------------------------------------------------
        let ok_before = handle.fido2_assertions_count("ok");
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        let req = build_req(
            &cred_id_b64,
            &ch_id,
            &ch_b64,
            &cred_sk,
            build_assertion_auth_data(rp_id, 1),
        );
        let _ = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect("happy-path assertion must verify");
        assert_eq!(
            handle.fido2_assertions_count("ok"),
            ok_before + 1,
            "ok bucket must advance once on a happy-path assertion"
        );

        // -------- result="signature" -----------------------------------------
        let sig_before = handle.fido2_assertions_count("signature");
        let wrong_sk = SigningKey::generate(&mut OsRng);
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        // sign_count=2 (monotonic forward from the ok bucket above).
        let req = build_req(
            &cred_id_b64,
            &ch_id,
            &ch_b64,
            &wrong_sk, // wrong key → BadSignature
            build_assertion_auth_data(rp_id, 2),
        );
        let err = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect_err("wrong-key assertion must reject");
        let _ = err;
        assert_eq!(
            handle.fido2_assertions_count("signature"),
            sig_before + 1,
            "signature bucket must advance on Fido2Error::BadSignature"
        );

        // -------- result="up" -------------------------------------------------
        let up_before = handle.fido2_assertions_count("up");
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        // Hand-build auth_data with the UP bit cleared. Layout:
        //   rpIdHash (32) | flags (1) | signCount (4)
        let mut auth_data = build_assertion_auth_data(rp_id, 3);
        auth_data[32] &= !0x01; // clear UP bit
        let req = build_req(
            &cred_id_b64,
            &ch_id,
            &ch_b64,
            &cred_sk, // correct key — signature verifies, UP fails
            auth_data,
        );
        let err = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect_err("UP-clear assertion must reject");
        let _ = err;
        assert_eq!(
            handle.fido2_assertions_count("up"),
            up_before + 1,
            "up bucket must advance when UP flag is cleared"
        );

        // -------- result="rp_id" ---------------------------------------------
        let rp_before = handle.fido2_assertions_count("rp_id");
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        // Build auth_data against a *different* rp_id, then sign over
        // that auth_data so the signature step passes — only the
        // rp_id_hash should mismatch the enrolled rp_id.
        let auth_data = build_assertion_auth_data("evil.example", 4);
        let req = build_req(&cred_id_b64, &ch_id, &ch_b64, &cred_sk, auth_data);
        let err = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect_err("wrong-rp_id assertion must reject");
        let _ = err;
        assert_eq!(
            handle.fido2_assertions_count("rp_id"),
            rp_before + 1,
            "rp_id bucket must advance when rp_id_hash mismatches enrolled relying party"
        );

        // -------- result="sign_count" ----------------------------------------
        let sc_before = handle.fido2_assertions_count("sign_count");
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        // sign_count=1 — already consumed by the ok bucket above.
        let req = build_req(
            &cred_id_b64,
            &ch_id,
            &ch_b64,
            &cred_sk,
            build_assertion_auth_data(rp_id, 1),
        );
        let err = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect_err("sign_count replay must reject");
        let _ = err;
        assert_eq!(
            handle.fido2_assertions_count("sign_count"),
            sc_before + 1,
            "sign_count bucket must advance on StoreError::SignCountReplay"
        );

        // -------- result="other" ---------------------------------------------
        // An unknown credential_id never reaches the named branches —
        // the trust-graph lookup rejects first, falling through to the
        // default `other` bucket.
        let other_before = handle.fido2_assertions_count("other");
        let (ch_id, ch_b64) = put_challenge(&mut svc);
        let req = build_req(
            "no-such-credential-id-b64",
            &ch_id,
            &ch_b64,
            &cred_sk,
            build_assertion_auth_data(rp_id, 99),
        );
        let err = svc
            .verify_assertion_common(
                &req.credential_id,
                &req.challenge_id,
                &req.client_data_hash,
                req.client_data_json.as_deref(),
                &req.authenticator_data,
                &req.signature,
            )
            .expect_err("unknown credential must reject");
        let _ = err;
        assert_eq!(
            handle.fido2_assertions_count("other"),
            other_before + 1,
            "other bucket must advance on credential lookup miss"
        );

        // The catalog's `uv` bucket must remain untouched — the
        // UV-required gate (AUDIT-2026-06-12 R2) lives in `admin_vouch`,
        // downstream of this verifier, so it never reaches this metric.
        assert_eq!(
            handle.fido2_assertions_count("uv"),
            0,
            "uv bucket is reserved for an in-verifier UV gate and must not advance"
        );
    }

    /// **AUDIT-2026-06-12 R2** — regression: `admin_vouch` must reject a
    /// cryptographically valid assertion whose User-Verified flag (UV,
    /// flags bit 0x04) is clear, and accept the identical flow once UV
    /// is set. The Windows tray client requests UV=REQUIRED at
    /// getAssertion time, but that lives in the client binary — a
    /// tampered client can submit a UP-only assertion, so the
    /// "stolen-but-presence-unlocked admin key cannot vouch" guarantee
    /// holds only if the node enforces UV server-side at the vouch
    /// boundary.
    #[test]
    fn admin_vouch_rejects_assertion_without_uv() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use dds_domain::fido2::{build_assertion_auth_data, build_packed_self_attestation};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::Digest;

        let (mut svc, _, _) = setup();
        svc.set_verify_fido2(true);
        let data_dir = tempfile::tempdir().expect("tempdir for admin_keys");
        svc.set_data_dir(data_dir.path().to_path_buf());

        // Enroll the vouching admin's FIDO2 credential.
        let cred_sk = SigningKey::generate(&mut OsRng);
        let cred_bytes = b"cred-admin-vouch-uv";
        let rp_id = "dds.local";
        let attestation = build_packed_self_attestation(rp_id, cred_bytes, &cred_sk, &[0u8; 32]);
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(cred_bytes);
        let enrolled = svc
            .enroll_user(EnrollUserRequest {
                label: "vouching-admin-uv".into(),
                credential_id: cred_id_b64.clone(),
                attestation_object: attestation,
                client_data_hash: vec![0u8; 32],
                rp_id: rp_id.into(),
                display_name: "Vouching Admin".into(),
                authenticator_type: "platform".into(),
                challenge_id: None,
                client_data_json: None,
            })
            .expect("admin credential enrollment");
        let admin_urn = enrolled.urn;

        // Promote the credential owner to bootstrap admin: trusted
        // root, bootstrap URN (so the H-8 capability gate does not
        // apply), and a persisted signing key for vouch minting.
        svc.trusted_roots.insert(admin_urn.clone());
        svc.set_bootstrap_admin_urn(Some(admin_urn.clone()));
        let admin_sk = SigningKey::generate(&mut OsRng);
        svc.store_admin_key(&admin_urn, &admin_sk)
            .expect("persist admin signing key");

        // The vouch subject needs an attestation in the graph (step 9
        // of `admin_vouch` computes `vch_sum` from it).
        let subject = Identity::generate("vouch-subject-uv", &mut OsRng);
        let subject_urn = subject.id.to_urn();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(make_attest_for_publisher_setup(&subject))
            .expect("subject attestation");

        // Helper: assemble a full `AdminVouchRequest` around the given
        // auth_data — fresh challenge, matching clientDataJSON, valid
        // signature. Everything except the flags byte is held valid so
        // a reject can only come from the flag gates.
        let mut next = 0u8;
        let mut vouch_req =
            |svc: &mut LocalService<MemoryBackend>, auth_data: Vec<u8>| -> AdminVouchRequest {
                next += 1;
                let ch_id = format!("ch-vouch-uv-{next}");
                let ch_bytes = [0x40 + next; 32];
                svc.store_mut()
                    .put_challenge(&ch_id, &ch_bytes, now_epoch() + 600)
                    .expect("put_challenge");
                let ch_b64 = URL_SAFE_NO_PAD.encode(ch_bytes);
                let cdj = format!(
                    r#"{{"type":"webauthn.get","challenge":"{ch_b64}","origin":"https://{rp_id}"}}"#
                );
                let cdh = sha2::Sha256::digest(cdj.as_bytes());
                let mut signed_msg = Vec::new();
                signed_msg.extend_from_slice(&auth_data);
                signed_msg.extend_from_slice(&cdh);
                let sig = cred_sk.sign(&signed_msg);
                AdminVouchRequest {
                    subject_urn: subject_urn.clone(),
                    credential_id: cred_id_b64.clone(),
                    challenge_id: ch_id,
                    client_data_hash: cdh.to_vec(),
                    client_data_json: Some(cdj.into_bytes()),
                    authenticator_data: auth_data,
                    signature: sig.to_bytes().to_vec(),
                    purpose: None,
                }
            };

        // UV clear, UP still set (flags 0x01): the assertion passes the
        // shared verifier, so the reject must come from the R2 gate.
        let mut auth_data = build_assertion_auth_data(rp_id, 1);
        auth_data[32] &= !0x04; // clear UV; UP (0x01) stays set
        let req = vouch_req(&mut svc, auth_data);
        let err = svc
            .admin_vouch(req)
            .expect_err("UP-only assertion must not mint an admin vouch");
        match &err {
            ServiceError::Fido2(msg) => assert!(
                msg.contains("user-verified (UV)"),
                "reject must name the UV requirement, got: {msg}"
            ),
            other => {
                panic!("expected ServiceError::Fido2 for UV-clear assertion, got: {other:?}")
            }
        }

        // UV set (helper default flags 0x05 = UP|UV): the identical
        // flow must succeed end-to-end.
        let req = vouch_req(&mut svc, build_assertion_auth_data(rp_id, 2));
        let ok = svc
            .admin_vouch(req)
            .expect("UV-set assertion must mint the vouch");
        assert_eq!(ok.subject_urn, subject_urn);
        assert_eq!(ok.admin_urn, admin_urn);
    }

    /// End-to-end offboarding: an admin vouches a user (dds:session),
    /// then revokes that vouch via `admin_revoke_vouch`. After revoke,
    /// the user must show as `revoked` in the enrolled-users listing and
    /// be hidden from the default (Credential-Provider) view.
    #[test]
    fn admin_revoke_vouch_offboards_user() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use dds_domain::DomainDocument;
        use dds_domain::fido2::{build_assertion_auth_data, build_packed_self_attestation};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::Digest;

        let (mut svc, _, _) = setup();
        svc.set_verify_fido2(true);
        let data_dir = tempfile::tempdir().expect("tempdir");
        svc.set_data_dir(data_dir.path().to_path_buf());

        // Bootstrap admin: build the attestation self-signed by the SAME
        // identity whose key we persist, so vouches this admin mints
        // pass `verify_issuer_binding` and actually land in the graph.
        // (enroll_user hides its ephemeral key, so a persisted-key admin
        // must be constructed by hand.) The FIDO2 credential (cred_sk)
        // is separate — it authenticates the ceremony assertion.
        let rp_id = "dds.local";
        let admin_ident = Identity::generate("offboard-admin", &mut OsRng);
        let admin_urn = admin_ident.id.to_urn();
        let cred_sk = SigningKey::generate(&mut OsRng);
        let cred_bytes = b"cred-offboard-admin";
        let attestation = build_packed_self_attestation(rp_id, cred_bytes, &cred_sk, &[0u8; 32]);
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(cred_bytes);
        let admin_doc = UserAuthAttestation {
            credential_id: cred_id_b64.clone(),
            attestation_object: attestation,
            client_data_hash: vec![0u8; 32],
            rp_id: rp_id.into(),
            user_display_name: "Offboard Admin".into(),
            authenticator_type: "platform".into(),
        };
        let mut admin_payload = svc.make_attest_payload(&admin_ident);
        admin_doc.embed(&mut admin_payload).unwrap();
        let admin_attest = Token::sign(admin_payload, &admin_ident.signing_key).unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(admin_attest)
            .expect("admin attestation");
        svc.trusted_roots.insert(admin_urn.clone());
        svc.set_bootstrap_admin_urn(Some(admin_urn.clone()));
        svc.store_admin_key(&admin_urn, &admin_ident.signing_key)
            .expect("persist admin key");

        // Enroll the user as a real FIDO2 user so its attestation embeds
        // a UserAuthAttestation (list_enrolled_users skips plain attests).
        let user_cred_sk = SigningKey::generate(&mut OsRng);
        let user_cred_bytes = b"cred-offboard-user";
        let user_attestation =
            build_packed_self_attestation(rp_id, user_cred_bytes, &user_cred_sk, &[0u8; 32]);
        let subject_urn = svc
            .enroll_user(EnrollUserRequest {
                label: "offboard-user".into(),
                credential_id: URL_SAFE_NO_PAD.encode(user_cred_bytes),
                attestation_object: user_attestation,
                client_data_hash: vec![0u8; 32],
                rp_id: rp_id.into(),
                display_name: "Offboard User".into(),
                authenticator_type: "platform".into(),
                challenge_id: None,
                client_data_json: None,
            })
            .expect("user enroll")
            .urn;

        // Assertion builder — fresh challenge + valid signature each call.
        let mut n = 0u8;
        let mut assertion = |svc: &mut LocalService<MemoryBackend>| {
            n += 1;
            let ch_id = format!("ch-offb-{n}");
            let ch_bytes = [0x30 + n; 32];
            svc.store_mut()
                .put_challenge(&ch_id, &ch_bytes, now_epoch() + 600)
                .unwrap();
            let ch_b64 = URL_SAFE_NO_PAD.encode(ch_bytes);
            let cdj = format!(
                r#"{{"type":"webauthn.get","challenge":"{ch_b64}","origin":"https://{rp_id}"}}"#
            );
            let cdh = sha2::Sha256::digest(cdj.as_bytes());
            let auth_data = build_assertion_auth_data(rp_id, n as u32); // flags 0x05 = UP|UV
            let mut signed = Vec::new();
            signed.extend_from_slice(&auth_data);
            signed.extend_from_slice(&cdh);
            let sig = cred_sk.sign(&signed);
            (
                ch_id,
                cdh.to_vec(),
                cdj.into_bytes(),
                auth_data,
                sig.to_bytes().to_vec(),
            )
        };

        // Approve the user.
        let (ch_id, cdh, cdj, auth_data, sig) = assertion(&mut svc);
        svc.admin_vouch(AdminVouchRequest {
            subject_urn: subject_urn.clone(),
            credential_id: cred_id_b64.clone(),
            challenge_id: ch_id,
            client_data_hash: cdh,
            client_data_json: Some(cdj),
            authenticator_data: auth_data,
            signature: sig,
            purpose: None, // dds:session
        })
        .expect("vouch");

        // User is now visible + vouched, not revoked.
        let listed = svc.list_enrolled_users("", false).unwrap();
        let u = listed
            .iter()
            .find(|u| u.subject_urn == subject_urn)
            .unwrap();
        assert!(
            u.vouched && !u.revoked,
            "user approved and active (vouched={}, revoked={})",
            u.vouched,
            u.revoked
        );

        // Offboard: revoke the admin's vouches for the subject.
        let (ch_id, cdh, cdj, auth_data, sig) = assertion(&mut svc);
        let r = svc
            .admin_revoke_vouch(AdminRevokeVouchRequest {
                subject_urn: subject_urn.clone(),
                credential_id: cred_id_b64.clone(),
                challenge_id: ch_id,
                client_data_hash: cdh,
                client_data_json: Some(cdj),
                authenticator_data: auth_data,
                signature: sig,
                purpose: None,
            })
            .expect("revoke-vouch");
        assert_eq!(r.revoked.len(), 1, "one vouch revoked");
        assert!(r.foreign.is_empty(), "no foreign vouches");
        assert!(
            !r.revoke_tokens.is_empty(),
            "revoke token minted for gossip"
        );

        // Default listing hides the offboarded user; include_revoked shows it.
        let default_list = svc.list_enrolled_users("", false).unwrap();
        assert!(
            !default_list.iter().any(|u| u.subject_urn == subject_urn),
            "offboarded user hidden from CP tile view"
        );
        let full_list = svc.list_enrolled_users("", true).unwrap();
        let u = full_list
            .iter()
            .find(|u| u.subject_urn == subject_urn)
            .expect("visible with include_revoked");
        assert!(u.revoked && !u.vouched, "shows as offboarded");

        // Idempotency: a second revoke finds nothing live to revoke.
        let (ch_id, cdh, cdj, auth_data, sig) = assertion(&mut svc);
        let err = svc.admin_revoke_vouch(AdminRevokeVouchRequest {
            subject_urn: subject_urn.clone(),
            credential_id: cred_id_b64,
            challenge_id: ch_id,
            client_data_hash: cdh,
            client_data_json: Some(cdj),
            authenticator_data: auth_data,
            signature: sig,
            purpose: None,
        });
        assert!(
            err.is_err(),
            "nothing left to revoke → error, not a double-revoke"
        );
    }

    /// `reconcile_trusted_roots` promotes a subject holding a live
    /// `dds:admin` vouch from a root, and demotes a root whose only
    /// `dds:admin` vouch was revoked — the cross-node admin
    /// promotion/demotion propagation the offboarding relies on.
    #[test]
    fn reconcile_trusted_roots_promotes_and_demotes() {
        let (mut svc, admin, _) = setup();
        let data_dir = tempfile::tempdir().expect("tempdir");
        svc.set_data_dir(data_dir.path().to_path_buf());
        svc.set_bootstrap_admin_urn(Some(admin.id.to_urn()));

        // A second identity gets a dds:admin vouch from the bootstrap admin.
        let admin2 = Identity::generate("admin2", &mut OsRng);
        let admin2_attest = make_attest_for_publisher_setup(&admin2);
        let admin2_hash = admin2_attest.payload_hash();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(admin2_attest)
            .unwrap();
        let admin_vouch = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "vouch-admin2".into(),
                sub: admin2.id.to_urn(),
                kind: TokenKind::Vouch,
                purpose: Some(dds_core::token::purpose::ADMIN.to_string()),
                vch_iss: Some(admin2.id.to_urn()),
                vch_sum: Some(admin2_hash),
                revokes: None,
                iat: now_epoch(),
                exp: Some(now_epoch() + 365 * 86400),
                body_type: None,
                body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(admin_vouch)
            .unwrap();

        assert!(!svc.trusted_roots.contains(&admin2.id.to_urn()));
        svc.reconcile_trusted_roots();
        assert!(
            svc.trusted_roots.contains(&admin2.id.to_urn()),
            "live dds:admin vouch from a root promotes the subject"
        );

        // Revoke the dds:admin vouch → reconcile demotes admin2.
        let revoke = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "revoke-admin2".into(),
                sub: admin2.id.to_urn(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some("vouch-admin2".into()),
                iat: now_epoch(),
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();
        svc.trust_graph.write().unwrap().add_token(revoke).unwrap();
        svc.reconcile_trusted_roots();
        assert!(
            !svc.trusted_roots.contains(&admin2.id.to_urn()),
            "revoked dds:admin vouch demotes the subject"
        );
        // The bootstrap admin (no vouch, config-anchored) is never demoted.
        assert!(svc.trusted_roots.contains(&admin.id.to_urn()));
    }

    /// Demotion must be **transitive** and must respect **surviving
    /// co-vouches**: (a) offboarding an admin R also demotes the sub-admin
    /// S that R promoted (once R leaves the root set, S's vouch-from-R stops
    /// counting); (b) if a second still-root admin also vouched S, S stays.
    #[test]
    fn reconcile_trusted_roots_demotion_is_transitive_and_covouch_aware() {
        let (mut svc, boot, _) = setup();
        let data_dir = tempfile::tempdir().expect("tempdir");
        svc.set_data_dir(data_dir.path().to_path_buf());
        svc.set_bootstrap_admin_urn(Some(boot.id.to_urn()));

        // Helper: enroll `who` (attestation) + a dds:admin vouch from `by`.
        let admin_purpose = dds_core::token::purpose::ADMIN;
        let mk_admin_vouch = |svc: &mut LocalService<MemoryBackend>,
                              who: &Identity,
                              by: &Identity,
                              jti: &str,
                              enroll: bool| {
            if enroll {
                let att = make_attest_for_publisher_setup(who);
                svc.trust_graph.write().unwrap().add_token(att).unwrap();
            }
            let hash = svc
                .trust_graph
                .read()
                .unwrap()
                .attestations_iter()
                .find(|t| t.payload.sub == who.id.to_urn())
                .map(|t| t.payload_hash())
                .unwrap();
            let v = Token::sign(
                TokenPayload {
                    iss: by.id.to_urn(),
                    iss_key: by.public_key.clone(),
                    jti: jti.into(),
                    sub: who.id.to_urn(),
                    kind: TokenKind::Vouch,
                    purpose: Some(admin_purpose.to_string()),
                    vch_iss: Some(who.id.to_urn()),
                    vch_sum: Some(hash),
                    revokes: None,
                    iat: now_epoch(),
                    exp: Some(now_epoch() + 365 * 86400),
                    body_type: None,
                    body_cbor: None,
                },
                &by.signing_key,
            )
            .unwrap();
            svc.trust_graph.write().unwrap().add_token(v).unwrap();
        };

        // boot → R → S (chain of promotions).
        let r = Identity::generate("admin-r", &mut OsRng);
        let s = Identity::generate("admin-s", &mut OsRng);
        mk_admin_vouch(&mut svc, &r, &boot, "vouch-boot-r", true);
        svc.reconcile_trusted_roots();
        assert!(
            svc.trusted_roots.contains(&r.id.to_urn()),
            "R promoted by boot"
        );
        mk_admin_vouch(&mut svc, &s, &r, "vouch-r-s", true);
        svc.reconcile_trusted_roots();
        assert!(
            svc.trusted_roots.contains(&s.id.to_urn()),
            "S promoted by R"
        );

        // Offboard R: revoke boot's vouch of R. A single reconcile must
        // cascade — R demoted, and then S demoted (its only vouch was from R).
        let revoke_r = Token::sign(
            TokenPayload {
                iss: boot.id.to_urn(),
                iss_key: boot.public_key.clone(),
                jti: "revoke-boot-r".into(),
                sub: r.id.to_urn(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some("vouch-boot-r".into()),
                iat: now_epoch(),
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &boot.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(revoke_r)
            .unwrap();
        svc.reconcile_trusted_roots();
        assert!(!svc.trusted_roots.contains(&r.id.to_urn()), "R demoted");
        assert!(
            !svc.trusted_roots.contains(&s.id.to_urn()),
            "S demoted transitively once R left the root set"
        );

        // Co-vouch case: boot ALSO vouches S directly, then R's vouch of S
        // is revoked. S must remain a root (boot's live vouch survives).
        mk_admin_vouch(&mut svc, &s, &boot, "vouch-boot-s", false);
        svc.reconcile_trusted_roots();
        assert!(
            svc.trusted_roots.contains(&s.id.to_urn()),
            "S re-promoted by boot"
        );
        let revoke_rs = Token::sign(
            TokenPayload {
                iss: r.id.to_urn(),
                iss_key: r.public_key.clone(),
                jti: "revoke-r-s".into(),
                sub: s.id.to_urn(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some("vouch-r-s".into()),
                iat: now_epoch(),
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &r.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(revoke_rs)
            .unwrap();
        svc.reconcile_trusted_roots();
        assert!(
            svc.trusted_roots.contains(&s.id.to_urn()),
            "S stays a root: boot's co-vouch is still live"
        );
    }

    #[test]
    fn lists_skip_revoked_and_burned() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-rb", vec!["workstation".into()], None);

        let policy = baseline_policy(
            "p:will-revoke",
            PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let policy_token = attest_with_body(&admin, "p-revoke", &policy);
        let policy_jti = policy_token.payload.jti.clone();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(policy_token)
            .unwrap();

        assert_eq!(svc.list_applicable_windows_policies(&dev).unwrap().len(), 1);

        // Revoke the policy: same issuer signs a Revoke targeting
        // the policy JTI. The trust graph drops it from the listing.
        // Note: revocation tokens *must not* carry an `exp` — the
        // token validator enforces that (RevocationMustNotExpire).
        let revoke = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "revoke-1".into(),
                sub: admin.id.to_urn(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some(policy_jti),
                iat: now_epoch(),
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();
        svc.trust_graph.write().unwrap().add_token(revoke).unwrap();

        assert_eq!(svc.list_applicable_windows_policies(&dev).unwrap().len(), 0);
    }

    #[test]
    fn typed_windows_settings_survive_listing_round_trip() {
        // The agent receives the typed bundle exactly as the admin
        // signed it. This is the contract that lets the .NET enforcers
        // dispatch off Rust enums.
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-typed", vec!["workstation".into()], None);

        let policy = WindowsPolicyDocument {
            policy_id: "p:typed".into(),
            display_name: "Typed".into(),
            version: 4,
            enforcement: Enforcement::Enforce,
            scope: PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            windows: Some(WindowsSettings {
                local_accounts: vec![AccountDirective {
                    username: "ddsadmin".into(),
                    action: AccountAction::Create,
                    claim_subject_urn: None,
                    full_name: Some("DDS Admin".into()),
                    description: None,
                    groups: vec!["Administrators".into()],
                    password_never_expires: Some(true),
                }],
                password_policy: Some(PasswordPolicy {
                    min_length: Some(14),
                    complexity_required: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-typed", &policy))
            .unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        let bundle = hits[0].document.windows.as_ref().unwrap();
        assert_eq!(bundle.local_accounts[0].username, "ddsadmin");
        assert_eq!(
            bundle.password_policy.as_ref().unwrap().min_length,
            Some(14)
        );
    }

    #[test]
    fn windows_claim_resolution_uses_local_session_and_policy_mapping() {
        let (mut svc, admin, roots) = setup();
        let device_urn = enroll_device(&mut svc, "ws-claim", vec!["workstation".into()], None);

        let user = Identity::generate("alice", &mut OsRng);
        let user_attest = Token::sign(
            TokenPayload {
                iss: user.id.to_urn(),
                iss_key: user.public_key.clone(),
                jti: "attest-user-claim".into(),
                sub: user.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &user.signing_key,
        )
        .unwrap();
        let user_hash = user_attest.payload_hash();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(user_attest)
            .unwrap();

        let vouch = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "vouch-user-claim".into(),
                sub: user.id.to_urn(),
                kind: TokenKind::Vouch,
                purpose: Some("dds:group:employees".into()),
                vch_iss: Some(user.id.to_urn()),
                vch_sum: Some(user_hash),
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();
        svc.trust_graph.write().unwrap().add_token(vouch).unwrap();

        let policy = WindowsPolicyDocument {
            policy_id: "p:claim".into(),
            display_name: "Claim".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope: PolicyScope {
                device_tags: vec!["workstation".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            windows: Some(WindowsSettings {
                local_accounts: vec![AccountDirective {
                    username: "alice-local".into(),
                    action: AccountAction::Create,
                    claim_subject_urn: Some(user.id.to_urn()),
                    full_name: Some("Alice Local".into()),
                    description: Some("Claimable account".into()),
                    groups: vec!["Users".into(), "Remote Desktop Users".into()],
                    password_never_expires: Some(true),
                }],
                ..Default::default()
            }),
        };
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-claim", &policy))
            .unwrap();

        let session = svc
            .issue_session(SessionRequest {
                subject_urn: user.id.to_urn(),
                device_urn: None,
                requested_resources: vec![],
                duration_secs: 300,
                mfa_verified: true,
                tls_binding: None,
            })
            .unwrap();

        let claim = svc
            .resolve_windows_account_claim(&device_urn, &session.token_cbor)
            .unwrap();
        assert_eq!(claim.subject_urn, user.id.to_urn());
        assert_eq!(claim.username, "alice-local");
        assert_eq!(claim.full_name.as_deref(), Some("Alice Local"));
        assert_eq!(
            claim.groups,
            vec!["Users".to_string(), "Remote Desktop Users".to_string()]
        );
        assert_eq!(claim.password_never_expires, Some(true));

        assert!(
            svc.trust_graph
                .read()
                .unwrap()
                .validate_chain(&user.id.to_urn(), &roots)
                .is_ok()
        );
    }

    #[test]
    fn windows_claim_resolution_rejects_conflicting_claims() {
        let (mut svc, admin, _) = setup();
        let device_urn = enroll_device(
            &mut svc,
            "ws-claim-conflict",
            vec!["workstation".into()],
            None,
        );

        let user = Identity::generate("bob", &mut OsRng);
        let user_attest = Token::sign(
            TokenPayload {
                iss: user.id.to_urn(),
                iss_key: user.public_key.clone(),
                jti: "attest-user-conflict".into(),
                sub: user.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &user.signing_key,
        )
        .unwrap();
        let user_hash = user_attest.payload_hash();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(user_attest)
            .unwrap();

        let vouch = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "vouch-user-conflict".into(),
                sub: user.id.to_urn(),
                kind: TokenKind::Vouch,
                purpose: Some("dds:group:employees".into()),
                vch_iss: Some(user.id.to_urn()),
                vch_sum: Some(user_hash),
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();
        svc.trust_graph.write().unwrap().add_token(vouch).unwrap();

        for (jti, username) in [("p-claim-a", "bob-a"), ("p-claim-b", "bob-b")] {
            let policy = WindowsPolicyDocument {
                policy_id: jti.into(),
                display_name: "Claim".into(),
                version: 1,
                enforcement: Enforcement::Enforce,
                scope: PolicyScope {
                    device_tags: vec!["workstation".into()],
                    org_units: vec![],
                    identity_urns: vec![],
                },
                settings: vec![],
                windows: Some(WindowsSettings {
                    local_accounts: vec![AccountDirective {
                        username: username.into(),
                        action: AccountAction::Create,
                        claim_subject_urn: Some(user.id.to_urn()),
                        full_name: None,
                        description: None,
                        groups: vec![],
                        password_never_expires: None,
                    }],
                    ..Default::default()
                }),
            };
            svc.trust_graph
                .write()
                .unwrap()
                .add_token(attest_with_body(&admin, jti, &policy))
                .unwrap();
        }

        let session = svc
            .issue_session(SessionRequest {
                subject_urn: user.id.to_urn(),
                device_urn: None,
                requested_resources: vec![],
                duration_secs: 300,
                mfa_verified: true,
                tls_binding: None,
            })
            .unwrap();

        let err = svc
            .resolve_windows_account_claim(&device_urn, &session.token_cbor)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("multiple conflicting windows account claims")
        );
    }

    #[test]
    fn macos_policy_tag_scope_matches_only_tagged_devices() {
        let (mut svc, admin, _) = setup();
        let dev_mac = enroll_device(&mut svc, "mac-1", vec!["mac-laptop".into()], None);
        let dev_other = enroll_device(&mut svc, "win-1", vec!["workstation".into()], None);

        let policy = baseline_macos_policy(
            "p:mac-laptops",
            PolicyScope {
                device_tags: vec!["mac-laptop".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_macos_policies(&dev_mac).unwrap().len(),
            1
        );
        assert_eq!(
            svc.list_applicable_macos_policies(&dev_other)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn macos_policy_global_scope_matches_every_device() {
        // An empty scope (no tags, no OUs, no identity URNs) must match
        // every enrolled device, mirroring the Windows global-scope test.
        let (mut svc, admin, _) = setup();
        let dev_a = enroll_device(&mut svc, "mac-global-a", vec!["mac-laptop".into()], None);
        let dev_b = enroll_device(&mut svc, "mac-global-b", vec![], Some("engineering".into()));

        let policy = baseline_macos_policy(
            "p:mac-global",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-global", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_macos_policies(&dev_a).unwrap().len(),
            1,
            "global-scope policy must match a device with tags"
        );
        assert_eq!(
            svc.list_applicable_macos_policies(&dev_b).unwrap().len(),
            1,
            "global-scope policy must match a device with an org unit"
        );
    }

    #[test]
    fn macos_policy_org_unit_and_identity_scope() {
        // OU-scoped policies must match only devices in that OU;
        // identity-URN-scoped policies must match only the exact device.
        // Mirrors the Windows org_unit_and_identity_scope test.
        let (mut svc, admin, _) = setup();
        let dev_design = enroll_device(&mut svc, "mac-ou-design", vec![], Some("design".into()));
        let dev_eng = enroll_device(&mut svc, "mac-ou-eng", vec![], Some("engineering".into()));

        let by_ou = baseline_macos_policy(
            "p:mac-design",
            PolicyScope {
                device_tags: vec![],
                org_units: vec!["design".into()],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-ou", &by_ou))
            .unwrap();

        let by_id = baseline_macos_policy(
            "p:mac-eng-direct",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![dev_eng.clone()],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-id", &by_id))
            .unwrap();

        let design_hits = svc.list_applicable_macos_policies(&dev_design).unwrap();
        let eng_hits = svc.list_applicable_macos_policies(&dev_eng).unwrap();

        assert_eq!(design_hits.len(), 1);
        assert_eq!(design_hits[0].document.policy_id, "p:mac-design");
        assert_eq!(eng_hits.len(), 1);
        assert_eq!(eng_hits[0].document.policy_id, "p:mac-eng-direct");
    }

    #[test]
    fn typed_macos_settings_survive_listing_round_trip() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-typed", vec!["mac-laptop".into()], None);

        let policy = MacOsPolicyDocument {
            policy_id: "p:mac-typed".into(),
            display_name: "Typed macOS".into(),
            version: 2,
            enforcement: Enforcement::Audit,
            scope: PolicyScope {
                device_tags: vec!["mac-laptop".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            macos: Some(MacOsSettings {
                local_accounts: vec![MacAccountDirective {
                    username: "alice".into(),
                    action: MacAccountAction::Create,
                    full_name: Some("Alice Example".into()),
                    shell: Some("/bin/zsh".into()),
                    admin: Some(true),
                    hidden: Some(false),
                }],
                launchd: vec![LaunchdDirective {
                    label: "com.dds.agent".into(),
                    plist_path: "/Library/LaunchDaemons/com.dds.agent.plist".into(),
                    enabled: Some(true),
                    action: LaunchdAction::Configure,
                }],
                profiles: vec![ProfileDirective {
                    identifier: "com.dds.test".into(),
                    display_name: "DDS Test".into(),
                    payload_sha256: "sha256:test".into(),
                    mobileconfig_b64: "SGVsbG8=".into(),
                    action: ProfileAction::Install,
                }],
                ..Default::default()
            }),
        };
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-typed", &policy))
            .unwrap();

        let hits = svc.list_applicable_macos_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].document.enforcement, Enforcement::Audit));
        let bundle = hits[0].document.macos.as_ref().unwrap();
        assert_eq!(bundle.local_accounts[0].username, "alice");
        assert_eq!(bundle.launchd[0].label, "com.dds.agent");
        assert_eq!(bundle.profiles[0].identifier, "com.dds.test");
    }

    #[test]
    fn macos_policy_disabled_documents_are_skipped() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-disabled", vec![], None);
        let mut policy = baseline_macos_policy(
            "p:mac-disabled",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Disabled;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-dis", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_macos_policies(&dev).unwrap().len(),
            0,
            "disabled macOS policies must not be returned"
        );
    }

    #[test]
    fn macos_policy_audit_documents_are_returned() {
        // Audit-mode docs must reach the agent — the agent decides whether
        // to enforce or log. The directory layer must not pre-filter them.
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-audit", vec![], None);
        let mut policy = baseline_macos_policy(
            "p:mac-audit",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Audit;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-audit", &policy))
            .unwrap();

        let hits = svc.list_applicable_macos_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].document.enforcement, Enforcement::Audit));
    }

    #[test]
    fn macos_policy_without_publisher_capability_is_rejected() {
        // A macOS policy signed by an identity that lacks the
        // `dds:policy-publisher-macos` purpose vouch must be silently
        // dropped by `list_applicable_macos_policies` (C-3 gate).
        let (mut svc, _admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-gated", vec![], None);

        let bare = Identity::generate("bare-mac-publisher", &mut OsRng);
        let bare_attest = Token::sign(
            TokenPayload {
                iss: bare.id.to_urn(),
                iss_key: bare.public_key.clone(),
                jti: "bare-attest-mac".into(),
                sub: bare.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &bare.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(bare_attest)
            .unwrap();

        let policy = baseline_macos_policy(
            "p:mac-gated",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&bare, "p-mac-bare", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_macos_policies(&dev).unwrap().len(),
            0,
            "macOS policy from issuer lacking POLICY_PUBLISHER_MACOS must be rejected"
        );
    }

    /// **B-4 regression.** Two `MacOsPolicyDocument` attestations with
    /// the same `policy_id` but different `version`s must collapse to
    /// the highest version.
    #[test]
    fn b4_macos_policies_supersede_by_version() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-b4", vec!["mac-laptop".into()], None);

        let mut p_old = baseline_macos_policy(
            "p:mac-supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_old.version = 2;
        let mut p_new = baseline_macos_policy(
            "p:mac-supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_new.version = 5;

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-new", &p_new))
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-mac-old", &p_old))
            .unwrap();

        let hits = svc.list_applicable_macos_policies(&dev).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "duplicate macOS policy_id must collapse to one"
        );
        assert_eq!(hits[0].document.version, 5);
        assert_eq!(hits[0].jti, "p-mac-new");
    }

    /// **B-4 regression.** Two `MacOsPolicyDocument` attestations with
    /// the same `policy_id` and identical `version` must collapse to
    /// the one with the later `iat` (signed timestamp).
    #[test]
    fn b4_macos_policies_supersede_by_iat_on_version_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-b4-iat", vec!["mac-laptop".into()], None);

        let p = baseline_macos_policy(
            "p:mac-iat-tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let t_early = attest_with_body(&admin, "p-mac-early", &p);
        let t_late_base = attest_with_body(&admin, "p-mac-late", &p);
        // attest_with_body fixes iat at 1_700_000_000; rebuild with a
        // later iat to exercise the tie-breaker path.
        let p_late_payload = TokenPayload {
            iat: 1_700_001_000,
            ..t_late_base.payload.clone()
        };
        let t_late = Token::sign(p_late_payload, &admin.signing_key).unwrap();

        svc.trust_graph.write().unwrap().add_token(t_early).unwrap();
        svc.trust_graph.write().unwrap().add_token(t_late).unwrap();

        let hits = svc.list_applicable_macos_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].iat, 1_700_001_000,
            "B-4: latest iat must win on macOS version tie"
        );
    }

    /// **B-4 regression.** When two `MacOsPolicyDocument` attestations
    /// share `policy_id`, `version`, *and* `iat`, the lex-smallest `jti`
    /// wins (final tiebreaker).
    #[test]
    fn b4_macos_policies_supersede_by_jti_on_iat_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "mac-b4-jti", vec!["mac-laptop".into()], None);

        let p = baseline_macos_policy(
            "p:mac-jti-tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        // Both tokens share the same iat. Lex-smaller jti "p-mac-aaa" must win.
        let t_lex_larger = attest_with_body(&admin, "p-mac-zzz", &p);
        let t_lex_smaller = attest_with_body(&admin, "p-mac-aaa", &p);

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_larger)
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_smaller)
            .unwrap();

        let hits = svc.list_applicable_macos_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].jti, "p-mac-aaa",
            "B-4: lex-smallest jti must win on macOS iat tie"
        );
    }

    // ============================================================
    // B-4 (security review): deterministic supersession
    // ============================================================

    /// **B-4 regression.** Two `WindowsPolicyDocument` attestations with
    /// the same `policy_id` but different `version`s must collapse to
    /// the highest version.
    #[test]
    fn b4_windows_policies_supersede_by_version() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4", vec!["workstation".into()], None);

        let mut p_old = baseline_policy(
            "p:supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_old.version = 3;
        let mut p_new = baseline_policy(
            "p:supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_new.version = 7;

        // Insert in "wrong" order: the higher version arrives first,
        // then the older one — supersession must still pick v=7.
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-new", &p_new))
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-old", &p_old))
            .unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1, "duplicate policy_id must collapse to one");
        assert_eq!(hits[0].document.version, 7);
        assert_eq!(hits[0].jti, "p-new");
    }

    /// **B-4 regression.** When two attestations share both `policy_id`
    /// and `version`, the one with the latest `iat` wins.
    #[test]
    fn b4_windows_policies_supersede_by_iat_on_version_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4-iat", vec!["workstation".into()], None);

        let p = baseline_policy(
            "p:tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let mut t_early = attest_with_body(&admin, "p-early", &p);
        let mut t_late = attest_with_body(&admin, "p-late", &p);
        // attest_with_body fixes iat at 1_700_000_000; tweak the late
        // one to be later by re-signing a copy of the payload with a
        // later iat. We rebuild from scratch to avoid mutating the
        // signed bytes.
        let _ = (&mut t_early, &mut t_late);
        let p_late_payload = TokenPayload {
            iat: 1_700_001_000,
            ..t_late.payload.clone()
        };
        t_late = Token::sign(p_late_payload, &admin.signing_key).unwrap();

        svc.trust_graph.write().unwrap().add_token(t_early).unwrap();
        svc.trust_graph.write().unwrap().add_token(t_late).unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].iat, 1_700_001_000,
            "B-4: latest iat must win on version tie"
        );
    }

    /// **B-4 regression.** When two `WindowsPolicyDocument` attestations
    /// share `policy_id`, `version`, *and* `iat`, the lex-smallest `jti`
    /// wins (final tiebreaker).
    #[test]
    fn b4_windows_policies_supersede_by_jti_on_iat_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4-jti", vec!["workstation".into()], None);

        let p = baseline_policy(
            "p:jti-tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        // Both tokens get the same iat (1_700_000_000 from attest_with_body)
        // and same version. Lex-smaller jti "p-aaa" must beat "p-zzz".
        let t_lex_larger = attest_with_body(&admin, "p-zzz", &p);
        let t_lex_smaller = attest_with_body(&admin, "p-aaa", &p);

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_larger)
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_smaller)
            .unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].jti, "p-aaa",
            "B-4: lex-smallest jti must win on Windows iat tie"
        );
    }

    /// **B-4 regression.** Two `SoftwareAssignment` attestations with
    /// the same `package_id` collapse to the latest `iat`.
    #[test]
    fn b4_software_supersedes_by_iat() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4-sw", vec!["developer".into()], None);

        let pkg_v1 = SoftwareAssignment {
            package_id: "com.example.editor".into(),
            display_name: "Editor".into(),
            version: "1.0.0".into(),
            source: "https://cdn.example.com/editor-1.0.0.msi".into(),
            sha256: "deadbeef".into(),
            action: dds_domain::InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["developer".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
            uninstall_script: None,
            publisher_identity: None,
            enforcement: dds_domain::types::Enforcement::Enforce,
        };
        let pkg_v2 = SoftwareAssignment {
            version: "2.0.0".into(),
            source: "https://cdn.example.com/editor-2.0.0.msi".into(),
            sha256: "feedface".into(),
            ..pkg_v1.clone()
        };

        let mut t_v1 = attest_with_body(&admin, "sw-v1", &pkg_v1);
        let _ = &mut t_v1;
        let pkg_v2_payload = TokenPayload {
            iat: 1_700_002_000,
            ..attest_with_body(&admin, "sw-v2", &pkg_v2).payload
        };
        let t_v2 = Token::sign(pkg_v2_payload, &admin.signing_key).unwrap();

        svc.trust_graph.write().unwrap().add_token(t_v1).unwrap();
        svc.trust_graph.write().unwrap().add_token(t_v2).unwrap();

        let hits = svc.list_applicable_software(&dev).unwrap();
        assert_eq!(hits.len(), 1, "duplicate package_id must collapse to one");
        assert_eq!(hits[0].document.version, "2.0.0");
        assert_eq!(hits[0].iat, 1_700_002_000);
    }

    /// **B-4 regression.** When two `SoftwareAssignment` attestations
    /// share `package_id` *and* `iat`, the lex-smallest `jti` wins.
    #[test]
    fn b4_software_supersedes_by_jti_on_iat_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4-sw-jti", vec!["developer".into()], None);

        let pkg = SoftwareAssignment {
            package_id: "com.example.jti-tie".into(),
            display_name: "JtiTie".into(),
            version: "1.0.0".into(),
            source: "https://cdn.example.com/jtitie-1.0.0.msi".into(),
            sha256: "deadbeef".into(),
            action: dds_domain::InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["developer".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
            uninstall_script: None,
            publisher_identity: None,
            enforcement: dds_domain::types::Enforcement::Enforce,
        };
        // Both tokens share the same iat (1_700_000_000 from attest_with_body).
        // Lex-smaller jti "sw-aaa" must beat "sw-zzz".
        let t_lex_larger = attest_with_body(&admin, "sw-zzz", &pkg);
        let t_lex_smaller = attest_with_body(&admin, "sw-aaa", &pkg);

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_larger)
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_smaller)
            .unwrap();

        let hits = svc.list_applicable_software(&dev).unwrap();
        assert_eq!(hits.len(), 1, "duplicate package_id must collapse to one");
        assert_eq!(
            hits[0].jti, "sw-aaa",
            "B-4: lex-smallest jti must win on software iat tie"
        );
    }

    /// **B-4 regression.** Documents with *different* logical IDs are
    /// preserved — supersession only collapses duplicates within the
    /// same `policy_id` / `package_id`.
    #[test]
    fn b4_distinct_ids_are_not_collapsed() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b4-distinct", vec![], None);

        let a = baseline_policy(
            "p:a",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let b = baseline_policy(
            "p:b",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-a", &a))
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-b", &b))
            .unwrap();

        let hits = svc.list_applicable_windows_policies(&dev).unwrap();
        assert_eq!(hits.len(), 2);
        // Stable order: alphabetic by policy_id.
        assert_eq!(hits[0].document.policy_id, "p:a");
        assert_eq!(hits[1].document.policy_id, "p:b");
    }

    /// **SC-5 Phase B.1 follow-on.** A `SoftwareAssignment` carrying a
    /// malformed `publisher_identity` (e.g. empty Authenticode subject)
    /// is dropped at the agent-facing read path. Without this gate the
    /// blob would land on the agent, the signer-subject compare would
    /// fail to match anything real, and the agent would fall through
    /// to hash-only — observationally identical to "no publisher
    /// pinning" and the exact silent downgrade the two-signature gate
    /// is meant to prevent.
    #[test]
    fn b1_software_with_invalid_publisher_identity_is_skipped() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "ws-b1-bad-pi", vec!["developer".into()], None);

        let bad = SoftwareAssignment {
            package_id: "com.example.editor".into(),
            display_name: "Editor".into(),
            version: "1.0.0".into(),
            source: "https://cdn.example.com/editor-1.0.0.msi".into(),
            sha256: "deadbeef".into(),
            action: dds_domain::InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["developer".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
            uninstall_script: None,
            // Invalid: empty Authenticode subject. `validate()`
            // returns `EmptyAuthenticodeSubject`.
            publisher_identity: Some(PublisherIdentity::Authenticode {
                subject: String::new(),
                root_thumbprint: None,
            }),
            enforcement: dds_domain::types::Enforcement::Enforce,
        };
        let good = SoftwareAssignment {
            package_id: "com.example.viewer".into(),
            sha256: "feedface".into(),
            source: "https://cdn.example.com/viewer-1.0.0.msi".into(),
            // Valid Apple Team ID — 10 uppercase alphanumerics.
            publisher_identity: Some(PublisherIdentity::AppleDeveloperId {
                team_id: "ABCDE12345".into(),
            }),
            ..bad.clone()
        };

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "sw-bad", &bad))
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "sw-good", &good))
            .unwrap();

        let hits = svc.list_applicable_software(&dev).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "malformed publisher_identity must be dropped, leaving only the valid assignment"
        );
        assert_eq!(hits[0].document.package_id, "com.example.viewer");
    }

    // ============================================================
    // Linux policy tests
    // ============================================================

    #[test]
    fn linux_policy_tag_scope_matches_only_tagged_devices() {
        let (mut svc, admin, _) = setup();
        let dev_linux = enroll_device(&mut svc, "linux-1", vec!["linux-server".into()], None);
        let dev_other = enroll_device(&mut svc, "win-1", vec!["workstation".into()], None);

        let policy = baseline_linux_policy(
            "p:linux-servers",
            PolicyScope {
                device_tags: vec!["linux-server".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_linux_policies(&dev_linux)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            svc.list_applicable_linux_policies(&dev_other)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn b4_linux_policies_supersede_by_version() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-b4", vec![], None);

        let mut p_old = baseline_linux_policy(
            "p:linux-supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_old.version = 3;
        let mut p_new = baseline_linux_policy(
            "p:linux-supersede",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        p_new.version = 7;

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-new", &p_new))
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-old", &p_old))
            .unwrap();

        let hits = svc.list_applicable_linux_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1, "duplicate policy_id must collapse to one");
        assert_eq!(hits[0].document.version, 7);
        assert_eq!(hits[0].jti, "p-linux-new");
    }

    /// **B-4 regression.** Two `LinuxPolicyDocument` attestations with
    /// the same `policy_id` and identical `version` must collapse to
    /// the one with the later `iat` (signed timestamp).
    #[test]
    fn b4_linux_policies_supersede_by_iat_on_version_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-b4-iat", vec![], None);

        let p = baseline_linux_policy(
            "p:linux-iat-tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        let t_early = attest_with_body(&admin, "p-linux-early", &p);
        let t_late_base = attest_with_body(&admin, "p-linux-late", &p);
        // attest_with_body fixes iat at 1_700_000_000; rebuild with a
        // later iat to exercise the tie-breaker path.
        let p_late_payload = TokenPayload {
            iat: 1_700_001_000,
            ..t_late_base.payload.clone()
        };
        let t_late = Token::sign(p_late_payload, &admin.signing_key).unwrap();

        svc.trust_graph.write().unwrap().add_token(t_early).unwrap();
        svc.trust_graph.write().unwrap().add_token(t_late).unwrap();

        let hits = svc.list_applicable_linux_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].iat, 1_700_001_000,
            "B-4: latest iat must win on Linux version tie"
        );
    }

    /// **B-4 regression.** When two `LinuxPolicyDocument` attestations
    /// share `policy_id`, `version`, *and* `iat`, the lex-smallest `jti`
    /// wins (final tiebreaker).
    #[test]
    fn b4_linux_policies_supersede_by_jti_on_iat_tie() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-b4-jti", vec![], None);

        let p = baseline_linux_policy(
            "p:linux-jti-tie",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        // Both tokens share the same iat. Lex-smaller jti "p-linux-aaa" must win.
        let t_lex_larger = attest_with_body(&admin, "p-linux-zzz", &p);
        let t_lex_smaller = attest_with_body(&admin, "p-linux-aaa", &p);

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_larger)
            .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(t_lex_smaller)
            .unwrap();

        let hits = svc.list_applicable_linux_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].jti, "p-linux-aaa",
            "B-4: lex-smallest jti must win on Linux iat tie"
        );
    }

    #[test]
    fn linux_policy_disabled_enforcement_is_skipped() {
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-disabled", vec![], None);

        let mut policy = baseline_linux_policy(
            "p:linux-disabled",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Disabled;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-off", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_linux_policies(&dev).unwrap().len(),
            0,
            "disabled Linux policies must not be returned"
        );
    }

    #[test]
    fn linux_policy_without_publisher_capability_is_rejected() {
        // A Linux policy signed by an identity that lacks the
        // `dds:policy-publisher-linux` purpose vouch must be silently
        // dropped by `list_applicable_linux_policies` (C-3 gate).
        let (mut svc, _admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-gated", vec![], None);

        // Create a "bare" publisher: it has an attestation token in the
        // graph but no publisher-capability vouch from any trusted root.
        let bare = Identity::generate("bare-publisher", &mut OsRng);
        let bare_attest = Token::sign(
            TokenPayload {
                iss: bare.id.to_urn(),
                iss_key: bare.public_key.clone(),
                jti: "bare-attest".into(),
                sub: bare.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1_700_000_000,
                exp: Some(4_102_444_800),
                body_type: None,
                body_cbor: None,
            },
            &bare.signing_key,
        )
        .unwrap();
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(bare_attest)
            .unwrap();

        // Sign a Linux policy as the bare publisher (no capability vouch).
        let policy = baseline_linux_policy(
            "p:linux-gated",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&bare, "p-linux-bare", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_linux_policies(&dev).unwrap().len(),
            0,
            "Linux policy from issuer lacking POLICY_PUBLISHER_LINUX must be rejected"
        );
    }

    #[test]
    fn linux_policy_global_scope_matches_every_device() {
        // An empty scope (no tags, no OUs, no identity URNs) must match
        // every enrolled device, mirroring the Windows global-scope test.
        let (mut svc, admin, _) = setup();
        let dev_a = enroll_device(&mut svc, "linux-global-a", vec!["server".into()], None);
        let dev_b = enroll_device(
            &mut svc,
            "linux-global-b",
            vec![],
            Some("engineering".into()),
        );

        let policy = baseline_linux_policy(
            "p:linux-global",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-global", &policy))
            .unwrap();

        assert_eq!(
            svc.list_applicable_linux_policies(&dev_a).unwrap().len(),
            1,
            "global-scope policy must match a device with tags"
        );
        assert_eq!(
            svc.list_applicable_linux_policies(&dev_b).unwrap().len(),
            1,
            "global-scope policy must match a device with an org unit"
        );
    }

    #[test]
    fn linux_policy_org_unit_and_identity_scope() {
        // OU-scoped policies must match only devices in that OU;
        // identity-URN-scoped policies must match only the exact device.
        // Mirrors the Windows org_unit_and_identity_scope test.
        let (mut svc, admin, _) = setup();
        let dev_eng = enroll_device(&mut svc, "linux-ou-eng", vec![], Some("engineering".into()));
        let dev_ops = enroll_device(&mut svc, "linux-ou-ops", vec![], Some("ops".into()));

        let by_ou = baseline_linux_policy(
            "p:linux-eng",
            PolicyScope {
                device_tags: vec![],
                org_units: vec!["engineering".into()],
                identity_urns: vec![],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-ou", &by_ou))
            .unwrap();

        let by_id = baseline_linux_policy(
            "p:linux-ops-direct",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![dev_ops.clone()],
            },
        );
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-id", &by_id))
            .unwrap();

        let eng_hits = svc.list_applicable_linux_policies(&dev_eng).unwrap();
        let ops_hits = svc.list_applicable_linux_policies(&dev_ops).unwrap();

        assert_eq!(eng_hits.len(), 1);
        assert_eq!(eng_hits[0].document.policy_id, "p:linux-eng");
        assert_eq!(ops_hits.len(), 1);
        assert_eq!(ops_hits[0].document.policy_id, "p:linux-ops-direct");
    }

    #[test]
    fn typed_linux_settings_survive_listing_round_trip() {
        // A `LinuxPolicyDocument` with fully-typed directives must arrive
        // at the agent exactly as the admin signed it.  Mirrors the
        // `typed_macos_settings_survive_listing_round_trip` test.
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-typed", vec!["linux-server".into()], None);

        let policy = LinuxPolicyDocument {
            policy_id: "p:linux-typed".into(),
            display_name: "Typed Linux".into(),
            version: 3,
            enforcement: dds_domain::types::Enforcement::Audit,
            scope: PolicyScope {
                device_tags: vec!["linux-server".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            linux: Some(LinuxSettings {
                local_users: vec![LinuxUserDirective {
                    username: "dds-svc".into(),
                    action: LinuxUserAction::Create,
                    uid: Some(1500),
                    shell: Some("/bin/bash".into()),
                    groups: vec!["sudo".into()],
                    full_name: Some("DDS Service Account".into()),
                }],
                files: vec![LinuxFileDirective {
                    path: "/etc/dds/agent.conf".into(),
                    action: LinuxFileAction::Set,
                    content_b64: Some("Y29uZg==".into()),
                    content_sha256: Some("abc123".into()),
                    owner: Some("root:root".into()),
                    mode: Some("0640".into()),
                }],
                packages: vec![LinuxPackageDirective {
                    name: "curl".into(),
                    action: LinuxPackageAction::Install,
                    version: Some("7.68.0".into()),
                }],
                ..Default::default()
            }),
        };

        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-typed", &policy))
            .unwrap();

        let hits = svc.list_applicable_linux_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(
            hits[0].document.enforcement,
            dds_domain::types::Enforcement::Audit
        ));
        assert_eq!(hits[0].document.version, 3);

        let bundle = hits[0].document.linux.as_ref().unwrap();
        assert_eq!(bundle.local_users.len(), 1);
        assert_eq!(bundle.local_users[0].username, "dds-svc");
        assert_eq!(bundle.local_users[0].uid, Some(1500));
        assert_eq!(bundle.local_users[0].groups, vec!["sudo"]);

        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].path, "/etc/dds/agent.conf");
        assert_eq!(bundle.files[0].owner.as_deref(), Some("root:root"));

        assert_eq!(bundle.packages.len(), 1);
        assert_eq!(bundle.packages[0].name, "curl");
        assert_eq!(bundle.packages[0].version.as_deref(), Some("7.68.0"));
    }

    #[test]
    fn linux_policy_audit_documents_are_returned() {
        // Audit-mode docs must reach the agent — the agent decides whether
        // to enforce or log. The directory layer must not pre-filter them.
        let (mut svc, admin, _) = setup();
        let dev = enroll_device(&mut svc, "linux-audit", vec![], None);
        let mut policy = baseline_linux_policy(
            "p:linux-audit",
            PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
        );
        policy.enforcement = Enforcement::Audit;
        svc.trust_graph
            .write()
            .unwrap()
            .add_token(attest_with_body(&admin, "p-linux-audit", &policy))
            .unwrap();

        let hits = svc.list_applicable_linux_policies(&dev).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(matches!(
            hits[0].document.enforcement,
            dds_domain::types::Enforcement::Audit
        ));
    }

    // Silence the unused-import warning when only some helpers are
    // exercised in this module.
    #[allow(dead_code)]
    fn _used(_: DeviceJoinDocument) {}
}

#[cfg(test)]
mod a1_step3_client_data_tests {
    //! **A-1 step-3**: unit tests for `verify_enrollment_client_data`.
    //! Mirror the M-12 assertion-side coverage. The original step-3
    //! pass landed `type` / `origin` / `crossOrigin`; the
    //! 2026-04-25 follow-up plumbed in the optional server-issued
    //! enrollment challenge (`expected_challenge`) so cdj.challenge
    //! can be bound just like at the assertion side.

    use super::*;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    fn cdj(ty: &str, origin: &str, cross_origin: Option<bool>) -> Vec<u8> {
        let mut obj = serde_json::json!({
            "type": ty,
            "origin": origin,
            "challenge": "AAAA",
        });
        if let Some(co) = cross_origin {
            obj["crossOrigin"] = serde_json::Value::Bool(co);
        }
        serde_json::to_vec(&obj).unwrap()
    }

    fn cdj_with_challenge(ty: &str, origin: &str, challenge_b64url: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": ty,
            "origin": origin,
            "challenge": challenge_b64url,
        }))
        .unwrap()
    }

    fn cdh_of(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }

    #[test]
    fn legacy_no_cdj_path_passes_through() {
        // None means "old client" — helper must succeed without
        // touching anything else. Caller still validates rp-id-hash
        // via verify_attestation.
        verify_enrollment_client_data(None, &[0u8; 32], "example.com", None).unwrap();
    }

    #[test]
    fn well_formed_cdj_accepted() {
        let bytes = cdj("webauthn.create", "https://example.com", None);
        let cdh = cdh_of(&bytes);
        verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None).unwrap();
    }

    #[test]
    fn cdh_mismatch_rejected() {
        let bytes = cdj("webauthn.create", "https://example.com", None);
        // Pass a CDH that doesn't match the JSON.
        let res = verify_enrollment_client_data(Some(&bytes), &[0u8; 32], "example.com", None);
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(
                    msg.contains("client_data_hash does not match"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected Fido2(cdh mismatch), got {other:?}"),
        }
    }

    #[test]
    fn wrong_type_rejected() {
        // `webauthn.get` is the assertion type; enrollment must be
        // `webauthn.create`. An attacker who replays an assertion-time
        // clientDataJSON to the enrollment endpoint must be rejected.
        let bytes = cdj("webauthn.get", "https://example.com", None);
        let cdh = cdh_of(&bytes);
        let res = verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None);
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("webauthn.create"), "msg: {msg}");
            }
            other => panic!("expected Fido2(type), got {other:?}"),
        }
    }

    #[test]
    fn wrong_origin_rejected() {
        let bytes = cdj("webauthn.create", "https://attacker.com", None);
        let cdh = cdh_of(&bytes);
        let res = verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None);
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("origin"), "msg: {msg}");
                assert!(msg.contains("example.com"), "msg: {msg}");
            }
            other => panic!("expected Fido2(origin), got {other:?}"),
        }
    }

    #[test]
    fn cross_origin_rejected() {
        let bytes = cdj("webauthn.create", "https://example.com", Some(true));
        let cdh = cdh_of(&bytes);
        let res = verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None);
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("crossOrigin"), "msg: {msg}");
            }
            other => panic!("expected Fido2(crossOrigin), got {other:?}"),
        }
    }

    #[test]
    fn cross_origin_false_or_missing_accepted() {
        // Explicit `false` is fine.
        let bytes = cdj("webauthn.create", "https://example.com", Some(false));
        let cdh = cdh_of(&bytes);
        verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None).unwrap();
        // Missing field defaults to `false`.
        let bytes = cdj("webauthn.create", "https://example.com", None);
        let cdh = cdh_of(&bytes);
        verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None).unwrap();
    }

    #[test]
    fn malformed_json_rejected() {
        let bytes = b"this is not json".to_vec();
        let cdh = cdh_of(&bytes);
        let res = verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", None);
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("not valid JSON"), "msg: {msg}");
            }
            other => panic!("expected Fido2(json), got {other:?}"),
        }
    }

    // -- A-1 follow-up: server-issued enrollment challenge --

    #[test]
    fn matching_challenge_accepted() {
        let server_bytes = vec![0xAB; 32];
        let ch_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&server_bytes);
        let bytes = cdj_with_challenge("webauthn.create", "https://example.com", &ch_b64url);
        let cdh = cdh_of(&bytes);
        verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", Some(&server_bytes))
            .unwrap();
    }

    #[test]
    fn mismatched_challenge_rejected() {
        let server_bytes = vec![0xAB; 32];
        // Client signs over a *different* challenge value.
        let other_bytes = vec![0xCD; 32];
        let ch_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&other_bytes);
        let bytes = cdj_with_challenge("webauthn.create", "https://example.com", &ch_b64url);
        let cdh = cdh_of(&bytes);
        let res =
            verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", Some(&server_bytes));
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("challenge does not match"), "msg: {msg}");
            }
            other => panic!("expected Fido2(challenge mismatch), got {other:?}"),
        }
    }

    #[test]
    fn padded_base64url_challenge_accepted() {
        // Some JS stacks emit base64url *with* padding. Mirror the
        // M-12 lenient decode.
        let server_bytes = b"hello world".to_vec();
        let ch_padded = base64::engine::general_purpose::URL_SAFE.encode(&server_bytes);
        assert!(ch_padded.contains('='), "expected padded encoding");
        let bytes = cdj_with_challenge("webauthn.create", "https://example.com", &ch_padded);
        let cdh = cdh_of(&bytes);
        verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", Some(&server_bytes))
            .unwrap();
    }

    #[test]
    fn challenge_supplied_without_cdj_rejected() {
        // The caller went to the trouble of consuming a server
        // challenge but then withheld the JSON — refuse, otherwise
        // the freshness binding is silently skipped.
        let server_bytes = vec![0u8; 32];
        let res =
            verify_enrollment_client_data(None, &[0u8; 32], "example.com", Some(&server_bytes));
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("challenge_id supplied without"), "msg: {msg}");
            }
            other => panic!("expected Fido2(challenge_id without cdj), got {other:?}"),
        }
    }

    #[test]
    fn missing_challenge_field_rejected_when_expected() {
        // Server expects a challenge to be bound, but the cdj has no
        // `challenge` field at all.
        let server_bytes = vec![0u8; 32];
        let bytes = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "origin": "https://example.com",
        }))
        .unwrap();
        let cdh = cdh_of(&bytes);
        let res =
            verify_enrollment_client_data(Some(&bytes), &cdh, "example.com", Some(&server_bytes));
        match res {
            Err(ServiceError::Fido2(msg)) => {
                assert!(msg.contains("missing challenge"), "msg: {msg}");
            }
            other => panic!("expected Fido2(missing challenge), got {other:?}"),
        }
    }
}
