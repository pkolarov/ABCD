//! Local authority service — enrollment, sessions, policy resolution, status.
//!
//! This module turns dds-node into the authoritative local service that
//! client applications talk to. It provides:
//! - **Enrollment**: accept device/user join requests, issue attestation tokens
//! - **Session issuance**: create short-lived SessionDocuments (< 1ms local check)
//! - **Policy resolution**: evaluate access decisions against the trust graph
//! - **Status reporting**: health, sync state, peer count, trust stats

use base64::Engine;
use dds_core::identity::Identity;
use dds_core::policy::{PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::{
    AccountAction, AccountDirective, DeviceJoinDocument, DomainDocument, Enforcement,
    MacOsPolicyDocument, PolicyScope, SessionDocument, SoftwareAssignment, UserAuthAttestation,
    WindowsPolicyDocument,
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
}

/// Internal output of the shared FIDO2 assertion verifier.
struct CommonAssertionOutput {
    subject_urn: String,
    user_verified: bool,
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
}

/// Policy evaluation result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: String,
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
        let scope_vouched = g.has_purpose(
            device_urn,
            dds_core::token::purpose::DEVICE_SCOPE,
            &self.trusted_roots,
        );
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

            let parsed = dds_domain::fido2::verify_attestation(
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

        Ok(EnrollmentResult {
            urn: device_ident.id.to_urn(),
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Issue a short-lived session token.
    pub fn issue_session(&mut self, req: SessionRequest) -> Result<SessionResult, ServiceError> {
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
            if !g.has_purpose(
                &token.payload.iss,
                dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
                &self.trusted_roots,
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
            if !g.has_purpose(
                &token.payload.iss,
                dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
                &self.trusted_roots,
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
            // C-3: same publisher capability gate.
            if !g.has_purpose(
                &token.payload.iss,
                dds_core::token::purpose::SOFTWARE_PUBLISHER,
                &self.trusted_roots,
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
    pub fn record_applied(&self, report: &AppliedReport) -> Result<(), ServiceError> {
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
        let parsed = verify_assertion(authenticator_data, client_data_hash, signature, &public_key)
            .map_err(|e| ServiceError::Fido2(e.to_string()))?;

        // 3. User-presence (UP) flag — physical touch/biometric required.
        if !parsed.user_present {
            return Err(ServiceError::Fido2(
                "assertion failed: user_present (UP) flag not set".into(),
            ));
        }

        // 4. RP-ID binding — prevents cross-site assertion replay.
        {
            let expected_hash = Sha256::digest(enrolled_rp_id.as_bytes());
            if parsed.rp_id_hash != expected_hash.as_slice() {
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
            match self.store.bump_sign_count(credential_id, parsed.sign_count) {
                Ok(()) => {}
                Err(dds_store::traits::StoreError::SignCountReplay { stored, attempted }) => {
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
        self.issue_session(session_req)
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
            users.push(EnrolledUser {
                subject_urn: token.payload.sub.clone(),
                display_name: doc.user_display_name.clone(),
                credential_id: doc.credential_id.clone(),
                vouched,
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

            let parsed = dds_domain::fido2::verify_attestation(
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
    /// freshness, and sign-count via `verify_assertion_common`), checks admin
    /// is a trusted root, loads the admin's persisted signing key, and signs a
    /// Vouch token granting the subject the requested purpose.
    pub fn admin_vouch(
        &mut self,
        req: AdminVouchRequest,
    ) -> Result<AdminVouchResult, ServiceError> {
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
                g.has_purpose(&admin_urn, &cap, &self.trusted_roots)
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
        })
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
        .unwrap()
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
        MacAccountAction, MacAccountDirective, MacOsPolicyDocument, MacOsSettings, PasswordPolicy,
        PolicyScope, PreferenceAction, PreferenceDirective, PreferenceScope, ProfileAction,
        ProfileDirective, RegistryAction, RegistryDirective, RegistryHive, RegistryValue,
        SoftwareAssignment, WindowsPolicyDocument, WindowsSettings,
    };
    use dds_store::MemoryBackend;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::{Arc, RwLock};

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
        let (svc, _, _) = setup();
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.xxx".into(),
            target_id: "security/baseline".into(),
            version: "7".into(),
            status: AppliedStatus::Ok,
            directives: vec!["registry: HKLM\\... = 1".into()],
            error: None,
            applied_at: 1_700_000_000,
        };
        assert!(svc.record_applied(&report).is_ok());
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
