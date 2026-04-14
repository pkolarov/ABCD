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
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub client_data_hash: Vec<u8>,
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
    pub client_data_hash: Vec<u8>,
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
    S: TokenStore + dds_store::traits::RevocationStore + dds_store::traits::AuditStore,
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
    /// Storage backend.
    store: S,
    /// Data directory for admin key storage (None in test/bench contexts).
    data_dir: Option<PathBuf>,
    /// Path to the TOML config file (for persisting trusted_roots changes).
    config_path: Option<PathBuf>,
    /// Node start time.
    start_time: u64,
    /// Whether to verify FIDO2 attestation on enroll_user.
    verify_fido2: bool,
}

impl<S: TokenStore + dds_store::traits::RevocationStore + dds_store::traits::AuditStore>
    LocalService<S>
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
            store,
            data_dir: None,
            config_path: None,
            start_time: now_epoch(),
            verify_fido2: true,
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

    /// Set the data directory for admin key storage.
    pub fn set_data_dir(&mut self, path: PathBuf) {
        self.data_dir = Some(path);
    }

    /// Set the config file path so trusted_roots changes can be persisted.
    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }

    /// Persist the current trusted_roots back to the TOML config file.
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

        std::fs::write(config_path, doc.to_string())
            .map_err(|e| ServiceError::Store(format!("write config: {e}")))?;

        tracing::info!(count = roots.len(), "persisted trusted_roots to config");
        Ok(())
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
            let parsed = dds_domain::fido2::verify_attestation(
                &req.attestation_object,
                &req.client_data_hash,
            )
            .map_err(|e| ServiceError::Fido2(e.to_string()))?;

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

    /// List every `WindowsPolicyDocument` whose scope matches the
    /// given device URN. Skips revoked, burned, and `Disabled`
    /// documents. The result is in attestation-iteration order
    /// (implementation-defined); the agent should sort by
    /// `(policy_id, version)` if it cares about determinism.
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

        let (device_tags, device_ou) = device_targeting_facts(&g, device_urn);

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
        Ok(out)
    }

    /// List every `MacOsPolicyDocument` whose scope matches the given
    /// device URN. Skips revoked, burned, and `Disabled` documents.
    /// Scope semantics are identical to
    /// `list_applicable_windows_policies`.
    pub fn list_applicable_macos_policies(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableMacOsPolicy>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = device_targeting_facts(&g, device_urn);

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
        Ok(out)
    }

    /// List every `SoftwareAssignment` whose scope matches the given
    /// device URN. Skips revoked / burned tokens. Same scope rules as
    /// `list_applicable_windows_policies`. Phase 3 item 10.
    pub fn list_applicable_software(
        &self,
        device_urn: &str,
    ) -> Result<Vec<ApplicableSoftware>, ServiceError> {
        let g = self
            .trust_graph
            .read()
            .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

        let (device_tags, device_ou) = device_targeting_facts(&g, device_urn);

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

    /// Issue a session from a FIDO2 assertion proof.
    ///
    /// The caller (Auth Bridge) sends the raw getAssertion output; we
    /// look up the credential's public key from the trust graph, verify
    /// the assertion signature, then issue a `SessionDocument` exactly
    /// like `issue_session` but with cryptographic proof of possession.
    pub fn issue_session_from_assertion(
        &mut self,
        req: AssertionSessionRequest,
    ) -> Result<SessionResult, ServiceError> {
        use dds_domain::fido2::{cose_to_credential_public_key, verify_assertion};

        // 1. Look up the credential's public key from the trust graph.
        //    We scan attestation tokens for a UserAuthAttestation whose
        //    credential_id matches.
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
                if doc.credential_id == req.credential_id {
                    // Extract the COSE public key from the attestation object.
                    let parsed = dds_domain::fido2::verify_attestation(
                        &doc.attestation_object,
                        &doc.client_data_hash,
                    )
                    .map_err(|e| ServiceError::Fido2(format!("re-parse attestation: {e}")))?;

                    // Build COSE_Key bytes from the parsed attestation's
                    // auth_data (credential public key starts after AAGUID + credId).
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
                    "credential_id '{}' not found in trust graph",
                    req.credential_id
                ))
            })?;

            let pk = cose_to_credential_public_key(&cose_bytes)
                .map_err(|e| ServiceError::Fido2(format!("COSE key parse: {e}")))?;
            (sub, pk, rp_id)
        };

        // 2. Verify the assertion signature and enforce WebAuthn flags.
        let parsed = verify_assertion(
            &req.authenticator_data,
            &req.client_data_hash,
            &req.signature,
            &public_key,
        )
        .map_err(|e| ServiceError::Fido2(e.to_string()))?;

        // Enforce user-presence (UP) flag — authenticator must confirm
        // the user is physically present (touch / biometric).
        if !parsed.user_present {
            return Err(ServiceError::Fido2(
                "assertion failed: user_present (UP) flag not set".into(),
            ));
        }

        // Enforce RP ID binding — the rp_id_hash in the assertion's
        // authenticatorData must match SHA-256(enrolled_rp_id). This
        // prevents cross-site assertion replay.
        {
            use sha2::{Digest, Sha256};
            let expected_hash = Sha256::digest(enrolled_rp_id.as_bytes());
            if parsed.rp_id_hash != expected_hash.as_slice() {
                return Err(ServiceError::Fido2(
                    "assertion rp_id_hash does not match enrolled relying party".into(),
                ));
            }
        }

        // Log sign_count for future replay detection. Full enforcement
        // requires per-credential counter persistence (not yet implemented).
        if parsed.sign_count > 0 {
            tracing::debug!(
                credential_id = %req.credential_id,
                sign_count = parsed.sign_count,
                "assertion sign_count (replay detection requires persistent counter)"
            );
        }

        // 3. Issue a session bound to the enrolled subject URN.
        //    The caller's subject_urn is IGNORED — the session is always
        //    issued for the identity that owns the verified credential.
        //    mfa_verified reflects the actual user_verified (UV) flag
        //    from the authenticator, not a caller-supplied claim.
        let session_req = SessionRequest {
            subject_urn,
            device_urn: None,
            requested_resources: vec![],
            duration_secs: req.duration_secs.unwrap_or(3600).min(86400),
            mfa_verified: parsed.user_verified,
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
    pub fn admin_setup(
        &mut self,
        req: AdminSetupRequest,
    ) -> Result<EnrollmentResult, ServiceError> {
        // Step 1: enroll the admin exactly like a normal user.
        // We need the generated identity to persist the signing key,
        // so we inline the enrollment logic here.
        let mut credential_id = req.credential_id.clone();
        if self.verify_fido2 {
            let parsed = dds_domain::fido2::verify_attestation(
                &req.attestation_object,
                &req.client_data_hash,
            )
            .map_err(|e| ServiceError::Fido2(e.to_string()))?;

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
        if let Err(e) = self.persist_trusted_roots() {
            tracing::warn!(error = %e, "failed to persist trusted_roots to config file (in-memory update still applies)");
        }
        tracing::info!(admin_urn = %admin_urn, "admin identity registered and added to trusted roots");

        Ok(EnrollmentResult {
            urn: admin_urn,
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Admin vouches for an enrolled user. The admin proves presence via
    /// FIDO2 assertion. The node verifies the assertion, checks admin is a
    /// trusted root, loads the admin's persisted signing key, and signs a
    /// Vouch token granting the subject the requested purpose.
    pub fn admin_vouch(
        &mut self,
        req: AdminVouchRequest,
    ) -> Result<AdminVouchResult, ServiceError> {
        use dds_domain::fido2::{cose_to_credential_public_key, verify_assertion};

        // 1. Look up admin credential in trust graph (same as session assertion).
        let (admin_urn, public_key) = {
            let g = self
                .trust_graph
                .read()
                .map_err(|e| ServiceError::Trust(format!("trust_graph poisoned: {e}")))?;

            let mut found: Option<(String, Vec<u8>)> = None;
            for token in g.attestations_iter() {
                if g.is_revoked(&token.payload.jti) || g.is_burned(&token.payload.iss) {
                    continue;
                }
                let doc = match UserAuthAttestation::extract(&token.payload) {
                    Ok(Some(d)) => d,
                    _ => continue,
                };
                if doc.credential_id == req.credential_id {
                    let parsed = dds_domain::fido2::verify_attestation(
                        &doc.attestation_object,
                        &doc.client_data_hash,
                    )
                    .map_err(|e| ServiceError::Fido2(format!("re-parse attestation: {e}")))?;
                    let auth_data = &parsed.auth_data;
                    let p = 37 + 16 + 2 + parsed.credential_id.len();
                    let cose_bytes = &auth_data[p..];
                    found = Some((token.payload.sub.clone(), cose_bytes.to_vec()));
                    break;
                }
            }

            let (sub, cose_bytes) = found.ok_or_else(|| {
                ServiceError::Fido2(format!(
                    "admin credential_id '{}' not found in trust graph",
                    req.credential_id
                ))
            })?;

            let pk = cose_to_credential_public_key(&cose_bytes)
                .map_err(|e| ServiceError::Fido2(format!("COSE key parse: {e}")))?;
            (sub, pk)
        };

        // 2. Verify FIDO2 assertion (proves admin touched authenticator).
        let _parsed = verify_assertion(
            &req.authenticator_data,
            &req.client_data_hash,
            &req.signature,
            &public_key,
        )
        .map_err(|e| ServiceError::Fido2(e.to_string()))?;

        // 3. Check admin is a trusted root.
        if !self.trusted_roots.contains(&admin_urn) {
            return Err(ServiceError::Trust(format!(
                "identity '{}' is not a trusted root",
                admin_urn
            )));
        }

        // 4. Load admin's persisted signing key.
        let admin_signing_key = self.load_admin_key(&admin_urn)?;

        // 5. Find the subject's attestation token to compute vch_sum.
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

        // 6. Build and sign the vouch token.
        let purpose = req.purpose.unwrap_or_else(|| "dds:session".to_string());
        let vouch_jti = format!("vouch-{}", rand_u64());
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
    /// The encryption key is derived from SHA-256(node_signing_key || "admin-key-wrap").
    fn store_admin_key(
        &self,
        admin_urn: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ServiceError> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ServiceError::Store("data_dir not set — cannot persist admin keys".to_string())
        })?;
        let dir = data_dir.join("admin_keys");
        std::fs::create_dir_all(&dir)
            .map_err(|e| ServiceError::Store(format!("create admin_keys dir: {e}")))?;

        let wrap_key = self.admin_wrap_key();
        let plaintext = signing_key.to_bytes();

        // Generate random IV (12 bytes) and encrypt with AES-256-GCM.
        let iv: [u8; 12] = {
            let mut buf = [0u8; 12];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        };

        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        let cipher = Aes256Gcm::new_from_slice(&wrap_key)
            .map_err(|e| ServiceError::Store(format!("AES key init: {e}")))?;
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| ServiceError::Store(format!("AES encrypt: {e}")))?;

        // Write: iv (12) || ciphertext+tag (32+16=48)
        let urn_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(admin_urn.as_bytes()))
        };
        let path = dir.join(format!("{urn_hash}.key"));
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ciphertext);
        std::fs::write(&path, &blob)
            .map_err(|e| ServiceError::Store(format!("write admin key: {e}")))?;

        tracing::debug!(path = %path.display(), "persisted admin signing key");
        Ok(())
    }

    /// Load an admin's Ed25519 signing key from encrypted storage.
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
        if blob.len() < 12 + 32 {
            return Err(ServiceError::Store("admin key file too short".to_string()));
        }

        let iv = &blob[..12];
        let ciphertext = &blob[12..];

        let wrap_key = self.admin_wrap_key();
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        let cipher = Aes256Gcm::new_from_slice(&wrap_key)
            .map_err(|e| ServiceError::Store(format!("AES key init: {e}")))?;
        let nonce = Nonce::from_slice(iv);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ServiceError::Store(format!("AES decrypt admin key: {e}")))?;

        if plaintext.len() != 32 {
            return Err(ServiceError::Store(format!(
                "decrypted admin key is {} bytes, expected 32",
                plaintext.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&plaintext);
        Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
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
            jti: format!("attest-{}", ident.id.label()),
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
        (svc, admin, roots)
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

    // Silence the unused-import warning when only some helpers are
    // exercised in this module.
    #[allow(dead_code)]
    fn _used(_: DeviceJoinDocument) {}
}
