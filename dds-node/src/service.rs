//! Local authority service — enrollment, sessions, policy resolution, status.
//!
//! This module turns dds-node into the authoritative local service that
//! client applications talk to. It provides:
//! - **Enrollment**: accept device/user join requests, issue attestation tokens
//! - **Session issuance**: create short-lived SessionDocuments (< 1ms local check)
//! - **Policy resolution**: evaluate access decisions against the trust graph
//! - **Status reporting**: health, sync state, peer count, trust stats

use dds_core::identity::Identity;
use dds_core::policy::{PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::{DeviceJoinDocument, DomainDocument, SessionDocument, UserAuthAttestation};
use dds_store::traits::*;
use std::collections::BTreeSet;
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

/// The local authority service.
pub struct LocalService<S: TokenStore + dds_store::traits::RevocationStore> {
    /// Node signing identity (used to issue tokens).
    node_identity: Identity,
    /// Policy engine with loaded rules.
    policy_engine: PolicyEngine,
    /// Trust graph reference.
    trust_graph: TrustGraph,
    /// Trusted root URNs.
    trusted_roots: BTreeSet<String>,
    /// Storage backend.
    store: S,
    /// Node start time.
    start_time: u64,
    /// Whether to verify FIDO2 attestation on enroll_user.
    verify_fido2: bool,
}

impl<S: TokenStore + dds_store::traits::RevocationStore> LocalService<S> {
    /// Create a new local service.
    pub fn new(
        node_identity: Identity,
        trust_graph: TrustGraph,
        trusted_roots: BTreeSet<String>,
        store: S,
    ) -> Self {
        Self {
            node_identity,
            policy_engine: PolicyEngine::new(),
            trust_graph,
            trusted_roots,
            store,
            start_time: now_epoch(),
            verify_fido2: true,
        }
    }

    /// Disable FIDO2 attestation verification (for test scenarios that
    /// pass synthetic enrollment data). Production code paths should
    /// leave this enabled.
    pub fn set_verify_fido2(&mut self, verify: bool) {
        self.verify_fido2 = verify;
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
        if self.verify_fido2 {
            dds_domain::fido2::verify_attestation(&req.attestation_object, &req.client_data_hash)
                .map_err(|e| ServiceError::Fido2(e.to_string()))?;
        }
        let user_ident = Identity::generate(&req.label, &mut rand::rngs::OsRng);
        let doc = UserAuthAttestation {
            credential_id: req.credential_id,
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
        let _ = self.trust_graph.add_token(token.clone());

        Ok(EnrollmentResult {
            urn: user_ident.id.to_urn(),
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Enroll a device.
    pub fn enroll_device(
        &mut self,
        req: EnrollDeviceRequest,
    ) -> Result<EnrollmentResult, ServiceError> {
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
        let _ = self.trust_graph.add_token(token.clone());

        Ok(EnrollmentResult {
            urn: device_ident.id.to_urn(),
            jti: token.payload.jti.clone(),
            token_cbor: cbor,
        })
    }

    /// Issue a short-lived session token.
    pub fn issue_session(&mut self, req: SessionRequest) -> Result<SessionResult, ServiceError> {
        // Resolve granted purposes from trust graph
        let granted = self
            .trust_graph
            .purposes_for(&req.subject_urn, &self.trusted_roots);

        let session_id = format!("sess-{:016x}", rand_u64());
        let expires_at = now_epoch() + req.duration_secs;

        let doc = SessionDocument {
            session_id: session_id.clone(),
            subject_urn: req.subject_urn.clone(),
            device_urn: req.device_urn,
            granted_purposes: granted.into_iter().collect(),
            authorized_resources: req.requested_resources,
            session_start: now_epoch(),
            duration_secs: req.duration_secs,
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
    pub fn evaluate_policy(&self, subject_urn: &str, resource: &str, action: &str) -> PolicyResult {
        let decision = self.policy_engine.evaluate(
            subject_urn,
            resource,
            action,
            &self.trust_graph,
            &self.trusted_roots,
        );
        PolicyResult {
            allowed: decision.is_allowed(),
            reason: format!("{decision}"),
        }
    }

    /// Get node status.
    pub fn status(&self, peer_id: &str, connected_peers: usize, dag_ops: usize) -> NodeStatus {
        NodeStatus {
            peer_id: peer_id.to_string(),
            connected_peers,
            dag_operations: dag_ops,
            trust_graph_tokens: self.trust_graph.token_count(),
            trusted_roots: self.trusted_roots.len(),
            store_tokens: self.store.count_tokens(None).unwrap_or(0),
            store_revoked: self.store.revoked_set().map(|s| s.len()).unwrap_or(0),
            store_burned: self.store.burned_set().map(|s| s.len()).unwrap_or(0),
            uptime_secs: now_epoch() - self.start_time,
        }
    }

    /// Access the trust graph mutably.
    pub fn trust_graph_mut(&mut self) -> &mut TrustGraph {
        &mut self.trust_graph
    }

    /// Access the store mutably.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
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
    Policy(String),
    Fido2(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Token(e) => write!(f, "token error: {e}"),
            ServiceError::Domain(e) => write!(f, "domain error: {e}"),
            ServiceError::Store(e) => write!(f, "store error: {e}"),
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
