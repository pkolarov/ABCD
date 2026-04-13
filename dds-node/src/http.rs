//! Localhost HTTP/JSON API exposing `LocalService` to platform clients.
//!
//! This is the integration surface that lets non-Rust clients (C#, Swift,
//! Kotlin, Python) talk to the node without embedding libp2p. The server
//! is intentionally bound to localhost — authentication for cross-host
//! access is out of scope at this layer (clients should tunnel via mTLS
//! or local IPC).
//!
//! Endpoints:
//! - `POST /v1/enroll/user`     -> EnrollmentResponse
//! - `POST /v1/enroll/device`   -> EnrollmentResponse
//! - `POST /v1/session/assert`  -> SessionResponse (from FIDO2 assertion)
//! - `GET  /v1/enrolled-users`  -> EnrolledUsersResponse
//! - `POST /v1/policy/evaluate` -> PolicyResponse
//! - `GET  /v1/status`          -> StatusResponse
//! - `GET  /v1/windows/policies` / `/software` / `POST /applied`
//! - `GET  /v1/macos/policies` / `/software` / `POST /applied`

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::service::{
    AdminSetupRequest, AdminVouchRequest,
    ApplicableMacOsPolicy, ApplicableSoftware, ApplicableWindowsPolicy, AppliedReport,
    AssertionSessionRequest, EnrollDeviceRequest, EnrollUserRequest, EnrolledUser, LocalService,
    NodeStatus, PolicyResult, ServiceError,
};
use dds_store::traits::{RevocationStore, TokenStore};

/// Shared, mutex-guarded service handle. Per-request handlers acquire
/// the lock for the (very short) duration of the call. The bottleneck
/// is the trust graph mutation, which is already in-memory and fast.
pub type SharedService<S> = Arc<Mutex<LocalService<S>>>;

/// Static node info captured at server start (peer id never changes for the
/// life of the process).
#[derive(Clone)]
pub struct NodeInfo {
    pub peer_id: String,
}

struct AppState<S: TokenStore + RevocationStore + Send + Sync + 'static> {
    svc: SharedService<S>,
    info: NodeInfo,
}

impl<S: TokenStore + RevocationStore + Send + Sync + 'static> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            info: self.info.clone(),
        }
    }
}

/// Build the axum router for the local API.
pub fn router<S>(svc: SharedService<S>, info: NodeInfo) -> Router
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let state = AppState { svc, info };
    Router::new()
        .route("/v1/enroll/user", post(enroll_user::<S>))
        .route("/v1/enroll/device", post(enroll_device::<S>))
        // NOTE: The unauthenticated POST /v1/session endpoint has been
        // removed. Session issuance now requires FIDO2 proof-of-possession
        // via /v1/session/assert. The internal `issue_session` method is
        // still available for use by `issue_session_from_assertion`.
        .route("/v1/session/assert", post(issue_session_assert::<S>))
        .route("/v1/enrolled-users", get(list_enrolled_users::<S>))
        .route("/v1/admin/setup", post(admin_setup::<S>))
        .route("/v1/admin/vouch", post(admin_vouch::<S>))
        .route("/v1/policy/evaluate", post(evaluate_policy::<S>))
        .route("/v1/status", get(status::<S>))
        .route("/v1/windows/policies", get(list_windows_policies::<S>))
        .route("/v1/windows/software", get(list_windows_software::<S>))
        .route("/v1/windows/applied", post(record_windows_applied::<S>))
        .route("/v1/macos/policies", get(list_macos_policies::<S>))
        .route("/v1/macos/software", get(list_macos_software::<S>))
        .route("/v1/macos/applied", post(record_macos_applied::<S>))
        .with_state(state)
}

// ---------- request/response types ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollUserRequestJson {
    pub label: String,
    pub credential_id: String,
    /// Base64-standard-encoded WebAuthn attestation object.
    pub attestation_object_b64: String,
    /// Base64-standard-encoded SHA-256(clientDataJSON).
    pub client_data_hash_b64: String,
    pub rp_id: String,
    pub display_name: String,
    pub authenticator_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollDeviceRequestJson {
    pub label: String,
    pub device_id: String,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub tpm_ek_hash: Option<String>,
    pub org_unit: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub urn: String,
    pub jti: String,
    pub token_cbor_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRequestJson {
    pub subject_urn: String,
    pub device_urn: Option<String>,
    #[serde(default)]
    pub requested_resources: Vec<String>,
    pub duration_secs: u64,
    #[serde(default)]
    pub mfa_verified: bool,
    pub tls_binding: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub token_cbor_b64: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRequestJson {
    pub subject_urn: String,
    pub resource: String,
    pub action: String,
}

// ---------- Credential Provider types (Phase III) ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionSessionRequestJson {
    pub subject_urn: Option<String>,
    pub credential_id: String,
    pub client_data_hash: String,
    pub authenticator_data: String,
    pub signature: String,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminVouchRequestJson {
    pub subject_urn: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_hash: String,
    pub signature: String,
    pub purpose: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminVouchResponseJson {
    pub vouch_jti: String,
    pub subject_urn: String,
    pub admin_urn: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolledUsersResponse {
    pub users: Vec<EnrolledUser>,
}

// ---------- Windows applier types (Phase 3 items 9–10) ----------

/// Query string for the two windows-listing endpoints.
#[derive(Debug, Deserialize)]
pub struct DeviceUrnQuery {
    pub device_urn: String,
}

/// Response wrapping a list of windows policies for a device.
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowsPoliciesResponse {
    pub policies: Vec<ApplicableWindowsPolicy>,
}

/// Response wrapping a list of macOS policies for a device.
#[derive(Debug, Serialize, Deserialize)]
pub struct MacOsPoliciesResponse {
    pub policies: Vec<ApplicableMacOsPolicy>,
}

/// Response wrapping a list of software assignments for a device.
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowsSoftwareResponse {
    pub software: Vec<ApplicableSoftware>,
}

/// Response wrapping a list of software assignments for a macOS device.
#[derive(Debug, Serialize, Deserialize)]
pub struct MacOsSoftwareResponse {
    pub software: Vec<ApplicableSoftware>,
}

// ---------- error type ----------

pub struct HttpError {
    pub status: StatusCode,
    pub message: String,
}

impl HttpError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
}

impl From<ServiceError> for HttpError {
    fn from(e: ServiceError) -> Self {
        let status = match e {
            ServiceError::Fido2(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: e.to_string(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}

fn b64_decode(s: &str, field: &str) -> Result<Vec<u8>, HttpError> {
    // Accept both standard base64 and base64url (the Windows WebAuthn API
    // callers send base64url while the Rust tests use standard base64).
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| HttpError::bad_request(format!("invalid base64 in {field}: {e}")))
}

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

// ---------- handlers ----------

async fn enroll_user<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<EnrollUserRequestJson>,
) -> Result<Json<EnrollmentResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let attestation_object = b64_decode(&req.attestation_object_b64, "attestation_object_b64")?;
    let client_data_hash = b64_decode(&req.client_data_hash_b64, "client_data_hash_b64")?;
    let internal = EnrollUserRequest {
        label: req.label,
        credential_id: req.credential_id,
        attestation_object,
        client_data_hash,
        rp_id: req.rp_id,
        display_name: req.display_name,
        authenticator_type: req.authenticator_type,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.enroll_user(internal)?;
    Ok(Json(EnrollmentResponse {
        urn: r.urn,
        jti: r.jti,
        token_cbor_b64: b64_encode(&r.token_cbor),
    }))
}

async fn enroll_device<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<EnrollDeviceRequestJson>,
) -> Result<Json<EnrollmentResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let internal = EnrollDeviceRequest {
        label: req.label,
        device_id: req.device_id,
        hostname: req.hostname,
        os: req.os,
        os_version: req.os_version,
        tpm_ek_hash: req.tpm_ek_hash,
        org_unit: req.org_unit,
        tags: req.tags,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.enroll_device(internal)?;
    Ok(Json(EnrollmentResponse {
        urn: r.urn,
        jti: r.jti,
        token_cbor_b64: b64_encode(&r.token_cbor),
    }))
}

// The unauthenticated `issue_session` HTTP handler has been removed.
// Session issuance now requires FIDO2 proof-of-possession via
// POST /v1/session/assert. The `SessionRequestJson` type is kept
// for internal use by the assertion flow.

async fn evaluate_policy<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<PolicyRequestJson>,
) -> Result<Json<PolicyResult>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let r = svc.evaluate_policy(&req.subject_urn, &req.resource, &req.action)?;
    Ok(Json(r))
}

async fn status<S>(State(state): State<AppState<S>>) -> Result<Json<NodeStatus>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    Ok(Json(svc.status(&state.info.peer_id, 0, 0)?))
}

// ---------- Credential Provider handlers (Phase III) ----------

async fn issue_session_assert<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<AssertionSessionRequestJson>,
) -> Result<Json<SessionResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let internal = AssertionSessionRequest {
        subject_urn: req.subject_urn,
        credential_id: req.credential_id,
        client_data_hash: b64_decode(&req.client_data_hash, "client_data_hash")?,
        authenticator_data: b64_decode(&req.authenticator_data, "authenticator_data")?,
        signature: b64_decode(&req.signature, "signature")?,
        duration_secs: req.duration_secs,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.issue_session_from_assertion(internal)?;
    Ok(Json(SessionResponse {
        session_id: r.session_id,
        token_cbor_b64: b64_encode(&r.token_cbor),
        expires_at: r.expires_at,
    }))
}

async fn list_enrolled_users<S>(
    State(state): State<AppState<S>>,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<EnrolledUsersResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let users = svc.list_enrolled_users(&q.device_urn)?;
    Ok(Json(EnrolledUsersResponse { users }))
}

// ---------- Admin enrollment + vouch handlers ----------

async fn admin_setup<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<EnrollUserRequestJson>,
) -> Result<Json<EnrollmentResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let attestation_object = b64_decode(&req.attestation_object_b64, "attestation_object_b64")?;
    let client_data_hash = b64_decode(&req.client_data_hash_b64, "client_data_hash_b64")?;
    let internal = AdminSetupRequest {
        label: req.label,
        credential_id: req.credential_id,
        attestation_object,
        client_data_hash,
        rp_id: req.rp_id,
        display_name: req.display_name,
        authenticator_type: req.authenticator_type,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.admin_setup(internal)?;
    Ok(Json(EnrollmentResponse {
        urn: r.urn,
        jti: r.jti,
        token_cbor_b64: b64_encode(&r.token_cbor),
    }))
}

async fn admin_vouch<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<AdminVouchRequestJson>,
) -> Result<Json<AdminVouchResponseJson>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let internal = AdminVouchRequest {
        subject_urn: req.subject_urn,
        credential_id: req.credential_id,
        client_data_hash: b64_decode(&req.client_data_hash, "client_data_hash")?,
        authenticator_data: b64_decode(&req.authenticator_data, "authenticator_data")?,
        signature: b64_decode(&req.signature, "signature")?,
        purpose: req.purpose,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.admin_vouch(internal)?;
    Ok(Json(AdminVouchResponseJson {
        vouch_jti: r.vouch_jti,
        subject_urn: r.subject_urn,
        admin_urn: r.admin_urn,
    }))
}

// ---------- Windows applier handlers (Phase 3 items 9–10) ----------

async fn list_windows_policies<S>(
    State(state): State<AppState<S>>,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<WindowsPoliciesResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let policies = svc.list_applicable_windows_policies(&q.device_urn)?;
    Ok(Json(WindowsPoliciesResponse { policies }))
}

async fn list_windows_software<S>(
    State(state): State<AppState<S>>,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<WindowsSoftwareResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let software = svc.list_applicable_software(&q.device_urn)?;
    Ok(Json(WindowsSoftwareResponse { software }))
}

async fn record_windows_applied<S>(
    State(state): State<AppState<S>>,
    Json(report): Json<AppliedReport>,
) -> Result<StatusCode, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    svc.record_applied(&report)?;
    Ok(StatusCode::ACCEPTED)
}

async fn list_macos_policies<S>(
    State(state): State<AppState<S>>,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<MacOsPoliciesResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let policies = svc.list_applicable_macos_policies(&q.device_urn)?;
    Ok(Json(MacOsPoliciesResponse { policies }))
}

async fn list_macos_software<S>(
    State(state): State<AppState<S>>,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<MacOsSoftwareResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let software = svc.list_applicable_software(&q.device_urn)?;
    Ok(Json(MacOsSoftwareResponse { software }))
}

async fn record_macos_applied<S>(
    State(state): State<AppState<S>>,
    Json(report): Json<AppliedReport>,
) -> Result<StatusCode, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    svc.record_applied(&report)?;
    Ok(StatusCode::ACCEPTED)
}

/// Bind and serve the HTTP API on `addr` until the future is dropped.
pub async fn serve<S>(
    addr: &str,
    svc: SharedService<S>,
    info: NodeInfo,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP API listening");
    axum::serve(listener, router(svc, info)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::LocalService;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_core::trust::TrustGraph;
    use dds_domain::fido2::build_none_attestation;
    use dds_store::MemoryBackend;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sha2::Digest;
    use std::collections::BTreeSet;

    struct TestState {
        app: AppState<MemoryBackend>,
        root: Identity,
    }

    fn make_state() -> AppState<MemoryBackend> {
        make_state_with_root().app
    }

    fn make_state_with_root() -> TestState {
        let node_ident = Identity::generate("test-node", &mut OsRng);
        let root = Identity::generate("root", &mut OsRng);
        let mut roots = BTreeSet::new();
        roots.insert(root.id.to_urn());
        let mut graph = TrustGraph::new();
        let attest = Token::sign(
            TokenPayload {
                iss: root.id.to_urn(),
                iss_key: root.public_key.clone(),
                jti: "attest-root".into(),
                sub: root.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1000,
                exp: Some(4102444800),
                body_type: None,
                body_cbor: None,
            },
            &root.signing_key,
        )
        .unwrap();
        graph.add_token(attest).unwrap();
        let shared_graph = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let svc = LocalService::new(node_ident, shared_graph, roots, MemoryBackend::new());
        TestState {
            app: AppState {
                svc: Arc::new(Mutex::new(svc)),
                info: NodeInfo {
                    peer_id: "12D3KooWUnit".into(),
                },
            },
            root,
        }
    }

    /// Add a vouch from root granting a purpose to the subject URN.
    /// Looks up the subject's attestation token in the graph to get the
    /// vch_sum hash required by the trust graph.
    async fn vouch_user(state: &AppState<MemoryBackend>, root: &Identity, subject_urn: &str) {
        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();

        // Find the subject's attestation token to get its payload hash.
        let attest_hash = g
            .attestations_iter()
            .find(|t| t.payload.sub == subject_urn)
            .map(|t| t.payload_hash())
            .expect("subject attestation not found in graph");

        let vouch = Token::sign(
            TokenPayload {
                iss: root.id.to_urn(),
                iss_key: root.public_key.clone(),
                jti: format!("vouch-{subject_urn}"),
                sub: subject_urn.to_string(),
                kind: TokenKind::Vouch,
                purpose: Some("dds:session".to_string()),
                vch_iss: Some(subject_urn.to_string()),
                vch_sum: Some(attest_hash),
                revokes: None,
                iat: 1000,
                exp: Some(4102444800),
                body_type: None,
                body_cbor: None,
            },
            &root.signing_key,
        )
        .unwrap();
        g.add_token(vouch).unwrap();
    }

    async fn spawn_server(state: AppState<MemoryBackend>) -> String {
        let app = Router::new()
            .route("/v1/enroll/user", post(enroll_user::<MemoryBackend>))
            .route("/v1/enroll/device", post(enroll_device::<MemoryBackend>))
            .route(
                "/v1/session/assert",
                post(issue_session_assert::<MemoryBackend>),
            )
            .route(
                "/v1/enrolled-users",
                get(list_enrolled_users::<MemoryBackend>),
            )
            .route(
                "/v1/policy/evaluate",
                post(evaluate_policy::<MemoryBackend>),
            )
            .route("/v1/status", get(status::<MemoryBackend>))
            .route(
                "/v1/windows/policies",
                get(list_windows_policies::<MemoryBackend>),
            )
            .route(
                "/v1/windows/software",
                get(list_windows_software::<MemoryBackend>),
            )
            .route(
                "/v1/windows/applied",
                post(record_windows_applied::<MemoryBackend>),
            )
            .route(
                "/v1/macos/policies",
                get(list_macos_policies::<MemoryBackend>),
            )
            .route(
                "/v1/macos/software",
                get(list_macos_software::<MemoryBackend>),
            )
            .route(
                "/v1/macos/applied",
                post(record_macos_applied::<MemoryBackend>),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let state = make_state();
        let base = spawn_server(state).await;
        let resp = reqwest::get(format!("{base}/v1/status")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: NodeStatus = resp.json().await.unwrap();
        assert_eq!(body.peer_id, "12D3KooWUnit");
        assert_eq!(body.trusted_roots, 1);
    }

    #[tokio::test]
    async fn test_enroll_user_endpoint_valid() {
        let state = make_state();
        let base = spawn_server(state).await;
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_none_attestation("example.com", b"cred-x", &sk.verifying_key());
        let req = EnrollUserRequestJson {
            label: "alice".into(),
            credential_id: "cred-x".into(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "example.com".into(),
            display_name: "Alice".into(),
            authenticator_type: "platform".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: EnrollmentResponse = resp.json().await.unwrap();
        assert!(body.urn.starts_with("urn:vouchsafe:alice."));
    }

    #[tokio::test]
    async fn test_enroll_user_endpoint_rejects_garbage() {
        let state = make_state();
        let base = spawn_server(state).await;
        let req = EnrollUserRequestJson {
            label: "alice".into(),
            credential_id: "cred-x".into(),
            attestation_object_b64: b64_encode(&[0u8, 1, 2]),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "example.com".into(),
            display_name: "Alice".into(),
            authenticator_type: "platform".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_evaluate_policy_endpoint() {
        let state = make_state();
        let base = spawn_server(state).await;
        let req = PolicyRequestJson {
            subject_urn: "urn:vouchsafe:nobody.zzz".into(),
            resource: "repo:main".into(),
            action: "read".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/policy/evaluate"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: PolicyResult = resp.json().await.unwrap();
        assert!(!body.allowed);
    }

    #[tokio::test]
    async fn test_session_endpoint_removed() {
        // The unauthenticated POST /v1/session endpoint has been removed.
        // Session issuance now requires FIDO2 proof via /v1/session/assert.
        let state = make_state();
        let base = spawn_server(state).await;
        let req = SessionRequestJson {
            subject_urn: "urn:vouchsafe:alice.hash".into(),
            device_urn: None,
            requested_resources: vec!["repo:main".into()],
            duration_secs: 600,
            mfa_verified: true,
            tls_binding: None,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session"))
            .json(&req)
            .send()
            .await
            .unwrap();
        // Endpoint removed — expect 404 Not Found.
        assert_eq!(resp.status(), 404);
    }

    // ----------------------------------------------------------------
    // Credential Provider endpoints (Phase III)
    // ----------------------------------------------------------------

    /// Enroll a user via attestation, then authenticate via assertion
    /// and verify a session is issued. End-to-end CP flow.
    #[tokio::test]
    async fn test_session_assert_ed25519_roundtrip() {
        use dds_domain::fido2::{build_assertion_auth_data, build_none_attestation};
        use ed25519_dalek::Signer;

        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        // 1. Enroll a user with an Ed25519 credential.
        let sk = SigningKey::generate(&mut OsRng);
        let cred_id = b"cred-assert-test";
        let attestation = build_none_attestation("dds.local", cred_id, &sk.verifying_key());
        // enroll_user base64url-encodes the raw credential_id from the
        // attestation object, so the stored credential_id in the trust
        // graph is base64url(b"cred-assert-test"), not the raw string.
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id);
        let enroll_req = EnrollUserRequestJson {
            label: "bob".into(),
            credential_id: cred_id_b64.clone(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "dds.local".into(),
            display_name: "Bob".into(),
            authenticator_type: "platform".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&enroll_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let enrolled: EnrollmentResponse = resp.json().await.unwrap();

        // 1b. Root vouches for the enrolled user so they have purposes.
        vouch_user(&state, &ts.root, &enrolled.urn).await;

        // 2. Build a FIDO2 assertion signed by the same key.
        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = sha2::Sha256::digest(b"test-client-data-json");
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&cdh);
        let sig = sk.sign(&signed_msg);

        // 3. POST /v1/session/assert — use the base64url credential_id
        //    that matches what enroll_user stored in the trust graph.
        let assert_req = AssertionSessionRequestJson {
            subject_urn: Some(enrolled.urn.clone()),
            credential_id: cred_id_b64,
            client_data_hash: b64_encode(&cdh),
            authenticator_data: b64_encode(&auth_data),
            signature: b64_encode(&sig.to_bytes()),
            duration_secs: Some(1800),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&assert_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "session/assert failed");
        let session: SessionResponse = resp.json().await.unwrap();
        assert!(session.session_id.starts_with("sess-"));
        assert!(!session.token_cbor_b64.is_empty());
    }

    /// Assertion with wrong key should be rejected.
    #[tokio::test]
    async fn test_session_assert_rejects_wrong_key() {
        use dds_domain::fido2::{build_assertion_auth_data, build_none_attestation};
        use ed25519_dalek::Signer;

        let state = make_state();
        let base = spawn_server(state).await;

        // Enroll with key A.
        let sk_a = SigningKey::generate(&mut OsRng);
        let cred_bytes = b"cred-wrong";
        let attestation = build_none_attestation("dds.local", cred_bytes, &sk_a.verifying_key());
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let enroll_req = EnrollUserRequestJson {
            label: "carol".into(),
            credential_id: cred_id_b64.clone(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "dds.local".into(),
            display_name: "Carol".into(),
            authenticator_type: "platform".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&enroll_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Sign assertion with key B (wrong key).
        let sk_b = SigningKey::generate(&mut OsRng);
        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = [0xABu8; 32];
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&cdh);
        let sig = sk_b.sign(&signed_msg);

        let assert_req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: cred_id_b64,
            client_data_hash: b64_encode(&cdh),
            authenticator_data: b64_encode(&auth_data),
            signature: b64_encode(&sig.to_bytes()),
            duration_secs: None,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&assert_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    /// Assertion with unknown credential_id should be rejected.
    #[tokio::test]
    async fn test_session_assert_rejects_unknown_credential() {
        use dds_domain::fido2::build_assertion_auth_data;
        use ed25519_dalek::Signer;

        let state = make_state();
        let base = spawn_server(state).await;

        let sk = SigningKey::generate(&mut OsRng);
        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = [0u8; 32];
        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&cdh);
        let sig = sk.sign(&signed_msg);

        let assert_req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: "nonexistent-cred".into(),
            client_data_hash: b64_encode(&cdh),
            authenticator_data: b64_encode(&auth_data),
            signature: b64_encode(&sig.to_bytes()),
            duration_secs: None,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&assert_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    /// GET /v1/enrolled-users returns enrolled user attestations.
    #[tokio::test]
    async fn test_enrolled_users_endpoint() {
        use dds_domain::fido2::build_none_attestation;

        let state = make_state();
        let base = spawn_server(state).await;

        // Initially empty.
        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/enrolled-users"))
            .query(&[("device_urn", "")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: EnrolledUsersResponse = resp.json().await.unwrap();
        assert_eq!(body.users.len(), 0);

        // Enroll two users.
        for (name, cred) in [("alice", "cred-a"), ("bob", "cred-b")] {
            let sk = SigningKey::generate(&mut OsRng);
            let attestation =
                build_none_attestation("dds.local", cred.as_bytes(), &sk.verifying_key());
            let cred_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred.as_bytes());
            let enroll_req = EnrollUserRequestJson {
                label: name.into(),
                credential_id: cred_b64,
                attestation_object_b64: b64_encode(&attestation),
                client_data_hash_b64: b64_encode(&[0u8; 32]),
                rp_id: "dds.local".into(),
                display_name: name.to_uppercase(),
                authenticator_type: "platform".into(),
            };
            let resp = reqwest::Client::new()
                .post(format!("{base}/v1/enroll/user"))
                .json(&enroll_req)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }

        // Now should return 2 users.
        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/enrolled-users"))
            .query(&[("device_urn", "")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: EnrolledUsersResponse = resp.json().await.unwrap();
        assert_eq!(body.users.len(), 2);
        let names: Vec<&str> = body.users.iter().map(|u| u.display_name.as_str()).collect();
        assert!(names.contains(&"ALICE"));
        assert!(names.contains(&"BOB"));
        assert!(body.users.iter().all(|u| !u.credential_id.is_empty()));
    }

    // ----------------------------------------------------------------
    // Windows applier endpoints (Phase 3 items 9–10)
    // ----------------------------------------------------------------

    /// Seed the test state with a device join + a policy and software
    /// assignment that target it via the `dev-machine` tag, then return
    /// the device URN. Used by the three windows endpoint tests below.
    async fn seed_windows_state(state: &AppState<MemoryBackend>) -> String {
        use crate::service::EnrollDeviceRequest;
        use dds_core::token::{Token, TokenKind, TokenPayload};
        use dds_domain::{
            DomainDocument, Enforcement, InstallAction, PolicyScope, RegistryAction,
            RegistryDirective, RegistryHive, RegistryValue, SoftwareAssignment,
            WindowsPolicyDocument, WindowsSettings,
        };

        // Enroll the target device.
        let device_urn = {
            let mut svc = state.svc.lock().await;
            svc.set_verify_fido2(false);
            svc.enroll_device(EnrollDeviceRequest {
                label: "ws".into(),
                device_id: "hw-1".into(),
                hostname: "ws-1".into(),
                os: "Windows 10".into(),
                os_version: "1809".into(),
                tpm_ek_hash: None,
                org_unit: None,
                tags: vec!["dev-machine".into()],
            })
            .unwrap()
            .urn
        };

        // Mint a self-signed admin identity that publishes the policy
        // and software docs into the trust graph. Mirrors the in-tree
        // pattern from `service::windows_applier_tests`.
        let admin = Identity::generate("admin", &mut OsRng);
        let mut payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: "p-baseline".into(),
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
        let policy = WindowsPolicyDocument {
            policy_id: "security/baseline".into(),
            display_name: "Baseline".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope: PolicyScope {
                device_tags: vec!["dev-machine".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
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
        };
        policy.embed(&mut payload).unwrap();
        let policy_token = Token::sign(payload, &admin.signing_key).unwrap();

        let mut sw_payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: "sw-editor".into(),
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
        let pkg = SoftwareAssignment {
            package_id: "com.example.editor".into(),
            display_name: "Editor".into(),
            version: "1.0.0".into(),
            source: "https://cdn.example.com/editor-1.0.0.msi".into(),
            sha256: "deadbeef".into(),
            action: InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["dev-machine".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
        };
        pkg.embed(&mut sw_payload).unwrap();
        let sw_token = Token::sign(sw_payload, &admin.signing_key).unwrap();

        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();
        g.add_token(policy_token).unwrap();
        g.add_token(sw_token).unwrap();
        device_urn
    }

    /// Seed the test state with a macOS device join + a macOS policy and
    /// software assignment that target it via the `mac-laptop` tag.
    async fn seed_macos_state(state: &AppState<MemoryBackend>) -> String {
        use crate::service::EnrollDeviceRequest;
        use dds_core::token::{Token, TokenKind, TokenPayload};
        use dds_domain::{
            DomainDocument, Enforcement, InstallAction, MacOsPolicyDocument, MacOsSettings,
            PolicyScope, PreferenceAction, PreferenceDirective, PreferenceScope,
            SoftwareAssignment,
        };
        use serde_json::json;

        let device_urn = {
            let mut svc = state.svc.lock().await;
            svc.set_verify_fido2(false);
            svc.enroll_device(EnrollDeviceRequest {
                label: "mac".into(),
                device_id: "hw-mac-1".into(),
                hostname: "mbp-1".into(),
                os: "macOS".into(),
                os_version: "15.4".into(),
                tpm_ek_hash: None,
                org_unit: Some("engineering".into()),
                tags: vec!["mac-laptop".into()],
            })
            .unwrap()
            .urn
        };

        let admin = Identity::generate("admin-mac", &mut OsRng);
        let mut payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: "mac-policy-baseline".into(),
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
        let policy = MacOsPolicyDocument {
            policy_id: "security/screensaver".into(),
            display_name: "Screensaver".into(),
            version: 3,
            enforcement: Enforcement::Audit,
            scope: PolicyScope {
                device_tags: vec!["mac-laptop".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
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
        };
        policy.embed(&mut payload).unwrap();
        let policy_token = Token::sign(payload, &admin.signing_key).unwrap();

        let mut sw_payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: "mac-sw-editor".into(),
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
        let pkg = SoftwareAssignment {
            package_id: "com.example.maceditor".into(),
            display_name: "Mac Editor".into(),
            version: "2.1.0".into(),
            source: "https://cdn.example.com/editor-2.1.0.pkg".into(),
            sha256: "cafebabe".into(),
            action: InstallAction::Install,
            scope: PolicyScope {
                device_tags: vec!["mac-laptop".into()],
                org_units: vec![],
                identity_urns: vec![],
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
        };
        pkg.embed(&mut sw_payload).unwrap();
        let sw_token = Token::sign(sw_payload, &admin.signing_key).unwrap();

        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();
        g.add_token(policy_token).unwrap();
        g.add_token(sw_token).unwrap();
        device_urn
    }

    #[tokio::test]
    async fn test_windows_policies_endpoint_returns_typed_bundle() {
        let state = make_state();
        let device_urn = seed_windows_state(&state).await;
        let base = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/windows/policies"))
            .query(&[("device_urn", &device_urn)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: WindowsPoliciesResponse = resp.json().await.unwrap();
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.policies[0].document.policy_id, "security/baseline");
        let bundle = body.policies[0].document.windows.as_ref().unwrap();
        assert_eq!(bundle.registry.len(), 1);
        assert_eq!(bundle.registry[0].key, "SOFTWARE\\Test");
    }

    #[tokio::test]
    async fn test_windows_software_endpoint_filters_by_scope() {
        let state = make_state();
        let device_urn = seed_windows_state(&state).await;
        let base = spawn_server(state).await;

        // Matching device → 1 hit.
        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/windows/software"))
            .query(&[("device_urn", &device_urn)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: WindowsSoftwareResponse = resp.json().await.unwrap();
        assert_eq!(body.software.len(), 1);
        assert_eq!(body.software[0].document.package_id, "com.example.editor");

        // Unknown device URN (not enrolled, so no tags) → 0 hits.
        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/windows/software"))
            .query(&[("device_urn", "urn:vouchsafe:nobody.zzz")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: WindowsSoftwareResponse = resp.json().await.unwrap();
        assert_eq!(body.software.len(), 0);
    }

    #[tokio::test]
    async fn test_windows_applied_endpoint_accepts_report() {
        let state = make_state();
        let base = spawn_server(state).await;
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:dev.xxx".into(),
            target_id: "security/baseline".into(),
            version: "1".into(),
            status: crate::service::AppliedStatus::Ok,
            directives: vec!["registry: HKLM\\SOFTWARE\\Test\\Enabled = 1".into()],
            error: None,
            applied_at: 1_700_000_000,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/windows/applied"))
            .json(&report)
            .send()
            .await
            .unwrap();
        // 202 Accepted — the report is logged; persistent applier audit
        // is intentionally a v2 follow-up (see service.rs::record_applied).
        assert_eq!(resp.status(), 202);
    }

    #[tokio::test]
    async fn test_macos_policies_endpoint_returns_typed_bundle() {
        let state = make_state();
        let device_urn = seed_macos_state(&state).await;
        let base = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/macos/policies"))
            .query(&[("device_urn", &device_urn)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: MacOsPoliciesResponse = resp.json().await.unwrap();
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.policies[0].document.policy_id, "security/screensaver");
        let bundle = body.policies[0].document.macos.as_ref().unwrap();
        assert_eq!(bundle.preferences.len(), 1);
        assert_eq!(bundle.preferences[0].domain, "com.apple.screensaver");
    }

    #[tokio::test]
    async fn test_macos_software_endpoint_filters_by_scope() {
        let state = make_state();
        let device_urn = seed_macos_state(&state).await;
        let base = spawn_server(state).await;

        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/macos/software"))
            .query(&[("device_urn", &device_urn)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: MacOsSoftwareResponse = resp.json().await.unwrap();
        assert_eq!(body.software.len(), 1);
        assert_eq!(
            body.software[0].document.package_id,
            "com.example.maceditor"
        );

        let resp = reqwest::Client::new()
            .get(format!("{base}/v1/macos/software"))
            .query(&[("device_urn", "urn:vouchsafe:nobody.zzz")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: MacOsSoftwareResponse = resp.json().await.unwrap();
        assert_eq!(body.software.len(), 0);
    }

    #[tokio::test]
    async fn test_macos_applied_endpoint_accepts_report() {
        let state = make_state();
        let base = spawn_server(state).await;
        let report = AppliedReport {
            device_urn: "urn:vouchsafe:mac.xxx".into(),
            target_id: "security/screensaver".into(),
            version: "3".into(),
            status: crate::service::AppliedStatus::Skipped,
            directives: vec!["preference: com.apple.screensaver idleTime".into()],
            error: None,
            applied_at: 1_700_000_000,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/macos/applied"))
            .json(&report)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);
    }
}
