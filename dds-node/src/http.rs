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
//! - `POST /v1/session`         -> SessionResponse
//! - `POST /v1/policy/evaluate` -> PolicyResponse
//! - `GET  /v1/status`          -> StatusResponse

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::service::{
    EnrollDeviceRequest, EnrollUserRequest, LocalService, NodeStatus, PolicyResult, ServiceError,
    SessionRequest,
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
        .route("/v1/session", post(issue_session::<S>))
        .route("/v1/policy/evaluate", post(evaluate_policy::<S>))
        .route("/v1/status", get(status::<S>))
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
    base64::engine::general_purpose::STANDARD
        .decode(s)
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

async fn issue_session<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<SessionRequestJson>,
) -> Result<Json<SessionResponse>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let internal = SessionRequest {
        subject_urn: req.subject_urn,
        device_urn: req.device_urn,
        requested_resources: req.requested_resources,
        duration_secs: req.duration_secs,
        mfa_verified: req.mfa_verified,
        tls_binding: req.tls_binding,
    };
    let mut svc = state.svc.lock().await;
    let r = svc.issue_session(internal)?;
    Ok(Json(SessionResponse {
        session_id: r.session_id,
        token_cbor_b64: b64_encode(&r.token_cbor),
        expires_at: r.expires_at,
    }))
}

async fn evaluate_policy<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<PolicyRequestJson>,
) -> Result<Json<PolicyResult>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    let r = svc.evaluate_policy(&req.subject_urn, &req.resource, &req.action);
    Ok(Json(r))
}

async fn status<S>(State(state): State<AppState<S>>) -> Result<Json<NodeStatus>, HttpError>
where
    S: TokenStore + RevocationStore + Send + Sync + 'static,
{
    let svc = state.svc.lock().await;
    Ok(Json(svc.status(&state.info.peer_id, 0, 0)))
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
    use std::collections::BTreeSet;

    fn make_state() -> AppState<MemoryBackend> {
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
        let svc = LocalService::new(node_ident, graph, roots, MemoryBackend::new());
        AppState {
            svc: Arc::new(Mutex::new(svc)),
            info: NodeInfo {
                peer_id: "12D3KooWUnit".into(),
            },
        }
    }

    async fn spawn_server(state: AppState<MemoryBackend>) -> String {
        let app = Router::new()
            .route("/v1/enroll/user", post(enroll_user::<MemoryBackend>))
            .route("/v1/enroll/device", post(enroll_device::<MemoryBackend>))
            .route("/v1/session", post(issue_session::<MemoryBackend>))
            .route(
                "/v1/policy/evaluate",
                post(evaluate_policy::<MemoryBackend>),
            )
            .route("/v1/status", get(status::<MemoryBackend>))
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
    async fn test_session_endpoint_rejects_no_purposes() {
        // Session request for a subject with no granted purposes should fail.
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
        // Without valid vouches, the session should be rejected (500 = domain error).
        assert_eq!(resp.status(), 500);
    }
}
