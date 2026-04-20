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
//! - `POST /v1/windows/claim-account`
//! - `GET  /v1/macos/policies` / `/software` / `POST /applied`

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::config::ApiAuthConfig;
use crate::device_binding::{BindingOutcome, CallerPrincipal, DeviceBindingStore};
use crate::service::{
    AdminSetupRequest, AdminVouchRequest, ApplicableMacOsPolicy, ApplicableSoftware,
    ApplicableWindowsPolicy, AppliedReport, AssertionSessionRequest, EnrollDeviceRequest,
    EnrollUserRequest, EnrolledUser, LocalService, NodeStatus, PolicyResult, ServiceError,
};
use dds_store::traits::{
    AuditStore, ChallengeStore, CredentialStateStore, RevocationStore, TokenStore,
};

/// **H-7 (security review)** — caller identity derived from the
/// transport layer. Populated per-connection by the listener; absent
/// on loopback TCP (the current production transport), in which case
/// the middleware treats the caller as [`CallerIdentity::Anonymous`].
///
/// Once the node listens on a Unix domain socket (G1-S2) or Windows
/// named pipe (G1-S3) the transport extracts peer credentials via
/// `SO_PEERCRED` / `getpeereid` or `GetNamedPipeClientProcessId` and
/// inserts the resulting `CallerIdentity` as a request extension.
/// Handlers and middleware then read it through
/// `req.extensions().get::<CallerIdentity>()`.
#[derive(Clone, Debug)]
pub enum CallerIdentity {
    /// No peer-credential info was available (loopback TCP).
    /// Admitted to admin endpoints only while
    /// [`AdminPolicy::trust_loopback_tcp_admin`] is `true`.
    Anonymous,
    /// UDS caller on Unix. `uid`/`gid` come from `SO_PEERCRED` (Linux)
    /// or `getpeereid` (macOS); `pid` is informational.
    #[cfg(unix)]
    Uds { uid: u32, gid: u32, pid: i32 },
    /// Named-pipe caller on Windows. `sid` is the caller's primary
    /// **user** SID in string form (`S-1-5-21-...` for domain /
    /// local-account users, or a service SID like `S-1-5-18` for
    /// `SYSTEM`). This is NOT a group SID — `BUILTIN\Administrators`
    /// (`S-1-5-32-544`) never appears here even for elevated admin
    /// users, because their primary SID is their individual user
    /// account, not the group. Group-membership-based admission
    /// (e.g., "any member of `Administrators`") will require the
    /// pipe listener (G1-S3) to surface `TokenGroups` separately;
    /// until then, admins must be listed explicitly in
    /// [`AdminPolicy::admin_sids`].
    #[cfg(windows)]
    Pipe { sid: String, pid: u32 },
}

#[async_trait::async_trait]
impl<S> axum::extract::FromRequestParts<S> for CallerIdentity
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<CallerIdentity>()
            .cloned()
            .unwrap_or(CallerIdentity::Anonymous))
    }
}

impl CallerIdentity {
    /// Returns true if the caller is authorized to reach admin-gated
    /// endpoints under the given policy.
    pub fn is_admin(&self, policy: &AdminPolicy) -> bool {
        match self {
            CallerIdentity::Anonymous => policy.trust_loopback_tcp_admin,
            #[cfg(unix)]
            CallerIdentity::Uds { uid, .. } => {
                *uid == 0 || policy.service_uid == Some(*uid) || policy.admin_uids.contains(uid)
            }
            #[cfg(windows)]
            CallerIdentity::Pipe { sid, .. } => {
                // `S-1-5-18` (`LocalSystem`) is a valid **primary**
                // SID for a service process, and the dds-node service
                // typically runs under it, so it's the one built-in
                // value we admit. We deliberately do NOT fast-path
                // `S-1-5-32-544` (`BUILTIN\Administrators`) here:
                // that's a group SID, never a caller's primary SID,
                // so the match would be dead code and the promise
                // that "elevated admin users are admitted" would be
                // a lie. Group-membership checks need the pipe
                // listener (G1-S3) to expose `TokenGroups`; until
                // then admins must be allowlisted by their primary
                // user SID in `admin_sids`.
                const SYSTEM_SID: &str = "S-1-5-18";
                sid == SYSTEM_SID || policy.admin_sids.iter().any(|s| s == sid)
            }
        }
    }
}

/// Runtime policy derived from [`ApiAuthConfig`] plus ambient info
/// (service UID on Unix). Cloned into the admin middleware's state.
#[derive(Clone, Debug)]
pub struct AdminPolicy {
    pub trust_loopback_tcp_admin: bool,
    pub admin_uids: Vec<u32>,
    pub admin_sids: Vec<String>,
    /// Effective UID of the dds-node process on Unix. Populated by
    /// [`AdminPolicy::from_config`]; always admitted. `None` on
    /// Windows or if the current UID cannot be determined.
    pub service_uid: Option<u32>,
}

impl AdminPolicy {
    /// Construct from config. On Unix the current process's effective
    /// UID is captured so that admin endpoints remain reachable to
    /// the dds-node service account without requiring an explicit
    /// entry in `unix_admin_uids`.
    pub fn from_config(cfg: &ApiAuthConfig) -> Self {
        #[cfg(unix)]
        let service_uid = {
            // Safety: `geteuid` has no preconditions and is always
            // safe to call.
            let uid = unsafe { libc::geteuid() };
            Some(uid)
        };
        #[cfg(not(unix))]
        let service_uid = None;

        Self {
            trust_loopback_tcp_admin: cfg.trust_loopback_tcp_admin,
            admin_uids: cfg.unix_admin_uids.clone(),
            admin_sids: cfg.windows_admin_sids.clone(),
            service_uid,
        }
    }
}

// ---------- M-8: device-caller binding helpers ----------

/// Read-side check for M-8. Admits a request against `device_urn`
/// when:
/// - the caller is an admin under the policy (operator inspecting a
///   peer), or
/// - the caller is [`CallerIdentity::Anonymous`] (loopback TCP; the
///   transport cannot supply peer credentials yet — existing
///   deployments keep working), or
/// - the stored binding equals the caller's principal.
///
/// Otherwise returns 403.
fn check_device_binding_read(
    caller: &CallerIdentity,
    admin_policy: &AdminPolicy,
    binding: Option<&DeviceBindingStore>,
    device_urn: &str,
) -> Result<(), HttpError> {
    if caller.is_admin(admin_policy) {
        return Ok(());
    }
    // M-8 is blocked on H-7 for loopback TCP; preserve behaviour.
    if matches!(caller, CallerIdentity::Anonymous) {
        return Ok(());
    }
    let Some(store) = binding else {
        // No store configured — fall through to allow (only happens in
        // unit tests constructed without a binding store).
        return Ok(());
    };
    let Some(principal) = CallerPrincipal::from_caller(caller) else {
        return Ok(());
    };
    match store.get(device_urn) {
        Some(stored) if stored == principal => Ok(()),
        Some(stored) => {
            tracing::warn!(
                device_urn,
                ?caller,
                ?stored,
                "M-8: device-caller binding mismatch"
            );
            Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "not_authorized".to_owned(),
            })
        }
        None => {
            tracing::warn!(
                device_urn,
                ?caller,
                "M-8: read against unbound device_urn — the device's agent must POST /applied first"
            );
            Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "not_authorized".to_owned(),
            })
        }
    }
}

/// Write-side helper for M-8. Called from
/// `POST /v1/{windows,macos}/applied` handlers: admits admin callers,
/// passes through for `Anonymous` (TCP back-compat), TOFU-binds
/// the first concrete caller for a given `device_urn`, and returns
/// 403 on a principal mismatch.
fn tofu_device_binding(
    caller: &CallerIdentity,
    admin_policy: &AdminPolicy,
    binding: Option<&DeviceBindingStore>,
    device_urn: &str,
) -> Result<(), HttpError> {
    if caller.is_admin(admin_policy) {
        return Ok(());
    }
    if matches!(caller, CallerIdentity::Anonymous) {
        return Ok(());
    }
    let Some(store) = binding else {
        return Ok(());
    };
    let Some(principal) = CallerPrincipal::from_caller(caller) else {
        return Ok(());
    };
    let outcome = store
        .tofu_bind(device_urn, principal.clone())
        .map_err(|e| {
            tracing::error!(error = %e, device_urn, "failed to persist device binding");
            HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "internal_error".to_owned(),
            }
        })?;
    match outcome {
        BindingOutcome::Established => {
            tracing::info!(device_urn, ?principal, "M-8: device binding established (TOFU)");
            Ok(())
        }
        BindingOutcome::Matched => Ok(()),
        BindingOutcome::Mismatch { stored } => {
            tracing::warn!(
                device_urn,
                ?principal,
                ?stored,
                "M-8: TOFU-bound device_urn rejected a different caller"
            );
            Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "not_authorized".to_owned(),
            })
        }
    }
}

// ---------- H-6: per-install HMAC signer for response bodies ----------

type HmacSha256 = Hmac<Sha256>;

/// **H-6 (security review)** — per-install HMAC-SHA256 key used to
/// authenticate the node's HTTP responses to the Windows Auth
/// Bridge and the Policy Agents. Loaded at startup from the path in
/// [`ApiAuthConfig::node_hmac_secret_path`]; `None` disables signing.
///
/// The key is wrapped in [`Zeroizing`] so the in-memory copy is
/// wiped on drop, and in an [`Arc`] so the middleware can clone it
/// cheaply per request.
#[derive(Clone)]
pub struct ResponseMacKey(Arc<Zeroizing<Vec<u8>>>);

impl ResponseMacKey {
    /// Load a per-install HMAC key from disk. The file must contain
    /// at least 16 bytes of key material; the MSI generates 32 random
    /// bytes.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "HMAC key at {} is {} bytes; at least 16 required",
                    path.display(),
                    bytes.len()
                ),
            ));
        }
        Ok(Self(Arc::new(Zeroizing::new(bytes))))
    }

    /// Compute `HMAC-SHA256(key, method || 0x00 || path || 0x00 || body)`.
    /// The null separators prevent ambiguity between e.g.
    /// `("GET", "/a/b")` and `("GE", "T/a/b")`.
    fn sign(&self, method: &str, path: &str, body: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.0)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(method.as_bytes());
        mac.update(&[0]);
        mac.update(path.as_bytes());
        mac.update(&[0]);
        mac.update(body);
        mac.finalize().into_bytes().into()
    }
}

/// Cap on the response body size we're willing to buffer for MAC
/// computation. 8 MiB is well above any legitimate response (audit
/// log pages are paginated, sync responses are capped at 5 MiB per
/// H-11, individual JSON objects are tiny).
const RESPONSE_MAC_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// HTTP header name carrying the MAC.
const RESPONSE_MAC_HEADER: &str = "x-dds-body-mac";

/// Middleware that buffers each response body, computes
/// `HMAC-SHA256(key, method || 0 || path || 0 || body)`, and writes
/// the base64-standard-encoded value into the `X-DDS-Body-MAC`
/// response header. Closes H-6 — the Windows Auth Bridge verifies
/// the MAC on `/v1/session/challenge` so an attacker who manages to
/// bind the server address first cannot substitute challenges.
///
/// Clients that do not verify the header simply ignore it, so the
/// change is transparent during the rollout.
async fn sign_response_body_middleware(
    State(key): State<ResponseMacKey>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, RESPONSE_MAC_MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to buffer response body for HMAC signing");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal_error"})),
            )
                .into_response();
        }
    };
    let mac = key.sign(&method, &path, &bytes);
    let mac_b64 = base64::engine::general_purpose::STANDARD.encode(mac);
    // HeaderValue::from_str only fails on invalid-ASCII; base64 is
    // ASCII by construction, so unwrap is sound.
    parts.headers.insert(
        axum::http::HeaderName::from_static(RESPONSE_MAC_HEADER),
        axum::http::HeaderValue::from_str(&mac_b64).expect("base64 output is ascii"),
    );
    Response::from_parts(parts, axum::body::Body::from(bytes))
}

/// Middleware that rejects the request with 403 if the caller is not
/// authorized for admin endpoints under [`AdminPolicy`]. Applied as a
/// `route_layer` on the admin sub-router in [`router`].
async fn require_admin_middleware(
    State(policy): State<Arc<AdminPolicy>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let caller = req
        .extensions()
        .get::<CallerIdentity>()
        .cloned()
        .unwrap_or(CallerIdentity::Anonymous);
    if !caller.is_admin(&policy) {
        tracing::warn!(
            caller = ?caller,
            path = %req.uri().path(),
            "admin endpoint denied: caller not authorized"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "not_authorized"})),
        )
            .into_response();
    }
    next.run(req).await
}

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

struct AppState<
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
    info: NodeInfo,
    /// **M-8 (security review)**. Shared device-caller binding store.
    /// `None` disables binding checks (useful in tests that construct
    /// a bare router). In production `main.rs` always supplies one.
    device_binding: Option<Arc<DeviceBindingStore>>,
    /// Cached admin policy. Needed by M-8's device-binding helper so
    /// the check can bypass the binding for admin callers (the CLI
    /// operator inspecting a peer's policy set).
    admin_policy: Arc<AdminPolicy>,
}

impl<
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
> Clone for AppState<S>
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
            info: self.info.clone(),
            device_binding: self.device_binding.clone(),
            admin_policy: self.admin_policy.clone(),
        }
    }
}

/// TTL for server-issued FIDO2 challenges (5 minutes).
const CHALLENGE_TTL_SECS: u64 = 300;

/// **M-11 (security review)**: cap inbound JSON bodies. The Axum
/// default is 2 MB; 256 KB is generous for the largest legitimate
/// payload here (FIDO2 attestation objects with large authenticator
/// extensions) and prevents an attacker from forcing the deserializer
/// to allocate huge buffers before any app-layer filter fires.
const HTTP_MAX_BODY_BYTES: usize = 256 * 1024;

/// **M-3 (security review)**: lightweight global token-bucket rate limit
/// applied to every HTTP request. Loopback-only API, so a single counter
/// is adequate defense-in-depth against pathological floods of
/// CPU-heavy paths (FIDO2 verification, policy evaluation) by a local
/// process. 60 req/s sustained, 60 burst. Returns HTTP 429.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const RATE_LIMIT_BURST: u32 = 60;

#[derive(Debug)]
struct GlobalRateLimiter {
    inner: StdMutex<(Instant, u32)>,
}

impl GlobalRateLimiter {
    fn new() -> Self {
        Self {
            inner: StdMutex::new((Instant::now(), 0)),
        }
    }

    /// Returns true if a request is permitted right now.
    fn check(&self) -> bool {
        let now = Instant::now();
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if now.duration_since(g.0) >= RATE_LIMIT_WINDOW {
            *g = (now, 1);
            true
        } else if g.1 < RATE_LIMIT_BURST {
            g.1 += 1;
            true
        } else {
            false
        }
    }
}

async fn rate_limit_middleware(
    State(rl): State<Arc<GlobalRateLimiter>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !rl.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    next.run(req).await
}

/// Build the axum router for the local API.
///
/// `admin_policy` governs which callers may reach admin-gated
/// endpoints (H-7). On loopback TCP — where the transport cannot
/// supply peer credentials — admission falls back to
/// [`AdminPolicy::trust_loopback_tcp_admin`], which is `true` by
/// default so existing deployments keep working during the migration
/// to UDS / named pipe.
///
/// `response_mac_key` — when `Some`, every response carries an
/// `X-DDS-Body-MAC` header (H-6). `None` disables the signer.
///
/// `device_binding` — shared device-caller binding store (M-8).
/// When `None` the binding check is a no-op — intended for unit
/// tests; `main.rs` always supplies a real store.
pub fn router<S>(
    svc: SharedService<S>,
    info: NodeInfo,
    admin_policy: AdminPolicy,
    response_mac_key: Option<ResponseMacKey>,
    device_binding: Option<Arc<DeviceBindingStore>>,
) -> Router
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
    let rate_limiter = Arc::new(GlobalRateLimiter::new());
    let admin_policy = Arc::new(admin_policy);
    let state = AppState {
        svc,
        info,
        device_binding,
        admin_policy: admin_policy.clone(),
    };

    // **H-7 (security review)** — admin-gated sub-router. Every route
    // here goes through `require_admin_middleware`, which denies
    // callers whose `CallerIdentity` fails the policy check.
    let admin_routes = Router::new()
        .route("/v1/enroll/user", post(enroll_user::<S>))
        .route("/v1/enroll/device", post(enroll_device::<S>))
        .route("/v1/enrolled-users", get(list_enrolled_users::<S>))
        .route("/v1/admin/challenge", get(issue_admin_challenge::<S>))
        .route("/v1/admin/setup", post(admin_setup::<S>))
        .route("/v1/admin/vouch", post(admin_vouch::<S>))
        .route("/v1/audit/entries", get(list_audit_entries::<S>))
        .route_layer(axum::middleware::from_fn_with_state(
            admin_policy.clone(),
            require_admin_middleware,
        ));

    // Public / per-session-auth routes. `session/assert` and
    // `session/challenge` carry their own FIDO2 proof-of-possession
    // semantics and are not gated by the transport admin check.
    // Policy / software enumeration remains public for now; G1-S1c
    // adds device-caller binding as a separate layer.
    let public_routes = Router::new()
        // NOTE: The unauthenticated POST /v1/session endpoint has been
        // removed. Session issuance now requires FIDO2 proof-of-possession
        // via /v1/session/assert. The internal `issue_session` method is
        // still available for use by `issue_session_from_assertion`.
        .route("/v1/session/challenge", get(issue_session_challenge::<S>))
        .route("/v1/session/assert", post(issue_session_assert::<S>))
        .route("/v1/policy/evaluate", post(evaluate_policy::<S>))
        .route("/v1/status", get(status::<S>))
        .route("/v1/node/info", get(node_info::<S>))
        .route("/v1/windows/policies", get(list_windows_policies::<S>))
        .route("/v1/windows/software", get(list_windows_software::<S>))
        .route("/v1/windows/applied", post(record_windows_applied::<S>))
        .route(
            "/v1/windows/claim-account",
            post(claim_windows_account::<S>),
        )
        .route("/v1/macos/policies", get(list_macos_policies::<S>))
        .route("/v1/macos/software", get(list_macos_software::<S>))
        .route("/v1/macos/applied", post(record_macos_applied::<S>));

    let mut app = admin_routes
        .merge(public_routes)
        .with_state(state)
        // M-3: rate limit before any handler runs.
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        // M-11: bound deserialization input size.
        .layer(DefaultBodyLimit::max(HTTP_MAX_BODY_BYTES));

    // H-6: append the response-body signer as the outermost layer
    // so its MAC covers the bytes the client actually receives
    // (after every other handler and middleware has run).
    if let Some(key) = response_mac_key {
        app = app.layer(axum::middleware::from_fn_with_state(
            key,
            sign_response_body_middleware,
        ));
    }

    app
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

/// Response from `GET /v1/session/challenge` and `GET /v1/admin/challenge`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge_b64url: String,
    pub expires_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AssertionSessionRequestJson {
    pub subject_urn: Option<String>,
    pub credential_id: String,
    /// Server-issued challenge ID from `GET /v1/session/challenge`.
    pub challenge_id: String,
    pub client_data_hash: String,
    /// **M-12 (security review)**: optional base64-standard
    /// encoding of the raw authenticator-signed `clientDataJSON`.
    /// When present, the node parses the JSON and validates
    /// `type`/`origin`/`challenge` individually per WebAuthn §7.2.
    /// When absent, the legacy reconstruct-and-hash path is used.
    /// Clients SHOULD always include this — the legacy path is
    /// fragile under JSON-serializer differences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_data_json_b64: Option<String>,
    pub authenticator_data: String,
    pub signature: String,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AdminVouchRequestJson {
    pub subject_urn: String,
    pub credential_id: String,
    /// Server-issued challenge ID from `GET /v1/admin/challenge`.
    pub challenge_id: String,
    pub authenticator_data: String,
    pub client_data_hash: String,
    /// M-12 (see `AssertionSessionRequestJson::client_data_json_b64`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_data_json_b64: Option<String>,
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

/// Request to resolve a Windows account claim from a freshly issued
/// local DDS session token.
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowsClaimAccountRequestJson {
    pub device_urn: String,
    pub session_token_cbor_b64: String,
}

/// Response describing the local account the caller may claim.
#[derive(Debug, Serialize, Deserialize)]
pub struct WindowsClaimAccountResponse {
    pub subject_urn: String,
    pub username: String,
    pub full_name: Option<String>,
    pub description: Option<String>,
    pub groups: Vec<String>,
    pub password_never_expires: Option<bool>,
}

/// Response wrapping a list of software assignments for a macOS device.
#[derive(Debug, Serialize, Deserialize)]
pub struct MacOsSoftwareResponse {
    pub software: Vec<ApplicableSoftware>,
}

/// Response for `GET /v1/node/info` — used by Policy Agents to
/// discover the node's URN and Ed25519 signing public key so they
/// can pin the key at first contact (H-2 / H-3).
///
/// **Trust model.** The response itself is served over unauthenticated
/// loopback HTTP, so it must not be trusted on its own for pinning.
/// Agents consume it in one of two ways:
///
/// 1. **Install-time pinning** (preferred): the MSI / provisioning
///    step writes the expected `node_pubkey_b64` into the agent's
///    config. The agent compares the live value to the pinned one
///    and refuses on mismatch.
/// 2. **TOFU** (fallback for dev): agents with no pinned value on
///    first run cache the served pubkey and refuse any subsequent
///    change. Operators are warned.
///
/// A future pass will add a `domain_binding_sig_b64` field — a
/// signature by the domain signing key over
/// `(domain_id || node_urn || node_pubkey)` generated once at
/// provisioning. That closes the TOFU gap because the agent only
/// needs to pin the domain pubkey (which already ships via the
/// provisioning bundle, H-10).
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfoResponse {
    pub node_urn: String,
    pub node_pubkey_b64: String,
    pub peer_id: String,
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
        // **L-9 (security review)**: classify the error coarsely for
        // the response — never expose the inner message, which can
        // contain trust-graph contents ("credential X not found",
        // "challenge expired") that aid an attacker. Full detail is
        // logged server-side at error level.
        let (status, code) = match &e {
            ServiceError::Fido2(_) => (StatusCode::UNAUTHORIZED, "auth_failed"),
            ServiceError::Trust(_) => (StatusCode::FORBIDDEN, "permission_denied"),
            ServiceError::Policy(_) => (StatusCode::FORBIDDEN, "permission_denied"),
            ServiceError::Token(_) => (StatusCode::BAD_REQUEST, "invalid_input"),
            ServiceError::Domain(_) => (StatusCode::BAD_REQUEST, "invalid_input"),
            ServiceError::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        tracing::warn!(error = %e, code, "service error returned to client");
        Self {
            status,
            message: code.to_string(),
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
{
    let svc = state.svc.lock().await;
    let r = svc.evaluate_policy(&req.subject_urn, &req.resource, &req.action)?;
    Ok(Json(r))
}

async fn status<S>(State(state): State<AppState<S>>) -> Result<Json<NodeStatus>, HttpError>
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
    let svc = state.svc.lock().await;
    Ok(Json(svc.status(&state.info.peer_id, 0, 0)?))
}

/// `GET /v1/node/info` — discovery endpoint for Policy Agents. See
/// `NodeInfoResponse` for the trust-model caveats.
async fn node_info<S>(State(state): State<AppState<S>>) -> Result<Json<NodeInfoResponse>, HttpError>
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
    use base64::Engine as _;
    let svc = state.svc.lock().await;
    Ok(Json(NodeInfoResponse {
        node_urn: svc.node_urn(),
        node_pubkey_b64: base64::engine::general_purpose::STANDARD.encode(svc.node_pubkey_bytes()),
        peer_id: state.info.peer_id.clone(),
    }))
}

// ---------- Credential Provider handlers (Phase III) ----------

async fn issue_session_challenge<S>(
    State(state): State<AppState<S>>,
) -> Result<Json<ChallengeResponse>, HttpError>
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
    issue_challenge(state, "session").await
}

async fn issue_admin_challenge<S>(
    State(state): State<AppState<S>>,
) -> Result<Json<ChallengeResponse>, HttpError>
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
    issue_challenge(state, "admin").await
}

async fn issue_challenge<S>(
    state: AppState<S>,
    kind: &str,
) -> Result<Json<ChallengeResponse>, HttpError>
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| HttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("system clock error: {e}"),
        })?
        .as_secs();
    let expires_at = now + CHALLENGE_TTL_SECS;

    let id = format!(
        "chall-{kind}-{}",
        now ^ u64::from_ne_bytes(bytes[..8].try_into().unwrap())
    );
    let challenge_b64url = URL_SAFE_NO_PAD.encode(bytes);

    {
        let mut svc = state.svc.lock().await;
        svc.store_mut()
            .put_challenge(&id, &bytes, expires_at)
            .map_err(|e| HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!("store error: {e}"),
            })?;
    }

    Ok(Json(ChallengeResponse {
        challenge_id: id,
        challenge_b64url,
        expires_at,
    }))
}

async fn issue_session_assert<S>(
    State(state): State<AppState<S>>,
    Json(req): Json<AssertionSessionRequestJson>,
) -> Result<Json<SessionResponse>, HttpError>
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
    let client_data_json = match req.client_data_json_b64.as_deref() {
        Some(s) => Some(b64_decode(s, "client_data_json_b64")?),
        None => None,
    };
    let internal = AssertionSessionRequest {
        subject_urn: req.subject_urn,
        credential_id: req.credential_id,
        challenge_id: req.challenge_id,
        client_data_hash: b64_decode(&req.client_data_hash, "client_data_hash")?,
        client_data_json,
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
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
    S: TokenStore
        + RevocationStore
        + AuditStore
        + ChallengeStore
        + CredentialStateStore
        + Send
        + Sync
        + 'static,
{
    let client_data_json = match req.client_data_json_b64.as_deref() {
        Some(s) => Some(b64_decode(s, "client_data_json_b64")?),
        None => None,
    };
    let internal = AdminVouchRequest {
        subject_urn: req.subject_urn,
        credential_id: req.credential_id,
        challenge_id: req.challenge_id,
        client_data_hash: b64_decode(&req.client_data_hash, "client_data_hash")?,
        client_data_json,
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
    caller: CallerIdentity,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<dds_core::envelope::SignedPolicyEnvelope>, HttpError>
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
    // M-8 (security review): bind every policy read to the caller's
    // device URN (once H-7's transport supplies caller credentials).
    check_device_binding_read(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &q.device_urn,
    )?;
    tracing::info!(device_urn = %q.device_urn, "list_windows_policies");
    let svc = state.svc.lock().await;
    let policies = svc.list_applicable_windows_policies(&q.device_urn)?;
    let payload = WindowsPoliciesResponse { policies };
    // H-2 (security review): serialize once, sign the bytes, hand the
    // bytes back base64-encoded. Policy Agent verifies the sig under
    // its pinned node pubkey before dispatching any enforcer.
    let payload_json = serde_json::to_vec(&payload).map_err(|e| HttpError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("serialize: {e}"),
    })?;
    let env = svc.sign_policy_envelope(
        &q.device_urn,
        dds_core::envelope::kind::WINDOWS_POLICIES,
        &payload_json,
    );
    Ok(Json(env))
}

async fn list_windows_software<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<dds_core::envelope::SignedPolicyEnvelope>, HttpError>
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
    check_device_binding_read(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &q.device_urn,
    )?;
    tracing::info!(device_urn = %q.device_urn, "list_windows_software");
    let svc = state.svc.lock().await;
    let software = svc.list_applicable_software(&q.device_urn)?;
    let payload = WindowsSoftwareResponse { software };
    let payload_json = serde_json::to_vec(&payload).map_err(|e| HttpError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("serialize: {e}"),
    })?;
    let env = svc.sign_policy_envelope(
        &q.device_urn,
        dds_core::envelope::kind::WINDOWS_SOFTWARE,
        &payload_json,
    );
    Ok(Json(env))
}

async fn record_windows_applied<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Json(report): Json<AppliedReport>,
) -> Result<StatusCode, HttpError>
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
    // M-8: TOFU-bind `(caller, device_urn)` on first applied-report.
    tofu_device_binding(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &report.device_urn,
    )?;
    let svc = state.svc.lock().await;
    svc.record_applied(&report)?;
    Ok(StatusCode::ACCEPTED)
}

async fn claim_windows_account<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Json(req): Json<WindowsClaimAccountRequestJson>,
) -> Result<Json<WindowsClaimAccountResponse>, HttpError>
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
    check_device_binding_read(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &req.device_urn,
    )?;
    let session_token_cbor = b64_decode(&req.session_token_cbor_b64, "session_token_cbor_b64")?;
    let svc = state.svc.lock().await;
    let claim = match svc.resolve_windows_account_claim(&req.device_urn, &session_token_cbor) {
        Ok(claim) => claim,
        Err(ServiceError::Policy(e) | ServiceError::Trust(e)) => {
            return Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: e,
            });
        }
        Err(ServiceError::Domain(e) | ServiceError::Token(e)) => {
            return Err(HttpError::bad_request(e));
        }
        Err(e) => return Err(e.into()),
    };

    Ok(Json(WindowsClaimAccountResponse {
        subject_urn: claim.subject_urn,
        username: claim.username,
        full_name: claim.full_name,
        description: claim.description,
        groups: claim.groups,
        password_never_expires: claim.password_never_expires,
    }))
}

async fn list_macos_policies<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<dds_core::envelope::SignedPolicyEnvelope>, HttpError>
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
    check_device_binding_read(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &q.device_urn,
    )?;
    tracing::info!(device_urn = %q.device_urn, "list_macos_policies");
    let svc = state.svc.lock().await;
    let policies = svc.list_applicable_macos_policies(&q.device_urn)?;
    let payload = MacOsPoliciesResponse { policies };
    // H-3 (security review): sign the payload so the macOS Policy
    // Agent can verify against its pinned node pubkey before
    // dispatching launchd/accounts/profiles enforcers as root.
    let payload_json = serde_json::to_vec(&payload).map_err(|e| HttpError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("serialize: {e}"),
    })?;
    let env = svc.sign_policy_envelope(
        &q.device_urn,
        dds_core::envelope::kind::MACOS_POLICIES,
        &payload_json,
    );
    Ok(Json(env))
}

async fn list_macos_software<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Query(q): Query<DeviceUrnQuery>,
) -> Result<Json<dds_core::envelope::SignedPolicyEnvelope>, HttpError>
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
    check_device_binding_read(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &q.device_urn,
    )?;
    tracing::info!(device_urn = %q.device_urn, "list_macos_software");
    let svc = state.svc.lock().await;
    let software = svc.list_applicable_software(&q.device_urn)?;
    let payload = MacOsSoftwareResponse { software };
    let payload_json = serde_json::to_vec(&payload).map_err(|e| HttpError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("serialize: {e}"),
    })?;
    let env = svc.sign_policy_envelope(
        &q.device_urn,
        dds_core::envelope::kind::MACOS_SOFTWARE,
        &payload_json,
    );
    Ok(Json(env))
}

async fn record_macos_applied<S>(
    State(state): State<AppState<S>>,
    caller: CallerIdentity,
    Json(report): Json<AppliedReport>,
) -> Result<StatusCode, HttpError>
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
    tofu_device_binding(
        &caller,
        &state.admin_policy,
        state.device_binding.as_deref(),
        &report.device_urn,
    )?;
    let svc = state.svc.lock().await;
    svc.record_applied(&report)?;
    Ok(StatusCode::ACCEPTED)
}

// ---------- Audit log query handler ----------

#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    action: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct AuditEntryJson {
    action: String,
    node_urn: String,
    timestamp: u64,
    token_cbor_b64: String,
}

#[derive(Debug, Serialize)]
struct AuditEntriesResponse {
    entries: Vec<AuditEntryJson>,
    total: usize,
}

async fn list_audit_entries<S>(
    State(state): State<AppState<S>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditEntriesResponse>, HttpError>
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
    let svc = state.svc.lock().await;
    let entries = svc.list_audit_entries(params.action.as_deref(), params.limit)?;
    let total = entries.len();
    let json_entries: Vec<AuditEntryJson> = entries
        .into_iter()
        .map(|e| AuditEntryJson {
            action: e.action,
            node_urn: e.node_urn,
            timestamp: e.timestamp,
            token_cbor_b64: base64::engine::general_purpose::STANDARD.encode(&e.token_bytes),
        })
        .collect();
    Ok(Json(AuditEntriesResponse {
        entries: json_entries,
        total,
    }))
}

/// Bind and serve the HTTP API on `addr` until the future is dropped.
///
/// Scheme dispatch (H-7 step-2):
/// - `unix:/path/to/sock` — Unix domain socket. Every accepted
///   connection's peer credentials (`uid`, `gid`, `pid`) are extracted
///   via `getpeereid` / `SO_PEERCRED` and injected as a
///   [`CallerIdentity::Uds`] extension on every request, so
///   [`require_admin_middleware`] sees a concrete identity rather than
///   falling back to `Anonymous`. The socket file is created with
///   `0o660` so only the owner and service group can connect.
/// - anything else — legacy loopback TCP (e.g. `127.0.0.1:5551`).
///   Callers are treated as [`CallerIdentity::Anonymous`] and fall
///   back to [`AdminPolicy::trust_loopback_tcp_admin`].
pub async fn serve<S>(
    addr: &str,
    svc: SharedService<S>,
    info: NodeInfo,
    admin_policy: AdminPolicy,
    response_mac_key: Option<ResponseMacKey>,
    device_binding: Option<Arc<DeviceBindingStore>>,
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
    if let Some(path) = addr.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            return serve_unix(
                Path::new(path),
                svc,
                info,
                admin_policy,
                response_mac_key,
                device_binding,
            )
            .await;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err("UDS transport is only supported on Unix platforms".into());
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP API listening on TCP");
    // Loopback TCP cannot supply peer credentials, so no `CallerIdentity`
    // extension is inserted here. `require_admin_middleware` will treat
    // callers as `CallerIdentity::Anonymous` and fall back to
    // `trust_loopback_tcp_admin`.
    axum::serve(
        listener,
        router(svc, info, admin_policy, response_mac_key, device_binding),
    )
    .await?;
    Ok(())
}

/// UDS serve loop for H-7 step-2.
///
/// axum 0.7's `axum::serve` only accepts a `TcpListener`, so this
/// mirrors what it does internally — accept a stream, wrap it with
/// `hyper_util::rt::TokioIo`, and hand it to
/// `hyper::server::conn::http1::Builder::serve_connection` with a
/// per-connection service that (a) injects the caller's UDS peer
/// credentials as a request extension and (b) delegates to the axum
/// router. One task per connection; router is cheaply `Clone`.
#[cfg(unix)]
async fn serve_unix<S>(
    path: &Path,
    svc: SharedService<S>,
    info: NodeInfo,
    admin_policy: AdminPolicy,
    response_mac_key: Option<ResponseMacKey>,
    device_binding: Option<Arc<DeviceBindingStore>>,
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
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    use tower::ServiceExt as _;

    // A stale socket file from a prior run of the same node would make
    // `bind` fail with `EADDRINUSE`. Remove it first; the subsequent
    // `bind` + `chmod` race window is negligible on a private data dir
    // that is already `0o700` (L-4 in the review).
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| format!("failed to remove stale socket {}: {e}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create socket parent dir {}: {e}",
                    parent.display()
                )
            })?;
        }
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("failed to bind UDS {}: {e}", path.display()))?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o660);
    std::fs::set_permissions(path, perms)?;
    tracing::info!(path = %path.display(), "HTTP API listening on UDS");

    let app = router(svc, info, admin_policy, response_mac_key, device_binding);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "UDS accept failed");
                // Avoid a spin-loop on a persistent accept error.
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let peer = match stream.peer_cred() {
            Ok(cred) => CallerIdentity::Uds {
                uid: cred.uid(),
                gid: cred.gid(),
                pid: cred.pid().unwrap_or(0),
            },
            Err(e) => {
                tracing::warn!(error = %e, "peer_cred failed; dropping connection");
                continue;
            }
        };
        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc_fn = hyper::service::service_fn({
                let app = app.clone();
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    let peer = peer.clone();
                    async move {
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(peer);
                        let body = axum::body::Body::new(body);
                        let req = axum::http::Request::from_parts(parts, body);
                        let resp: axum::response::Response =
                            app.oneshot(req).await.unwrap_or_else(|never| match never {});
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc_fn).await {
                tracing::debug!(error = %e, "UDS connection closed");
            }
        });
    }
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
        let attest_hash = attest.payload_hash();
        graph.add_token(attest).unwrap();
        // C-3: seed publisher capabilities so the policy/software list
        // endpoints accept root-issued documents in tests.
        for purpose in [
            dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
            dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
            dds_core::token::purpose::SOFTWARE_PUBLISHER,
        ] {
            let v = Token::sign(
                TokenPayload {
                    iss: root.id.to_urn(),
                    iss_key: root.public_key.clone(),
                    jti: format!("vouch-self-root-{}", purpose.replace(':', "-")),
                    sub: root.id.to_urn(),
                    kind: TokenKind::Vouch,
                    purpose: Some(purpose.to_string()),
                    vch_iss: Some(root.id.to_urn()),
                    vch_sum: Some(attest_hash.clone()),
                    revokes: None,
                    iat: 1000,
                    exp: Some(4102444800),
                    body_type: None,
                    body_cbor: None,
                },
                &root.signing_key,
            )
            .unwrap();
            graph.add_token(v).unwrap();
        }
        let shared_graph = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let svc = LocalService::new(node_ident, shared_graph, roots, MemoryBackend::new());
        TestState {
            app: AppState {
                svc: Arc::new(Mutex::new(svc)),
                info: NodeInfo {
                    peer_id: "12D3KooWUnit".into(),
                },
                device_binding: None,
                admin_policy: Arc::new(tcp_trust_policy()),
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
                "/v1/session/challenge",
                get(issue_session_challenge::<MemoryBackend>),
            )
            .route(
                "/v1/session/assert",
                post(issue_session_assert::<MemoryBackend>),
            )
            .route(
                "/v1/enrolled-users",
                get(list_enrolled_users::<MemoryBackend>),
            )
            .route(
                "/v1/admin/challenge",
                get(issue_admin_challenge::<MemoryBackend>),
            )
            .route("/v1/admin/setup", post(admin_setup::<MemoryBackend>))
            .route("/v1/admin/vouch", post(admin_vouch::<MemoryBackend>))
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
                "/v1/windows/claim-account",
                post(claim_windows_account::<MemoryBackend>),
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

    /// Fetch a server-issued challenge from `path` (e.g. `/v1/session/challenge`).
    /// Returns `(challenge_id, challenge_b64url)`.
    async fn fetch_challenge(base: &str, path: &str) -> (String, String) {
        let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert_eq!(resp.status(), 200, "challenge endpoint failed");
        let body: ChallengeResponse = resp.json().await.unwrap();
        (body.challenge_id, body.challenge_b64url)
    }

    /// Build a FIDO2 assertion using a server-supplied challenge.
    ///
    /// Constructs `clientDataJSON` exactly as the C++ bridge does:
    /// `{"type":"webauthn.get","challenge":"<b64url>","origin":"https://<rp_id>"}`.
    /// Returns `(auth_data_b64, client_data_hash_b64, sig_b64)`.
    fn build_assertion_with_challenge(
        rp_id: &str,
        sk: &SigningKey,
        sign_count: u32,
        challenge_b64url: &str,
    ) -> (String, String, String) {
        use dds_domain::fido2::build_assertion_auth_data;
        use ed25519_dalek::Signer;

        let auth_data = build_assertion_auth_data(rp_id, sign_count);

        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#
        );
        let cdh = sha2::Sha256::digest(cdj.as_bytes());

        let mut signed_msg = Vec::new();
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&cdh);
        let sig = sk.sign(&signed_msg);

        (
            b64_encode(&auth_data),
            b64_encode(&cdh),
            b64_encode(&sig.to_bytes()),
        )
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
        use dds_domain::fido2::build_none_attestation;

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

        // 2. Fetch a server challenge and build the FIDO2 assertion from it.
        let (challenge_id, challenge_b64url) =
            fetch_challenge(&base, "/v1/session/challenge").await;
        let (auth_data_b64, cdh_b64, sig_b64) =
            build_assertion_with_challenge("dds.local", &sk, 1, &challenge_b64url);

        // 3. POST /v1/session/assert — use the base64url credential_id
        //    that matches what enroll_user stored in the trust graph.
        let assert_req = AssertionSessionRequestJson {
            subject_urn: Some(enrolled.urn.clone()),
            credential_id: cred_id_b64,
            challenge_id,
            client_data_hash: cdh_b64,
            authenticator_data: auth_data_b64,
            signature: sig_b64,
            duration_secs: Some(1800),
        
            ..Default::default()
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

        // Sign assertion with key B (wrong key). Rejected at crypto step (before challenge).
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
            challenge_id: "dummy-id".into(),
            client_data_hash: b64_encode(&cdh),
            authenticator_data: b64_encode(&auth_data),
            signature: b64_encode(&sig.to_bytes()),
            duration_secs: None,
        
            ..Default::default()
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

        // Rejected at credential-lookup step (before challenge).
        let assert_req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: "nonexistent-cred".into(),
            challenge_id: "dummy-id".into(),
            client_data_hash: b64_encode(&cdh),
            authenticator_data: b64_encode(&auth_data),
            signature: b64_encode(&sig.to_bytes()),
            duration_secs: None,
        
            ..Default::default()
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

    #[tokio::test]
    async fn test_windows_claim_account_endpoint() {
        use crate::service::SessionRequest;
        use dds_domain::{
            AccountAction, AccountDirective, DomainDocument, Enforcement, PolicyScope,
            WindowsPolicyDocument, WindowsSettings,
        };

        let TestState { app: state, root } = make_state_with_root();
        let base = spawn_server(state.clone()).await;

        let device_urn = {
            let mut svc = state.svc.lock().await;
            svc.set_verify_fido2(false);
            svc.enroll_device(EnrollDeviceRequest {
                label: "claim-device".into(),
                device_id: "hw-claim-1".into(),
                hostname: "claim-host".into(),
                os: "Windows 11".into(),
                os_version: "24H2".into(),
                tpm_ek_hash: None,
                org_unit: None,
                tags: vec!["claim".into()],
            })
            .unwrap()
            .urn
        };

        let user_sk = SigningKey::generate(&mut OsRng);
        let credential_id = "claim-cred-1";
        let attestation = build_none_attestation(
            "dds.local",
            credential_id.as_bytes(),
            &user_sk.verifying_key(),
        );
        let enroll_req = EnrollUserRequestJson {
            label: "alice".into(),
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(credential_id.as_bytes()),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "dds.local".into(),
            display_name: "Alice".into(),
            authenticator_type: "cross-platform".into(),
        };
        let enroll_resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&enroll_req)
            .send()
            .await
            .unwrap();
        assert_eq!(enroll_resp.status(), 200);
        let enroll_body: EnrollmentResponse = enroll_resp.json().await.unwrap();

        vouch_user(&state, &root, &enroll_body.urn).await;

        let admin = Identity::generate("admin-claim", &mut OsRng);
        let mut payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: "claim-policy".into(),
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
        let claim_policy = WindowsPolicyDocument {
            policy_id: "windows/claim".into(),
            display_name: "Claim".into(),
            version: 1,
            enforcement: Enforcement::Enforce,
            scope: PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![device_urn.clone()],
            },
            settings: vec![],
            windows: Some(WindowsSettings {
                local_accounts: vec![AccountDirective {
                    username: "alice-local".into(),
                    action: AccountAction::Create,
                    claim_subject_urn: Some(enroll_body.urn.clone()),
                    full_name: Some("Alice Local".into()),
                    description: Some("Claimable account".into()),
                    groups: vec!["Users".into()],
                    password_never_expires: Some(true),
                }],
                ..Default::default()
            }),
        };
        claim_policy.embed(&mut payload).unwrap();
        let claim_token = Token::sign(payload, &admin.signing_key).unwrap();
        // C-3: grant the claim-policy admin a publisher capability.
        seed_publisher_capabilities(
            &state,
            &admin,
            &[dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS],
        )
        .await;
        {
            let svc = state.svc.lock().await;
            svc.trust_graph
                .write()
                .unwrap()
                .add_token(claim_token)
                .unwrap();
        }

        let session_token_cbor_b64 = {
            let mut svc = state.svc.lock().await;
            let session = svc
                .issue_session(SessionRequest {
                    subject_urn: enroll_body.urn.clone(),
                    device_urn: None,
                    requested_resources: vec![],
                    duration_secs: 300,
                    mfa_verified: true,
                    tls_binding: None,
                })
                .unwrap();
            b64_encode(&session.token_cbor)
        };

        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/windows/claim-account"))
            .json(&WindowsClaimAccountRequestJson {
                device_urn: device_urn.clone(),
                session_token_cbor_b64,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: WindowsClaimAccountResponse = resp.json().await.unwrap();
        assert_eq!(body.subject_urn, enroll_body.urn);
        assert_eq!(body.username, "alice-local");
        assert_eq!(body.full_name.as_deref(), Some("Alice Local"));
        assert_eq!(body.groups, vec!["Users".to_string()]);
        assert_eq!(body.password_never_expires, Some(true));
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

        // C-3: register admin as trusted root + grant publisher capabilities
        // via self-vouches so the list endpoints accept these issuers.
        seed_publisher_capabilities(
            state,
            &admin,
            &[
                dds_core::token::purpose::POLICY_PUBLISHER_WINDOWS,
                dds_core::token::purpose::SOFTWARE_PUBLISHER,
            ],
        )
        .await;

        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();
        g.add_token(policy_token).unwrap();
        g.add_token(sw_token).unwrap();
        device_urn
    }

    /// Test helper: register `admin` as a trusted root and self-vouch
    /// the requested publisher capabilities (C-3 in the security review).
    async fn seed_publisher_capabilities(
        state: &AppState<MemoryBackend>,
        admin: &Identity,
        purposes: &[&str],
    ) {
        use dds_core::token::{Token, TokenKind, TokenPayload};

        {
            let mut svc = state.svc.lock().await;
            svc.insert_trusted_root_for_test(admin.id.to_urn());
        }
        let admin_attest = Token::sign(
            TokenPayload {
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
            },
            &admin.signing_key,
        )
        .unwrap();
        let admin_attest_hash = admin_attest.payload_hash();
        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();
        g.add_token(admin_attest).unwrap();
        for purpose in purposes {
            let v = Token::sign(
                TokenPayload {
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
                    vch_sum: Some(admin_attest_hash.clone()),
                    revokes: None,
                    iat: 1_700_000_000,
                    exp: Some(4_102_444_800),
                    body_type: None,
                    body_cbor: None,
                },
                &admin.signing_key,
            )
            .unwrap();
            g.add_token(v).unwrap();
        }
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

        // C-3: same publisher-capability seeding as the Windows path.
        seed_publisher_capabilities(
            state,
            &admin,
            &[
                dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
                dds_core::token::purpose::SOFTWARE_PUBLISHER,
            ],
        )
        .await;

        let svc = state.svc.lock().await;
        let mut g = svc.trust_graph.write().unwrap();
        g.add_token(policy_token).unwrap();
        g.add_token(sw_token).unwrap();
        device_urn
    }

    /// H-2 / H-3 (security review): policy/software endpoints now
    /// return a `SignedPolicyEnvelope`; the tests unwrap the envelope
    /// (payload is the same JSON they used to receive directly).
    /// Tests don't re-verify the signature — that's exercised in
    /// `dds_core::envelope::tests::interop_vector_is_stable` and the
    /// C# agent-side suites.
    fn unwrap_envelope_payload(env: dds_core::envelope::SignedPolicyEnvelope) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&env.payload_b64)
            .expect("envelope payload_b64 must decode")
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        assert_eq!(env.kind, dds_core::envelope::kind::WINDOWS_POLICIES);
        assert_eq!(env.device_urn, device_urn);
        let bytes = unwrap_envelope_payload(env);
        let body: WindowsPoliciesResponse = serde_json::from_slice(&bytes).unwrap();
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        assert_eq!(env.kind, dds_core::envelope::kind::WINDOWS_SOFTWARE);
        let bytes = unwrap_envelope_payload(env);
        let body: WindowsSoftwareResponse = serde_json::from_slice(&bytes).unwrap();
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        let bytes = unwrap_envelope_payload(env);
        let body: WindowsSoftwareResponse = serde_json::from_slice(&bytes).unwrap();
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        assert_eq!(env.kind, dds_core::envelope::kind::MACOS_POLICIES);
        let bytes = unwrap_envelope_payload(env);
        let body: MacOsPoliciesResponse = serde_json::from_slice(&bytes).unwrap();
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        assert_eq!(env.kind, dds_core::envelope::kind::MACOS_SOFTWARE);
        let bytes = unwrap_envelope_payload(env);
        let body: MacOsSoftwareResponse = serde_json::from_slice(&bytes).unwrap();
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
        let env: dds_core::envelope::SignedPolicyEnvelope = resp.json().await.unwrap();
        let bytes = unwrap_envelope_payload(env);
        let body: MacOsSoftwareResponse = serde_json::from_slice(&bytes).unwrap();
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

    // ----------------------------------------------------------------
    // FIDO2 replay / freshness regression tests (Phase 5)
    // ----------------------------------------------------------------

    /// Helper: enroll a user and return (cred_id_b64, sk, enrolled_urn).
    async fn enroll_user_helper(
        base: &str,
        label: &str,
        cred_bytes: &[u8],
        rp_id: &str,
    ) -> (String, SigningKey, String) {
        use dds_domain::fido2::build_none_attestation;
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_none_attestation(rp_id, cred_bytes, &sk.verifying_key());
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let enroll_req = EnrollUserRequestJson {
            label: label.into(),
            credential_id: cred_id_b64.clone(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: rp_id.into(),
            display_name: label.to_uppercase(),
            authenticator_type: "platform".into(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&enroll_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: EnrollmentResponse = resp.json().await.unwrap();
        (cred_id_b64, sk, body.urn)
    }

    /// POST /v1/session/assert using a fresh challenge.
    #[allow(clippy::too_many_arguments)]
    async fn assert_session(
        base: &str,
        cred_id: &str,
        sk: &SigningKey,
        rp_id: &str,
        sign_count: u32,
        challenge_id: String,
        challenge_b64url: &str,
        duration_secs: Option<u64>,
    ) -> reqwest::StatusCode {
        let (auth_data_b64, cdh_b64, sig_b64) =
            build_assertion_with_challenge(rp_id, sk, sign_count, challenge_b64url);
        let req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: cred_id.into(),
            challenge_id,
            client_data_hash: cdh_b64,
            authenticator_data: auth_data_b64,
            signature: sig_b64,
            duration_secs,
        
            ..Default::default()
};
        reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&req)
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Omitting `challenge_id` causes JSON deserialization failure → 422.
    #[tokio::test]
    async fn test_assert_requires_challenge() {
        let state = make_state();
        let base = spawn_server(state).await;

        // Send request without `challenge_id` field.
        let body = serde_json::json!({
            "credential_id": "cred-x",
            "client_data_hash": b64_encode(&[0u8; 32]),
            "authenticator_data": b64_encode(&[0u8; 37]),
            "signature": b64_encode(&[0u8; 64]),
        });
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&body)
            .send()
            .await
            .unwrap();
        // axum returns 422 Unprocessable Entity for missing required fields.
        assert_eq!(resp.status(), 422);
    }

    /// A challenge is single-use: replaying the same challenge_id is rejected.
    #[tokio::test]
    async fn test_assert_challenge_single_use() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, urn) =
            enroll_user_helper(&base, "alice", b"cred-single-use", "dds.local").await;
        vouch_user(&state, &ts.root, &urn).await;

        let (challenge_id, challenge_b64url) =
            fetch_challenge(&base, "/v1/session/challenge").await;

        // First use succeeds.
        let status = assert_session(
            &base,
            &cred_id,
            &sk,
            "dds.local",
            1,
            challenge_id.clone(),
            &challenge_b64url,
            None,
        )
        .await;
        assert_eq!(status, 200, "first assertion should succeed");

        // Second use with same challenge_id is rejected.
        let (auth_data_b64, cdh_b64, sig_b64) =
            build_assertion_with_challenge("dds.local", &sk, 2, &challenge_b64url);
        let req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: cred_id,
            challenge_id,
            client_data_hash: cdh_b64,
            authenticator_data: auth_data_b64,
            signature: sig_b64,
            duration_secs: None,
        
            ..Default::default()
};
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "replayed challenge should be rejected");
    }

    /// A challenge with an already-expired TTL is rejected.
    #[tokio::test]
    async fn test_assert_stale_challenge() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, urn) =
            enroll_user_helper(&base, "dave", b"cred-stale", "dds.local").await;
        vouch_user(&state, &ts.root, &urn).await;

        // Inject an already-expired challenge directly into the store.
        let stale_bytes = [0xDEu8; 32];
        let stale_id = "chall-expired-test";
        {
            let mut svc = state.svc.lock().await;
            // expires_at = 1 (Unix epoch + 1 s) — already expired.
            svc.store_mut()
                .put_challenge(stale_id, &stale_bytes, 1)
                .unwrap();
        }

        let challenge_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(stale_bytes);
        let (auth_data_b64, cdh_b64, sig_b64) =
            build_assertion_with_challenge("dds.local", &sk, 1, &challenge_b64url);
        let req = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: cred_id,
            challenge_id: stale_id.into(),
            client_data_hash: cdh_b64,
            authenticator_data: auth_data_b64,
            signature: sig_b64,
            duration_secs: None,
        
            ..Default::default()
};
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "stale challenge should be rejected");
    }

    /// Non-monotonic sign_count is rejected as a replay attack.
    #[tokio::test]
    async fn test_assert_nonmonotonic_sign_count() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, urn) =
            enroll_user_helper(&base, "eve", b"cred-counter", "dds.local").await;
        vouch_user(&state, &ts.root, &urn).await;

        // First assertion with count=5 — accepted.
        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/session/challenge").await;
        let status =
            assert_session(&base, &cred_id, &sk, "dds.local", 5, ch_id, &ch_b64, None).await;
        assert_eq!(status, 200, "first assertion (count=5) should succeed");

        // Second assertion with count=3 (not monotonic) — rejected.
        let (ch_id2, ch_b64_2) = fetch_challenge(&base, "/v1/session/challenge").await;
        let status2 = assert_session(
            &base,
            &cred_id,
            &sk,
            "dds.local",
            3,
            ch_id2,
            &ch_b64_2,
            None,
        )
        .await;
        assert_eq!(status2, 401, "non-monotonic sign_count should be rejected");
    }

    /// sign_count=0 (authenticator without counter support) skips replay detection.
    #[tokio::test]
    async fn test_assert_sign_count_zero_skips_check() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, urn) =
            enroll_user_helper(&base, "frank", b"cred-no-counter", "dds.local").await;
        vouch_user(&state, &ts.root, &urn).await;

        // Two consecutive assertions both with count=0 should both succeed.
        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/session/challenge").await;
        let status =
            assert_session(&base, &cred_id, &sk, "dds.local", 0, ch_id, &ch_b64, None).await;
        assert_eq!(status, 200, "first count=0 assertion should succeed");

        let (ch_id2, ch_b64_2) = fetch_challenge(&base, "/v1/session/challenge").await;
        let status2 = assert_session(
            &base,
            &cred_id,
            &sk,
            "dds.local",
            0,
            ch_id2,
            &ch_b64_2,
            None,
        )
        .await;
        assert_eq!(status2, 200, "second count=0 assertion should also succeed");
    }

    /// admin_vouch missing challenge_id → 422.
    #[tokio::test]
    async fn test_admin_vouch_requires_challenge() {
        let state = make_state();
        let base = spawn_server(state).await;

        let body = serde_json::json!({
            "subject_urn": "urn:vouchsafe:nobody.aaa",
            "credential_id": "cred-x",
            "authenticator_data": b64_encode(&[0u8; 37]),
            "client_data_hash": b64_encode(&[0u8; 32]),
            "signature": b64_encode(&[0u8; 64]),
        });
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/vouch"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    /// admin_vouch enforces UP flag (user_present must be set).
    ///
    /// `build_assertion_auth_data` sets flags=0x01 (UP). We craft
    /// authenticatorData with flags=0x00 to simulate a missing UP flag.
    #[tokio::test]
    async fn test_admin_vouch_requires_up() {
        use sha2::Digest;

        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, _urn) =
            enroll_user_helper(&base, "grace", b"cred-no-up", "dds.local").await;

        // Build authenticatorData with flags=0x00 (UP not set).
        let rp_id_hash = sha2::Sha256::digest(b"dds.local");
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x00); // flags: UP=0, UV=0
        auth_data.extend_from_slice(&[0u8; 4]); // sign_count = 0

        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/admin/challenge").await;
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch_b64}","origin":"https://dds.local"}}"#
        );
        let cdh = sha2::Sha256::digest(cdj.as_bytes());
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&cdh);
        let sig = {
            use ed25519_dalek::Signer;
            sk.sign(&msg)
        };

        let req = AdminVouchRequestJson {
            subject_urn: "urn:vouchsafe:nobody.bbb".into(),
            credential_id: cred_id,
            challenge_id: ch_id,
            authenticator_data: b64_encode(&auth_data),
            client_data_hash: b64_encode(&cdh),
            signature: b64_encode(&sig.to_bytes()),
            purpose: None,
        
            ..Default::default()
};
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/vouch"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "UP=0 should be rejected");
    }

    /// admin_vouch enforces RP-ID binding.
    #[tokio::test]
    async fn test_admin_vouch_rp_id_enforced() {
        use sha2::Digest;

        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        // Enroll at "dds.local" but present auth_data for "evil.com".
        let (cred_id, sk, _urn) =
            enroll_user_helper(&base, "heidi", b"cred-rp-test", "dds.local").await;

        // Build authenticatorData with rp_id_hash for wrong origin.
        let wrong_rp_hash = sha2::Sha256::digest(b"evil.com");
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&wrong_rp_hash);
        auth_data.push(0x01); // UP flag set
        auth_data.extend_from_slice(&[0u8; 4]); // sign_count = 0

        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/admin/challenge").await;
        // Use correct origin in clientDataJSON, wrong rp_id in auth_data hash.
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch_b64}","origin":"https://dds.local"}}"#
        );
        let cdh = sha2::Sha256::digest(cdj.as_bytes());
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&cdh);
        let sig = {
            use ed25519_dalek::Signer;
            sk.sign(&msg)
        };

        let req = AdminVouchRequestJson {
            subject_urn: "urn:vouchsafe:nobody.ccc".into(),
            credential_id: cred_id,
            challenge_id: ch_id,
            authenticator_data: b64_encode(&auth_data),
            client_data_hash: b64_encode(&cdh),
            signature: b64_encode(&sig.to_bytes()),
            purpose: None,
        
            ..Default::default()
};
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/vouch"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "wrong RP-ID hash should be rejected");
    }

    /// admin_vouch challenge is single-use — replaying the same challenge_id fails.
    ///
    /// The first vouch attempt consumes the challenge but fails at the "not a
    /// trusted root" check. The second attempt with the same challenge_id must
    /// fail at the challenge step itself (401), proving the challenge was consumed.
    #[tokio::test]
    async fn test_admin_vouch_challenge_single_use() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, _urn) =
            enroll_user_helper(&base, "ivan", b"cred-vouch-single", "dds.local").await;

        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/admin/challenge").await;
        let (auth_data_b64, cdh_b64, sig_b64) =
            build_assertion_with_challenge("dds.local", &sk, 1, &ch_b64);

        // First attempt: challenge is valid but credential is not a trusted root,
        // so we get a non-422 error (challenge is consumed regardless of outcome).
        let resp1 = reqwest::Client::new()
            .post(format!("{base}/v1/admin/vouch"))
            .json(&AdminVouchRequestJson {
                subject_urn: "urn:vouchsafe:nobody.ddd".into(),
                credential_id: cred_id.clone(),
                challenge_id: ch_id.clone(),
                authenticator_data: auth_data_b64.clone(),
                client_data_hash: cdh_b64.clone(),
                signature: sig_b64.clone(),
                purpose: None,
            
                ..Default::default()
})
            .send()
            .await
            .unwrap();
        assert_ne!(
            resp1.status(),
            422,
            "first attempt must not be a parse error"
        );

        // Second attempt with same challenge_id — must be rejected at challenge step.
        let (auth_data2, cdh2, sig2) = build_assertion_with_challenge("dds.local", &sk, 2, &ch_b64);
        let resp2 = reqwest::Client::new()
            .post(format!("{base}/v1/admin/vouch"))
            .json(&AdminVouchRequestJson {
                subject_urn: "urn:vouchsafe:nobody.ddd".into(),
                credential_id: cred_id,
                challenge_id: ch_id,
                authenticator_data: auth_data2,
                client_data_hash: cdh2,
                signature: sig2,
                purpose: None,
            
                ..Default::default()
})
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            401,
            "replayed admin challenge should be rejected"
        );
    }

    /// A session challenge cannot be used for admin/vouch (they're independent stores,
    /// both using the same ChallengeStore, but a valid challenge_id issued by
    /// /v1/session/challenge is consumed here — the test verifies it's rejected on
    /// the second use regardless of which endpoint issued it).
    #[tokio::test]
    async fn test_session_and_vouch_challenges_independent() {
        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        let (cred_id, sk, urn) =
            enroll_user_helper(&base, "judy", b"cred-cross", "dds.local").await;
        vouch_user(&state, &ts.root, &urn).await;

        // Obtain a session challenge, consume it successfully via /v1/session/assert.
        let (ch_id, ch_b64) = fetch_challenge(&base, "/v1/session/challenge").await;
        let status = assert_session(
            &base,
            &cred_id,
            &sk,
            "dds.local",
            1,
            ch_id.clone(),
            &ch_b64,
            None,
        )
        .await;
        assert_eq!(status, 200, "first session assert should succeed");

        // Now try to reuse the same challenge_id for a second session assert.
        let (auth2, cdh2, sig2) = build_assertion_with_challenge("dds.local", &sk, 2, &ch_b64);
        let req2 = AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: cred_id,
            challenge_id: ch_id,
            client_data_hash: cdh2,
            authenticator_data: auth2,
            signature: sig2,
            duration_secs: None,
        
            ..Default::default()
};
        let resp2 = reqwest::Client::new()
            .post(format!("{base}/v1/session/assert"))
            .json(&req2)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            401,
            "consumed session challenge must not be reusable"
        );
    }

    // ---------- H-7: admin-gate middleware tests ----------

    fn tcp_trust_policy() -> AdminPolicy {
        AdminPolicy {
            trust_loopback_tcp_admin: true,
            admin_uids: Vec::new(),
            admin_sids: Vec::new(),
            service_uid: None,
        }
    }

    fn strict_policy() -> AdminPolicy {
        AdminPolicy {
            trust_loopback_tcp_admin: false,
            admin_uids: vec![4242],
            admin_sids: vec!["S-1-5-21-1-2-3-4242".to_string()],
            service_uid: None,
        }
    }

    #[test]
    fn anonymous_caller_admitted_when_trust_loopback_tcp() {
        let caller = CallerIdentity::Anonymous;
        assert!(caller.is_admin(&tcp_trust_policy()));
    }

    #[test]
    fn anonymous_caller_denied_under_strict_policy() {
        let caller = CallerIdentity::Anonymous;
        assert!(!caller.is_admin(&strict_policy()));
    }

    #[cfg(unix)]
    #[test]
    fn uds_root_is_always_admin() {
        let caller = CallerIdentity::Uds {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        // Root wins even under the strict policy that doesn't list 0.
        assert!(caller.is_admin(&strict_policy()));
    }

    #[cfg(unix)]
    #[test]
    fn uds_service_uid_is_admin() {
        let policy = AdminPolicy {
            trust_loopback_tcp_admin: false,
            admin_uids: Vec::new(),
            admin_sids: Vec::new(),
            service_uid: Some(1000),
        };
        let caller = CallerIdentity::Uds {
            uid: 1000,
            gid: 1000,
            pid: 42,
        };
        assert!(caller.is_admin(&policy));
    }

    #[cfg(unix)]
    #[test]
    fn uds_non_admin_uid_denied() {
        let caller = CallerIdentity::Uds {
            uid: 9999,
            gid: 9999,
            pid: 42,
        };
        assert!(!caller.is_admin(&strict_policy()));
    }

    #[cfg(unix)]
    #[test]
    fn uds_allowlisted_uid_admitted() {
        let caller = CallerIdentity::Uds {
            uid: 4242,
            gid: 4242,
            pid: 42,
        };
        assert!(caller.is_admin(&strict_policy()));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_system_always_admin() {
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-18".to_string(),
            pid: 4,
        };
        assert!(caller.is_admin(&strict_policy()));
    }

    /// Regression: `BUILTIN\Administrators` (`S-1-5-32-544`) is a
    /// group SID and never appears as a caller's primary SID, so
    /// `is_admin` must NOT fast-path it. Group-membership-based
    /// admission requires the pipe listener (G1-S3) to surface
    /// `TokenGroups` separately; until then, admins go through
    /// `admin_sids` by primary SID.
    #[cfg(windows)]
    #[test]
    fn pipe_builtin_admins_group_sid_is_not_an_auto_admin() {
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-32-544".to_string(),
            pid: 7,
        };
        // Under strict_policy the list does not contain the group
        // SID, so admission must be refused.
        assert!(!caller.is_admin(&strict_policy()));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_allowlisted_sid_admitted() {
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-21-1-2-3-4242".to_string(),
            pid: 7,
        };
        assert!(caller.is_admin(&strict_policy()));
    }

    #[cfg(windows)]
    #[test]
    fn pipe_non_admin_sid_denied() {
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-21-9-9-9-1001".to_string(),
            pid: 7,
        };
        assert!(!caller.is_admin(&strict_policy()));
    }

    /// When the router is built with a strict policy and the caller
    /// has no `CallerIdentity` extension (loopback TCP during the
    /// migration), admin endpoints return 403 and public endpoints
    /// keep working.
    #[tokio::test]
    async fn production_router_enforces_admin_gate_under_strict_policy() {
        let state = make_state();
        let svc = state.svc.clone();
        let info = state.info.clone();
        let app = router::<MemoryBackend>(svc, info, strict_policy(), None, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        // Public endpoint still works.
        let resp = reqwest::get(format!("{base}/v1/status")).await.unwrap();
        assert_eq!(resp.status(), 200, "status endpoint must remain public");

        // Admin endpoint denied.
        let resp = reqwest::get(format!("{base}/v1/enrolled-users"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "admin endpoint must return 403 under strict policy"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "not_authorized");

        // Admin challenge is admin-gated too.
        let resp = reqwest::get(format!("{base}/v1/admin/challenge"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);

        // Audit entries (admin-gated) denied.
        let resp = reqwest::get(format!("{base}/v1/audit/entries"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    /// Regression: when `trust_loopback_tcp_admin = true` (the current
    /// default), the admin gate is a no-op on TCP and existing
    /// behavior is preserved.
    #[tokio::test]
    async fn production_router_admits_anonymous_under_trust_loopback() {
        let state = make_state();
        let svc = state.svc.clone();
        let info = state.info.clone();
        let app = router::<MemoryBackend>(svc, info, tcp_trust_policy(), None, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        // enrolled-users needs a device_urn query param; any response
        // *other than* 403 proves the admin gate admitted.
        let resp = reqwest::get(format!(
            "{base}/v1/enrolled-users?device_urn=urn:vouchsafe:device.x"
        ))
        .await
        .unwrap();
        assert_ne!(
            resp.status(),
            403,
            "admin gate must admit Anonymous when trust_loopback_tcp_admin=true"
        );

        // Admin challenge should also be reachable (no body required).
        let resp = reqwest::get(format!("{base}/v1/admin/challenge"))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            403,
            "admin/challenge must admit Anonymous when trust_loopback_tcp_admin=true"
        );
    }

    // ---------- H-6: response MAC signer tests ----------

    fn test_mac_key() -> ResponseMacKey {
        // 32 bytes of deterministic material so tests can recompute.
        let bytes: Vec<u8> = (0u8..32).collect();
        ResponseMacKey(Arc::new(Zeroizing::new(bytes)))
    }

    fn expected_mac(key: &[u8], method: &str, path: &str, body: &[u8]) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(method.as_bytes());
        mac.update(&[0]);
        mac.update(path.as_bytes());
        mac.update(&[0]);
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn mac_key_rejects_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tiny.key");
        std::fs::write(&p, b"short").unwrap();
        assert!(ResponseMacKey::from_file(&p).is_err());
    }

    #[test]
    fn mac_key_loads_from_sufficient_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.key");
        std::fs::write(&p, vec![0u8; 32]).unwrap();
        assert!(ResponseMacKey::from_file(&p).is_ok());
    }

    #[test]
    fn mac_separator_prevents_method_path_splice() {
        // ("GET", "/a/b") and ("GE", "T/a/b") must yield different
        // MACs — the null separator is what prevents the splice.
        let key = test_mac_key();
        let a = key.sign("GET", "/a/b", b"");
        let b = key.sign("GE", "T/a/b", b"");
        assert_ne!(a, b);
    }

    /// Response MAC header is present and correct when a key is
    /// configured. Also asserts the signer runs as the outermost
    /// layer — rate-limit / body-limit errors would otherwise produce
    /// a response without the header.
    #[tokio::test]
    async fn response_mac_header_is_signed_and_verifiable() {
        let state = make_state();
        let svc = state.svc.clone();
        let info = state.info.clone();
        let key = test_mac_key();
        let app = router::<MemoryBackend>(svc, info, tcp_trust_policy(), Some(key.clone()), None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        let resp = reqwest::get(format!("{base}/v1/status")).await.unwrap();
        let header = resp
            .headers()
            .get(RESPONSE_MAC_HEADER)
            .expect("X-DDS-Body-MAC header present")
            .to_str()
            .unwrap()
            .to_owned();
        let body = resp.bytes().await.unwrap();
        let expected = expected_mac(&key.0, "GET", "/v1/status", &body);
        assert_eq!(header, expected, "MAC header matches expected HMAC");
    }

    #[tokio::test]
    async fn response_mac_absent_when_key_not_configured() {
        let state = make_state();
        let svc = state.svc.clone();
        let info = state.info.clone();
        let app = router::<MemoryBackend>(svc, info, tcp_trust_policy(), None, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        let resp = reqwest::get(format!("{base}/v1/status")).await.unwrap();
        assert!(
            resp.headers().get(RESPONSE_MAC_HEADER).is_none(),
            "no MAC header when key not configured"
        );
    }

    // ---------- M-8: device-caller binding tests ----------

    fn anon_caller() -> CallerIdentity {
        CallerIdentity::Anonymous
    }

    #[cfg(unix)]
    fn uds_caller(uid: u32) -> CallerIdentity {
        CallerIdentity::Uds {
            uid,
            gid: uid,
            pid: 1,
        }
    }

    #[test]
    fn anonymous_caller_bypasses_binding_read() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let res = check_device_binding_read(
            &anon_caller(),
            &tcp_trust_policy(),
            Some(&store),
            "urn:device:x",
        );
        assert!(res.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_read_denied_on_unbound_urn_under_strict_policy() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = uds_caller(1000);
        let res = check_device_binding_read(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().status, StatusCode::FORBIDDEN);
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_tofu_binds_then_reads_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = uds_caller(1000);
        let res = tofu_device_binding(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
        let res = check_device_binding_read(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_mismatch_rejected_after_tofu() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let good = uds_caller(1000);
        let bad = uds_caller(9999);
        assert!(tofu_device_binding(&good, &strict_policy(), Some(&store), "urn:device:x").is_ok());
        let res = check_device_binding_read(&bad, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_err());
        let res = tofu_device_binding(&bad, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn admin_caller_bypasses_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let other = uds_caller(1000);
        assert!(tofu_device_binding(&other, &strict_policy(), Some(&store), "urn:device:x").is_ok());
        // uid=0 passes the admin check even under strict_policy().
        let admin = uds_caller(0);
        let res = check_device_binding_read(&admin, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn response_mac_header_covers_error_responses() {
        // An admin-gated endpoint returning 403 must still carry a
        // signed MAC header — otherwise a MITM could manufacture
        // error responses.
        let state = make_state();
        let svc = state.svc.clone();
        let info = state.info.clone();
        let key = test_mac_key();
        let app = router::<MemoryBackend>(svc, info, strict_policy(), Some(key.clone()), None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        let resp = reqwest::get(format!("{base}/v1/admin/challenge"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let header = resp
            .headers()
            .get(RESPONSE_MAC_HEADER)
            .expect("MAC header present even on 403")
            .to_str()
            .unwrap()
            .to_owned();
        let body = resp.bytes().await.unwrap();
        let expected = expected_mac(&key.0, "GET", "/v1/admin/challenge", &body);
        assert_eq!(header, expected);
    }

    // ---------- H-7 step-2: UDS listener end-to-end ----------

    #[cfg(unix)]
    mod uds_listener {
        use super::*;
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;
        use tokio::time::{Duration, sleep};

        async fn wait_for_socket(path: &std::path::Path) {
            use std::os::unix::fs::FileTypeExt;
            for _ in 0..100 {
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.file_type().is_socket() {
                        return;
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
            panic!("UDS socket {} never appeared", path.display());
        }

        async fn send(
            sock: &std::path::Path,
            method: &str,
            uri: &str,
        ) -> (hyper::StatusCode, Bytes) {
            let stream = UnixStream::connect(sock).await.unwrap();
            let io = TokioIo::new(stream);
            let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = hyper::Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "localhost")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        }

        /// Under a strict policy whose `service_uid` is the test
        /// process's effective UID, UDS callers should be admitted to
        /// admin endpoints. This pins the full pipeline: UDS accept →
        /// peer_cred → `CallerIdentity::Uds` injection → admin gate.
        #[tokio::test]
        async fn admin_endpoint_admits_service_uid_caller() {
            let state = make_state();
            let svc = state.svc.clone();
            let info = state.info.clone();

            let tmp = tempfile::tempdir().unwrap();
            let sock = tmp.path().join("dds.sock");
            let addr = format!("unix:{}", sock.display());
            let current_uid = unsafe { libc::geteuid() };
            let policy = AdminPolicy {
                trust_loopback_tcp_admin: false,
                admin_uids: vec![],
                admin_sids: vec![],
                service_uid: Some(current_uid),
            };

            let server = tokio::spawn(async move {
                let _ = super::super::serve::<MemoryBackend>(&addr, svc, info, policy, None, None)
                    .await;
            });
            wait_for_socket(&sock).await;

            // Public endpoint must work.
            let (status, _) = send(&sock, "GET", "/v1/status").await;
            assert!(
                status.is_success(),
                "expected /v1/status to succeed over UDS, got {status}"
            );

            // Admin endpoint — the caller's uid equals the configured
            // `service_uid`, so the gate admits and the handler runs.
            // We only care that it is NOT 403; the underlying request
            // may 200 or 400 depending on handler state.
            let (status, _) = send(&sock, "GET", "/v1/admin/challenge").await;
            assert_ne!(
                status,
                hyper::StatusCode::FORBIDDEN,
                "admin gate denied UDS caller whose uid matches service_uid"
            );

            server.abort();
        }

        /// When `service_uid` is set to a sentinel that cannot match the
        /// test process, the admin gate must return 403 — the UDS peer
        /// creds are being extracted and the policy is being enforced.
        #[tokio::test]
        async fn admin_endpoint_rejects_unknown_uid_caller() {
            let state = make_state();
            let svc = state.svc.clone();
            let info = state.info.clone();

            let tmp = tempfile::tempdir().unwrap();
            let sock = tmp.path().join("dds.sock");
            let addr = format!("unix:{}", sock.display());
            // service_uid = u32::MAX is guaranteed not to match any
            // real process, so the test's own uid must fail the gate.
            let policy = AdminPolicy {
                trust_loopback_tcp_admin: false,
                admin_uids: vec![],
                admin_sids: vec![],
                service_uid: Some(u32::MAX),
            };

            let server = tokio::spawn(async move {
                let _ = super::super::serve::<MemoryBackend>(&addr, svc, info, policy, None, None)
                    .await;
            });
            wait_for_socket(&sock).await;

            let (status, body) = send(&sock, "GET", "/v1/admin/challenge").await;
            assert_eq!(
                status,
                hyper::StatusCode::FORBIDDEN,
                "admin gate must reject non-service uid over UDS; body={:?}",
                String::from_utf8_lossy(&body),
            );

            // Public endpoint remains reachable — the gate is
            // per-route, not per-connection.
            let (status, _) = send(&sock, "GET", "/v1/status").await;
            assert!(status.is_success());

            server.abort();
        }

        /// Socket file permissions must be `0o660` after bind so
        /// other local users can't connect. L-16 / H-5 analogue for
        /// the Unix side of H-7.
        #[tokio::test]
        async fn socket_mode_is_group_only_on_bind() {
            use std::os::unix::fs::PermissionsExt;

            let state = make_state();
            let svc = state.svc.clone();
            let info = state.info.clone();

            let tmp = tempfile::tempdir().unwrap();
            let sock = tmp.path().join("dds.sock");
            let addr = format!("unix:{}", sock.display());
            let policy = AdminPolicy {
                trust_loopback_tcp_admin: false,
                admin_uids: vec![],
                admin_sids: vec![],
                service_uid: Some(unsafe { libc::geteuid() }),
            };

            let server = tokio::spawn(async move {
                let _ = super::super::serve::<MemoryBackend>(&addr, svc, info, policy, None, None)
                    .await;
            });
            wait_for_socket(&sock).await;

            let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o660,
                "expected socket mode 0o660 after bind, got 0o{mode:o}"
            );

            server.abort();
        }

        /// Re-binding over a stale socket (previous run's leftover) must
        /// succeed — the listener removes the file first. Prevents
        /// `EADDRINUSE` on a non-clean shutdown.
        #[tokio::test]
        async fn stale_socket_is_replaced_on_bind() {
            let state = make_state();
            let svc = state.svc.clone();
            let info = state.info.clone();

            let tmp = tempfile::tempdir().unwrap();
            let sock = tmp.path().join("dds.sock");
            // Plant a stale file so `bind` would otherwise fail.
            std::fs::write(&sock, b"stale").unwrap();
            assert!(sock.exists());

            let addr = format!("unix:{}", sock.display());
            let policy = AdminPolicy {
                trust_loopback_tcp_admin: false,
                admin_uids: vec![],
                admin_sids: vec![],
                service_uid: Some(unsafe { libc::geteuid() }),
            };

            let server = tokio::spawn(async move {
                let _ = super::super::serve::<MemoryBackend>(&addr, svc, info, policy, None, None)
                    .await;
            });
            wait_for_socket(&sock).await;

            // Sanity: connect succeeds, so we're hitting the fresh
            // listener, not the stale file.
            let (status, _) = send(&sock, "GET", "/v1/status").await;
            assert!(status.is_success());

            server.abort();
        }
    }
}
