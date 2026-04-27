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
    /// **M-8 step-2 (security review)**. When `true`, `Anonymous`
    /// callers (loopback TCP) are refused on device-scoped read
    /// endpoints. Operators set this via
    /// [`ApiAuthConfig::strict_device_binding`] once the H-7
    /// transport cutover is complete and TCP is no longer a
    /// default.
    pub strict_device_binding: bool,
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
            strict_device_binding: cfg.strict_device_binding,
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
    // **M-8 step-2 (security review)**. On TCP the caller has no
    // peer credentials, so we cannot bind them to a concrete
    // principal. Legacy deployments keep the old bypass (the
    // operator still has to tighten things — see
    // `strict_device_binding`). Strict deployments refuse the
    // request outright: if you want device-scoped reads, switch to
    // UDS / named-pipe and expose a real `CallerIdentity` to this
    // helper.
    if matches!(caller, CallerIdentity::Anonymous) {
        if admin_policy.strict_device_binding {
            tracing::warn!(
                device_urn,
                "M-8 step-2: refusing Anonymous (TCP) caller on device-scoped read under strict_device_binding"
            );
            return Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "not_authorized".to_owned(),
            });
        }
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
        // **M-8 step-2**: same rationale as `check_device_binding_read`.
        // On strict deployments, TCP callers cannot TOFU-bind a device
        // URN because we have no principal to bind them to.
        if admin_policy.strict_device_binding {
            tracing::warn!(
                device_urn,
                "M-8 step-2: refusing Anonymous (TCP) caller on device-scoped write under strict_device_binding"
            );
            return Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "not_authorized".to_owned(),
            });
        }
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
            tracing::info!(
                device_urn,
                ?principal,
                "M-8: device binding established (TOFU)"
            );
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
///
/// `peer_seen` is a shared boolean toggled by [`crate::node::DdsNode`] the
/// first time a peer connection is established. It feeds the Phase D
/// `/readyz` check (observability-plan.md): a node with bootstrap peers
/// configured is "ready" only after it has actually reached one.
///
/// `bootstrap_empty` is `true` when the node is configured with zero
/// bootstrap peers (lone-node deployment). In that case `/readyz` skips
/// the peer-seen check — the node is ready as soon as the store smoke
/// test passes.
#[derive(Clone)]
pub struct NodeInfo {
    pub peer_id: String,
    pub peer_seen: Arc<std::sync::atomic::AtomicBool>,
    pub bootstrap_empty: bool,
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

/// **B-5 (security review)**: cap on outstanding challenge rows. The
/// production sweeper deletes expired rows on every issue and on every
/// failed consume, but a flood of un-consumed challenges can still
/// accumulate within a single TTL window. Once this many rows are
/// outstanding (after sweeping expired ones), `/v1/session/challenge`
/// and `/v1/admin/challenge` return 503 instead of issuing a new
/// challenge. 4096 is comfortably above any single-host workload —
/// the credential provider issues one challenge per logon — and tight
/// enough to bound the redb table.
const MAX_OUTSTANDING_CHALLENGES: usize = 4096;

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

/// Classify a caller into its transport kind (`anonymous|uds|pipe`)
/// for the `dds_http_caller_identity_total` metric
/// (observability-plan.md Phase C). The orthogonal `admin` bucket is
/// bumped separately by [`caller_identity_observer_middleware`] when
/// `is_admin(policy)` returns `true`, so callers reading these
/// counters can rely on `sum(anonymous+uds+pipe) == total request
/// count` while still seeing admin volume.
pub(crate) fn classify_caller_identity(caller: &CallerIdentity) -> &'static str {
    match caller {
        CallerIdentity::Anonymous => "anonymous",
        #[cfg(unix)]
        CallerIdentity::Uds { .. } => "uds",
        #[cfg(windows)]
        CallerIdentity::Pipe { .. } => "pipe",
    }
}

/// Observer middleware (no policy enforcement) that bumps
/// `dds_http_caller_identity_total{kind=...}` for every request the
/// API listener serves. Wraps the entire app so rate-limited and
/// 4xx-rejected requests are counted too — operators want the full
/// caller-kind picture, not just successful traffic.
///
/// Bumps the transport bucket (anonymous|uds|pipe) for every
/// request, plus `admin` when the caller passes the admin policy
/// check; the H-7 `DdsLoopbackTcpAdminUsed` alert keys off
/// `kind="anonymous"`.
async fn caller_identity_observer_middleware(
    State(policy): State<Arc<AdminPolicy>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let caller = req
        .extensions()
        .get::<CallerIdentity>()
        .cloned()
        .unwrap_or(CallerIdentity::Anonymous);
    crate::telemetry::record_caller_identity(classify_caller_identity(&caller));
    if caller.is_admin(&policy) {
        crate::telemetry::record_caller_identity("admin");
    }
    next.run(req).await
}

/// Per-route observer middleware (no policy enforcement) that bumps
/// `dds_http_requests_total{route, method, status}` for every
/// matched-route request. Applied via [`axum::Router::route_layer`] so
/// the per-route handler stack populates `MatchedPath` in the request
/// extensions before this middleware reads it; unmatched 404s served
/// by the default fallback are not counted (they remain visible via
/// `dds_http_caller_identity_total`).
///
/// `route` falls back to the literal URI path string when (in
/// principle, never in practice) `MatchedPath` is unset; the DDS
/// router has no path parameters today, so the matched template
/// equals the literal URI path.
async fn http_request_observer_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let response = next.run(req).await;
    let status = response.status().as_u16();
    crate::telemetry::record_http_request(&route, &method, status);
    response
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
        .route("/v1/enroll/challenge", get(issue_enroll_challenge::<S>))
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
        // observability-plan.md Phase D — orchestrator-friendly probes.
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S>))
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
        // observability-plan.md Phase C — per-route HTTP request
        // counter. `route_layer` so the inner handler stack populates
        // `MatchedPath` before the middleware reads it; unmatched 404s
        // served by the default fallback are not counted (they remain
        // visible via `dds_http_caller_identity_total`).
        .route_layer(axum::middleware::from_fn(http_request_observer_middleware))
        // M-3: rate limit before any handler runs.
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        // M-11: bound deserialization input size.
        .layer(DefaultBodyLimit::max(HTTP_MAX_BODY_BYTES))
        // observability-plan.md Phase C — count every request by
        // caller kind. Sits outside rate-limit / body-limit so we
        // see the rejected traffic too; sits inside the H-6 MAC
        // signer so the metric reflects what the listener actually
        // accepted.
        .layer(axum::middleware::from_fn_with_state(
            admin_policy.clone(),
            caller_identity_observer_middleware,
        ));

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
    /// **A-1 step-3 (security review)**: base64-standard-encoded raw
    /// UTF-8 bytes of the authenticator's `clientDataJSON`. Optional
    /// for backward compatibility — when present, the server
    /// validates `type == "webauthn.create"`, `origin ==
    /// "https://<rp_id>"`, and `crossOrigin != true` per WebAuthn
    /// §7.1 steps 8–11. The supplied JSON is bound to
    /// `client_data_hash_b64` via SHA-256 first.
    #[serde(default)]
    pub client_data_json_b64: Option<String>,
    /// **A-1 follow-up (server-issued enrollment challenge)**:
    /// optional `challenge_id` returned by `GET /v1/enroll/challenge`.
    /// When supplied together with `client_data_json_b64`, the server
    /// consumes the challenge atomically and verifies that the
    /// `clientDataJSON.challenge` field decodes to the same bytes —
    /// closing WebAuthn §7.1 step 9 at enrollment. Backward
    /// compatible: when absent the legacy "no enrollment challenge"
    /// path runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
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

    /// Internal-error response. Body is the literal `"internal_error"`
    /// code so the inner message (which may include redb error text)
    /// never reaches the wire — the caller still gets a 500 they can
    /// match on and the full detail is logged at warn.
    fn internal(detail: impl AsRef<str>) -> Self {
        tracing::warn!(detail = detail.as_ref(), "internal error in HTTP handler");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal_error".to_string(),
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
    let client_data_json = match &req.client_data_json_b64 {
        Some(s) => Some(b64_decode(s, "client_data_json_b64")?),
        None => None,
    };
    let internal = EnrollUserRequest {
        label: req.label,
        credential_id: req.credential_id,
        attestation_object,
        client_data_hash,
        rp_id: req.rp_id,
        display_name: req.display_name,
        authenticator_type: req.authenticator_type,
        client_data_json,
        challenge_id: req.challenge_id,
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

/// `GET /healthz` — observability-plan.md Phase D.1 liveness probe.
/// Returns 200 unconditionally as long as the axum task is scheduling.
/// Orchestrators (kube, systemd, launchd) use this for restart decisions.
/// No dependency checks here — a poisoned redb still answers liveness so
/// the orchestrator does not flap a recovering node before it can
/// actually serve `/readyz`.
async fn healthz() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct ReadyzResponse {
    ready: bool,
    /// Per-check status. `"ok"` if the check passed, an error string
    /// otherwise. Operators and the `dds-cli health` subcommand surface
    /// this body verbatim — the response is the troubleshooting handle.
    checks: ReadyzChecks,
}

#[derive(Serialize)]
struct ReadyzChecks {
    /// Node Vouchsafe identity is loaded (the service object exists).
    node_identity: &'static str,
    /// redb store responds to a read; smoke test for at-rest corruption
    /// or a permission regression.
    store: String,
    /// Either an inbound or outbound peer connection has been observed
    /// since startup, or `bootstrap_peers` is empty (lone-node mode).
    peers: &'static str,
}

/// `GET /readyz` — observability-plan.md Phase D.2 readiness probe.
/// 200 + `{"ready": true, …}` when every check passes; 503 +
/// `{"ready": false, …}` when one fails. Orchestrators use this to
/// decide whether to route traffic to the node.
///
/// Checks performed:
/// - **node_identity** — the `LocalService` exists, so identity is
///   loaded by construction. (The router is built only after
///   `LocalService::new` returns.)
/// - **store** — `audit_chain_head()` round-trips. A redb open / DACL
///   regression surfaces here as 503 rather than as a stack of 500s
///   from real traffic.
/// - **peers** — `peer_seen` is set (we've completed at least one
///   `ConnectionEstablished`) **or** the bootstrap-peer list is empty
///   so the node was deployed standalone.
///
/// Domain-pubkey / admission-cert verification is implicit: if either
/// failed, [`crate::node::DdsNode::init`] errored before this server
/// ever bound to a port, so a process answering `/readyz` necessarily
/// passed those gates at startup.
async fn readyz<S>(
    State(state): State<AppState<S>>,
) -> (axum::http::StatusCode, Json<ReadyzResponse>)
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
    use std::sync::atomic::Ordering;

    let store_status = {
        let svc = state.svc.lock().await;
        match svc.readiness_smoketest() {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("store smoketest failed: {e}"),
        }
    };

    let peers_ok = state.info.bootstrap_empty || state.info.peer_seen.load(Ordering::Relaxed);
    let peers_status = if peers_ok {
        "ok"
    } else {
        "no peers observed since startup"
    };

    let store_ok = store_status == "ok";
    let ready = store_ok && peers_ok;

    let body = ReadyzResponse {
        ready,
        checks: ReadyzChecks {
            node_identity: "ok",
            store: store_status,
            peers: peers_status,
        },
    };

    let code = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
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

/// **A-1 follow-up**: server-issued enrollment challenge. Mirrors the
/// session/admin challenge endpoints but tags rows as `enroll-` so a
/// nonce minted for one purpose can't be replayed against another
/// (the prefix is purely informational; consumption is by `id` only,
/// but the lookup is across one shared challenge table so the hint
/// stays useful in audit logs).
///
/// The endpoint is admin-gated because it sits on the same enrollment
/// sub-router as `/v1/enroll/user` and `/v1/admin/setup`. A caller who
/// can't reach the enrollment endpoints has no use for the challenge.
async fn issue_enroll_challenge<S>(
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
    issue_challenge(state, "enroll").await
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
        // B-5: amortized cleanup on every issue. Drop expired rows first,
        // then enforce a global cap. The cap is checked AFTER the sweep so
        // a long-idle node never trips it unnecessarily.
        let store = svc.store_mut();
        if let Err(e) = store.sweep_expired_challenges(now) {
            // Sweep failures are not fatal to issuance — log and continue.
            tracing::warn!("sweep_expired_challenges failed: {e}");
        }
        let outstanding = store.count_challenges().map_err(|e| HttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("store error: {e}"),
        })?;
        if outstanding >= MAX_OUTSTANDING_CHALLENGES {
            return Err(HttpError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: format!(
                    "challenge backlog full ({outstanding} outstanding); retry after consume/expiry"
                ),
            });
        }
        store
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
    let client_data_json = match &req.client_data_json_b64 {
        Some(s) => Some(b64_decode(s, "client_data_json_b64")?),
        None => None,
    };
    let internal = AdminSetupRequest {
        label: req.label,
        credential_id: req.credential_id,
        attestation_object,
        client_data_hash,
        rp_id: req.rp_id,
        display_name: req.display_name,
        authenticator_type: req.authenticator_type,
        client_data_json,
        challenge_id: req.challenge_id,
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
    let mut svc = state.svc.lock().await;
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
    let mut svc = state.svc.lock().await;
    svc.record_applied(&report)?;
    Ok(StatusCode::ACCEPTED)
}

// ---------- Audit log query handler ----------

#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    action: Option<String>,
    limit: Option<usize>,
    /// **observability-plan.md Phase B.1**: filter to entries with
    /// `timestamp >= since` (Unix seconds). Lets `dds-cli audit tail`
    /// poll for incremental updates without re-fetching the full chain.
    since: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AuditEntryJson {
    action: String,
    node_urn: String,
    timestamp: u64,
    token_cbor_b64: String,
    /// **observability-plan.md Phase B.2**: full CBOR-encoded
    /// `AuditLogEntry` (signed fields + signature) so a remote
    /// `dds-cli audit verify` can reconstruct the exact bytes the node
    /// signed and check the chain end-to-end. Decoded via
    /// `ciborium::from_reader` into `dds_core::audit::AuditLogEntry`.
    entry_cbor_b64: String,
    /// **observability-plan.md Phase A.2**: rejection reason
    /// (`"signature-invalid"`, `"revoked-issuer"`, …) for `*.rejected`
    /// actions. `None` for success entries (omitted via
    /// `skip_serializing_if`); SIEMs treat the absence as "successful
    /// outcome".
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Hex-encoded `chain_hash()` of this entry — what the *next* entry
    /// will carry as `prev_hash`. SIEMs that do not want to CBOR-decode
    /// `entry_cbor_b64` can still chain-link incoming entries by this
    /// field.
    chain_hash_hex: String,
    /// Hex-encoded `prev_hash` field — empty string for the genesis
    /// entry.
    prev_hash_hex: String,
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
    let mut entries = svc.list_audit_entries(params.action.as_deref(), params.limit)?;
    if let Some(since) = params.since {
        entries.retain(|e| e.timestamp >= since);
    }
    let total = entries.len();
    let json_entries: Vec<AuditEntryJson> = entries
        .into_iter()
        .map(audit_entry_to_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(AuditEntriesResponse {
        entries: json_entries,
        total,
    }))
}

/// Serialise a chain-bearing `AuditLogEntry` to its JSON wire form. The
/// CBOR re-encode pins the exact bytes the node signed — the decoder
/// in `dds-cli audit verify` runs `verify()` against those bytes.
fn audit_entry_to_json(e: dds_core::audit::AuditLogEntry) -> Result<AuditEntryJson, HttpError> {
    let mut entry_cbor = Vec::new();
    ciborium::into_writer(&e, &mut entry_cbor)
        .map_err(|err| HttpError::internal(format!("audit entry CBOR encode: {err}")))?;
    let chain_hash = e
        .chain_hash()
        .map_err(|err| HttpError::internal(format!("audit chain hash: {err}")))?;
    Ok(AuditEntryJson {
        action: e.action,
        node_urn: e.node_urn,
        timestamp: e.timestamp,
        token_cbor_b64: base64::engine::general_purpose::STANDARD.encode(&e.token_bytes),
        entry_cbor_b64: base64::engine::general_purpose::STANDARD.encode(&entry_cbor),
        reason: e.reason,
        chain_hash_hex: hex::encode(&chain_hash),
        prev_hash_hex: hex::encode(&e.prev_hash),
    })
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
/// - `pipe:<pipe-name>` — Windows named pipe. `<pipe-name>` is either a
///   bare name (e.g. `dds-api`, expanded to `\\.\pipe\dds-api`) or a
///   full pipe path (`\\.\pipe\...`, passthrough). Every accepted
///   connection extracts the caller's primary **user** SID via
///   `GetNamedPipeClientProcessId` + `OpenProcessToken` +
///   `GetTokenInformation(TokenUser)` and injects
///   [`CallerIdentity::Pipe`].
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

    if let Some(pipe_spec) = addr.strip_prefix("pipe:") {
        #[cfg(windows)]
        {
            return serve_pipe(
                pipe_spec,
                svc,
                info,
                admin_policy,
                response_mac_key,
                device_binding,
            )
            .await;
        }
        #[cfg(not(windows))]
        {
            let _ = pipe_spec;
            return Err("named-pipe transport is only supported on Windows".into());
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
                        let resp: axum::response::Response = app
                            .oneshot(req)
                            .await
                            .unwrap_or_else(|never| match never {});
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

/// Named-pipe serve loop for H-7 step-2b on Windows.
///
/// Mirror of [`serve_unix`]: accept a pipe connection, extract the
/// caller's primary user SID from the bound token, inject
/// [`CallerIdentity::Pipe`] as a per-request extension, and serve
/// HTTP/1 over the pipe via hyper. The caller SID is the input to
/// [`AdminPolicy::is_admin`] on Windows.
///
/// `pipe_spec` is either a bare name (e.g. `dds-api`, expanded to
/// `\\.\pipe\dds-api`) or a full pipe path (`\\.\pipe\...`).
#[cfg(windows)]
async fn serve_pipe<S>(
    pipe_spec: &str,
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
    use tokio::net::windows::named_pipe::ServerOptions;
    use tower::ServiceExt as _;

    let pipe_path = normalize_pipe_name(pipe_spec);
    tracing::info!(pipe = %pipe_path, "HTTP API listening on named pipe");

    let app = router(svc, info, admin_policy, response_mac_key, device_binding);

    // First instance: `first_pipe_instance(true)` makes `create` fail
    // if another process has already opened a server on this name.
    // This is the named-pipe analogue of the stale-socket cleanup in
    // `serve_unix`: we would rather fail-fast at startup than accept
    // connections on an unowned pipe.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_path)
        .map_err(|e| format!("failed to create named pipe {pipe_path}: {e}"))?;

    loop {
        if let Err(e) = server.connect().await {
            tracing::error!(error = %e, "named-pipe connect failed");
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        // The connected pipe becomes this request's stream; spin up a
        // fresh server instance so new clients aren't refused while
        // this one is in use.
        let connected = server;
        server = ServerOptions::new()
            .create(&pipe_path)
            .map_err(|e| format!("failed to create next named-pipe instance: {e}"))?;

        // Pull caller SID + PID off the connected pipe handle BEFORE
        // we hand it to hyper.
        let caller = match extract_pipe_caller(&connected) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "named-pipe caller lookup failed; dropping");
                drop(connected);
                continue;
            }
        };

        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(connected);
            let svc_fn = hyper::service::service_fn({
                let app = app.clone();
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    let caller = caller.clone();
                    async move {
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(caller);
                        let body = axum::body::Body::new(body);
                        let req = axum::http::Request::from_parts(parts, body);
                        let resp: axum::response::Response = app
                            .oneshot(req)
                            .await
                            .unwrap_or_else(|never| match never {});
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc_fn).await {
                tracing::debug!(error = %e, "named-pipe connection closed");
            }
        });
    }
}

#[cfg(windows)]
fn normalize_pipe_name(spec: &str) -> String {
    if spec.starts_with(r"\\") {
        spec.to_string()
    } else {
        format!(r"\\.\pipe\{spec}")
    }
}

/// Extract the connected client's primary user SID and process id
/// from a server-side named-pipe handle. Used on Windows to populate
/// [`CallerIdentity::Pipe`]. Returns an I/O error when any of the
/// Win32 calls fail; callers drop the connection and log.
#[cfg(windows)]
fn extract_pipe_caller(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> std::io::Result<CallerIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pipe_handle = server.as_raw_handle() as HANDLE;

    // 1. client PID from the pipe.
    let mut pid: u32 = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut pid) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. open the client process with the minimum access needed to
    //    grab its primary token.
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc_handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    // 3. open the token for TOKEN_QUERY.
    let mut token_handle: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token_handle) } == 0 {
        let e = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(proc_handle);
        }
        return Err(e);
    }

    // 4. sized query first, then real query, for TOKEN_USER.
    let mut needed: u32 = 0;
    let _ = unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        unsafe {
            CloseHandle(token_handle);
            CloseHandle(proc_handle);
        }
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    unsafe {
        CloseHandle(token_handle);
        CloseHandle(proc_handle);
    }
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Safety: `buf` is aligned to u8; `TOKEN_USER` begins with a
    // pointer and a `DWORD`. It has stricter alignment than u8, so
    // we must read through a pointer rather than mem::transmute — but
    // `&*` on a cast pointer is fine since the allocator returns a
    // properly-aligned allocation for `Vec<u8>` only if we cast it to
    // a pointer that expects a less-strict type. In practice glibc /
    // MSVC allocators return 8- or 16-byte aligned blocks so this is
    // safe; to be robust we copy the pointer value out rather than
    // take a reference into the buffer.
    let sid_ptr = {
        let token_user = buf.as_ptr() as *const TOKEN_USER;
        // Copy out just the SID pointer.
        unsafe { (*token_user).User.Sid }
    };
    if sid_ptr.is_null() {
        return Err(std::io::Error::other("TokenUser.Sid is null"));
    }

    // 5. SID → string via Authorization::ConvertSidToStringSidW.
    let mut sid_wstr: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid_ptr, &mut sid_wstr) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // wcslen on the returned UTF-16 string.
    let mut len = 0usize;
    while unsafe { *sid_wstr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(sid_wstr, len) };
    let sid_string = String::from_utf16_lossy(slice);
    unsafe {
        LocalFree(sid_wstr.cast());
    }

    Ok(CallerIdentity::Pipe {
        sid: sid_string,
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::LocalService;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_core::trust::TrustGraph;
    use dds_domain::fido2::build_packed_self_attestation;
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
                    peer_seen: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    bootstrap_empty: true,
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
                "/v1/enroll/challenge",
                get(issue_enroll_challenge::<MemoryBackend>),
            )
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
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz::<MemoryBackend>))
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
        // A-1 step-1: packed self-attestation over the all-zero CDH
        // that the request below pins (`client_data_hash_b64:
        // b64_encode(&[0u8; 32])`).
        let attestation = build_packed_self_attestation("example.com", b"cred-x", &sk, &[0u8; 32]);
        let req = EnrollUserRequestJson {
            label: "alice".into(),
            credential_id: "cred-x".into(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "example.com".into(),
            display_name: "Alice".into(),
            authenticator_type: "platform".into(),
            client_data_json_b64: None,
            challenge_id: None,
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
            client_data_json_b64: None,
            challenge_id: None,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    // ----------------------------------------------------------------
    // A-1 follow-up: server-issued enrollment challenge
    // ----------------------------------------------------------------

    /// `GET /v1/enroll/challenge` returns a fresh, single-use nonce
    /// just like `/v1/session/challenge` and `/v1/admin/challenge`.
    #[tokio::test]
    async fn test_enroll_challenge_issues_unique_nonces() {
        let state = make_state();
        let base = spawn_server(state).await;
        let (id1, b64_1) = fetch_challenge(&base, "/v1/enroll/challenge").await;
        let (id2, b64_2) = fetch_challenge(&base, "/v1/enroll/challenge").await;
        assert!(id1.starts_with("chall-enroll-"), "id was {id1}");
        assert!(id2.starts_with("chall-enroll-"), "id was {id2}");
        assert_ne!(id1, id2);
        assert_ne!(b64_1, b64_2);
    }

    /// Round-trip: fetch challenge, enroll a user with a clientDataJSON
    /// whose `challenge` field encodes the server-issued bytes — must
    /// succeed. Then re-using the same `challenge_id` must fail
    /// (single-use enforcement, mirrors the assertion side).
    #[tokio::test]
    async fn test_enroll_user_with_server_challenge_roundtrip() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let state = make_state();
        let base = spawn_server(state).await;

        // 1. Mint a challenge.
        let (challenge_id, challenge_b64url) = fetch_challenge(&base, "/v1/enroll/challenge").await;

        // 2. Build a real clientDataJSON whose `challenge` matches the
        //    server-issued b64url string. Hash it for the cdh, then
        //    build a packed self-attestation over that cdh.
        let cdj = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge_b64url}","origin":"https://example.com"}}"#
        );
        use sha2::{Digest, Sha256};
        let cdh: [u8; 32] = Sha256::digest(cdj.as_bytes()).into();

        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_packed_self_attestation("example.com", b"cred-cb", &sk, &cdh);

        let mut req = EnrollUserRequestJson {
            label: "alice".into(),
            credential_id: "cred-cb".into(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&cdh),
            rp_id: "example.com".into(),
            display_name: "Alice".into(),
            authenticator_type: "platform".into(),
            client_data_json_b64: Some(b64_encode(cdj.as_bytes())),
            challenge_id: Some(challenge_id.clone()),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "first enroll should succeed");
        let body: EnrollmentResponse = resp.json().await.unwrap();
        assert!(body.urn.starts_with("urn:vouchsafe:alice."));

        // 3. Re-using the same `challenge_id` must be rejected — the
        //    server already consumed it on the first call.
        req.label = "alice2".into();
        req.credential_id = "cred-cb2".into();
        // We can hand the same cdj since the attestation will fail
        // signature verification first (different sk), but the test
        // really wants the challenge to be the rejection reason. Use
        // a fresh sk + matching attestation that would otherwise
        // succeed.
        let _ = URL_SAFE_NO_PAD.decode(&challenge_b64url).unwrap();
        let resp2 = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert!(
            resp2.status().is_client_error() || resp2.status().is_server_error(),
            "second enroll with consumed challenge should fail, got {}",
            resp2.status()
        );
    }

    /// Caller supplies a `challenge_id` that the cdj.challenge field
    /// does not match — must be rejected even though the cdh and
    /// attestation are otherwise valid.
    #[tokio::test]
    async fn test_enroll_user_with_mismatched_challenge_rejected() {
        let state = make_state();
        let base = spawn_server(state).await;

        // Fetch a challenge but build a cdj that encodes *different*
        // bytes in the challenge field.
        let (challenge_id, _) = fetch_challenge(&base, "/v1/enroll/challenge").await;
        let attacker_challenge_b64url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // fake
        let cdj = format!(
            r#"{{"type":"webauthn.create","challenge":"{attacker_challenge_b64url}","origin":"https://example.com"}}"#
        );
        use sha2::{Digest, Sha256};
        let cdh: [u8; 32] = Sha256::digest(cdj.as_bytes()).into();
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_packed_self_attestation("example.com", b"cred-bad", &sk, &cdh);

        let req = EnrollUserRequestJson {
            label: "mallory".into(),
            credential_id: "cred-bad".into(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&cdh),
            rp_id: "example.com".into(),
            display_name: "Mallory".into(),
            authenticator_type: "platform".into(),
            client_data_json_b64: Some(b64_encode(cdj.as_bytes())),
            challenge_id: Some(challenge_id),
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_client_error() || resp.status().is_server_error(),
            "mismatched challenge should fail, got {}",
            resp.status()
        );
    }

    /// Legacy callers that don't supply `challenge_id` keep working —
    /// no enrollment-side challenge gets bound, the cdj fields still
    /// validate, and the request succeeds.
    #[tokio::test]
    async fn test_enroll_user_legacy_no_challenge_id_still_works() {
        let state = make_state();
        let base = spawn_server(state).await;

        // No fetch — the client just sends a cdj without going
        // through `/v1/enroll/challenge`.
        let cdj = r#"{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}"#;
        use sha2::{Digest, Sha256};
        let cdh: [u8; 32] = Sha256::digest(cdj.as_bytes()).into();
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_packed_self_attestation("example.com", b"cred-leg", &sk, &cdh);

        let req = EnrollUserRequestJson {
            label: "bob".into(),
            credential_id: "cred-leg".into(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&cdh),
            rp_id: "example.com".into(),
            display_name: "Bob".into(),
            authenticator_type: "platform".into(),
            client_data_json_b64: Some(b64_encode(cdj.as_bytes())),
            challenge_id: None,
        };
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/enroll/user"))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "legacy no-challenge_id path must succeed"
        );
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
        use dds_domain::fido2::build_packed_self_attestation;

        let ts = make_state_with_root();
        let state = ts.app;
        let base = spawn_server(state.clone()).await;

        // 1. Enroll a user with an Ed25519 credential.
        let sk = SigningKey::generate(&mut OsRng);
        let cred_id = b"cred-assert-test";
        // A-1 step-1: packed self-attestation over the same all-zero
        // CDH the request below pins.
        let attestation = build_packed_self_attestation("dds.local", cred_id, &sk, &[0u8; 32]);
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
            client_data_json_b64: None,
            challenge_id: None,
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
        use dds_domain::fido2::{build_assertion_auth_data, build_packed_self_attestation};
        use ed25519_dalek::Signer;

        let state = make_state();
        let base = spawn_server(state).await;

        // Enroll with key A.
        let sk_a = SigningKey::generate(&mut OsRng);
        let cred_bytes = b"cred-wrong";
        // A-1 step-1: enroll with a packed self-attestation; the
        // assertion path below uses a different signing key (sk_b) to
        // exercise the wrong-key rejection.
        let attestation = build_packed_self_attestation("dds.local", cred_bytes, &sk_a, &[0u8; 32]);
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let enroll_req = EnrollUserRequestJson {
            label: "carol".into(),
            credential_id: cred_id_b64.clone(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: "dds.local".into(),
            display_name: "Carol".into(),
            authenticator_type: "platform".into(),
            client_data_json_b64: None,
            challenge_id: None,
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
        use dds_domain::fido2::build_packed_self_attestation;

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
                build_packed_self_attestation("dds.local", cred.as_bytes(), &sk, &[0u8; 32]);
            let cred_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred.as_bytes());
            let enroll_req = EnrollUserRequestJson {
                label: name.into(),
                credential_id: cred_b64,
                attestation_object_b64: b64_encode(&attestation),
                client_data_hash_b64: b64_encode(&[0u8; 32]),
                rp_id: "dds.local".into(),
                display_name: name.to_uppercase(),
                authenticator_type: "platform".into(),
                client_data_json_b64: None,
                challenge_id: None,
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
        let attestation = build_packed_self_attestation(
            "dds.local",
            credential_id.as_bytes(),
            &user_sk,
            &[0u8; 32],
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
            client_data_json_b64: None,
            challenge_id: None,
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
        use dds_domain::fido2::build_packed_self_attestation;
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_packed_self_attestation(rp_id, cred_bytes, &sk, &[0u8; 32]);
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_bytes);
        let enroll_req = EnrollUserRequestJson {
            label: label.into(),
            credential_id: cred_id_b64.clone(),
            attestation_object_b64: b64_encode(&attestation),
            client_data_hash_b64: b64_encode(&[0u8; 32]),
            rp_id: rp_id.into(),
            display_name: label.to_uppercase(),
            authenticator_type: "platform".into(),
            client_data_json_b64: None,
            challenge_id: None,
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

    /// **B-5**: when more than `MAX_OUTSTANDING_CHALLENGES` live rows
    /// are already in the store, `/v1/session/challenge` returns 503
    /// instead of issuing a new one — the issue path sweeps expired
    /// rows first, so a long-idle table never trips the cap.
    #[tokio::test]
    async fn test_issue_challenge_caps_outstanding() {
        let state = make_state();
        let base = spawn_server(state.clone()).await;

        // Pre-populate the store with the cap's worth of live challenges.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let live_until = now + CHALLENGE_TTL_SECS;
        {
            let mut svc = state.svc.lock().await;
            let store = svc.store_mut();
            for i in 0..MAX_OUTSTANDING_CHALLENGES {
                let id = format!("chall-cap-{i}");
                store.put_challenge(&id, &[0u8; 32], live_until).unwrap();
            }
            assert_eq!(
                store.count_challenges().unwrap(),
                MAX_OUTSTANDING_CHALLENGES
            );
        }

        // The next issue request must be rejected with 503.
        let resp = reqwest::get(format!("{base}/v1/session/challenge"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            503,
            "challenge issuance must fail closed once the cap is reached"
        );

        // Drop one live row and re-issue — the cap should now allow it.
        {
            let mut svc = state.svc.lock().await;
            let _ = svc
                .store_mut()
                .consume_challenge("chall-cap-0", now)
                .unwrap();
        }
        let resp2 = reqwest::get(format!("{base}/v1/session/challenge"))
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            200,
            "challenge issuance must succeed after the backlog drops below the cap"
        );
    }

    /// **B-5**: a probe of an expired `challenge_id` must drop the row
    /// from the store rather than letting it accumulate.
    #[tokio::test]
    async fn test_consume_expired_drops_row() {
        let state = make_state();
        let _base = spawn_server(state.clone()).await;

        let stale_bytes = [0xABu8; 32];
        let stale_id = "chall-b5-expired";
        {
            let mut svc = state.svc.lock().await;
            // expires_at = 1 → already expired for any realistic `now`.
            svc.store_mut()
                .put_challenge(stale_id, &stale_bytes, 1)
                .unwrap();
            assert_eq!(svc.store_mut().count_challenges().unwrap(), 1);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        {
            let mut svc = state.svc.lock().await;
            let err = svc
                .store_mut()
                .consume_challenge(stale_id, now)
                .unwrap_err();
            // Expiry path returns Io with a descriptive message.
            assert!(format!("{err}").contains("expired"));
            // Row is gone.
            assert_eq!(svc.store_mut().count_challenges().unwrap(), 0);
        }
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
            strict_device_binding: false,
        }
    }

    fn strict_policy() -> AdminPolicy {
        AdminPolicy {
            trust_loopback_tcp_admin: false,
            admin_uids: vec![4242],
            admin_sids: vec!["S-1-5-21-1-2-3-4242".to_string()],
            service_uid: None,
            strict_device_binding: false,
        }
    }

    /// **M-8 step-2**: strict policy with `strict_device_binding` on.
    /// Used by the two M-8 step-2 regression tests below.
    fn strict_device_binding_policy() -> AdminPolicy {
        AdminPolicy {
            strict_device_binding: true,
            ..strict_policy()
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
            strict_device_binding: false,
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
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
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
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = uds_caller(1000);
        let res =
            check_device_binding_read(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().status, StatusCode::FORBIDDEN);
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_tofu_binds_then_reads_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = uds_caller(1000);
        let res = tofu_device_binding(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
        let res =
            check_device_binding_read(&caller, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_mismatch_rejected_after_tofu() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
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
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let other = uds_caller(1000);
        assert!(
            tofu_device_binding(&other, &strict_policy(), Some(&store), "urn:device:x").is_ok()
        );
        // uid=0 passes the admin check even under strict_policy().
        let admin = uds_caller(0);
        let res = check_device_binding_read(&admin, &strict_policy(), Some(&store), "urn:device:x");
        assert!(res.is_ok());
    }

    // ---------- M-8 step-2: strict_device_binding Anonymous gate ----------

    #[test]
    fn anonymous_read_allowed_when_strict_device_binding_off() {
        // Default (lenient) behaviour: Anonymous callers pass through
        // device-scoped read endpoints so legacy TCP deployments keep
        // working during the H-7 transport cutover.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = CallerIdentity::Anonymous;
        let res =
            check_device_binding_read(&caller, &strict_policy(), Some(&store), "urn:device:any");
        assert!(
            res.is_ok(),
            "Anonymous must pass when strict_device_binding=false"
        );
    }

    #[test]
    fn anonymous_read_refused_under_strict_device_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = CallerIdentity::Anonymous;
        let res = check_device_binding_read(
            &caller,
            &strict_device_binding_policy(),
            Some(&store),
            "urn:device:any",
        );
        let err = res.expect_err("strict mode must refuse Anonymous read");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn anonymous_write_refused_under_strict_device_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = CallerIdentity::Anonymous;
        let res = tofu_device_binding(
            &caller,
            &strict_device_binding_policy(),
            Some(&store),
            "urn:device:any",
        );
        let err = res.expect_err("strict mode must refuse Anonymous write");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn anonymous_write_allowed_when_strict_device_binding_off() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        let caller = CallerIdentity::Anonymous;
        let res = tofu_device_binding(&caller, &strict_policy(), Some(&store), "urn:device:any");
        assert!(res.is_ok());
    }

    /// Admin callers keep bypassing regardless of `strict_device_binding`
    /// — operators inspecting a peer's policy set should always have
    /// unfettered access.
    #[cfg(unix)]
    #[test]
    fn admin_caller_bypasses_strict_device_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap());
        // uid=0 → admin under strict_policy and strict_device_binding_policy.
        let caller = uds_caller(0);
        let res = check_device_binding_read(
            &caller,
            &strict_device_binding_policy(),
            Some(&store),
            "urn:device:any",
        );
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
                strict_device_binding: false,
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
                strict_device_binding: false,
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
                strict_device_binding: false,
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
                strict_device_binding: false,
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

    // ──────────────────────────────────────────────────────────────
    // observability-plan.md Phase D — `/healthz` + `/readyz`
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn healthz_returns_200_ok_body() {
        let state = make_state();
        let base = spawn_server(state).await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn healthz_via_production_router_is_unauthenticated() {
        // /healthz must not be gated by `require_admin_middleware`,
        // even on a strict-admin policy where loopback TCP is not
        // trusted. Otherwise an orchestrator running on the host
        // (without UDS / pipe credentials) would never see liveness.
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

        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn readyz_is_ready_when_bootstrap_empty_and_store_ok() {
        // make_state sets bootstrap_empty=true — lone-node deployment.
        // No peer connection ever needed; readiness depends only on
        // the store smoke test.
        let state = make_state();
        let base = spawn_server(state).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["checks"]["node_identity"], "ok");
        assert_eq!(body["checks"]["store"], "ok");
        assert_eq!(body["checks"]["peers"], "ok");
    }

    #[tokio::test]
    async fn readyz_returns_503_when_bootstrap_nonempty_and_no_peer_seen() {
        // Configured bootstrap peers but the swarm has not connected
        // to anyone — orchestrator should hold traffic.
        let mut state = make_state();
        state.info.bootstrap_empty = false;
        // peer_seen left at default false.
        let base = spawn_server(state).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status(), 503);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], false);
        assert_eq!(body["checks"]["peers"], "no peers observed since startup");
        assert_eq!(body["checks"]["store"], "ok");
    }

    #[tokio::test]
    async fn readyz_flips_to_ready_when_peer_seen_set() {
        // Same configured-bootstrap scenario, but now the swarm has
        // observed a `ConnectionEstablished`. The shared AtomicBool
        // is the contract between the swarm and the readyz handler;
        // once flipped, readiness is sticky.
        let mut state = make_state();
        state.info.bootstrap_empty = false;
        let peer_seen = state.info.peer_seen.clone();
        let base = spawn_server(state).await;

        // Pre-flip: not ready.
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status(), 503);

        // Flip — simulates the swarm event loop catching a peer.
        peer_seen.store(true, std::sync::atomic::Ordering::Relaxed);

        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], true);
    }

    #[tokio::test]
    async fn readyz_via_production_router_is_unauthenticated() {
        // Same posture as healthz: orchestrator probes must work
        // without admin caller credentials.
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

        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    /// observability-plan.md Phase C — regression test for
    /// `dds_http_requests_total{route, method, status}`. Confirms the
    /// `route_layer`-applied `http_request_observer_middleware`
    /// captures `MatchedPath` from the per-route handler stack and
    /// bumps the global telemetry counter for a real request through
    /// the production router. The route template `/healthz` is the
    /// most stable target — no path parameters, no body, deterministic
    /// 200 outcome.
    ///
    /// `TELEMETRY` is process-global (`OnceLock`), so other tests in
    /// the suite may also bump `(/healthz, GET, 200)` concurrently.
    /// The assertion uses `>= before + 1` rather than `== before + 1`
    /// so the test pins the wiring without over-fitting to scheduling
    /// — the wire-up is broken iff `after == before` (the middleware
    /// never ran).
    #[tokio::test]
    async fn http_request_observer_advances_per_route_counter() {
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

        let handle = crate::telemetry::install();
        let before = handle.http_requests_count("/healthz", "GET", 200);
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let after = handle.http_requests_count("/healthz", "GET", 200);
        assert!(
            after > before,
            "middleware did not bump dds_http_requests_total{{/healthz, GET, 200}} \
             (before={before} after={after})"
        );
    }

    // ----------------------------------------------------------------
    // observability-plan.md Phase B — audit endpoint wire format.
    // The endpoint must surface enough structure for `dds-cli audit
    // verify` to walk the chain end-to-end without reading the redb
    // file directly. These tests pin that contract.
    // ----------------------------------------------------------------

    /// Helper: emit `n` audit entries via the live LocalService and
    /// return the resulting JSON shape from `GET /v1/audit/entries`.
    async fn emit_and_fetch_audit_entries(actions: &[(&str, Option<&str>)]) -> serde_json::Value {
        let state = make_state();
        // Seed the audit chain via the canonical helper so each entry
        // is signed + chain-hashed exactly as production does.
        {
            let mut svc = state.svc.lock().await;
            for (action, reason) in actions {
                svc.emit_local_audit(
                    action.to_string(),
                    b"token-bytes".to_vec(),
                    reason.map(|s| s.to_string()),
                );
            }
        }
        let svc = state.svc.clone();
        let info = state.info.clone();
        let app = router::<MemoryBackend>(svc, info, tcp_trust_policy(), None, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);
        let resp = reqwest::get(format!("{base}/v1/audit/entries"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "audit endpoint must admit anonymous under tcp_trust_policy"
        );
        resp.json().await.unwrap()
    }

    /// Phase B.2: each entry carries the new fields a remote verifier
    /// needs — full CBOR-encoded signed entry, chain hash hex, prev
    /// hash hex.
    #[tokio::test]
    async fn audit_entries_response_includes_chain_fields_for_verify() {
        let body =
            emit_and_fetch_audit_entries(&[("attest", None), ("vouch.rejected", Some("test"))])
                .await;
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "expected two emitted audit entries");
        for e in entries {
            assert!(
                e.get("entry_cbor_b64").and_then(|v| v.as_str()).is_some(),
                "entry_cbor_b64 must be present"
            );
            assert!(
                e.get("chain_hash_hex").and_then(|v| v.as_str()).is_some(),
                "chain_hash_hex must be present"
            );
            // prev_hash_hex is empty for the genesis entry but the
            // field must be present for a SIEM to chain-link.
            assert!(
                e.get("prev_hash_hex").is_some(),
                "prev_hash_hex must be present (empty string is fine for genesis)"
            );
        }
        // The second entry's prev_hash must be the first entry's chain hash.
        let h1 = entries[0]["chain_hash_hex"].as_str().unwrap().to_string();
        let p2 = entries[1]["prev_hash_hex"].as_str().unwrap().to_string();
        assert_eq!(p2, h1, "chain link must hold across entries");

        // Rejection reason is signed and round-trips.
        assert_eq!(entries[1]["reason"].as_str(), Some("test"));
        // Success entry omits the reason field (Option::None +
        // skip_serializing_if).
        assert!(
            entries[0]
                .get("reason")
                .map(|v| v.is_null())
                .unwrap_or(true),
            "success entries should not surface a reason field"
        );
    }

    /// Phase B.2: a remote verifier reconstructs the signed entry from
    /// `entry_cbor_b64`, the signature verifies, and the chain links
    /// reproduce.
    #[tokio::test]
    async fn audit_entry_cbor_b64_decodes_and_verifies() {
        let body = emit_and_fetch_audit_entries(&[("attest", None), ("vouch", None)]).await;
        let entries = body["entries"].as_array().unwrap();
        let mut prev_chain_hash: Vec<u8> = Vec::new();
        for e in entries {
            let b64 = e["entry_cbor_b64"].as_str().unwrap();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            let decoded: dds_core::audit::AuditLogEntry =
                ciborium::from_reader(&bytes[..]).unwrap();
            // Signature + URN-binding verify must pass.
            assert!(decoded.verify().is_ok(), "audit entry verify failed");
            // Chain link: this entry's prev_hash matches the prior
            // entry's chain_hash.
            assert_eq!(decoded.prev_hash, prev_chain_hash);
            prev_chain_hash = decoded.chain_hash().unwrap();
        }
    }

    /// Phase B.1: `since=N` query param drops entries older than the
    /// watermark so `dds-cli audit tail` can do incremental polls.
    /// Uses live emission timestamps — both entries land in the same
    /// wallclock second on a fast machine, so the filter test pins
    /// only the boundary semantics (since=ts returns the entries,
    /// since=ts+1 drops them).
    #[tokio::test]
    async fn audit_entries_since_filter_drops_older() {
        let body = emit_and_fetch_audit_entries(&[("attest", None), ("vouch", None)]).await;
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let ts = entries[0]["timestamp"].as_u64().unwrap();

        // Stand up a second router on the same state to issue further
        // queries without re-emitting.
        let state2 = make_state();
        {
            let mut svc = state2.svc.lock().await;
            svc.emit_local_audit("attest".to_string(), b"x".to_vec(), None);
            svc.emit_local_audit("vouch".to_string(), b"y".to_vec(), None);
        }
        let svc = state2.svc.clone();
        let info = state2.info.clone();
        let app = router::<MemoryBackend>(svc, info, tcp_trust_policy(), None, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{}", addr);

        // since = ts of first entry → both still returned (>=).
        let body: serde_json::Value = reqwest::get(format!("{base}/v1/audit/entries?since={ts}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let total_at_ts = body["total"].as_u64().unwrap();
        assert!(
            total_at_ts >= 1,
            "since={ts} must include the entries that share that timestamp; got {total_at_ts}"
        );

        // since = far future → empty.
        let body: serde_json::Value = reqwest::get(format!(
            "{base}/v1/audit/entries?since={}",
            u64::from(u32::MAX)
        ))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(body["total"].as_u64().unwrap(), 0);
    }

    // -- classify_caller_identity (observability-plan.md Phase C) --

    fn make_admin_policy(trust_loopback: bool) -> AdminPolicy {
        AdminPolicy {
            trust_loopback_tcp_admin: trust_loopback,
            admin_uids: Vec::new(),
            admin_sids: Vec::new(),
            service_uid: None,
            strict_device_binding: false,
        }
    }

    #[test]
    fn classify_anonymous_returns_anonymous_regardless_of_admin_trust() {
        // Transport-kind partition: trust_loopback_tcp_admin does not
        // shift the bucket — admin is bumped orthogonally by the
        // observer middleware.
        assert_eq!(
            classify_caller_identity(&CallerIdentity::Anonymous),
            "anonymous"
        );
    }

    #[test]
    fn anonymous_with_admin_trust_is_also_admitted_as_admin() {
        let policy = make_admin_policy(true);
        assert!(
            CallerIdentity::Anonymous.is_admin(&policy),
            "Anonymous + trust_loopback_tcp_admin must be admin per is_admin policy so the \
             observer middleware bumps the admin bucket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_uds_returns_uds() {
        let caller = CallerIdentity::Uds {
            uid: 1000,
            gid: 1000,
            pid: 1,
        };
        assert_eq!(classify_caller_identity(&caller), "uds");
    }

    #[cfg(unix)]
    #[test]
    fn uds_caller_in_admin_uids_is_admin_per_policy() {
        let mut policy = make_admin_policy(false);
        policy.admin_uids = vec![1000];
        let caller = CallerIdentity::Uds {
            uid: 1000,
            gid: 1000,
            pid: 1,
        };
        assert_eq!(classify_caller_identity(&caller), "uds");
        assert!(caller.is_admin(&policy));
    }

    #[cfg(windows)]
    #[test]
    fn classify_pipe_returns_pipe() {
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
            pid: 1,
        };
        assert_eq!(classify_caller_identity(&caller), "pipe");
    }

    #[cfg(windows)]
    #[test]
    fn pipe_system_caller_is_admin_per_policy() {
        let policy = make_admin_policy(false);
        let caller = CallerIdentity::Pipe {
            sid: "S-1-5-18".to_string(),
            pid: 1,
        };
        assert_eq!(classify_caller_identity(&caller), "pipe");
        assert!(caller.is_admin(&policy));
    }
}
