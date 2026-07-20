//! HTTP client for the `dds-node` endpoints this tool drives.
//!
//! Two transports, matching `dds-node`'s `network.api_addr` config:
//! `http://host:port` (plain reqwest) and `unix:/path/to/dds.sock`
//! (raw HTTP/1 over a `UnixStream`, since reqwest has no UDS connector).
//! macOS and Linux both default their packaged `dds.toml` to the UDS
//! transport with `trust_loopback_tcp_admin = false`, so callers on
//! those platforms MUST pass `--node-url unix:...` — the compiled-in
//! default below is `http://127.0.0.1:5551` purely for dev/test nodes
//! that haven't been given a UDS config.
//!
//! Mirrors the proven transport pattern in `dds-cli/src/client.rs`
//! (`uds_request`), trimmed to drop the Windows named-pipe branch —
//! out of scope here, Windows keeps its own native `DdsEnrollUser.exe`.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:5551";

async fn uds_request(
    sock_path: &str,
    method: &str,
    path: &str,
    body: Bytes,
    content_type: Option<&str>,
) -> Result<(StatusCode, Bytes), String> {
    let stream = UnixStream::connect(sock_path)
        .await
        .map_err(|e| format!("cannot reach dds-node at unix:{sock_path}: {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|e| format!("HTTP handshake over UDS failed: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost");
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    req = req.header("content-length", body.len().to_string());
    let req = req
        .body(Full::new(body))
        .map_err(|e| format!("build request: {e}"))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("cannot reach dds-node at unix:{sock_path}: {e}"))?;
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    Ok((status, collected.to_bytes()))
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: String,
}

fn error_message(status: StatusCode, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let msg = serde_json::from_str::<ErrorEnvelope>(&text)
        .map(|e| e.error)
        .unwrap_or_else(|_| text.into_owned());
    format!("HTTP {status} — {msg}")
}

async fn get_raw(base: &str, path: &str) -> Result<(StatusCode, Bytes), String> {
    if let Some(sock) = base.strip_prefix("unix:") {
        return uds_request(sock, "GET", path, Bytes::new(), None).await;
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("build HTTP client: {e}"))?;
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .map_err(|e| format!("cannot reach dds-node at {base}: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    Ok((status, bytes))
}

async fn post_raw(base: &str, path: &str, body_json: &[u8]) -> Result<(StatusCode, Bytes), String> {
    if let Some(sock) = base.strip_prefix("unix:") {
        return uds_request(
            sock,
            "POST",
            path,
            Bytes::copy_from_slice(body_json),
            Some("application/json"),
        )
        .await;
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("build HTTP client: {e}"))?;
    let resp = client
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(body_json.to_vec())
        .send()
        .await
        .map_err(|e| format!("cannot reach dds-node at {base}: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    Ok((status, bytes))
}

pub async fn get_json<T: DeserializeOwned>(base: &str, path: &str) -> Result<T, String> {
    let (status, body) = get_raw(base, path).await?;
    if !status.is_success() {
        return Err(error_message(status, &body));
    }
    serde_json::from_slice(&body).map_err(|e| format!("invalid JSON response: {e}"))
}

pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
    base: &str,
    path: &str,
    req: &Req,
) -> Result<Resp, String> {
    let json = serde_json::to_vec(req).map_err(|e| format!("serialize request: {e}"))?;
    let (status, body) = post_raw(base, path, &json).await?;
    if !status.is_success() {
        return Err(error_message(status, &body));
    }
    serde_json::from_slice(&body).map_err(|e| format!("invalid JSON response: {e}"))
}

// ---- Wire types — mirror dds-node/src/http.rs byte-for-byte. ----

#[derive(Deserialize)]
pub struct NodeInfoResponse {
    #[allow(dead_code)]
    pub node_urn: String,
    #[allow(dead_code)]
    pub node_pubkey_b64: String,
    #[allow(dead_code)]
    pub peer_id: String,
    pub admin_setup_available: bool,
}

/// Shared request shape for both `POST /v1/enroll/user` and
/// `POST /v1/admin/setup` — the server's `EnrollUserRequestJson`.
#[derive(Serialize)]
pub struct EnrollUserRequest {
    pub label: String,
    pub credential_id: String,
    pub attestation_object_b64: String,
    pub client_data_hash_b64: String,
    pub rp_id: String,
    pub display_name: String,
    pub authenticator_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_data_json_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

/// Shared response shape for both endpoints above — the server's
/// `EnrollmentResponse`.
#[derive(Deserialize)]
pub struct EnrollmentResponse {
    pub urn: String,
    pub jti: String,
    #[allow(dead_code)]
    pub token_cbor_b64: String,
    #[serde(default)]
    pub published: bool,
}

/// `GET /v1/admin/challenge` response — the server's `ChallengeResponse`.
#[derive(Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge_b64url: String,
    #[allow(dead_code)]
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct AdminVouchRequest {
    pub subject_urn: String,
    pub credential_id: String,
    pub challenge_id: String,
    pub authenticator_data: String,
    pub client_data_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_data_json_b64: Option<String>,
    pub signature: String,
    pub purpose: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminVouchResponse {
    pub vouch_jti: String,
    #[allow(dead_code)]
    pub subject_urn: String,
    #[allow(dead_code)]
    pub admin_urn: String,
    #[serde(default)]
    pub published: bool,
}

#[derive(Serialize)]
pub struct AdminRevokeVouchRequest {
    pub subject_urn: String,
    pub credential_id: String,
    pub challenge_id: String,
    pub authenticator_data: String,
    pub client_data_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_data_json_b64: Option<String>,
    pub signature: String,
    pub purpose: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokedVouchInfo {
    pub revoke_jti: String,
    pub target_jti: String,
    pub purpose: Option<String>,
}

#[derive(Deserialize)]
pub struct ForeignVouchInfo {
    pub target_jti: String,
    pub issuer: String,
    pub purpose: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminRevokeVouchResponse {
    #[allow(dead_code)]
    pub subject_urn: String,
    #[allow(dead_code)]
    pub admin_urn: String,
    pub revoked: Vec<RevokedVouchInfo>,
    pub foreign: Vec<ForeignVouchInfo>,
    pub demoted_from_trusted_roots: bool,
    #[serde(default)]
    pub published: bool,
}
