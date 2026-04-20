//! Shared HTTP client helpers for CLI subcommands that call `dds-node`.
//!
//! Two transports are supported:
//! - `http://host:port` / `https://host:port` — normal TCP, via reqwest.
//! - `unix:/path/to/dds.sock` — Unix domain socket (H-7 step-2), served
//!   by `dds-node` when `network.api_addr = "unix:/..."` in the node's
//!   TOML config. The CLI runs an HTTP/1 client directly over the
//!   socket using hyper + hyper-util so reqwest's TCP-only connector
//!   doesn't get in the way.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::UnixStream;

/// Default dds-node loopback API base URL.
pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:5551";

/// Build a short-timeout HTTP client suitable for local CLI calls.
pub fn new_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client build")
}

/// **L-6 (security review)**: refuse non-loopback HTTP URLs. The CLI
/// is designed for local admin use; a plaintext `http://` call to a
/// non-loopback host would leak bearer-like tokens and requests over
/// the wire. Loopback (127.0.0.1, ::1, localhost) stays allowed
/// because the API is loopback-only by design. HTTPS is always
/// allowed regardless of host. `unix:` URLs are local by definition
/// and bypass the check.
fn enforce_tls_for_non_loopback(url: &str) {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("unix:") {
        return;
    }
    if !lower.starts_with("http://") {
        fail(&format!(
            "unsupported URL scheme (only http, https, and unix: are allowed): {url}"
        ));
    }
    // Extract the host between "http://" and the next '/' or ':'.
    let rest = &lower[7..];
    let host_end = rest.find(['/', ':']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    if !is_loopback {
        fail(&format!(
            "refusing plaintext http:// to non-loopback host {host} — \
             use https:// or target 127.0.0.1/localhost (see L-6 in the security review)"
        ));
    }
}

/// Run `GET {base}{path}` with the given query params, deserializing the
/// JSON body on success. On HTTP error, print the node's error body to
/// stderr and exit with code 1.
pub async fn get_json<T>(base: &str, path: &str, query: &[(&str, &str)]) -> T
where
    T: DeserializeOwned,
{
    enforce_tls_for_non_loopback(base);

    if let Some(sock) = base.strip_prefix("unix:") {
        let full_path = build_path_with_query(path, query);
        let (status, body) = uds_request(sock, "GET", &full_path, Bytes::new(), None).await;
        return handle_uds_response(status, body);
    }

    let client = new_client();
    let url = format!("{base}{path}");
    let resp = client
        .get(&url)
        .query(query)
        .send()
        .await
        .unwrap_or_else(|e| fail_reach(&url, &e.to_string()));
    handle_response(resp).await
}

/// Run `POST {base}{path}` with a JSON body, deserializing the JSON
/// response. Same error handling as `get_json`.
pub async fn post_json<Req, Resp>(base: &str, path: &str, body: &Req) -> Resp
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    enforce_tls_for_non_loopback(base);

    if let Some(sock) = base.strip_prefix("unix:") {
        let json = serde_json::to_vec(body).unwrap_or_else(|e| fail(&format!("serialize: {e}")));
        let (status, body) = uds_request(
            sock,
            "POST",
            path,
            Bytes::from(json),
            Some("application/json"),
        )
        .await;
        return handle_uds_response(status, body);
    }

    let client = new_client();
    let url = format!("{base}{path}");
    let resp = client
        .post(&url)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| fail_reach(&url, &e.to_string()));
    handle_response(resp).await
}

/// `POST {base}{path}` with a JSON body, expecting an empty/accepted
/// response. Returns the `StatusCode` on success; exits on failure.
pub async fn post_no_body<Req>(base: &str, path: &str, body: &Req) -> StatusCode
where
    Req: Serialize,
{
    enforce_tls_for_non_loopback(base);

    if let Some(sock) = base.strip_prefix("unix:") {
        let json = serde_json::to_vec(body).unwrap_or_else(|e| fail(&format!("serialize: {e}")));
        let (status, bytes) = uds_request(
            sock,
            "POST",
            path,
            Bytes::from(json),
            Some("application/json"),
        )
        .await;
        return if status.is_success() {
            status
        } else {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            eprintln!("Error: HTTP {status} — {text}");
            std::process::exit(1);
        };
    }

    let client = new_client();
    let url = format!("{base}{path}");
    let resp = client
        .post(&url)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| fail_reach(&url, &e.to_string()));
    if resp.status().is_success() {
        resp.status()
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("Error: HTTP {status} — {body}");
        std::process::exit(1);
    }
}

/// Return-typed response handler: on success deserialize as JSON, on
/// failure print the body and exit.
async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> T {
    if resp.status().is_success() {
        resp.json::<T>()
            .await
            .unwrap_or_else(|e| fail(&format!("invalid JSON response: {e}")))
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let msg = parse_error_message(&body).unwrap_or(body);
        eprintln!("Error: HTTP {status} — {msg}");
        std::process::exit(1);
    }
}

fn handle_uds_response<T: DeserializeOwned>(status: StatusCode, body: Bytes) -> T {
    if status.is_success() {
        serde_json::from_slice::<T>(&body)
            .unwrap_or_else(|e| fail(&format!("invalid JSON response: {e}")))
    } else {
        let text = String::from_utf8_lossy(&body).into_owned();
        let msg = parse_error_message(&text).unwrap_or(text);
        eprintln!("Error: HTTP {status} — {msg}");
        std::process::exit(1);
    }
}

/// Minimal HTTP/1 client over a Unix domain socket. Opens a fresh
/// connection per call — the CLI is short-lived and the overhead is
/// one syscall plus HTTP/1 line-parsing, so pooling is not worth the
/// complexity here.
async fn uds_request(
    sock_path: &str,
    method: &str,
    path_and_query: &str,
    body: Bytes,
    content_type: Option<&str>,
) -> (StatusCode, Bytes) {
    #[cfg(unix)]
    {
        let stream = UnixStream::connect(sock_path).await.unwrap_or_else(|e| {
            fail_reach(&format!("unix:{sock_path}"), &e.to_string());
        });
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io)
            .await
            .unwrap_or_else(|e| fail(&format!("HTTP handshake over UDS failed: {e}")));
        tokio::spawn(async move {
            // The connection future drives the I/O for this one request;
            // errors are routed back through `send_request` so we can
            // drop them here.
            let _ = conn.await;
        });

        let mut req = hyper::Request::builder()
            .method(method)
            .uri(path_and_query)
            .header("host", "localhost");
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        req = req.header("content-length", body.len().to_string());
        let req = req
            .body(Full::new(body))
            .unwrap_or_else(|e| fail(&format!("build request: {e}")));

        let resp = sender
            .send_request(req)
            .await
            .unwrap_or_else(|e| fail_reach(&format!("unix:{sock_path}"), &e.to_string()));
        let status = StatusCode::from_u16(resp.status().as_u16())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let collected = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| fail(&format!("read response body: {e}")));
        let body = collected.to_bytes();
        (status, body)
    }
    #[cfg(not(unix))]
    {
        let _ = (sock_path, method, path_and_query, body, content_type);
        fail("UDS transport is only supported on Unix platforms");
    }
}

fn build_path_with_query(path: &str, query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len() + 32);
    out.push_str(path);
    out.push('?');
    for (i, (k, v)) in query.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        push_form_encoded(&mut out, k);
        out.push('=');
        push_form_encoded(&mut out, v);
    }
    out
}

/// Minimal application/x-www-form-urlencoded encoder for path-query
/// keys and values. Keeps unreserved chars as-is, percent-encodes
/// everything else. Matches the subset reqwest emits for our callers
/// (only ASCII keys/values in practice).
fn push_form_encoded(out: &mut String, s: &str) {
    for b in s.as_bytes() {
        let c = *b;
        let unreserved = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(c as char);
        } else {
            out.push('%');
            out.push_str(&format!("{c:02X}"));
        }
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: String,
}

fn parse_error_message(body: &str) -> Option<String> {
    serde_json::from_str::<ErrorEnvelope>(body)
        .ok()
        .map(|e| e.error)
}

fn fail_reach(url: &str, detail: &str) -> ! {
    eprintln!("Error: cannot reach dds-node at {url}: {detail}");
    std::process::exit(1);
}

fn fail(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_path_with_query_empty() {
        assert_eq!(build_path_with_query("/v1/x", &[]), "/v1/x");
    }

    #[test]
    fn build_path_with_query_encodes_reserved() {
        let got = build_path_with_query("/v1/x", &[("device_urn", "urn:vch:ab cd")]);
        assert_eq!(got, "/v1/x?device_urn=urn%3Avch%3Aab%20cd");
    }

    #[test]
    fn build_path_with_query_multi() {
        let got = build_path_with_query("/v1/audit/entries", &[("action", "vouch"), ("limit", "10")]);
        assert_eq!(got, "/v1/audit/entries?action=vouch&limit=10");
    }
}
