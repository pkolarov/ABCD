//! Shared HTTP client helpers for CLI subcommands that call `dds-node`.

use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
/// allowed regardless of host.
fn enforce_tls_for_non_loopback(url: &str) {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return;
    }
    if !lower.starts_with("http://") {
        fail(&format!(
            "unsupported URL scheme (only http and https are allowed): {url}"
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
    let client = new_client();
    let url = format!("{base}{path}");
    enforce_tls_for_non_loopback(&url);
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
    let client = new_client();
    let url = format!("{base}{path}");
    enforce_tls_for_non_loopback(&url);
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
    let client = new_client();
    let url = format!("{base}{path}");
    enforce_tls_for_non_loopback(&url);
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
