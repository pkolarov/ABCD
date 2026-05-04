// SPDX-License-Identifier: MIT OR Apache-2.0
//! `dds-pam-helper` — FIDO2 assertion helper for `pam_dds.so`.
//!
//! ## Responsibilities
//!
//! 1. Fetch a fresh challenge from the local `dds-node` via
//!    `GET /v1/session/challenge`.
//! 2. Collect a FIDO2 assertion from the user's authenticator (USB, NFC,
//!    or BLE security key).
//! 3. Submit the assertion to `POST /v1/session/assert`.
//! 4. Write a [`HelperOutcome`] JSON object to stdout and exit 0 on
//!    success, exit 1 on failure.
//!
//! ## FIDO2 collection strategy
//!
//! The helper uses a tiered strategy to collect the assertion:
//!
//! - **`fido2-assert` tool** (from `libfido2-tools`): if present on `PATH`,
//!   the helper delegates to it and parses its output.
//! - **Stdin piped mode** (`--assertion-json FILE` / `-`): a pre-computed
//!   assertion JSON is read from a file or stdin.  Intended for testing and
//!   scriptable environments.
//!
//! USB HID / CTAP2 native support will be added in a follow-up once a
//! suitable Rust CTAP2 crate stabilises.
//!
//! ## Usage
//!
//! ```text
//! dds-pam-helper [OPTIONS]
//!
//! Options:
//!   --node-sock <PATH>       dds-node Unix socket [default: /var/lib/dds/dds.sock]
//!   --user <USERNAME>        Local POSIX username to authenticate
//!   --assertion-json <PATH>  Read pre-computed assertion from file ('-' = stdin)
//!   --credential-id <B64>    Credential ID (base64url) — required with --assertion-json
//!   --duration-secs <N>      Requested session duration in seconds [default: 28800]
//! ```

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Read;
use std::process;

use pam_dds::HelperOutcome;

// ─── HTTP types mirrored from dds-node ────────────────────────────────────────

/// Response from `GET /v1/session/challenge`.
#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge_id: String,
    challenge_b64url: String,
}

/// Request body for `POST /v1/session/assert`.
#[derive(Debug, Serialize)]
struct AssertionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_urn: Option<String>,
    credential_id: String,
    challenge_id: String,
    client_data_hash: String,
    authenticator_data: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_data_json_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_secs: Option<u64>,
}

/// Response from `POST /v1/session/assert`.
#[derive(Debug, Deserialize)]
struct SessionResponse {
    session_id: String,
    #[allow(dead_code)]
    expires_at: u64,
    #[allow(dead_code)]
    token_cbor_b64: String,
}

// ─── Pre-computed assertion JSON (for --assertion-json mode) ──────────────────

/// A pre-computed FIDO2 assertion provided via `--assertion-json`.
/// Fields match the raw authenticator output before being sent to dds-node.
#[derive(Debug, Deserialize)]
struct PrecomputedAssertion {
    credential_id: String,
    authenticator_data: String,
    client_data_hash: String,
    signature: String,
    #[serde(default)]
    client_data_json_b64: Option<String>,
    #[serde(default)]
    subject_urn: Option<String>,
}

// ─── CLI args ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Args {
    node_sock: String,
    user: Option<String>,
    assertion_json: Option<String>,
    duration_secs: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            node_sock: pam_dds::DEFAULT_NODE_SOCK.to_owned(),
            user: None,
            assertion_json: None,
            duration_secs: 28800,
        }
    }
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let mut args = Args::default();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--node-sock" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.node_sock = v.clone();
                }
            }
            "--user" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.user = Some(v.clone());
                }
            }
            "--assertion-json" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.assertion_json = Some(v.clone());
                }
            }
            "--duration-secs" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    if let Ok(n) = v.parse() {
                        args.duration_secs = n;
                    }
                }
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: dds-pam-helper [--node-sock PATH] [--user USER] \
                    [--assertion-json FILE|-] [--duration-secs N]"
                );
                process::exit(0);
            }
            unknown => {
                eprintln!("dds-pam-helper: unknown argument: {unknown}");
                process::exit(1);
            }
        }
        i += 1;
    }
    args
}

// ─── HTTP over Unix Domain Socket ─────────────────────────────────────────────

#[cfg(unix)]
async fn uds_get(sock_path: &str, path: &str) -> Result<Bytes, String> {
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(sock_path)
        .await
        .map_err(|e| format!("connect to {sock_path}: {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .map_err(|e| format!("HTTP handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("build request: {e}"))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send GET {path}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {} for GET {path}", resp.status().as_u16()));
    }

    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    Ok(collected.to_bytes())
}

#[cfg(unix)]
async fn uds_post_json<T: Serialize>(
    sock_path: &str,
    path: &str,
    body: &T,
) -> Result<Bytes, String> {
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let json = serde_json::to_vec(body).map_err(|e| format!("serialize: {e}"))?;
    let content_len = json.len().to_string();

    let stream = UnixStream::connect(sock_path)
        .await
        .map_err(|e| format!("connect to {sock_path}: {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|e| format!("HTTP handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("content-length", content_len)
        .body(Full::new(Bytes::from(json)))
        .map_err(|e| format!("build request: {e}"))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send POST {path}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let msg = String::from_utf8_lossy(&body_bytes);
        return Err(format!("HTTP {status} for POST {path}: {msg}"));
    }

    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    Ok(collected.to_bytes())
}

// ─── FIDO2 assertion collection ───────────────────────────────────────────────

/// Read a pre-computed assertion JSON from a file path or stdin (`"-"`).
fn read_assertion_json(path: &str) -> Result<PrecomputedAssertion, String> {
    let content = if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?
    };
    serde_json::from_str(&content).map_err(|e| format!("parse assertion JSON: {e}"))
}

/// Attempt to collect a FIDO2 assertion using the `fido2-assert` tool from
/// the `libfido2-tools` package.
///
/// The tool is invoked as:
/// ```text
/// fido2-assert -G -h <rp_id> -u <user> /dev/hidraw0 < challenge_b64
/// ```
///
/// This is an optional path — if `fido2-assert` is not on `PATH`, or the
/// user has no registered authenticator, this returns an error and the
/// caller falls back to other strategies.
fn try_fido2_assert_tool(
    challenge_b64url: &str,
    rp_id: &str,
) -> Result<PrecomputedAssertion, String> {
    // Attempt to locate `fido2-assert` in PATH.
    let which_output = std::process::Command::new("which")
        .arg("fido2-assert")
        .output()
        .map_err(|e| format!("which fido2-assert: {e}"))?;
    if !which_output.status.success() {
        return Err("fido2-assert not found on PATH".to_owned());
    }
    let tool_path = String::from_utf8_lossy(&which_output.stdout)
        .trim()
        .to_owned();

    // Convert base64url to raw bytes then re-encode as base64-standard for
    // the fido2-assert tool which expects standard base64 on stdin.
    let b64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let challenge_bytes = b64_engine
        .decode(challenge_b64url)
        .map_err(|e| format!("decode challenge: {e}"))?;
    let challenge_b64std = base64::engine::general_purpose::STANDARD.encode(&challenge_bytes);

    // Prompt the user (on the terminal via stderr) then invoke the tool.
    eprintln!("[dds-pam-helper] Touch your FIDO2 authenticator to log in…");
    let output = std::process::Command::new(&tool_path)
        .args(["-G", "-h", rp_id])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(challenge_b64std.as_bytes());
            }
            child.wait_with_output()
        })
        .map_err(|e| format!("run fido2-assert: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "fido2-assert exited {}",
            output.status.code().unwrap_or(-1)
        ));
    }

    // `fido2-assert` prints assertion fields one per line:
    // <credential_id_b64url>
    // <authenticator_data_b64url>
    // <signature_b64url>
    // <user_id_b64url>  (optional)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let credential_id = lines
        .next()
        .ok_or("fido2-assert: missing credential_id")?
        .to_owned();
    let authenticator_data = lines
        .next()
        .ok_or("fido2-assert: missing authenticator_data")?
        .to_owned();
    let signature = lines
        .next()
        .ok_or("fido2-assert: missing signature")?
        .to_owned();

    // Build a synthetic clientDataHash (SHA-256 of {"type":"webauthn.get",
    // "challenge":"<b64url>","origin":"https://<rp_id>"}).
    use std::collections::BTreeMap;
    let mut client_data: BTreeMap<&str, &str> = BTreeMap::new();
    client_data.insert("type", "webauthn.get");
    client_data.insert("challenge", challenge_b64url);
    let origin = format!("https://{rp_id}");
    client_data.insert("origin", &origin);
    let client_data_json =
        serde_json::to_string(&client_data).map_err(|e| format!("serialize clientData: {e}"))?;
    let client_data_json_b64 =
        base64::engine::general_purpose::STANDARD.encode(client_data_json.as_bytes());

    use sha2::Digest;
    let hash = sha2::Sha256::digest(client_data_json.as_bytes());
    let client_data_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_slice());

    Ok(PrecomputedAssertion {
        credential_id,
        authenticator_data,
        client_data_hash,
        signature,
        client_data_json_b64: Some(client_data_json_b64),
        subject_urn: None,
    })
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn emit_outcome(outcome: &HelperOutcome) -> ! {
    let json = serde_json::to_string(outcome)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"internal serialization failure"}"#.to_owned());
    println!("{json}");
    if outcome.ok {
        process::exit(0);
    } else {
        process::exit(1);
    }
}

fn emit_error(msg: impl Into<String>) -> ! {
    emit_outcome(&HelperOutcome {
        ok: false,
        session_id: None,
        error: Some(msg.into()),
    });
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    let args = parse_args();

    let user = args.user.unwrap_or_else(|| {
        emit_error("--user is required");
    });

    // 1. Fetch a server-issued challenge.
    let challenge_bytes = uds_get(&args.node_sock, "/v1/session/challenge")
        .await
        .unwrap_or_else(|e| emit_error(format!("fetch challenge: {e}")));

    let challenge_resp: ChallengeResponse = serde_json::from_slice(&challenge_bytes)
        .unwrap_or_else(|e| emit_error(format!("parse challenge response: {e}")));

    // 2. Collect the FIDO2 assertion.
    let assertion = if let Some(ref path) = args.assertion_json {
        read_assertion_json(path).unwrap_or_else(|e| emit_error(e))
    } else {
        // Default RP-ID is the hostname of this machine.
        let rp_id = hostname::get_rp_id();
        try_fido2_assert_tool(&challenge_resp.challenge_b64url, &rp_id)
            .unwrap_or_else(|e| emit_error(format!("FIDO2 assertion: {e}")))
    };

    // 3. Submit the assertion to dds-node.
    // Prefer the credential-embedded subject URN; fall back to
    // synthesising a local-user hint so dds-node can include the
    // POSIX username in its audit log.
    let subject_urn = assertion
        .subject_urn
        .or_else(|| Some(format!("dds:local:{user}")));
    let request = AssertionRequest {
        subject_urn,
        credential_id: assertion.credential_id,
        challenge_id: challenge_resp.challenge_id,
        client_data_hash: assertion.client_data_hash,
        authenticator_data: assertion.authenticator_data,
        signature: assertion.signature,
        client_data_json_b64: assertion.client_data_json_b64,
        duration_secs: Some(args.duration_secs),
    };

    let session_bytes = uds_post_json(&args.node_sock, "/v1/session/assert", &request)
        .await
        .unwrap_or_else(|e| emit_error(format!("session assert: {e}")));

    let session: SessionResponse = serde_json::from_slice(&session_bytes)
        .unwrap_or_else(|e| emit_error(format!("parse session response: {e}")));

    // 4. Emit a success outcome and exit 0.
    emit_outcome(&HelperOutcome {
        ok: true,
        session_id: Some(session.session_id),
        error: None,
    });
}

#[cfg(not(unix))]
fn main() {
    eprintln!("dds-pam-helper is only supported on Unix platforms");
    process::exit(1);
}

// ─── hostname helper ──────────────────────────────────────────────────────────

mod hostname {
    /// Return the hostname-derived RP ID to use for WebAuthn.
    ///
    /// The RP ID should be the effective domain of the relying party.  For
    /// a local device login, we use the FQDN of the machine.  Falls back
    /// to `"localhost"` when the hostname cannot be resolved.
    pub fn get_rp_id() -> String {
        std::process::Command::new("hostname")
            .arg("--fqdn")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "localhost".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        // Simulate an empty argv (the binary name is argv[0] and is skipped).
        let saved = env::args().collect::<Vec<_>>();
        // We can't easily override env::args() in tests, so just verify the
        // Default impl directly.
        let a = Args::default();
        assert_eq!(a.node_sock, pam_dds::DEFAULT_NODE_SOCK);
        assert!(a.user.is_none());
        assert!(a.assertion_json.is_none());
        assert_eq!(a.duration_secs, 28800);
        drop(saved);
    }

    #[test]
    fn challenge_response_deserialise() {
        let json = r#"{"challenge_id":"chal-abc","challenge_b64url":"AAAA","expires_at":9999}"#;
        let r: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.challenge_id, "chal-abc");
        assert_eq!(r.challenge_b64url, "AAAA");
    }

    #[test]
    fn session_response_deserialise() {
        let json = r#"{"session_id":"sess-1","expires_at":9999,"token_cbor_b64":"abc="}"#;
        let r: SessionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.session_id, "sess-1");
    }

    #[test]
    fn assertion_request_serialise_skips_none() {
        let req = AssertionRequest {
            subject_urn: None,
            credential_id: "cred-1".to_owned(),
            challenge_id: "chal-1".to_owned(),
            client_data_hash: "hash".to_owned(),
            authenticator_data: "adata".to_owned(),
            signature: "sig".to_owned(),
            client_data_json_b64: None,
            duration_secs: Some(3600),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("subject_urn").is_none());
        assert!(json.get("client_data_json_b64").is_none());
        assert_eq!(json["credential_id"], "cred-1");
        assert_eq!(json["duration_secs"], 3600);
    }

    #[test]
    fn precomputed_assertion_parse() {
        let json = serde_json::json!({
            "credential_id": "cred-abc",
            "authenticator_data": "adata-b64",
            "client_data_hash": "hash-b64",
            "signature": "sig-b64"
        });
        let a: PrecomputedAssertion = serde_json::from_value(json).unwrap();
        assert_eq!(a.credential_id, "cred-abc");
        assert!(a.client_data_json_b64.is_none());
        assert!(a.subject_urn.is_none());
    }

    #[test]
    fn helper_outcome_round_trip() {
        let o = HelperOutcome {
            ok: true,
            session_id: Some("sess-xyz".to_owned()),
            error: None,
        };
        let json = serde_json::to_string(&o).unwrap();
        let back = HelperOutcome::from_stdout(json.as_bytes()).unwrap();
        assert!(back.ok);
        assert_eq!(back.session_id.as_deref(), Some("sess-xyz"));
    }
}
