// SPDX-License-Identifier: MIT OR Apache-2.0
// Suppress dead-code / unused-import warnings when cross-compiled for non-Linux
// targets (e.g. x86_64-pc-windows-gnu in CI).  The binary is only *run* on
// Linux, but the crate must compile everywhere so `main` remains reachable.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
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
//!   --device-urn <URN>       Device URN for the node's account-authorization
//!                            check (default: DeviceUrn from /etc/dds/policy-agent.json)
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
    token_cbor_b64: String,
}

/// `GET /v1/linux/account/login-options` response (F4).
#[derive(Debug, Deserialize)]
struct LoginOptionsResponse {
    #[allow(dead_code)]
    username: String,
    candidates: Vec<LoginCandidate>,
}

#[derive(Debug, Deserialize)]
struct LoginCandidate {
    #[allow(dead_code)]
    subject_urn: String,
    credential_id: String,
    rp_id: String,
    #[allow(dead_code)]
    display_name: String,
}

/// `POST /v1/linux/account/authorize` request / response (F4).
#[derive(Debug, Serialize)]
struct AuthorizeRequest {
    device_urn: String,
    session_token_cbor_b64: String,
    username: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeResponse {
    #[allow(dead_code)]
    subject_urn: String,
    username: String,
    #[allow(dead_code)]
    policy_id: String,
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
    device_urn: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            node_sock: pam_dds::DEFAULT_NODE_SOCK.to_owned(),
            user: None,
            assertion_json: None,
            duration_secs: 28800,
            device_urn: None,
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
            "--device-urn" => {
                i += 1;
                if let Some(v) = argv.get(i) {
                    args.device_urn = Some(v.clone());
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
                    [--assertion-json FILE|-] [--duration-secs N] [--device-urn URN]"
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

/// Default path to the Linux policy agent's config, whose `DeviceUrn` is
/// the device URN the node scopes Linux policies (and therefore account
/// authorizations) by.
const AGENT_CONFIG_PATH: &str = "/etc/dds/policy-agent.json";

/// Extract `DeviceUrn` from the policy agent's JSON config.
fn device_urn_from_agent_config_json(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("DeviceUrn")
        .and_then(|d| d.as_str())
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::to_owned)
}

/// Parse `fido2-token -L` output: one authenticator per line,
/// `<device path>: vendor=0x…, product=0x… (<product name>)`.
fn parse_fido2_token_devices(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split_once(':').map(|(p, _)| p.trim()))
        .filter(|p| !p.is_empty() && p.starts_with('/'))
        .map(str::to_owned)
        .collect()
}

/// Parsed `fido2-assert -G` output. Per the libfido2 manual the tool
/// prints, one per line: client data hash (base64), relying party id,
/// authenticator data (base64), assertion signature (base64), and the
/// credential id (base64) when the credential is not resident.
#[derive(Debug, PartialEq, Eq)]
struct Fido2AssertOutput {
    client_data_hash_b64: String,
    rp_id: String,
    authenticator_data_b64: String,
    signature_b64: String,
    credential_id_b64: Option<String>,
}

fn parse_fido2_assert_output(out: &str) -> Result<Fido2AssertOutput, String> {
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    let client_data_hash_b64 = lines
        .next()
        .ok_or("fido2-assert: missing client data hash")?
        .to_owned();
    let rp_id = lines
        .next()
        .ok_or("fido2-assert: missing relying party id")?
        .to_owned();
    let authenticator_data_b64 = lines
        .next()
        .ok_or("fido2-assert: missing authenticator data")?
        .to_owned();
    let signature_b64 = lines
        .next()
        .ok_or("fido2-assert: missing signature")?
        .to_owned();
    let credential_id_b64 = lines.next().map(str::to_owned);
    Ok(Fido2AssertOutput {
        client_data_hash_b64,
        rp_id,
        authenticator_data_b64,
        signature_b64,
        credential_id_b64,
    })
}

/// Collect a FIDO2 assertion for one enrolled credential with the
/// `fido2-assert` tool from `libfido2-tools`, following the libfido2
/// manual (`fido2-assert -G [-bdhpruv] [-t option] [-i input_file]
/// [-o output_file] device`):
///
/// * the device is a path from `fido2-token -L`, not a relying party id;
/// * stdin carries the client data hash (base64), the relying party id
///   and the credential id (base64), each on its own line;
/// * stdout is parsed by [`parse_fido2_assert_output`].
///
/// The client data hash is `SHA-256(clientDataJSON)` for the JSON this
/// helper builds around the node's challenge, so the node can verify the
/// hash, the challenge and the origin exactly as it does for the Windows
/// Credential Provider. `-p` asks for user presence (the node requires
/// the UP flag). This path has been written against the manual and unit
/// tests; it still needs a run against real hardware.
fn try_fido2_assert_tool(
    challenge_b64url: &str,
    rp_id: &str,
    credential_id_b64url: &str,
) -> Result<PrecomputedAssertion, String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use sha2::Digest;

    let which = |tool: &str| -> Result<String, String> {
        let out = std::process::Command::new("which")
            .arg(tool)
            .output()
            .map_err(|e| format!("which {tool}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{tool} not found on PATH"));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let assert_tool = which("fido2-assert")?;
    let token_tool = which("fido2-token")?;

    let listed = std::process::Command::new(&token_tool)
        .arg("-L")
        .output()
        .map_err(|e| format!("run fido2-token -L: {e}"))?;
    let devices = parse_fido2_token_devices(&String::from_utf8_lossy(&listed.stdout));
    let device = devices
        .first()
        .cloned()
        .ok_or("no FIDO2 authenticator found (fido2-token -L listed none)")?;

    // clientDataJSON around the node's challenge; the node re-derives the
    // hash from this JSON and checks challenge + origin.
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#
    );
    let client_data_hash = sha2::Sha256::digest(client_data_json.as_bytes());
    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(credential_id_b64url)
        .or_else(|_| STANDARD.decode(credential_id_b64url))
        .map_err(|e| format!("decode credential id: {e}"))?;
    let stdin_payload = format!(
        "{}\n{}\n{}\n",
        STANDARD.encode(client_data_hash),
        rp_id,
        STANDARD.encode(&credential_id_bytes)
    );

    eprintln!("[dds-pam-helper] Touch your FIDO2 authenticator to log in…");
    let output = std::process::Command::new(&assert_tool)
        .args(["-G", "-p", &device])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(stdin_payload.as_bytes());
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
    let parsed = parse_fido2_assert_output(&String::from_utf8_lossy(&output.stdout))?;

    // Transcode the tool's standard base64 to the base64url the node's
    // API accepts everywhere else.
    let to_url = |b64: &str, what: &str| -> Result<String, String> {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| format!("fido2-assert: {what} is not base64: {e}"))?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    };
    Ok(PrecomputedAssertion {
        credential_id: credential_id_b64url.to_owned(),
        authenticator_data: to_url(&parsed.authenticator_data_b64, "authenticator data")?,
        client_data_hash: URL_SAFE_NO_PAD.encode(client_data_hash),
        signature: to_url(&parsed.signature_b64, "signature")?,
        client_data_json_b64: Some(STANDARD.encode(client_data_json.as_bytes())),
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
        authorized_user: None,
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

    // 2. Resolve the device URN the node scopes account authorization by.
    let device_urn = args.device_urn.clone().or_else(|| {
        std::fs::read_to_string(AGENT_CONFIG_PATH)
            .ok()
            .and_then(|j| device_urn_from_agent_config_json(&j))
    });
    let device_urn = device_urn.unwrap_or_else(|| {
        emit_error(format!(
            "device URN unknown: pass --device-urn or set DeviceUrn in {AGENT_CONFIG_PATH}"
        ))
    });

    // 3. Collect the FIDO2 assertion — only for credentials the node says
    //    are mapped to this Unix account on this device (F4).
    let assertion = if let Some(ref path) = args.assertion_json {
        read_assertion_json(path).unwrap_or_else(|e| emit_error(e))
    } else {
        let query = format!(
            "/v1/linux/account/login-options?device_urn={}&username={}",
            urlencode(&device_urn),
            urlencode(&user)
        );
        let options_bytes = uds_get(&args.node_sock, &query)
            .await
            .unwrap_or_else(|e| emit_error(format!("fetch login options: {e}")));
        let options: LoginOptionsResponse = serde_json::from_slice(&options_bytes)
            .unwrap_or_else(|e| emit_error(format!("parse login options: {e}")));
        if options.candidates.is_empty() {
            emit_error(format!(
                "no enrolled DDS user is authorized to log in as '{user}' on this device"
            ));
        }
        let mut last_err = String::from("no candidate credential produced an assertion");
        let mut found = None;
        for cand in &options.candidates {
            match try_fido2_assert_tool(
                &challenge_resp.challenge_b64url,
                &cand.rp_id,
                &cand.credential_id,
            ) {
                Ok(a) => {
                    found = Some(a);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        found.unwrap_or_else(|| emit_error(format!("FIDO2 assertion: {last_err}")))
    };

    // 4. Submit the assertion to dds-node. The subject hint is audit-only;
    //    the node binds the session to the credential owner.
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

    // 5. Ask the node whether this DDS subject may log in as `user` on
    //    this device (F4). A valid credential for some other user, or a
    //    user not mapped to this account, fails here.
    let authorize = AuthorizeRequest {
        device_urn: device_urn.clone(),
        session_token_cbor_b64: session.token_cbor_b64.clone(),
        username: user.clone(),
    };
    let auth_bytes = uds_post_json(&args.node_sock, "/v1/linux/account/authorize", &authorize)
        .await
        .unwrap_or_else(|e| emit_error(format!("account authorization refused: {e}")));
    let auth: AuthorizeResponse = serde_json::from_slice(&auth_bytes)
        .unwrap_or_else(|e| emit_error(format!("parse authorization response: {e}")));
    if auth.username != user {
        emit_error(format!(
            "node authorized account '{}' but PAM asked for '{user}'",
            auth.username
        ));
    }

    // 6. Emit a success outcome and exit 0.
    emit_outcome(&HelperOutcome {
        ok: true,
        session_id: Some(session.session_id),
        error: None,
        authorized_user: Some(auth.username),
    });
}

/// Minimal percent-encoding for query values (URNs contain ':' and
/// usernames may contain '@' or '.').
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(not(unix))]
fn main() {
    eprintln!("dds-pam-helper is only supported on Unix platforms");
    process::exit(1);
}

// ─── hostname helper ──────────────────────────────────────────────────────────

#[allow(dead_code)]
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
            authorized_user: None,
        };
        let json = serde_json::to_string(&o).unwrap();
        let back = HelperOutcome::from_stdout(json.as_bytes()).unwrap();
        assert!(back.ok);
        assert_eq!(back.session_id.as_deref(), Some("sess-xyz"));
    }

    #[test]
    fn device_urn_from_agent_config() {
        let j = r#"{"DeviceUrn":"urn:vouchsafe:device.abc","NodeSock":"/x"}"#;
        assert_eq!(
            device_urn_from_agent_config_json(j).as_deref(),
            Some("urn:vouchsafe:device.abc")
        );
        assert!(device_urn_from_agent_config_json(r#"{"DeviceUrn":""}"#).is_none());
        assert!(device_urn_from_agent_config_json("{}").is_none());
        assert!(device_urn_from_agent_config_json("nope").is_none());
    }

    #[test]
    fn parse_args_device_urn() {
        let a = Args::default();
        assert!(a.device_urn.is_none());
    }

    #[test]
    fn fido2_token_device_list_parses_paths() {
        let out = "/dev/hidraw2: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n\
                   /dev/hidraw5: vendor=0x32a3, product=0x3201 (Feitian ePass)\n";
        assert_eq!(
            parse_fido2_token_devices(out),
            vec!["/dev/hidraw2".to_owned(), "/dev/hidraw5".to_owned()]
        );
        assert!(parse_fido2_token_devices("").is_empty());
    }

    #[test]
    fn fido2_assert_output_parses_manual_layout() {
        // client data hash, rp id, authenticator data, signature, credential id
        let out = "AAAA\ndds.local\nBBBB\nCCCC\nDDDD\n";
        let p = parse_fido2_assert_output(out).unwrap();
        assert_eq!(p.client_data_hash_b64, "AAAA");
        assert_eq!(p.rp_id, "dds.local");
        assert_eq!(p.authenticator_data_b64, "BBBB");
        assert_eq!(p.signature_b64, "CCCC");
        assert_eq!(p.credential_id_b64.as_deref(), Some("DDDD"));
        // resident credential: no trailing credential id line
        let p = parse_fido2_assert_output("AAAA\ndds.local\nBBBB\nCCCC\n").unwrap();
        assert!(p.credential_id_b64.is_none());
        assert!(parse_fido2_assert_output("AAAA\ndds.local\n").is_err());
    }

    #[test]
    fn urlencode_escapes_reserved_characters() {
        assert_eq!(
            urlencode("urn:vouchsafe:device.abc"),
            "urn%3Avouchsafe%3Adevice.abc"
        );
        assert_eq!(urlencode("alice@corp"), "alice%40corp");
    }

    #[test]
    fn login_options_response_deserialises() {
        let j = r#"{"username":"alice","candidates":[{"subject_urn":"urn:vouchsafe:a","credential_id":"Y3JlZA","rp_id":"dds.local","display_name":"Alice"}]}"#;
        let o: LoginOptionsResponse = serde_json::from_str(j).unwrap();
        assert_eq!(o.candidates.len(), 1);
        assert_eq!(o.candidates[0].rp_id, "dds.local");
    }
}
