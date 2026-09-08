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
/// authenticator data (base64), assertion signature (base64), and — only
/// when the credential is resident — the resident credential's *user id*
/// (base64), not a credential id (see `resident_user_id_b64` below; **R1
/// (2026-09-08 follow-up review)**).
#[derive(Debug, PartialEq, Eq)]
struct Fido2AssertOutput {
    client_data_hash_b64: String,
    rp_id: String,
    authenticator_data_b64: String,
    signature_b64: String,
    /// Line 5 of `fido2-assert -G` output, present only for a resident
    /// credential: the FIDO2 *user id* the credential is bound to, base64
    /// encoded (NOT a credential id, despite the field's former name).
    /// Currently unused: `try_fido2_assert_tool` returns the
    /// caller-supplied credential id, never this value. Kept (rather than
    /// removed) so a future caller that needs the resident user id doesn't
    /// have to re-add the parsing.
    resident_user_id_b64: Option<String>,
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
    let resident_user_id_b64 = lines.next().map(str::to_owned);
    Ok(Fido2AssertOutput {
        client_data_hash_b64,
        rp_id,
        authenticator_data_b64,
        signature_b64,
        resident_user_id_b64,
    })
}

/// Maximum plausible length of the raw `authenticatorData` byte string
/// unwrapped from `fido2-assert`'s CBOR-encoded line 3. A plain assertion
/// (no attested credential data, no extensions) is always 37 bytes
/// (rpIdHash(32) + flags(1) + signCount(4)); even with extensions it stays
/// well under this. 1024 is a generous bound that rejects a malformed or
/// hostile `fido2-assert` output before it can drive an oversized slice or
/// allocation, while comfortably covering any assertion this helper
/// actually requests (we never pass `-h` or request a largeBlobKey).
const MAX_CBOR_BSTR_LEN: usize = 1024;

/// Unwrap a CBOR byte-string (major type 2, a "bstr") header from `bytes`,
/// returning the raw contents after the header.
///
/// Per the libfido2 manual, `fido2-assert -G` line 3 ("CBOR encoded
/// authenticator data") is a CBOR byte string *wrapping* the raw WebAuthn
/// `authenticatorData` — not the raw bytes themselves. The node's verifier
/// reads `rpIdHash`/`flags`/`signCount` at fixed offsets from byte 0 of the
/// raw bytes, so this header must be stripped before the value is
/// forwarded, or a real authenticator's assertion fails verification at
/// the node. **R1 (2026-09-08 follow-up review)**.
///
/// Only the definite-length forms actually needed here are supported: the
/// 5 low bits of the initial byte are the length directly (0-23), or `24`
/// (length in the next 1 byte) or `25` (length in the next 2 bytes,
/// big-endian). The 4-/8-byte-length forms (26/27) and indefinite-length
/// byte strings are rejected — a plain assertion's authenticatorData is
/// always well under 256 bytes, so these forms never occur in legitimate
/// output and are not worth supporting.
fn unwrap_cbor_bstr(bytes: &[u8]) -> Result<&[u8], String> {
    let &first = bytes.first().ok_or("CBOR byte string: empty input")?;
    let major_type = first >> 5;
    if major_type != 2 {
        return Err(format!(
            "CBOR byte string: expected major type 2 (byte string), got {major_type}"
        ));
    }
    let additional = first & 0x1f;
    let (len, header_len): (usize, usize) = match additional {
        0..=23 => (additional as usize, 1),
        24 => {
            let b = *bytes
                .get(1)
                .ok_or("CBOR byte string: truncated 1-byte length")?;
            (b as usize, 2)
        }
        25 => {
            let b0 = *bytes
                .get(1)
                .ok_or("CBOR byte string: truncated 2-byte length")?;
            let b1 = *bytes
                .get(2)
                .ok_or("CBOR byte string: truncated 2-byte length")?;
            (u16::from_be_bytes([b0, b1]) as usize, 3)
        }
        26 | 27 => {
            return Err(format!(
                "CBOR byte string: unsupported 4-/8-byte length encoding ({additional})"
            ));
        }
        31 => return Err("CBOR byte string: indefinite-length form is not supported".to_owned()),
        _ => {
            return Err(format!(
                "CBOR byte string: reserved/invalid length encoding ({additional})"
            ));
        }
    };
    if len > MAX_CBOR_BSTR_LEN {
        return Err(format!(
            "CBOR byte string: declared length {len} exceeds bound {MAX_CBOR_BSTR_LEN}"
        ));
    }
    let end = header_len
        .checked_add(len)
        .ok_or("CBOR byte string: length overflow")?;
    bytes
        .get(header_len..end)
        .ok_or_else(|| "CBOR byte string: declared length exceeds remaining input".to_owned())
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
    // **R1 (2026-09-08 follow-up review)**: line 3 of `fido2-assert -G`
    // output is CBOR-encoded (a CBOR byte string wrapping the raw
    // authenticatorData), per the libfido2 manual. Unwrap the CBOR
    // byte-string header BETWEEN the base64 decode and the base64url
    // re-encode, so the value forwarded to the node is the raw
    // authenticatorData its verifier expects at fixed byte offsets — not
    // the CBOR-wrapped bytes, which would shift every offset and corrupt
    // what's actually signed over, making a real authenticator's
    // assertion unverifiable.
    let authenticator_data_cbor = STANDARD
        .decode(&parsed.authenticator_data_b64)
        .map_err(|e| format!("fido2-assert: authenticator data is not base64: {e}"))?;
    let authenticator_data_raw = unwrap_cbor_bstr(&authenticator_data_cbor)
        .map_err(|e| format!("fido2-assert: authenticator data: {e}"))?;
    Ok(PrecomputedAssertion {
        credential_id: credential_id_b64url.to_owned(),
        authenticator_data: URL_SAFE_NO_PAD.encode(authenticator_data_raw),
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
        // client data hash, rp id, authenticator data, signature, resident user id
        let out = "AAAA\ndds.local\nBBBB\nCCCC\nDDDD\n";
        let p = parse_fido2_assert_output(out).unwrap();
        assert_eq!(p.client_data_hash_b64, "AAAA");
        assert_eq!(p.rp_id, "dds.local");
        assert_eq!(p.authenticator_data_b64, "BBBB");
        assert_eq!(p.signature_b64, "CCCC");
        assert_eq!(p.resident_user_id_b64.as_deref(), Some("DDDD"));
        // non-resident credential: no trailing resident-user-id line
        let p = parse_fido2_assert_output("AAAA\ndds.local\nBBBB\nCCCC\n").unwrap();
        assert!(p.resident_user_id_b64.is_none());
        assert!(parse_fido2_assert_output("AAAA\ndds.local\n").is_err());
    }

    // ─── R1 (2026-09-08 follow-up review): CBOR byte-string unwrap ────────────

    /// Build a raw 37-byte authenticatorData fixture (rpIdHash(32) ||
    /// flags(1) || signCount(4)); only the *length* matters for these
    /// tests, so the content is arbitrary but fixed for reproducibility.
    fn raw_auth_data_fixture() -> [u8; 37] {
        let mut b = [0u8; 37];
        for (i, v) in b.iter_mut().enumerate().take(32) {
            *v = i as u8; // rpIdHash: arbitrary
        }
        b[32] = 0x01; // flags: UP bit set
        b[33..37].copy_from_slice(&1u32.to_be_bytes()); // signCount = 1
        b
    }

    #[test]
    fn unwrap_cbor_bstr_1_byte_length_follows_form() {
        let raw = raw_auth_data_fixture();
        assert_eq!(raw.len(), 37);
        // additional-info 24 ("1 byte length follows") is required once
        // the length no longer fits in the 5 low bits (0-23): 37 >= 24.
        // 0x25 == 2*16 + 5 == 37 decimal — confirm the arithmetic here
        // rather than trusting the magic number.
        assert_eq!(0x25u8, 37);
        let mut wrapped = vec![0x58u8, 0x25u8]; // major type 2, additional 24, len byte
        wrapped.extend_from_slice(&raw);
        assert_eq!(wrapped.len(), 39);

        let unwrapped = unwrap_cbor_bstr(&wrapped).unwrap();
        assert_eq!(unwrapped, &raw[..]);
    }

    #[test]
    fn unwrap_cbor_bstr_short_form_under_24_bytes() {
        let raw: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // additional-info == length directly: major type 2 (0x40) | 10.
        let mut wrapped = vec![0x40u8 + 10];
        wrapped.extend_from_slice(&raw);

        let unwrapped = unwrap_cbor_bstr(&wrapped).unwrap();
        assert_eq!(unwrapped, &raw[..]);
    }

    #[test]
    fn unwrap_cbor_bstr_rejects_wrong_major_type() {
        // 0x65 == major type 3 (text string), additional 5 — not a byte
        // string.
        let bytes = [0x65u8, b'h', b'e', b'l', b'l', b'o'];
        let err = unwrap_cbor_bstr(&bytes).unwrap_err();
        assert!(err.contains("major type 2"), "unexpected error: {err}");
    }

    #[test]
    fn unwrap_cbor_bstr_rejects_length_exceeding_input() {
        // Header claims 37 bytes follow, but only 5 are actually present.
        let bytes = [0x58u8, 0x25u8, 1, 2, 3, 4, 5];
        let err = unwrap_cbor_bstr(&bytes).unwrap_err();
        assert!(
            err.contains("exceeds remaining input"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unwrap_cbor_bstr_rejects_4_and_8_byte_length_forms() {
        // additional-info 26 ("4-byte length follows").
        let bytes26 = [0x5au8, 0, 0, 0, 10, 1, 2, 3];
        let err = unwrap_cbor_bstr(&bytes26).unwrap_err();
        assert!(err.contains("unsupported"), "unexpected error: {err}");

        // additional-info 27 ("8-byte length follows").
        let bytes27 = [0x5bu8, 0, 0, 0, 0, 0, 0, 0, 10];
        let err = unwrap_cbor_bstr(&bytes27).unwrap_err();
        assert!(err.contains("unsupported"), "unexpected error: {err}");
    }

    #[test]
    fn unwrap_cbor_bstr_rejects_indefinite_length_and_empty_input() {
        // additional-info 31: indefinite-length byte string.
        let bytes = [0x5fu8, 1, 2, 3];
        assert!(unwrap_cbor_bstr(&bytes).is_err());

        assert!(unwrap_cbor_bstr(&[]).is_err());
    }

    #[test]
    fn unwrap_cbor_bstr_rejects_declared_length_over_bound() {
        // additional-info 25 ("2-byte length follows"), declaring a
        // length well past MAX_CBOR_BSTR_LEN.
        let bytes = [0x59u8, 0xffu8, 0xffu8]; // len = 65535, no payload at all
        let err = unwrap_cbor_bstr(&bytes).unwrap_err();
        assert!(err.contains("exceeds bound"), "unexpected error: {err}");
    }

    /// End-to-end-ish: a synthetic `fido2-assert`-shaped output whose
    /// authenticator-data line is the CBOR-wrapped-then-base64-encoded raw
    /// 37-byte fixture (39 wrapped bytes). This is the test that most
    /// directly proves the fix: it confirms the value that would actually
    /// be forwarded to dds-node is the raw 37-byte authenticatorData, not
    /// the 39-byte CBOR-wrapped value.
    #[test]
    fn parse_and_unwrap_authenticator_data_matches_raw_fixture() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

        let raw = raw_auth_data_fixture();
        let mut wrapped = vec![0x58u8, 0x25u8];
        wrapped.extend_from_slice(&raw);
        assert_eq!(wrapped.len(), 39);

        let auth_data_line_b64 = STANDARD.encode(&wrapped);
        let out = format!(
            "{}\n{}\n{}\n{}\n",
            "Y2xpZW50ZGF0YWhhc2g=", // arbitrary client data hash
            "dds.local",
            auth_data_line_b64,
            "c2lnbmF0dXJl", // arbitrary signature
        );

        let parsed = parse_fido2_assert_output(&out).unwrap();
        let decoded_cbor = STANDARD.decode(&parsed.authenticator_data_b64).unwrap();
        assert_eq!(
            decoded_cbor, wrapped,
            "sanity: line 3 decodes to the CBOR-wrapped bytes"
        );

        let raw_unwrapped = unwrap_cbor_bstr(&decoded_cbor).unwrap();
        assert_eq!(raw_unwrapped, &raw[..]);

        // Simulate the outgoing base64url re-encode exactly as
        // `try_fido2_assert_tool` does, and confirm decoding it back
        // yields the original raw fixture (37 bytes) — not the
        // CBOR-wrapped value (39 bytes).
        let authenticator_data_out = URL_SAFE_NO_PAD.encode(raw_unwrapped);
        let round_tripped = URL_SAFE_NO_PAD.decode(&authenticator_data_out).unwrap();
        assert_eq!(round_tripped.len(), 37);
        assert_eq!(round_tripped, raw.to_vec());
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
