//! Interactive FIDO2 enrollment + authentication test.
//!
//! Tests the full DDS credential provider flow with a real USB FIDO2 key:
//!
//! 1. Detects connected FIDO2 authenticators
//! 2. Creates a new credential (makeCredential) — touch your key
//! 3. Enrolls the user in dds-node via POST /v1/enroll/user
//! 4. Gets an assertion (getAssertion) — touch your key again
//! 5. Posts assertion to dds-node POST /v1/session/assert
//! 6. Receives and displays the DDS session token
//!
//! Usage:
//!   cargo run -p dds-fido2-test
//!
//! Prerequisites:
//!   - A FIDO2 USB key (YubiKey, SoloKey, etc.) plugged in
//!   - dds-node running locally: cargo run -p dds-node

use base64::Engine;
use ctap_hid_fido2::{
    Cfg, FidoKeyHidFactory,
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RP_ID: &str = "dds.local";
const NODE_URL: &str = "http://127.0.0.1:5551";

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Rebuild a CBOR attestation object from the parsed Attestation struct.
fn rebuild_attestation_cbor(
    fmt: &str,
    auth_data: &[u8],
    attstmt_alg: i32,
    attstmt_sig: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();

    // CBOR map with 3 entries: fmt, attStmt, authData
    out.push(0xa3); // map(3)

    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, fmt);

    cbor_text(&mut out, "attStmt");
    if fmt == "none" || attstmt_sig.is_empty() {
        out.push(0xa0); // empty map
    } else {
        out.push(0xa2); // map(2): alg + sig
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, attstmt_alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, attstmt_sig);
    }

    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);

    out
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    let len = s.len();
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.push(len as u8);
    } else {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = b.len();
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len < 256 {
        out.push(0x58);
        out.push(len as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(b);
}

fn cbor_int(out: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        let v = val as u64;
        if v < 24 {
            out.push(v as u8);
        } else if v < 256 {
            out.push(0x18);
            out.push(v as u8);
        } else {
            out.push(0x19);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    } else {
        let v = (-1 - val) as u64;
        if v < 24 {
            out.push(0x20 | v as u8);
        } else if v < 256 {
            out.push(0x38);
            out.push(v as u8);
        } else {
            out.push(0x39);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    }
}

// ---- dds-node API types ----

#[derive(Serialize)]
struct EnrollUserRequest {
    label: String,
    credential_id: String,
    attestation_object_b64: String,
    client_data_hash_b64: String,
    rp_id: String,
    display_name: String,
    authenticator_type: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct EnrollmentResponse {
    urn: String,
    jti: String,
    token_cbor_b64: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ChallengeResponse {
    challenge_id: String,
    challenge_b64url: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct SessionAssertRequest {
    subject_urn: Option<String>,
    credential_id: String,
    challenge_id: String,
    client_data_hash: String,
    authenticator_data: String,
    signature: String,
    duration_secs: Option<u64>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct SessionResponse {
    session_id: String,
    token_cbor_b64: String,
    expires_at: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=== DDS FIDO2 End-to-End Test ===");
    println!();

    // Step 0: Check dds-node is running
    print!("[0/5] Checking dds-node at {NODE_URL}... ");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    match client.get(format!("{NODE_URL}/v1/status")).send().await {
        Ok(r) if r.status().is_success() => println!("OK"),
        _ => {
            println!("FAILED");
            eprintln!("  Start dds-node first: cargo run -p dds-node");
            std::process::exit(1);
        }
    }

    // Step 1: Open FIDO2 device
    println!("[1/5] Opening FIDO2 authenticator...");
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap_or_else(|e| {
        eprintln!("  Failed to open FIDO2 device: {e}");
        eprintln!("  Plug in a YubiKey, SoloKey, or other FIDO2 key.");
        std::process::exit(1);
    });
    println!("  Device opened.");

    // Step 2: Create credential (makeCredential)
    println!();
    println!("[2/5] Creating FIDO2 credential (rpId={RP_ID})...");
    println!();
    println!("  >>> TOUCH YOUR FIDO2 KEY NOW <<<");
    println!();

    let challenge_create = verifier::create_challenge();

    let make_args = MakeCredentialArgsBuilder::new(RP_ID, &challenge_create).build();

    let attestation = device
        .make_credential_with_args(&make_args)
        .unwrap_or_else(|e| {
            eprintln!("  makeCredential failed: {e}");
            std::process::exit(1);
        });

    // Verify the attestation locally first
    let verify_result = verifier::verify_attestation(RP_ID, &challenge_create, &attestation);
    if !verify_result.is_success {
        eprintln!("  Local attestation verification FAILED");
        std::process::exit(1);
    }

    let credential_id = &verify_result.credential_id;
    let credential_id_b64url = b64url(credential_id);
    println!("  Credential created and verified!");
    println!(
        "  ID: {}... ({} bytes)",
        &credential_id_b64url[..20.min(credential_id_b64url.len())],
        credential_id.len()
    );

    // Rebuild CBOR attestation object for dds-node enrollment
    let attestation_object = rebuild_attestation_cbor(
        &attestation.fmt,
        &attestation.auth_data,
        attestation.attstmt_alg,
        &attestation.attstmt_sig,
    );

    // The challenge IS the client data hash for this simplified flow.
    // (In a real WebAuthn flow, clientDataHash = SHA-256(clientDataJSON),
    // but ctap-hid-fido2 uses the raw challenge as the hash.)
    let cdh_create = &challenge_create;

    // Step 3: Enroll in dds-node
    println!();
    println!("[3/5] Enrolling user in dds-node...");

    let user_name = format!("fido-test-{:08x}", rand::random::<u32>());

    let enroll_req = EnrollUserRequest {
        label: user_name.clone(),
        credential_id: credential_id_b64url.clone(),
        attestation_object_b64: b64(&attestation_object),
        client_data_hash_b64: b64(cdh_create),
        rp_id: RP_ID.to_string(),
        display_name: format!("FIDO2 Test User ({})", &user_name),
        authenticator_type: "cross-platform".to_string(),
    };

    let resp = client
        .post(format!("{NODE_URL}/v1/enroll/user"))
        .json(&enroll_req)
        .send()
        .await;

    let enrolled = match resp {
        Ok(r) if r.status().is_success() => {
            let body: EnrollmentResponse = r.json().await.unwrap();
            println!("  Enrolled!");
            println!("  URN: {}", body.urn);
            body
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            eprintln!("  Enrollment failed: HTTP {status}");
            eprintln!("  {body}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  Request failed: {e}");
            std::process::exit(1);
        }
    };

    // Step 4: Fetch server challenge then get FIDO2 assertion
    println!();
    println!("[4/5] Getting FIDO2 assertion...");

    // Fetch a single-use server challenge.  The server stores the nonce and
    // will consume it when verifying /v1/session/assert, so we must use it
    // rather than a locally generated random value.
    let challenge_resp: ChallengeResponse = client
        .get(format!("{NODE_URL}/v1/session/challenge"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("  GET /v1/session/challenge failed: {e}");
            std::process::exit(1);
        })
        .json()
        .await
        .unwrap_or_else(|e| {
            eprintln!("  Failed to parse challenge response: {e}");
            std::process::exit(1);
        });

    // Build clientDataJSON exactly as the server reconstructs it in
    // verify_assertion_common (service.rs):
    //   {"type":"webauthn.get","challenge":"<b64url>","origin":"https://<rpId>"}
    // No spaces, fixed field order.
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}"}}"#,
        challenge_resp.challenge_b64url, RP_ID
    );

    // The cdh the server expects (and the device must sign) is
    // SHA-256(clientDataJSON). `ctap-hid-fido2`'s GetAssertion API
    // takes the *raw* challenge and hashes it internally before
    // wiring it to the CTAP2 command — so we MUST pass clientDataJSON
    // itself (NOT the pre-hashed cdh) here, otherwise the device
    // signs over SHA-256(cdh) and the server's verify disagrees by
    // one hash round.
    let cdj_bytes = client_data_json.as_bytes();
    let cdh: [u8; 32] = Sha256::digest(cdj_bytes).into();

    println!();
    println!("  >>> TOUCH YOUR FIDO2 KEY AGAIN <<<");
    println!();

    let assert_args = GetAssertionArgsBuilder::new(RP_ID, cdj_bytes)
        .credential_id(credential_id)
        .build();

    let assertions = device
        .get_assertion_with_args(&assert_args)
        .unwrap_or_else(|e| {
            eprintln!("  getAssertion failed: {e}");
            std::process::exit(1);
        });

    if assertions.is_empty() {
        eprintln!("  getAssertion returned no assertions");
        std::process::exit(1);
    }
    let assertion = &assertions[0];

    // Local verify — `verifier::verify_assertion`'s `challenge` parameter
    // is hashed internally before being concatenated with auth_data, so
    // we pass `cdj_bytes` (matching what we passed to GetAssertion) so
    // both sides hash the same input once.
    let ok =
        verifier::verify_assertion(RP_ID, &verify_result.credential_public_key, cdj_bytes, assertion);
    println!(
        "  Assertion received! (local verify: {})",
        if ok { "PASS" } else { "FAIL" }
    );
    println!(
        "  authData: {} bytes, signature: {} bytes",
        assertion.auth_data.len(),
        assertion.signature.len()
    );

    // Step 5: POST assertion to dds-node /v1/session/assert
    println!();
    println!("[5/5] Requesting DDS session from assertion...");

    let assert_req = SessionAssertRequest {
        subject_urn: Some(enrolled.urn.clone()),
        credential_id: credential_id_b64url,
        challenge_id: challenge_resp.challenge_id,
        client_data_hash: b64(&cdh),
        authenticator_data: b64(&assertion.auth_data),
        signature: b64(&assertion.signature),
        duration_secs: Some(3600),
    };

    let resp = client
        .post(format!("{NODE_URL}/v1/session/assert"))
        .json(&assert_req)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let session: SessionResponse = r.json().await.unwrap();
            println!("  Session issued!");
            println!("  session_id:  {}", session.session_id);
            println!("  expires_at:  {}", session.expires_at);
            println!(
                "  token (b64): {}...",
                &session.token_cbor_b64[..64.min(session.token_cbor_b64.len())]
            );
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            eprintln!("  Session failed: HTTP {status}");
            eprintln!("  {body}");
            if body.contains("no granted purposes") {
                eprintln!();
                eprintln!("  The FIDO2 hardware flow works! The user just needs");
                eprintln!("  a vouch from a trusted root for session issuance.");
            }
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  Request failed: {e}");
            std::process::exit(1);
        }
    }

    println!();
    println!("=== ALL STEPS PASSED ===");
    println!();
    println!("Full FIDO2 flow verified end-to-end with real hardware:");
    println!("  USB key -> makeCredential -> dds-node enroll");
    println!("  USB key -> getAssertion   -> dds-node session");
}
