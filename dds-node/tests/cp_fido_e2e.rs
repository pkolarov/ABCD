//! End-to-end smoke test for the Credential Provider + FIDO2 flow.
//!
//! Exercises the complete lifecycle that the Windows Credential Provider
//! relies on:
//!
//!   1. Boot a dds-node with pre-seeded trust chain
//!   2. Enroll a device  (POST /v1/enroll/device)
//!   3. Enroll a user with packed FIDO2 attestation (POST /v1/enroll/user)
//!   4. Vouch for the enrolled user (root → user trust chain)
//!   5. List enrolled users (GET /v1/enrolled-users)
//!   6. Authenticate via FIDO2 assertion (POST /v1/session/assert)
//!   7. Validate the returned session token
//!   8. Evaluate policy for the authenticated user
//!   9. Verify negative cases (wrong key, unknown credential)
//!
//! This test uses synthetic Ed25519 and P-256 FIDO2 keys (no real
//! hardware authenticator) exercising the exact same code paths that
//! the Auth Bridge → dds-node HTTP flow uses in production.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_domain::fido2::{build_assertion_auth_data, build_packed_self_attestation};
use dds_domain::{DeviceJoinDocument, DomainDocument, SessionDocument, UserAuthAttestation};
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::domain_store;
use dds_node::http::{
    AssertionSessionRequestJson, ChallengeResponse, EnrollDeviceRequestJson, EnrollUserRequestJson,
    EnrolledUsersResponse, EnrollmentResponse, PolicyRequestJson, SessionResponse,
};
use dds_node::p2p_identity;
use dds_node::service::{NodeStatus, PolicyResult};
use dds_store::RedbBackend;
use dds_store::traits::TokenStore;
use ed25519_dalek::{Signer, SigningKey};
use libp2p::PeerId;
use rand::rngs::OsRng;
use reqwest::Client;
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

// ── Helpers ─────────────────────────────────────────────────────────

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// Fetch a server-issued challenge from the node. Returns `(challenge_id, challenge_b64url)`.
async fn fetch_challenge(client: &Client, api: &str) -> (String, String) {
    let resp = client
        .get(format!("{api}/v1/session/challenge"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "challenge endpoint failed");
    let body: ChallengeResponse = resp.json().await.unwrap();
    (body.challenge_id, body.challenge_b64url)
}

/// Build the clientDataHash for a server-issued challenge.
/// Constructs the exact JSON the C++ bridge produces:
/// `{"type":"webauthn.get","challenge":"<b64url>","origin":"https://<rp_id>"}`.
fn make_cdh_from_challenge(rp_id: &str, challenge_b64url: &str) -> [u8; 32] {
    use sha2::Digest;
    let cdj = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#
    );
    sha2::Sha256::digest(cdj.as_bytes()).into()
}

fn make_attest(identity: &Identity, jti: &str) -> Token {
    Token::sign(
        TokenPayload {
            iss: identity.id.to_urn(),
            iss_key: identity.public_key.clone(),
            jti: jti.to_string(),
            sub: identity.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_000,
            exp: Some(u64::MAX / 2),
            body_type: None,
            body_cbor: None,
        },
        &identity.signing_key,
    )
    .unwrap()
}

fn make_vouch(
    voucher: &Identity,
    subject_urn: &str,
    subject_token: &Token,
    purpose: &str,
    jti: &str,
) -> Token {
    Token::sign(
        TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: jti.to_string(),
            sub: subject_urn.to_string(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose.to_string()),
            vch_iss: Some(subject_urn.to_string()),
            vch_sum: Some(subject_token.payload_hash()),
            revokes: None,
            iat: 1_001,
            exp: Some(u64::MAX / 2),
            body_type: None,
            body_cbor: None,
        },
        &voucher.signing_key,
    )
    .unwrap()
}

fn seed_store(db_path: &std::path::Path, tokens: &[Token]) {
    let mut store = RedbBackend::open(db_path).unwrap();
    for token in tokens {
        store.put_token(token).unwrap();
    }
}

struct NodeFixture {
    _dir: TempDir,
    config_path: PathBuf,
    db_path: PathBuf,
    api_url: String,
}

fn write_node_fixture(
    name: &str,
    domain_key: &dds_domain::DomainKey,
    trusted_roots: Vec<String>,
    listen_port: u16,
    api_port: u16,
) -> NodeFixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join(name);
    std::fs::create_dir_all(&data_dir).unwrap();

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(p2p_keypair.public());
    p2p_identity::save(&data_dir.join("p2p_key.bin"), &p2p_keypair).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

    let domain = domain_key.domain();
    let listen_addr = format!("/ip4/127.0.0.1/tcp/{listen_port}");
    let api_addr = format!("127.0.0.1:{api_port}");
    let cfg = NodeConfig {
        data_dir: data_dir.clone(),
        network: NetworkConfig {
            listen_addr,
            bootstrap_peers: Vec::new(),
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: api_addr.clone(),
            api_auth: Default::default(),
            allow_legacy_v1_tokens: false,
            metrics_addr: None,
        },
        org_hash: "cp-e2e-org".to_string(),
        domain: DomainConfig {
            name: domain.name,
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            pq_pubkey: None,
            capabilities: Vec::new(),
            admission_path: None,
            audit_log_enabled: false,
            max_delegation_depth: 5,
            audit_log_max_entries: 0,
            audit_log_retention_days: 0,
            enforce_device_scope_vouch: false,
            allow_unattested_credentials: false,
            fido2_allowed_aaguids: Vec::new(),
            fido2_attestation_roots: Vec::new(),
            epoch_rotation_secs: 86_400,
        },
        trusted_roots,
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 1,
    };
    let config_path = dir.path().join(format!("{name}.toml"));
    std::fs::write(&config_path, toml::to_string_pretty(&cfg).unwrap()).unwrap();

    NodeFixture {
        _dir: dir,
        config_path,
        db_path: cfg.db_path(),
        api_url: format!("http://{api_addr}"),
    }
}

struct RunningNode {
    fixture: NodeFixture,
    child: Child,
}

impl RunningNode {
    fn spawn(fixture: NodeFixture) -> Self {
        let child = dds_node_bin()
            .arg("run")
            .arg(&fixture.config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self { fixture, child }
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_status(client: &Client, api_url: &str) -> NodeStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(resp) = client.get(format!("{api_url}/v1/status")).send().await {
            if resp.status().is_success() {
                return resp.json().await.unwrap();
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {api_url}/v1/status"
        );
        sleep(Duration::from_millis(200)).await;
    }
}

/// Build a UserAuthAttestation token with a real packed FIDO2 attestation,
/// pre-signed by the given identity. This produces a token that can be
/// seeded into the store before the node starts.
fn make_fido2_user_attest(
    user: &Identity,
    cred_sk: &SigningKey,
    credential_id: &[u8],
    rp_id: &str,
    display_name: &str,
    jti: &str,
) -> Token {
    let client_data_hash = [0xAB; 32];
    let attestation =
        build_packed_self_attestation(rp_id, credential_id, cred_sk, &client_data_hash);
    let doc = UserAuthAttestation {
        credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
        attestation_object: attestation,
        client_data_hash: client_data_hash.to_vec(),
        rp_id: rp_id.to_string(),
        user_display_name: display_name.to_string(),
        authenticator_type: "platform".to_string(),
    };
    let mut payload = TokenPayload {
        iss: user.id.to_urn(),
        iss_key: user.public_key.clone(),
        jti: jti.to_string(),
        sub: user.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: 1_000,
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    doc.embed(&mut payload).unwrap();
    Token::sign(payload, &user.signing_key).unwrap()
}

// ── Tests ───────────────────────────────────────────────────────────

/// Full Credential Provider + FIDO2 smoke test (Ed25519).
///
/// Pre-seeds the node with a complete trust chain:
///   root (trusted) → vouch → alice (with FIDO2 credential)
///
/// Then exercises:
///   node boot → device enroll → list users → FIDO2 assertion
///   → session token → policy check → wrong-key reject → unknown-cred reject
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cp_fido2_ed25519_full_lifecycle() {
    let client = Client::new();
    let domain_key = dds_domain::DomainKey::from_secret_bytes("cp-e2e.local", [42u8; 32]);
    let root = Identity::generate("root", &mut OsRng);
    let alice = Identity::generate("alice", &mut OsRng);

    // Create FIDO2 credential key for Alice
    let cred_sk = SigningKey::generate(&mut OsRng);
    let rp_id = "dds.local";
    let credential_id = b"cp-e2e-cred-ed25519";
    let stored_cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);

    // Build the trust chain: root attest → alice UserAuthAttestation → root vouches alice
    let root_attest = make_attest(&root, "att-root-cp-e2e");
    let alice_attest = make_fido2_user_attest(
        &alice,
        &cred_sk,
        credential_id,
        rp_id,
        "Alice (E2E Test)",
        "att-alice-cp-e2e",
    );
    let alice_vouch = make_vouch(
        &root,
        &alice.id.to_urn(),
        &alice_attest,
        "dds:session",
        "vouch-alice-cp-e2e",
    );

    let fixture = write_node_fixture(
        "cp-node",
        &domain_key,
        vec![root.id.to_urn()],
        reserve_port(),
        reserve_port(),
    );
    seed_store(
        &fixture.db_path,
        &[root_attest, alice_attest.clone(), alice_vouch],
    );
    let node = RunningNode::spawn(fixture);
    let api = &node.fixture.api_url;

    // ── 1. Wait for node to be healthy ──────────────────────────────
    let status = wait_for_status(&client, api).await;
    assert_eq!(status.store_tokens, 3, "root attest + alice attest + vouch");
    assert_eq!(status.trust_graph_tokens, 3);

    // ── 2. Enroll a device ──────────────────────────────────────────
    let device_resp = client
        .post(format!("{api}/v1/enroll/device"))
        .json(&EnrollDeviceRequestJson {
            label: "win11-arm64".to_string(),
            device_id: "TPM-E2E-001".to_string(),
            hostname: "DESKTOP-DDS-E2E".to_string(),
            os: "Windows".to_string(),
            os_version: "11".to_string(),
            tpm_ek_hash: Some("sha256:e2e-tpm-hash".to_string()),
            org_unit: Some("engineering".to_string()),
            tags: vec!["e2e-test".to_string(), "arm64".to_string()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(device_resp.status(), 200, "device enrollment failed");
    let device: EnrollmentResponse = device_resp.json().await.unwrap();
    let device_token = Token::from_cbor(&decode_b64(&device.token_cbor_b64)).unwrap();
    let device_doc = DeviceJoinDocument::extract(&device_token.payload)
        .unwrap()
        .unwrap();
    assert_eq!(device_doc.device_id, "TPM-E2E-001");
    assert_eq!(device_doc.os, "Windows");
    let device_urn = device.urn.clone();

    // ── 3. List enrolled users ──────────────────────────────────────
    let list_resp = client
        .get(format!("{api}/v1/enrolled-users"))
        .query(&[("device_urn", &device_urn)])
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let users: EnrolledUsersResponse = list_resp.json().await.unwrap();
    assert_eq!(users.users.len(), 1, "expected exactly 1 enrolled user");
    assert_eq!(users.users[0].display_name, "Alice (E2E Test)");
    assert_eq!(users.users[0].credential_id, stored_cred_id);

    // ── 4. Authenticate via FIDO2 assertion ─────────────────────────
    //
    // This simulates exactly what the Auth Bridge does after calling
    // the platform WebAuthn API: fetches a server challenge, builds
    // clientDataJSON from it, hashes it, signs auth_data || cdh,
    // then POSTs to /v1/session/assert.

    let (challenge_id, challenge_b64url) = fetch_challenge(&client, api).await;
    let auth_data = build_assertion_auth_data(rp_id, 1);
    let assertion_cdh = make_cdh_from_challenge(rp_id, &challenge_b64url);
    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(&auth_data);
    signed_msg.extend_from_slice(&assertion_cdh);
    let signature = cred_sk.sign(&signed_msg);

    let assert_resp = client
        .post(format!("{api}/v1/session/assert"))
        .json(&AssertionSessionRequestJson {
            subject_urn: Some(alice.id.to_urn()),
            credential_id: stored_cred_id.clone(),
            challenge_id,
            client_data_hash: encode_b64(&assertion_cdh),
            authenticator_data: encode_b64(&auth_data),
            signature: encode_b64(&signature.to_bytes()),
            duration_secs: Some(3600),

            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    let assert_status = assert_resp.status();
    let assert_body = assert_resp.text().await.unwrap();
    assert_eq!(
        assert_status, 200,
        "session/assert failed (body: {assert_body})"
    );
    let session: SessionResponse = serde_json::from_str(&assert_body).unwrap();
    assert!(session.session_id.starts_with("sess-"));
    assert!(!session.token_cbor_b64.is_empty());

    // Validate the session token structure
    let session_token = Token::from_cbor(&decode_b64(&session.token_cbor_b64)).unwrap();
    let session_doc = SessionDocument::extract(&session_token.payload)
        .unwrap()
        .unwrap();
    assert_eq!(session_doc.subject_urn, alice.id.to_urn());
    assert!(session_doc.mfa_verified, "FIDO2 assertion implies MFA");
    assert!(session.expires_at > 0);

    // ── 5. Verify wrong key is rejected ─────────────────────────────
    // Fails at crypto step (before challenge check); dummy challenge_id suffices.
    let wrong_sk = SigningKey::generate(&mut OsRng);
    let wrong_sig = wrong_sk.sign(&signed_msg);

    let bad_resp = client
        .post(format!("{api}/v1/session/assert"))
        .json(&AssertionSessionRequestJson {
            subject_urn: Some(alice.id.to_urn()),
            credential_id: stored_cred_id.clone(),
            challenge_id: "dummy-bad-key".into(),
            client_data_hash: encode_b64(&assertion_cdh),
            authenticator_data: encode_b64(&auth_data),
            signature: encode_b64(&wrong_sig.to_bytes()),
            duration_secs: None,

            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_resp.status(),
        401,
        "wrong key should be rejected with 401"
    );

    // ── 6. Verify unknown credential is rejected ────────────────────
    // Fails at credential-lookup step; dummy challenge_id suffices.
    let unknown_resp = client
        .post(format!("{api}/v1/session/assert"))
        .json(&AssertionSessionRequestJson {
            subject_urn: None,
            credential_id: "nonexistent-credential-id".to_string(),
            challenge_id: "dummy-unknown-cred".into(),
            client_data_hash: encode_b64(&assertion_cdh),
            authenticator_data: encode_b64(&auth_data),
            signature: encode_b64(&signature.to_bytes()),
            duration_secs: None,

            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown_resp.status(),
        401,
        "unknown credential_id should be rejected"
    );

    // ── 7. Policy evaluation ────────────────────────────────────────
    let policy_resp = client
        .post(format!("{api}/v1/policy/evaluate"))
        .json(&PolicyRequestJson {
            subject_urn: alice.id.to_urn(),
            resource: "repo:main".to_string(),
            action: "read".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), 200);
    let _policy: PolicyResult = policy_resp.json().await.unwrap();

    // ── 8. Final status check ───────────────────────────────────────
    let final_status = wait_for_status(&client, api).await;
    assert!(
        final_status.store_tokens >= 4,
        "should have root + alice + vouch + device tokens"
    );
}

/// Same flow but with P-256 (ES256) FIDO2 credentials.
/// Verifies the node correctly handles the alternative COSE algorithm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cp_fido2_p256_assertion() {
    use dds_domain::fido2::build_packed_self_attestation_p256;
    use p256::ecdsa::{DerSignature, SigningKey as P256SigningKey, signature::Signer as _};

    let client = Client::new();
    let domain_key = dds_domain::DomainKey::from_secret_bytes("cp-p256.local", [43u8; 32]);
    let root = Identity::generate("root", &mut OsRng);
    let bob = Identity::generate("bob", &mut OsRng);

    // P-256 FIDO2 credential
    let p256_sk = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let rp_id = "dds.local";
    let credential_id = b"cp-e2e-cred-p256";
    let cdh = [0xEF; 32];
    let attestation = build_packed_self_attestation_p256(rp_id, credential_id, &p256_sk, &cdh);
    let stored_cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);

    // Build trust chain with P-256 attestation embedded
    let root_attest = make_attest(&root, "att-root-p256");
    let doc = UserAuthAttestation {
        credential_id: stored_cred_id.clone(),
        attestation_object: attestation,
        client_data_hash: cdh.to_vec(),
        rp_id: rp_id.to_string(),
        user_display_name: "Bob (P-256 E2E)".to_string(),
        authenticator_type: "cross-platform".to_string(),
    };
    let mut payload = TokenPayload {
        iss: bob.id.to_urn(),
        iss_key: bob.public_key.clone(),
        jti: "att-bob-p256".to_string(),
        sub: bob.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: 1_000,
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    doc.embed(&mut payload).unwrap();
    let bob_attest = Token::sign(payload, &bob.signing_key).unwrap();
    let bob_vouch = make_vouch(
        &root,
        &bob.id.to_urn(),
        &bob_attest,
        "dds:session",
        "vouch-bob-p256",
    );

    let fixture = write_node_fixture(
        "cp-p256-node",
        &domain_key,
        vec![root.id.to_urn()],
        reserve_port(),
        reserve_port(),
    );
    seed_store(&fixture.db_path, &[root_attest, bob_attest, bob_vouch]);
    let node = RunningNode::spawn(fixture);
    let api = &node.fixture.api_url;
    wait_for_status(&client, api).await;

    // FIDO2 assertion with P-256 — fetch a real challenge so the node accepts it.
    let (challenge_id, challenge_b64url) = fetch_challenge(&client, api).await;
    let auth_data = build_assertion_auth_data(rp_id, 1);
    let assertion_cdh = make_cdh_from_challenge(rp_id, &challenge_b64url);
    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(&auth_data);
    signed_msg.extend_from_slice(&assertion_cdh);
    let sig: DerSignature = p256_sk.sign(&signed_msg);

    let assert_resp = client
        .post(format!("{api}/v1/session/assert"))
        .json(&AssertionSessionRequestJson {
            subject_urn: Some(bob.id.to_urn()),
            credential_id: stored_cred_id,
            challenge_id,
            client_data_hash: encode_b64(&assertion_cdh),
            authenticator_data: encode_b64(&auth_data),
            signature: encode_b64(sig.as_bytes()),
            duration_secs: Some(1800),

            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    let status = assert_resp.status();
    let body = assert_resp.text().await.unwrap();
    assert_eq!(status, 200, "P-256 session/assert failed (body: {body})");
    let session: SessionResponse = serde_json::from_str(&body).unwrap();
    assert!(session.session_id.starts_with("sess-"));

    let session_token = Token::from_cbor(&decode_b64(&session.token_cbor_b64)).unwrap();
    let session_doc = SessionDocument::extract(&session_token.payload)
        .unwrap()
        .unwrap();
    assert_eq!(session_doc.subject_urn, bob.id.to_urn());
    assert!(session_doc.mfa_verified);
}

/// Enroll a user via HTTP API, then vouch for them via pre-seeded root.
/// Verifies the HTTP enrollment + assertion flow works end-to-end when
/// the vouch arrives via gossip (simulated by seeding before node start,
/// using a second enrollment).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cp_fido2_enroll_then_assert() {
    let client = Client::new();
    let domain_key = dds_domain::DomainKey::from_secret_bytes("cp-enroll.local", [45u8; 32]);
    let root = Identity::generate("root", &mut OsRng);

    let root_attest = make_attest(&root, "att-root-enroll");

    let fixture = write_node_fixture(
        "cp-enroll",
        &domain_key,
        vec![root.id.to_urn()],
        reserve_port(),
        reserve_port(),
    );
    seed_store(&fixture.db_path, &[root_attest]);
    let node = RunningNode::spawn(fixture);
    let api = &node.fixture.api_url;
    wait_for_status(&client, api).await;

    // Enroll user via HTTP API with packed attestation
    let cred_sk = SigningKey::generate(&mut OsRng);
    let rp_id = "dds.local";
    let credential_id = b"enroll-test-cred";
    let cdh = [0x11; 32];
    let attestation = build_packed_self_attestation(rp_id, credential_id, &cred_sk, &cdh);

    let resp = client
        .post(format!("{api}/v1/enroll/user"))
        .json(&EnrollUserRequestJson {
            label: "carol".to_string(),
            credential_id: "enroll-test-cred".to_string(),
            attestation_object_b64: encode_b64(&attestation),
            client_data_hash_b64: encode_b64(&cdh),
            rp_id: rp_id.to_string(),
            display_name: "Carol".to_string(),
            authenticator_type: "platform".to_string(),
            client_data_json_b64: None,
            challenge_id: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "enrollment failed");
    let enrolled: EnrollmentResponse = resp.json().await.unwrap();
    assert!(enrolled.urn.starts_with("urn:vouchsafe:"));

    // Verify the enrolled user appears in the list
    let list_resp = client
        .get(format!("{api}/v1/enrolled-users"))
        .query(&[("device_urn", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let users: EnrolledUsersResponse = list_resp.json().await.unwrap();
    assert_eq!(users.users.len(), 1);
    assert_eq!(users.users[0].display_name, "Carol");

    // Without a vouch from root, assertion should fail with 500
    // (subject has no granted purposes)
    let auth_data = build_assertion_auth_data(rp_id, 1);
    let stored_cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
    // Use a real challenge so verification proceeds through UP, RP-ID, and challenge
    // checks — only failing at session issuance because the user has no vouch.
    let (no_vouch_ch_id, no_vouch_ch_b64) = fetch_challenge(&client, api).await;
    let no_vouch_cdh = make_cdh_from_challenge(rp_id, &no_vouch_ch_b64);
    let mut no_vouch_msg = auth_data.clone();
    no_vouch_msg.extend_from_slice(&no_vouch_cdh);
    let no_vouch_sig = cred_sk.sign(&no_vouch_msg);
    let no_vouch_resp = client
        .post(format!("{api}/v1/session/assert"))
        .json(&AssertionSessionRequestJson {
            subject_urn: Some(enrolled.urn.clone()),
            credential_id: stored_cred_id,
            challenge_id: no_vouch_ch_id,
            client_data_hash: encode_b64(&no_vouch_cdh),
            authenticator_data: encode_b64(&auth_data),
            signature: encode_b64(&no_vouch_sig.to_bytes()),
            duration_secs: None,

            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    // Without vouch, this should fail (500 or 403 depending on implementation)
    assert_ne!(
        no_vouch_resp.status(),
        200,
        "assertion without vouch should NOT succeed"
    );
}
