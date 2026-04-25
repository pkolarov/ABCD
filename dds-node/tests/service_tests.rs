//! Tests for the local authority service.

use dds_core::identity::Identity;
use dds_core::policy::{Effect, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::fido2::build_packed_self_attestation;
use dds_domain::{DeviceJoinDocument, DomainDocument, SessionDocument, UserAuthAttestation};
use dds_node::service::*;
use dds_store::MemoryBackend;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

fn make_service() -> (Identity, LocalService<MemoryBackend>) {
    let node_ident = Identity::generate("test-node", &mut OsRng);
    let root = Identity::generate("root", &mut OsRng);

    let mut trusted_roots = BTreeSet::new();
    trusted_roots.insert(root.id.to_urn());

    // Add root attestation to trust graph
    let mut graph = TrustGraph::new();
    let root_attest = Token::sign(
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
    graph.add_token(root_attest).unwrap();

    let store = MemoryBackend::new();
    let shared_graph = Arc::new(RwLock::new(graph));
    let svc = LocalService::new(node_ident, shared_graph, trusted_roots, store);
    (root, svc)
}

// ---- Enrollment tests ----

#[test]
fn test_enroll_user() {
    let (_root, mut svc) = make_service();
    let cred_sk = SigningKey::generate(&mut OsRng);
    // A-1 step-1: packed self-attestation over the 0xBB CDH passed
    // below. Default `allow_unattested_credentials = false` no longer
    // accepts fmt=none, so this test exercises the packed path.
    let cdh = [0xBB; 32];
    let attestation = build_packed_self_attestation("example.com", b"cred-123", &cred_sk, &cdh);
    let result = svc
        .enroll_user(EnrollUserRequest {
            label: "alice".into(),
            credential_id: "cred-123".into(),
            attestation_object: attestation,
            client_data_hash: cdh.to_vec(),
            rp_id: "example.com".into(),
            display_name: "Alice".into(),
            authenticator_type: "platform".into(),
            client_data_json: None,
            challenge_id: None,
        })
        .unwrap();

    assert!(result.urn.starts_with("urn:vouchsafe:alice."));
    assert!(result.jti.starts_with("attest-"));
    assert!(!result.token_cbor.is_empty());

    // Verify token is valid and contains the attestation
    let token = Token::from_cbor(&result.token_cbor).unwrap();
    assert!(token.validate().is_ok());
    let doc = UserAuthAttestation::extract(&token.payload)
        .unwrap()
        .unwrap();
    // credential_id is now base64url-encoded from the parsed attestation object
    assert_eq!(doc.credential_id, "Y3JlZC0xMjM");
    assert_eq!(doc.rp_id, "example.com");
}

#[test]
fn test_enroll_user_rejects_invalid_attestation() {
    let (_root, mut svc) = make_service();
    let result = svc.enroll_user(EnrollUserRequest {
        label: "alice".into(),
        credential_id: "cred-123".into(),
        attestation_object: vec![0x00, 0x01, 0x02],
        client_data_hash: vec![0xBB; 32],
        rp_id: "example.com".into(),
        display_name: "Alice".into(),
        authenticator_type: "platform".into(),
        client_data_json: None,
        challenge_id: None,
    });
    assert!(result.is_err());
}

#[test]
fn test_enroll_device() {
    let (_root, mut svc) = make_service();
    let result = svc
        .enroll_device(EnrollDeviceRequest {
            label: "laptop-01".into(),
            device_id: "HW-ABC".into(),
            hostname: "workstation-01".into(),
            os: "Windows 11".into(),
            os_version: "24H2".into(),
            tpm_ek_hash: Some("sha256:tpmhash".into()),
            org_unit: Some("engineering".into()),
            tags: vec!["developer".into(), "laptop".into()],
        })
        .unwrap();

    assert!(result.urn.starts_with("urn:vouchsafe:laptop-01."));
    let token = Token::from_cbor(&result.token_cbor).unwrap();
    assert!(token.validate().is_ok());
    let doc = DeviceJoinDocument::extract(&token.payload)
        .unwrap()
        .unwrap();
    assert_eq!(doc.device_id, "HW-ABC");
    assert_eq!(doc.hostname, "workstation-01");
    assert_eq!(doc.tags, vec!["developer", "laptop"]);
}

// ---- Session tests ----

#[test]
fn test_issue_session() {
    let (root, mut svc) = make_service();

    // Create alice's attestation and a vouch from root with purpose "repo:main"
    let alice = Identity::generate("alice", &mut OsRng);
    let alice_attest = Token::sign(
        TokenPayload {
            iss: alice.id.to_urn(),
            iss_key: alice.public_key.clone(),
            jti: "attest-alice".into(),
            sub: alice.id.to_urn(),
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
        &alice.signing_key,
    )
    .unwrap();
    svc.trust_graph
        .write()
        .unwrap()
        .add_token(alice_attest.clone())
        .unwrap();

    let vouch = Token::sign(
        TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "vouch-alice-repo".into(),
            sub: alice.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some("repo:main".into()),
            vch_iss: Some(alice.id.to_urn()),
            vch_sum: Some(alice_attest.payload_hash()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        &root.signing_key,
    )
    .unwrap();
    svc.trust_graph.write().unwrap().add_token(vouch).unwrap();

    let result = svc
        .issue_session(SessionRequest {
            subject_urn: alice.id.to_urn(),
            device_urn: Some("urn:vouchsafe:laptop.hash".into()),
            requested_resources: vec!["repo:main".into()],
            duration_secs: 300,
            mfa_verified: true,
            tls_binding: None,
        })
        .unwrap();

    assert!(result.session_id.starts_with("sess-"));
    assert!(result.expires_at > 0);
    assert!(!result.token_cbor.is_empty());

    // Verify the session token
    let token = Token::from_cbor(&result.token_cbor).unwrap();
    assert!(token.validate().is_ok());
    let doc = SessionDocument::extract(&token.payload).unwrap().unwrap();
    assert_eq!(doc.session_id, result.session_id);
    assert_eq!(doc.duration_secs, 300);
    assert!(doc.mfa_verified);
    assert_eq!(doc.authorized_resources, vec!["repo:main"]);
}

// ---- Policy tests ----

#[test]
fn test_policy_evaluation() {
    let (_root, mut svc) = make_service();
    svc.add_policy_rule(PolicyRule {
        effect: Effect::Allow,
        required_purpose: "group:dev".into(),
        resource: "repo:main".into(),
        actions: vec!["read".into(), "write".into()],
    });

    // No trust chain → deny
    let result = svc
        .evaluate_policy("urn:vouchsafe:alice.hash", "repo:main", "read")
        .unwrap();
    assert!(!result.allowed);
}

// ---- Status tests ----

#[test]
fn test_node_status() {
    let (_root, svc) = make_service();
    let status = svc.status("12D3KooWTest", 3, 42).unwrap();
    assert_eq!(status.peer_id, "12D3KooWTest");
    assert_eq!(status.connected_peers, 3);
    assert_eq!(status.dag_operations, 42);
    assert!(status.trust_graph_tokens > 0); // at least root attestation
    assert_eq!(status.trusted_roots, 1);
}
