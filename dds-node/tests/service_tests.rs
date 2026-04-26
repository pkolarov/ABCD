//! Tests for the local authority service.

use dds_core::identity::Identity;
use dds_core::policy::{Effect, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_domain::fido2::{build_packed_self_attestation, build_packed_self_attestation_with_aaguid};
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

/// Phase 1 of `docs/fido2-attestation-allowlist.md`: when the
/// allow-list is empty (the default), enrollment must accept any
/// AAGUID — the all-zero AAGUID, a YubiKey, anything.
#[test]
fn aaguid_empty_allow_list_accepts_anything() {
    let (_root, mut svc) = make_service();
    svc.set_fido2_allowed_aaguids(&[]).unwrap();
    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xBB; 32];
    let yubikey: [u8; 16] = [
        0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20,
        0x2a,
    ];
    let attestation =
        build_packed_self_attestation_with_aaguid("example.com", b"cred", &cred_sk, &cdh, &yubikey);
    let res = svc.enroll_user(EnrollUserRequest {
        label: "alice".into(),
        credential_id: "cred".into(),
        attestation_object: attestation,
        client_data_hash: cdh.to_vec(),
        rp_id: "example.com".into(),
        display_name: "Alice".into(),
        authenticator_type: "roaming".into(),
        client_data_json: None,
        challenge_id: None,
    });
    assert!(
        res.is_ok(),
        "empty allow-list must accept any AAGUID, got {res:?}"
    );
}

/// When the allow-list contains the credential's AAGUID, enrollment
/// proceeds. Both the canonical UUID layout and the bare-hex layout
/// must parse successfully.
#[test]
fn aaguid_allow_list_accepts_listed_authenticator() {
    let (_root, mut svc) = make_service();
    let yubikey_uuid = "2fc0579f-8113-47ea-b116-bb5a8db9202a";
    svc.set_fido2_allowed_aaguids(&[yubikey_uuid.to_string()])
        .unwrap();
    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xBB; 32];
    let yubikey: [u8; 16] = [
        0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20,
        0x2a,
    ];
    let attestation =
        build_packed_self_attestation_with_aaguid("example.com", b"cred", &cred_sk, &cdh, &yubikey);
    let res = svc.enroll_user(EnrollUserRequest {
        label: "alice".into(),
        credential_id: "cred".into(),
        attestation_object: attestation,
        client_data_hash: cdh.to_vec(),
        rp_id: "example.com".into(),
        display_name: "Alice".into(),
        authenticator_type: "roaming".into(),
        client_data_json: None,
        challenge_id: None,
    });
    assert!(
        res.is_ok(),
        "AAGUID matching the allow-list must be accepted, got {res:?}"
    );
}

/// When the allow-list does not contain the credential's AAGUID,
/// enrollment must fail before the token is signed/persisted. This
/// is the load-bearing assertion: an operator who restricts
/// enrollment to a specific authenticator vendor must be able to
/// rely on the gate.
#[test]
fn aaguid_allow_list_rejects_unlisted_authenticator() {
    let (_root, mut svc) = make_service();
    let yubikey_uuid = "2fc0579f-8113-47ea-b116-bb5a8db9202a";
    svc.set_fido2_allowed_aaguids(&[yubikey_uuid.to_string()])
        .unwrap();
    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xBB; 32];
    // Crayonic C-Key AAGUID — not in the allow-list.
    let crayonic: [u8; 16] = [
        0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07,
        0x2a,
    ];
    let attestation = build_packed_self_attestation_with_aaguid(
        "example.com",
        b"cred",
        &cred_sk,
        &cdh,
        &crayonic,
    );
    let res = svc.enroll_user(EnrollUserRequest {
        label: "alice".into(),
        credential_id: "cred".into(),
        attestation_object: attestation,
        client_data_hash: cdh.to_vec(),
        rp_id: "example.com".into(),
        display_name: "Alice".into(),
        authenticator_type: "roaming".into(),
        client_data_json: None,
        challenge_id: None,
    });
    let err = res.expect_err("non-listed AAGUID must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("AAGUID") && msg.contains("ee882879-721c-4913-9775-3dfcce97072a"),
        "error must name the rejected AAGUID and the gate, got: {msg}"
    );
}

/// Bare 32-character hex (no hyphens) is a valid configuration form
/// per `docs/fido2-attestation-allowlist.md`. Mixing case across the
/// list and authData is also fine — the parser is case-insensitive.
#[test]
fn aaguid_allow_list_accepts_bare_hex_and_mixed_case() {
    let (_root, mut svc) = make_service();
    svc.set_fido2_allowed_aaguids(&[
        // YubiKey 5 NFC, mixed case, no hyphens.
        "2FC0579F811347EAB116BB5A8DB9202A".to_string(),
    ])
    .unwrap();
    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xBB; 32];
    let yubikey: [u8; 16] = [
        0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20,
        0x2a,
    ];
    let attestation =
        build_packed_self_attestation_with_aaguid("example.com", b"cred", &cred_sk, &cdh, &yubikey);
    let res = svc.enroll_user(EnrollUserRequest {
        label: "alice".into(),
        credential_id: "cred".into(),
        attestation_object: attestation,
        client_data_hash: cdh.to_vec(),
        rp_id: "example.com".into(),
        display_name: "Alice".into(),
        authenticator_type: "roaming".into(),
        client_data_json: None,
        challenge_id: None,
    });
    assert!(
        res.is_ok(),
        "bare-hex AAGUID config must be accepted, got {res:?}"
    );
}

/// Unparseable allow-list entries must surface as a configuration
/// error rather than a silent fallback to "any AAGUID is fine" —
/// that would defeat the whole point of the gate. The setter is
/// called before the service starts serving traffic, so a hard
/// failure here is the right answer.
#[test]
fn aaguid_allow_list_rejects_malformed_config() {
    let (_root, mut svc) = make_service();
    let res = svc.set_fido2_allowed_aaguids(&["not-a-uuid".to_string()]);
    assert!(
        res.is_err(),
        "malformed AAGUID must be rejected at config time"
    );
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("not-a-uuid"));
}

// -------------------------------------------------------------------
// Phase 2 of docs/fido2-attestation-allowlist.md — per-AAGUID
// attestation cert chain enforcement.
//
// The fixtures here mint a synthetic leaf cert with an embedded
// `id-fido-gen-ce-aaguid` extension matching the AAGUID in authData,
// signed by an rcgen-generated root. The leaf private key signs
// `authData || cdh` so the WebAuthn `attStmt.sig` validates against
// the leaf SPKI (the existing dds-domain check), and the chain
// validates to the configured root (the new Phase 2 check).
// -------------------------------------------------------------------

const YUBIKEY_AAGUID_BYTES: [u8; 16] = [
    0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20, 0x2a,
];

struct ChainFixture {
    root_der: Vec<u8>,
    root_pem_path: std::path::PathBuf,
    leaf_der: Vec<u8>,
    leaf_sk: p256::ecdsa::SigningKey,
    _tempdir: tempfile::TempDir,
}

fn build_chain_fixture_p256(aaguid: &[u8; 16]) -> ChainFixture {
    let root_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = rcgen::CertificateParams::new(vec!["dds-test-root".into()]).unwrap();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_kp).unwrap();
    let root_der = root_cert.der().to_vec();

    let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(vec!["dds-test-leaf".into()]).unwrap();
    let mut ext_content = Vec::with_capacity(18);
    ext_content.push(0x04);
    ext_content.push(0x10);
    ext_content.extend_from_slice(aaguid);
    leaf_params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
            ext_content,
        ));
    let leaf_cert = leaf_params
        .signed_by(&leaf_kp, &root_cert, &root_kp)
        .unwrap();
    let leaf_der = leaf_cert.der().to_vec();
    let leaf_sk = {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_kp.serialize_der()).unwrap()
    };

    let tempdir = tempfile::tempdir().unwrap();
    let root_pem_path = tempdir.path().join("root.pem");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_lines(&root_der)
    );
    std::fs::write(&root_pem_path, pem).unwrap();

    ChainFixture {
        root_der,
        root_pem_path,
        leaf_der,
        leaf_sk,
        _tempdir: tempdir,
    }
}

fn base64_lines(bytes: &[u8]) -> String {
    use base64::Engine;
    let s = base64::engine::general_purpose::STANDARD.encode(bytes);
    s.as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build an attestation_object with `fmt = packed`, `attStmt.x5c = [leaf]`,
/// and `attStmt.sig` signed by `leaf_sk`. The credential pubkey in
/// authData is `cred_pk`. AAGUID in authData is `aaguid`.
fn build_packed_x5c_attestation(
    rp_id: &str,
    credential_id: &[u8],
    cred_pk_p256: &p256::ecdsa::VerifyingKey,
    aaguid: &[u8; 16],
    leaf_der: &[u8],
    leaf_sk: &p256::ecdsa::SigningKey,
    cdh: &[u8; 32],
) -> Vec<u8> {
    use ciborium::value::Value as CborValue;
    use p256::ecdsa::signature::Signer;

    let auth_data = build_auth_data_p256(rp_id, credential_id, cred_pk_p256, aaguid);
    let mut signed = Vec::new();
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(cdh);
    let sig: p256::ecdsa::Signature = leaf_sk.sign(&signed);

    let stmt: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("alg".into()),
            CborValue::Integer((-7i64).into()),
        ),
        (
            CborValue::Text("sig".into()),
            CborValue::Bytes(sig.to_der().as_bytes().to_vec()),
        ),
        (
            CborValue::Text("x5c".into()),
            CborValue::Array(vec![CborValue::Bytes(leaf_der.to_vec())]),
        ),
    ];
    let map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (CborValue::Text("attStmt".into()), CborValue::Map(stmt)),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut out).unwrap();
    out
}

fn build_auth_data_p256(
    rp_id: &str,
    credential_id: &[u8],
    pk: &p256::ecdsa::VerifyingKey,
    aaguid: &[u8; 16],
) -> Vec<u8> {
    use ciborium::value::Value as CborValue;
    use sha2::Digest;
    let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // UP | AT
    out.extend_from_slice(&[0u8, 0, 0, 0]); // signCount
    out.extend_from_slice(aaguid);
    let id_len = credential_id.len() as u16;
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(credential_id);

    let point = pk.to_encoded_point(false);
    let x = point.x().unwrap().to_vec();
    let y = point.y().unwrap().to_vec();
    let cose: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty=EC2
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7i64).into()),
        ), // alg=ES256
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ), // crv=P-256
        (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
        (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
    ];
    ciborium::into_writer(&CborValue::Map(cose), &mut out).unwrap();
    out
}

fn enroll_attestation(
    svc: &mut LocalService<MemoryBackend>,
    label: &str,
    cdh: [u8; 32],
    attestation_object: Vec<u8>,
) -> Result<EnrollmentResult, ServiceError> {
    svc.enroll_user(EnrollUserRequest {
        label: label.into(),
        credential_id: "ignored".into(),
        attestation_object,
        client_data_hash: cdh.to_vec(),
        rp_id: "example.com".into(),
        display_name: label.into(),
        authenticator_type: "roaming".into(),
        client_data_json: None,
        challenge_id: None,
    })
}

/// Phase 2: when an AAGUID has a configured trust root, a credential
/// whose chain validates to that root is accepted.
#[test]
fn attestation_root_accepts_valid_chain() {
    let (_root, mut svc) = make_service();
    let fixture = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: fixture.root_pem_path.clone(),
    }])
    .unwrap();

    let cred_sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let cred_pk = p256::ecdsa::VerifyingKey::from(&cred_sk);
    let cdh = [0xCD; 32];
    let attestation = build_packed_x5c_attestation(
        "example.com",
        b"hw-cred",
        &cred_pk,
        &YUBIKEY_AAGUID_BYTES,
        &fixture.leaf_der,
        &fixture.leaf_sk,
        &cdh,
    );
    let res = enroll_attestation(&mut svc, "alice", cdh, attestation);
    assert!(res.is_ok(), "valid chain must enroll, got {res:?}");
}

/// Phase 2: when an AAGUID has a configured trust root, self-attested
/// `packed` (no x5c) is refused — strict mode is the whole point.
#[test]
fn attestation_root_rejects_self_attested() {
    let (_root, mut svc) = make_service();
    let fixture = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: fixture.root_pem_path.clone(),
    }])
    .unwrap();

    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xCD; 32];
    let attestation = build_packed_self_attestation_with_aaguid(
        "example.com",
        b"hw-cred",
        &cred_sk,
        &cdh,
        &YUBIKEY_AAGUID_BYTES,
    );
    let res = enroll_attestation(&mut svc, "alice", cdh, attestation);
    let err = res.expect_err("self-attested must be rejected when a trust root is configured");
    let msg = err.to_string();
    assert!(
        msg.contains("attStmt.x5c") || msg.contains("self-attestation"),
        "error must mention missing x5c, got: {msg}"
    );
}

/// Phase 2: a chain that validates to a *different* root is rejected.
/// Even if the attacker brings a perfectly-valid YubiKey cert chain,
/// they can't enroll under an AAGUID configured for a different
/// vendor.
#[test]
fn attestation_root_rejects_chain_to_wrong_root() {
    let (_root, mut svc) = make_service();
    // Operator configures Vendor A's root for the YubiKey AAGUID.
    let fixture_a = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: fixture_a.root_pem_path.clone(),
    }])
    .unwrap();

    // Attacker brings a chain signed by Vendor B's root, claiming the
    // same AAGUID.
    let fixture_b = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    let cred_sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let cred_pk = p256::ecdsa::VerifyingKey::from(&cred_sk);
    let cdh = [0xCD; 32];
    let attestation = build_packed_x5c_attestation(
        "example.com",
        b"hw-cred",
        &cred_pk,
        &YUBIKEY_AAGUID_BYTES,
        &fixture_b.leaf_der,
        &fixture_b.leaf_sk,
        &cdh,
    );
    // Sanity: it isn't actually fixture A's root we're carrying.
    assert_ne!(fixture_a.root_der, fixture_b.root_der);
    let res = enroll_attestation(&mut svc, "alice", cdh, attestation);
    let err = res.expect_err("chain to a non-configured root must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("chain validation failed") || msg.contains("BadSignature"),
        "error must mention chain failure, got: {msg}"
    );
}

/// Phase 2: a leaf whose `id-fido-gen-ce-aaguid` extension does not
/// match the AAGUID in authData is rejected. This catches an attacker
/// who reuses a vendor leaf cert under a different AAGUID claim.
#[test]
fn attestation_root_rejects_aaguid_extension_mismatch() {
    let (_root, mut svc) = make_service();
    // Operator binds the YubiKey AAGUID to a YubiKey-flavored root.
    let fixture = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: fixture.root_pem_path.clone(),
    }])
    .unwrap();

    // Build authData with a *different* AAGUID, but reuse the
    // YubiKey leaf cert (whose extension still claims YubiKey).
    let other_aaguid: [u8; 16] = [
        0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07,
        0x2a,
    ];
    let cred_sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let cred_pk = p256::ecdsa::VerifyingKey::from(&cred_sk);
    let cdh = [0xCD; 32];
    // Configure the root for the OTHER aaguid as well, so the chain
    // check itself would pass — the extension mismatch is what should
    // fail the enrollment.
    svc.set_fido2_attestation_roots(&[
        dds_node::config::Fido2AttestationRoot {
            aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
            ca_pem_path: fixture.root_pem_path.clone(),
        },
        dds_node::config::Fido2AttestationRoot {
            aaguid: "ee882879-721c-4913-9775-3dfcce97072a".into(),
            ca_pem_path: fixture.root_pem_path.clone(),
        },
    ])
    .unwrap();

    let attestation = build_packed_x5c_attestation(
        "example.com",
        b"hw-cred",
        &cred_pk,
        &other_aaguid,
        &fixture.leaf_der,
        &fixture.leaf_sk,
        &cdh,
    );
    let res = enroll_attestation(&mut svc, "alice", cdh, attestation);
    let err = res.expect_err("AAGUID extension mismatch must reject enrollment");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match"),
        "error must mention AAGUID mismatch, got: {msg}"
    );
}

/// Phase 2: an AAGUID without any configured root falls back to
/// today's behavior (self-attested packed accepted). Configuration is
/// strictly opt-in per-AAGUID.
#[test]
fn attestation_root_unconfigured_aaguid_keeps_self_attested_path() {
    let (_root, mut svc) = make_service();
    // Configure a root for some specific AAGUID, but the credential's
    // AAGUID is different and unbound.
    let fixture = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: fixture.root_pem_path.clone(),
    }])
    .unwrap();

    let cred_sk = SigningKey::generate(&mut OsRng);
    let cdh = [0xCD; 32];
    let other: [u8; 16] = [0x99; 16];
    let attestation =
        build_packed_self_attestation_with_aaguid("example.com", b"cred", &cred_sk, &cdh, &other);
    let res = enroll_attestation(&mut svc, "alice", cdh, attestation);
    assert!(
        res.is_ok(),
        "unconfigured AAGUID must follow legacy self-attested path, got {res:?}"
    );
}

/// Phase 2: a malformed PEM file or unparseable AAGUID at config time
/// surfaces as a hard error so the operator never silently runs with
/// strict mode disabled.
#[test]
fn attestation_root_rejects_malformed_config() {
    let (_root, mut svc) = make_service();

    // Bad AAGUID.
    let fixture = build_chain_fixture_p256(&YUBIKEY_AAGUID_BYTES);
    let res = svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "totally-not-a-uuid".into(),
        ca_pem_path: fixture.root_pem_path.clone(),
    }]);
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("totally-not-a-uuid"), "got: {msg}");

    // Missing PEM file.
    let res = svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: std::path::PathBuf::from("/nonexistent/dds-test-root.pem"),
    }]);
    assert!(res.is_err());

    // PEM file with no CERTIFICATE blocks.
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-a-cert.pem");
    std::fs::write(
        &bogus,
        b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
    )
    .unwrap();
    let res = svc.set_fido2_attestation_roots(&[dds_node::config::Fido2AttestationRoot {
        aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a".into(),
        ca_pem_path: bogus,
    }]);
    assert!(res.is_err());
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("no PEM CERTIFICATE blocks"), "got: {msg}");
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
