//! Unit tests for all 6 domain document types + embed/extract lifecycle.

use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_domain::*;
use rand::rngs::OsRng;

fn make_payload(ident: &Identity) -> TokenPayload {
    TokenPayload {
        iss: ident.id.to_urn(),
        iss_key: ident.public_key.clone(),
        jti: format!("test-{}", ident.id.label()),
        sub: ident.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: 1000,
        exp: Some(9999),
        body_type: None,
        body_cbor: None,
    }
}

// ============================================================
// 1. UserAuthAttestation
// ============================================================

#[test]
fn test_user_auth_attestation_roundtrip() {
    let doc = UserAuthAttestation {
        credential_id: "dGVzdC1jcmVkLWlk".to_string(),
        attestation_object: vec![0xA1, 0x01, 0x02],
        client_data_hash: vec![0xAA; 32],
        rp_id: "login.example.com".to_string(),
        user_display_name: "Alice".to_string(),
        authenticator_type: "platform".to_string(),
    };
    let cbor = doc.to_cbor().unwrap();
    let decoded = UserAuthAttestation::from_cbor(&cbor).unwrap();
    assert_eq!(doc, decoded);
}

#[test]
fn test_user_auth_embed_extract() {
    let ident = Identity::generate("alice", &mut OsRng);
    let mut payload = make_payload(&ident);
    let doc = UserAuthAttestation {
        credential_id: "cred-1".into(),
        attestation_object: vec![1, 2, 3],
        client_data_hash: vec![0xBB; 32],
        rp_id: "example.com".into(),
        user_display_name: "Alice".into(),
        authenticator_type: "cross-platform".into(),
    };
    doc.embed(&mut payload).unwrap();
    assert_eq!(
        payload.body_type.as_deref(),
        Some(body_types::USER_AUTH_ATTESTATION)
    );

    let extracted = UserAuthAttestation::extract(&payload).unwrap().unwrap();
    assert_eq!(extracted, doc);

    // Wrong type returns None
    let wrong = DeviceJoinDocument::extract(&payload).unwrap();
    assert!(wrong.is_none());
}

// ============================================================
// 2. DeviceJoinDocument
// ============================================================

#[test]
fn test_device_join_roundtrip() {
    let doc = DeviceJoinDocument {
        device_id: "TPM-ABC123".into(),
        hostname: "workstation-01".into(),
        os: "Windows 11".into(),
        os_version: "24H2".into(),
        tpm_ek_hash: Some("sha256:aabb".into()),
        org_unit: Some("engineering".into()),
        tags: vec!["laptop".into(), "developer".into()],
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(DeviceJoinDocument::from_cbor(&cbor).unwrap(), doc);
}

#[test]
fn test_device_join_in_token() {
    let ident = Identity::generate("device", &mut OsRng);
    let mut payload = make_payload(&ident);
    let doc = DeviceJoinDocument {
        device_id: "HW-001".into(),
        hostname: "srv-01".into(),
        os: "Ubuntu".into(),
        os_version: "24.04".into(),
        tpm_ek_hash: None,
        org_unit: None,
        tags: vec![],
    };
    doc.embed(&mut payload).unwrap();
    let token = Token::sign(payload, &ident.signing_key).unwrap();
    assert!(token.validate().is_ok());
    let extracted = DeviceJoinDocument::extract(&token.payload)
        .unwrap()
        .unwrap();
    assert_eq!(extracted.device_id, "HW-001");
}

// ============================================================
// 3. WindowsPolicyDocument
// ============================================================

#[test]
fn test_windows_policy_roundtrip() {
    let doc = WindowsPolicyDocument {
        policy_id: "security/password".into(),
        display_name: "Password Policy".into(),
        version: 3,
        enforcement: Enforcement::Enforce,
        scope: PolicyScope {
            device_tags: vec!["workstation".into()],
            org_units: vec!["engineering".into()],
            identity_urns: vec![],
        },
        settings: vec![
            PolicySetting {
                key: "password.min_length".into(),
                value: SettingValue::Int(12),
            },
            PolicySetting {
                key: "password.require_mfa".into(),
                value: SettingValue::Bool(true),
            },
            PolicySetting {
                key: "password.forbidden_words".into(),
                value: SettingValue::List(vec!["password".into(), "123456".into()]),
            },
        ],
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(WindowsPolicyDocument::from_cbor(&cbor).unwrap(), doc);
}

// ============================================================
// 4. SoftwareAssignment
// ============================================================

#[test]
fn test_software_assignment_roundtrip() {
    let doc = SoftwareAssignment {
        package_id: "com.example.editor".into(),
        display_name: "Example Editor".into(),
        version: "2.1.0".into(),
        source: "https://cdn.example.com/editor-2.1.0.msi".into(),
        sha256: "abc123def456".into(),
        action: InstallAction::Install,
        scope: PolicyScope {
            device_tags: vec!["developer".into()],
            org_units: vec![],
            identity_urns: vec![],
        },
        silent: true,
        pre_install_script: None,
        post_install_script: Some("cleanup.ps1".into()),
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(SoftwareAssignment::from_cbor(&cbor).unwrap(), doc);
}

// ============================================================
// 5. ServicePrincipalDocument
// ============================================================

#[test]
fn test_service_principal_roundtrip() {
    let doc = ServicePrincipalDocument {
        spn: "HTTP/api.example.com".into(),
        display_name: "API Gateway".into(),
        service_type: "api-gateway".into(),
        auth_methods: vec!["mtls".into(), "token".into()],
        endpoints: vec!["https://api.example.com".into()],
        max_session_secs: Some(3600),
        tags: vec!["production".into()],
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(ServicePrincipalDocument::from_cbor(&cbor).unwrap(), doc);
}

// ============================================================
// 6. SessionDocument
// ============================================================

#[test]
fn test_session_document_roundtrip() {
    let doc = SessionDocument {
        session_id: "sess-abc-123".into(),
        subject_urn: "urn:vouchsafe:alice.hash".into(),
        device_urn: Some("urn:vouchsafe:laptop.hash".into()),
        granted_purposes: vec!["group:developers".into(), "group:backend".into()],
        authorized_resources: vec!["repo:main".into()],
        session_start: 1714605000,
        duration_secs: 3600,
        mfa_verified: true,
        tls_binding: Some("sha256:tls-cert-hash".into()),
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(SessionDocument::from_cbor(&cbor).unwrap(), doc);
}

#[test]
fn test_session_in_signed_token() {
    let ident = Identity::generate("session-issuer", &mut OsRng);
    let session = SessionDocument {
        session_id: "sess-xyz".into(),
        subject_urn: "urn:vouchsafe:bob.hash".into(),
        device_urn: None,
        granted_purposes: vec!["group:users".into()],
        authorized_resources: vec![],
        session_start: 1714605000,
        duration_secs: 300,
        mfa_verified: false,
        tls_binding: None,
    };
    let mut payload = make_payload(&ident);
    session.embed(&mut payload).unwrap();
    let token = Token::sign(payload, &ident.signing_key).unwrap();
    assert!(token.validate().is_ok());
    let extracted = SessionDocument::extract(&token.payload).unwrap().unwrap();
    assert_eq!(extracted.session_id, "sess-xyz");
    assert_eq!(extracted.duration_secs, 300);
}

// ============================================================
// Cross-type safety
// ============================================================

#[test]
fn test_extract_wrong_type_returns_none() {
    let ident = Identity::generate("test", &mut OsRng);
    let mut payload = make_payload(&ident);
    let session = SessionDocument {
        session_id: "s1".into(),
        subject_urn: "urn:x".into(),
        device_urn: None,
        granted_purposes: vec![],
        authorized_resources: vec![],
        session_start: 1000,
        duration_secs: 60,
        mfa_verified: false,
        tls_binding: None,
    };
    session.embed(&mut payload).unwrap();
    assert!(UserAuthAttestation::extract(&payload).unwrap().is_none());
    assert!(DeviceJoinDocument::extract(&payload).unwrap().is_none());
    assert!(WindowsPolicyDocument::extract(&payload).unwrap().is_none());
    assert!(SoftwareAssignment::extract(&payload).unwrap().is_none());
    assert!(
        ServicePrincipalDocument::extract(&payload)
            .unwrap()
            .is_none()
    );
    assert!(SessionDocument::extract(&payload).unwrap().is_some());
}

#[test]
fn test_no_body_returns_none() {
    let ident = Identity::generate("empty", &mut OsRng);
    let payload = make_payload(&ident);
    assert!(SessionDocument::extract(&payload).unwrap().is_none());
    assert!(UserAuthAttestation::extract(&payload).unwrap().is_none());
}
