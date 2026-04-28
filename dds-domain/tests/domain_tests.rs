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
        exp: Some(4102444800),
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
        windows: None,
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(WindowsPolicyDocument::from_cbor(&cbor).unwrap(), doc);
}

// ----------------------------------------------------------------
// 3a. WindowsSettings typed bundle (Phase 3 item 9 — applier inputs)
// ----------------------------------------------------------------

#[test]
fn test_windows_settings_default_is_empty() {
    let s = WindowsSettings::default();
    assert!(s.registry.is_empty());
    assert!(s.local_accounts.is_empty());
    assert!(s.password_policy.is_none());
    assert!(s.services.is_empty());
}

#[test]
fn test_registry_value_variants_roundtrip() {
    // Each REG_* variant must serialize and deserialize losslessly.
    let cases = vec![
        RegistryValue::String("hello".into()),
        RegistryValue::ExpandString("%SystemRoot%\\System32".into()),
        RegistryValue::Dword(0xDEAD_BEEF),
        RegistryValue::Qword(0x0123_4567_89AB_CDEF),
        RegistryValue::MultiString(vec!["a".into(), "b".into(), "c".into()]),
        RegistryValue::Binary(vec![0x00, 0xFF, 0xCA, 0xFE]),
    ];
    for v in cases {
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        let decoded: RegistryValue = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, v);
    }
}

#[test]
fn test_registry_directive_set_and_delete() {
    let set = RegistryDirective {
        hive: RegistryHive::LocalMachine,
        key: "SOFTWARE\\Policies\\Microsoft\\Windows\\System".into(),
        name: Some("DisableCMD".into()),
        value: Some(RegistryValue::Dword(1)),
        action: RegistryAction::Set,
    };
    let del = RegistryDirective {
        hive: RegistryHive::LocalMachine,
        key: "SOFTWARE\\Policies\\Example".into(),
        name: None,
        value: None,
        action: RegistryAction::Delete,
    };
    for d in [set, del] {
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).unwrap();
        let back: RegistryDirective = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn test_account_directive_minimal_and_full() {
    let minimal = AccountDirective {
        username: "alice".into(),
        action: AccountAction::Create,
        claim_subject_urn: None,
        full_name: None,
        description: None,
        groups: vec![],
        password_never_expires: None,
    };
    let full = AccountDirective {
        username: "bob".into(),
        action: AccountAction::Create,
        claim_subject_urn: Some("urn:vouchsafe:bob.example".into()),
        full_name: Some("Bob Builder".into()),
        description: Some("Service account for nightly builds".into()),
        groups: vec!["Administrators".into(), "Remote Desktop Users".into()],
        password_never_expires: Some(true),
    };
    for d in [minimal, full] {
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).unwrap();
        let back: AccountDirective = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn test_password_policy_partial_set() {
    // Half the knobs configured, half left as `None`. The applier
    // must treat `None` as "leave the existing value alone".
    let p = PasswordPolicy {
        min_length: Some(14),
        max_age_days: None,
        min_age_days: Some(1),
        history_size: Some(24),
        complexity_required: Some(true),
        lockout_threshold: None,
        lockout_duration_minutes: None,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&p, &mut buf).unwrap();
    let back: PasswordPolicy = ciborium::from_reader(buf.as_slice()).unwrap();
    assert_eq!(back, p);
    assert!(back.max_age_days.is_none());
    assert_eq!(back.min_length, Some(14));
}

#[test]
fn test_service_directive_all_actions() {
    for (action, start_type) in [
        (ServiceAction::Configure, Some(ServiceStartType::Automatic)),
        (ServiceAction::Start, Some(ServiceStartType::Automatic)),
        (ServiceAction::Stop, Some(ServiceStartType::Disabled)),
        (ServiceAction::Configure, None),
    ] {
        let d = ServiceDirective {
            name: "wuauserv".into(),
            display_name: Some("Windows Update".into()),
            start_type,
            action,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).unwrap();
        let back: ServiceDirective = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, d);
    }
}

#[test]
fn test_windows_policy_with_typed_bundle_roundtrip() {
    // Combined doc: free-form `settings` AND typed `windows` bundle
    // populated. Both must survive a round-trip and the bundle must
    // come back exactly equal.
    let doc = WindowsPolicyDocument {
        policy_id: "security/baseline".into(),
        display_name: "Workstation Baseline".into(),
        version: 7,
        enforcement: Enforcement::Enforce,
        scope: PolicyScope {
            device_tags: vec!["workstation".into()],
            org_units: vec!["engineering".into()],
            identity_urns: vec![],
        },
        settings: vec![PolicySetting {
            key: "audit.power_events".into(),
            value: SettingValue::Bool(true),
        }],
        windows: Some(WindowsSettings {
            registry: vec![RegistryDirective {
                hive: RegistryHive::LocalMachine,
                key: "SOFTWARE\\Policies\\Microsoft\\Windows\\System".into(),
                name: Some("DisableCMD".into()),
                value: Some(RegistryValue::Dword(1)),
                action: RegistryAction::Set,
            }],
            local_accounts: vec![AccountDirective {
                username: "ddsadmin".into(),
                action: AccountAction::Create,
                claim_subject_urn: Some("urn:vouchsafe:alice.example".into()),
                full_name: Some("DDS Admin".into()),
                description: None,
                groups: vec!["Administrators".into()],
                password_never_expires: Some(true),
            }],
            password_policy: Some(PasswordPolicy {
                min_length: Some(14),
                complexity_required: Some(true),
                ..Default::default()
            }),
            services: vec![ServiceDirective {
                name: "RemoteRegistry".into(),
                display_name: None,
                start_type: Some(ServiceStartType::Disabled),
                action: ServiceAction::Stop,
            }],
        }),
    };

    let cbor = doc.to_cbor().unwrap();
    let back = WindowsPolicyDocument::from_cbor(&cbor).unwrap();
    assert_eq!(back, doc);
    let bundle = back.windows.expect("typed bundle preserved");
    assert_eq!(bundle.registry.len(), 1);
    assert_eq!(bundle.local_accounts[0].username, "ddsadmin");
    assert_eq!(bundle.password_policy.unwrap().min_length, Some(14));
    assert_eq!(bundle.services[0].action, ServiceAction::Stop);
}

#[test]
fn test_windows_policy_backward_compat_decodes_old_shape() {
    // A token signed against the *old* WindowsPolicyDocument shape
    // (no `windows` field at all) must still deserialize today, with
    // `windows: None`. We simulate the old shape with a struct that
    // matches it exactly and re-encode through ciborium.
    #[derive(serde::Serialize)]
    struct LegacyWindowsPolicyDocument {
        policy_id: String,
        display_name: String,
        version: u64,
        scope: PolicyScope,
        settings: Vec<PolicySetting>,
        enforcement: Enforcement,
    }
    let legacy = LegacyWindowsPolicyDocument {
        policy_id: "legacy".into(),
        display_name: "Legacy Policy".into(),
        version: 1,
        scope: PolicyScope {
            device_tags: vec![],
            org_units: vec![],
            identity_urns: vec![],
        },
        settings: vec![PolicySetting {
            key: "k".into(),
            value: SettingValue::Str("v".into()),
        }],
        enforcement: Enforcement::Audit,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&legacy, &mut buf).unwrap();

    // Decode with the new struct shape — must succeed and report
    // `windows = None`.
    let new_shape = WindowsPolicyDocument::from_cbor(&buf).unwrap();
    assert_eq!(new_shape.policy_id, "legacy");
    assert!(new_shape.windows.is_none());
    assert_eq!(new_shape.settings.len(), 1);
}

#[test]
fn test_windows_policy_with_bundle_in_signed_token() {
    // End-to-end: typed bundle survives the full embed → sign → validate
    // → extract round-trip through TokenPayload, not just the raw CBOR.
    let ident = Identity::generate("policy-issuer", &mut OsRng);
    let mut payload = make_payload(&ident);
    let doc = WindowsPolicyDocument {
        policy_id: "security/lockout".into(),
        display_name: "Account Lockout".into(),
        version: 1,
        enforcement: Enforcement::Enforce,
        scope: PolicyScope {
            device_tags: vec!["all".into()],
            org_units: vec![],
            identity_urns: vec![],
        },
        settings: vec![],
        windows: Some(WindowsSettings {
            password_policy: Some(PasswordPolicy {
                lockout_threshold: Some(5),
                lockout_duration_minutes: Some(30),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    doc.embed(&mut payload).unwrap();
    let token = Token::sign(payload, &ident.signing_key).unwrap();
    assert!(token.validate().is_ok());

    let extracted = WindowsPolicyDocument::extract(&token.payload)
        .unwrap()
        .unwrap();
    let pp = extracted.windows.unwrap().password_policy.unwrap();
    assert_eq!(pp.lockout_threshold, Some(5));
    assert_eq!(pp.lockout_duration_minutes, Some(30));
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
        publisher_identity: None,
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(SoftwareAssignment::from_cbor(&cbor).unwrap(), doc);
}

#[test]
fn test_software_assignment_with_authenticode_publisher_roundtrip() {
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
        post_install_script: None,
        publisher_identity: Some(PublisherIdentity::Authenticode {
            subject: "Example Software, Inc.".into(),
            root_thumbprint: Some("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4".into()),
        }),
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(SoftwareAssignment::from_cbor(&cbor).unwrap(), doc);
}

#[test]
fn test_software_assignment_with_apple_publisher_roundtrip() {
    let doc = SoftwareAssignment {
        package_id: "com.example.maceditor".into(),
        display_name: "Mac Editor".into(),
        version: "2.1.0".into(),
        source: "https://cdn.example.com/editor-2.1.0.pkg".into(),
        sha256: "cafebabe".into(),
        action: InstallAction::Install,
        scope: PolicyScope {
            device_tags: vec!["mac-laptop".into()],
            org_units: vec![],
            identity_urns: vec![],
        },
        silent: true,
        pre_install_script: None,
        post_install_script: None,
        publisher_identity: Some(PublisherIdentity::AppleDeveloperId {
            team_id: "ABCDE12345".into(),
        }),
    };
    let cbor = doc.to_cbor().unwrap();
    assert_eq!(SoftwareAssignment::from_cbor(&cbor).unwrap(), doc);
}

/// Backward-compat: a v1 CBOR blob (no `publisher_identity` field at
/// all) must deserialize as `publisher_identity = None`. Pinned by
/// minting the v1 wire by serializing a clone with the new field set
/// to `None` — `skip_serializing_if = "Option::is_none"` guarantees the
/// emitted bytes match what a pre-Phase-B publisher would have written.
#[test]
fn test_software_assignment_legacy_cbor_decodes_as_none() {
    let v1 = SoftwareAssignment {
        package_id: "com.legacy.app".into(),
        display_name: "Legacy".into(),
        version: "1.0.0".into(),
        source: "https://example.com/legacy.msi".into(),
        sha256: "ff".into(),
        action: InstallAction::Install,
        scope: PolicyScope {
            device_tags: vec![],
            org_units: vec![],
            identity_urns: vec![],
        },
        silent: false,
        pre_install_script: None,
        post_install_script: None,
        publisher_identity: None,
    };
    let cbor = v1.to_cbor().unwrap();
    let decoded = SoftwareAssignment::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.publisher_identity, None);
    assert_eq!(decoded, v1);
}

#[test]
fn test_publisher_identity_validate_authenticode() {
    assert!(
        PublisherIdentity::Authenticode {
            subject: "Example Software, Inc.".into(),
            root_thumbprint: None,
        }
        .validate()
        .is_ok()
    );
    // 40 lowercase hex chars
    assert!(
        PublisherIdentity::Authenticode {
            subject: "Example".into(),
            root_thumbprint: Some("0123456789abcdef0123456789abcdef01234567".into()),
        }
        .validate()
        .is_ok()
    );
    // Empty subject rejected
    assert_eq!(
        PublisherIdentity::Authenticode {
            subject: "   ".into(),
            root_thumbprint: None,
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::EmptyAuthenticodeSubject
    );
    // Wrong thumbprint length
    assert_eq!(
        PublisherIdentity::Authenticode {
            subject: "Example".into(),
            root_thumbprint: Some("abcd".into()),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidRootThumbprint
    );
    // Uppercase hex rejected — agents normalise to lowercase
    assert_eq!(
        PublisherIdentity::Authenticode {
            subject: "Example".into(),
            root_thumbprint: Some("0123456789ABCDEF0123456789ABCDEF01234567".into()),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidRootThumbprint
    );
}

#[test]
fn test_publisher_identity_validate_apple_team_id() {
    assert!(
        PublisherIdentity::AppleDeveloperId {
            team_id: "ABCDE12345".into(),
        }
        .validate()
        .is_ok()
    );
    // Lowercase rejected (Apple Team IDs are uppercase alphanumerics)
    assert_eq!(
        PublisherIdentity::AppleDeveloperId {
            team_id: "abcde12345".into(),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidAppleTeamId
    );
    // Wrong length
    assert_eq!(
        PublisherIdentity::AppleDeveloperId {
            team_id: "SHORT".into(),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidAppleTeamId
    );
    assert_eq!(
        PublisherIdentity::AppleDeveloperId {
            team_id: "TOOLONG12345".into(),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidAppleTeamId
    );
    // Non-alphanumeric rejected
    assert_eq!(
        PublisherIdentity::AppleDeveloperId {
            team_id: "ABC-E12345".into(),
        }
        .validate()
        .unwrap_err(),
        PublisherIdentityError::InvalidAppleTeamId
    );
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
