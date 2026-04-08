//! Integration tests — end-to-end flows crossing module boundaries.

use std::collections::BTreeSet;

use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_core::crypto::SchemeId;
use dds_core::identity::Identity;
use dds_core::policy::{Effect, PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use dds_store::traits::TokenStore;
use rand::rngs::OsRng;

/// Helper: make a signed attest token for an identity.
fn attest(ident: &Identity) -> Token {
    Token::sign(
        TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("attest-{}", ident.id.label()),
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
        },
        &ident.signing_key,
    )
    .unwrap()
}

/// Helper: make a vouch token from voucher for subject with a purpose.
fn vouch(voucher: &Identity, subject: &Identity, purpose: &str, subject_token: &Token) -> Token {
    Token::sign(
        TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: format!("vouch-{}-{}", voucher.id.label(), subject.id.label()),
            sub: subject.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose.to_string()),
            vch_iss: Some(subject.id.to_urn()),
            vch_sum: Some(subject_token.payload_hash()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        &voucher.signing_key,
    )
    .unwrap()
}

/// Helper: make a revoke token.
fn revoke(revoker: &Identity, target_jti: &str) -> Token {
    Token::sign(
        TokenPayload {
            iss: revoker.id.to_urn(),
            iss_key: revoker.public_key.clone(),
            jti: format!("revoke-{}", target_jti),
            sub: "revocation".to_string(),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(target_jti.to_string()),
            iat: 2000,
            exp: None,
            body_type: None,
            body_cbor: None,
        },
        &revoker.signing_key,
    )
    .unwrap()
}

// ============================================================
// Integration Test 1: Full trust chain lifecycle
// root → admin → user, then revoke admin's vouch → user loses access
// ============================================================
#[test]
fn test_full_trust_chain_lifecycle() {
    let root = Identity::generate("root", &mut OsRng);
    let admin = Identity::generate("admin", &mut OsRng);
    let user = Identity::generate("user", &mut OsRng);

    let mut graph = TrustGraph::new();
    let mut roots = BTreeSet::new();
    roots.insert(root.id.to_urn());

    // Build chain: root attests, admin attests, root vouches admin, admin vouches user
    let root_attest = attest(&root);
    let admin_attest = attest(&admin);
    let user_attest = attest(&user);

    let root_vouches_admin = vouch(&root, &admin, "dds:group:admins", &admin_attest);
    let admin_vouches_user = vouch(&admin, &user, "dds:group:developers", &user_attest);

    graph.add_token(root_attest).unwrap();
    graph.add_token(admin_attest).unwrap();
    graph.add_token(user_attest).unwrap();
    graph.add_token(root_vouches_admin.clone()).unwrap();
    graph.add_token(admin_vouches_user.clone()).unwrap();

    // User should be trusted via root → admin → user
    assert!(graph.validate_chain(&user.id.to_urn(), &roots).is_ok());
    assert!(graph.has_purpose(&user.id.to_urn(), "dds:group:developers", &roots));

    // Now revoke admin's vouch for user
    let revoke_token = revoke(&admin, admin_vouches_user.payload.jti.as_str());
    graph.add_token(revoke_token).unwrap();

    // User should no longer be trusted
    assert!(graph.validate_chain(&user.id.to_urn(), &roots).is_err());
    assert!(!graph.has_purpose(&user.id.to_urn(), "dds:group:developers", &roots));

    // Admin should still be trusted
    assert!(graph.validate_chain(&admin.id.to_urn(), &roots).is_ok());
}

// ============================================================
// Integration Test 2: Policy evaluation with trust graph
// ============================================================
#[test]
fn test_policy_evaluation_end_to_end() {
    let root = Identity::generate("root", &mut OsRng);
    let dev = Identity::generate("dev", &mut OsRng);
    let outsider = Identity::generate("outsider", &mut OsRng);

    let mut graph = TrustGraph::new();
    let mut roots = BTreeSet::new();
    roots.insert(root.id.to_urn());

    // Build trust: root → dev (purpose: group:backend)
    let root_attest = attest(&root);
    let dev_attest = attest(&dev);
    let outsider_attest = attest(&outsider);
    let root_vouches_dev = vouch(&root, &dev, "dds:group:backend", &dev_attest);

    graph.add_token(root_attest).unwrap();
    graph.add_token(dev_attest).unwrap();
    graph.add_token(outsider_attest).unwrap();
    graph.add_token(root_vouches_dev).unwrap();

    // Policy: backend group can read repo:main
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule {
        effect: Effect::Allow,
        required_purpose: "dds:group:backend".to_string(),
        resource: "repo:main".to_string(),
        actions: vec!["read".to_string(), "write".to_string()],
    });

    // Dev should be allowed
    let decision = engine.evaluate(&dev.id.to_urn(), "repo:main", "read", &graph, &roots);
    assert!(decision.is_allowed(), "dev should be allowed: {decision}");

    // Dev should be allowed to write too
    let decision = engine.evaluate(&dev.id.to_urn(), "repo:main", "write", &graph, &roots);
    assert!(decision.is_allowed());

    // Outsider should be denied (not in group:backend)
    let decision = engine.evaluate(&outsider.id.to_urn(), "repo:main", "read", &graph, &roots);
    assert!(
        decision.is_denied(),
        "outsider should be denied: {decision}"
    );

    // Dev should be denied for unknown resource
    let decision = engine.evaluate(&dev.id.to_urn(), "repo:other", "read", &graph, &roots);
    assert!(decision.is_denied());

    // Dev should be denied for unknown action
    let decision = engine.evaluate(&dev.id.to_urn(), "repo:main", "delete", &graph, &roots);
    assert!(decision.is_denied());
}

// ============================================================
// Integration Test 3: Token CBOR roundtrip through store
// ============================================================
#[test]
fn test_token_store_roundtrip() {
    use dds_store::MemoryBackend;

    let ident = Identity::generate("store-test", &mut OsRng);
    let token = attest(&ident);

    // Verify the token is valid before storing
    assert!(token.validate().is_ok());

    // Store and retrieve
    let mut store = MemoryBackend::new();
    store.put_token(&token).unwrap();

    let retrieved = store.get_token(&token.payload.jti).unwrap();

    // Verify the retrieved token is still valid
    assert!(retrieved.validate().is_ok());
    assert_eq!(retrieved.payload.jti, token.payload.jti);
    assert_eq!(retrieved.payload.iss, token.payload.iss);
    assert_eq!(retrieved.payload.kind, token.payload.kind);
    assert_eq!(
        retrieved.payload.iss_key.scheme,
        token.payload.iss_key.scheme
    );
    assert_eq!(retrieved.payload.iss_key.bytes, token.payload.iss_key.bytes);
}

// ============================================================
// Integration Test 4: Two-node sync via apply_sync_payloads
// ============================================================
#[test]
fn test_two_node_sync() {
    use dds_net::sync::{SyncPayload, apply_sync_payloads, build_summary, compute_missing_ops};
    use dds_store::MemoryBackend;

    let alice = Identity::generate("alice", &mut OsRng);
    let bob = Identity::generate("bob", &mut OsRng);

    // Node A has ops a1, a2
    let mut dag_a = CausalDag::new();
    let mut store_a = MemoryBackend::new();
    let op_a1 = Operation {
        id: "a1".into(),
        author: "alice".into(),
        deps: vec![],
        data: vec![1],
        timestamp: 1,
    };
    let op_a2 = Operation {
        id: "a2".into(),
        author: "alice".into(),
        deps: vec!["a1".into()],
        data: vec![2],
        timestamp: 2,
    };
    dag_a.insert(op_a1.clone()).unwrap();
    dag_a.insert(op_a2.clone()).unwrap();

    let tok_a = attest(&alice);
    store_a.put_token(&tok_a).unwrap();

    // Node B has ops b1
    let mut dag_b = CausalDag::new();
    let mut store_b = MemoryBackend::new();
    let op_b1 = Operation {
        id: "b1".into(),
        author: "bob".into(),
        deps: vec![],
        data: vec![3],
        timestamp: 1,
    };
    dag_b.insert(op_b1.clone()).unwrap();

    let tok_b = attest(&bob);
    store_b.put_token(&tok_b).unwrap();

    // Exchange summaries
    let summary_a = build_summary(&dag_a, &store_a).unwrap();
    let summary_b = build_summary(&dag_b, &store_b).unwrap();
    assert_ne!(summary_a, summary_b);

    // Compute what B is missing from A
    let a_ids: BTreeSet<String> = dag_a.heads().iter().cloned().chain(["a1".into()]).collect();
    let b_ids: BTreeSet<String> = dag_b.heads().iter().cloned().collect();
    let b_missing = compute_missing_ops(&b_ids, &a_ids);
    assert!(b_missing.contains(&"a1".to_string()));
    assert!(b_missing.contains(&"a2".to_string()));

    // Serialize ops from A for B
    fn serialize_op(op: &Operation) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(op, &mut buf).unwrap();
        buf
    }

    let payloads: Vec<SyncPayload> = vec![
        SyncPayload {
            op_bytes: serialize_op(&op_a1),
            token_bytes: tok_a.to_cbor().unwrap(),
        },
        SyncPayload {
            op_bytes: serialize_op(&op_a2),
            token_bytes: tok_a.to_cbor().unwrap(),
        },
    ];

    // Apply on B
    let result = apply_sync_payloads(&payloads, &mut dag_b, &mut store_b);
    assert_eq!(result.ops_merged, 2);
    assert!(result.errors.is_empty(), "sync errors: {:?}", result.errors);

    // B now has all 3 ops
    assert!(dag_b.contains("a1"));
    assert!(dag_b.contains("a2"));
    assert!(dag_b.contains("b1"));
    assert_eq!(dag_b.len(), 3);
}

// ============================================================
// Integration Test 5: Hybrid crypto identity end-to-end
// ============================================================
#[cfg(feature = "pq")]
#[test]
fn test_hybrid_identity_full_lifecycle() {
    let root = Identity::generate_hybrid("pq-root", &mut OsRng);
    let user = Identity::generate("classical-user", &mut OsRng);

    // Root attestation with hybrid key
    let root_attest = Token::create(
        TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "attest-pq-root".into(),
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
        |msg| root.sign(msg),
    )
    .unwrap();

    // Verify hybrid token
    assert!(root_attest.validate().is_ok());
    assert_eq!(
        root_attest.payload.iss_key.scheme,
        SchemeId::HybridEdMldsa65
    );

    // User attestation with classical key
    let user_attest = attest(&user);
    assert!(user_attest.validate().is_ok());
    assert_eq!(user_attest.payload.iss_key.scheme, SchemeId::Ed25519);

    // Hybrid root vouches for classical user
    let vouch_token = Token::create(
        TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "vouch-pq-root-for-user".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some("group:trusted".into()),
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(user_attest.payload_hash()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        },
        |msg| root.sign(msg),
    )
    .unwrap();
    assert!(vouch_token.validate().is_ok());

    // Build trust graph and verify chain
    let mut graph = TrustGraph::new();
    let mut roots = BTreeSet::new();
    roots.insert(root.id.to_urn());

    graph.add_token(root_attest).unwrap();
    graph.add_token(user_attest).unwrap();
    graph.add_token(vouch_token).unwrap();

    assert!(graph.validate_chain(&user.id.to_urn(), &roots).is_ok());
    assert!(graph.has_purpose(&user.id.to_urn(), "group:trusted", &roots));
}
