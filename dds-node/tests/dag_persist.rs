//! Regression tests for operation-store persistence (§14.8.2 fix).
//!
//! Verifies that:
//! 1. `seed_dag_from_store` populates `DdsNode::dag` from previously
//!    persisted operations on startup.
//! 2. `seed_dag_from_store` is a no-op on a node with no stored operations.
//! 3. Ops with missing token entries are skipped without panic.

use dds_core::crdt::causal_dag::Operation;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_domain::DomainKey;
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_store::traits::{OperationStore, TokenStore};
use rand::rngs::OsRng;

fn make_node(domain_key: &DomainKey) -> (dds_node::node::DdsNode, tempfile::TempDir) {
    unsafe {
        std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS");
    }
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let domain = domain_key.domain();
    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();
    let cfg = NodeConfig {
        data_dir,
        network: NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            bootstrap_peers: Vec::new(),
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: "127.0.0.1:0".to_string(),
            api_auth: Default::default(),
            allow_legacy_v1_tokens: false,
            metrics_addr: None,
        },
        org_hash: "test-org".to_string(),
        domain: DomainConfig {
            name: domain.name.clone(),
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
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };
    let node = dds_node::node::DdsNode::init(cfg, p2p_keypair).expect("init node");
    (node, dir)
}

fn make_token(jti: &str) -> Token {
    let identity = Identity::generate("test", &mut OsRng);
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
            iat: 1_000_000,
            exp: Some(9_999_999_999),
            body_type: None,
            body_cbor: None,
        },
        &identity.signing_key,
    )
    .unwrap()
}

fn make_op(jti: &str) -> Operation {
    Operation {
        id: format!("op-{jti}"),
        author: "urn:dds:test".to_string(),
        deps: Vec::new(),
        data: Vec::new(),
        timestamp: 0,
    }
}

#[test]
fn seed_dag_from_store_empty_is_noop() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key);
    assert_eq!(node.dag.len(), 0);
    node.seed_dag_from_store();
    assert_eq!(node.dag.len(), 0);
}

#[test]
fn seed_dag_from_store_populates_dag() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key);

    // Seed store with two (op, token) pairs.
    let token1 = make_token("jti-1");
    let op1 = make_op("jti-1");
    let token2 = make_token("jti-2");
    let op2 = make_op("jti-2");

    node.store.put_token(&token1).unwrap();
    node.store.put_operation(&op1).unwrap();
    node.store.put_token(&token2).unwrap();
    node.store.put_operation(&op2).unwrap();

    assert_eq!(node.dag.len(), 0, "dag must start empty");

    node.seed_dag_from_store();

    assert_eq!(node.dag.len(), 2, "both ops should be seeded into dag");
}

#[test]
fn seed_dag_from_store_skips_op_without_token() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key);

    // Op with backing token.
    let token = make_token("jti-ok");
    let op_ok = make_op("jti-ok");
    node.store.put_token(&token).unwrap();
    node.store.put_operation(&op_ok).unwrap();

    // Op whose token was never stored (simulates a torn write).
    let op_orphan = make_op("jti-orphan");
    node.store.put_operation(&op_orphan).unwrap();

    node.seed_dag_from_store();

    // Only the op with a valid token enters the dag.
    assert_eq!(node.dag.len(), 1);
    assert!(node.dag.get("op-jti-ok").is_some());
    assert!(node.dag.get("op-jti-orphan").is_none());
}

#[test]
fn seed_dag_from_store_idempotent() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key);

    let token = make_token("jti-1");
    let op = make_op("jti-1");
    node.store.put_token(&token).unwrap();
    node.store.put_operation(&op).unwrap();

    node.seed_dag_from_store();
    assert_eq!(node.dag.len(), 1);

    // Second call is a no-op (dag already has the op, insert returns Ok(false)).
    node.seed_dag_from_store();
    assert_eq!(node.dag.len(), 1);
}
