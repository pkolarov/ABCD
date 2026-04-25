//! Integration tests for the admission revocation list
//! (threat-model §1, open item #4).
//!
//! Single-node scenarios — full peer-side enforcement is exercised
//! indirectly by the unit tests in `admission_revocation_store` and
//! by every existing multinode test (which doesn't add a revocation
//! and therefore proves the no-op path stays green). The startup
//! self-check is the load-bearing piece here: if it lands, a revoked
//! node cannot rejoin even if it still holds a valid admission cert.

use dds_node::admission_revocation_store::{self, AdmissionRevocationStore};
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use tempfile::TempDir;

fn build_node_dir(secret: [u8; 32]) -> (TempDir, NodeConfig, libp2p::identity::Keypair, String) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();

    let dkey = dds_domain::DomainKey::from_secret_bytes("test.revocation", secret);
    let domain = dkey.domain();

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());

    // Seed the persistent libp2p key file so DdsNode::init reuses the
    // same peer id we just generated.
    dds_node::p2p_identity::save(&data_dir.join("p2p_key.bin"), &p2p_keypair).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert = dkey.issue_admission(peer_id.to_string(), now, None);
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
        },
        org_hash: "org.test".to_string(),
        domain: DomainConfig {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            admission_path: None,
            audit_log_enabled: false,
            max_delegation_depth: 5,
            audit_log_max_entries: 0,
            audit_log_retention_days: 0,
            enforce_device_scope_vouch: false,
            allow_unattested_credentials: false,
        },
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };

    (dir, cfg, p2p_keypair, peer_id.to_string())
}

#[test]
fn node_starts_when_revocations_file_is_absent() {
    let (_dir, cfg, kp, _peer) = build_node_dir([1u8; 32]);
    let node = DdsNode::init(cfg, kp).expect("init should succeed without a revocation file");
    assert!(node.admission_revocations().is_empty());
}

#[test]
fn node_starts_when_revocation_targets_a_different_peer() {
    let (_dir, cfg, kp, _peer) = build_node_dir([2u8; 32]);
    // Drop a revocation for a fictional peer id in the data dir.
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.revocation", [2u8; 32]);
    let stranger = "12D3KooWStrangerThatIsntUs".to_string();
    let rev = dkey.revoke_admission(stranger.clone(), 0, Some("not us".into()));
    let mut store = AdmissionRevocationStore::for_domain(dkey.domain().id, dkey.domain().pubkey);
    store.add(rev).unwrap();
    let path = cfg.admission_revocations_path();
    admission_revocation_store::save(&path, &store).unwrap();

    let node = DdsNode::init(cfg, kp).expect("init should succeed when only a stranger is revoked");
    assert_eq!(node.admission_revocations().len(), 1);
    assert!(node.admission_revocations().is_revoked(&stranger));
}

#[test]
fn node_refuses_to_start_when_its_own_peer_id_is_revoked() {
    let (_dir, cfg, kp, peer) = build_node_dir([3u8; 32]);
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.revocation", [3u8; 32]);
    let rev = dkey.revoke_admission(peer.clone(), 0, Some("compromise drill".into()));
    let mut store = AdmissionRevocationStore::for_domain(dkey.domain().id, dkey.domain().pubkey);
    store.add(rev).unwrap();
    let path = cfg.admission_revocations_path();
    admission_revocation_store::save(&path, &store).unwrap();

    let result = DdsNode::init(cfg, kp);
    let err = match result {
        Ok(_) => panic!("init must fail for a revoked peer id"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("revoked") && msg.contains(&peer),
        "unexpected error: {msg}"
    );
}

#[test]
fn node_refuses_to_start_when_revocation_file_is_corrupt() {
    let (_dir, cfg, kp, _peer) = build_node_dir([4u8; 32]);
    // Write garbage at the revocation list path. `load_or_empty`
    // should propagate the parse error rather than silently treating
    // the file as empty (which would defeat tamper detection).
    let path = cfg.admission_revocations_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not a cbor map at all").unwrap();
    let result = DdsNode::init(cfg, kp);
    let err = match result {
        Ok(_) => panic!("init must fail for a malformed revocation file"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("admission revocation list"),
        "unexpected error: {msg}"
    );
}
