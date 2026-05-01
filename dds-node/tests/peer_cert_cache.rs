//! **Z-1 Phase B.3 / §4.6.2** — regression tests for the `PeerCertStore`
//! wiring inside `DdsNode`.
//!
//! These pin three properties of the cache funnel:
//!
//! 1. `cache_peer_admission_cert` inserts a verified cert into both the
//!    in-memory cache and the on-disk `<data_dir>/peer_certs.cbor` file.
//! 2. Re-handshakes overwrite the cached entry (publisher KEM-key
//!    rotation re-issues the cert; the latest version wins).
//! 3. A successful `merge_piggybacked_revocations` against a cached
//!    peer evicts the cached cert, so a Phase B.7+ KEM-pubkey lookup
//!    cannot reuse the revoked publisher's pubkey.
//!
//! The H-12 end-to-end path (cert decode + `verify_with_domain` + then
//! cache-on-success) is covered by `h12_admission.rs`. These tests
//! exercise the cache helper directly so the cache-then-evict
//! contract is pinned without depending on a libp2p swarm spin-up.

use std::sync::OnceLock;

use dds_domain::DomainKey;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use dds_node::peer_cert_store;
use rand::rngs::OsRng;

/// Process-wide guard for the env-var dance below. Multiple tests in
/// the same binary share `std::env::set_var`, which is `unsafe` and
/// races at the process level; serializing through this mutex keeps
/// the expectation deterministic.
fn env_guard() -> &'static std::sync::Mutex<()> {
    static GUARD: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a node belonging to `domain_key`. The node has a freshly
/// generated libp2p keypair, an admission cert valid for ~24h, and an
/// empty data dir (the swarm is built but not started — these tests
/// never call `node.start()`). Returns the live `DdsNode` plus the
/// `TempDir` it owns so the caller can keep the data dir alive for
/// on-disk assertions.
fn spawn_node(domain_key: &DomainKey, org: &str) -> (DdsNode, tempfile::TempDir) {
    // `set_var` is `unsafe` and racy at the process level. Hold the
    // guard while we mutate; the guard releases when this function
    // returns and the caller takes ownership of the configured node.
    let _guard = env_guard().lock().unwrap_or_else(|e| e.into_inner());
    // The plaintext-keys gate must be off for this test — we are not
    // exercising the encrypted-keys posture here.
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
        org_hash: org.to_string(),
        domain: dds_node::config::DomainConfig {
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
    let node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    (node, dir)
}

/// Build a remote-peer admission cert keyed on a freshly-generated
/// libp2p `PeerId`. The cert verifies against `domain_key`'s domain so
/// the test can simulate a successful H-12 handshake outcome by
/// calling `cache_peer_admission_cert` directly.
fn issue_remote_cert(domain_key: &DomainKey) -> (libp2p::PeerId, dds_domain::AdmissionCert) {
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(kp.public());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    (peer_id, cert)
}

#[test]
fn cache_peer_admission_cert_persists_to_disk() {
    let domain_key = DomainKey::generate("acme.example", &mut OsRng);
    let (mut node, dir) = spawn_node(&domain_key, "test-org");
    let peer_certs_path = dir.path().join("peer_certs.cbor");

    // Empty start: cache is in-memory empty and on disk no file yet.
    assert!(node.peer_certs().is_empty());
    assert!(!peer_certs_path.exists());

    let (remote_peer, remote_cert) = issue_remote_cert(&domain_key);
    let remote_str = remote_peer.to_string();
    node.cache_peer_admission_cert(remote_str.clone(), remote_cert.clone());

    // In-memory entry visible.
    assert_eq!(node.peer_certs().len(), 1);
    let cached = node
        .peer_certs()
        .get(&remote_str)
        .expect("entry present in cache");
    assert_eq!(cached.signature, remote_cert.signature);

    // On-disk file written and readable through the public load path.
    let on_disk = peer_cert_store::load_or_empty(&peer_certs_path).expect("load round-trip");
    let on_disk_cert = on_disk.get(&remote_str).expect("entry round-tripped");
    assert_eq!(on_disk_cert.signature, remote_cert.signature);
}

#[test]
fn re_handshake_overwrites_cached_entry() {
    let domain_key = DomainKey::generate("acme.example", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key, "test-org");

    // First handshake.
    let (remote_peer, cert_v1) = issue_remote_cert(&domain_key);
    node.cache_peer_admission_cert(remote_peer.to_string(), cert_v1.clone());

    // Second handshake against the *same* peer id but with a freshly
    // issued cert (mirrors a Phase B.7 publisher rotating its KEM
    // keypair and re-issuing its cert). We can't keep the same peer id
    // through `issue_remote_cert` because that helper generates a
    // fresh keypair each call — instead, hand-craft a second cert for
    // the same peer id by re-issuing through the same `domain_key`.
    // Re-issue with a bumped `issued_at` so the body — and therefore
    // the deterministic Ed25519 signature — differs from cert_v1.
    // (Two issuances at the same `now` would produce byte-identical
    // certs because the issuing key signs `body.to_signing_bytes()`
    // and Ed25519 is deterministic.)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert_v2 = domain_key.issue_admission(remote_peer.to_string(), now + 1, None);
    assert_ne!(
        cert_v1.signature, cert_v2.signature,
        "bumped issued_at must yield a distinct signature"
    );
    node.cache_peer_admission_cert(remote_peer.to_string(), cert_v2.clone());

    // Cache shows v2 only — overwrite, not append.
    assert_eq!(node.peer_certs().len(), 1);
    let cached = node.peer_certs().get(&remote_peer.to_string()).unwrap();
    assert_eq!(cached.signature, cert_v2.signature);
}

#[test]
fn revocation_evicts_cached_cert() {
    let domain_key = DomainKey::generate("acme.example", &mut OsRng);
    let (mut node, dir) = spawn_node(&domain_key, "test-org");
    let peer_certs_path = dir.path().join("peer_certs.cbor");

    // Cache a cert for peer R (the soon-to-be-revoked publisher).
    let (revoked_peer, revoked_cert) = issue_remote_cert(&domain_key);
    node.cache_peer_admission_cert(revoked_peer.to_string(), revoked_cert.clone());
    assert!(node.peer_certs().get(&revoked_peer.to_string()).is_some());

    // Sender is a different admitted peer (the one that piggy-backed
    // the revocation in its `AdmissionResponse`). The piggy-back path
    // doesn't care that the sender is unrelated to the revoked peer.
    let sender_peer = libp2p::PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());

    // Domain-signed revocation against `revoked_peer`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let revocation =
        domain_key.revoke_admission(revoked_peer.to_string(), now, Some("rotated".into()));
    let mut blob = Vec::new();
    ciborium::into_writer(&revocation, &mut blob).unwrap();

    // Drive the merge funnel directly.
    node.merge_piggybacked_revocations(&sender_peer, vec![blob]);

    // In-memory eviction.
    assert!(
        node.peer_certs().get(&revoked_peer.to_string()).is_none(),
        "cached cert for revoked peer must be dropped"
    );
    // On-disk file mirrors the eviction (the helper persists after
    // each successful eviction). Tolerant of the post-eviction file
    // being absent (fresh run with no other peers cached) or present
    // and empty.
    let on_disk = peer_cert_store::load_or_empty(&peer_certs_path).expect("load");
    assert!(
        on_disk.get(&revoked_peer.to_string()).is_none(),
        "on-disk cache must not retain the revoked peer's cert"
    );
}
