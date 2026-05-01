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
            metrics_addr: None,
        },
        org_hash: "org.test".to_string(),
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

/// observability-plan.md Phase A — `admission.cert.revoked` audit
/// emission on the piggy-backed merge path. Closes the deferred
/// catalog row at `audit-event-schema.md` §3 and the matching row in
/// `observability-plan.md` Phase A.1.
///
/// Drives `merge_piggybacked_revocations` with two new revocations
/// plus one duplicate: the audit chain must gain exactly two
/// `admission.cert.revoked` entries (one per *newly* admitted
/// revocation; duplicates and verify-failures must not stamp the
/// chain).
#[test]
fn piggybacked_admission_revocation_emits_audit_entry_per_new_entry() {
    use dds_core::identity::Identity;
    use dds_store::traits::AuditStore;
    use rand::rngs::OsRng;

    let (_dir, mut cfg, kp, _peer) = build_node_dir([5u8; 32]);
    cfg.domain.audit_log_enabled = true;
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.revocation", [5u8; 32]);
    let domain = dkey.domain();

    let mut node = DdsNode::init(cfg, kp).expect("init clean node");
    // A node identity is required for the gossip-ingest audit-emit
    // funnel — without it the helper returns early (matches the
    // `revoke` / `burn` ingest contract).
    node.set_node_identity(Identity::generate("test.revocation", &mut OsRng));

    // Seed the store with one already-known revocation so we can prove
    // duplicates do *not* re-emit.
    let known = dkey.revoke_admission("12D3KooWAlreadyKnown".into(), 100, Some("known".into()));
    let known_blob = known.to_cbor().unwrap();

    let new_a = dkey.revoke_admission("12D3KooWNewAlpha".into(), 200, Some("alpha".into()));
    let new_b = dkey.revoke_admission("12D3KooWNewBeta".into(), 300, Some("beta".into()));

    // Pre-load the "already known" entry by driving the piggyback
    // funnel once — afterwards the chain should hold exactly one
    // `admission.cert.revoked` entry.
    let fake_peer = libp2p::PeerId::random();
    node.merge_piggybacked_revocations(&fake_peer, vec![known_blob.clone()]);
    let after_first = node.store.list_audit_entries().expect("list entries");
    let revoked_after_first = after_first
        .iter()
        .filter(|e| e.action == "admission.cert.revoked")
        .count();
    assert_eq!(
        revoked_after_first, 1,
        "first merge should stamp exactly one admission.cert.revoked entry"
    );

    // Now feed the same `known` blob alongside two genuinely new ones.
    // Only the two new revocations should stamp the audit chain; the
    // duplicate is a silent no-op per `AdmissionRevocationStore::add`'s
    // dedupe contract.
    node.merge_piggybacked_revocations(
        &fake_peer,
        vec![
            known_blob,
            new_a.to_cbor().unwrap(),
            new_b.to_cbor().unwrap(),
        ],
    );
    let after_second = node.store.list_audit_entries().expect("list entries");
    let revoked_after_second = after_second
        .iter()
        .filter(|e| e.action == "admission.cert.revoked")
        .count();
    assert_eq!(
        revoked_after_second, 3,
        "second merge should add exactly two new admission.cert.revoked entries (one per new revocation)"
    );

    // The new chain entries' token bytes must round-trip back to the
    // exact CBOR blobs we admitted — this pins the audit-event-schema
    // §2 `token_cbor_b64` contract for this action.
    let new_a_blob = new_a.to_cbor().unwrap();
    let new_b_blob = new_b.to_cbor().unwrap();
    let entries: Vec<_> = after_second
        .iter()
        .filter(|e| e.action == "admission.cert.revoked")
        .collect();
    let blobs: Vec<&Vec<u8>> = entries.iter().map(|e| &e.token_bytes).collect();
    assert!(
        blobs.contains(&&new_a_blob),
        "audit chain missing new_a CBOR blob"
    );
    assert!(
        blobs.contains(&&new_b_blob),
        "audit chain missing new_b CBOR blob"
    );

    // Sanity: the in-memory revocation store contains all three entries
    // (one pre-loaded plus two new) and the new peer ids resolve as
    // revoked.
    assert_eq!(node.admission_revocations().len(), 3);
    assert!(node.admission_revocations().is_revoked("12D3KooWNewAlpha"));
    assert!(node.admission_revocations().is_revoked("12D3KooWNewBeta"));

    // And the saved file matches in-memory so a restart picks up the
    // same set.
    let on_disk =
        admission_revocation_store::load_or_empty(&cfg_path_for(&node), domain.id, domain.pubkey)
            .expect("load_or_empty");
    assert_eq!(on_disk.len(), 3);
}

/// Helper — DdsNode does not expose its data dir directly, so we
/// recompute the revocations path the same way `init` does. This is
/// a test-only helper kept private to this module.
fn cfg_path_for(node: &DdsNode) -> std::path::PathBuf {
    // The data dir survives on `node.config.data_dir`; the
    // revocations path mirrors `NodeConfig::admission_revocations_path`
    // (one shared helper used by both the node and the import CLI).
    node.config.admission_revocations_path()
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
