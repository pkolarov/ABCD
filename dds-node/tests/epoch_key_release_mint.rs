//! **Z-1 Phase B.7** — regression tests for the publisher-side
//! `EpochKeyRelease` mint helper and the `build_epoch_key_response`
//! responder pipeline.
//!
//! These exercise the publisher half of §4.5.1 (late-join recovery):
//!
//! 1. [`mint_epoch_key_release_for_recipient`] returns a release whose
//!    `(kem_ct, aead_ciphertext)` pair decaps + unwraps to the
//!    publisher's epoch key when handed to a recipient holding the
//!    matching hybrid KEM secret.
//! 2. The canonical [`epoch_key_binding`] is what allows the publisher
//!    and the recipient to derive the same KEM shared secret without
//!    any out-of-band negotiation.
//! 3. [`DdsNode::build_epoch_key_response`] (driven via the Phase B.5
//!    request-response handler) returns a non-empty release for a
//!    request that asks for the responder's own peer id, and an empty
//!    response for any other publisher.
//! 4. A request from a peer whose `AdmissionCert` is not cached in
//!    `peer_certs` (or whose cached cert lacks `pq_kem_pubkey`) gets
//!    an empty response — the responder cannot mint to a recipient
//!    whose KEM pubkey is unknown.
//! 5. Round-trip: a release minted on node A and installed on node B
//!    survives the schema + replay-window + decap + unwrap pipeline
//!    end-to-end, matching the receive-side contract pinned by
//!    `epoch_key_release_ingest.rs`.
//!
//! Like the ingest tests, these do **not** spin up a libp2p swarm —
//! they call the public mint helper and the `build_epoch_key_response`
//! funnel directly so the contract is pinned without depending on a
//! request-response round-trip. The full libp2p path lands when the
//! B.9 rotation timer wires the publisher-side request emission.

use std::sync::OnceLock;

use dds_core::crypto::kem;
use dds_domain::{AdmissionCert, DomainKey};
use dds_net::pq_envelope::{
    EPOCH_KEY_RELEASE_AEAD_CT_LEN, EPOCH_KEY_RELEASE_ED25519_SIG_LEN, EPOCH_KEY_RELEASE_KEM_CT_LEN,
    EpochKeyRelease, EpochKeyRequest,
};
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::epoch_key_store::InstallOutcome;
use dds_node::node::{DdsNode, mint_epoch_key_release_for_recipient};
use rand::rngs::OsRng;

/// Process-wide guard for env-var mutations across tests sharing the
/// same binary.
fn env_guard() -> &'static std::sync::Mutex<()> {
    static GUARD: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a node belonging to `domain_key`. Mirrors the helper in
/// `epoch_key_release_ingest.rs` — fresh libp2p keypair, fresh
/// admission cert valid for ~24h, fresh data dir.
fn spawn_node(domain_key: &DomainKey) -> (DdsNode, tempfile::TempDir) {
    let _guard = env_guard().lock().unwrap_or_else(|e| e.into_inner());
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
        },
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };
    let node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    (node, dir)
}

/// Build a hybrid v3 admission cert for `peer_id` carrying the given
/// hybrid KEM pubkey. Used to populate `peer_certs` on the responder
/// side so `build_epoch_key_response` has a recipient pubkey to encap
/// to.
fn issue_hybrid_cert_with_kem(peer_id: &str, kem_pk_bytes: Vec<u8>) -> AdmissionCert {
    let key = DomainKey::generate_hybrid("test-publisher.example", &mut OsRng);
    key.issue_admission_with_kem(peer_id.into(), 0, None, Some(kem_pk_bytes))
}

#[test]
fn mint_helper_produces_release_decryptable_by_recipient() {
    // The publisher mints a release and the recipient installs it
    // via the receive-side ingest funnel. Round-trip pins that the
    // canonical `epoch_key_binding` matches on both ends and the
    // decap+unwrap pipeline recovers the original epoch key.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut recipient_node, _dir) = spawn_node(&domain_key);
    let recipient_id = recipient_node.peer_id.to_string();
    let recipient_kem_pk = recipient_node.epoch_keys_for_tests().kem_public().clone();

    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let release = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &publisher_id,
        17,
        &epoch_key,
        &recipient_id,
        &recipient_kem_pk,
        now,
        now + 86_400,
    )
    .expect("mint ok");

    // Schema invariants the receiver enforces.
    assert_eq!(release.kem_ct.len(), EPOCH_KEY_RELEASE_KEM_CT_LEN);
    assert_eq!(release.aead_ciphertext.len(), EPOCH_KEY_RELEASE_AEAD_CT_LEN);
    assert_eq!(release.signature.len(), EPOCH_KEY_RELEASE_ED25519_SIG_LEN);
    assert_eq!(release.publisher, publisher_id);
    assert_eq!(release.recipient, recipient_id);
    assert_eq!(release.epoch_id, 17);
    assert!(release.pq_signature.is_none());

    let outcome = recipient_node
        .install_epoch_key_release(&release, &recipient_id, now)
        .expect("install ok");
    assert!(matches!(
        outcome,
        InstallOutcome::Inserted | InstallOutcome::Rotated
    ));

    let cached = recipient_node
        .epoch_keys_for_tests()
        .peer_epoch_key(&publisher_id, 17)
        .copied()
        .expect("release cached");
    assert_eq!(cached, epoch_key);
}

#[test]
fn mint_helper_rejects_invalid_inputs() {
    let recipient_kem_pk = {
        let (_sk, pk) = kem::generate(&mut OsRng);
        pk
    };
    let now = 1_700_000_000u64;
    let epoch_key = [7u8; 32];

    // Empty publisher.
    let err = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        "",
        1,
        &epoch_key,
        "12D3KooWRecipient",
        &recipient_kem_pk,
        now,
        now + 60,
    )
    .unwrap_err();
    assert_eq!(err, "empty_publisher");

    // Empty recipient.
    let err = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        "12D3KooWPub",
        1,
        &epoch_key,
        "",
        &recipient_kem_pk,
        now,
        now + 60,
    )
    .unwrap_err();
    assert_eq!(err, "empty_recipient");

    // expires_at <= issued_at.
    let err = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        "12D3KooWPub",
        1,
        &epoch_key,
        "12D3KooWRecipient",
        &recipient_kem_pk,
        now,
        now,
    )
    .unwrap_err();
    assert_eq!(err, "invalid_expiry");
}

#[test]
fn mint_two_releases_for_different_recipients_decap_independently() {
    // Pins the §4.3 component-binding defence at the mint layer:
    // each release is bound to its (publisher, recipient, epoch_id)
    // tuple, so a release minted for recipient R1 cannot be lifted
    // into recipient R2's slot.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node1, _dir1) = spawn_node(&domain_key);
    let (mut node2, _dir2) = spawn_node(&domain_key);
    let r1_id = node1.peer_id.to_string();
    let r2_id = node2.peer_id.to_string();
    let r1_kem = node1.epoch_keys_for_tests().kem_public().clone();
    let r2_kem = node2.epoch_keys_for_tests().kem_public().clone();

    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);

    let now = 1_700_000_000u64;
    let rel_for_r1 = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &publisher_id,
        9,
        &epoch_key,
        &r1_id,
        &r1_kem,
        now,
        now + 86_400,
    )
    .unwrap();
    let rel_for_r2 = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &publisher_id,
        9,
        &epoch_key,
        &r2_id,
        &r2_kem,
        now,
        now + 86_400,
    )
    .unwrap();

    // Each recipient decaps its own release.
    node1
        .install_epoch_key_release(&rel_for_r1, &r1_id, now)
        .expect("r1 install");
    node2
        .install_epoch_key_release(&rel_for_r2, &r2_id, now)
        .expect("r2 install");

    // Cross-installing a release minted for a different recipient
    // fails at recipient_mismatch (the schema gate runs first), or
    // would fail at decap if recipient is forced.
    let err = node1
        .install_epoch_key_release(&rel_for_r2, &r1_id, now)
        .unwrap_err();
    assert_eq!(err, "recipient_mismatch");

    // Even with a forged recipient label, the KEM ct was
    // encapsulated to r2_kem, so node1's KEM secret cannot decap.
    let mut forged = rel_for_r2.clone();
    forged.recipient = r1_id.clone();
    let err = node1
        .install_epoch_key_release(&forged, &r1_id, now)
        .unwrap_err();
    // Either decap fails (the X25519 leg matches the wrong
    // recipient key) or the AEAD unwrap fails — both prove the
    // component binding holds.
    assert!(matches!(err, "decap" | "aead"), "got {err:?}");
}

/// Drive the responder's `EpochKeyRequest` handler end-to-end via the
/// public test hook on `DdsNode`. We populate `peer_certs` with the
/// requesting peer's hybrid v3 cert so the responder has a KEM pubkey
/// to encap to, then send a request asking for the responder's own
/// peer id.
#[test]
fn build_response_returns_release_for_self_when_requester_kem_known() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut publisher, _dir_p) = spawn_node(&domain_key);
    let (mut requester, _dir_r) = spawn_node(&domain_key);
    let publisher_id = publisher.peer_id;
    let requester_id = requester.peer_id;
    let publisher_id_str = publisher_id.to_string();
    let requester_id_str = requester_id.to_string();

    // Populate publisher.peer_certs with a hybrid v3 cert for the
    // requester carrying the requester's actual KEM pubkey, so the
    // KEM lookup at the call site succeeds and the encap targets the
    // right secret.
    let requester_kem_bytes = requester.epoch_keys_for_tests().kem_public().to_bytes();
    let requester_cert = issue_hybrid_cert_with_kem(&requester_id_str, requester_kem_bytes.clone());
    publisher.cache_peer_admission_cert(requester_id_str.clone(), requester_cert);

    // Request from the requester asking for the publisher's own key.
    let request = EpochKeyRequest {
        publishers: vec![publisher_id_str.clone()],
    };
    let response = publisher.build_epoch_key_response_for_tests(&request, &requester_id);
    assert_eq!(response.releases.len(), 1, "expected one minted release");

    // Decode and install the release at the requester. This proves
    // the responder used `requester`'s real KEM pubkey for encap (the
    // requester's KEM secret can decap) and that the canonical
    // binding matched on both sides.
    let release = EpochKeyRelease::from_cbor(&response.releases[0]).expect("decode release");
    assert_eq!(release.publisher, publisher_id_str);
    assert_eq!(release.recipient, requester_id_str);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let outcome = requester
        .install_epoch_key_release(&release, &requester_id_str, now)
        .expect("install at requester");
    assert!(matches!(
        outcome,
        InstallOutcome::Inserted | InstallOutcome::Rotated
    ));

    // The cached epoch key on the requester equals the publisher's
    // current epoch key on the responder.
    let (publisher_epoch_id, publisher_epoch_key) =
        publisher.epoch_keys_for_tests().my_current_epoch();
    assert_eq!(release.epoch_id, publisher_epoch_id);
    let cached = requester
        .epoch_keys_for_tests()
        .peer_epoch_key(&publisher_id_str, publisher_epoch_id)
        .copied()
        .expect("release cached at requester");
    assert_eq!(&cached, publisher_epoch_key);
}

#[test]
fn build_response_is_empty_when_request_does_not_ask_for_self() {
    // Asking for a publisher peer-id that is not the responder's own
    // gets an empty response — Phase B.7 only mints for self.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut publisher, _dir_p) = spawn_node(&domain_key);
    let (requester, _dir_r) = spawn_node(&domain_key);
    let requester_id = requester.peer_id;
    let requester_id_str = requester_id.to_string();

    // Even with a fully-populated requester cert, the responder
    // returns an empty body when none of the requested publishers
    // is the responder itself.
    let requester_kem_bytes = requester.epoch_keys_for_tests().kem_public().to_bytes();
    let requester_cert = issue_hybrid_cert_with_kem(&requester_id_str, requester_kem_bytes);
    publisher.cache_peer_admission_cert(requester_id_str.clone(), requester_cert);

    let request = EpochKeyRequest {
        publishers: vec!["12D3KooWSomeOtherPublisher".to_string()],
    };
    let response = publisher.build_epoch_key_response_for_tests(&request, &requester_id);
    assert!(
        response.releases.is_empty(),
        "expected empty response, got {}",
        response.releases.len()
    );
}

#[test]
fn build_response_is_empty_when_requester_kem_unknown() {
    // No cached cert for the requester — the responder cannot encap
    // and returns empty rather than failing the request channel.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (publisher, _dir_p) = spawn_node(&domain_key);
    let (requester, _dir_r) = spawn_node(&domain_key);
    let publisher_id_str = publisher.peer_id.to_string();
    let requester_id = requester.peer_id;

    let request = EpochKeyRequest {
        publishers: vec![publisher_id_str.clone()],
    };
    let response = publisher.build_epoch_key_response_for_tests(&request, &requester_id);
    assert!(response.releases.is_empty());
}

#[test]
fn build_response_is_empty_when_requester_cert_lacks_kem_pubkey() {
    // The requester's cached cert exists but is a v1/v2 cert without
    // `pq_kem_pubkey` — the responder skips with an empty body.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut publisher, _dir_p) = spawn_node(&domain_key);
    let (requester, _dir_r) = spawn_node(&domain_key);
    let publisher_id_str = publisher.peer_id.to_string();
    let requester_id = requester.peer_id;
    let requester_id_str = requester_id.to_string();

    // Issue a v1 (Ed25519-only) cert so `pq_kem_pubkey` is None.
    let v1_key = DomainKey::generate("test-publisher-v1", &mut OsRng);
    let v1_cert = v1_key.issue_admission(requester_id_str.clone(), 0, None);
    publisher.cache_peer_admission_cert(requester_id_str.clone(), v1_cert);

    let request = EpochKeyRequest {
        publishers: vec![publisher_id_str.clone()],
    };
    let response = publisher.build_epoch_key_response_for_tests(&request, &requester_id);
    assert!(response.releases.is_empty());
}
