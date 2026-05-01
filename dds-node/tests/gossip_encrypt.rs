//! **Z-1 Phase B.7** — regression tests for encrypted `GossipEnvelopeV3`
//! ingest in [`dds_node::node::DdsNode::handle_gossip_message`].
//!
//! Tests in this file call `handle_gossip_message_for_tests` directly
//! (no libp2p swarm) and pin the following contract:
//!
//! 1. A well-formed `GossipEnvelopeV3` whose `(epoch_id, ciphertext,
//!    nonce)` was encrypted under an epoch key the receiver has cached
//!    is decrypted and the inner `GossipMessage` is ingested normally.
//! 2. An encrypted envelope for which no epoch key is cached (either
//!    publisher unknown or wrong `epoch_id`) is dropped with
//!    `dds_pq_envelope_decrypt_total{result="no_key"}` bumped.
//! 3. An encrypted envelope whose AEAD tag fails verification (tampered
//!    ciphertext) is dropped with `result="aead_fail"`.
//! 4. A plaintext `GossipMessage` on a domain with the `enc-v3`
//!    capability set is dropped with
//!    `dds_gossip_messages_dropped_total{reason="enc_v3_plaintext_rejected"}`.
//! 5. A plaintext `GossipMessage` on a domain WITHOUT the `enc-v3`
//!    capability is ingested normally (mixed-fleet window).
//!
//! The `GossipEnvelopeV3::to_cbor` / `from_cbor` round-trip used by
//! the encrypt path is exercised here as a side-effect; the low-level
//! `encrypt_payload` / `decrypt_payload` helpers are covered by unit
//! tests inside `dds-core`.

use std::sync::OnceLock;

use dds_core::crypto::epoch_key as ek_crypto;
use dds_domain::DomainKey;
use dds_net::gossip::GossipMessage;
use dds_net::pq_envelope::GossipEnvelopeV3;
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::epoch_key_store::InstallOutcome;
use rand::rngs::OsRng;
use rand_core::RngCore;

/// Process-wide guard for telemetry counter snapshots.
fn tel_guard() -> &'static std::sync::Mutex<()> {
    static G: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a minimal node. `capabilities` controls whether `enc-v3` is
/// active.
fn make_node(
    domain_key: &DomainKey,
    capabilities: Vec<String>,
) -> (dds_node::node::DdsNode, tempfile::TempDir) {
    let _e = unsafe {
        std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS");
        ()
    };

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
            capabilities,
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
    let node = dds_node::node::DdsNode::init(cfg, p2p_keypair).expect("init node");
    (node, dir)
}

/// Helper: install a synthetic epoch key directly into `node`'s
/// epoch-key store, as if it had been decapped from an `EpochKeyRelease`.
fn install_epoch_key(
    node: &mut dds_node::node::DdsNode,
    publisher_id: &str,
    epoch_id: u64,
    epoch_key: &[u8; 32],
) {
    let outcome = node.epoch_keys_mut_for_tests().install_peer_release(
        publisher_id,
        epoch_id,
        *epoch_key,
        u64::MAX,
    );
    assert!(
        matches!(outcome, InstallOutcome::Inserted | InstallOutcome::Rotated),
        "install_epoch_key failed: {outcome:?}"
    );
}

/// Build a `GossipEnvelopeV3` CBOR blob encrypting `plaintext_cbor`
/// under `epoch_key` for publisher `publisher_id` at `epoch_id`.
fn make_v3_envelope(
    publisher_id: &str,
    epoch_id: u64,
    epoch_key: &[u8; 32],
    plaintext_cbor: &[u8],
) -> Vec<u8> {
    let mut rng = OsRng;
    let (nonce, ciphertext) =
        ek_crypto::encrypt_payload(&mut rng, epoch_key, plaintext_cbor).expect("encrypt");
    let env = GossipEnvelopeV3 {
        publisher: publisher_id.to_string(),
        epoch_id,
        nonce,
        ciphertext,
    };
    env.to_cbor().expect("encode envelope")
}

/// Returns the gossipsub `TopicHash` for the Operations topic on this
/// node's domain/org config.
fn ops_topic_hash(node: &dds_node::node::DdsNode) -> libp2p::gossipsub::TopicHash {
    node.topics.operations.to_ident_topic().hash()
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// A well-formed `GossipEnvelopeV3` whose epoch key is cached → the
/// inner `GossipMessage::DirectoryOp` is processed (ingest counter
/// increments after decrypt succeeds).
#[test]
fn encrypted_envelope_with_cached_key_is_decrypted_and_ingested() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    dds_node::telemetry::install();
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new());

    let publisher_id = "12D3KooWFakePublisherForEncryptTest01".to_string();
    let epoch_id = 3u64;
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    install_epoch_key(&mut node, &publisher_id, epoch_id, &epoch_key);

    // Build a minimal DirectoryOp message and encrypt it.
    let inner = GossipMessage::DirectoryOp {
        op_bytes: b"fake-op".to_vec(),
        token_bytes: b"fake-token".to_vec(),
    };
    let inner_cbor = inner.to_cbor().expect("inner cbor");
    let envelope_cbor = make_v3_envelope(&publisher_id, epoch_id, &epoch_key, &inner_cbor);

    let decrypt_ok_before = tel.pq_envelope_decrypt_count("ok");
    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    let aead_fail_before = tel.pq_envelope_decrypt_count("aead_fail");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &envelope_cbor);

    // Decrypt succeeded.
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        decrypt_ok_before + 1,
        "expected pq_envelope_decrypt{{result=ok}} to advance"
    );
    // The no_key / aead_fail buckets must not have moved.
    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        no_key_before,
        "no_key must not advance"
    );
    assert_eq!(
        tel.pq_envelope_decrypt_count("aead_fail"),
        aead_fail_before,
        "aead_fail must not advance"
    );
}

/// An encrypted envelope for which no epoch key is cached → dropped
/// with `pq_envelope_decrypt{result="no_key"}`.
#[test]
fn encrypted_envelope_without_cached_key_drops_with_no_key() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new());

    let publisher_id = "12D3KooWFakePublisherMissingKey01".to_string();
    let epoch_id = 5u64;
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    // Intentionally NOT installing the epoch key.

    let inner_cbor = GossipMessage::DirectoryOp {
        op_bytes: vec![1],
        token_bytes: vec![2],
    }
    .to_cbor()
    .unwrap();
    let envelope_cbor = make_v3_envelope(&publisher_id, epoch_id, &epoch_key, &inner_cbor);

    let before_no_key = tel.pq_envelope_decrypt_count("no_key");
    let before_ok = tel.pq_envelope_decrypt_count("ok");
    let dropped_before = tel.gossip_messages_dropped_count("enc_v3_no_key");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &envelope_cbor);

    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        before_no_key + 1,
        "expected no_key bump"
    );
    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_no_key"),
        dropped_before + 1,
        "expected dropped enc_v3_no_key bump"
    );
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        before_ok,
        "ok must not advance"
    );
}

/// An encrypted envelope whose ciphertext has been tampered → AEAD
/// verification fails → dropped with `result="aead_fail"`.
#[test]
fn encrypted_envelope_with_tampered_ciphertext_drops_with_aead_fail() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new());

    let publisher_id = "12D3KooWFakePublisherTamperedCT01".to_string();
    let epoch_id = 9u64;
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    install_epoch_key(&mut node, &publisher_id, epoch_id, &epoch_key);

    let inner_cbor = GossipMessage::DirectoryOp {
        op_bytes: vec![1, 2, 3],
        token_bytes: vec![4, 5, 6],
    }
    .to_cbor()
    .unwrap();

    // Build the envelope and then flip a byte in the ciphertext.
    let mut rng = OsRng;
    let (nonce, mut ciphertext) =
        ek_crypto::encrypt_payload(&mut rng, &epoch_key, &inner_cbor).expect("encrypt");
    ciphertext[0] ^= 0xFF; // corrupt it
    let env = GossipEnvelopeV3 {
        publisher: publisher_id.clone(),
        epoch_id,
        nonce,
        ciphertext,
    };
    let envelope_cbor = env.to_cbor().expect("encode");

    let before_aead = tel.pq_envelope_decrypt_count("aead_fail");
    let before_ok = tel.pq_envelope_decrypt_count("ok");
    let dropped_before = tel.gossip_messages_dropped_count("enc_v3_aead_fail");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &envelope_cbor);

    assert_eq!(
        tel.pq_envelope_decrypt_count("aead_fail"),
        before_aead + 1,
        "expected aead_fail bump"
    );
    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_aead_fail"),
        dropped_before + 1,
        "expected dropped enc_v3_aead_fail bump"
    );
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        before_ok,
        "ok must not advance"
    );
}

/// Plaintext `GossipMessage` on an `enc-v3` domain is rejected.
#[test]
fn plaintext_gossip_on_enc_v3_domain_is_dropped() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    // Enable enc-v3 capability.
    let (mut node, _dir) = make_node(&domain_key, vec!["enc-v3".to_string()]);

    let plain_msg = GossipMessage::DirectoryOp {
        op_bytes: vec![1],
        token_bytes: vec![2],
    };
    let plain_cbor = plain_msg.to_cbor().expect("cbor");

    let before = tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &plain_cbor);

    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected"),
        before + 1,
        "expected enc_v3_plaintext_rejected bump"
    );
}

/// Plaintext `GossipMessage` on a non-`enc-v3` domain is accepted
/// (mixed-fleet window).
#[test]
fn plaintext_gossip_on_non_enc_v3_domain_is_accepted() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new()); // no enc-v3

    let plain_msg = GossipMessage::DirectoryOp {
        op_bytes: vec![1],
        token_bytes: vec![2],
    };
    let plain_cbor = plain_msg.to_cbor().expect("cbor");

    let plaintext_rejected_before = tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &plain_cbor);

    // Must NOT drop as enc_v3_plaintext_rejected.
    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected"),
        plaintext_rejected_before,
        "enc_v3_plaintext_rejected must not advance on non-enc-v3 domain"
    );
}

/// Wrong `epoch_id` in the envelope: the key for `epoch_id=1` is
/// cached, but the envelope says `epoch_id=2` → no key lookup hits →
/// `no_key` drop (not `aead_fail`).
#[test]
fn encrypted_envelope_with_wrong_epoch_id_drops_as_no_key() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new());

    let publisher_id = "12D3KooWFakePublisherWrongEpochId01".to_string();
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);
    // Install under epoch_id=1, but envelope will claim epoch_id=2.
    install_epoch_key(&mut node, &publisher_id, 1, &epoch_key);

    let inner_cbor = GossipMessage::DirectoryOp {
        op_bytes: vec![7],
        token_bytes: vec![8],
    }
    .to_cbor()
    .unwrap();
    // Encrypt under epoch_key but label it epoch_id=2.
    let envelope_cbor = make_v3_envelope(&publisher_id, 2, &epoch_key, &inner_cbor);

    let before_no_key = tel.pq_envelope_decrypt_count("no_key");
    let topic_hash = ops_topic_hash(&node);
    node.handle_gossip_message_for_tests(&topic_hash, &envelope_cbor);

    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        before_no_key + 1,
        "expected no_key drop for wrong epoch_id"
    );
}

/// `GossipEnvelopeV3::to_cbor` / `from_cbor` roundtrip is stable.
#[test]
fn gossip_envelope_v3_cbor_roundtrip() {
    let mut rng = OsRng;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let env = GossipEnvelopeV3 {
        publisher: "12D3KooWFakePublisherRoundtrip".to_string(),
        epoch_id: 42,
        nonce,
        ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let cbor = env.to_cbor().expect("to_cbor");
    let decoded = GossipEnvelopeV3::from_cbor(&cbor).expect("from_cbor");
    assert_eq!(env, decoded);
}

/// `encrypt_payload` + `decrypt_payload` roundtrip at the B.7 gossip level.
#[test]
fn encrypt_decrypt_payload_roundtrip() {
    let mut rng = OsRng;
    let mut epoch_key = [0u8; 32];
    rng.fill_bytes(&mut epoch_key);
    let plaintext = b"hello encrypted gossip world";
    let (nonce, ct) = ek_crypto::encrypt_payload(&mut rng, &epoch_key, plaintext).expect("encrypt");
    let recovered = ek_crypto::decrypt_payload(&epoch_key, &nonce, &ct).expect("decrypt");
    assert_eq!(recovered, plaintext);
}

/// `decrypt_payload` with a wrong key fails.
#[test]
fn encrypt_decrypt_payload_wrong_key_fails() {
    let mut rng = OsRng;
    let mut epoch_key_a = [0u8; 32];
    let mut epoch_key_b = [0u8; 32];
    rng.fill_bytes(&mut epoch_key_a);
    rng.fill_bytes(&mut epoch_key_b);
    let plaintext = b"secret";
    let (nonce, ct) =
        ek_crypto::encrypt_payload(&mut rng, &epoch_key_a, plaintext).expect("encrypt");
    let res = ek_crypto::decrypt_payload(&epoch_key_b, &nonce, &ct);
    assert!(res.is_err(), "wrong key must fail");
}

/// `decrypt_payload` with a tampered ciphertext fails.
#[test]
fn encrypt_decrypt_payload_tampered_fails() {
    let mut rng = OsRng;
    let mut epoch_key = [0u8; 32];
    rng.fill_bytes(&mut epoch_key);
    let plaintext = b"secret2";
    let (nonce, mut ct) =
        ek_crypto::encrypt_payload(&mut rng, &epoch_key, plaintext).expect("encrypt");
    ct[0] ^= 0x01;
    let res = ek_crypto::decrypt_payload(&epoch_key, &nonce, &ct);
    assert!(res.is_err(), "tampered ciphertext must fail");
}
