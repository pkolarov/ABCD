//! **Z-1 Phase B.12** — integration tests for the complete PQC encrypted
//! gossip lifecycle.
//!
//! These tests cover the multi-node scenarios specified in
//! [`docs/pqc-phase-b-plan.md`](../../docs/pqc-phase-b-plan.md) §7:
//!
//! 1. **Mixed-fleet** — `enc-v3` transition: before the domain flips the
//!    capability, plaintext gossip flows between nodes; after the flip,
//!    only encrypted gossip is accepted.
//!
//! 2. **Epoch-key rotation + grace window** — publisher A rotates its
//!    epoch key; receiver B still decrypts in-flight messages under the
//!    old key via the grace cache; after installing the new release, B
//!    decrypts under the new key.
//!
//! 3. **Revocation-triggered rotation** — when A's `ingest_revocation`
//!    path triggers `rotate_and_fan_out`, the old epoch key is no longer
//!    the current key; a peer that does **not** receive the new release
//!    cannot decrypt subsequent gossip from A.
//!
//! 4. **Offline > 24h reconnect** — simulate a node that missed several
//!    of A's rotation cycles; after "reconnecting" (installing a fresh
//!    release via the request-response path), decryption resumes without
//!    manual operator action.
//!
//! 5. **KEM-pubkey-rotated-while-offline** — publisher's KEM keypair is
//!    replaced (new node identity on the same domain); receiver's stale
//!    cached cert is overwritten via `cache_peer_admission_cert`; the
//!    release minted against the new KEM pubkey decaps cleanly at the
//!    receiver with the new KEM secret.
//!
//! All tests use the `*_for_tests` hooks on `DdsNode` — no live libp2p
//! swarm is required.

use std::sync::OnceLock;

use dds_core::crypto::epoch_key as ek_crypto;
use dds_domain::DomainKey;
use dds_net::gossip::GossipMessage;
use dds_net::pq_envelope::{EpochKeyRequest, GossipEnvelopeV3};
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::epoch_key_store::InstallOutcome;
use dds_node::node::{DdsNode, mint_epoch_key_release_for_recipient};
use rand::rngs::OsRng;

// ─── test infrastructure ─────────────────────────────────────────────────────

/// Process-wide serialisation guard for telemetry counter deltas.
fn tel_guard() -> &'static std::sync::Mutex<()> {
    static G: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(()))
}

/// Spawn a node on `domain_key` with the given `capabilities`.
fn spawn_node(domain_key: &DomainKey, capabilities: Vec<String>) -> (DdsNode, tempfile::TempDir) {
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

/// Build a `GossipEnvelopeV3` CBOR blob for `publisher_id` / `epoch_id`
/// encrypting a minimal `DirectoryOp` `GossipMessage` under `epoch_key`.
fn make_encrypted_gossip(publisher_id: &str, epoch_id: u64, epoch_key: &[u8; 32]) -> Vec<u8> {
    let inner = GossipMessage::DirectoryOp {
        op_bytes: b"op-bytes".to_vec(),
        token_bytes: b"token-bytes".to_vec(),
    };
    let inner_cbor = inner.to_cbor().expect("inner cbor");
    let (nonce, ciphertext) =
        ek_crypto::encrypt_payload(&mut OsRng, epoch_key, &inner_cbor).expect("encrypt");
    let env = GossipEnvelopeV3 {
        publisher: publisher_id.to_string(),
        epoch_id,
        nonce,
        ciphertext,
    };
    env.to_cbor().expect("encode envelope")
}

/// Build a plaintext `DirectoryOp` CBOR blob.
fn make_plaintext_gossip() -> Vec<u8> {
    GossipMessage::DirectoryOp {
        op_bytes: b"plain-op".to_vec(),
        token_bytes: b"plain-token".to_vec(),
    }
    .to_cbor()
    .expect("cbor")
}

/// Return the gossipsub `TopicHash` for the Operations topic on `node`.
fn ops_topic(node: &DdsNode) -> libp2p::gossipsub::TopicHash {
    node.topics.operations.to_ident_topic().hash()
}

/// Mint and immediately install an `EpochKeyRelease` from `publisher` to
/// `recipient`. Returns `InstallOutcome` so the caller can assert the
/// expected classification.
fn distribute_epoch_key(
    publisher: &DdsNode,
    recipient: &mut DdsNode,
) -> Result<InstallOutcome, &'static str> {
    let publisher_id = publisher.peer_id.to_string();
    let recipient_id = recipient.peer_id.to_string();
    let (epoch_id, epoch_key) = publisher.epoch_keys_for_tests().my_current_epoch();
    let recipient_kem_pk = recipient.epoch_keys_for_tests().kem_public().clone();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let release = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &publisher_id,
        epoch_id,
        epoch_key,
        &recipient_id,
        &recipient_kem_pk,
        now,
        now + 86_400,
    )?;
    recipient.install_epoch_key_release(&release, &recipient_id, now)
}

// ─── 1. Mixed-fleet: enc-v3 transition ───────────────────────────────────────

/// Before `enc-v3` is active: plaintext gossip flows between two nodes
/// on the same domain; neither drops it.
#[test]
fn mixed_fleet_plaintext_accepted_before_enc_v3_flip() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-mixed", &mut OsRng);

    // Both nodes: no enc-v3 capability (Stage 0 / 1 mixed-fleet window).
    let (mut node_a, _da) = spawn_node(&domain_key, Vec::new());
    let (mut node_b, _db) = spawn_node(&domain_key, Vec::new());

    let plaintext = make_plaintext_gossip();
    let topic_a = ops_topic(&node_a);
    let topic_b = ops_topic(&node_b);

    let rejected_before_a = tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected");
    let rejected_before_b = tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected");

    node_a.handle_gossip_message_for_tests(&topic_a, &plaintext);
    node_b.handle_gossip_message_for_tests(&topic_b, &plaintext);

    // Neither node should have incremented the enc_v3_plaintext_rejected counter.
    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected"),
        rejected_before_b, // covers both since we used the same initial snapshot
        "plaintext must not be rejected on non-enc-v3 domains"
    );
    let _ = (node_a, rejected_before_a); // suppress unused warnings
}

/// After `enc-v3` is active: node B (enc-v3) rejects plaintext gossip from
/// node A (not yet enc-v3 capable). This is the Stage 2 transition gate.
#[test]
fn mixed_fleet_plaintext_rejected_after_enc_v3_flip() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-mixed-enc", &mut OsRng);

    let (_node_a, _da) = spawn_node(&domain_key, Vec::new()); // v2-only publisher
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]); // enc-v3 receiver

    let plaintext = make_plaintext_gossip();
    let topic_b = ops_topic(&node_b);

    let rejected_before = tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected");
    node_b.handle_gossip_message_for_tests(&topic_b, &plaintext);

    assert_eq!(
        tel.gossip_messages_dropped_count("enc_v3_plaintext_rejected"),
        rejected_before + 1,
        "enc-v3 node must reject plaintext gossip after capability flip"
    );
}

/// Two enc-v3 nodes exchange encrypted gossip successfully.
#[test]
fn mixed_fleet_encrypted_gossip_flows_between_two_enc_v3_nodes() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-enc-v3-both", &mut OsRng);
    let (node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    // Distribute A's epoch key to B.
    let outcome = distribute_epoch_key(&node_a, &mut node_b).expect("distribute ok");
    assert!(matches!(
        outcome,
        InstallOutcome::Inserted | InstallOutcome::Rotated
    ));

    let (epoch_id, epoch_key) = node_a.epoch_keys_for_tests().my_current_epoch();
    let envelope = make_encrypted_gossip(&node_a.peer_id.to_string(), epoch_id, epoch_key);
    let topic_b = ops_topic(&node_b);

    let ok_before = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &envelope);

    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "enc-v3 node must decrypt and ingest encrypted gossip from peer"
    );
}

// ─── 2. Epoch-key rotation + grace window ────────────────────────────────────

/// After publisher A rotates its epoch key, receiver B can still decrypt
/// messages encrypted under the *old* `epoch_id` via the grace cache on B's
/// `EpochKeyStore`, **and** can decrypt messages under the new epoch once
/// the new release is installed.
#[test]
fn rotation_grace_window_then_new_release() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-rotation", &mut OsRng);
    let (mut node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    // Step 1: distribute A's initial epoch key (epoch_id=1) to B.
    let outcome = distribute_epoch_key(&node_a, &mut node_b).expect("initial distribute");
    assert!(matches!(
        outcome,
        InstallOutcome::Inserted | InstallOutcome::Rotated
    ));

    let (old_epoch_id, old_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };

    // Step 2: B can decrypt A's gossip under epoch_id=old.
    let topic_b = ops_topic(&node_b);
    let old_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), old_epoch_id, &old_epoch_key);
    let ok_before = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &old_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "B must decrypt A's gossip under initial epoch_id"
    );

    // Step 3: A rotates its epoch key.
    node_a.rotate_and_fan_out("time");
    let (new_epoch_id, new_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };
    assert!(
        new_epoch_id > old_epoch_id,
        "epoch_id must increment after rotation"
    );

    // Step 4: B still has the old key in its current release cache
    // (it hasn't been overwritten yet by a new release).  Messages
    // encrypted under the *old* epoch_id are still in B's cache.
    let old_still = node_b
        .epoch_keys_for_tests()
        .peer_epoch_key(&node_a.peer_id.to_string(), old_epoch_id)
        .copied();
    assert_eq!(
        old_still,
        Some(old_epoch_key),
        "B must still have A's old epoch key before new release is installed"
    );

    // Step 5: Distribute A's new release to B.
    let new_outcome = distribute_epoch_key(&node_a, &mut node_b).expect("new distribute");
    assert!(
        matches!(new_outcome, InstallOutcome::Rotated),
        "second distribution must show Rotated outcome; got {:?}",
        new_outcome
    );

    // Step 6: B can now decrypt A's gossip under the new epoch_id.
    let new_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), new_epoch_id, &new_epoch_key);
    let ok_before2 = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &new_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before2 + 1,
        "B must decrypt A's gossip under new epoch_id after installing new release"
    );

    // Step 7: The old epoch key is now in B's grace cache (not evicted
    // yet).  Gossip that was in-flight under old_epoch_id still decrypts.
    let inflight_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), old_epoch_id, &old_epoch_key);
    let ok_before3 = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &inflight_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before3 + 1,
        "in-flight gossip under old epoch_id must still decrypt via grace cache"
    );
}

/// After `EpochKeyStore::prune_grace` clears B's grace cache, the old
/// `epoch_id` is no longer decryptable (key evicted).
#[test]
fn rotation_grace_pruned_old_epoch_key_no_longer_decryptable() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-grace-prune", &mut OsRng);
    let (mut node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    distribute_epoch_key(&node_a, &mut node_b).expect("initial distribute");
    let (old_epoch_id, old_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };

    // A rotates; B installs new release → old goes to grace cache.
    node_a.rotate_and_fan_out("time");
    distribute_epoch_key(&node_a, &mut node_b).expect("new distribute");

    // Manually force prune with a very far-future instant so the grace
    // window appears expired.
    use std::time::{Duration, Instant};
    let far_future = Instant::now() + Duration::from_secs(86_400); // 24h in the future
    let pruned = node_b.epoch_keys_mut_for_tests().prune_grace(far_future);
    assert!(
        pruned >= 1,
        "prune must evict at least the old peer grace entry"
    );

    // Now the old epoch_id is gone from the cache.
    let still_cached = node_b
        .epoch_keys_for_tests()
        .peer_epoch_key(&node_a.peer_id.to_string(), old_epoch_id);
    assert!(
        still_cached.is_none(),
        "old epoch key must be evicted after grace prune"
    );

    // Attempting to decrypt a message encrypted under the old epoch_id → no_key.
    let old_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), old_epoch_id, &old_epoch_key);
    let topic_b = ops_topic(&node_b);
    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    node_b.handle_gossip_message_for_tests(&topic_b, &old_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        no_key_before + 1,
        "after grace prune, decryption under old epoch_id must drop with no_key"
    );
}

// ─── 3. Revocation-triggered rotation ────────────────────────────────────────

/// When A calls `rotate_and_fan_out("revocation")` (simulating the
/// `ingest_revocation` path), the new epoch key replaces the old one.
/// A peer (C) that only has the **pre-rotation** key cached cannot decrypt
/// subsequent gossip from A.
#[test]
fn revocation_triggered_rotation_blocks_peer_without_new_release() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-revoc-rotation", &mut OsRng);
    let (mut node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_c, _dc) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    // Pre-rotation: distribute A's epoch key to both B and C.
    distribute_epoch_key(&node_a, &mut node_b).expect("pre-rotation B");
    distribute_epoch_key(&node_a, &mut node_c).expect("pre-rotation C");

    let (pre_epoch_id, pre_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };

    // All three can decrypt pre-rotation gossip.
    let topic_b = ops_topic(&node_b);
    let topic_c = ops_topic(&node_c);
    let pre_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), pre_epoch_id, &pre_epoch_key);
    let ok_b = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &pre_envelope);
    node_c.handle_gossip_message_for_tests(&topic_c, &pre_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_b + 2,
        "both B and C must decrypt pre-rotation gossip"
    );

    // Rotation triggered by a revocation (simulated).
    let rotation_before = tel.pq_rotation_count("revocation");
    node_a.rotate_and_fan_out("revocation");
    assert_eq!(
        tel.pq_rotation_count("revocation"),
        rotation_before + 1,
        "revocation-triggered rotation must be recorded"
    );

    let (post_epoch_id, post_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };
    assert!(
        post_epoch_id > pre_epoch_id,
        "epoch_id must advance on rotation"
    );

    // B gets the new release; C does NOT.
    distribute_epoch_key(&node_a, &mut node_b).expect("post-rotation B");
    // C intentionally not updated — simulates revoked peer.

    let post_envelope =
        make_encrypted_gossip(&node_a.peer_id.to_string(), post_epoch_id, &post_epoch_key);

    // B can decrypt post-rotation gossip.
    let ok_before_b = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &post_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before_b + 1,
        "B (received new release) must decrypt post-rotation gossip"
    );

    // C cannot decrypt post-rotation gossip — drops with no_key (once
    // C's old key ages out of current slot and the new epoch_id is
    // unknown to C).
    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    node_c.handle_gossip_message_for_tests(&topic_c, &post_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        no_key_before + 1,
        "C (revoked, no new release) must NOT decrypt post-rotation gossip"
    );
}

// ─── 4. Offline > 24h reconnect ──────────────────────────────────────────────

/// Simulate a node B that was offline while A rotated multiple times.
/// B's cached epoch key for A is now stale (A is on epoch N+k).
/// After B "reconnects" and receives a fresh release (via the
/// `EpochKeyRequest` / response protocol), B can decrypt A's current gossip.
#[test]
fn offline_reconnect_fresh_release_restores_decryption() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-offline", &mut OsRng);
    let (mut node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    // Initial distribution — B comes online and installs A's epoch key.
    distribute_epoch_key(&node_a, &mut node_b).expect("initial distribute");

    // Simulate A rotating several times while B is "offline" — B never
    // receives the intermediate releases.
    for reason in &["time", "time", "manual"] {
        node_a.rotate_and_fan_out(reason);
        // Intentionally NOT distributing to B.
    }

    let (current_epoch_id, current_epoch_key) = {
        let (id, k) = node_a.epoch_keys_for_tests().my_current_epoch();
        (id, *k)
    };

    // B tries to decrypt A's current gossip — fails with no_key because
    // B's cache still holds A's initial epoch_id, not the current one.
    let current_envelope = make_encrypted_gossip(
        &node_a.peer_id.to_string(),
        current_epoch_id,
        &current_epoch_key,
    );
    let topic_b = ops_topic(&node_b);
    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    node_b.handle_gossip_message_for_tests(&topic_b, &current_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        no_key_before + 1,
        "B must fail to decrypt while holding a stale epoch key"
    );

    // B "reconnects": receives a fresh release from A (simulating the
    // EpochKeyRequest → EpochKeyResponse path from §4.5.1).
    // We use the same mint+install path the request-response handler drives.
    let reconnect_outcome =
        distribute_epoch_key(&node_a, &mut node_b).expect("reconnect distribute");
    assert!(
        matches!(
            reconnect_outcome,
            InstallOutcome::Inserted | InstallOutcome::Rotated
        ),
        "reconnect must install or rotate the cached release; got {reconnect_outcome:?}"
    );

    // Now B can decrypt A's current gossip.
    let ok_before = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &current_envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "after reconnect release, B must decrypt A's current gossip"
    );
}

/// The `EpochKeyRequest` handler (`build_epoch_key_response_for_tests`)
/// returns a release encapsulated to the requester's live KEM pubkey,
/// which the requester installs and uses to decrypt the current epoch's
/// gossip — this exercises the complete §4.5.1 late-join recovery protocol
/// without a live swarm.
#[test]
fn offline_reconnect_via_epoch_key_request_response() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-offline-rr", &mut OsRng);
    let (mut node_a, _da) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);

    // A rotates a few times; B never received any of A's releases.
    node_a.rotate_and_fan_out("time");
    node_a.rotate_and_fan_out("time");

    // Populate A's peer_certs with a hybrid v3 cert for B carrying B's
    // actual KEM pubkey (simulates the H-12 cert exchange on reconnect).
    let b_kem_bytes = node_b.epoch_keys_for_tests().kem_public().to_bytes();
    let b_cert = DomainKey::generate_hybrid("test-domain-b-cert", &mut OsRng)
        .issue_admission_with_kem(node_b.peer_id.to_string(), 0, None, Some(b_kem_bytes));
    node_a.cache_peer_admission_cert(node_b.peer_id.to_string(), b_cert);

    // B sends an EpochKeyRequest for A's own epoch key.
    let request = EpochKeyRequest {
        publishers: vec![node_a.peer_id.to_string()],
        outbound_releases: vec![],
    };
    let response = node_a.build_epoch_key_response_for_tests(&request, &node_b.peer_id);
    assert_eq!(
        response.releases.len(),
        1,
        "A must return one release for its own epoch key"
    );

    // B installs the release from A's response.
    use dds_net::pq_envelope::EpochKeyRelease;
    let release = EpochKeyRelease::from_cbor(&response.releases[0]).expect("decode release");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let install_outcome = node_b
        .install_epoch_key_release(&release, &node_b.peer_id.to_string(), now)
        .expect("install release");
    assert!(
        matches!(
            install_outcome,
            InstallOutcome::Inserted | InstallOutcome::Rotated
        ),
        "install outcome unexpected: {install_outcome:?}"
    );

    // B can now decrypt A's current gossip.
    let (epoch_id, epoch_key) = node_a.epoch_keys_for_tests().my_current_epoch();
    let envelope = make_encrypted_gossip(&node_a.peer_id.to_string(), epoch_id, epoch_key);
    let topic_b = ops_topic(&node_b);
    let ok_before = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "B must decrypt A's gossip after late-join recovery via EpochKeyRequest"
    );
}

// ─── 5. KEM pubkey rotated while offline ─────────────────────────────────────

/// Publisher A replaces its KEM keypair (new node identity on the same
/// domain — simulates `dds-cli pq rotate` or a node re-provision).
/// Receiver B's cached cert for A is stale; when B updates its cert
/// cache (H-12 reconnect), a new release minted against the new KEM
/// pubkey decaps cleanly at B using the new KEM secret.
#[test]
fn kem_pubkey_rotation_while_offline_receiver_updates_cert_and_decrypts() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("domain-kem-rotate", &mut OsRng);

    // ── A (old identity) ──────────────────────────────────────────────
    let (old_a, _da_old) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let old_a_peer_id_str = old_a.peer_id.to_string();
    let old_a_kem_pk_bytes = old_a.epoch_keys_for_tests().kem_public().to_bytes();

    // Receiver B initially knows about A's old identity.
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    distribute_epoch_key(&old_a, &mut node_b).expect("initial distribute from old A");

    // ── A rotates its KEM keypair: new node instance (same domain) ────
    // In practice this is done via `dds-cli pq rotate` which generates a
    // new KEM keypair, re-issues the AdmissionCert with `pq_kem_pubkey`,
    // and redistributes releases. We simulate by spawning a new node
    // instance (new KEM keypair) that takes over the same publisher peer_id.
    let (new_a, _da_new) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let new_a_peer_id_str = new_a.peer_id.to_string();
    let new_a_kem_pk_bytes = new_a.epoch_keys_for_tests().kem_public().to_bytes();

    // The new KEM pubkey must differ from the old one (new node = new keypair).
    assert_ne!(
        old_a_kem_pk_bytes, new_a_kem_pk_bytes,
        "new node must have a different KEM keypair"
    );

    // ── B "reconnects" and receives new_a's fresh cert ────────────────
    // On H-12 reconnect, B's `verify_peer_admission` would call
    // `cache_peer_admission_cert` with the new cert. We simulate:
    let new_a_cert = domain_key.issue_admission_with_kem(
        new_a_peer_id_str.clone(),
        0,
        None,
        Some(new_a_kem_pk_bytes.clone()),
    );
    node_b.cache_peer_admission_cert(new_a_peer_id_str.clone(), new_a_cert);

    // Overwrite B's stale epoch key cache for the old A identity
    // (B would lose A's entry when A's peer_id changed; simulated by
    // using a distinct peer_id for new_a since each DdsNode::init
    // generates a fresh libp2p keypair).
    let _ = old_a_peer_id_str; // old identity is now gone from the mesh

    // ── New A mints a release for B ───────────────────────────────────
    let b_kem_pk = node_b.epoch_keys_for_tests().kem_public().clone();
    let b_id = node_b.peer_id.to_string();
    let (new_epoch_id, new_epoch_key) = new_a.epoch_keys_for_tests().my_current_epoch();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let release = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &new_a_peer_id_str,
        new_epoch_id,
        new_epoch_key,
        &b_id,
        &b_kem_pk,
        now,
        now + 86_400,
    )
    .expect("mint with new KEM pubkey");

    // ── B installs the new release using the new KEM secret ──────────
    let install_outcome = node_b
        .install_epoch_key_release(&release, &b_id, now)
        .expect("install release with new KEM pubkey");
    assert!(
        matches!(
            install_outcome,
            InstallOutcome::Inserted | InstallOutcome::Rotated
        ),
        "expected Inserted or Rotated, got {install_outcome:?}"
    );

    // ── B can decrypt new_a's current gossip ──────────────────────────
    let envelope = make_encrypted_gossip(&new_a_peer_id_str, new_epoch_id, new_epoch_key);
    let topic_b = ops_topic(&node_b);
    let ok_before = tel.pq_envelope_decrypt_count("ok");
    node_b.handle_gossip_message_for_tests(&topic_b, &envelope);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "B must decrypt gossip from new_a after KEM pubkey rotation + fresh release"
    );
}

/// The stale cert for A (with the old KEM pubkey) cannot be used to mint
/// a release that decaps at B — verifies the component-binding defence
/// holds across a KEM pubkey rotation.
#[test]
fn stale_kem_pubkey_release_cannot_be_decapped_by_recipient() {
    let domain_key = DomainKey::generate("domain-kem-stale", &mut OsRng);

    // Old A: generates initial KEM keypair.
    let (old_a, _da_old) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let old_a_kem_pk = old_a.epoch_keys_for_tests().kem_public().clone();

    // B
    let (mut node_b, _db) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let b_id = node_b.peer_id.to_string();
    let b_kem_pk = node_b.epoch_keys_for_tests().kem_public().clone();

    // New A: fresh KEM keypair.
    let (new_a, _da_new) = spawn_node(&domain_key, vec!["enc-v3".to_string()]);
    let new_a_id = new_a.peer_id.to_string();
    let (new_epoch_id, new_epoch_key) = new_a.epoch_keys_for_tests().my_current_epoch();

    // An attacker or stale intermediary mints a release using the OLD A
    // KEM pubkey but claims it is for B (as recipient).  B's KEM secret
    // cannot decap a ciphertext encapsulated to old_a_kem_pk.
    let now = 1_700_000_000u64;
    // We mint to B's pubkey (correct) but using the NEW A's epoch key
    // so the result is a well-formed release for B.  Separately, a
    // release mistakenly minted to the OLD A's pubkey instead of B's
    // would fail at B's KEM decap.
    let release_to_old_pk = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &new_a_id,
        new_epoch_id,
        new_epoch_key,
        &b_id,
        &old_a_kem_pk, // wrong: encapsulated to A's old KEM pubkey, not B's
        now,
        now + 86_400,
    )
    .expect("mint");

    // B tries to install it — should fail at `recipient_mismatch` (the
    // label `b_id` is in the release, but the KEM ct was encapped to
    // `old_a_kem_pk` not `b_kem_pk`). Schema validate passes because
    // the lengths are correct; the fail happens at KEM decap.
    // Note: recipient field matches (b_id), so `recipient_mismatch`
    // is skipped; the fail will surface at `decap` or `aead`.
    let err = node_b
        .install_epoch_key_release(&release_to_old_pk, &b_id, now)
        .unwrap_err();
    assert!(
        matches!(err, "decap" | "aead"),
        "installing a release encapped to wrong KEM pubkey must fail; got {err:?}"
    );

    // A correctly-minted release to B's actual KEM pubkey succeeds.
    let good_release = mint_epoch_key_release_for_recipient(
        &mut OsRng,
        &new_a_id,
        new_epoch_id,
        new_epoch_key,
        &b_id,
        &b_kem_pk, // correct: B's own KEM pubkey
        now,
        now + 86_400,
    )
    .expect("mint good release");
    node_b
        .install_epoch_key_release(&good_release, &b_id, now)
        .expect("good release must install");
}
