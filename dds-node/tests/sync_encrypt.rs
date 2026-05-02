//! **Z-1 Phase B.8** — regression tests for encrypted `SyncEnvelopeV3`
//! response building and ingestion in
//! [`dds_node::node::DdsNode::build_sync_response`] and
//! [`dds_node::node::DdsNode::handle_sync_response`].
//!
//! Tests call `build_sync_response_for_tests` / `handle_sync_response_for_tests`
//! directly (no libp2p swarm) and pin the following contracts:
//!
//! 1. On a domain **without** `enc-v3`, `build_sync_response` returns a
//!    plaintext response (`payloads` non-empty, `enc_payloads` empty).
//! 2. On a domain **with** `enc-v3`, `build_sync_response` returns an
//!    encrypted response (`enc_payloads` non-empty, `payloads` empty).
//! 3. `handle_sync_response` on an encrypted response decrypts each blob,
//!    bumps `dds_pq_envelope_decrypt_total{result="ok"}`, and merges the
//!    payloads into the node state (validated by the sync-payloads cache
//!    being populated).
//! 4. Encrypted response with no cached epoch key → each blob drops with
//!    `result="no_key"`.
//! 5. Encrypted response with a tampered ciphertext → each blob drops with
//!    `result="aead_fail"`.
//! 6. An encrypted round-trip between two node instances (responder builds,
//!    requester decrypts and processes) succeeds end-to-end.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use dds_core::crdt::causal_dag::Operation;
use dds_core::crypto::epoch_key as ek_crypto;
use dds_domain::DomainKey;
use dds_net::pq_envelope::SyncEnvelopeV3;
use dds_net::sync::{SyncRequest, SyncResponse};
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::epoch_key_store::InstallOutcome;
use rand::rngs::OsRng;
use rand_core::RngCore;

/// Process-wide serialisation guard so telemetry counter deltas are
/// attributable to individual tests.
fn tel_guard() -> &'static std::sync::Mutex<()> {
    static G: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a minimal node. `capabilities` controls whether `enc-v3` is active.
fn make_node(
    domain_key: &DomainKey,
    capabilities: Vec<String>,
) -> (dds_node::node::DdsNode, tempfile::TempDir) {
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
    let node = dds_node::node::DdsNode::init(cfg, p2p_keypair).expect("init node");
    (node, dir)
}

/// Seed the sync-payload cache with a single synthetic entry. Returns the
/// op-id used so callers can build `SyncRequest::known_op_ids`.
fn seed_sync_payload(node: &mut dds_node::node::DdsNode, op_id: &str) {
    let op = Operation {
        id: op_id.to_string(),
        author: "test-author".to_string(),
        deps: Vec::new(),
        data: vec![1, 2, 3],
        timestamp: 0,
    };
    // Use synthetic (invalid) token bytes — the sync-cache stores them opaquely;
    // the crypto path only cares about the CBOR framing of the `SyncPayload`.
    node.cache_sync_payload(op_id, &op, b"fake-token-bytes");
}

/// Install a synthetic epoch key into `node`'s epoch-key store, as if it
/// arrived via an `EpochKeyRelease` decap.
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

/// Helper: make an empty `SyncRequest` (requester knows nothing).
fn empty_sync_request() -> SyncRequest {
    SyncRequest {
        known_op_ids: BTreeSet::new(),
        heads: BTreeSet::new(),
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// Non-`enc-v3` domain: `build_sync_response` returns plaintext payloads,
/// `enc_payloads` is empty.
#[test]
fn build_sync_response_plaintext_on_non_enc_v3_domain() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, Vec::new()); // no enc-v3

    seed_sync_payload(&mut node, "op-001");

    let resp = node.build_sync_response_for_tests(&empty_sync_request());

    assert!(
        !resp.payloads.is_empty(),
        "non-enc-v3: payloads must be populated"
    );
    assert!(
        resp.enc_payloads.is_empty(),
        "non-enc-v3: enc_payloads must be empty"
    );
}

/// `enc-v3` domain: `build_sync_response` returns encrypted payloads,
/// plaintext `payloads` is empty.
#[test]
fn build_sync_response_encrypted_on_enc_v3_domain() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, vec!["enc-v3".to_string()]);

    seed_sync_payload(&mut node, "op-001");

    let resp = node.build_sync_response_for_tests(&empty_sync_request());

    assert!(
        resp.payloads.is_empty(),
        "enc-v3: plaintext payloads must be empty"
    );
    assert!(
        !resp.enc_payloads.is_empty(),
        "enc-v3: enc_payloads must be populated"
    );
    // Each blob must decode as a valid SyncEnvelopeV3.
    for blob in &resp.enc_payloads {
        SyncEnvelopeV3::from_cbor(blob).expect("enc_payload blob must decode as SyncEnvelopeV3");
    }
}

/// `enc-v3` domain: a requester that already knows an op-id does not receive
/// it in the encrypted response (same diff-filter as plaintext path).
#[test]
fn build_sync_response_enc_v3_respects_known_op_ids() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = make_node(&domain_key, vec!["enc-v3".to_string()]);

    seed_sync_payload(&mut node, "op-already-known");

    let mut req = empty_sync_request();
    req.known_op_ids.insert("op-already-known".to_string());

    let resp = node.build_sync_response_for_tests(&req);

    assert!(
        resp.enc_payloads.is_empty(),
        "no diff: enc_payloads must be empty when requester knows all ops"
    );
    assert!(
        resp.complete,
        "complete flag must be true when diff is empty"
    );
}

/// Encrypted response with a cached epoch key → AEAD decrypt succeeds and
/// `pq_envelope_decrypt_total{result="ok"}` is bumped.
#[test]
fn handle_sync_response_decrypts_with_cached_epoch_key() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);

    // Responder: enc-v3, has payload in cache.
    let (mut responder, _rdir) = make_node(&domain_key, vec!["enc-v3".to_string()]);
    seed_sync_payload(&mut responder, "op-001");
    let responder_peer_id = responder.peer_id;
    let (responder_epoch_id, responder_epoch_key) =
        responder.epoch_keys_for_tests().my_current_epoch();

    // Build encrypted response.
    let enc_resp = responder.build_sync_response_for_tests(&empty_sync_request());
    assert!(
        !enc_resp.enc_payloads.is_empty(),
        "responder should have produced enc_payloads"
    );

    // Requester: install responder's epoch key.
    let (mut requester, _qdir) = make_node(&domain_key, Vec::new());
    install_epoch_key(
        &mut requester,
        &responder_peer_id.to_string(),
        responder_epoch_id,
        responder_epoch_key,
    );

    let ok_before = tel.pq_envelope_decrypt_count("ok");
    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    let aead_fail_before = tel.pq_envelope_decrypt_count("aead_fail");

    requester.handle_sync_response_for_tests(responder_peer_id, enc_resp);

    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 1,
        "pq_envelope_decrypt{{result=ok}} must advance by 1"
    );
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

/// Encrypted response with no cached epoch key → drops with `result="no_key"`.
#[test]
fn handle_sync_response_no_cached_key_drops_with_no_key() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);

    let (mut responder, _rdir) = make_node(&domain_key, vec!["enc-v3".to_string()]);
    seed_sync_payload(&mut responder, "op-001");
    let responder_peer_id = responder.peer_id;

    let enc_resp = responder.build_sync_response_for_tests(&empty_sync_request());
    assert!(!enc_resp.enc_payloads.is_empty());

    // Requester has NO cached epoch key for the responder.
    let (mut requester, _qdir) = make_node(&domain_key, Vec::new());

    let no_key_before = tel.pq_envelope_decrypt_count("no_key");
    let ok_before = tel.pq_envelope_decrypt_count("ok");

    requester.handle_sync_response_for_tests(responder_peer_id, enc_resp);

    assert_eq!(
        tel.pq_envelope_decrypt_count("no_key"),
        no_key_before + 1,
        "pq_envelope_decrypt{{result=no_key}} must advance"
    );
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before,
        "ok must not advance"
    );
}

/// Encrypted response with a tampered ciphertext → drops with `result="aead_fail"`.
#[test]
fn handle_sync_response_tampered_ciphertext_drops_with_aead_fail() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);

    let (mut responder, _rdir) = make_node(&domain_key, vec!["enc-v3".to_string()]);
    seed_sync_payload(&mut responder, "op-001");
    let responder_peer_id = responder.peer_id;
    let (responder_epoch_id, responder_epoch_key) =
        responder.epoch_keys_for_tests().my_current_epoch();

    let enc_resp = responder.build_sync_response_for_tests(&empty_sync_request());
    assert!(!enc_resp.enc_payloads.is_empty());

    // Tamper: flip bytes in each enc_payload's ciphertext.
    let tampered_enc_payloads: Vec<Vec<u8>> = enc_resp
        .enc_payloads
        .iter()
        .map(|blob| {
            let mut env = SyncEnvelopeV3::from_cbor(blob).expect("decode env");
            // Flip the last byte of the ciphertext to corrupt the AEAD tag.
            if let Some(last) = env.ciphertext.last_mut() {
                *last ^= 0xff;
            }
            env.to_cbor().expect("re-encode tampered env")
        })
        .collect();
    let tampered_resp = SyncResponse {
        payloads: Vec::new(),
        complete: enc_resp.complete,
        enc_payloads: tampered_enc_payloads,
    };

    let (mut requester, _qdir) = make_node(&domain_key, Vec::new());
    install_epoch_key(
        &mut requester,
        &responder_peer_id.to_string(),
        responder_epoch_id,
        responder_epoch_key,
    );

    let aead_fail_before = tel.pq_envelope_decrypt_count("aead_fail");
    let ok_before = tel.pq_envelope_decrypt_count("ok");

    requester.handle_sync_response_for_tests(responder_peer_id, tampered_resp);

    assert_eq!(
        tel.pq_envelope_decrypt_count("aead_fail"),
        aead_fail_before + 1,
        "pq_envelope_decrypt{{result=aead_fail}} must advance"
    );
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before,
        "ok must not advance on tampered ciphertext"
    );
}

/// Plaintext response (`payloads` only, `enc_payloads` empty) is still
/// accepted by `handle_sync_response` on a non-`enc-v3` node (mixed-fleet
/// window; §4.7 Stage 0–1).
#[test]
fn handle_sync_response_accepts_plaintext_on_non_enc_v3_node() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);

    // Responder without enc-v3 sends plaintext.
    let (mut responder, _rdir) = make_node(&domain_key, Vec::new());
    seed_sync_payload(&mut responder, "op-001");
    let responder_peer_id = responder.peer_id;

    let plain_resp = responder.build_sync_response_for_tests(&empty_sync_request());
    assert!(
        plain_resp.enc_payloads.is_empty(),
        "non-enc-v3 must send plaintext"
    );
    assert!(
        !plain_resp.payloads.is_empty(),
        "non-enc-v3 must have payloads"
    );

    let (mut requester, _qdir) = make_node(&domain_key, Vec::new());

    // No pq_envelope_decrypt bumps for the plaintext path.
    let ok_before = tel.pq_envelope_decrypt_count("ok");
    requester.handle_sync_response_for_tests(responder_peer_id, plain_resp);
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before,
        "plaintext path must not touch pq_envelope_decrypt counter"
    );
}

/// End-to-end encrypted sync round-trip: responder builds an encrypted
/// response using its own epoch key; requester installs that epoch key and
/// decrypts the response successfully. The round-trip exercises the full
/// encrypt → CBOR encode → CBOR decode → AEAD decrypt → SyncPayload decode
/// pipeline without a live libp2p swarm.
#[test]
fn encrypted_sync_round_trip_end_to_end() {
    let _g = tel_guard().lock().unwrap_or_else(|e| e.into_inner());
    let tel = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);

    // Responder: enc-v3, two payloads cached.
    let (mut responder, _rdir) = make_node(&domain_key, vec!["enc-v3".to_string()]);
    seed_sync_payload(&mut responder, "op-A");
    seed_sync_payload(&mut responder, "op-B");
    let responder_peer_id = responder.peer_id;
    let (epoch_id, epoch_key) = responder.epoch_keys_for_tests().my_current_epoch();

    let enc_resp = responder.build_sync_response_for_tests(&empty_sync_request());
    assert_eq!(
        enc_resp.enc_payloads.len(),
        2,
        "two payloads → two encrypted blobs"
    );
    assert!(
        enc_resp.payloads.is_empty(),
        "enc-v3 must not send plaintext"
    );

    // Requester: install responder's epoch key, then process encrypted response.
    let (mut requester, _qdir) = make_node(&domain_key, Vec::new());
    install_epoch_key(
        &mut requester,
        &responder_peer_id.to_string(),
        epoch_id,
        epoch_key,
    );

    let ok_before = tel.pq_envelope_decrypt_count("ok");

    requester.handle_sync_response_for_tests(responder_peer_id, enc_resp);

    // Both blobs must have decrypted cleanly.
    assert_eq!(
        tel.pq_envelope_decrypt_count("ok"),
        ok_before + 2,
        "two decryptions must succeed in the round-trip"
    );
}

/// Verify that `SyncEnvelopeV3` CBOR round-trips faithfully (unit-level
/// wire-format pin; complements the integration tests above).
#[test]
fn sync_envelope_v3_cbor_round_trip() {
    let mut rng = OsRng;
    let mut epoch_key = [0u8; 32];
    rng.fill_bytes(&mut epoch_key);

    let payload_cbor = b"fake-payload-cbor";
    let (nonce, ciphertext) =
        ek_crypto::encrypt_payload(&mut rng, &epoch_key, payload_cbor).expect("encrypt");

    let env = SyncEnvelopeV3 {
        responder: "12D3KooWFakeResponder".to_string(),
        epoch_id: 42,
        nonce,
        ciphertext: ciphertext.clone(),
    };
    let blob = env.to_cbor().expect("to_cbor");
    let decoded = SyncEnvelopeV3::from_cbor(&blob).expect("from_cbor");

    assert_eq!(decoded.responder, env.responder);
    assert_eq!(decoded.epoch_id, env.epoch_id);
    assert_eq!(decoded.nonce, env.nonce);
    assert_eq!(decoded.ciphertext, env.ciphertext);

    // Decrypt the ciphertext from the decoded envelope.
    let plaintext = ek_crypto::decrypt_payload(&epoch_key, &decoded.nonce, &decoded.ciphertext)
        .expect("decrypt");
    assert_eq!(plaintext, payload_cbor);
}
