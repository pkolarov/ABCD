//! **Z-1 Phase B.5** — regression tests for the dds-node side of the
//! `EpochKeyRelease` request-response receive pipeline.
//!
//! These exercise [`DdsNode::install_epoch_key_release`] end-to-end:
//!
//! 1. a well-formed release whose `(kem_ct, aead_ciphertext)` pair was
//!    encapsulated to the receiver's hybrid KEM pubkey is decapped,
//!    unwrapped, and installed in the local epoch-key store;
//! 2. the canonical binding `(publisher, recipient, epoch_id)` from
//!    [`dds_node::node::epoch_key_binding`] is enforced — a release
//!    encapsulated to a different `(publisher, recipient, epoch_id)`
//!    tuple decaps to a different shared secret and the AEAD unwrap
//!    fails;
//! 3. a release whose `recipient` is not us is rejected before any
//!    decap work;
//! 4. a release outside the
//!    [`dds_net::pq_envelope::EPOCH_RELEASE_REPLAY_WINDOW_SECS`] window
//!    is rejected before any decap work;
//! 5. the schema gate from
//!    [`dds_net::pq_envelope::EpochKeyRelease::validate`] runs first
//!    and rejects malformed shapes.
//!
//! The libp2p swarm is **not** spun up — these tests call the install
//! funnel directly so the contract is pinned without depending on a
//! request-response round-trip. The end-to-end libp2p path
//! (`/dds/epoch-keys/1.0.0/<domain>` stream → handler dispatch →
//! install) lands once B.7 / B.9 wire the publisher-side mint flow and
//! a multi-node integration harness can drive both sides.

use std::sync::OnceLock;

use dds_core::crypto::{epoch_key as ek_crypto, kem};
use dds_domain::DomainKey;
use dds_net::pq_envelope::{
    EPOCH_KEY_RELEASE_AEAD_CT_LEN, EPOCH_KEY_RELEASE_KEM_CT_LEN, EPOCH_RELEASE_REPLAY_WINDOW_SECS,
    EpochKeyRelease,
};
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::epoch_key_store::InstallOutcome;
use dds_node::node::{DdsNode, epoch_key_binding};
use rand::rngs::OsRng;

/// Process-wide guard for env-var mutations across tests sharing the
/// same binary.
fn env_guard() -> &'static std::sync::Mutex<()> {
    static GUARD: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| std::sync::Mutex::new(()))
}

/// Process-wide guard for tests that read/write the global telemetry
/// counters (`pq_releases_installed_count`). Tests share the
/// `OnceLock`-backed [`dds_node::telemetry`] handle so concurrent
/// access would race the before/after snapshot. Mirrors `env_guard`
/// — both are cheap (held only across the single install call).
fn telemetry_guard() -> &'static std::sync::Mutex<()> {
    static GUARD: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    GUARD.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a node belonging to `domain_key`. Mirrors the helper in
/// `peer_cert_cache.rs` — fresh libp2p keypair, fresh admission cert
/// valid for ~24h, fresh data dir.
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

/// Mint a release for `recipient_id` from synthetic `publisher_id`,
/// wrapping `epoch_key` under a fresh hybrid-KEM shared secret derived
/// to `recipient_kem_pk`. Mirrors the (future) publisher-side mint
/// path — the canonical binding [`epoch_key_binding`] is what allows a
/// real publisher and a real receiver to derive the same shared
/// secret without any out-of-band negotiation.
fn mint_release(
    publisher_id: &str,
    recipient_id: &str,
    epoch_id: u64,
    issued_at: u64,
    expires_at: u64,
    epoch_key: &[u8; 32],
    recipient_kem_pk: &kem::HybridKemPublicKey,
) -> EpochKeyRelease {
    let mut rng = OsRng;
    let binding = epoch_key_binding(publisher_id, recipient_id, epoch_id);
    let (kem_ct, shared) = kem::encap(&mut rng, recipient_kem_pk, &binding).expect("encap");
    let (aead_nonce, aead_ciphertext) =
        ek_crypto::wrap(&mut rng, &shared, epoch_key).expect("wrap");
    EpochKeyRelease {
        publisher: publisher_id.to_string(),
        epoch_id,
        issued_at,
        expires_at,
        recipient: recipient_id.to_string(),
        kem_ct: kem_ct.to_bytes(),
        aead_nonce,
        aead_ciphertext,
        signature: vec![0u8; 64], // not yet verified at the install layer
        pq_signature: None,
    }
}

#[test]
fn install_inserts_well_formed_release() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    let release = mint_release(
        &publisher_id,
        &recipient_id,
        7,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );

    let outcome = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .expect("install ok");
    assert!(matches!(
        outcome,
        InstallOutcome::Inserted | InstallOutcome::Rotated
    ));
    let cached = node
        .epoch_keys_for_tests()
        .peer_epoch_key(&publisher_id, 7)
        .copied()
        .expect("release cached");
    assert_eq!(cached, epoch_key);
}

#[test]
fn install_rejects_release_for_other_recipient() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    // Mint release for someone else, even though encrypted to us.
    let mut release = mint_release(
        &publisher_id,
        &recipient_id,
        7,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    release.recipient = "12D3KooWNotMe".into();

    let err = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .unwrap_err();
    assert_eq!(err, "recipient_mismatch");
    assert!(
        node.epoch_keys_for_tests()
            .peer_epoch_key(&publisher_id, 7)
            .is_none()
    );
}

#[test]
fn install_rejects_release_outside_replay_window() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now: u64 = 1_700_000_000;
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    let stale_issued_at = now - EPOCH_RELEASE_REPLAY_WINDOW_SECS - 1;
    let release = mint_release(
        &publisher_id,
        &recipient_id,
        7,
        stale_issued_at,
        stale_issued_at + 86_400,
        &epoch_key,
        &kem_pk,
    );

    let err = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .unwrap_err();
    assert_eq!(err, "replay_window");
}

#[test]
fn install_rejects_tampered_aead_ciphertext() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    let mut release = mint_release(
        &publisher_id,
        &recipient_id,
        7,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    // Flip a single byte in the AEAD ciphertext — Poly1305 must catch
    // it on `unwrap`.
    release.aead_ciphertext[0] ^= 0x01;

    let err = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .unwrap_err();
    assert_eq!(err, "aead");
}

#[test]
fn install_rejects_release_bound_to_different_epoch() {
    // Encapsulate using the binding for epoch 7 but publish the
    // release as if it were epoch 8 — the receiver re-derives the
    // binding using the release's claimed epoch and the shared
    // secrets diverge, so AEAD unwrap fails. Pins the
    // (publisher, recipient, epoch_id) component-binding defence.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    let mut release = mint_release(
        &publisher_id,
        &recipient_id,
        7,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    release.epoch_id = 8;

    let err = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .unwrap_err();
    assert_eq!(err, "aead");
}

#[test]
fn install_rejects_release_with_wrong_length_kem_ct() {
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Hand-craft a release with a kem_ct one byte short — the schema
    // gate must catch it before any decap work.
    let release = EpochKeyRelease {
        publisher: "12D3KooWPub".into(),
        epoch_id: 1,
        issued_at: now,
        expires_at: now + 60,
        recipient: recipient_id.clone(),
        kem_ct: vec![0u8; EPOCH_KEY_RELEASE_KEM_CT_LEN - 1],
        aead_nonce: [0u8; 12],
        aead_ciphertext: vec![0u8; EPOCH_KEY_RELEASE_AEAD_CT_LEN],
        signature: vec![0u8; 64],
        pq_signature: None,
    };
    let err = node
        .install_epoch_key_release(&release, &recipient_id, now)
        .unwrap_err();
    assert_eq!(err, "schema");
}

#[test]
fn epoch_key_store_persists_after_install() {
    // After a successful install + on-disk save, the freshly-decapped
    // release survives a fresh load_or_create from disk. Pins the
    // restart-survives-the-cache contract that the live node depends
    // on for the offline-and-back gossip path.
    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut epoch_key);
    let release = mint_release(
        &publisher_id,
        &recipient_id,
        42,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    node.install_epoch_key_release(&release, &recipient_id, now)
        .expect("install ok");
    // The handler persists via `epoch_keys.save` after every install
    // batch — drive that explicitly here since the test bypassed the
    // handler.
    node.epoch_keys_for_tests()
        .save(&dir.path().join("epoch_keys.cbor"))
        .expect("save ok");

    let mut rng = OsRng;
    let reloaded = dds_node::epoch_key_store::EpochKeyStore::load_or_create(
        &dir.path().join("epoch_keys.cbor"),
        &mut rng,
    )
    .expect("reload ok");
    let cached = reloaded
        .peer_epoch_key(&publisher_id, 42)
        .copied()
        .expect("release survived restart");
    assert_eq!(cached, epoch_key);
}

/// **Z-1 Phase B.11 (partial)** — every exit branch of
/// [`DdsNode::install_epoch_key_release`] bumps
/// `dds_pq_releases_installed_total{result=...}` by one. The receive
/// funnel is the load-bearing observability surface for the H-12
/// piggy-back path and the `/dds/epoch-keys/1.0.0/<domain>` request-
/// response path; this test pins ok + four failure-path buckets in
/// one sequential run under a process-wide telemetry guard so the
/// before/after deltas don't race other tests in the same binary.
#[test]
fn install_bumps_pq_releases_installed_metric() {
    use rand_core::RngCore;
    let _t_guard = telemetry_guard().lock().unwrap_or_else(|e| e.into_inner());
    // Lazily initialise the process-global telemetry handle. Idempotent
    // — the handle survives across tests in this binary.
    let telemetry = dds_node::telemetry::install();

    let domain_key = DomainKey::generate("test-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let recipient_id = node.peer_id.to_string();
    let kem_pk = node.epoch_keys_for_tests().kem_public().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_id = "12D3KooWPublisherSyntheticForTest".to_string();
    let mut epoch_key = [0u8; 32];
    OsRng.fill_bytes(&mut epoch_key);

    let baseline_ok = telemetry.pq_releases_installed_count("ok");
    let baseline_recipient_mismatch = telemetry.pq_releases_installed_count("recipient_mismatch");
    let baseline_replay_window = telemetry.pq_releases_installed_count("replay_window");
    let baseline_aead = telemetry.pq_releases_installed_count("aead");
    let baseline_schema = telemetry.pq_releases_installed_count("schema");

    // 1) ok — well-formed release, decap+unwrap succeeds.
    let release = mint_release(
        &publisher_id,
        &recipient_id,
        100,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    node.install_epoch_key_release(&release, &recipient_id, now)
        .expect("install ok");

    // 2) recipient_mismatch — release.recipient lies about who it's for.
    let mut wrong_recipient = mint_release(
        &publisher_id,
        &recipient_id,
        101,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    wrong_recipient.recipient = "12D3KooWNotMe".into();
    let _ = node.install_epoch_key_release(&wrong_recipient, &recipient_id, now);

    // 3) replay_window — issued_at older than the 7-day window.
    let stale_now: u64 = 1_700_000_000;
    let stale_issued = stale_now - EPOCH_RELEASE_REPLAY_WINDOW_SECS - 1;
    let stale = mint_release(
        &publisher_id,
        &recipient_id,
        102,
        stale_issued,
        stale_issued + 86_400,
        &epoch_key,
        &kem_pk,
    );
    let _ = node.install_epoch_key_release(&stale, &recipient_id, stale_now);

    // 4) aead — single-byte flip in the AEAD ciphertext, Poly1305
    //    catches it on unwrap.
    let mut tampered = mint_release(
        &publisher_id,
        &recipient_id,
        103,
        now,
        now + 86_400,
        &epoch_key,
        &kem_pk,
    );
    tampered.aead_ciphertext[0] ^= 0x01;
    let _ = node.install_epoch_key_release(&tampered, &recipient_id, now);

    // 5) schema — wrong-length kem_ct caught by validate().
    let bad_schema = EpochKeyRelease {
        publisher: publisher_id.clone(),
        epoch_id: 104,
        issued_at: now,
        expires_at: now + 86_400,
        recipient: recipient_id.clone(),
        kem_ct: vec![0u8; EPOCH_KEY_RELEASE_KEM_CT_LEN - 1],
        aead_nonce: [0u8; 12],
        aead_ciphertext: vec![0u8; EPOCH_KEY_RELEASE_AEAD_CT_LEN],
        signature: vec![0u8; 64],
        pq_signature: None,
    };
    let _ = node.install_epoch_key_release(&bad_schema, &recipient_id, now);

    assert_eq!(telemetry.pq_releases_installed_count("ok"), baseline_ok + 1);
    assert_eq!(
        telemetry.pq_releases_installed_count("recipient_mismatch"),
        baseline_recipient_mismatch + 1
    );
    assert_eq!(
        telemetry.pq_releases_installed_count("replay_window"),
        baseline_replay_window + 1
    );
    assert_eq!(
        telemetry.pq_releases_installed_count("aead"),
        baseline_aead + 1
    );
    assert_eq!(
        telemetry.pq_releases_installed_count("schema"),
        baseline_schema + 1
    );
}
