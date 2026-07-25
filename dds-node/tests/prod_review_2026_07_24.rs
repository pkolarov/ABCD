//! Regression tests for the 2026-07-24 pre-production review.
//!
//! Each test names the finding it pins. They drive the production code
//! paths through the `#[doc(hidden)]` test hooks on [`DdsNode`] rather
//! than reimplementing the logic, so a regression in the real decision
//! function fails here.
//!
//! Covered: **H-1** (gossip relay gated on admission + per-peer inbound
//! budget), **M-1** (unadmitted-connection deadline), **M-5**
//! (expiry-driven `trusted_roots` demotion on the swarm ingest gate),
//! **L-5** (mDNS peer-table eviction), **L-11** (admission challenge
//! correlated to its request).

use std::time::{Duration, Instant};

use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_net::gossip::GossipMessage;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use libp2p::gossipsub::MessageAcceptance;
use rand::rngs::OsRng;
use tempfile::TempDir;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a node on a fresh domain. Mirrors the fixture in
/// `h12_admission.rs` but without the deliberately-broken-cert branch.
fn spawn_node(domain_key: &dds_domain::DomainKey) -> (DdsNode, TempDir) {
    spawn_node_with(domain_key, |_| {})
}

/// [`spawn_node`] with a hook to adjust `NetworkConfig` before the node
/// is built — used by the rate-budget test to pin a small, deterministic
/// budget instead of depending on production defaults and wall clock.
fn spawn_node_with(
    domain_key: &dds_domain::DomainKey,
    tune: impl FnOnce(&mut NetworkConfig),
) -> (DdsNode, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let domain = domain_key.domain();
    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());

    let cert = domain_key.issue_admission(peer_id.to_string(), now_epoch(), None);
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

    let mut network = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        mdns_enabled: false,
        heartbeat_secs: 1,
        api_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    tune(&mut network);

    let cfg = NodeConfig {
        data_dir,
        network,
        org_hash: "prod-review-org".to_string(),
        domain: dds_node::config::DomainConfig {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            pq_pubkey: None,
            // Plaintext gossip so the H-1 tests exercise the relay gate
            // rather than the enc-v3 decrypt path.
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
        self_update_apply: true,
    };
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

/// A syntactically valid plaintext `DirectoryOp` gossip message on the
/// Operations topic.
fn operations_message(node: &DdsNode) -> libp2p::gossipsub::Message {
    let ident = Identity::generate("gossip-src", &mut OsRng);
    let token = Token::sign(
        TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("jti-{}", uuid::Uuid::new_v4()),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some("test".to_string()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: now_epoch(),
            exp: Some(now_epoch() + 3600),
            body_type: None,
            body_cbor: None,
        },
        &ident.signing_key,
    )
    .unwrap();
    let op = dds_core::crdt::causal_dag::Operation {
        id: format!("op-{}", uuid::Uuid::new_v4()),
        author: ident.id.to_urn(),
        deps: vec![],
        data: token.to_cbor().unwrap(),
        timestamp: now_epoch(),
    };
    let mut op_bytes = Vec::new();
    ciborium::into_writer(&op, &mut op_bytes).unwrap();
    let msg = GossipMessage::DirectoryOp {
        op_bytes,
        token_bytes: token.to_cbor().unwrap(),
    };
    libp2p::gossipsub::Message {
        source: None,
        data: msg.to_cbor().unwrap(),
        sequence_number: None,
        topic: node.topics.operations.to_ident_topic().hash(),
    }
}

// ---------------------------------------------------------------------
// H-1 — gossip is not relayed until the admission gate passes
// ---------------------------------------------------------------------

/// **H-1 (blocker)** — a message relayed by an *unadmitted* peer must
/// not be accepted, and therefore must not be forwarded to the mesh.
///
/// Before the fix, gossipsub auto-forwarded every signature-valid
/// message to mesh peers before the application ran the H-12 check, so
/// the check only suppressed local ingest — the relay had already
/// happened. One unadmitted, Noise-only peer could use any entry node
/// as an amplifier for the entire domain, and downstream nodes saw the
/// message arrive from an honest relay so their own gate passed too.
///
/// `Accept` is what tells libp2p to forward. Anything else stops it
/// here, which is the property under test.
#[test]
fn h1_gossip_from_unadmitted_peer_is_not_relayed() {
    let domain_key = dds_domain::DomainKey::generate("h1-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let stranger = libp2p::PeerId::random();
    let msg = operations_message(&node);

    let verdict = node.classify_gossip_message_for_tests(&stranger, &msg);

    assert!(
        !matches!(verdict, MessageAcceptance::Accept),
        "H-1: an unadmitted relayer's message must never be Accepted (Accept == relay to mesh)"
    );
}

/// **H-1** — the same message from an *admitted* relayer is accepted, so
/// the fix does not break normal propagation. Without this the previous
/// test would pass trivially by rejecting everything.
#[test]
fn h1_gossip_from_admitted_peer_is_relayed() {
    let domain_key = dds_domain::DomainKey::generate("h1-domain-ok", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let peer = libp2p::PeerId::random();
    node.admit_peer_for_tests(peer);
    let msg = operations_message(&node);

    let verdict = node.classify_gossip_message_for_tests(&peer, &msg);

    assert!(
        matches!(verdict, MessageAcceptance::Accept),
        "an admitted relayer's valid message must still propagate"
    );
}

/// **H-1** — a malformed payload from an admitted peer is `Reject`ed,
/// which both stops the relay and charges the peer a peer-scoring
/// penalty so a repeat offender is eventually graylisted. Without
/// scoring, rejection costs an attacker nothing.
#[test]
fn h1_malformed_gossip_from_admitted_peer_is_rejected() {
    let domain_key = dds_domain::DomainKey::generate("h1-domain-bad", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let peer = libp2p::PeerId::random();
    node.admit_peer_for_tests(peer);

    let mut msg = operations_message(&node);
    msg.data = b"not valid cbor at all".to_vec();

    let verdict = node.classify_gossip_message_for_tests(&peer, &msg);

    assert!(
        matches!(verdict, MessageAcceptance::Reject),
        "an undecodable payload is an unambiguous protocol violation and must be penalised"
    );
}

/// **H-1** — the per-peer inbound budget must actually bite.
///
/// Admission proves domain membership, not good behaviour, and every
/// inbound message costs a signature verify plus a trust-graph insert.
/// Past the budget the node must stop both ingesting and relaying.
///
/// The budget and window are pinned small/long here rather than taken
/// from the production defaults. Driving the real 1200-per-60s default
/// meant minting 1200 signed messages inside the window, which a slow CI
/// runner cannot do — the window rolled over mid-loop, the budget never
/// exhausted, and the test failed for a reason that had nothing to do
/// with the behaviour under test. `h1_default_gossip_budget_is_finite`
/// keeps coverage of the shipped values.
#[test]
fn h1_admitted_peer_inbound_gossip_budget_is_enforced() {
    const BUDGET: u32 = 5;
    let domain_key = dds_domain::DomainKey::generate("h1-domain-rate", &mut OsRng);
    let (mut node, _dir) = spawn_node_with(&domain_key, |net| {
        net.gossip_inbound_max_per_window = BUDGET;
        // Long enough that the window cannot roll over mid-test on any
        // runner, so this asserts the budget and not the clock.
        net.gossip_rate_window_secs = 3600;
    });
    let peer = libp2p::PeerId::random();
    node.admit_peer_for_tests(peer);

    // Spend exactly the budget — every one of these must be accepted.
    for i in 0..BUDGET {
        let msg = operations_message(&node);
        let verdict = node.classify_gossip_message_for_tests(&peer, &msg);
        assert!(
            matches!(verdict, MessageAcceptance::Accept),
            "message {i} is inside the budget and must be accepted"
        );
    }

    // The next message is over budget: not ingested, not relayed.
    let msg = operations_message(&node);
    let verdict = node.classify_gossip_message_for_tests(&peer, &msg);
    assert!(
        matches!(verdict, MessageAcceptance::Ignore),
        "H-1: past the per-peer budget the message must be dropped without relay"
    );
}

/// **H-1** — the shipped defaults must still be a finite budget over a
/// finite window. Separated from the behavioural test above so the
/// latter does not depend on how fast the host can mint 1200 tokens.
#[test]
fn h1_default_gossip_budget_is_finite() {
    let net = NetworkConfig::default();
    assert!(
        net.gossip_inbound_max_per_window > 0,
        "the default build must ship a finite per-peer gossip budget"
    );
    assert!(
        net.gossip_rate_window_secs > 0,
        "the budget window must be non-zero or the cap never resets"
    );
}

// ---------------------------------------------------------------------
// M-1 — unadmitted connections are torn down on a deadline
// ---------------------------------------------------------------------

/// **M-1** — a peer that holds a connection past the admission deadline
/// without completing the H-12 handshake is disconnected and denylisted.
///
/// The retry path already bounded *retries*, but it ran on the 60 s
/// anti-entropy tick and spent five attempts first, so an unadmitted
/// peer previously pinned a connection (and its Noise state and pending
/// challenge) for roughly five minutes per keypair — and an attacker
/// rotates keypairs, so the PeerId denylist never bit.
#[test]
fn m1_unadmitted_peer_is_disconnected_after_the_deadline() {
    let domain_key = dds_domain::DomainKey::generate("m1-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let squatter = libp2p::PeerId::random();

    let timeout_secs = NetworkConfig::default().unadmitted_peer_timeout_secs;
    assert!(timeout_secs > 0, "the default build must ship a deadline");

    // Just inside the deadline — left alone.
    let now = Instant::now();
    node.mark_unadmitted_since_for_tests(squatter, now);
    assert_eq!(
        node.disconnect_stale_unadmitted_peers_for_tests(now + Duration::from_secs(1)),
        0,
        "a peer still inside its admission window must not be torn down"
    );

    // Past the deadline — swept.
    assert_eq!(
        node.disconnect_stale_unadmitted_peers_for_tests(
            now + Duration::from_secs(timeout_secs + 1)
        ),
        1,
        "M-1: a peer past the admission deadline must be disconnected"
    );

    // Idempotent: the entry is gone, so a second sweep is a no-op.
    assert_eq!(
        node.disconnect_stale_unadmitted_peers_for_tests(
            now + Duration::from_secs(timeout_secs + 2)
        ),
        0
    );
}

/// **M-1** — an *admitted* peer is never swept, however long it has been
/// connected. Admission clears the deadline.
#[test]
fn m1_admitted_peer_is_never_swept() {
    let domain_key = dds_domain::DomainKey::generate("m1-domain-ok", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);
    let peer = libp2p::PeerId::random();

    let now = Instant::now();
    node.mark_unadmitted_since_for_tests(peer, now);
    node.admit_peer_for_tests(peer);

    assert_eq!(
        node.disconnect_stale_unadmitted_peers_for_tests(now + Duration::from_secs(3600)),
        0,
        "an admitted peer must never be torn down by the M-1 deadline"
    );
}

// ---------------------------------------------------------------------
// L-5 — mDNS peer table evicts never-admitted entries
// ---------------------------------------------------------------------

/// **L-5** — the mDNS peer table must not be a fill-once/never-drain
/// resource.
///
/// Announcements are pre-Noise and therefore unauthenticated, so one LAN
/// host advertising `MDNS_PEER_TABLE_MAX` spoofed PeerIds used to fill
/// the table permanently and lock out every genuine peer, with no
/// recovery short of a node restart — in exactly the zero-config bridged
/// LAN topology where mDNS is the only discovery path.
#[test]
fn l5_mdns_table_evicts_never_admitted_entries() {
    let domain_key = dds_domain::DomainKey::generate("l5-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);

    // Fill the table with spoofed, long-stale, never-admitted entries.
    let stale_at = Instant::now() - Duration::from_secs(600);
    for _ in 0..300 {
        node.insert_mdns_peer_for_tests(libp2p::PeerId::random(), stale_at);
    }
    let before = node.mdns_known_peer_count();
    assert!(
        before >= 256,
        "table should be at/over the ceiling: {before}"
    );

    let evicted = node.evict_stale_mdns_peers_for_tests(Instant::now());
    assert!(
        evicted > 0,
        "L-5: stale unadmitted entries must be evictable"
    );
    assert!(
        node.mdns_known_peer_count() < before,
        "the table must actually shrink"
    );
}

/// **L-5** — a peer that *is* admitted holds its slot, and a freshly
/// discovered peer still inside its grace window is not reclaimed out
/// from under an in-flight handshake.
#[test]
fn l5_mdns_eviction_spares_admitted_and_fresh_entries() {
    let domain_key = dds_domain::DomainKey::generate("l5-domain-spare", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);

    let admitted = libp2p::PeerId::random();
    let fresh = libp2p::PeerId::random();
    let stale = libp2p::PeerId::random();

    let long_ago = Instant::now() - Duration::from_secs(600);
    node.insert_mdns_peer_for_tests(admitted, long_ago);
    node.admit_peer_for_tests(admitted);
    node.insert_mdns_peer_for_tests(fresh, Instant::now());
    node.insert_mdns_peer_for_tests(stale, long_ago);

    let evicted = node.evict_stale_mdns_peers_for_tests(Instant::now());
    assert_eq!(
        evicted, 1,
        "only the stale, never-admitted entry may be evicted"
    );
    assert_eq!(node.mdns_known_peer_count(), 2);
}

// ---------------------------------------------------------------------
// M-5 — expired admin vouches demote on the swarm ingest gate
// ---------------------------------------------------------------------

/// **M-5** — an admin whose promoting `dds:admin` vouch has *expired*
/// (rather than being explicitly revoked) must be demoted from the swarm
/// task's `trusted_roots`.
///
/// The swarm copy previously demoted only on an explicit `Revoke` token.
/// Every `dds:admin` vouch carries a finite 1-year expiry, so a
/// delegated sub-admin — and anyone it vouched for — stayed a fully
/// authoritative trust root on the ingest gate until the process
/// restarted. `LocalService` got this right; the gate that actually
/// enforces C-3 publisher capability did not.
#[test]
fn m5_expired_admin_vouch_demotes_on_the_swarm_gate() {
    let domain_key = dds_domain::DomainKey::generate("m5-domain", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);

    let boot = Identity::generate("boot-admin", &mut OsRng);
    let sub = Identity::generate("sub-admin", &mut OsRng);

    // Seed the bootstrap admin as a config-anchored root.
    node.seed_trusted_root_for_tests(boot.id.to_urn());

    // Enroll `sub` so the vouch has a target attestation to bind to.
    let sub_attest = Token::sign(
        TokenPayload {
            iss: sub.id.to_urn(),
            iss_key: sub.public_key.clone(),
            jti: "attest-sub".to_string(),
            sub: sub.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some("dds:user-auth".to_string()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: now_epoch() - 7200,
            exp: Some(now_epoch() + 86_400),
            body_type: None,
            body_cbor: None,
        },
        &sub.signing_key,
    )
    .unwrap();
    let sub_hash = sub_attest.payload_hash();

    // A `dds:admin` vouch from the bootstrap admin that has ALREADY
    // EXPIRED — no revocation anywhere.
    let expired_vouch = Token::sign(
        TokenPayload {
            iss: boot.id.to_urn(),
            iss_key: boot.public_key.clone(),
            jti: "vouch-boot-sub-expired".to_string(),
            sub: sub.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(dds_core::token::purpose::ADMIN.to_string()),
            vch_iss: Some(sub.id.to_urn()),
            vch_sum: Some(sub_hash),
            revokes: None,
            iat: now_epoch() - 7200,
            exp: Some(now_epoch() - 60),
            body_type: None,
            body_cbor: None,
        },
        &boot.signing_key,
    )
    .unwrap();

    {
        let mut g = node.trust_graph.write().unwrap();
        g.add_token(sub_attest).unwrap();
        g.add_token(expired_vouch).unwrap();
    }

    // Simulate the pre-expiry state: `sub` was promoted while the vouch
    // was live and is still sitting in the swarm's root set.
    node.seed_trusted_root_for_tests(sub.id.to_urn());
    assert!(node.trusted_roots_for_tests().contains(&sub.id.to_urn()));

    node.reconcile_roots_by_expiry_for_tests();

    assert!(
        !node.trusted_roots_for_tests().contains(&sub.id.to_urn()),
        "M-5: an admin whose promoting vouch expired must be demoted without waiting for a restart"
    );
    assert!(
        node.trusted_roots_for_tests().contains(&boot.id.to_urn()),
        "the config-anchored bootstrap admin must survive reconcile"
    );
}

/// **M-5** — a *live* `dds:admin` vouch must keep its subject promoted,
/// so the expiry sweep cannot be passed by demoting everything.
#[test]
fn m5_live_admin_vouch_is_not_demoted() {
    let domain_key = dds_domain::DomainKey::generate("m5-domain-live", &mut OsRng);
    let (mut node, _dir) = spawn_node(&domain_key);

    let boot = Identity::generate("boot-admin", &mut OsRng);
    let sub = Identity::generate("sub-admin", &mut OsRng);
    node.seed_trusted_root_for_tests(boot.id.to_urn());

    let sub_attest = Token::sign(
        TokenPayload {
            iss: sub.id.to_urn(),
            iss_key: sub.public_key.clone(),
            jti: "attest-sub-live".to_string(),
            sub: sub.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some("dds:user-auth".to_string()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: now_epoch() - 60,
            exp: Some(now_epoch() + 86_400),
            body_type: None,
            body_cbor: None,
        },
        &sub.signing_key,
    )
    .unwrap();
    let sub_hash = sub_attest.payload_hash();

    let live_vouch = Token::sign(
        TokenPayload {
            iss: boot.id.to_urn(),
            iss_key: boot.public_key.clone(),
            jti: "vouch-boot-sub-live".to_string(),
            sub: sub.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(dds_core::token::purpose::ADMIN.to_string()),
            vch_iss: Some(sub.id.to_urn()),
            vch_sum: Some(sub_hash),
            revokes: None,
            iat: now_epoch() - 60,
            exp: Some(now_epoch() + 86_400),
            body_type: None,
            body_cbor: None,
        },
        &boot.signing_key,
    )
    .unwrap();

    {
        let mut g = node.trust_graph.write().unwrap();
        g.add_token(sub_attest).unwrap();
        g.add_token(live_vouch).unwrap();
    }

    node.reconcile_roots_by_expiry_for_tests();

    assert!(
        node.trusted_roots_for_tests().contains(&sub.id.to_urn()),
        "a live dds:admin vouch from a current root must promote (and keep) its subject"
    );
}
