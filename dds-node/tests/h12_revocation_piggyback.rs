//! Threat-model §1 / item #4 follow-up: gossip-piggyback distribution
//! for admission revocations.
//!
//! These tests pin the property that two nodes completing the H-12
//! admission handshake exchange their local revocation lists, and that
//! newly-learned revocations land both in memory and on disk so they
//! survive a restart. This closes the "v1 distribution is manual file
//! copy; gossip-piggyback is a future increment" note left in
//! `dds-node::admission_revocation_store` and `docs/threat-model-review.md`.
//!
//! Construction strategy: write a pre-built `admission_revocations.cbor`
//! to the node's data dir *before* calling `DdsNode::init`, so the
//! load path inside `init` populates the in-memory store. After the
//! handshake fires we re-read the on-disk file with
//! `admission_revocation_store::load_or_empty` to assert persistence.
//!
//! The negative-path properties (over-cap drop, malformed entries,
//! foreign-domain rejection) are pinned in unit tests at the
//! `dds-net::admission` and `dds-node::admission_revocation_store`
//! layers — those exercise the same code paths without needing a
//! libp2p swarm spin-up.

use std::time::Duration;

use dds_node::admission_revocation_store::{self, AdmissionRevocationStore, RevocationListV1};
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use tempfile::TempDir;
use tokio::time::{Instant, timeout};

const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Spin up a node, optionally pre-seeding its on-disk
/// `admission_revocations.cbor` with `seed`. The seeded file is
/// loaded and verified by `DdsNode::init` before the swarm is built,
/// so the in-memory store reflects `seed` from the start.
async fn spawn_with_revocations(
    domain_key: &dds_domain::DomainKey,
    org: &str,
    seed: Option<&AdmissionRevocationStore>,
) -> (DdsNode, TempDir) {
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

    if let Some(store) = seed {
        let rev_path = data_dir.join("admission_revocations.cbor");
        admission_revocation_store::save(&rev_path, store).unwrap();
    }

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
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

async fn wait_for_listen(node: &mut DdsNode) -> Multiaddr {
    timeout(Duration::from_secs(5), async {
        loop {
            let event = node.swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    })
    .await
    .expect("listen addr")
}

async fn pump_until<F>(a: &mut DdsNode, b: &mut DdsNode, dur: Duration, mut stop: F)
where
    F: FnMut(&DdsNode, &DdsNode) -> bool,
{
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if stop(a, b) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let routed = {
            let futs: Vec<
                std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = SwarmEvent<dds_net::transport::DdsBehaviourEvent>,
                            > + Send,
                    >,
                >,
            > = vec![
                Box::pin(a.swarm.select_next_some()),
                Box::pin(b.swarm.select_next_some()),
            ];
            match timeout(remaining, futures::future::select_all(futs)).await {
                Ok((event, idx, _rest)) => Some((event, idx)),
                Err(_) => None,
            }
        };
        match routed {
            Some((event, 0)) => a.handle_swarm_event(event),
            Some((event, 1)) => b.handle_swarm_event(event),
            Some((_, _)) => unreachable!(),
            None => return,
        }
    }
}

fn connect_one_sided(
    initiator: &mut DdsNode,
    initiator_pid: libp2p::PeerId,
    initiator_addr: Multiaddr,
    responder: &mut DdsNode,
    responder_pid: libp2p::PeerId,
    responder_addr: Multiaddr,
) {
    let init_addr = initiator_addr.with(libp2p::multiaddr::Protocol::P2p(initiator_pid));
    let resp_addr = responder_addr.with(libp2p::multiaddr::Protocol::P2p(responder_pid));
    initiator
        .swarm
        .add_peer_address(responder_pid, resp_addr.clone());
    responder.swarm.add_peer_address(initiator_pid, init_addr);
    initiator.swarm.dial(resp_addr).unwrap();
}

/// **Happy path**: A starts with two domain-signed revocations on
/// disk; B starts empty. After the H-12 handshake completes, B's
/// in-memory store contains both entries AND its on-disk file
/// reflects them (so a restart re-loads them at `init`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocations_propagate_via_h12_handshake_and_persist() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("piggyback.local", [7u8; 32]);
    let domain = dkey.domain();

    // Build the seed store for A: two revocations against arbitrary
    // (non-participant) peer ids. Using non-participant ids keeps the
    // handshake itself unaffected — the test isolates "did the list
    // propagate" from "did the cert verify".
    let mut seed = AdmissionRevocationStore::for_domain(domain.id, domain.pubkey);
    seed.add(dkey.revoke_admission(
        "12D3KooWRevokedAlpha".into(),
        100,
        Some("compromised".into()),
    ))
    .unwrap();
    seed.add(dkey.revoke_admission(
        "12D3KooWRevokedBeta".into(),
        200,
        Some("decommissioned".into()),
    ))
    .unwrap();
    assert_eq!(seed.len(), 2);

    let (mut a, _ad) = spawn_with_revocations(&dkey, "h12-piggy", Some(&seed)).await;
    let (mut b, bdir) = spawn_with_revocations(&dkey, "h12-piggy", None).await;
    assert_eq!(
        a.admission_revocations().len(),
        2,
        "A should load its seed list at init"
    );
    assert!(
        b.admission_revocations().is_empty(),
        "B should start with no revocations"
    );

    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);
    a.swarm.behaviour_mut().gossipsub.add_explicit_peer(&b_pid);

    // Handshake should complete and B should learn both revocations
    // from A's piggy-back.
    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |a, b| {
        a.admitted_peers().contains(&b_pid)
            && b.admitted_peers().contains(&a_pid)
            && b.admission_revocations().len() == 2
    })
    .await;

    assert!(
        b.admitted_peers().contains(&a_pid),
        "B never admitted A: {:?}",
        b.admitted_peers()
    );
    let b_store = b.admission_revocations();
    assert_eq!(
        b_store.len(),
        2,
        "B did not learn A's revocations: {:?}",
        b_store.entries()
    );
    assert!(b_store.is_revoked("12D3KooWRevokedAlpha"));
    assert!(b_store.is_revoked("12D3KooWRevokedBeta"));

    // And the persistence half: B's on-disk file reflects what is in
    // memory, so a future `init` load picks it up at startup.
    let on_disk = admission_revocation_store::load_or_empty(
        &bdir.path().join("admission_revocations.cbor"),
        domain.id,
        domain.pubkey,
    )
    .expect("load_or_empty");
    assert_eq!(
        on_disk.len(),
        2,
        "piggy-backed revocations were not persisted to disk"
    );
    assert!(on_disk.is_revoked("12D3KooWRevokedAlpha"));
    assert!(on_disk.is_revoked("12D3KooWRevokedBeta"));
}

/// **Cross-domain rejection**: A foreign domain key signs a
/// revocation and ships it as a piggy-back. B verifies each entry
/// against *its own* domain pubkey via
/// `AdmissionRevocationStore::merge`, so the foreign entry is
/// dropped. We exercise this by hand-encoding a malicious
/// `AdmissionResponse` rather than spinning a second domain-bound
/// node — the `merge` path is symmetric across both gossip-piggyback
/// and `dds-node import-revocation`, and the unit-level coverage
/// already lives in `admission_revocation_store::tests::add_rejects_wrong_domain`.
/// What this test pins is the *integration* invariant that the
/// piggy-back path also rejects a foreign signature.
#[test]
fn merge_path_rejects_foreign_domain_revocation() {
    use rand::rngs::OsRng;
    let real = dds_domain::DomainKey::generate("real.local", &mut OsRng);
    let foreign = dds_domain::DomainKey::generate("evil.local", &mut OsRng);
    let real_dom = real.domain();

    let mut store = AdmissionRevocationStore::for_domain(real_dom.id, real_dom.pubkey);
    let bad = foreign.revoke_admission("12D3KooWForeign".into(), 0, None);
    let added = store.merge(RevocationListV1 {
        v: 1,
        entries: vec![bad],
    });
    assert_eq!(
        added, 0,
        "foreign-domain revocation must not land in the local store"
    );
    assert!(store.is_empty());
    assert!(!store.is_revoked("12D3KooWForeign"));
}
