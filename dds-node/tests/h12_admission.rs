//! H-12 regression tests.
//!
//! These exercise the production `handle_swarm_event` path end-to-end
//! (unlike `multinode.rs`, which uses a custom ingester that bypasses
//! admission-gating on purpose). The goal is to pin two properties:
//!
//! 1. **Positive**: two nodes with valid admission certs exchange
//!    certs after `ConnectionEstablished`, both land in each other's
//!    `admitted_peers`, and gossip flows normally through the
//!    production ingest path.
//! 2. **Negative**: a peer presenting a cert that doesn't verify
//!    (wrong `peer_id`, expired, or wrong domain) stays out of
//!    `admitted_peers`, and its gossip is silently dropped — the
//!    other node's trust graph never grows.

use std::time::Duration;

use dds_core::crdt::causal_dag::Operation;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_net::gossip::GossipMessage;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use rand::rngs::OsRng;
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};

const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Spin up a node belonging to `domain_key`, with an admission cert
/// that the test can choose to leave valid or deliberately break.
///
/// If `break_cert_for_peer_id` is `Some(wrong)`, the admission cert
/// is issued for `wrong` instead of the node's actual peer id, so any
/// peer that verifies it will reject it. `init()` still accepts the
/// cert because it verifies against *this* node's own peer id — we
/// only break it relative to the remote verifier.
async fn spawn_with_domain(
    domain_key: &dds_domain::DomainKey,
    org: &str,
    break_cert_for_peer_id: Option<libp2p::PeerId>,
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
    // In the "broken" branch, the cert is issued for the wrong peer
    // id — passes the local self-check in `init` iff we also issue a
    // correct one for self-verification. Simpler: issue a valid cert
    // for ourselves so `init` succeeds, then overwrite the file on
    // disk with the bad one before any peer reads it. Wait — init
    // reads the cert once and keeps it in memory. So we need to
    // patch the in-memory `admission_cert` *after* init, not rewrite
    // the file.
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
        },
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    if let Some(wrong_pid) = break_cert_for_peer_id {
        // Overwrite the in-memory cert with one issued for the wrong
        // peer id. The remote verifier compares the cert's peer id
        // against the remote libp2p peer id on the connection, so a
        // cert for a different peer id will always fail verification.
        let bad = domain_key.issue_admission(wrong_pid.to_string(), now, None);
        node.set_admission_cert_for_tests(bad);
    }
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

/// Wait for a node to learn its first listen address.
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

/// Drive two nodes concurrently through the production
/// `handle_swarm_event` path for at most `dur`, stopping early when
/// `stop` returns true.
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
        // Scope `futs` so its borrows of `a.swarm` / `b.swarm` are
        // released before we hand the resulting event back to the
        // owning node's `handle_swarm_event`.
        let routed = {
            let futs: Vec<
                std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = SwarmEvent<dds_net::transport::DdsBehaviourEvent>>
                            + Send,
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

fn make_attest_token(label: &str, jti: &str) -> (Identity, Token) {
    let id = Identity::generate(label, &mut OsRng);
    let payload = TokenPayload {
        iss: id.id.to_urn(),
        iss_key: id.public_key.clone(),
        jti: jti.to_string(),
        sub: id.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: Some("dds:directory-entry".into()),
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: 0,
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    let t = Token::sign(payload, &id.signing_key).unwrap();
    (id, t)
}

fn op_for(token: &Token) -> Operation {
    Operation {
        id: format!("op-{}", token.payload.jti),
        author: token.payload.iss.clone(),
        deps: Vec::new(),
        data: vec![0],
        timestamp: 0,
    }
}

fn publish_attest(node: &mut DdsNode, op: &Operation, token: &Token) {
    let mut op_bytes = Vec::new();
    ciborium::into_writer(op, &mut op_bytes).unwrap();
    let token_bytes = token.to_cbor().unwrap();
    let msg = GossipMessage::DirectoryOp {
        op_bytes,
        token_bytes,
    };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.operations.to_ident_topic();
    let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
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

/// **Positive case**: two nodes with valid certs admit each other
/// and gossip flows through the production ingest path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_peers_populated_and_gossip_flows() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [42u8; 32]);

    let (mut a, _ad) = spawn_with_domain(&dkey, "h12-ok", None).await;
    let (mut b, _bd) = spawn_with_domain(&dkey, "h12-ok", None).await;
    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);
    a.swarm.behaviour_mut().gossipsub.add_explicit_peer(&b_pid);

    // Admission handshake should complete within a few seconds.
    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |a, b| {
        a.admitted_peers().contains(&b_pid) && b.admitted_peers().contains(&a_pid)
    })
    .await;
    assert!(
        a.admitted_peers().contains(&b_pid),
        "A never admitted B: {:?}",
        a.admitted_peers()
    );
    assert!(
        b.admitted_peers().contains(&a_pid),
        "B never admitted A: {:?}",
        b.admitted_peers()
    );

    // Publish via gossip from A; B must ingest through the production
    // `handle_swarm_event` path (with H-12 gating active).
    let (_id, token) = make_attest_token("alice", "att-h12-ok");
    let op = op_for(&token);
    publish_attest(&mut a, &op, &token);

    pump_until(&mut a, &mut b, PROPAGATION_TIMEOUT, |_, b| {
        b.trust_graph.read().unwrap().attestations_iter().count() > 0
    })
    .await;
    let b_attests = b
        .trust_graph
        .read()
        .unwrap()
        .attestations_iter()
        .count();
    assert!(
        b_attests > 0,
        "attestation did not propagate to B under valid admission"
    );
}

/// **Negative case**: B presents a cert that doesn't verify (issued
/// for the wrong peer id). A must NOT admit B, and gossip from B
/// must NOT land in A's trust graph.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unadmitted_peer_gossip_dropped() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [42u8; 32]);

    // Pre-allocate a "wrong" peer id: a fresh keypair whose id is
    // NOT the same as B's actual libp2p peer id. The cert issued for
    // this wrong peer id will fail verification when A checks it
    // against B's real peer id on the connection.
    let fake_kp = libp2p::identity::Keypair::generate_ed25519();
    let fake_pid = libp2p::PeerId::from(fake_kp.public());

    let (mut a, _ad) = spawn_with_domain(&dkey, "h12-bad", None).await;
    let (mut b, _bd) = spawn_with_domain(&dkey, "h12-bad", Some(fake_pid)).await;
    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);
    a.swarm.behaviour_mut().gossipsub.add_explicit_peer(&b_pid);

    // Give the handshake + a round of heartbeats a chance to run.
    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |_, _| false).await;

    // A must NOT have admitted B — B's cert has the wrong peer id.
    assert!(
        !a.admitted_peers().contains(&b_pid),
        "A admitted B despite bad cert: {:?}",
        a.admitted_peers()
    );

    // B publishes an attestation. A must NOT ingest it: the gossip
    // handler drops it because B is unadmitted.
    let (_id, token) = make_attest_token("mallory", "att-h12-bad");
    let op = op_for(&token);
    publish_attest(&mut b, &op, &token);

    // Pump for a further propagation window and then verify A's
    // trust graph is still empty.
    pump_until(&mut a, &mut b, PROPAGATION_TIMEOUT, |_, _| false).await;
    // Give gossipsub one more heartbeat just in case.
    sleep(Duration::from_secs(2)).await;
    pump_until(&mut a, &mut b, Duration::from_secs(1), |_, _| false).await;

    let a_attests = a
        .trust_graph
        .read()
        .unwrap()
        .attestations_iter()
        .count();
    assert_eq!(
        a_attests, 0,
        "A ingested a token from unadmitted peer B (H-12 gate failed)"
    );
}
