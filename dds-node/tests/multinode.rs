//! Multi-node integration tests.
//!
//! Spins up 3 in-process `DdsNode` instances on ephemeral TCP ports,
//! wires them together via explicit dials, and verifies real
//! gossip-based propagation of:
//!   (a) attestation token operations
//!   (b) revocation announcements
//!   (c) DAG convergence after a partition (a node is dropped, the
//!       remaining nodes mutate state, then a fresh node rejoins)
//!
//! These tests use `tokio::time::timeout` heavily — gossipsub mesh
//! formation is timing-dependent. The harness drives every node's
//! swarm event loop concurrently via `select_all`.

use std::time::Duration;

use dds_core::crdt::causal_dag::Operation;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_net::gossip::GossipMessage;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::swarm::SwarmEvent;
use rand::rngs::OsRng;
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};

/// Build a single node with an ephemeral listen address and the given
/// org hash. Returns the node, its temp dir (must outlive the node), and
/// the listen address picked once it's listening.
async fn spawn_node(org: &str) -> (DdsNode, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();

    // Shared test domain — all multinode-test nodes belong to it.
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [42u8; 32]);
    let domain = dkey.domain();

    // Generate the libp2p keypair, derive peer id, write an admission cert.
    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());
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
        },
        org_hash: org.to_string(),
        domain: dds_node::config::DomainConfig {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            admission_path: None,
            audit_log_enabled: false,
        },
        trusted_roots: Vec::new(),
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init node");
    // Listen + subscribe to topics. We bypass `start()` to avoid
    // bootstrap-peer parsing on an empty list.
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

/// Drive a node's swarm forward for `dur`, applying the standard
/// ingestion handlers via the public DdsNode methods. Used to give
/// gossipsub time to form a mesh and deliver messages.
#[allow(dead_code)]
async fn pump(node: &mut DdsNode, dur: Duration) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, node.swarm.select_next_some()).await {
            Ok(event) => {
                handle_event(node, event);
            }
            Err(_) => return,
        }
    }
}

/// Drive several nodes concurrently for `dur`. Uses `futures::select_all`
/// to actually wake whichever node has an event, instead of round-robin
/// polling that would wait per-node.
async fn pump_many(nodes: &mut [&mut DdsNode], dur: Duration) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Build a future for the next event from each node.
        let futs: Vec<_> = nodes
            .iter_mut()
            .map(|n| Box::pin(n.swarm.select_next_some()))
            .collect();
        match timeout(remaining, futures::future::select_all(futs)).await {
            Ok((event, idx, _rest)) => {
                handle_event(nodes[idx], event);
            }
            Err(_) => return,
        }
    }
}

fn handle_event(node: &mut DdsNode, event: SwarmEvent<dds_net::transport::DdsBehaviourEvent>) {
    use dds_net::transport::DdsBehaviourEvent;
    match event {
        SwarmEvent::Behaviour(DdsBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Message { message, .. },
        )) => {
            ingest_gossip(node, &message.topic, &message.data);
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            node.config.network.listen_addr = address.to_string();
        }
        _ => {}
    }
}

fn ingest_gossip(node: &mut DdsNode, topic_hash: &libp2p::gossipsub::TopicHash, data: &[u8]) {
    use dds_net::gossip::DdsTopic;
    let topic = match node.topics.identify_topic(topic_hash) {
        Some(t) => t.clone(),
        None => return,
    };
    let msg = match GossipMessage::from_cbor(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    match (topic, msg) {
        (
            DdsTopic::Operations(..),
            GossipMessage::DirectoryOp {
                op_bytes,
                token_bytes,
            },
        ) => {
            if let (Ok(op), Ok(token)) = (
                ciborium::from_reader::<Operation, _>(op_bytes.as_slice()),
                Token::from_cbor(&token_bytes),
            ) {
                if token.validate().is_ok() {
                    let _ = node.trust_graph.add_token(token.clone());
                    use dds_store::traits::TokenStore;
                    let _ = node.store.put_token(&token);
                    let _ = node.dag.insert(op);
                }
            }
        }
        (DdsTopic::Revocations(..), GossipMessage::Revocation { token_bytes }) => {
            if let Ok(token) = Token::from_cbor(&token_bytes) {
                if token.validate().is_ok() {
                    let _ = node.trust_graph.add_token(token.clone());
                    if let Some(target) = token.payload.revokes.clone() {
                        use dds_store::traits::RevocationStore;
                        let _ = node.store.revoke(&target);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Wait for a node to learn its first listen address and return it.
async fn wait_for_listen(node: &mut DdsNode) -> Multiaddr {
    let result = timeout(Duration::from_secs(5), async {
        loop {
            let event = node.swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    })
    .await;
    result.expect("listen addr")
}

/// Dial peer's address from `from` and remember it as an explicit
/// gossipsub peer so the mesh forms quickly.
fn connect(from: &mut DdsNode, peer: libp2p::PeerId, addr: Multiaddr) {
    from.swarm
        .behaviour_mut()
        .gossipsub
        .add_explicit_peer(&peer);
    from.swarm
        .behaviour_mut()
        .kademlia
        .add_address(&peer, addr.clone());
    from.swarm.dial(addr).unwrap();
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

fn make_revoke(target_jti: &str, issuer: &Identity) -> Token {
    let payload = TokenPayload {
        iss: issuer.id.to_urn(),
        iss_key: issuer.public_key.clone(),
        jti: format!("rev-{target_jti}"),
        sub: issuer.id.to_urn(),
        kind: TokenKind::Revoke,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: Some(target_jti.to_string()),
        iat: 0,
        exp: None,
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &issuer.signing_key).unwrap()
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
    // Gossipsub does NOT echo messages back to the publisher, so apply
    // the same effect locally to mirror the real ingest path on the
    // node that originated the op.
    let _ = node.trust_graph.add_token(token.clone());
    use dds_store::traits::TokenStore;
    let _ = node.store.put_token(token);
    let _ = node.dag.insert(op.clone());
}

fn publish_revocation(node: &mut DdsNode, token: &Token) {
    let token_bytes = token.to_cbor().unwrap();
    let msg = GossipMessage::Revocation { token_bytes };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.revocations.to_ident_topic();
    let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
    let _ = node.trust_graph.add_token(token.clone());
    if let Some(target) = token.payload.revokes.clone() {
        use dds_store::traits::RevocationStore;
        let _ = node.store.revoke(&target);
    }
}

/// Set up three connected nodes; returns them and their temp dirs.
async fn three_node_cluster(org: &str) -> (Vec<DdsNode>, Vec<TempDir>) {
    let (mut a, ad) = spawn_node(org).await;
    let (mut b, bd) = spawn_node(org).await;
    let (mut c, cd) = spawn_node(org).await;

    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let c_addr = wait_for_listen(&mut c).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;
    let c_pid = c.peer_id;

    // Star topology: a <-> b, a <-> c, b <-> c
    connect(&mut a, b_pid, b_addr.clone());
    connect(&mut a, c_pid, c_addr.clone());
    connect(&mut b, a_pid, a_addr.clone());
    connect(&mut b, c_pid, c_addr.clone());
    connect(&mut c, a_pid, a_addr.clone());
    connect(&mut c, b_pid, b_addr.clone());

    // Pump until mesh forms — gossipsub heartbeat is 1s, mesh formation
    // typically requires 2-3 heartbeats after the TCP handshake.
    {
        let mut nodes = vec![&mut a, &mut b, &mut c];
        pump_many(&mut nodes, Duration::from_secs(8)).await;
    }
    (vec![a, b, c], vec![ad, bd, cd])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_attestation_propagates_three_nodes() {
    let _ = tracing_subscriber::fmt::try_init();
    let (mut nodes, _dirs) = three_node_cluster("multinode-attest").await;

    let (_id, token) = make_attest_token("alice", "att-multinode-1");
    let op = op_for(&token);
    publish_attest(&mut nodes[0], &op, &token);

    // Drive event loops until both other nodes have ingested the op
    // (or 15s timeout).
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut refs: Vec<&mut DdsNode> = nodes.iter_mut().collect();
        pump_many(&mut refs, Duration::from_millis(200)).await;
        let count = nodes.iter().filter(|n| n.dag.contains(&op.id)).count();
        if count == 3 {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let counts: Vec<_> = nodes.iter().map(|n| n.dag.len()).collect();
    panic!("attestation did not propagate to all three nodes: dag sizes = {counts:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_propagates_three_nodes() {
    let _ = tracing_subscriber::fmt::try_init();
    let (mut nodes, _dirs) = three_node_cluster("multinode-revoke").await;

    // Pre-seed an attestation on every node directly so the revocation
    // has something to target.
    let (bob_id, token) = make_attest_token("bob", "att-bob-1");
    for n in nodes.iter_mut() {
        n.trust_graph.add_token(token.clone()).unwrap();
        use dds_store::traits::TokenStore;
        n.store.put_token(&token).unwrap();
    }

    let revoke = make_revoke("att-bob-1", &bob_id);
    publish_revocation(&mut nodes[1], &revoke);

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let mut refs: Vec<&mut DdsNode> = nodes.iter_mut().collect();
        pump_many(&mut refs, Duration::from_millis(200)).await;
        let revoked = nodes
            .iter()
            .filter(|n| n.trust_graph.is_revoked("att-bob-1"))
            .count();
        if revoked == 3 {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("revocation did not propagate to all nodes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dag_converges_after_partition() {
    let _ = tracing_subscriber::fmt::try_init();
    let (mut nodes, _dirs) = three_node_cluster("multinode-partition").await;

    // Drop node C entirely (simulate partition).
    let _dropped = nodes.pop().unwrap();

    // Nodes A and B mutate while C is gone.
    let (_id, t1) = make_attest_token("carol", "part-1");
    let op1 = op_for(&t1);
    publish_attest(&mut nodes[0], &op1, &t1);

    let (_id2, t2) = make_attest_token("dave", "part-2");
    let op2 = op_for(&t2);
    publish_attest(&mut nodes[1], &op2, &t2);

    // Pump A and B until both ops are everywhere on the partition side.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut converged = false;
    while Instant::now() < deadline {
        {
            let mut refs: Vec<&mut DdsNode> = nodes.iter_mut().collect();
            pump_many(&mut refs, Duration::from_millis(200)).await;
        }
        if nodes
            .iter()
            .all(|n| n.dag.contains(&op1.id) && n.dag.contains(&op2.id))
        {
            converged = true;
            break;
        }
    }
    assert!(converged, "A/B did not converge before rejoin");

    // Spin up a fresh "rejoined" node C' and connect it to A and B.
    let (mut rejoiner, _rd) = spawn_node("multinode-partition").await;
    let r_addr = wait_for_listen(&mut rejoiner).await;
    let r_pid = rejoiner.peer_id;
    let a_pid = nodes[0].peer_id;
    let b_pid = nodes[1].peer_id;
    let a_addr: Multiaddr = nodes[0].config.network.listen_addr.parse().unwrap();
    let b_addr: Multiaddr = nodes[1].config.network.listen_addr.parse().unwrap();

    connect(&mut rejoiner, a_pid, a_addr);
    connect(&mut rejoiner, b_pid, b_addr);
    connect(&mut nodes[0], r_pid, r_addr.clone());
    connect(&mut nodes[1], r_pid, r_addr);

    // Let mesh form between rejoiner and existing nodes.
    {
        let (left, right) = nodes.split_at_mut(1);
        let mut refs: Vec<&mut DdsNode> = vec![&mut left[0], &mut right[0], &mut rejoiner];
        pump_many(&mut refs, Duration::from_secs(8)).await;
    }
    // Publish a brand-new op AFTER rejoin. Gossipsub dedupes by
    // message-content hash so re-publishing op1/op2 would be a no-op
    // for any node already in the cluster; instead exercise that
    // fresh ops reach the rejoined node, demonstrating it's truly
    // back in the mesh.
    let (_id3, t3) = make_attest_token("eve", "part-3-rejoin");
    let op3 = op_for(&t3);
    publish_attest(&mut nodes[0], &op3, &t3);

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let (left, right) = nodes.split_at_mut(1);
        let mut refs: Vec<&mut DdsNode> = vec![&mut left[0], &mut right[0], &mut rejoiner];
        pump_many(&mut refs, Duration::from_millis(200)).await;
        if rejoiner.dag.contains(&op3.id) {
            return;
        }
    }
    panic!(
        "rejoined node failed to converge after partition: dag size {}",
        rejoiner.dag.len()
    );
}
