//! Phase A2 H-12 admission integration tests.
//!
//! Exercises the challenge-response step added in Phase A2
//! (`hardware-bound-admission-plan.md` §12 "H-12 integration tests").
//!
//! Covered scenarios:
//!
//! 1. **Positive — v2-cert handshake**: two nodes with v2 admission certs
//!    (SoftwareKeyfile backend) mutually admit each other and gossip flows
//!    through the production ingest path.
//!
//! 2. **Positive — v1 cert, `allow_v1_certs = true`**: v1 certs (no
//!    `admission_pubkey`) are accepted during the migration window.
//!
//! 3. **Negative — v1 cert, `allow_v1_certs = false`**: once the migration
//!    window closes, a peer presenting a v1 cert is rejected by a node
//!    configured with `allow_v1_certs = false`.
//!
//! 4. **Negative — clone attack**: an attacker who steals `p2p_key.bin +
//!    admission.cbor` but not the hardware-bound admission key cannot pass
//!    the H-12 challenge-response. Simulated with SoftwareKeyfile: the clone
//!    gets a different `admission_key.bin` than the one whose pubkey is
//!    embedded in the cert.

use std::time::Duration;

use dds_core::key_provider::KeyProvider;
use dds_node::config::{NetworkConfig, NodeConfig};
use dds_node::node::DdsNode;
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use tempfile::TempDir;
use tokio::time::{Instant, timeout};

const ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(5);

fn run_in_bounded_rt<F>(test: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(test);
    }));
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

/// Build a minimal `NodeConfig` rooted at `data_dir` with `allow_v1_certs`
/// as specified.
fn make_config(
    data_dir: std::path::PathBuf,
    org: &str,
    domain: &dds_domain::Domain,
    allow_v1_certs: bool,
) -> NodeConfig {
    NodeConfig {
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
            allow_v1_certs,
        },
        org_hash: org.to_string(),
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
    }
}

/// Spawn a node with a **v2 admission cert** (carries `admission_pubkey`).
///
/// Pre-creates `admission_key.bin` in `data_dir` using `SoftwareKeyfile` so
/// `DdsNode::init` picks up the same key. Issues a v2 cert embedding the
/// SoftwareKeyfile's public key. Challenge-response will succeed for this
/// node because the key in `admission_key.bin` matches the cert's pubkey.
async fn spawn_v2(
    domain_key: &dds_domain::DomainKey,
    org: &str,
    allow_v1_certs: bool,
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

    // Pre-create the admission key so DdsNode::init loads this exact key.
    let admission_key_path = data_dir.join("admission_key.bin");
    let kp = dds_node::key_provider::SoftwareKeyfile::load_or_create(&admission_key_path).unwrap();
    let admission_pubkey = kp.public_key();

    // Issue a v2 cert carrying the admission public key.
    let cert =
        domain_key.issue_admission_v2(peer_id.to_string(), now, None, None, Some(admission_pubkey));
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

    let cfg = make_config(data_dir, org, &domain, allow_v1_certs);
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init v2 node");
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

/// Spawn a node with a **v1 admission cert** (no `admission_pubkey`).
///
/// Matches the legacy `spawn_with_domain` from `h12_admission.rs` but
/// accepts an explicit `allow_v1_certs` flag.
async fn spawn_v1(
    domain_key: &dds_domain::DomainKey,
    org: &str,
    allow_v1_certs: bool,
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

    // v1 cert — no admission_pubkey.
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

    let cfg = make_config(data_dir, org, &domain, allow_v1_certs);
    let mut node = DdsNode::init(cfg, p2p_keypair).expect("init v1 node");
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)
        .unwrap();
    (node, dir)
}

/// Spawn a **clone** node: same p2p keypair + same v2 cert as the original,
/// but a DIFFERENT `admission_key.bin`. Simulates the attacker scenario where
/// `p2p_key.bin` and `admission.cbor` are stolen but the hardware-bound
/// admission key cannot be exfiltrated.
///
/// The clone's `DdsNode::init` will create a new random `SoftwareKeyfile`
/// at the clone's `admission_key.bin` (different key than the cert's pubkey),
/// so challenge-response will fail when any peer verifies it.
async fn spawn_clone(
    domain_key: &dds_domain::DomainKey,
    org: &str,
    stolen_keypair: libp2p::identity::Keypair,
    stolen_cert: dds_domain::AdmissionCert,
) -> (DdsNode, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let domain = domain_key.domain();

    // The clone has the stolen cert — save it to disk.
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &stolen_cert)
        .unwrap();
    // Do NOT pre-create admission_key.bin — DdsNode::init will generate a
    // fresh random SoftwareKeyfile that does NOT match the cert's pubkey.

    let cfg = make_config(data_dir, org, &domain, true);
    let mut node = DdsNode::init(cfg, stolen_keypair).expect("init clone node");
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

/// **Positive — v2 certs**: two nodes with v2 admission certs
/// (SoftwareKeyfile) complete the challenge-response step and mutually admit
/// each other.
#[test]
fn v2_certs_admitted() {
    run_in_bounded_rt(async {
        v2_certs_admitted_inner().await;
    });
}

async fn v2_certs_admitted_inner() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [11u8; 32]);

    let telemetry = dds_node::telemetry::install();
    let ok_before = telemetry.admission_handshakes_count("ok");

    let (mut a, _ad) = spawn_v2(&dkey, "h12-v2-ok", true).await;
    let (mut b, _bd) = spawn_v2(&dkey, "h12-v2-ok", true).await;
    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);
    a.swarm.behaviour_mut().gossipsub.add_explicit_peer(&b_pid);

    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |a, b| {
        a.admitted_peers().contains(&b_pid) && b.admitted_peers().contains(&a_pid)
    })
    .await;

    assert!(
        a.admitted_peers().contains(&b_pid),
        "A never admitted B (v2 cert): {:?}",
        a.admitted_peers()
    );
    assert!(
        b.admitted_peers().contains(&a_pid),
        "B never admitted A (v2 cert): {:?}",
        b.admitted_peers()
    );

    let ok_after = telemetry.admission_handshakes_count("ok");
    assert!(
        ok_after >= ok_before + 2,
        "admission_handshakes_total{{result=ok}} delta={} (expected ≥2)",
        ok_after - ok_before
    );
}

/// **Positive — v1 cert, `allow_v1_certs = true`**: nodes with legacy v1
/// certs are admitted during the migration window.
#[test]
fn v1_cert_allowed_when_flag_true() {
    run_in_bounded_rt(async {
        v1_cert_allowed_when_flag_true_inner().await;
    });
}

async fn v1_cert_allowed_when_flag_true_inner() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [22u8; 32]);

    let (mut a, _ad) = spawn_v1(&dkey, "h12-v1-allow", true).await;
    let (mut b, _bd) = spawn_v1(&dkey, "h12-v1-allow", true).await;
    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);

    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |a, b| {
        a.admitted_peers().contains(&b_pid) && b.admitted_peers().contains(&a_pid)
    })
    .await;

    assert!(
        a.admitted_peers().contains(&b_pid),
        "A never admitted B (v1 cert, allow=true): {:?}",
        a.admitted_peers()
    );
    assert!(
        b.admitted_peers().contains(&a_pid),
        "B never admitted A (v1 cert, allow=true): {:?}",
        b.admitted_peers()
    );
}

/// **Negative — v1 cert, `allow_v1_certs = false`**: once the migration
/// window closes, a v1 cert is rejected by a node with `allow_v1_certs =
/// false`.
///
/// Node A has `allow_v1_certs = false`; node B presents a v1 cert. A must
/// NOT admit B.
#[test]
fn v1_cert_rejected_when_flag_false() {
    run_in_bounded_rt(async {
        v1_cert_rejected_when_flag_false_inner().await;
    });
}

async fn v1_cert_rejected_when_flag_false_inner() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [33u8; 32]);

    let telemetry = dds_node::telemetry::install();
    let fail_before = telemetry.admission_handshakes_count("fail");

    // A is strict (post-migration); B uses a legacy v1 cert.
    let (mut a, _ad) = spawn_v2(&dkey, "h12-v1-reject", false).await;
    let (mut b, _bd) = spawn_v1(&dkey, "h12-v1-reject", true).await;
    let a_addr = wait_for_listen(&mut a).await;
    let b_addr = wait_for_listen(&mut b).await;
    let a_pid = a.peer_id;
    let b_pid = b.peer_id;

    connect_one_sided(&mut a, a_pid, a_addr, &mut b, b_pid, b_addr);

    // Allow enough time for the handshake to run.
    pump_until(&mut a, &mut b, ADMISSION_TIMEOUT, |_, _| false).await;

    assert!(
        !a.admitted_peers().contains(&b_pid),
        "A admitted B despite v1 cert and allow_v1_certs=false: {:?}",
        a.admitted_peers()
    );

    let fail_after = telemetry.admission_handshakes_count("fail");
    assert!(
        fail_after > fail_before,
        "admission_handshakes_total{{result=fail}} did not advance (before={} after={})",
        fail_before,
        fail_after
    );
}

/// **Negative — clone attack**: an attacker who steals `p2p_key.bin +
/// admission.cbor` but cannot exfiltrate the hardware admission key is
/// rejected at H-12.
///
/// The clone gets the original p2p keypair and v2 cert (cert embeds
/// `pubkey_A`), but its `DdsNode::init` generates a fresh random
/// `SoftwareKeyfile` (`key_B ≠ key_A`). When the verifier sends a
/// challenge, the clone signs with key_B but the cert says pubkey_A →
/// verification fails → clone is not admitted.
#[test]
fn clone_attack_rejected() {
    run_in_bounded_rt(async {
        clone_attack_rejected_inner().await;
    });
}

async fn clone_attack_rejected_inner() {
    let _ = tracing_subscriber::fmt::try_init();
    let dkey = dds_domain::DomainKey::from_secret_bytes("test.local", [44u8; 32]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Use a fixed seed so we can produce two Keypair instances with the
    // same peer_id (simulating "stolen" key bytes vs. "clone using the
    // same bytes"). Each call to ed25519_from_bytes zeroes its own copy.
    let stolen_seed_a: [u8; 32] = [0xABu8; 32];
    let stolen_seed_b: [u8; 32] = [0xABu8; 32];

    // Derive the peer_id that will go into the stolen cert.
    let original_keypair = libp2p::identity::Keypair::ed25519_from_bytes(stolen_seed_a).unwrap();
    let stolen_peer_id = libp2p::PeerId::from(original_keypair.public());

    // Generate the admission key the original would have had (key_A).
    // We only need the pubkey to embed in the cert; we never run a node
    // that actually uses key_A.
    let original_admission_dir = tempfile::tempdir().unwrap();
    let original_admission_key_path = original_admission_dir.path().join("admission_key.bin");
    let original_kp =
        dds_node::key_provider::SoftwareKeyfile::load_or_create(&original_admission_key_path)
            .unwrap();
    let original_admission_pubkey = original_kp.public_key();

    // Issue a v2 cert that embeds pubkey_A — this is the "stolen" cert.
    let stolen_cert = dkey.issue_admission_v2(
        stolen_peer_id.to_string(),
        now,
        None,
        None,
        Some(original_admission_pubkey),
    );

    // The clone uses the second instance of the stolen keypair (same peer_id)
    // plus the stolen cert, but DdsNode::init will auto-generate a FRESH
    // admission_key.bin (key_B ≠ key_A) in its own data dir.
    let clone_keypair = libp2p::identity::Keypair::ed25519_from_bytes(stolen_seed_b).unwrap();
    let (mut clone_node, _clone_dir) =
        spawn_clone(&dkey, "h12-clone", clone_keypair, stolen_cert).await;

    // --- Set up the verifier (honest peer with a valid v2 cert). ---
    let (mut verifier, _vd) = spawn_v2(&dkey, "h12-clone", true).await;

    let clone_addr = wait_for_listen(&mut clone_node).await;
    let verifier_addr = wait_for_listen(&mut verifier).await;
    let verifier_pid = verifier.peer_id;
    let clone_pid = clone_node.peer_id;

    // Connect verifier → clone so the verifier attempts to verify the clone.
    connect_one_sided(
        &mut verifier,
        verifier_pid,
        verifier_addr,
        &mut clone_node,
        clone_pid,
        clone_addr,
    );

    pump_until(&mut verifier, &mut clone_node, ADMISSION_TIMEOUT, |_, _| {
        false
    })
    .await;

    assert!(
        !verifier.admitted_peers().contains(&clone_pid),
        "verifier admitted clone despite mismatched admission key: {:?}",
        verifier.admitted_peers()
    );

    // Gossip from the clone must not land in the verifier's trust graph.
    use dds_core::crdt::causal_dag::Operation;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_net::gossip::GossipMessage;

    let id = Identity::generate("mallory", &mut rand::rngs::OsRng);
    let payload = TokenPayload {
        iss: id.id.to_urn(),
        iss_key: id.public_key.clone(),
        jti: "att-clone".to_string(),
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
    let token = Token::sign(payload, &id.signing_key).unwrap();
    let op = Operation {
        id: format!("op-{}", token.payload.jti),
        author: token.payload.iss.clone(),
        deps: Vec::new(),
        data: vec![0],
        timestamp: 0,
    };
    let mut op_bytes = Vec::new();
    ciborium::into_writer(&op, &mut op_bytes).unwrap();
    let token_bytes = token.to_cbor().unwrap();
    let msg = GossipMessage::DirectoryOp {
        op_bytes,
        token_bytes,
    };
    let topic = clone_node.topics.operations.to_ident_topic();
    let _ = clone_node.publish_gossip_op(topic, msg);

    pump_until(
        &mut verifier,
        &mut clone_node,
        PROPAGATION_TIMEOUT,
        |_, _| false,
    )
    .await;

    let attestations = verifier
        .trust_graph
        .read()
        .unwrap()
        .attestations_iter()
        .count();
    assert_eq!(
        attestations, 0,
        "verifier ingested gossip from clone (clone attack not blocked)"
    );
}
