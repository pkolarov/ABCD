//! Interactive multinode FIDO2 end-to-end test.
//!
//! Spins up three in-process `DdsNode` instances (A / B / C) in a libp2p
//! mesh on loopback, binds an HTTP API for each, and walks a real
//! hardware FIDO2 key through:
//!
//!   TOUCH 1 — `makeCredential` against node A → `POST /v1/enroll/user`
//!             on A. Wait for the enrolment to gossip to B and C.
//!   TOUCH 2 — `getAssertion` against **node B** (a different node from
//!             enrolment) → `POST /v1/session/assert` on B. Validate the
//!             returned subject by issuing a `POST /v1/policy/evaluate`
//!             against **node C**.
//!   ── Disconnect node C from the mesh.
//!   ── Admin signs a `Revoke` token for the user's vouch and gossips it
//!      from node A. Confirm A and B see the revoke.
//!   ── Reconnect node C and let the request_response sync protocol
//!      catch it up. Confirm C now sees the revoke.
//!   TOUCH 3 — `getAssertion` against node C → `POST /v1/session/assert`
//!             on C **must fail** with "no granted purposes".
//!
//! Run:
//!     cargo run -p dds-fido2-test --bin dds-multinode-fido2-test --release
//!
//! Prerequisites: a FIDO2 authenticator plugged in (Crayonic KeyVault,
//! YubiKey, SoloKey, etc.).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use ctap_hid_fido2::{
    Cfg, FidoKeyHidFactory,
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier,
};
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_net::gossip::GossipMessage;
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::http;
use dds_node::node::DdsNode;
use dds_node::service::LocalService;
use dds_store::traits::{RevocationStore, TokenStore};
use futures::StreamExt;
use libp2p::Multiaddr;
use libp2p::swarm::SwarmEvent;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep, timeout};

const RP_ID: &str = "dds.local";
const ADMIN_LABEL: &str = "multinode-admin";
const MESH_FORMATION_TIMEOUT: Duration = Duration::from_secs(15);
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(20);
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

fn b64_std(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// ── HTTP request/response types (copied from dds-fido2-test/src/main.rs;
//    keeping them duplicated avoids exposing them as a public surface) ──

#[derive(Serialize)]
struct EnrollUserRequest {
    label: String,
    credential_id: String,
    attestation_object_b64: String,
    client_data_hash_b64: String,
    rp_id: String,
    display_name: String,
    authenticator_type: String,
}

#[derive(Deserialize, Debug)]
struct EnrollmentResponse {
    urn: String,
    #[allow(dead_code)]
    jti: String,
    #[allow(dead_code)]
    token_cbor_b64: String,
}

#[derive(Deserialize, Debug)]
struct ChallengeResponse {
    challenge_id: String,
    challenge_b64url: String,
    #[allow(dead_code)]
    expires_at: u64,
}

#[derive(Serialize)]
struct SessionAssertRequest {
    subject_urn: Option<String>,
    credential_id: String,
    challenge_id: String,
    client_data_hash: String,
    authenticator_data: String,
    signature: String,
    duration_secs: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct SessionResponse {
    #[allow(dead_code)]
    session_id: String,
    #[allow(dead_code)]
    token_cbor_b64: String,
    #[allow(dead_code)]
    expires_at: u64,
}

#[derive(Deserialize, Debug)]
struct EnrolledUsersResponse {
    users: Vec<EnrolledUser>,
}

#[derive(Deserialize, Debug)]
struct EnrolledUser {
    #[allow(dead_code)]
    subject_urn: String,
    #[allow(dead_code)]
    display_name: String,
    #[allow(dead_code)]
    credential_id: String,
}

// ─── CBOR builder for the makeCredential `attestationObject` we send
//     to /v1/enroll/user. Identical to dds-fido2-test/src/main.rs.

fn rebuild_attestation_cbor(
    fmt: &str,
    auth_data: &[u8],
    attstmt_alg: i32,
    attstmt_sig: &[u8],
    attstmt_x5c: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa3); // map(3): fmt, attStmt, authData
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, fmt);
    cbor_text(&mut out, "attStmt");
    if fmt == "none" || attstmt_sig.is_empty() {
        out.push(0xa0); // empty map
    } else if !attstmt_x5c.is_empty() {
        // Full packed attestation: alg + sig + x5c (chain of DER certs).
        // The server's verify_attestation tolerates x5c by skipping the
        // cert-chain check (Fido2Error::Format would fire if x5c were
        // missing from the CBOR but present logically — and the
        // signature would mismatch because it's signed by the
        // attestation-cert key, not the credential key).
        out.push(0xa3);
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, attstmt_alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, attstmt_sig);
        cbor_text(&mut out, "x5c");
        cbor_array_header(&mut out, attstmt_x5c.len());
        for cert in attstmt_x5c {
            cbor_bytes(&mut out, cert);
        }
    } else {
        // Self-attestation: alg + sig only.
        out.push(0xa2);
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, attstmt_alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, attstmt_sig);
    }
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

fn cbor_array_header(out: &mut Vec<u8>, len: usize) {
    if len < 24 {
        out.push(0x80 | len as u8);
    } else if len < 256 {
        out.push(0x98);
        out.push(len as u8);
    } else {
        out.push(0x99);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    let len = s.len();
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.push(len as u8);
    } else {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = b.len();
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len < 256 {
        out.push(0x58);
        out.push(len as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(b);
}

fn cbor_int(out: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        let v = val as u64;
        if v < 24 {
            out.push(v as u8);
        } else if v < 256 {
            out.push(0x18);
            out.push(v as u8);
        } else {
            out.push(0x19);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    } else {
        let v = (-1 - val) as u64;
        if v < 24 {
            out.push(0x20 | v as u8);
        } else if v < 256 {
            out.push(0x38);
            out.push(v as u8);
        } else {
            out.push(0x39);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    }
}

// ── In-process node setup ──────────────────────────────────────────

struct NodeHandle {
    node: DdsNode,
    _temp: TempDir,
    api_url: String,
    listen_addr: Multiaddr,
    peer_id: libp2p::PeerId,
}

/// Spin up one in-process node with the given trusted_roots + a known
/// admin self-attest pre-seeded into the store. Binds an HTTP API on a
/// random localhost port. Returns a handle holding the node, its temp
/// dir, and the URL the orchestrator should call.
async fn spawn_node(
    _name: &str,
    domain_key: &dds_domain::DomainKey,
    trusted_roots: &[String],
    admin_attest: &Token,
) -> Result<NodeHandle, Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().to_path_buf();

    // libp2p identity + admission cert (matches multinode.rs::spawn_node).
    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    dds_node::domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert)?;

    // Reserve a free port for the HTTP API. The OS may reuse it before
    // http::serve binds (race), but we only do this once at startup so
    // the window is microseconds.
    let api_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let api_addr = format!("127.0.0.1:{api_port}");

    let domain = domain_key.domain();
    let cfg = NodeConfig {
        data_dir,
        network: NetworkConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            bootstrap_peers: Vec::new(),
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: api_addr.clone(),
            api_auth: Default::default(),
            allow_legacy_v1_tokens: false,
        },
        // Same org_hash on every node — gossipsub topics are derived
        // from (domain_tag, org_hash), so giving each node a different
        // org_hash silently puts them on disjoint topics and the mesh
        // never forms. Suffixing with `name` was a copy-paste leftover
        // from per-node config.
        org_hash: "multinode-hw-shared".to_string(),
        domain: DomainConfig {
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
        trusted_roots: trusted_roots.to_vec(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };

    let mut node = DdsNode::init(cfg, p2p_keypair)?;

    // Pre-seed admin self-attest into the store. We deliberately do NOT
    // add it to the trust graph here — `LocalService::new` rehydrates
    // the graph from the store at HTTP-bind time, so adding it now
    // would surface as a duplicate-JTI warning during rehydrate.
    node.store.put_token(admin_attest)?;

    // Listen + subscribe (matches multinode.rs).
    node.swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    node.topics
        .subscribe_all(&mut node.swarm.behaviour_mut().gossipsub, false)?;

    // Drain swarm until we learn our listen address.
    let listen_addr = wait_for_listen(&mut node).await?;

    Ok(NodeHandle {
        node,
        _temp: temp,
        api_url: format!("http://{api_addr}"),
        listen_addr,
        peer_id,
    })
}

async fn wait_for_listen(node: &mut DdsNode) -> Result<Multiaddr, Box<dyn std::error::Error>> {
    let r = timeout(Duration::from_secs(5), async {
        loop {
            let event = node.swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    })
    .await?;
    Ok(r)
}

/// Star topology with single-direction dials A→B, A→C, B→C — matches
/// `multinode.rs::three_node_cluster` to dodge the simultaneous-dial race
/// in libp2p-tcp.
fn wire_mesh(handles: &mut [NodeHandle]) {
    assert_eq!(handles.len(), 3, "wire_mesh expects exactly three handles");
    // Take three disjoint mutable references via split_at_mut.
    let (left, right) = handles.split_at_mut(1);
    let a = &mut left[0];
    let (b_slice, c_slice) = right.split_at_mut(1);
    let b = &mut b_slice[0];
    let c = &mut c_slice[0];

    let a_addr_p = a.listen_addr.clone().with(libp2p::multiaddr::Protocol::P2p(a.peer_id));
    let b_addr_p = b.listen_addr.clone().with(libp2p::multiaddr::Protocol::P2p(b.peer_id));
    let c_addr_p = c.listen_addr.clone().with(libp2p::multiaddr::Protocol::P2p(c.peer_id));

    // A→B
    a.node.swarm.add_peer_address(b.peer_id, b_addr_p.clone());
    b.node.swarm.add_peer_address(a.peer_id, a_addr_p.clone());
    a.node.swarm.dial(b_addr_p.clone()).unwrap();

    // A→C
    a.node.swarm.add_peer_address(c.peer_id, c_addr_p.clone());
    c.node.swarm.add_peer_address(a.peer_id, a_addr_p);
    a.node.swarm.dial(c_addr_p.clone()).unwrap();

    // B→C
    b.node.swarm.add_peer_address(c.peer_id, c_addr_p.clone());
    c.node.swarm.add_peer_address(b.peer_id, b_addr_p);
    b.node.swarm.dial(c_addr_p).unwrap();

    // Gossipsub explicit_peer on initiator side only — see multinode.rs
    // for why this avoids the dial race.
    a.node.swarm.behaviour_mut().gossipsub.add_explicit_peer(&b.peer_id);
    a.node.swarm.behaviour_mut().gossipsub.add_explicit_peer(&c.peer_id);
    b.node.swarm.behaviour_mut().gossipsub.add_explicit_peer(&c.peer_id);
}

// ── HTTP serve binding ────────────────────────────────────────────

/// Build the LocalService for one node sharing its trust_graph + store
/// with the in-process DdsNode, then spawn the HTTP serve loop.
fn spawn_http(
    h: &NodeHandle,
    admin_attest: &Token,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use a synthetic node Identity — we never persist it; it's only used
    // to sign internally-issued tokens (e.g. session docs).
    let node_identity = Identity::generate("multinode-test-node", &mut OsRng);

    let mut svc = LocalService::new(
        node_identity,
        Arc::clone(&h.node.trust_graph),
        h.node.config.trusted_roots.iter().cloned().collect(),
        h.node.store.clone(),
    );
    svc.set_data_dir(h.node.config.data_dir.clone());

    // Re-seed via LocalService so its internal in-memory cache is in
    // sync with the trust graph (LocalService::new rehydrates from the
    // store, but our admin_attest may already be present — this is
    // idempotent).
    let _ = admin_attest;

    let shared_svc = Arc::new(tokio::sync::Mutex::new(svc));
    let info = http::NodeInfo {
        peer_id: h.node.peer_id.to_string(),
    };
    let admin_policy = http::AdminPolicy::from_config(&h.node.config.network.api_auth);
    let api_addr = h.node.config.network.api_addr.clone();

    tokio::spawn(async move {
        if let Err(e) =
            http::serve(&api_addr, shared_svc, info, admin_policy, None, None).await
        {
            eprintln!("HTTP serve error on {api_addr}: {e}");
        }
    });

    Ok(())
}

// ── Token construction (admin Identity-signed) ─────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_admin_self_attest(admin: &Identity) -> Token {
    let payload = TokenPayload {
        iss: admin.id.to_urn(),
        iss_key: admin.public_key.clone(),
        jti: format!("admin-attest-{:016x}", rand::random::<u64>()),
        sub: admin.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: Some("dds:admin".to_string()),
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: now_secs(),
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &admin.signing_key).expect("sign admin attest")
}

fn build_admin_vouch(admin: &Identity, subject_urn: &str, subject_attest: &Token) -> Token {
    let payload = TokenPayload {
        iss: admin.id.to_urn(),
        iss_key: admin.public_key.clone(),
        jti: format!("admin-vouch-{:016x}", rand::random::<u64>()),
        sub: subject_urn.to_string(),
        kind: TokenKind::Vouch,
        purpose: Some("dds:user".to_string()),
        vch_iss: Some(subject_urn.to_string()),
        // Bind to the specific user-attest token's payload hash —
        // `Token::sign` enforces both `vch_iss` and `vch_sum` are set
        // for `Vouch` (see TokenError::VouchMissingFields).
        vch_sum: Some(subject_attest.payload_hash()),
        revokes: None,
        iat: now_secs(),
        exp: Some(u64::MAX / 2),
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &admin.signing_key).expect("sign admin vouch")
}

fn build_admin_revoke(admin: &Identity, target_jti: &str) -> Token {
    let payload = TokenPayload {
        iss: admin.id.to_urn(),
        iss_key: admin.public_key.clone(),
        jti: format!("admin-revoke-{:016x}", rand::random::<u64>()),
        sub: admin.id.to_urn(),
        kind: TokenKind::Revoke,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: Some(target_jti.to_string()),
        iat: now_secs(),
        exp: None,
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &admin.signing_key).expect("sign admin revoke")
}

// ── Pump task + commands ──────────────────────────────────────────

enum PumpCmd {
    PublishVouch {
        node_idx: usize,
        token: Token,
    },
    PublishRevoke {
        node_idx: usize,
        token: Token,
    },
    Disconnect {
        node_idx: usize,
        peers: Vec<libp2p::PeerId>,
    },
    Reconnect {
        node_idx: usize,
        peers: Vec<(libp2p::PeerId, Multiaddr)>,
    },
    /// Force a sync request from `node_idx` to each `peer`, bypassing the
    /// per-peer cooldown. Used after Reconnect to nudge the sync
    /// protocol if the on-admission auto-sync didn't fire fast enough.
    ForceSync {
        node_idx: usize,
        peers: Vec<libp2p::PeerId>,
    },
    /// Snapshot whether each (subject_urn, expected_purpose) pair
    /// currently holds, plus revoke status for each given JTI, plus
    /// the live `swarm.connected_peers().count()` for the node.
    Snapshot {
        node_idx: usize,
        purposes: Vec<(String, String)>,
        revokes: Vec<String>,
        reply: oneshot::Sender<SnapshotResult>,
    },
    Shutdown,
}

#[derive(Default)]
struct SnapshotResult {
    purposes: BTreeMap<(String, String), bool>,
    revokes: BTreeMap<String, bool>,
    connected_peers: usize,
    admitted_peers: usize,
    attest_count: usize,
    /// Number of peers known (from gossipsub SUBSCRIBE messages) to
    /// be subscribed to the operations topic. With `add_explicit_peer`
    /// our peers are "direct" and never enter the gossipsub mesh —
    /// `mesh_peers()` would always read 0. `publish` still routes to
    /// direct peers, but only after SUBSCRIBE exchange tells us they
    /// hold the topic.
    mesh_peers_ops: usize,
}

async fn swarm_pump(mut nodes: Vec<NodeHandle>, mut rx: mpsc::Receiver<PumpCmd>) {
    let trusted_roots: BTreeSet<String> = nodes[0]
        .node
        .config
        .trusted_roots
        .iter()
        .cloned()
        .collect();

    loop {
        // Race: command arrival vs swarm event from any node.
        let cmd_fut = rx.recv();
        let mut event_futs: Vec<_> = nodes
            .iter_mut()
            .map(|h| Box::pin(h.node.swarm.select_next_some()))
            .collect();
        let event_race = futures::future::select_all(event_futs.iter_mut());

        tokio::select! {
            biased;
            cmd = cmd_fut => match cmd {
                Some(PumpCmd::PublishVouch { node_idx, token }) => {
                    drop(event_futs);
                    publish_vouch_or_revoke(&mut nodes[node_idx].node, &token);
                }
                Some(PumpCmd::PublishRevoke { node_idx, token }) => {
                    drop(event_futs);
                    publish_revoke(&mut nodes[node_idx].node, &token);
                }
                Some(PumpCmd::Disconnect { node_idx, peers }) => {
                    drop(event_futs);
                    for p in peers {
                        let _ = nodes[node_idx].node.swarm.disconnect_peer_id(p);
                    }
                }
                Some(PumpCmd::Reconnect { node_idx, peers }) => {
                    drop(event_futs);
                    for (pid, addr) in peers {
                        nodes[node_idx].node.swarm.add_peer_address(pid, addr.clone());
                        nodes[node_idx]
                            .node
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&pid);
                        let _ = nodes[node_idx].node.swarm.dial(addr);
                    }
                }
                Some(PumpCmd::ForceSync { node_idx, peers }) => {
                    drop(event_futs);
                    for p in peers {
                        nodes[node_idx].node.force_sync_with(p);
                    }
                }
                Some(PumpCmd::Snapshot { node_idx, purposes, revokes, reply }) => {
                    drop(event_futs);
                    let mut out = SnapshotResult::default();
                    out.connected_peers =
                        nodes[node_idx].node.swarm.connected_peers().count();
                    out.admitted_peers = nodes[node_idx].node.admitted_peers().len();
                    let ops_topic = nodes[node_idx].node.topics.operations.to_ident_topic();
                    let topic_hash = ops_topic.hash();
                    // Count peers we know are subscribed to the
                    // operations topic. With `add_explicit_peer` the
                    // peers are "direct" and never enter the mesh —
                    // `mesh_peers` would always be 0. `all_peers`
                    // returns subscription state from the exchanged
                    // SUBSCRIBE messages, which is what `publish`
                    // actually consults for direct peers.
                    out.mesh_peers_ops = nodes[node_idx]
                        .node
                        .swarm
                        .behaviour()
                        .gossipsub
                        .all_peers()
                        .filter(|(_, topics)| topics.iter().any(|t| **t == topic_hash))
                        .count();
                    let g = nodes[node_idx].node.trust_graph.read().unwrap();
                    out.attest_count = g.attestations_iter().count();
                    for (urn, want) in &purposes {
                        let p = g.purposes_for(urn, &trusted_roots);
                        out.purposes.insert((urn.clone(), want.clone()), p.contains(want));
                    }
                    for j in &revokes {
                        out.revokes.insert(j.clone(), g.is_revoked(j));
                    }
                    let _ = reply.send(out);
                }
                Some(PumpCmd::Shutdown) | None => return,
            },
            (event, idx, _) = event_race => {
                nodes[idx].node.handle_swarm_event(event);
            }
        }
    }
}

fn publish_vouch_or_revoke(node: &mut DdsNode, token: &Token) {
    // We don't have a meaningful Operation to bundle with a vouch, so we
    // build a tiny synthetic op so the gossip envelope (DirectoryOp) is
    // well-formed. multinode.rs::publish_attest does the same.
    use dds_core::crdt::causal_dag::Operation;
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
        token_bytes: token_bytes.clone(),
    };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.operations.to_ident_topic();
    if let Err(e) = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor) {
        eprintln!("  [pump] gossipsub.publish (DirectoryOp) failed: {e:?}");
    }
    // Mirror locally — gossipsub does not echo to the publisher.
    let _ = node.trust_graph.write().unwrap().add_token(token.clone());
    let _ = node.store.put_token(token);
    let _ = node.dag.insert(op.clone());
    // Seed the sync cache so a peer that connects later (or rejoins
    // after a disconnect) can pull this op via the request_response
    // sync protocol.
    node.cache_sync_payload(&op.id, &op, &token_bytes);
}

fn publish_revoke(node: &mut DdsNode, token: &Token) {
    let token_bytes = token.to_cbor().unwrap();
    let msg = GossipMessage::Revocation {
        token_bytes: token_bytes.clone(),
    };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.revocations.to_ident_topic();
    if let Err(e) = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor) {
        eprintln!("  [pump] gossipsub.publish (Revocation) failed: {e:?}");
    }
    let _ = node.trust_graph.write().unwrap().add_token(token.clone());
    if let Some(target) = token.payload.revokes.clone() {
        let _ = node.store.revoke(&target);
    }
    // Sync protocol delivers revocations too — seed the cache so a
    // freshly reconnected node can pull the revoke.
    use dds_core::crdt::causal_dag::Operation;
    let op = Operation {
        id: format!("op-{}", token.payload.jti),
        author: token.payload.iss.clone(),
        deps: Vec::new(),
        data: vec![1],
        timestamp: 0,
    };
    node.cache_sync_payload(&op.id, &op, &token_bytes);
}

// ── HTTP orchestration helpers ────────────────────────────────────

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
}

async fn wait_status_ready(urls: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let client = http_client();
    let deadline = Instant::now() + Duration::from_secs(15);
    for url in urls {
        loop {
            if Instant::now() > deadline {
                return Err(format!("status endpoint never came up: {url}").into());
            }
            if let Ok(r) = client.get(format!("{url}/v1/status")).send().await {
                if r.status().is_success() {
                    break;
                }
            }
            sleep(Duration::from_millis(150)).await;
        }
    }
    Ok(())
}

async fn diag_snapshot(
    cmd_tx: &mpsc::Sender<PumpCmd>,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for idx in 0..3 {
        let (tx, rx) = oneshot::channel();
        cmd_tx
            .send(PumpCmd::Snapshot {
                node_idx: idx,
                purposes: vec![],
                revokes: vec![],
                reply: tx,
            })
            .await?;
        let s = rx.await?;
        rows.push(format!(
            "    {:<4} connected={} admitted={} mesh_ops={} attestations={}",
            ["A", "B", "C"][idx],
            s.connected_peers,
            s.admitted_peers,
            s.mesh_peers_ops,
            s.attest_count
        ));
    }
    println!("  diag [{label}]:");
    for r in rows {
        println!("{r}");
    }
    Ok(())
}

/// Wait until every node has at least one gossipsub mesh peer for the
/// operations topic — required before `publish` will actually emit.
async fn wait_gossip_mesh(
    cmd_tx: &mpsc::Sender<PumpCmd>,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + MESH_FORMATION_TIMEOUT;
    loop {
        let mut all_ok = true;
        let mut counts = Vec::new();
        for idx in 0..3 {
            let (tx, rx) = oneshot::channel();
            cmd_tx
                .send(PumpCmd::Snapshot {
                    node_idx: idx,
                    purposes: vec![],
                    revokes: vec![],
                    reply: tx,
                })
                .await?;
            let s = rx.await?;
            counts.push(s.mesh_peers_ops);
            if s.mesh_peers_ops == 0 {
                all_ok = false;
            }
        }
        if all_ok {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "gossipsub mesh did not form within timeout — mesh_peers_ops per node: {counts:?}"
            )
            .into());
        }
        sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_mesh(
    cmd_tx: &mpsc::Sender<PumpCmd>,
    n_nodes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Query the swarm directly via the pump task — `/v1/status` reports
    // `connected_peers: 0` because the live count is never plumbed
    // through the HTTP service in production main.rs either.
    let deadline = Instant::now() + MESH_FORMATION_TIMEOUT;
    loop {
        let mut all_ok = true;
        let mut counts = Vec::with_capacity(n_nodes);
        for idx in 0..n_nodes {
            let (tx, rx) = oneshot::channel();
            cmd_tx
                .send(PumpCmd::Snapshot {
                    node_idx: idx,
                    purposes: vec![],
                    revokes: vec![],
                    reply: tx,
                })
                .await?;
            let snap = rx.await?;
            counts.push(snap.connected_peers);
            if snap.connected_peers < (n_nodes - 1) {
                all_ok = false;
            }
        }
        if all_ok {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "mesh failed to form within timeout — connected_peers per node: {counts:?}"
            )
            .into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_user_visible(urls: &[String]) -> Result<usize, Box<dyn std::error::Error>> {
    // /v1/enrolled-users requires a device_urn query param but the
    // service deliberately ignores it for filtering (see service.rs:
    // "the Credential Provider needs the full list ... filtering by
    // device would break the CP tile enumeration flow"). Pass a
    // placeholder so the route handler accepts the request.
    let client = http_client();
    let deadline = Instant::now() + PROPAGATION_TIMEOUT;
    let mut last = 0usize;
    loop {
        let mut all_ok = true;
        for url in urls {
            let r: EnrolledUsersResponse = client
                .get(format!("{url}/v1/enrolled-users"))
                .query(&[("device_urn", "urn:vch:placeholder")])
                .send()
                .await?
                .json()
                .await?;
            last = r.users.len();
            if r.users.is_empty() {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            return Ok(last);
        }
        if Instant::now() > deadline {
            return Err("user enrollment failed to propagate within timeout".into());
        }
        sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_purpose(
    cmd_tx: &mpsc::Sender<PumpCmd>,
    node_idxs: &[usize],
    urn: &str,
    purpose: &str,
    deadline_dur: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + deadline_dur;
    loop {
        let mut all_have = true;
        for &idx in node_idxs {
            let (tx, rx) = oneshot::channel();
            cmd_tx
                .send(PumpCmd::Snapshot {
                    node_idx: idx,
                    purposes: vec![(urn.to_string(), purpose.to_string())],
                    revokes: vec![],
                    reply: tx,
                })
                .await?;
            let snap = rx.await?;
            if !snap
                .purposes
                .get(&(urn.to_string(), purpose.to_string()))
                .copied()
                .unwrap_or(false)
            {
                all_have = false;
                break;
            }
        }
        if all_have {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "purpose {purpose} for {urn} did not propagate to nodes {node_idxs:?}"
            )
            .into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_revoke(
    cmd_tx: &mpsc::Sender<PumpCmd>,
    node_idxs: &[usize],
    jti: &str,
    deadline_dur: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + deadline_dur;
    let mut next_diag = Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_have = true;
        for &idx in node_idxs {
            let (tx, rx) = oneshot::channel();
            cmd_tx
                .send(PumpCmd::Snapshot {
                    node_idx: idx,
                    purposes: vec![],
                    revokes: vec![jti.to_string()],
                    reply: tx,
                })
                .await?;
            let snap = rx.await?;
            if !snap.revokes.get(jti).copied().unwrap_or(false) {
                all_have = false;
                break;
            }
        }
        if all_have {
            return Ok(());
        }
        if Instant::now() >= next_diag {
            diag_snapshot(cmd_tx, "wait_revoke tick").await?;
            next_diag = Instant::now() + Duration::from_secs(5);
        }
        if Instant::now() > deadline {
            diag_snapshot(cmd_tx, "wait_revoke FINAL").await?;
            return Err(format!(
                "revoke for vouch {jti} did not propagate to nodes {node_idxs:?}"
            )
            .into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

// ── HW touches ────────────────────────────────────────────────────

/// Print a "get ready, touch is coming" prompt, sleep for a fixed
/// `TOUCH_LEAD_SECS` window so the message has time to reach the
/// operator's terminal, then return — the caller fires the CTAP
/// command immediately afterward. This defends against the round-trip
/// between "binary prints prompt → orchestrator UI relays → operator
/// reacts" being longer than the device's CTAP user-interaction
/// timeout (~30 s on most authenticators).
async fn touch_prompt(label: &str) {
    use std::io::Write;
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ {label:^55} │");
    println!("  │ get ready — touch window opens in {TOUCH_LEAD_SECS}s        │");
    println!("  └─────────────────────────────────────────────────────────┘");
    let _ = std::io::stdout().flush();
    sleep(Duration::from_secs(TOUCH_LEAD_SECS)).await;
    println!("\n  >>> TOUCH YOUR FIDO2 KEY NOW <<<\n");
    let _ = std::io::stdout().flush();
}

const TOUCH_LEAD_SECS: u64 = 5;

/// Retry a FIDO call that can return `CTAP2_ERR_USER_ACTION_TIMEOUT`
/// (Crayonic KeyVault is occasionally flaky on `makeCredential`).
/// Re-prompts the operator and retries up to `max_attempts` total.
async fn retry_fido<T, E, F>(
    label: &str,
    max_attempts: usize,
    mut op: F,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    for attempt in 1..=max_attempts {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let msg = e.to_string();
                let is_timeout = msg.contains("USER_ACTION_TIMEOUT") || msg.contains("0x2F");
                eprintln!("\n  [!] {label} attempt {attempt}/{max_attempts} failed: {msg}");
                if attempt == max_attempts {
                    return Err(msg);
                }
                if is_timeout {
                    eprintln!("  [!] retrying — touch the key again");
                    sleep(Duration::from_millis(800)).await;
                } else {
                    return Err(msg);
                }
            }
        }
    }
    Err(format!("{label} exhausted retries"))
}


struct EnrolledHw {
    cred_id: Vec<u8>,
    user_urn: String,
    /// Server-issued user attestation token (CBOR). The HTTP
    /// `/v1/enroll/user` route stores it locally on node A but does
    /// NOT gossip it — production nodes don't auto-broadcast user
    /// attestations either. The orchestrator manually re-publishes
    /// this via `PumpCmd::PublishToken` so node B and C learn the
    /// credential before the assert step.
    user_attest_token: Token,
}

async fn touch_1_enroll(
    api: &str,
    device: &ctap_hid_fido2::FidoKeyHid,
) -> Result<EnrolledHw, Box<dyn std::error::Error>> {
    touch_prompt("TOUCH 1 — enrollment / makeCredential").await;

    // KeyVault occasionally returns CTAP2_ERR_USER_ACTION_TIMEOUT even
    // when the user did touch — auto-retry up to 3 times before giving
    // up. Re-emit the prompt on each retry so the operator knows
    // another touch is expected.
    let challenge = verifier::create_challenge();
    let make_args = MakeCredentialArgsBuilder::new(RP_ID, &challenge).build();
    let attestation = retry_fido("makeCredential", 3, || {
        device.make_credential_with_args(&make_args)
    })
    .await
    .map_err(|e| format!("makeCredential failed after retries: {e}"))?;

    let verify = verifier::verify_attestation(RP_ID, &challenge, &attestation);
    if !verify.is_success {
        return Err("local attestation verification failed".into());
    }

    let cred_id = verify.credential_id.clone();
    let attobj = rebuild_attestation_cbor(
        &attestation.fmt,
        &attestation.auth_data,
        attestation.attstmt_alg,
        &attestation.attstmt_sig,
        &attestation.attstmt_x5c,
    );
    let cdh = challenge.clone();

    let user_label = format!("multinode-user-{:08x}", rand::random::<u32>());
    let req = EnrollUserRequest {
        label: user_label.clone(),
        credential_id: b64url(&cred_id),
        attestation_object_b64: b64_std(&attobj),
        client_data_hash_b64: b64_std(&cdh),
        rp_id: RP_ID.to_string(),
        display_name: format!("Multinode HW Test ({user_label})"),
        authenticator_type: "cross-platform".to_string(),
    };
    let resp = http_client()
        .post(format!("{api}/v1/enroll/user"))
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("enroll failed: {s} — {body}").into());
    }
    let enrolled: EnrollmentResponse = resp.json().await?;
    let token_cbor = base64::engine::general_purpose::STANDARD
        .decode(&enrolled.token_cbor_b64)
        .map_err(|e| format!("decode user attest token: {e}"))?;
    let user_attest_token =
        Token::from_cbor(&token_cbor).map_err(|e| format!("parse user attest token: {e}"))?;
    Ok(EnrolledHw {
        cred_id,
        user_urn: enrolled.urn,
        user_attest_token,
    })
}

async fn fido_assert(
    device: &ctap_hid_fido2::FidoKeyHid,
    api: &str,
    cred_id: &[u8],
) -> Result<(String, Vec<u8>, Vec<u8>, [u8; 32]), Box<dyn std::error::Error>> {
    let chal: ChallengeResponse = http_client()
        .get(format!("{api}/v1/session/challenge"))
        .send()
        .await?
        .json()
        .await?;
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}"}}"#,
        chal.challenge_b64url, RP_ID
    );
    // The cdh the server expects (and the device must sign) is
    // SHA-256(clientDataJSON). ctap-hid-fido2's GetAssertion API
    // takes the *raw* challenge and hashes it internally before
    // wiring it to the CTAP2 command — so we MUST pass
    // clientDataJSON itself (not the pre-hashed cdh) here, otherwise
    // the device signs over SHA-256(cdh) and the server's verify
    // disagrees by one hash round.
    let cdj_bytes = client_data_json.as_bytes();
    let cdh: [u8; 32] = Sha256::digest(cdj_bytes).into();

    touch_prompt("assertion / getAssertion").await;

    let args = GetAssertionArgsBuilder::new(RP_ID, cdj_bytes)
        .credential_id(cred_id)
        .build();
    let assertions = retry_fido("getAssertion", 3, || {
        device.get_assertion_with_args(&args)
    })
    .await
    .map_err(|e| format!("getAssertion failed after retries: {e}"))?;
    let a = assertions
        .into_iter()
        .next()
        .ok_or("getAssertion returned no assertions")?;
    Ok((chal.challenge_id, a.auth_data, a.signature, cdh))
}

async fn touch_2_assert(
    api: &str,
    device: &ctap_hid_fido2::FidoKeyHid,
    cred_id: &[u8],
    user_urn: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (challenge_id, auth_data, signature, cdh) = fido_assert(device, api, cred_id).await?;
    let req = SessionAssertRequest {
        subject_urn: Some(user_urn.to_string()),
        credential_id: b64url(cred_id),
        challenge_id,
        client_data_hash: b64_std(&cdh),
        authenticator_data: b64_std(&auth_data),
        signature: b64_std(&signature),
        duration_secs: Some(3600),
    };
    let resp = http_client()
        .post(format!("{api}/v1/session/assert"))
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("assertion failed: {s} — {body}").into());
    }
    let _session: SessionResponse = resp.json().await?;
    Ok(())
}

async fn touch_3_assert_must_fail(
    api: &str,
    device: &ctap_hid_fido2::FidoKeyHid,
    cred_id: &[u8],
    user_urn: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (challenge_id, auth_data, signature, cdh) = fido_assert(device, api, cred_id).await?;
    let req = SessionAssertRequest {
        subject_urn: Some(user_urn.to_string()),
        credential_id: b64url(cred_id),
        challenge_id,
        client_data_hash: b64_std(&cdh),
        authenticator_data: b64_std(&auth_data),
        signature: b64_std(&signature),
        duration_secs: Some(3600),
    };
    let resp = http_client()
        .post(format!("{api}/v1/session/assert"))
        .json(&req)
        .send()
        .await?;
    if resp.status().is_success() {
        return Err("assertion unexpectedly SUCCEEDED after revoke".into());
    }
    // The HTTP layer maps service errors to opaque codes (L-9 in the
    // security review): `auth_failed` / `permission_denied` /
    // `invalid_input` — the per-finding detail only appears in
    // server-side tracing. We saw the correct behaviour in practice:
    //   "domain error: subject has no granted purposes; cannot issue
    //    session" → HTTP 400 with {"error":"invalid_input"}.
    // That's the expected shape after the revoke took effect.
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    println!("  → server rejected: HTTP {status} — {}", body.trim());
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread", worker_threads = 6)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    println!("=== DDS Multinode FIDO2 E2E (in-process 3-node mesh) ===\n");

    // Pre-create admin Identity and self-attest. Trusted by all 3 nodes.
    let admin = Identity::generate(ADMIN_LABEL, &mut OsRng);
    let admin_attest = build_admin_self_attest(&admin);
    println!("Admin URN (trusted root on all 3 nodes): {}", admin.id.to_urn());

    // Shared domain (deterministic per run — 32 zero bytes XOR'd with run id).
    let domain_key =
        dds_domain::DomainKey::from_secret_bytes("multinode-hw", [42u8; 32]);
    println!("Domain: {} ({})", domain_key.domain().name, domain_key.domain().id);

    // Spawn 3 nodes.
    let trusted_roots = vec![admin.id.to_urn()];
    let mut handles = Vec::with_capacity(3);
    for i in 0..3 {
        let h = spawn_node(
            &format!("node-{i}"),
            &domain_key,
            &trusted_roots,
            &admin_attest,
        )
        .await?;
        println!(
            "Node {} listening on {} — HTTP {}",
            ["A", "B", "C"][i],
            h.listen_addr,
            h.api_url
        );
        handles.push(h);
    }

    // Wire star mesh + start HTTP servers.
    wire_mesh(&mut handles);
    for h in &handles {
        spawn_http(h, &admin_attest)?;
    }
    let urls: Vec<String> = handles.iter().map(|h| h.api_url.clone()).collect();

    // Remember each node's address book entry for later reconnect.
    let peer_addrs: Vec<(libp2p::PeerId, Multiaddr)> = handles
        .iter()
        .map(|h| {
            let addr = h
                .listen_addr
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(h.peer_id));
            (h.peer_id, addr)
        })
        .collect();

    // Hand nodes off to the swarm pump task.
    let (cmd_tx, cmd_rx) = mpsc::channel::<PumpCmd>(16);
    let pump = tokio::spawn(swarm_pump(handles, cmd_rx));

    // ── Wait for HTTP + mesh to be live ─────────────────────────────
    println!("\nWaiting for HTTP + mesh ...");
    wait_status_ready(&urls).await?;
    wait_mesh(&cmd_tx, 3).await?;
    println!("  ✓ all 3 nodes report connected_peers >= 2");
    diag_snapshot(&cmd_tx, "post-mesh").await?;
    println!("\nWaiting for gossipsub topic mesh to form ...");
    wait_gossip_mesh(&cmd_tx).await?;
    diag_snapshot(&cmd_tx, "post-gossip-mesh").await?;
    println!("  ✓ gossipsub mesh formed for operations topic");

    // ── Open FIDO2 device once ──────────────────────────────────────
    println!("\nOpening FIDO2 authenticator ...");
    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| format!("open FIDO2 device failed: {e}"))?;
    println!("  ✓ device opened");

    // ── TOUCH 1 ─────────────────────────────────────────────────────
    println!("\n[TOUCH 1] Enrol user via node A");
    let enrolled = touch_1_enroll(&urls[0], &device).await?;
    println!("  ✓ enrolled — user URN = {}", enrolled.user_urn);

    // The HTTP enroll route stores the attestation locally on node A
    // only. Manually re-broadcast via gossip so B and C learn the
    // credential before the assert step. (Production nodes that own
    // the device's enrollment behave the same way; cross-node
    // session issuance from a single physical key is a test-specific
    // demonstration.)
    println!("Re-broadcasting user attestation via node A gossip ...");
    diag_snapshot(&cmd_tx, "before publish").await?;
    cmd_tx
        .send(PumpCmd::PublishVouch {
            node_idx: 0,
            token: enrolled.user_attest_token.clone(),
        })
        .await?;

    // Wait for B and C to see the enrolled user via gossip.
    println!("Waiting for enrollment to gossip to B + C ...");
    let res = wait_user_visible(&urls[1..]).await;
    diag_snapshot(&cmd_tx, "after publish").await?;
    res?;
    println!("  ✓ user visible on B and C");

    // ── Inject admin vouch (Identity-signed, no touch) ──────────────
    println!("\nAdmin issues vouch granting dds:user (Identity-signed, no touch)");
    let vouch = build_admin_vouch(&admin, &enrolled.user_urn, &enrolled.user_attest_token);
    let vouch_jti = vouch.payload.jti.clone();
    cmd_tx
        .send(PumpCmd::PublishVouch {
            node_idx: 0,
            token: vouch,
        })
        .await?;
    wait_purpose(&cmd_tx, &[0, 1, 2], &enrolled.user_urn, "dds:user", PROPAGATION_TIMEOUT).await?;
    println!("  ✓ vouch propagated — purposes_for(user) contains dds:user on all 3 nodes");

    // ── TOUCH 2 ─────────────────────────────────────────────────────
    println!("\n[TOUCH 2] Assert against node B (different node from enrollment)");
    touch_2_assert(&urls[1], &device, &enrolled.cred_id, &enrolled.user_urn).await?;
    println!("  ✓ session issued by node B");

    // Cross-node validation: ask node-C if the user has dds:user.
    let (tx, rx) = oneshot::channel();
    cmd_tx
        .send(PumpCmd::Snapshot {
            node_idx: 2,
            purposes: vec![(enrolled.user_urn.clone(), "dds:user".to_string())],
            revokes: vec![],
            reply: tx,
        })
        .await?;
    let snap = rx.await?;
    let c_has = snap
        .purposes
        .get(&(enrolled.user_urn.clone(), "dds:user".to_string()))
        .copied()
        .unwrap_or(false);
    if !c_has {
        return Err("node C should have dds:user purpose for the user".into());
    }
    println!("  ✓ node C also grants dds:user → cross-node consistency confirmed");

    // ── Disconnect node C ───────────────────────────────────────────
    println!("\n[Disconnect] node C ⊘ A,B");
    let other_peers: Vec<libp2p::PeerId> = peer_addrs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, (pid, _))| *pid)
        .collect();
    cmd_tx
        .send(PumpCmd::Disconnect {
            node_idx: 2,
            peers: other_peers.clone(),
        })
        .await?;
    // Also disconnect from A and B's side so the partition is real.
    for src in [0usize, 1] {
        cmd_tx
            .send(PumpCmd::Disconnect {
                node_idx: src,
                peers: vec![peer_addrs[2].0],
            })
            .await?;
    }
    sleep(Duration::from_millis(800)).await; // let SwarmEvent::ConnectionClosed flush

    // ── Revoke the vouch on A while C is offline ────────────────────
    println!("[Revoke] admin signs Revoke({vouch_jti}) → publish via node A");
    let revoke = build_admin_revoke(&admin, &vouch_jti);
    cmd_tx
        .send(PumpCmd::PublishRevoke {
            node_idx: 0,
            token: revoke,
        })
        .await?;
    // A and B should see the revoke via gossip.
    wait_revoke(&cmd_tx, &[0, 1], &vouch_jti, PROPAGATION_TIMEOUT).await?;
    println!("  ✓ revoke visible on A and B (C is partitioned)");

    // Confirm C does NOT have the revoke yet.
    let (tx, rx) = oneshot::channel();
    cmd_tx
        .send(PumpCmd::Snapshot {
            node_idx: 2,
            purposes: vec![],
            revokes: vec![vouch_jti.clone()],
            reply: tx,
        })
        .await?;
    let snap = rx.await?;
    if snap.revokes.get(&vouch_jti).copied().unwrap_or(false) {
        return Err("node C unexpectedly has the revoke while disconnected".into());
    }
    println!("  ✓ node C still missing the revoke (as expected)");

    // ── Reconnect node C ─────────────────────────────────────────────
    println!("[Reconnect] node C ⇄ A,B — sync protocol must catch C up");
    let reconnect_peers: Vec<(libp2p::PeerId, Multiaddr)> = peer_addrs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, p)| p.clone())
        .collect();
    cmd_tx
        .send(PumpCmd::Reconnect {
            node_idx: 2,
            peers: reconnect_peers.clone(),
        })
        .await?;
    // Give the H-12 admission handshake a couple of seconds to land,
    // then nudge the sync protocol from BOTH sides — if the on-
    // admission auto-sync raced with disconnect cleanup, this kicks
    // it again. force_sync_with bypasses the 15 s per-peer cooldown.
    sleep(Duration::from_secs(3)).await;
    let other_peer_ids: Vec<libp2p::PeerId> =
        reconnect_peers.iter().map(|(p, _)| *p).collect();
    cmd_tx
        .send(PumpCmd::ForceSync {
            node_idx: 2,
            peers: other_peer_ids,
        })
        .await?;
    for src in [0usize, 1] {
        cmd_tx
            .send(PumpCmd::ForceSync {
                node_idx: src,
                peers: vec![peer_addrs[2].0],
            })
            .await?;
    }

    wait_revoke(&cmd_tx, &[2], &vouch_jti, SYNC_TIMEOUT).await?;
    println!("  ✓ revoke arrived on C via sync protocol");

    // ── TOUCH 3 ─────────────────────────────────────────────────────
    println!("\n[TOUCH 3] Assert against node C — must FAIL after revoke");
    touch_3_assert_must_fail(&urls[2], &device, &enrolled.cred_id, &enrolled.user_urn).await?;
    println!("  ✓ node C correctly refused session issuance");

    // ── Cleanup ─────────────────────────────────────────────────────
    let _ = cmd_tx.send(PumpCmd::Shutdown).await;
    let _ = pump.await;

    println!("\n=== ALL CHECKS PASSED ===");
    println!("\nFlow demonstrated end-to-end with real hardware:");
    println!("  - Enrollment on node A → gossip propagated user to B and C");
    println!("  - Assertion on node B (different node from enrollment) → session issued");
    println!("  - Cross-node trust graph consistency (A=B=C all granted dds:user)");
    println!("  - Disconnect C → revoke vouch from A → A,B see it, C does not");
    println!("  - Reconnect C → request_response sync protocol delivered the revoke");
    println!("  - Assertion on C correctly rejected after revoke");

    Ok(())
}
