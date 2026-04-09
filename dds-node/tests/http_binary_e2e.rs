use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use dds_core::crdt::causal_dag::Operation;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_domain::fido2::build_none_attestation;
use dds_domain::{DeviceJoinDocument, DomainDocument, SessionDocument, UserAuthAttestation};
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::domain_store;
use dds_node::http::{
    EnrollDeviceRequestJson, EnrollUserRequestJson, EnrollmentResponse, PolicyRequestJson,
    SessionRequestJson, SessionResponse,
};
use dds_node::node::DdsNode;
use dds_node::p2p_identity;
use dds_node::service::{NodeStatus, PolicyResult};
use dds_store::traits::TokenStore;
use dds_store::RedbBackend;
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId, Swarm};
use rand::rngs::OsRng;
use reqwest::Client;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn make_attest(identity: &Identity, jti: &str) -> Token {
    Token::sign(
        TokenPayload {
            iss: identity.id.to_urn(),
            iss_key: identity.public_key.clone(),
            jti: jti.to_string(),
            sub: identity.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_000,
            exp: Some(u64::MAX / 2),
            body_type: None,
            body_cbor: None,
        },
        &identity.signing_key,
    )
    .unwrap()
}

fn make_vouch(
    voucher: &Identity,
    subject: &Identity,
    subject_token: &Token,
    purpose: &str,
    jti: &str,
) -> Token {
    Token::sign(
        TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: jti.to_string(),
            sub: subject.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(purpose.to_string()),
            vch_iss: Some(subject.id.to_urn()),
            vch_sum: Some(subject_token.payload_hash()),
            revokes: None,
            iat: 1_001,
            exp: Some(u64::MAX / 2),
            body_type: None,
            body_cbor: None,
        },
        &voucher.signing_key,
    )
    .unwrap()
}

fn make_revoke(revoker: &Identity, target_jti: &str, jti: &str) -> Token {
    Token::sign(
        TokenPayload {
            iss: revoker.id.to_urn(),
            iss_key: revoker.public_key.clone(),
            jti: jti.to_string(),
            sub: revoker.id.to_urn(),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(target_jti.to_string()),
            iat: 1_002,
            exp: None,
            body_type: None,
            body_cbor: None,
        },
        &revoker.signing_key,
    )
    .unwrap()
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

fn seed_store(db_path: &Path, tokens: &[Token]) {
    let mut store = RedbBackend::open(db_path).unwrap();
    for token in tokens {
        store.put_token(token).unwrap();
    }
}

struct NodeFixture {
    _dir: TempDir,
    config_path: PathBuf,
    db_path: PathBuf,
    api_url: String,
    listen_addr: String,
    peer_id: PeerId,
}

impl NodeFixture {
    fn peer_bootstrap_addr(&self) -> String {
        format!("{}/p2p/{}", self.listen_addr, self.peer_id)
    }
}

fn write_node_fixture(
    name: &str,
    domain_key: &dds_domain::DomainKey,
    trusted_roots: Vec<String>,
    bootstrap_peers: Vec<String>,
    listen_port: u16,
    api_port: u16,
) -> NodeFixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join(name);
    std::fs::create_dir_all(&data_dir).unwrap();

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(p2p_keypair.public());
    p2p_identity::save(&data_dir.join("p2p_key.bin"), &p2p_keypair).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
    domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

    let domain = domain_key.domain();
    let listen_addr = format!("/ip4/127.0.0.1/tcp/{listen_port}");
    let api_addr = format!("127.0.0.1:{api_port}");
    let cfg = NodeConfig {
        data_dir: data_dir.clone(),
        network: NetworkConfig {
            listen_addr: listen_addr.clone(),
            bootstrap_peers,
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: api_addr.clone(),
        },
        org_hash: "e2e-org".to_string(),
        domain: DomainConfig {
            name: domain.name,
            id: domain.id.to_string(),
            pubkey: dds_domain::domain::to_hex(&domain.pubkey),
            admission_path: None,
            audit_log_enabled: false,
        },
        trusted_roots,
        identity_path: None,
        expiry_scan_interval_secs: 1,
    };
    let config_path = dir.path().join(format!("{name}.toml"));
    std::fs::write(&config_path, toml::to_string_pretty(&cfg).unwrap()).unwrap();

    NodeFixture {
        _dir: dir,
        config_path,
        db_path: cfg.db_path(),
        api_url: format!("http://{api_addr}"),
        listen_addr,
        peer_id,
    }
}

struct RunningNode {
    fixture: NodeFixture,
    child: Child,
}

impl RunningNode {
    fn spawn(fixture: NodeFixture) -> Self {
        let child = dds_node_bin()
            .arg("run")
            .arg(&fixture.config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self { fixture, child }
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum PublishCommand {
    Operation(Token),
    Revocation(Token),
}

struct Publisher {
    _dir: TempDir,
    tx: mpsc::UnboundedSender<PublishCommand>,
    task: tokio::task::JoinHandle<()>,
}

impl Publisher {
    fn spawn(domain_key: &dds_domain::DomainKey, peer: &NodeFixture) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("publisher");
        std::fs::create_dir_all(&data_dir).unwrap();

        let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(p2p_keypair.public());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cert = domain_key.issue_admission(peer_id.to_string(), now, None);
        domain_store::save_admission_cert(&data_dir.join("admission.cbor"), &cert).unwrap();

        let domain = domain_key.domain();
        let cfg = NodeConfig {
            data_dir,
            network: NetworkConfig {
                listen_addr: format!("/ip4/127.0.0.1/tcp/{}", reserve_port()),
                bootstrap_peers: Vec::new(),
                mdns_enabled: false,
                heartbeat_secs: 1,
                idle_timeout_secs: 60,
                api_addr: format!("127.0.0.1:{}", reserve_port()),
            },
            org_hash: "e2e-org".to_string(),
            domain: DomainConfig {
                name: domain.name,
                id: domain.id.to_string(),
                pubkey: dds_domain::domain::to_hex(&domain.pubkey),
                admission_path: None,
                audit_log_enabled: false,
            },
            trusted_roots: Vec::new(),
            identity_path: None,
            expiry_scan_interval_secs: 60,
        };
        let mut node = DdsNode::init(cfg, p2p_keypair).unwrap();
        node.start().unwrap();
        connect(&mut node.swarm, peer.peer_id, &peer.listen_addr);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_cmd = rx.recv() => {
                        let Some(cmd) = maybe_cmd else { break; };
                        match cmd {
                            PublishCommand::Operation(token) => publish_operation(&mut node, &token),
                            PublishCommand::Revocation(token) => publish_revocation(&mut node, &token),
                        }
                    }
                    _event = node.swarm.select_next_some() => {}
                }
            }
        });

        Self { _dir: dir, tx, task }
    }

    fn publish_operation(&self, token: Token) {
        self.tx.send(PublishCommand::Operation(token)).unwrap();
    }

    fn publish_revocation(&self, token: Token) {
        self.tx.send(PublishCommand::Revocation(token)).unwrap();
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn connect(swarm: &mut Swarm<dds_net::transport::DdsBehaviour>, peer_id: PeerId, addr: &str) {
    let addr: Multiaddr = addr.parse().unwrap();
    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
    swarm.dial(addr).unwrap();
}

fn publish_operation(node: &mut DdsNode, token: &Token) {
    let op = op_for(token);
    let mut op_bytes = Vec::new();
    ciborium::into_writer(&op, &mut op_bytes).unwrap();
    let token_bytes = token.to_cbor().unwrap();
    let msg = dds_net::gossip::GossipMessage::DirectoryOp {
        op_bytes,
        token_bytes,
    };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.operations.to_ident_topic();
    let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
}

fn publish_revocation(node: &mut DdsNode, token: &Token) {
    let token_bytes = token.to_cbor().unwrap();
    let msg = dds_net::gossip::GossipMessage::Revocation { token_bytes };
    let cbor = msg.to_cbor().unwrap();
    let topic = node.topics.revocations.to_ident_topic();
    let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
}

async fn wait_for_status(client: &Client, api_url: &str) -> NodeStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(resp) = client.get(format!("{api_url}/v1/status")).send().await {
            if resp.status().is_success() {
                return resp.json().await.unwrap();
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for {api_url}/v1/status");
        sleep(Duration::from_millis(200)).await;
    }
}

async fn post_session(
    client: &Client,
    api_url: &str,
    subject_urn: &str,
    requested_resources: Vec<String>,
) -> reqwest::Response {
    client
        .post(format!("{api_url}/v1/session"))
        .json(&SessionRequestJson {
            subject_urn: subject_urn.to_string(),
            device_urn: None,
            requested_resources,
            duration_secs: 300,
            mfa_verified: true,
            tls_binding: None,
        })
        .send()
        .await
        .unwrap()
}

async fn wait_for_session_success(
    client: &Client,
    api_url: &str,
    subject_urn: &str,
) -> SessionResponse {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let resp = post_session(client, api_url, subject_urn, vec!["repo:main".to_string()]).await;
        if resp.status().is_success() {
            return resp.json().await.unwrap();
        }
        assert!(Instant::now() < deadline, "timed out waiting for session success on {api_url}");
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_session_failure(client: &Client, api_url: &str, subject_urn: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let resp = post_session(client, api_url, subject_urn, vec!["repo:main".to_string()]).await;
        if !resp.status().is_success() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for session failure on {api_url}");
        sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_http_api_end_to_end() {
    let client = Client::new();
    let domain_key = dds_domain::DomainKey::from_secret_bytes("binary-http.local", [19u8; 32]);
    let root = Identity::generate("root", &mut OsRng);
    let alice = Identity::generate("alice", &mut OsRng);
    let alice_attest = make_attest(&alice, "att-alice-http-e2e");
    let alice_vouch = make_vouch(&root, &alice, &alice_attest, "repo:main", "vouch-alice-http-e2e");

    let fixture = write_node_fixture(
        "single-node",
        &domain_key,
        vec![root.id.to_urn()],
        Vec::new(),
        reserve_port(),
        reserve_port(),
    );
    seed_store(&fixture.db_path, &[alice_attest, alice_vouch]);

    let node = RunningNode::spawn(fixture);
    let initial_status = wait_for_status(&client, &node.fixture.api_url).await;
    assert_eq!(initial_status.peer_id, node.fixture.peer_id.to_string());
    assert_eq!(initial_status.store_tokens, 2);
    assert_eq!(initial_status.trust_graph_tokens, 2);

    let session_resp = post_session(
        &client,
        &node.fixture.api_url,
        &alice.id.to_urn(),
        vec!["repo:main".to_string(), "repo:other".to_string()],
    )
    .await;
    assert!(session_resp.status().is_success());
    let session: SessionResponse = session_resp.json().await.unwrap();
    let session_token = Token::from_cbor(&decode_b64(&session.token_cbor_b64)).unwrap();
    let session_doc = SessionDocument::extract(&session_token.payload).unwrap().unwrap();
    assert_eq!(session_doc.subject_urn, alice.id.to_urn());
    assert_eq!(session_doc.granted_purposes, vec!["repo:main"]);
    assert_eq!(session_doc.authorized_resources, vec!["repo:main"]);

    let policy_resp = client
        .post(format!("{}/v1/policy/evaluate", node.fixture.api_url))
        .json(&PolicyRequestJson {
            subject_urn: alice.id.to_urn(),
            resource: "repo:main".to_string(),
            action: "read".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert!(policy_resp.status().is_success());
    let policy: PolicyResult = policy_resp.json().await.unwrap();
    assert!(!policy.allowed);

    let device_resp = client
        .post(format!("{}/v1/enroll/device", node.fixture.api_url))
        .json(&EnrollDeviceRequestJson {
            label: "laptop-01".to_string(),
            device_id: "HW-123".to_string(),
            hostname: "workstation-01".to_string(),
            os: "macOS".to_string(),
            os_version: "15.0".to_string(),
            tpm_ek_hash: Some("sha256:tpm".to_string()),
            org_unit: Some("engineering".to_string()),
            tags: vec!["developer".to_string(), "laptop".to_string()],
        })
        .send()
        .await
        .unwrap();
    assert!(device_resp.status().is_success());
    let device: EnrollmentResponse = device_resp.json().await.unwrap();
    let device_token = Token::from_cbor(&decode_b64(&device.token_cbor_b64)).unwrap();
    let device_doc = DeviceJoinDocument::extract(&device_token.payload).unwrap().unwrap();
    assert_eq!(device_doc.device_id, "HW-123");
    assert_eq!(device_doc.hostname, "workstation-01");

    let cred_sk = SigningKey::generate(&mut OsRng);
    let attestation = build_none_attestation("example.com", b"cred-http-e2e", &cred_sk.verifying_key());
    let user_resp = client
        .post(format!("{}/v1/enroll/user", node.fixture.api_url))
        .json(&EnrollUserRequestJson {
            label: "carol".to_string(),
            credential_id: "ignored-by-attestation-parser".to_string(),
            attestation_object_b64: encode_b64(&attestation),
            client_data_hash_b64: encode_b64(&[0xAB; 32]),
            rp_id: "example.com".to_string(),
            display_name: "Carol".to_string(),
            authenticator_type: "platform".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert!(user_resp.status().is_success());
    let user: EnrollmentResponse = user_resp.json().await.unwrap();
    let user_token = Token::from_cbor(&decode_b64(&user.token_cbor_b64)).unwrap();
    let user_doc = UserAuthAttestation::extract(&user_token.payload).unwrap().unwrap();
    assert_eq!(user_doc.rp_id, "example.com");
    assert_eq!(user_doc.credential_id, "Y3JlZC1odHRwLWUyZQ");

    let final_status = wait_for_status(&client, &node.fixture.api_url).await;
    assert_eq!(final_status.store_tokens, 4);
    assert_eq!(final_status.trust_graph_tokens, 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_nodes_converge_on_gossip_and_revocation() {
    let client = Client::new();
    let domain_key = dds_domain::DomainKey::from_secret_bytes("binary-cluster.local", [23u8; 32]);
    let root = Identity::generate("root", &mut OsRng);
    let alice = Identity::generate("alice", &mut OsRng);
    let alice_attest = make_attest(&alice, "att-alice-cluster-e2e");
    let alice_vouch = make_vouch(
        &root,
        &alice,
        &alice_attest,
        "repo:main",
        "vouch-alice-cluster-e2e",
    );

    let node_a_fixture = write_node_fixture(
        "node-a",
        &domain_key,
        vec![root.id.to_urn()],
        Vec::new(),
        reserve_port(),
        reserve_port(),
    );
    let node_b_fixture = write_node_fixture(
        "node-b",
        &domain_key,
        vec![root.id.to_urn()],
        vec![node_a_fixture.peer_bootstrap_addr()],
        reserve_port(),
        reserve_port(),
    );

    let node_a = RunningNode::spawn(node_a_fixture);
    let _ = wait_for_status(&client, &node_a.fixture.api_url).await;
    let node_b = RunningNode::spawn(node_b_fixture);
    let _ = wait_for_status(&client, &node_b.fixture.api_url).await;

    sleep(Duration::from_secs(3)).await;

    let publisher = Publisher::spawn(&domain_key, &node_a.fixture);
    sleep(Duration::from_secs(3)).await;
    publisher.publish_operation(alice_attest);
    publisher.publish_operation(alice_vouch.clone());

    let session_a = wait_for_session_success(&client, &node_a.fixture.api_url, &alice.id.to_urn()).await;
    let session_b = wait_for_session_success(&client, &node_b.fixture.api_url, &alice.id.to_urn()).await;
    for session in [session_a, session_b] {
        let token = Token::from_cbor(&decode_b64(&session.token_cbor_b64)).unwrap();
        let doc = SessionDocument::extract(&token.payload).unwrap().unwrap();
        assert_eq!(doc.authorized_resources, vec!["repo:main"]);
    }

    let revoke = make_revoke(&root, &alice_vouch.payload.jti, "revoke-alice-cluster-e2e");
    publisher.publish_revocation(revoke);
    wait_for_session_failure(&client, &node_a.fixture.api_url, &alice.id.to_urn()).await;
    wait_for_session_failure(&client, &node_b.fixture.api_url, &alice.id.to_urn()).await;
}
