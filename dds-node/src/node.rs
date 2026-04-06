//! DDS node: ties together storage, trust, networking, and sync.

use std::collections::BTreeSet;
use std::time::Duration;

use dds_core::crdt::causal_dag::CausalDag;
use dds_core::token::Token;
use dds_core::trust::TrustGraph;
use dds_net::gossip::{DdsTopic, DdsTopicSet, GossipMessage};
use dds_net::transport::{DdsBehaviour, DdsBehaviourEvent, SwarmConfig};
use dds_store::RedbBackend;
use dds_store::traits::*;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId, Swarm};
use tracing::{error, info, warn};

use crate::config::NodeConfig;

/// The running DDS node state.
pub struct DdsNode {
    pub swarm: Swarm<DdsBehaviour>,
    pub peer_id: PeerId,
    pub store: RedbBackend,
    pub dag: CausalDag,
    pub trust_graph: TrustGraph,
    pub trusted_roots: BTreeSet<String>,
    pub topics: DdsTopicSet,
    pub config: NodeConfig,
}

impl DdsNode {
    /// Initialize a new node from config.
    pub fn init(config: NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Open storage
        let store = RedbBackend::open(config.db_path())?;

        // Build swarm
        let swarm_config = SwarmConfig {
            heartbeat_interval: Duration::from_secs(config.network.heartbeat_secs),
            kad_protocol: "/dds/kad/1.0.0".to_string(),
            idle_timeout: Duration::from_secs(config.network.idle_timeout_secs),
        };
        let (swarm, peer_id) = dds_net::transport::build_swarm(swarm_config)?;

        // Build trusted roots set
        let trusted_roots: BTreeSet<String> = config.trusted_roots.iter().cloned().collect();

        // Create topics for the org
        let topics = DdsTopic::for_org(&config.org_hash);

        info!(%peer_id, org = %config.org_hash, "DDS node initialized");

        Ok(Self {
            swarm,
            peer_id,
            store,
            dag: CausalDag::new(),
            trust_graph: TrustGraph::new(),
            trusted_roots,
            topics,
            config,
        })
    }

    /// Start listening and subscribe to gossipsub topics.
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Listen on configured address
        let listen_addr: Multiaddr = self.config.network.listen_addr.parse()?;
        self.swarm.listen_on(listen_addr)?;

        // Subscribe to org topics
        self.topics
            .subscribe_all(&mut self.swarm.behaviour_mut().gossipsub)?;

        // Add bootstrap peers
        for addr_str in &self.config.network.bootstrap_peers {
            match dds_net::discovery::parse_peer_multiaddr(addr_str) {
                Ok((peer_id, addr)) => {
                    dds_net::discovery::add_bootstrap_peer(&mut self.swarm, peer_id, addr);
                    info!(%peer_id, "added bootstrap peer");
                }
                Err(e) => warn!(addr = %addr_str, "invalid bootstrap peer: {e}"),
            }
        }

        // Bootstrap Kademlia if we have peers
        if !self.config.network.bootstrap_peers.is_empty() {
            if let Err(e) = dds_net::discovery::bootstrap_kademlia(&mut self.swarm) {
                warn!("Kademlia bootstrap failed: {e}");
            }
        }

        info!(
            listen = %self.config.network.listen_addr,
            "DDS node started"
        );
        Ok(())
    }

    /// Run the main event loop. Processes swarm events until shutdown.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let event = self.swarm.select_next_some().await;
            self.handle_swarm_event(event);
        }
    }

    fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<DdsBehaviourEvent>) {
        use libp2p::swarm::SwarmEvent;

        match event {
            SwarmEvent::Behaviour(DdsBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Message { message, .. },
            )) => {
                self.handle_gossip_message(&message.topic, &message.data);
            }
            SwarmEvent::Behaviour(DdsBehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(
                peers,
            ))) => {
                for (peer_id, addr) in peers {
                    info!(%peer_id, %addr, "mDNS: discovered peer");
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                    dds_net::discovery::add_mdns_peer(&mut self.swarm, peer_id);
                }
            }
            SwarmEvent::Behaviour(DdsBehaviourEvent::Mdns(libp2p::mdns::Event::Expired(peers))) => {
                for (peer_id, _addr) in peers {
                    info!(%peer_id, "mDNS: peer expired");
                    dds_net::discovery::remove_mdns_peer(&mut self.swarm, peer_id);
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!(%peer_id, "connection established");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!(%peer_id, "connection closed");
            }
            _ => {}
        }
    }

    fn handle_gossip_message(&mut self, topic_hash: &libp2p::gossipsub::TopicHash, data: &[u8]) {
        let topic = match self.topics.identify_topic(topic_hash) {
            Some(t) => t,
            None => {
                warn!(?topic_hash, "received message on unknown topic");
                return;
            }
        };

        let msg = match GossipMessage::from_cbor(data) {
            Ok(m) => m,
            Err(e) => {
                warn!("invalid gossip message: {e}");
                return;
            }
        };

        match (topic, msg) {
            (
                DdsTopic::Operations(_),
                GossipMessage::DirectoryOp {
                    op_bytes,
                    token_bytes,
                },
            ) => {
                self.ingest_operation(&op_bytes, &token_bytes);
            }
            (DdsTopic::Revocations(_), GossipMessage::Revocation { token_bytes }) => {
                self.ingest_revocation(&token_bytes);
            }
            (DdsTopic::Burns(_), GossipMessage::Burn { token_bytes }) => {
                self.ingest_burn(&token_bytes);
            }
            _ => {
                warn!("message type mismatch for topic");
            }
        }
    }

    fn ingest_operation(&mut self, op_bytes: &[u8], token_bytes: &[u8]) {
        let op: dds_core::crdt::causal_dag::Operation = match ciborium::from_reader(op_bytes) {
            Ok(op) => op,
            Err(e) => {
                error!("op deserialize: {e}");
                return;
            }
        };
        let token = match Token::from_cbor(token_bytes) {
            Ok(t) => t,
            Err(e) => {
                error!("token deserialize: {e}");
                return;
            }
        };
        if let Err(e) = token.validate() {
            warn!("token validation failed: {e}");
            return;
        }
        if let Err(e) = self.trust_graph.add_token(token.clone()) {
            warn!("trust graph rejected token: {e}");
            return;
        }
        if let Err(e) = self.store.put_token(&token) {
            error!("store error: {e}");
        }
        match self.dag.insert(op) {
            Ok(true) => info!(jti = %token.payload.jti, "ingested new operation"),
            Ok(false) => {} // duplicate
            Err(e) => warn!("DAG insert failed: {e}"),
        }
    }

    fn ingest_revocation(&mut self, token_bytes: &[u8]) {
        let token = match Token::from_cbor(token_bytes) {
            Ok(t) => t,
            Err(e) => {
                error!("revoke token deserialize: {e}");
                return;
            }
        };
        if let Err(e) = token.validate() {
            warn!("revocation validation failed: {e}");
            return;
        }
        if let Err(e) = self.trust_graph.add_token(token.clone()) {
            warn!("trust graph rejected revocation: {e}");
            return;
        }
        if let Some(ref target) = token.payload.revokes {
            if let Err(e) = self.store.revoke(target) {
                error!("store revoke error: {e}");
            }
            info!(target_jti = %target, "revocation applied");
        }
    }

    fn ingest_burn(&mut self, token_bytes: &[u8]) {
        let token = match Token::from_cbor(token_bytes) {
            Ok(t) => t,
            Err(e) => {
                error!("burn token deserialize: {e}");
                return;
            }
        };
        if let Err(e) = token.validate() {
            warn!("burn validation failed: {e}");
            return;
        }
        if let Err(e) = self.trust_graph.add_token(token.clone()) {
            warn!("trust graph rejected burn: {e}");
            return;
        }
        if let Err(e) = self.store.burn(&token.payload.iss) {
            error!("store burn error: {e}");
        }
        info!(urn = %token.payload.iss, "identity burned");
    }

    /// Get the number of connected peers.
    pub fn connected_peers(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Get the number of operations in the DAG.
    pub fn operation_count(&self) -> usize {
        self.dag.len()
    }

    /// Evaluate a policy decision locally.
    pub fn evaluate_access(
        &self,
        subject_urn: &str,
        resource: &str,
        action: &str,
        policy_engine: &dds_core::policy::PolicyEngine,
    ) -> dds_core::policy::PolicyDecision {
        policy_engine.evaluate(
            subject_urn,
            resource,
            action,
            &self.trust_graph,
            &self.trusted_roots,
        )
    }
}
