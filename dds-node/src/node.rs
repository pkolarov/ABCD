//! DDS node: ties together storage, trust, networking, and sync.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_core::token::Token;
use dds_core::trust::TrustGraph;
use dds_net::gossip::{DdsTopic, DdsTopicSet, GossipMessage};
use dds_net::sync::{SyncPayload, SyncRequest, SyncResponse, apply_sync_payloads_with_graph};
use dds_net::transport::{DdsBehaviour, DdsBehaviourEvent, SwarmConfig};
use dds_store::RedbBackend;
use dds_store::traits::*;
use futures::StreamExt;
use libp2p::request_response::{Event as RrEvent, Message as RrMessage};
use libp2p::{Multiaddr, PeerId, Swarm};
use tracing::{debug, error, info, warn};

use dds_domain::{DomainId, domain::from_hex};

use crate::config::NodeConfig;

/// How often we proactively sync against every connected peer as a
/// backstop against gossip drops. The on-connect sync handles fresh
/// rejoin convergence; this catches steady-state divergence.
const ANTI_ENTROPY_INTERVAL: Duration = Duration::from_secs(60);

/// Minimum gap between two outbound sync requests to the same peer.
/// Throttles the on-connect storm when libp2p reconnects flap.
const SYNC_PER_PEER_COOLDOWN: Duration = Duration::from_secs(15);

/// The running DDS node state.
///
/// `trust_graph` is shared (`Arc<RwLock<TrustGraph>>`) so the swarm event
/// loop and the `LocalService` HTTP API can both observe gossip-received
/// tokens. Before this fix the two had cloned-but-divergent graphs and
/// `LocalService` had to rebuild from the store on every query — which
/// the 2026-04-09 chaos soak found drove `evaluate_policy` p99 to 10 ms
/// (see B5b). The lock is read-heavy: every query reads, only the swarm
/// gossip handlers and enrollment paths write.
pub struct DdsNode {
    pub swarm: Swarm<DdsBehaviour>,
    pub peer_id: PeerId,
    pub store: RedbBackend,
    pub dag: CausalDag,
    pub trust_graph: Arc<RwLock<TrustGraph>>,
    pub trusted_roots: BTreeSet<String>,
    pub topics: DdsTopicSet,
    pub config: NodeConfig,
    /// In-memory cache of live `SyncPayload`s, keyed by operation id.
    /// Built up at gossip-ingest time so the anti-entropy responder can
    /// reply without re-deriving op→token mapping at lookup time.
    /// Resolves B6 (the gossip-only delivery gap from the chaos soak).
    sync_payloads: BTreeMap<String, SyncPayload>,
    /// Per-peer "last outbound sync" timestamp for the cooldown throttle.
    sync_last_outbound: BTreeMap<PeerId, Instant>,
}

impl DdsNode {
    /// Initialize a new node from config and a pre-existing libp2p
    /// keypair. The keypair must be persistent across restarts so that the
    /// node's `PeerId` is stable — it is bound by the admission cert.
    pub fn init(
        config: NodeConfig,
        keypair: libp2p::identity::Keypair,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Parse domain id and pubkey from config (fail fast on bad config).
        let domain_id = DomainId::parse(&config.domain.id)?;
        let pubkey_bytes = from_hex(&config.domain.pubkey)?;
        if pubkey_bytes.len() != 32 {
            return Err(format!(
                "domain.pubkey: expected 32 bytes, got {}",
                pubkey_bytes.len()
            )
            .into());
        }
        let mut domain_pubkey = [0u8; 32];
        domain_pubkey.copy_from_slice(&pubkey_bytes);
        // Sanity: pubkey must hash to the configured id.
        if DomainId::from_pubkey(&domain_pubkey) != domain_id {
            return Err("domain.pubkey does not hash to domain.id".into());
        }

        // Open storage
        let store = RedbBackend::open(config.db_path())?;

        // Build swarm with the persistent libp2p identity.
        let swarm_config = SwarmConfig {
            heartbeat_interval: Duration::from_secs(config.network.heartbeat_secs),
            domain_tag: domain_id.protocol_tag(),
            idle_timeout: Duration::from_secs(config.network.idle_timeout_secs),
            mdns_enabled: config.network.mdns_enabled,
        };
        let (swarm, peer_id) = dds_net::transport::build_swarm(swarm_config, keypair)?;

        // Verify the admission certificate before doing anything else.
        let admission_path = config.admission_path();
        let cert = crate::domain_store::load_admission_cert(&admission_path).map_err(|e| {
            format!(
                "failed to load admission cert from {}: {e} — \
                 a node cannot join a domain without an admission cert signed by the domain key",
                admission_path.display()
            )
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error, cannot verify admission cert: {e}"))?
            .as_secs();
        cert.verify(&domain_pubkey, &domain_id, &peer_id.to_string(), now)
            .map_err(|e| format!("admission cert verification failed: {e}"))?;
        info!(domain = %config.domain.name, %peer_id, "admission cert verified");

        // Build trusted roots set
        let trusted_roots: BTreeSet<String> = config.trusted_roots.iter().cloned().collect();

        // Create topics for the (domain, org) pair.
        let topics = DdsTopic::for_domain_org(&domain_id.protocol_tag(), &config.org_hash);

        info!(%peer_id, domain = %config.domain.name, org = %config.org_hash, "DDS node initialized");

        Ok(Self {
            swarm,
            peer_id,
            store,
            dag: CausalDag::new(),
            trust_graph: {
                let mut g = TrustGraph::new();
                g.set_max_chain_depth(config.domain.max_delegation_depth);
                Arc::new(RwLock::new(g))
            },
            trusted_roots,
            topics,
            config,
            sync_payloads: BTreeMap::new(),
            sync_last_outbound: BTreeMap::new(),
        })
    }

    /// Start listening and subscribe to gossipsub topics.
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Listen on configured address
        let listen_addr: Multiaddr = self.config.network.listen_addr.parse()?;
        self.swarm.listen_on(listen_addr)?;

        // Subscribe to org topics
        self.topics.subscribe_all(
            &mut self.swarm.behaviour_mut().gossipsub,
            self.config.domain.audit_log_enabled,
        )?;

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

    /// Run the main event loop. Processes swarm events, periodic expiry
    /// sweeps, and periodic anti-entropy sync against connected peers.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let interval_secs = self.config.expiry_scan_interval_secs;
        let mut expiry_interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // The first tick completes immediately; consume it.
        expiry_interval.tick().await;

        // Anti-entropy backstop: periodically pull from every connected
        // peer so we converge even when gossip drops messages or a
        // node missed a window. The on-connect sync covers fresh
        // rejoins; this catches steady-state divergence.
        let mut anti_entropy = tokio::time::interval(ANTI_ENTROPY_INTERVAL);
        anti_entropy.tick().await;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
                _ = expiry_interval.tick() => {
                    let expired = {
                        let mut g = self.trust_graph.write().expect("trust_graph poisoned");
                        g.sweep_expired()
                    };
                    for jti in &expired {
                        let _ = self.store.revoke(jti);
                    }
                    if !expired.is_empty() {
                        info!(count = expired.len(), "swept expired tokens");
                    }

                    // Audit log pruning (only if audit log is enabled)
                    if self.config.domain.audit_log_enabled {
                        self.prune_audit_log();
                    }
                }
                _ = anti_entropy.tick() => {
                    let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
                    for peer in peers {
                        self.try_sync_with(peer);
                    }
                }
            }
        }
    }

    /// Apply one swarm event using the production ingest path (gossip,
    /// sync, mDNS, lifecycle). Public so integration tests can drive
    /// the same code path that `run()` uses.
    pub fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<DdsBehaviourEvent>) {
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
            SwarmEvent::Behaviour(DdsBehaviourEvent::Sync(sync_event)) => {
                self.handle_sync_event(sync_event);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!(%peer_id, "connection established");
                // Pull anything we might have missed while we were
                // disconnected from this peer (or never knew about).
                self.try_sync_with(peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!(%peer_id, "connection closed");
                // Drop the cooldown so a fresh reconnect immediately
                // re-syncs without waiting out the throttle.
                self.sync_last_outbound.remove(&peer_id);
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
                DdsTopic::Operations(..),
                GossipMessage::DirectoryOp {
                    op_bytes,
                    token_bytes,
                },
            ) => {
                self.ingest_operation(&op_bytes, &token_bytes);
            }
            (DdsTopic::Revocations(..), GossipMessage::Revocation { token_bytes }) => {
                self.ingest_revocation(&token_bytes);
            }
            (DdsTopic::Burns(..), GossipMessage::Burn { token_bytes }) => {
                self.ingest_burn(&token_bytes);
            }
            (DdsTopic::AuditLog(..), GossipMessage::AuditLog { entry_bytes }) => {
                self.ingest_audit(&entry_bytes);
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
        {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            if let Err(e) = g.add_token(token.clone()) {
                warn!("trust graph rejected token: {e}");
                return;
            }
        }
        if let Err(e) = self.store.put_token(&token) {
            error!("store error: {e}");
        }
        let op_id = op.id.clone();
        let op_for_cache = op.clone();
        match self.dag.insert(op) {
            Ok(true) => {
                info!(jti = %token.payload.jti, "ingested new operation");
                self.cache_sync_payload(&op_id, &op_for_cache, token_bytes);
            }
            Ok(false) => {} // duplicate
            Err(e) => warn!("DAG insert failed: {e}"),
        }
    }

    /// Insert an op + its backing token bytes into the sync payload cache
    /// so the anti-entropy responder can serve it back to peers without
    /// reconstructing the (op, token) pair from scratch. Called from both
    /// the gossip ingest path and the sync-applied path.
    fn cache_sync_payload(&mut self, op_id: &str, op: &Operation, token_bytes: &[u8]) {
        let mut op_bytes = Vec::new();
        if ciborium::into_writer(op, &mut op_bytes).is_err() {
            return;
        }
        self.sync_payloads.insert(
            op_id.to_string(),
            SyncPayload {
                op_bytes,
                token_bytes: token_bytes.to_vec(),
            },
        );
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
        {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            if let Err(e) = g.add_token(token.clone()) {
                warn!("trust graph rejected revocation: {e}");
                return;
            }
        }
        if let Err(e) = self.store.put_token(&token) {
            error!("store error: {e}");
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
        {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            if let Err(e) = g.add_token(token.clone()) {
                warn!("trust graph rejected burn: {e}");
                return;
            }
        }
        if let Err(e) = self.store.put_token(&token) {
            error!("store error: {e}");
        }
        if let Err(e) = self.store.burn(&token.payload.iss) {
            error!("store burn error: {e}");
        }
        info!(urn = %token.payload.iss, "identity burned");
    }

    fn ingest_audit(&mut self, entry_bytes: &[u8]) {
        if !self.config.domain.audit_log_enabled {
            return;
        }
        if let Ok(entry) = ciborium::from_reader::<dds_core::audit::AuditLogEntry, _>(entry_bytes) {
            let _ = self.store.append_audit_entry(&entry);
            info!(action = %entry.action, node = %entry.node_urn, "audit log entry appended");
        }
    }

    // ---------- anti-entropy sync (B6) ----------

    /// Build the response to an inbound sync request: every cached
    /// payload whose op_id is *not* in the requester's `known_op_ids`.
    fn build_sync_response(&self, req: &SyncRequest) -> SyncResponse {
        let payloads: Vec<SyncPayload> = self
            .sync_payloads
            .iter()
            .filter(|(id, _)| !req.known_op_ids.contains(id.as_str()))
            .map(|(_, payload)| payload.clone())
            .collect();
        SyncResponse {
            payloads,
            complete: true,
        }
    }

    /// Build a sync request from local DAG state.
    fn build_sync_request(&self) -> SyncRequest {
        SyncRequest {
            known_op_ids: self.dag.operation_ids(),
            heads: self.dag.heads().clone(),
        }
    }

    /// Send a sync request to a peer, respecting the per-peer cooldown.
    /// No-op if the peer was contacted within `SYNC_PER_PEER_COOLDOWN`.
    fn try_sync_with(&mut self, peer: PeerId) {
        let now = Instant::now();
        if let Some(prev) = self.sync_last_outbound.get(&peer) {
            if now.duration_since(*prev) < SYNC_PER_PEER_COOLDOWN {
                return;
            }
        }
        let req = self.build_sync_request();
        let req_id = self.swarm.behaviour_mut().sync.send_request(&peer, req);
        self.sync_last_outbound.insert(peer, now);
        debug!(%peer, ?req_id, "sync: sent request");
    }

    /// Apply an inbound sync response: merge into trust graph + DAG +
    /// store, and cache the payloads for future serving to other peers.
    fn handle_sync_response(&mut self, peer: PeerId, resp: SyncResponse) {
        if resp.payloads.is_empty() {
            debug!(%peer, "sync: peer reported no diff");
            return;
        }
        let payloads = resp.payloads;
        let result = {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            apply_sync_payloads_with_graph(&payloads, &mut self.dag, &mut self.store, &mut g)
        };
        // Repopulate the sync cache so the next inbound request from
        // some other peer can serve these payloads onward.
        for payload in &payloads {
            if let Ok(op) = ciborium::from_reader::<Operation, _>(payload.op_bytes.as_slice()) {
                let id = op.id.clone();
                self.sync_payloads.insert(id, payload.clone());
            }
        }
        info!(
            %peer,
            ops_merged = result.ops_merged,
            tokens_stored = result.tokens_stored,
            revocations_applied = result.revocations_applied,
            burns_applied = result.burns_applied,
            err_count = result.errors.len(),
            "sync: applied response"
        );
    }

    /// Handle one libp2p `request_response` event for the sync protocol.
    fn handle_sync_event(&mut self, event: RrEvent<SyncRequest, SyncResponse>) {
        match event {
            RrEvent::Message { peer, message, .. } => match message {
                RrMessage::Request {
                    request, channel, ..
                } => {
                    let response = self.build_sync_response(&request);
                    let payload_count = response.payloads.len();
                    if self
                        .swarm
                        .behaviour_mut()
                        .sync
                        .send_response(channel, response)
                        .is_err()
                    {
                        warn!(%peer, "sync: failed to send response (channel closed)");
                    } else {
                        debug!(%peer, payload_count, "sync: served request");
                    }
                }
                RrMessage::Response { response, .. } => {
                    self.handle_sync_response(peer, response);
                }
            },
            RrEvent::OutboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "sync: outbound failure");
            }
            RrEvent::InboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "sync: inbound failure");
            }
            RrEvent::ResponseSent { .. } => {}
        }
    }

    /// Run a single token-expiry sweep using the current system time.
    /// Public so the binary or tests can drive it on demand.
    pub fn sweep_expired(&mut self) -> crate::expiry::SweepStats {
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                warn!("system clock error, skipping expiry sweep: {e}");
                return crate::expiry::SweepStats::default();
            }
        };
        let mut g = self.trust_graph.write().expect("trust_graph poisoned");
        crate::expiry::sweep_once(&mut g, &mut self.store, now)
    }

    /// Prune audit log entries based on retention config.
    fn prune_audit_log(&mut self) {
        use dds_store::traits::AuditStore;

        // Prune by age
        if self.config.domain.audit_log_retention_days > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let cutoff = now.saturating_sub(self.config.domain.audit_log_retention_days * 86400);
            match self.store.prune_audit_entries_before(cutoff) {
                Ok(n) if n > 0 => info!(removed = n, "pruned old audit entries"),
                Err(e) => warn!("audit prune by age failed: {e}"),
                _ => {}
            }
        }

        // Prune by count
        if self.config.domain.audit_log_max_entries > 0 {
            match self
                .store
                .prune_audit_entries_to_max(self.config.domain.audit_log_max_entries)
            {
                Ok(n) if n > 0 => info!(removed = n, "pruned excess audit entries"),
                Err(e) => warn!("audit prune by count failed: {e}"),
                _ => {}
            }
        }
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
        let g = self.trust_graph.read().expect("trust_graph poisoned");
        policy_engine.evaluate(subject_urn, resource, action, &g, &self.trusted_roots)
    }
}
