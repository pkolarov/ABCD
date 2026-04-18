//! DDS node: ties together storage, trust, networking, and sync.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_core::token::{TOKEN_WIRE_V1, Token, TokenKind};
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

/// **H-11 (security review)**: hard cap on the number of payloads
/// returned in a single `SyncResponse`. Prevents an attacker (or any
/// admitted peer with an empty `known_op_ids`) from forcing the
/// responder to clone the entire `sync_payloads` cache into one
/// message. Pagination across requests handles the legitimate case.
const SYNC_MAX_RESPONSE_ENTRIES: usize = 1_000;
/// **H-11 (security review)**: hard cap on the serialized op + token
/// bytes returned in a single `SyncResponse`. ~5 MB is large enough for
/// healthy domains but small enough to bound the worst-case allocation
/// in `build_sync_response` and the per-request CBOR work in the codec.
const SYNC_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
/// **M-5 (security review)**: cap on `sync_payloads` cache size. The
/// previous unbounded `BTreeMap` accumulated forever; combined with H-11
/// it gave a hostile peer an unbounded amplification factor. Eviction
/// policy is FIFO via `BTreeMap::pop_first` — sufficient since op_ids
/// embed UUIDv7-ish prefixes and are roughly time-ordered.
const SYNC_PAYLOAD_CACHE_CAP: usize = 10_000;

/// **M-6 (security review)**: how often to re-verify the admission
/// cert after startup. An expired cert will trigger a clean shutdown
/// — the node stops publishing and returns from `run()`. Set to
/// 10 minutes to balance "catch expiry quickly" against log/CPU
/// overhead.
const ADMISSION_RECHECK_INTERVAL_SECS: u64 = 600;

/// **M-9 (security review)**: maximum age (in seconds) of an inbound
/// revocation or burn `iat` relative to the local wall clock. Older
/// tokens are rejected on the theory that a legitimate revocation
/// will be issued within minutes of its creation. Blocks an attacker
/// from recording an old revocation and replaying it forever with a
/// fresh gossip envelope — the content-hash dedupe in gossipsub is
/// not enough because an attacker can inject a different op_id and
/// force a re-apply + audit-log spam.
/// 7 days accommodates slow human review/approval paths while still
/// bounding the replay window tightly.
const REVOCATION_REPLAY_WINDOW_SECS: u64 = 7 * 86400;

/// **M-4 (security review)**: upper bound on the number of mDNS-
/// discovered peers we accept per minute. Each new peer triggers a
/// Noise handshake (CPU-heavy) and a sync request (allocates
/// response state). Without a cap, a LAN attacker that can
/// fabricate mDNS responses with attacker-controlled peer IDs can
/// burn the node's CPU on handshakes against ghosts and crowd real
/// peers out of the peer table. 60 accept/minute is generous for
/// real deployments (office floors rarely churn that fast) while
/// shutting down Sybil floods.
const MDNS_NEW_PEER_ACCEPT_PER_MINUTE: u32 = 60;

/// **M-4 (security review)**: hard ceiling on the number of
/// actively-tracked mDNS peers the node keeps addresses for in the
/// Kademlia routing table. Once we reach this, new mDNS
/// announcements are ignored (not evicted; we prefer stable
/// known-good peers under attack). Legitimate discovery re-runs on
/// expiry, so a lost real peer will reappear once a fake one is
/// evicted via the mDNS TTL.
const MDNS_PEER_TABLE_MAX: usize = 256;

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
    /// **M-6 (security review)**: retained admission cert + domain
    /// pubkey + domain id so we can re-verify the cert on every
    /// `ADMISSION_RECHECK_INTERVAL` tick. Without a periodic re-verify
    /// a node whose cert has expired keeps operating until restart.
    admission_cert: dds_domain::AdmissionCert,
    domain_pubkey: [u8; 32],
    domain_id: DomainId,
    /// In-memory cache of live `SyncPayload`s, keyed by operation id.
    /// Built up at gossip-ingest time so the anti-entropy responder can
    /// reply without re-deriving op→token mapping at lookup time.
    /// Resolves B6 (the gossip-only delivery gap from the chaos soak).
    sync_payloads: BTreeMap<String, SyncPayload>,
    /// Per-peer "last outbound sync" timestamp for the cooldown throttle.
    sync_last_outbound: BTreeMap<PeerId, Instant>,
    /// **M-4 (security review)**: sliding-window counter for newly
    /// accepted mDNS peers. `(window_start, count)`: if `now -
    /// window_start >= 60s`, reset and start a fresh window; else
    /// increment and reject once `count >= MDNS_NEW_PEER_ACCEPT_PER_MINUTE`.
    mdns_rate: (Instant, u32),
    /// **M-4 (security review)**: set of peer-IDs we've added via
    /// mDNS since startup (and not yet expired). Used to enforce the
    /// hard ceiling and to de-duplicate Discovered events for the
    /// same peer within a short window.
    mdns_known_peers: BTreeSet<PeerId>,
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
            admission_cert: cert,
            domain_pubkey,
            domain_id,
            mdns_rate: (Instant::now(), 0),
            mdns_known_peers: BTreeSet::new(),
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

        // **M-6 (security review)**: re-verify the admission cert on
        // a schedule. An expired cert means the node should stop
        // participating — we return cleanly from `run()` rather than
        // continuing to gossip/serve under an invalid admission.
        let mut admission_recheck = tokio::time::interval(std::time::Duration::from_secs(
            ADMISSION_RECHECK_INTERVAL_SECS,
        ));
        admission_recheck.tick().await;

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
                _ = admission_recheck.tick() => {
                    if let Err(e) = self.verify_admission_still_valid() {
                        tracing::error!(
                            peer_id = %self.peer_id,
                            error = %e,
                            "admission cert no longer valid — shutting down"
                        );
                        return Err(
                            format!("admission cert re-verification failed: {e}").into()
                        );
                    }
                }
            }
        }
    }

    /// **M-6 (security review)**: re-run the same admission-cert
    /// verification that happens at startup. Returns `Err` if the
    /// cert is expired, if its signature no longer checks out, or
    /// if it is bound to a different peer. Exposed publicly for
    /// tests that want to observe expiry handling.
    pub fn verify_admission_still_valid(&self) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();
        self.admission_cert
            .verify(
                &self.domain_pubkey,
                &self.domain_id,
                &self.peer_id.to_string(),
                now,
            )
            .map_err(|e| format!("{e}"))
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
                    // M-4: gate mDNS-discovered peers on per-minute rate
                    // and a hard table ceiling. Already-known peers
                    // bypass both (a re-announcement from a peer we
                    // already track is not a new resource commitment).
                    if !self.mdns_accept_peer(&peer_id) {
                        debug!(%peer_id, %addr, "mDNS: peer rejected by M-4 caps");
                        continue;
                    }
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
                    self.mdns_known_peers.remove(&peer_id);
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

    /// **M-4 (security review)**: decide whether to accept an
    /// mDNS-discovered peer. Returns `true` if the peer should be
    /// added to the Kademlia routing table and the gossipsub
    /// explicit-peer list; `false` if the per-minute rate or table
    /// ceiling is exceeded (or the peer is already tracked).
    ///
    /// Already-tracked peers return `false` — there is no additional
    /// resource cost to re-announce, and returning `true` would
    /// let an attacker inflate the per-minute counter with re-runs.
    fn mdns_accept_peer(&mut self, peer_id: &PeerId) -> bool {
        if self.mdns_known_peers.contains(peer_id) {
            return false;
        }
        if self.mdns_known_peers.len() >= MDNS_PEER_TABLE_MAX {
            warn!(
                known = self.mdns_known_peers.len(),
                cap = MDNS_PEER_TABLE_MAX,
                "mDNS peer-table ceiling hit; dropping new peer"
            );
            return false;
        }
        let now = Instant::now();
        if now.duration_since(self.mdns_rate.0) >= Duration::from_secs(60) {
            self.mdns_rate = (now, 0);
        }
        if self.mdns_rate.1 >= MDNS_NEW_PEER_ACCEPT_PER_MINUTE {
            warn!(
                accepted_this_window = self.mdns_rate.1,
                cap = MDNS_NEW_PEER_ACCEPT_PER_MINUTE,
                "mDNS new-peer rate cap hit; dropping discovery"
            );
            return false;
        }
        self.mdns_rate.1 += 1;
        self.mdns_known_peers.insert(*peer_id);
        true
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

    /// **M-1 / M-2 downgrade guard (security review)**. When
    /// `NetworkConfig::allow_legacy_v1_tokens` is false, drop any
    /// inbound token in the legacy v=1 envelope. Persisted v1 state
    /// already in the local store keeps verifying — only fresh ingest
    /// from peers is gated.
    fn legacy_token_refused(&self, token: &Token, source: &str) -> bool {
        if token.wire_version() == TOKEN_WIRE_V1
            && !self.config.network.allow_legacy_v1_tokens
        {
            warn!(
                jti = %token.payload.jti,
                issuer = %token.payload.iss,
                source,
                "dropping legacy v1 token (allow_legacy_v1_tokens=false)"
            );
            true
        } else {
            false
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
        if self.legacy_token_refused(&token, "gossip-op") {
            return;
        }
        if let Err(e) = token.validate() {
            warn!("token validation failed: {e}");
            return;
        }
        // **C-3 (security review)**: before admitting the token to the
        // trust graph, reject attestations that embed a policy or
        // software document whose issuer lacks the matching publisher
        // capability. Filtering only at serve time (see
        // `LocalService::list_applicable_*`) still admitted the rogue
        // token into the graph, letting it propagate to peers whose
        // filters or agents might be older/patched differently.
        // Ingest-side reject is the authoritative gate.
        if !publisher_capability_ok(&token, &self.trust_graph, &self.trusted_roots) {
            warn!(
                jti = %token.payload.jti,
                issuer = %token.payload.iss,
                body_type = ?token.payload.body_type,
                "rejecting inbound token: issuer lacks the required publisher capability"
            );
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
    /// the gossip ingest path and the sync-applied path. Pub so that the
    /// local publish path (HTTP handler, tests) can seed the cache for
    /// ops that originate here and never travel inbound via gossip.
    pub fn cache_sync_payload(&mut self, op_id: &str, op: &Operation, token_bytes: &[u8]) {
        let mut op_bytes = Vec::new();
        if ciborium::into_writer(op, &mut op_bytes).is_err() {
            return;
        }
        // M-5: enforce a hard cap with FIFO eviction so the cache can't
        // grow unbounded under steady-state op traffic.
        while self.sync_payloads.len() >= SYNC_PAYLOAD_CACHE_CAP
            && !self.sync_payloads.contains_key(op_id)
        {
            self.sync_payloads.pop_first();
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
        if self.legacy_token_refused(&token, "gossip-revocation") {
            return;
        }
        if let Err(e) = token.validate() {
            warn!("revocation validation failed: {e}");
            return;
        }
        // **M-9 (security review)**: reject replays of old revocations.
        // A revocation's `iat` must be within REVOCATION_REPLAY_WINDOW_SECS
        // of the local wall clock. Without this gate an attacker could
        // record any old revocation and replay it indefinitely, which
        // pollutes the audit log and can cause a revoked-but-not-yet-
        // expired token to re-enter the revoked set at an inconvenient
        // time.
        if !revocation_within_replay_window(token.payload.iat) {
            warn!(
                jti = %token.payload.jti,
                iat = token.payload.iat,
                "rejecting revocation: iat is outside the replay-tolerance window"
            );
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
        if self.legacy_token_refused(&token, "gossip-burn") {
            return;
        }
        if let Err(e) = token.validate() {
            warn!("burn validation failed: {e}");
            return;
        }
        // M-9: same replay window applies to burn tokens.
        if !revocation_within_replay_window(token.payload.iat) {
            warn!(
                jti = %token.payload.jti,
                iat = token.payload.iat,
                "rejecting burn: iat is outside the replay-tolerance window"
            );
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
        let entry = match ciborium::from_reader::<dds_core::audit::AuditLogEntry, _>(entry_bytes) {
            Ok(e) => e,
            Err(e) => {
                warn!("audit entry deserialize failed: {e}");
                return;
            }
        };
        // **M-21 (security review)**: verify the entry's `node_signature`
        // and that `node_urn` cryptographically binds to `node_public_key`
        // before appending. The previous path appended any deserializable
        // entry from any peer, letting a malicious peer poison the
        // compliance trail with forged actions.
        if let Err(e) = entry.verify() {
            warn!(
                node = %entry.node_urn,
                action = %entry.action,
                error = %e,
                "rejecting forged or malformed audit entry"
            );
            return;
        }
        // **L-12 (security review)**: the store now enforces
        // `entry.prev_hash == local_chain_head()`. Inbound gossip
        // entries carry the SOURCE node's chain linkage which will
        // not match our local chain — log the rejection as an
        // integrity event rather than silently accepting it. When
        // audit-log gossip becomes a live feature it will need a
        // wrapper entry: we stamp a LOCAL `AuditLogEntry` whose
        // `action` encodes "observed inbound" and whose `token_bytes`
        // carry the original — future work.
        if let Err(e) = self.store.append_audit_entry(&entry) {
            warn!(
                node = %entry.node_urn,
                action = %entry.action,
                error = %e,
                "audit entry refused by store (likely chain mismatch from gossip)"
            );
            return;
        }
        info!(action = %entry.action, node = %entry.node_urn, "audit log entry appended");
    }

    /// **L-12 (security review)**: emit a locally-chained audit
    /// entry for an action this node just performed. Reads the
    /// current chain head from the store, stamps `prev_hash`, signs
    /// with `signing_key`, and appends. Returns the appended entry
    /// so the caller can gossip it if they choose.
    ///
    /// This is the ONE public path production code should use when
    /// generating audit entries — it guarantees the chain property
    /// holds at append time.
    pub fn emit_local_audit(
        &mut self,
        action: impl Into<String>,
        token_bytes: Vec<u8>,
        node_urn: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
        timestamp: u64,
    ) -> Result<dds_core::audit::AuditLogEntry, String> {
        let prev_hash = self
            .store
            .audit_chain_head()
            .map_err(|e| format!("chain head: {e}"))?
            .unwrap_or_default();
        let entry = dds_core::audit::AuditLogEntry::sign_ed25519_chained(
            action,
            token_bytes,
            node_urn,
            signing_key,
            timestamp,
            prev_hash,
        )
        .map_err(|e| format!("sign: {e}"))?;
        self.store
            .append_audit_entry(&entry)
            .map_err(|e| format!("append: {e}"))?;
        Ok(entry)
    }

    // ---------- anti-entropy sync (B6) ----------

    /// Build the response to an inbound sync request: every cached
    /// payload whose op_id is *not* in the requester's `known_op_ids`.
    ///
    /// **H-11 (security review)**: capped at `SYNC_MAX_RESPONSE_ENTRIES`
    /// payloads or `SYNC_MAX_RESPONSE_BYTES` of serialized op + token
    /// bytes, whichever is reached first. The previous unbounded form
    /// let a peer with `known_op_ids: {}` force the responder to clone
    /// the entire `sync_payloads` cache into one message — combined
    /// with no LRU on the cache (M-5) this was an unbounded amplification
    /// attack. Now any peer must page through repeated requests; the
    /// `complete` flag tells them whether more remains.
    fn build_sync_response(&self, req: &SyncRequest) -> SyncResponse {
        let mut payloads: Vec<SyncPayload> =
            Vec::with_capacity(SYNC_MAX_RESPONSE_ENTRIES.min(self.sync_payloads.len()));
        let mut bytes_acc: usize = 0;
        let mut complete = true;
        for (id, payload) in &self.sync_payloads {
            if req.known_op_ids.contains(id.as_str()) {
                continue;
            }
            let payload_bytes = payload.op_bytes.len() + payload.token_bytes.len();
            if payloads.len() >= SYNC_MAX_RESPONSE_ENTRIES
                || bytes_acc.saturating_add(payload_bytes) > SYNC_MAX_RESPONSE_BYTES
            {
                complete = false;
                break;
            }
            bytes_acc += payload_bytes;
            payloads.push(payload.clone());
        }
        SyncResponse { payloads, complete }
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

    /// Send a sync request to a peer unconditionally, bypassing the
    /// per-peer cooldown. Intended for tests and for the HTTP layer when
    /// a fresh enrollment makes an immediate re-sync desirable.
    pub fn force_sync_with(&mut self, peer: PeerId) {
        self.sync_last_outbound.remove(&peer);
        self.try_sync_with(peer);
    }

    /// Apply an inbound sync response: merge into trust graph + DAG +
    /// store, and cache the payloads for future serving to other peers.
    fn handle_sync_response(&mut self, peer: PeerId, resp: SyncResponse) {
        if resp.payloads.is_empty() {
            debug!(%peer, "sync: peer reported no diff");
            return;
        }
        // **C-3 (security review)**: filter out any inbound payload whose
        // token is a publisher-kind attestation from an issuer that
        // lacks the matching capability. The sync path receives the same
        // trust-graph additions as the gossip ingest path, so it must
        // run the same gate — otherwise an attacker who hits a peer's
        // sync protocol (bypassing the gossip mesh) can still seed
        // rogue policy/software tokens into every node they sync with.
        let payloads: Vec<SyncPayload> = resp
            .payloads
            .into_iter()
            .filter(|payload| {
                let token = match Token::from_cbor(&payload.token_bytes) {
                    Ok(t) => t,
                    Err(_) => return true, // let apply_sync_payloads surface the error
                };
                // **M-1 / M-2 downgrade guard**: same cutoff as the
                // gossip path. Persisted v1 on this node's disk is
                // fine; fresh ingest from a peer is not, unless the
                // operator has opted in.
                if token.wire_version() == TOKEN_WIRE_V1
                    && !self.config.network.allow_legacy_v1_tokens
                {
                    warn!(
                        %peer,
                        jti = %token.payload.jti,
                        issuer = %token.payload.iss,
                        "sync: dropping legacy v1 token (allow_legacy_v1_tokens=false)"
                    );
                    return false;
                }
                if !publisher_capability_ok(&token, &self.trust_graph, &self.trusted_roots) {
                    warn!(
                        %peer,
                        jti = %token.payload.jti,
                        issuer = %token.payload.iss,
                        body_type = ?token.payload.body_type,
                        "sync: dropping payload whose issuer lacks publisher capability"
                    );
                    return false;
                }
                // **M-9 (security review)**: the live gossip ingest path
                // runs `revocation_within_replay_window` on
                // revoke/burn tokens. The sync path has to run the
                // same check — otherwise an attacker who can push to
                // a peer's sync protocol can replay old revocations
                // that gossip would reject.
                if matches!(token.payload.kind, TokenKind::Revoke | TokenKind::Burn)
                    && !revocation_within_replay_window(token.payload.iat)
                {
                    warn!(
                        %peer,
                        jti = %token.payload.jti,
                        iat = token.payload.iat,
                        kind = ?token.payload.kind,
                        "sync: dropping revoke/burn payload: iat outside replay window"
                    );
                    return false;
                }
                true
            })
            .collect();
        if payloads.is_empty() {
            debug!(%peer, "sync: all payloads rejected by publisher capability filter");
            return;
        }
        let result = {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            apply_sync_payloads_with_graph(&payloads, &mut self.dag, &mut self.store, &mut g)
        };
        // Repopulate the sync cache so the next inbound request from
        // some other peer can serve these payloads onward. **M-5
        // (security review)**: route through `cache_sync_payload` so
        // the FIFO cap applies — the previous raw `insert` here
        // bypassed the bound.
        for payload in &payloads {
            if let Ok(op) = ciborium::from_reader::<Operation, _>(payload.op_bytes.as_slice()) {
                let id = op.id.clone();
                self.cache_sync_payload(&id, &op, &payload.token_bytes);
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

/// **M-9 (security review)**: return `true` if a revocation or burn
/// token's `iat` is within `REVOCATION_REPLAY_WINDOW_SECS` of the
/// local wall clock — i.e. neither far in the future (clock skew or
/// malicious) nor far in the past (replay). `iat == 0` is accepted
/// (legacy unstamped tokens from very old exports) to avoid a
/// wholesale rejection of pre-stamp revocations.
fn revocation_within_replay_window(iat: u64) -> bool {
    if iat == 0 {
        return true;
    }
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return true, // clock pre-1970: don't gate
    };
    // Permit small forward clock skew (up to 1 hour) but reject
    // anything beyond the replay window backwards.
    const FORWARD_SKEW_SECS: u64 = 3600;
    if iat > now.saturating_add(FORWARD_SKEW_SECS) {
        return false;
    }
    now.saturating_sub(iat) <= REVOCATION_REPLAY_WINDOW_SECS
}

/// **C-3 (security review)**: return `true` unless the token is an
/// attestation embedding one of the publisher-gated document types
/// (Windows policy, macOS policy, software assignment) whose issuer
/// does NOT hold the matching `dds:policy-publisher-*` /
/// `dds:software-publisher` capability chained to a trusted root.
///
/// Non-publisher tokens (user-auth attestations, device joins,
/// vouches, revocations, burns) are always accepted here — this
/// gate is specifically for the unauthenticated-remote-state
/// injection path the security review called out as C-3.
fn publisher_capability_ok(
    token: &Token,
    trust_graph: &Arc<RwLock<TrustGraph>>,
    trusted_roots: &BTreeSet<String>,
) -> bool {
    use dds_core::token::purpose;
    use dds_domain::body_types;

    if token.payload.kind != TokenKind::Attest {
        return true;
    }
    let body_type = match token.payload.body_type.as_deref() {
        Some(bt) => bt,
        None => return true,
    };
    let required = match body_type {
        body_types::WINDOWS_POLICY => purpose::POLICY_PUBLISHER_WINDOWS,
        body_types::MACOS_POLICY => purpose::POLICY_PUBLISHER_MACOS,
        body_types::SOFTWARE_ASSIGNMENT => purpose::SOFTWARE_PUBLISHER,
        _ => return true,
    };
    let g = match trust_graph.read() {
        Ok(g) => g,
        // Defensive: if the lock is poisoned, prefer to err on the
        // side of rejecting the token rather than panicking the event
        // loop or silently admitting a potentially rogue token.
        Err(_) => return false,
    };
    g.has_purpose(&token.payload.iss, required, trusted_roots)
}
