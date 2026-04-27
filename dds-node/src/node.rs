//! DDS node: ties together storage, trust, networking, and sync.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use dds_core::crdt::causal_dag::{CausalDag, Operation};
use dds_core::identity::Identity;
use dds_core::token::{TOKEN_WIRE_V1, Token, TokenKind};
use dds_core::trust::TrustGraph;
use dds_net::admission::{AdmissionRequest, AdmissionResponse, MAX_REVOCATIONS_PER_RESPONSE};
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

use crate::admission_revocation_store::{self, AdmissionRevocationStore};
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
    /// **H-12 (security review)**: peers that have presented a valid
    /// admission cert via the `/dds/admission/1.0.0/<domain>` handshake
    /// since the connection was established. Membership is the
    /// authoritative gate for `handle_gossip_message` and
    /// `handle_sync_event` — messages from unadmitted peers are
    /// dropped at the behaviour layer before `dds-node` ingests them.
    /// Cleared on `ConnectionClosed` so a reconnected peer must
    /// present its cert afresh.
    admitted_peers: BTreeSet<PeerId>,
    /// **Threat-model §1 — admission cert revocation list (open
    /// item #4)**: domain-signed list of peer ids that are no longer
    /// welcome. Loaded once at startup from
    /// `<data_dir>/admission_revocations.cbor`. Consulted before
    /// admitting a peer in [`Self::verify_peer_admission`] and at
    /// startup in [`Self::init`] so a revoked node refuses to start.
    /// The store is also extended at runtime via the H-12 admission
    /// handshake — neighbours piggy-back their local revocation lists
    /// onto [`AdmissionResponse::revocations`] and the requester
    /// merges any new entries (gated by signature verification).
    admission_revocations: AdmissionRevocationStore,
    /// On-disk path that backs [`Self::admission_revocations`]. Held
    /// here so the H-12 piggy-back path can persist newly-merged
    /// entries without re-reading the config; the same path is
    /// computed by [`crate::config::NodeConfig::admission_revocations_path`]
    /// at startup.
    admission_revocations_path: PathBuf,
    /// **Z-3 / Phase A.1 (observability-plan.md)**: optional Vouchsafe
    /// node identity used to emit signed audit-log entries from the
    /// gossip-ingest path. Set via [`Self::set_node_identity`] from
    /// `main.rs` after the identity store has been opened. Tests and
    /// callers that don't care about audit emission leave it `None` —
    /// the emit helpers are no-ops in that case so a missing identity
    /// never crashes the swarm event loop.
    node_identity: Option<Identity>,
    /// **observability-plan.md Phase D.2 (`/readyz` peer check)**:
    /// flipped from `false` to `true` the first time a swarm
    /// `ConnectionEstablished` event fires. Cloned (`Arc::clone`) into
    /// [`crate::http::NodeInfo::peer_seen`] before the HTTP task is
    /// spawned so the readyz handler can observe the same flag without
    /// reaching into the swarm. Sticky once set — `ConnectionClosed`
    /// does not reset it; readiness is "have we ever reached a peer",
    /// not "are we connected right now".
    peer_seen: Arc<AtomicBool>,
    /// **observability-plan.md Phase C — network gauges**: shared
    /// snapshot of `admitted_peers.len()` (`peer_counts.admitted`)
    /// and `swarm.connected_peers().count()` (`peer_counts.connected`),
    /// refreshed by [`Self::refresh_peer_count_gauges`] after every
    /// connection lifecycle event and after every successful inbound
    /// admission handshake. Cloned (`NodePeerCounts::clone`) into
    /// [`crate::telemetry::serve`] so the metrics scrape can read both
    /// gauges without reaching into the swarm task.
    peer_counts: NodePeerCounts,
}

/// Shared peer-count snapshot for the Prometheus exposition. Two
/// `Arc<AtomicU64>` so the swarm task and the metrics scrape task each
/// own a cheap-to-clone handle without locking. Updated only by the
/// swarm task in [`DdsNode::refresh_peer_count_gauges`]; reads by the
/// scrape task are `Relaxed` since neither gauge has a happens-before
/// dependency on any other state.
#[derive(Clone, Default)]
pub struct NodePeerCounts {
    /// Backing store for `dds_peers_admitted`: count of peers
    /// currently in [`DdsNode::admitted_peers`]. Reset on
    /// `ConnectionClosed` (which removes the peer from the set) and
    /// re-incremented on a successful H-12 admission handshake.
    pub admitted: Arc<AtomicU64>,
    /// Backing store for `dds_peers_connected`: count returned by
    /// `swarm.connected_peers().count()` at the last connection
    /// lifecycle event. Includes admitted *and* still-unadmitted peers
    /// — readers compute the unadmitted share as `connected - admitted`.
    pub connected: Arc<AtomicU64>,
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

        // Threat-model §1 — admission cert revocation list (open item #4):
        // Load the domain-signed revocation list and refuse to start if
        // *this* node's PeerId appears in it. Without the self-check a
        // compromised node could keep restarting after the admin issued
        // a revocation — only peer-side enforcement would stop it from
        // talking to the network.
        let revocations_path = config.admission_revocations_path();
        let admission_revocations =
            admission_revocation_store::load_or_empty(&revocations_path, domain_id, domain_pubkey)
                .map_err(|e| {
                    format!(
                        "failed to load admission revocation list from {}: {e}",
                        revocations_path.display()
                    )
                })?;
        if admission_revocations.is_revoked(&peer_id.to_string()) {
            return Err(format!(
                "this node's admission has been revoked (peer_id {peer_id}); refusing to start. \
                 Re-provision with a new libp2p keypair and a fresh admission cert to rejoin."
            )
            .into());
        }
        if !admission_revocations.is_empty() {
            info!(
                count = admission_revocations.len(),
                path = %revocations_path.display(),
                "loaded admission revocation list"
            );
        }

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
            admitted_peers: BTreeSet::new(),
            admission_revocations,
            admission_revocations_path: revocations_path,
            node_identity: None,
            peer_seen: Arc::new(AtomicBool::new(false)),
            peer_counts: NodePeerCounts::default(),
        })
    }

    /// **observability-plan.md Phase D.2**: hand out an `Arc` clone of
    /// the peer-seen flag for the HTTP `/readyz` handler. The flag is
    /// flipped on the first `ConnectionEstablished` event (sticky) and
    /// must be plumbed into [`crate::http::NodeInfo`] before
    /// `tokio::spawn(http::serve(...))` so the handler sees the same
    /// `AtomicBool`.
    pub fn peer_seen_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.peer_seen)
    }

    /// **observability-plan.md Phase C — network gauges**: hand out a
    /// `Clone` of the shared peer-count snapshot for
    /// [`crate::telemetry::serve`]. Both gauges are kept in sync by
    /// [`Self::refresh_peer_count_gauges`] inside the swarm event
    /// loop; the metrics scrape task only reads.
    pub fn peer_counts_handle(&self) -> NodePeerCounts {
        self.peer_counts.clone()
    }

    /// Refresh `dds_peers_admitted` + `dds_peers_connected` from the
    /// authoritative state in the swarm task. Called from
    /// [`Self::handle_swarm_event`] after every connection lifecycle
    /// transition and after every H-12 admission handshake outcome,
    /// so the metrics scrape always reads a value that matches a
    /// recent point-in-time snapshot of the swarm. Cheap — two
    /// `connected_peers()` iterator counts plus two `Relaxed` stores.
    fn refresh_peer_count_gauges(&self) {
        let admitted = self.admitted_peers.len() as u64;
        let connected = self.swarm.connected_peers().count() as u64;
        self.peer_counts.admitted.store(admitted, Ordering::Relaxed);
        self.peer_counts
            .connected
            .store(connected, Ordering::Relaxed);
    }

    /// **Z-3 / Phase A.1**: install the Vouchsafe node identity used to
    /// sign audit-log entries emitted from the gossip-ingest path.
    /// Should be called once after [`Self::init`] from `main.rs`,
    /// before [`Self::run`]. Tests omit this and the audit-emit
    /// helpers stay no-ops.
    pub fn set_node_identity(&mut self, identity: Identity) {
        self.node_identity = Some(identity);
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
                libp2p::gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                },
            )) => {
                // H-12: gate gossip ingest on the relayer being
                // admitted. The gossipsub signer (`message.source`) is
                // whoever originally published; `propagation_source`
                // is the peer that actually handed us this envelope.
                // An unadmitted peer should not be able to inject into
                // our ingest pipeline regardless of whom it claims to
                // be relaying for.
                if !self.admitted_peers.contains(&propagation_source) {
                    debug!(
                        peer = %propagation_source,
                        "H-12: dropping gossip from unadmitted peer"
                    );
                    return;
                }
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
            SwarmEvent::Behaviour(DdsBehaviourEvent::Admission(admission_event)) => {
                self.handle_admission_event(admission_event);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!(%peer_id, "connection established");
                // observability-plan.md Phase D.2 — sticky readiness
                // signal for `/readyz`. Set on every event because the
                // store is cheap and Relaxed; only the first transition
                // is observable to readers.
                self.peer_seen.store(true, Ordering::Relaxed);
                // H-12: initiate the admission handshake immediately
                // so the peer is either admitted (and can contribute
                // gossip / sync) or silently unadmitted (messages
                // dropped). The peer reciprocates by sending its own
                // AdmissionRequest — we'll answer by returning our
                // own cert in the Message::Request handler.
                self.request_peer_admission(peer_id);
                // NOTE: sync is *not* kicked off here any more. We
                // want peers to be admitted before we burn sync-state
                // transfer on them. The admission-success path fires
                // `try_sync_with` once the peer is verified.
                self.refresh_peer_count_gauges();
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!(%peer_id, "connection closed");
                // Drop the cooldown so a fresh reconnect immediately
                // re-syncs without waiting out the throttle.
                self.sync_last_outbound.remove(&peer_id);
                // H-12: a reconnected peer must present its cert
                // afresh — we don't trust a stale admission across
                // connection lifecycles.
                self.admitted_peers.remove(&peer_id);
                self.refresh_peer_count_gauges();
            }
            _ => {}
        }
    }

    /// Send an `AdmissionRequest` to a peer we just connected to
    /// (H-12). The peer answers with its admission cert in an
    /// `AdmissionResponse`, which we verify in
    /// `handle_admission_event`. Between `ConnectionEstablished` and
    /// receipt of a valid cert, the peer stays out of
    /// `admitted_peers` and therefore its gossip / sync is dropped.
    fn request_peer_admission(&mut self, peer_id: PeerId) {
        let _id = self
            .swarm
            .behaviour_mut()
            .admission
            .send_request(&peer_id, AdmissionRequest);
        debug!(%peer_id, "H-12: sent admission request");
    }

    /// Handle admission-protocol events (H-12). Serves our own cert
    /// in response to inbound requests, and verifies peer-supplied
    /// certs from inbound responses.
    fn handle_admission_event(&mut self, event: RrEvent<AdmissionRequest, AdmissionResponse>) {
        match event {
            RrEvent::Message { peer, message, .. } => match message {
                RrMessage::Request { channel, .. } => {
                    // Serve our own admission cert. Serialising on
                    // every request is cheap (one CBOR encode of a
                    // ~100-byte struct) and keeps us from caching a
                    // potentially-stale blob if the cert is rotated
                    // at runtime in the future.
                    let cert_cbor = match self.admission_cert.to_cbor() {
                        Ok(b) => Some(b),
                        Err(e) => {
                            warn!(%peer, error = %e, "H-12: failed to serialize our cert");
                            None
                        }
                    };
                    // Threat-model §1 / item #4 follow-up — piggy-back
                    // the local revocation list onto the response so
                    // newly connected peers pick up revocations
                    // transitively. Capped by
                    // `MAX_REVOCATIONS_PER_RESPONSE` to keep a single
                    // exchange bounded; entries beyond the cap fan
                    // out on subsequent reconnections.
                    let revocations = self.serialized_revocations_for_wire();
                    if self
                        .swarm
                        .behaviour_mut()
                        .admission
                        .send_response(
                            channel,
                            AdmissionResponse {
                                cert_cbor,
                                revocations,
                            },
                        )
                        .is_err()
                    {
                        warn!(%peer, "H-12: failed to send admission response (channel closed)");
                    }
                }
                RrMessage::Response { response, .. } => {
                    self.verify_peer_admission(peer, response);
                }
            },
            RrEvent::OutboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "H-12: admission outbound failure");
            }
            RrEvent::InboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "H-12: admission inbound failure");
            }
            RrEvent::ResponseSent { .. } => {}
        }
    }

    /// Encode up to [`MAX_REVOCATIONS_PER_RESPONSE`] entries from the
    /// local revocation store as opaque CBOR blobs for the H-12
    /// piggy-back. The order is whatever the store yields (insertion
    /// order today); deterministic ordering is not required because
    /// the receiver merges by `(peer_id, signature)` independent of
    /// position. A serialization failure on any single entry skips
    /// just that entry — the rest still ship.
    fn serialized_revocations_for_wire(&self) -> Vec<Vec<u8>> {
        let entries = self.admission_revocations.entries();
        let mut out = Vec::with_capacity(entries.len().min(MAX_REVOCATIONS_PER_RESPONSE));
        for rev in entries.iter().take(MAX_REVOCATIONS_PER_RESPONSE) {
            match rev.to_cbor() {
                Ok(b) => out.push(b),
                Err(e) => {
                    warn!(error = %e, peer_id = %rev.body.peer_id, "H-12: skipping revocation that failed to encode for piggy-back")
                }
            }
        }
        out
    }

    /// Verify a peer-supplied admission cert (H-12). On success the
    /// peer is added to `admitted_peers` and an opportunistic sync is
    /// kicked off — at this point we've proven the peer belongs to
    /// the same domain and is worth catching up with.
    ///
    /// Threat-model §1 — admission cert revocation list (open item #4):
    /// before accepting the cert we consult `admission_revocations`.
    /// A peer whose id appears there is rejected even with a valid
    /// cert, since the cert was issued before the admin revoked them.
    ///
    /// Threat-model §1 — gossip-piggyback distribution: any
    /// revocations the peer attached to its response are merged into
    /// the local store *regardless* of whether the cert verification
    /// succeeds. Each entry is independently signed by the domain
    /// key, so a peer that fails to admit can still legitimately
    /// hand us a freshly-issued revocation we should honour. Newly-
    /// merged entries are persisted atomically so the next start-up
    /// applies them at `init`.
    fn verify_peer_admission(&mut self, peer_id: PeerId, response: AdmissionResponse) {
        // Process piggy-backed revocations first. We do this even if
        // the cert later fails to verify — the revocations carry
        // their own domain-signed authority and `add` rejects any
        // entry that doesn't verify against our domain pubkey.
        self.merge_piggybacked_revocations(&peer_id, response.revocations);

        let peer_str = peer_id.to_string();
        if self.admission_revocations.is_revoked(&peer_str) {
            warn!(
                %peer_id,
                "H-12: peer is on the domain admission revocation list — refusing to admit"
            );
            crate::telemetry::record_admission_handshake("revoked");
            return;
        }
        let Some(cert_cbor) = response.cert_cbor else {
            warn!(%peer_id, "H-12: peer returned no cert — staying unadmitted");
            crate::telemetry::record_admission_handshake("fail");
            return;
        };
        let cert = match dds_domain::AdmissionCert::from_cbor(&cert_cbor) {
            Ok(c) => c,
            Err(e) => {
                warn!(%peer_id, error = ?e, "H-12: peer cert failed to decode");
                crate::telemetry::record_admission_handshake("fail");
                return;
            }
        };
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                warn!(%peer_id, error = %e, "H-12: system clock error verifying peer cert");
                crate::telemetry::record_admission_handshake("fail");
                return;
            }
        };
        match cert.verify(&self.domain_pubkey, &self.domain_id, &peer_str, now) {
            Ok(()) => {
                info!(%peer_id, "H-12: peer admitted to domain");
                self.admitted_peers.insert(peer_id);
                crate::telemetry::record_admission_handshake("ok");
                self.refresh_peer_count_gauges();
                // Now that we've verified the peer belongs to our
                // domain, kick off an opportunistic sync.
                self.try_sync_with(peer_id);
            }
            Err(e) => {
                warn!(%peer_id, error = ?e, "H-12: peer cert rejected — staying unadmitted");
                crate::telemetry::record_admission_handshake("fail");
            }
        }
    }

    /// Merge piggy-backed admission revocations from a peer's
    /// `AdmissionResponse` into the local store. Drops the entire
    /// list if it exceeds [`MAX_REVOCATIONS_PER_RESPONSE`] so a
    /// hostile sender cannot wedge the handshake by oversending; per-
    /// entry verification (signature against the domain pubkey) is
    /// the gating check for everything that survives the cap. If any
    /// new entries land, the on-disk file is rewritten atomically so
    /// the next start-up sees them.
    fn merge_piggybacked_revocations(&mut self, peer_id: &PeerId, revocations: Vec<Vec<u8>>) {
        if revocations.is_empty() {
            return;
        }
        if revocations.len() > MAX_REVOCATIONS_PER_RESPONSE {
            warn!(
                %peer_id,
                count = revocations.len(),
                cap = MAX_REVOCATIONS_PER_RESPONSE,
                "H-12: peer over-sent piggy-backed revocations — dropping"
            );
            return;
        }
        let mut decoded = Vec::with_capacity(revocations.len());
        for blob in revocations {
            match dds_domain::AdmissionRevocation::from_cbor(&blob) {
                Ok(r) => decoded.push(r),
                Err(e) => debug!(
                    %peer_id,
                    error = %e,
                    "H-12: skipping piggy-backed revocation that failed to decode"
                ),
            }
        }
        if decoded.is_empty() {
            return;
        }
        let added =
            self.admission_revocations
                .merge(crate::admission_revocation_store::RevocationListV1 {
                    v: 1,
                    entries: decoded,
                });
        if added == 0 {
            return;
        }
        // Persist the augmented list so the new entries survive
        // restart. A persistence failure must not break the
        // admission path — log loudly and leave the in-memory store
        // updated. The next successful `import-revocation` or
        // piggy-back will re-attempt the save.
        match crate::admission_revocation_store::save(
            &self.admission_revocations_path,
            &self.admission_revocations,
        ) {
            Ok(()) => info!(
                %peer_id,
                added,
                total = self.admission_revocations.len(),
                "H-12: merged piggy-backed admission revocations from peer"
            ),
            Err(e) => warn!(
                %peer_id,
                added,
                error = %e,
                path = %self.admission_revocations_path.display(),
                "H-12: merged revocations into memory but failed to persist"
            ),
        }
    }

    /// Threat-model §1 — open item #4 (admission cert revocation list):
    /// expose the in-memory revocation store for tests. The store is
    /// loaded once at startup; callers that want to force a reload
    /// (e.g. after `dds-node import-revocation`) should restart the
    /// node, since the H-12 handshake only fires on connect/reconnect.
    pub fn admission_revocations(&self) -> &AdmissionRevocationStore {
        &self.admission_revocations
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
                crate::telemetry::record_gossip_message("op");
                self.ingest_operation(&op_bytes, &token_bytes);
            }
            (DdsTopic::Revocations(..), GossipMessage::Revocation { token_bytes }) => {
                crate::telemetry::record_gossip_message("revocation");
                self.ingest_revocation(&token_bytes);
            }
            (DdsTopic::Burns(..), GossipMessage::Burn { token_bytes }) => {
                crate::telemetry::record_gossip_message("burn");
                self.ingest_burn(&token_bytes);
            }
            (DdsTopic::AuditLog(..), GossipMessage::AuditLog { entry_bytes }) => {
                crate::telemetry::record_gossip_message("audit");
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
        if token.wire_version() == TOKEN_WIRE_V1 && !self.config.network.allow_legacy_v1_tokens {
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
        // Bounded depth: op_bytes are peer-supplied. Security review I-6.
        let op: dds_core::crdt::causal_dag::Operation =
            match dds_core::cbor_bounded::from_reader(op_bytes) {
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
            self.emit_audit_from_ingest(
                rejected_action_for(&token.payload.kind),
                token_bytes.to_vec(),
                Some("legacy-v1-refused".to_string()),
            );
            return;
        }
        if let Err(e) = token.validate() {
            warn!("token validation failed: {e}");
            self.emit_audit_from_ingest(
                rejected_action_for(&token.payload.kind),
                token_bytes.to_vec(),
                Some(format!("validation-failed: {e}")),
            );
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
            self.emit_audit_from_ingest(
                rejected_action_for(&token.payload.kind),
                token_bytes.to_vec(),
                Some("publisher-capability-missing".to_string()),
            );
            return;
        }
        let graph_err = {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            g.add_token(token.clone()).err()
        };
        if let Some(e) = graph_err {
            warn!("trust graph rejected token: {e}");
            self.emit_audit_from_ingest(
                rejected_action_for(&token.payload.kind),
                token_bytes.to_vec(),
                Some(format!("trust-graph-rejected: {e}")),
            );
            return;
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
                // Z-3 Phase A.1: stamp the chain only on novel ops; a
                // duplicate token (DAG returned false) is not a state
                // change so we don't log it as one.
                self.emit_audit_from_ingest(
                    accepted_action_for(&token.payload.kind),
                    token_bytes.to_vec(),
                    None,
                );
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
            self.emit_audit_from_ingest(
                "revoke.rejected",
                token_bytes.to_vec(),
                Some("legacy-v1-refused".to_string()),
            );
            return;
        }
        if let Err(e) = token.validate() {
            warn!("revocation validation failed: {e}");
            self.emit_audit_from_ingest(
                "revoke.rejected",
                token_bytes.to_vec(),
                Some(format!("validation-failed: {e}")),
            );
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
            self.emit_audit_from_ingest(
                "revoke.rejected",
                token_bytes.to_vec(),
                Some("iat-outside-replay-window".to_string()),
            );
            return;
        }
        let graph_err = {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            g.add_token(token.clone()).err()
        };
        if let Some(e) = graph_err {
            warn!("trust graph rejected revocation: {e}");
            self.emit_audit_from_ingest(
                "revoke.rejected",
                token_bytes.to_vec(),
                Some(format!("trust-graph-rejected: {e}")),
            );
            return;
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
        // Z-3 Phase A.1: revocation accepted — record on local chain.
        self.emit_audit_from_ingest("revoke", token_bytes.to_vec(), None);
        // Seed the sync-payload cache so a peer that reconnects (or
        // joins fresh) AFTER this revoke landed via gossip can still
        // pull it from us via the request_response sync protocol.
        // Without this, only the originating publisher could relay the
        // revoke — every other node that learned about it via gossip
        // would silently fail to forward it on sync, so a partitioned
        // peer's catch-up depended on the original publisher being
        // reachable. Mirrors the `cache_sync_payload` call in
        // `ingest_operation`.
        let op = synthetic_op_for_token(&token);
        self.cache_sync_payload(&op.id, &op, token_bytes);
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
            self.emit_audit_from_ingest(
                "burn.rejected",
                token_bytes.to_vec(),
                Some("legacy-v1-refused".to_string()),
            );
            return;
        }
        if let Err(e) = token.validate() {
            warn!("burn validation failed: {e}");
            self.emit_audit_from_ingest(
                "burn.rejected",
                token_bytes.to_vec(),
                Some(format!("validation-failed: {e}")),
            );
            return;
        }
        // M-9: same replay window applies to burn tokens.
        if !revocation_within_replay_window(token.payload.iat) {
            warn!(
                jti = %token.payload.jti,
                iat = token.payload.iat,
                "rejecting burn: iat is outside the replay-tolerance window"
            );
            self.emit_audit_from_ingest(
                "burn.rejected",
                token_bytes.to_vec(),
                Some("iat-outside-replay-window".to_string()),
            );
            return;
        }
        let graph_err = {
            let mut g = self.trust_graph.write().expect("trust_graph poisoned");
            g.add_token(token.clone()).err()
        };
        if let Some(e) = graph_err {
            warn!("trust graph rejected burn: {e}");
            self.emit_audit_from_ingest(
                "burn.rejected",
                token_bytes.to_vec(),
                Some(format!("trust-graph-rejected: {e}")),
            );
            return;
        }
        if let Err(e) = self.store.put_token(&token) {
            error!("store error: {e}");
        }
        if let Err(e) = self.store.burn(&token.payload.iss) {
            error!("store burn error: {e}");
        }
        info!(urn = %token.payload.iss, "identity burned");
        // Z-3 Phase A.1: burn accepted — record on local chain.
        self.emit_audit_from_ingest("burn", token_bytes.to_vec(), None);
        // See comment in `ingest_revocation`: cache the burn so a
        // reconnecting peer can sync it from us, not just from the
        // original publisher.
        let op = synthetic_op_for_token(&token);
        self.cache_sync_payload(&op.id, &op, token_bytes);
    }

    fn ingest_audit(&mut self, entry_bytes: &[u8]) {
        if !self.config.domain.audit_log_enabled {
            return;
        }
        // Bounded depth: entry_bytes are peer-supplied via gossip. Security review I-6.
        let entry = match dds_core::cbor_bounded::from_reader::<dds_core::audit::AuditLogEntry, _>(
            entry_bytes,
        ) {
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
        self.emit_local_audit_with_reason(
            action,
            token_bytes,
            node_urn,
            signing_key,
            timestamp,
            None,
        )
    }

    /// Phase A.2 (observability-plan.md): chained-emit with an
    /// optional `reason` covering rejection paths. Older callers stay
    /// on [`Self::emit_local_audit`] for the success-only shape.
    pub fn emit_local_audit_with_reason(
        &mut self,
        action: impl Into<String>,
        token_bytes: Vec<u8>,
        node_urn: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
        timestamp: u64,
        reason: Option<String>,
    ) -> Result<dds_core::audit::AuditLogEntry, String> {
        let prev_hash = self
            .store
            .audit_chain_head()
            .map_err(|e| format!("chain head: {e}"))?
            .unwrap_or_default();
        let entry = dds_core::audit::AuditLogEntry::sign_ed25519_chained_with_reason(
            action,
            token_bytes,
            node_urn,
            signing_key,
            timestamp,
            prev_hash,
            reason,
        )
        .map_err(|e| format!("sign: {e}"))?;
        self.store
            .append_audit_entry(&entry)
            .map_err(|e| format!("append: {e}"))?;
        // observability-plan.md Phase C — bump
        // `dds_audit_entries_total{action=...}` after the chain
        // append succeeds. Mirrors the LocalService side of the
        // funnel (HTTP / admin emissions are funneled through
        // `LocalService::emit_local_audit`; gossip-ingest uses this
        // path).
        crate::telemetry::record_audit_entry(&entry.action);
        Ok(entry)
    }

    /// **Z-3 / Phase A.1 (observability-plan.md)**: emit an audit
    /// entry from a gossip-ingest path using the registered node
    /// identity. No-op when the identity has not been set (tests,
    /// fixture harnesses) so absence of audit never crashes the swarm
    /// event loop. Errors during emission are logged and swallowed —
    /// the inbound token has already been admitted to the trust graph
    /// by the time this is called.
    fn emit_audit_from_ingest(
        &mut self,
        action: &'static str,
        token_bytes: Vec<u8>,
        reason: Option<String>,
    ) {
        let (node_urn, signing_key) = match self.node_identity.as_ref() {
            Some(id) => (id.id.to_urn(), id.signing_key.clone()),
            None => return,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = self.emit_local_audit_with_reason(
            action,
            token_bytes,
            node_urn,
            &signing_key,
            now,
            reason,
        ) {
            warn!(action, error = %e, "audit: emit-from-ingest failed");
        }
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
            // Bounded depth: peer-supplied. Security review I-6.
            if let Ok(op) =
                dds_core::cbor_bounded::from_reader::<Operation, _>(payload.op_bytes.as_slice())
            {
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
                    // H-12: refuse to serve sync data to unadmitted
                    // peers. Dropping the channel closes the stream
                    // without a response; the requester sees an
                    // `OutboundFailure::ConnectionClosed`.
                    if !self.admitted_peers.contains(&peer) {
                        debug!(%peer, "H-12: dropping sync request from unadmitted peer");
                        drop(channel);
                        return;
                    }
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
                    // H-12: ignore sync responses from unadmitted
                    // peers — their payloads could carry unauthorised
                    // state. Without admission we can't trust the
                    // peer belongs to our domain.
                    if !self.admitted_peers.contains(&peer) {
                        debug!(%peer, "H-12: dropping sync response from unadmitted peer");
                        return;
                    }
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

    /// H-12: read-only view of peers admitted to this node's domain
    /// during the current connection lifecycle. Primarily for tests
    /// that want to assert the admission handshake completed.
    pub fn admitted_peers(&self) -> &BTreeSet<PeerId> {
        &self.admitted_peers
    }

    /// H-12 test hook: overwrite the cert this node hands out to
    /// peers during the admission handshake. Used by the H-12
    /// regression suite to simulate a peer presenting a cert that
    /// will fail verification at the remote end (e.g., issued for
    /// the wrong peer id). Not intended for production use — the
    /// real cert is verified against this node's own peer id at
    /// `init()` time, and we don't want a running node to
    /// accidentally re-key itself.
    #[doc(hidden)]
    pub fn set_admission_cert_for_tests(&mut self, cert: dds_domain::AdmissionCert) {
        self.admission_cert = cert;
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

/// Z-3 Phase A.1 audit-action vocabulary helpers (observability-plan.md).
/// `Attest` and `Vouch` tokens flow through `ingest_operation`; the
/// dedicated `Revoke` and `Burn` topics have their own ingest paths
/// and pass their action strings inline.
fn accepted_action_for(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Attest => "attest",
        TokenKind::Vouch => "vouch",
        TokenKind::Revoke => "revoke",
        TokenKind::Burn => "burn",
    }
}

fn rejected_action_for(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Attest => "attest.rejected",
        TokenKind::Vouch => "vouch.rejected",
        TokenKind::Revoke => "revoke.rejected",
        TokenKind::Burn => "burn.rejected",
    }
}

/// **C-3 (security review)**: return `true` unless the token is an
/// attestation embedding one of the publisher-gated document types
/// (Windows policy, macOS policy, software assignment) whose issuer
/// does NOT hold the matching `dds:policy-publisher-*` /
/// `dds:software-publisher` capability chained to a trusted root.
///
/// Build a deterministic synthetic `Operation` for a token that
/// arrived on a side-channel topic (Revocation / Burn). The sync
/// protocol carries (op, token) pairs — using a stable id keyed on
/// the token's JTI ensures the publisher and any relay node compute
/// the same cache key, so the responder's `known_op_ids` filter
/// correctly dedupes when the requester already has the token.
fn synthetic_op_for_token(token: &Token) -> Operation {
    Operation {
        id: format!("op-{}", token.payload.jti),
        author: token.payload.iss.clone(),
        deps: Vec::new(),
        data: Vec::new(),
        timestamp: 0,
    }
}

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
    let ok = g.has_purpose(&token.payload.iss, required, trusted_roots);
    crate::telemetry::record_purpose_lookup(if ok { "ok" } else { "denied" });
    ok
}
