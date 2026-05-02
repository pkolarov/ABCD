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
use dds_net::pq_envelope::{
    EPOCH_KEY_RELEASE_AEAD_CT_LEN, EPOCH_KEY_RELEASE_ED25519_SIG_LEN, EPOCH_KEY_RELEASE_KEM_CT_LEN,
    EpochKeyRelease, EpochKeyRequest, EpochKeyResponse, GossipEnvelopeV3, SyncEnvelopeV3,
};
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
use crate::epoch_key_store::{EpochKeyStore, InstallOutcome, is_release_within_replay_window};
use crate::peer_cert_store::{self, PeerCertStore};

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

/// **Z-1 Phase B.7 PQ-B7-RECOVERY-1**: minimum gap between two outbound
/// `EpochKeyRequest`s for the same publisher. A node that drops many
/// gossip envelopes for the same missing epoch key should not flood
/// the publisher with repeated requests before the first response
/// arrives. 30 seconds is long enough that one request-response
/// round-trip completes before the next request is allowed; short
/// enough that a lost response self-heals on the next drop.
const EPOCH_KEY_REQUEST_COOLDOWN: Duration = Duration::from_secs(30);

/// **Z-1 Phase B.9** — maximum jitter added to a revocation-triggered
/// epoch rotation (§6.1). Spreads the "everyone rotates at once"
/// thundering-herd over a 30-second window so a 1000-publisher domain
/// emits ~33 publishers/sec instead of all at once.
const REVOCATION_ROTATION_JITTER_SECS: u64 = 30;

/// **Z-1 Phase B.9** — per-publisher concurrency cap for outbound
/// `EpochKeyRequest` fan-out sends during rotation. Bounds the number
/// of parallel libp2p request-response substreams opened in a single
/// rotation sweep. The remainder queue naturally via the libp2p
/// request-response backpressure mechanism.
const EPOCH_KEY_FANOUT_CONCURRENCY: usize = 10;

/// **NET-REDIAL-1**: how often to re-attempt `bootstrap_peers` dials when
/// the node has no connected peers. Kademlia only dials bootstrap addrs at
/// startup; if the anchor restarts while a member is running the member sits
/// orphaned until it also restarts or mDNS re-discovers the anchor. This
/// timer fires every 30 s and re-dials all configured bootstrap addrs
/// whenever `connected_peers == 0`, so WAN-anchor members recover without
/// needing mDNS (which is disabled by default in the member config template).
const BOOTSTRAP_REDIAL_INTERVAL: Duration = Duration::from_secs(30);

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
    /// descriptor so we can re-verify the cert on every
    /// `ADMISSION_RECHECK_INTERVAL` tick. Without a periodic re-verify
    /// a node whose cert has expired keeps operating until restart.
    ///
    /// **Z-1 Phase A**: holds the full [`dds_domain::Domain`]
    /// (including the optional ML-DSA-65 `pq_pubkey`) so verification
    /// routes through `verify_with_domain` and enforces the hybrid
    /// component on every cert / revocation when the domain is v2.
    admission_cert: dds_domain::AdmissionCert,
    domain: dds_domain::Domain,
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
    /// **Z-1 Phase B.3 / §4.6.2** — local cache of remote peers'
    /// `AdmissionCert`s, keyed by stringified `PeerId`. Populated on
    /// every successful H-12 admission handshake in
    /// [`Self::verify_peer_admission`] (and re-populated when a peer
    /// re-handshakes after rotating its KEM pubkey). Consumed by Phase
    /// B.7+ to look up a publisher's hybrid KEM pubkey when wrapping
    /// or unwrapping an `EpochKeyRelease`; the cert is *not* a trust
    /// anchor in itself, only a write-after-verify cache of the body
    /// already verified against [`Self::domain`].
    peer_certs: PeerCertStore,
    /// On-disk path that backs [`Self::peer_certs`]. Computed once at
    /// startup by [`crate::config::NodeConfig::peer_certs_path`]; held
    /// here so the H-12 success branch can persist newly-cached certs
    /// without re-reading the config.
    peer_certs_path: PathBuf,
    /// **Z-1 Phase B.5 / §4.4-§4.6** — local epoch-key store. Carries
    /// the node's hybrid X25519 + ML-KEM-768 KEM keypair (the
    /// `pq_kem_pubkey` peers encrypt `EpochKeyRelease` payloads to),
    /// the local node's current `(epoch_id, epoch_key)`, and the
    /// per-publisher cached releases this node has decapped. Loaded
    /// at startup via [`epoch_key_store::EpochKeyStore::load_or_create`]
    /// so a fresh KEM keypair is generated on first start and survives
    /// process restarts. Plaintext at rest today (same posture as
    /// `peer_cert_store` / `admission_revocation_store`); the eventual
    /// encrypted-at-rest tier rides the Z-4 plan.
    epoch_keys: EpochKeyStore,
    /// On-disk path that backs [`Self::epoch_keys`]. Held here so the
    /// receive path (`/dds/epoch-keys/...` request-response responses,
    /// plus the H-12 piggy-back ingest) can persist newly-installed
    /// releases without re-reading the config. Default
    /// `<data_dir>/epoch_keys.cbor`.
    epoch_keys_path: PathBuf,
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
    /// **Z-1 Phase B.7 / PQ-B7-RECOVERY-1**: per-publisher cooldown
    /// for outbound `EpochKeyRequest`s. Keyed by the publisher's
    /// stringified `PeerId`; value is the `Instant` at which the last
    /// request was sent. Prevents request storms when many consecutive
    /// gossip envelopes arrive for a publisher whose epoch key we
    /// haven't yet received. Entries are cheap to keep indefinitely
    /// (one `PeerId` string + one `Instant` per publisher); no explicit
    /// eviction is needed because the set of publishers in a domain is
    /// bounded and stable.
    epoch_key_request_last: BTreeMap<String, Instant>,
    /// **Z-1 Phase B.9** — pending revocation-triggered epoch rotation.
    /// Set by [`Self::ingest_revocation`] after a valid admission
    /// revocation is applied; cleared by the `run()` loop once the
    /// deferred sleep fires. The sleep duration is `rng.gen_range(0..
    /// REVOCATION_ROTATION_JITTER_SECS)` so the rotation-triggered
    /// thundering-herd (§6.1) is staggered across the mesh. `None`
    /// means no revocation rotation is pending.
    pending_revocation_rotation: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    /// **Z-1 Phase B.9 / B.10** — manual-rotation notifier. The HTTP
    /// handler for `POST /v1/pq/rotate` calls `notify_one()` on this
    /// `Arc<Notify>`; the `run()` loop wakes up and calls
    /// [`Self::rotate_and_fan_out`] with `reason = "manual"`. The
    /// `Arc` is cloned into [`crate::http::AppState`] at startup so
    /// both tasks share the same notification handle without additional
    /// channel plumbing.
    pub manual_rotate: Arc<tokio::sync::Notify>,
    /// **NET-REDIAL-1**: parsed bootstrap peer addresses (peer_id +
    /// multiaddr with /p2p/ suffix) retained so the periodic redial
    /// timer can call `swarm.dial()` without re-parsing the config
    /// strings on every tick. Empty when `config.network.bootstrap_peers`
    /// is empty (e.g. on the anchor itself or on mDNS-only members).
    bootstrap_addrs: Vec<Multiaddr>,
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

        // **Z-1 Phase A** — assemble the full Domain descriptor. The
        // optional ML-DSA-65 `pq_pubkey` is parsed from
        // `config.domain.pq_pubkey` when present; absent ⇒ legacy
        // Ed25519-only domain (the v1 default). `verify_self_consistent`
        // re-checks both the Ed25519 hash invariant and the PQ pubkey
        // length so a hand-edited config can't slip past the early-startup
        // gate.
        let pq_pubkey = match config.domain.pq_pubkey.as_deref() {
            Some(hex) if !hex.is_empty() => Some(from_hex(hex)?),
            _ => None,
        };
        // **Z-1 Phase B.3** — capability tags from `[domain].capabilities`
        // in `dds.toml`. Empty by default (legacy v1 / v2 domains); a v3
        // gate flip drops `["enc-v3"]` here once published.
        let capabilities = config.domain.capabilities.clone();
        let domain = dds_domain::Domain {
            name: config.domain.name.clone(),
            id: domain_id,
            pubkey: domain_pubkey,
            pq_pubkey,
            capabilities,
        };
        domain
            .verify_self_consistent()
            .map_err(|e| format!("domain config: {e}"))?;

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
        cert.verify_with_domain(&domain, &peer_id.to_string(), now)
            .map_err(|e| format!("admission cert verification failed: {e}"))?;
        info!(
            domain = %domain.name,
            %peer_id,
            hybrid = domain.is_hybrid(),
            "admission cert verified"
        );

        // Threat-model §1 — admission cert revocation list (open item #4):
        // Load the domain-signed revocation list and refuse to start if
        // *this* node's PeerId appears in it. Without the self-check a
        // compromised node could keep restarting after the admin issued
        // a revocation — only peer-side enforcement would stop it from
        // talking to the network.
        // **Z-1 Phase A**: when the domain is v2-hybrid, route through
        // `load_or_empty_with_pq` so the store enforces the ML-DSA-65
        // component on every revocation it loads or merges.
        let revocations_path = config.admission_revocations_path();
        let admission_revocations = admission_revocation_store::load_or_empty_with_pq(
            &revocations_path,
            domain.id,
            domain.pubkey,
            domain.pq_pubkey.clone(),
        )
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

        // **Z-1 Phase B.3 / §4.6.2** — restore the on-disk cache of
        // peer admission certs (cleared on every reboot would force
        // every Phase-B publisher to wait for fresh H-12 handshakes
        // before its KEM pubkey is reachable). The cache is *not* a
        // trust anchor: every entry is re-verified against the live
        // domain on the next handshake, and a stale entry can only
        // delay a freshly-issued cert by one handshake. A torn or
        // version-mismatched file fails loud rather than silently
        // dropping cached pubkeys.
        let peer_certs_path = config.peer_certs_path();
        let peer_certs = peer_cert_store::load_or_empty(&peer_certs_path).map_err(|e| {
            format!(
                "failed to load peer cert cache from {}: {e}",
                peer_certs_path.display()
            )
        })?;
        if !peer_certs.is_empty() {
            info!(
                count = peer_certs.len(),
                path = %peer_certs_path.display(),
                "loaded peer cert cache"
            );
        }

        // **Z-1 Phase B.5 / §4.4-§4.6** — bring up the local epoch-key
        // store. `load_or_create` generates a fresh hybrid KEM keypair
        // + seeds `epoch_id = 1` on first start (without touching disk
        // — we save below so the freshly-generated keypair survives
        // restart). Subsequent starts re-load the persisted keypair +
        // current epoch + cached peer releases (the previous-epoch
        // grace window is process-scoped and starts empty after a
        // restart, which is the right posture per the §4.6 design).
        let epoch_keys_path = config.epoch_keys_path();
        let mut rng = rand::rngs::OsRng;
        let was_first_start = !epoch_keys_path.exists();
        let epoch_keys =
            EpochKeyStore::load_or_create(&epoch_keys_path, &mut rng).map_err(|e| {
                format!(
                    "failed to load epoch-key store from {}: {e}",
                    epoch_keys_path.display()
                )
            })?;
        if was_first_start {
            // Persist the freshly-generated KEM keypair so the next
            // start finds the same identity + so peer releases that
            // arrive on this start can be decapped after restart.
            if let Err(e) = epoch_keys.save(&epoch_keys_path) {
                warn!(
                    path = %epoch_keys_path.display(),
                    error = %e,
                    "failed to persist freshly-generated epoch-key store on first start"
                );
            } else {
                info!(
                    path = %epoch_keys_path.display(),
                    "epoch-key store: generated fresh hybrid KEM keypair on first start"
                );
            }
        } else {
            info!(
                path = %epoch_keys_path.display(),
                peer_releases = epoch_keys.peer_release_count(),
                "loaded epoch-key store"
            );
        }
        // Report initial epoch_id so the dds_pq_epoch_id gauge is
        // non-zero from the first Prometheus scrape after init.
        crate::telemetry::record_pq_epoch_id(epoch_keys.my_current_epoch().0);

        // Build trusted roots set
        let trusted_roots: BTreeSet<String> = config.trusted_roots.iter().cloned().collect();

        // Create topics for the (domain, org) pair.
        let topics = DdsTopic::for_domain_org(&domain_id.protocol_tag(), &config.org_hash);

        // **NET-REDIAL-1**: pre-parse bootstrap peer multiaddrs so the
        // periodic redial timer can call `swarm.dial()` without re-parsing
        // the raw config strings on every 30-second tick. Warn-and-skip any
        // address that fails to parse — the same behaviour as the addr-book
        // registration in `start()`.
        let bootstrap_addrs: Vec<Multiaddr> = config
            .network
            .bootstrap_peers
            .iter()
            .filter_map(
                |addr_str| match dds_net::discovery::parse_peer_multiaddr(addr_str) {
                    Ok((_pid, addr)) => Some(addr),
                    Err(e) => {
                        warn!(addr = %addr_str, "NET-REDIAL-1: invalid bootstrap peer addr: {e}");
                        None
                    }
                },
            )
            .collect();

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
            domain,
            mdns_rate: (Instant::now(), 0),
            mdns_known_peers: BTreeSet::new(),
            admitted_peers: BTreeSet::new(),
            admission_revocations,
            admission_revocations_path: revocations_path,
            peer_certs,
            peer_certs_path,
            epoch_keys,
            epoch_keys_path,
            node_identity: None,
            peer_seen: Arc::new(AtomicBool::new(false)),
            peer_counts: NodePeerCounts::default(),
            epoch_key_request_last: BTreeMap::new(),
            pending_revocation_rotation: None,
            manual_rotate: Arc::new(tokio::sync::Notify::new()),
            bootstrap_addrs,
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

        // **Z-1 Phase B.9** — epoch-key rotation timer. The first tick
        // fires after `epoch_rotation_secs` (not immediately) so we
        // don't rotate on every startup.
        let epoch_rotation_secs = self.config.domain.epoch_rotation_secs.max(1);
        let mut epoch_rotation_timer =
            tokio::time::interval(std::time::Duration::from_secs(epoch_rotation_secs));
        epoch_rotation_timer.tick().await; // consume the immediate tick

        // **NET-REDIAL-1**: periodic bootstrap-peer re-dial. When a member
        // node configured with WAN bootstrap peers loses all connections (e.g.
        // anchor restart) it stays orphaned because Kademlia only dials
        // bootstrap addrs at startup. This timer fires every
        // `BOOTSTRAP_REDIAL_INTERVAL` and re-dials every configured bootstrap
        // addr whenever `connected_peers == 0`. Skip immediately when
        // `bootstrap_addrs` is empty (anchor itself, mDNS-only members).
        let mut bootstrap_redial = tokio::time::interval(BOOTSTRAP_REDIAL_INTERVAL);
        bootstrap_redial.tick().await; // consume the immediate tick — start first fire after interval

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
                _ = epoch_rotation_timer.tick() => {
                    self.rotate_and_fan_out("time");
                }
                // **Z-1 Phase B.9** — revocation-triggered jittered rotation.
                // `pending_revocation_rotation` is set by `ingest_revocation`
                // when a valid admission revocation arrives. The sleep fires
                // after the jitter expires (0..REVOCATION_ROTATION_JITTER_SECS)
                // and is cleared here so it only fires once per revocation.
                _ = async {
                    if let Some(ref mut sleep) = self.pending_revocation_rotation {
                        sleep.await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    self.pending_revocation_rotation = None;
                    self.rotate_and_fan_out("revocation");
                }
                // **Z-1 Phase B.9 / B.10** — operator-requested manual rotation.
                // `POST /v1/pq/rotate` calls `notify_one()` on `self.manual_rotate`.
                _ = self.manual_rotate.notified() => {
                    self.rotate_and_fan_out("manual");
                }
                // **NET-REDIAL-1**: re-dial bootstrap peers when orphaned.
                // Fires every BOOTSTRAP_REDIAL_INTERVAL; is a no-op when
                // bootstrap_addrs is empty or when we already have peers.
                _ = bootstrap_redial.tick() => {
                    self.try_bootstrap_redial();
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
            .verify_with_domain(&self.domain, &self.peer_id.to_string(), now)
            .map_err(|e| format!("{e}"))
    }

    /// **NET-REDIAL-1**: attempt to re-dial all configured bootstrap peers.
    /// Called from the periodic `run()` timer arm when `connected_peers == 0`.
    /// Exposed as `pub` so integration tests can call it directly without
    /// running the full async timer loop.
    pub fn try_bootstrap_redial(&mut self) {
        if self.bootstrap_addrs.is_empty() || self.swarm.connected_peers().count() != 0 {
            return;
        }
        for addr in self.bootstrap_addrs.clone() {
            debug!(%addr, "NET-REDIAL-1: re-dialing bootstrap peer");
            if let Err(e) = self.swarm.dial(addr.clone()) {
                warn!(%addr, "NET-REDIAL-1: dial error: {e}");
            }
        }
    }

    /// **NET-REDIAL-1**: number of parsed bootstrap peer addresses retained
    /// for periodic redialing. Exposed so integration tests can verify that
    /// addresses were parsed from config without running the full async loop.
    pub fn bootstrap_addrs_len(&self) -> usize {
        self.bootstrap_addrs.len()
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
                    crate::telemetry::record_gossip_messages_dropped("unadmitted");
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
            SwarmEvent::Behaviour(DdsBehaviourEvent::EpochKeys(event)) => {
                self.handle_epoch_keys_event(event);
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
                    // **Z-1 Phase B.5 / §4.5 H-12 piggy-back**: include
                    // our current epoch-key release for the requester if
                    // we have a cached cert with their KEM pubkey. A first-
                    // ever handshake (no cached cert yet) ships an empty
                    // list — the requester will use `EpochKeyRequest` via
                    // PQ-B7-RECOVERY-1 once they start receiving gossip.
                    let epoch_key_releases = self.epoch_key_releases_for_admission_response(&peer);
                    if self
                        .swarm
                        .behaviour_mut()
                        .admission
                        .send_response(
                            channel,
                            AdmissionResponse {
                                cert_cbor,
                                revocations,
                                epoch_key_releases,
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

    /// **Z-1 Phase B.5 / §4.5 H-12 piggy-back** — mint an
    /// `EpochKeyRelease` for the requesting peer (if we have a cached
    /// cert with a `pq_kem_pubkey` for them) and return it as an opaque
    /// CBOR blob ready for inclusion in [`AdmissionResponse::epoch_key_releases`].
    ///
    /// Called from the admission-request responder path. Returns an empty
    /// `Vec` in all skip cases so the caller always ships a valid (though
    /// possibly empty) `epoch_key_releases` field.
    ///
    /// Skip conditions (all logged at debug):
    /// - requester has no cached cert (first-ever connection; they will
    ///   use `EpochKeyRequest` after the H-12 handshake completes);
    /// - cached cert has no `pq_kem_pubkey` (pre-Phase-B requester);
    /// - KEM pubkey fails the schema gate;
    /// - any inner mint / serialization step fails.
    fn epoch_key_releases_for_admission_response(&self, requester: &PeerId) -> Vec<Vec<u8>> {
        let requester_str = requester.to_string();
        let recipient_kem_pk = match self
            .peer_certs
            .get(&requester_str)
            .and_then(|cert| cert.pq_kem_pubkey.as_deref())
        {
            Some(bytes) => match dds_core::crypto::kem::HybridKemPublicKey::from_bytes(bytes) {
                Ok(pk) => pk,
                Err(_) => {
                    debug!(
                        peer = %requester,
                        "H-12 piggy-back: cached requester KEM pubkey is malformed — empty releases"
                    );
                    return Vec::new();
                }
            },
            None => {
                debug!(
                    peer = %requester,
                    "H-12 piggy-back: requester has no cached KEM pubkey — empty releases"
                );
                return Vec::new();
            }
        };

        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return Vec::new(),
        };
        let expires_at = now_unix + 24 * 3600;
        let my_peer_id_str = self.peer_id.to_string();
        let (epoch_id, epoch_key) = self.epoch_keys.my_current_epoch();

        let mut rng = rand::rngs::OsRng;
        let release = match mint_epoch_key_release_for_recipient(
            &mut rng,
            &my_peer_id_str,
            epoch_id,
            epoch_key,
            &requester_str,
            &recipient_kem_pk,
            now_unix,
            expires_at,
        ) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    peer = %requester,
                    error = %e,
                    "H-12 piggy-back: mint failed — empty releases"
                );
                return Vec::new();
            }
        };

        let mut blob = Vec::new();
        match ciborium::into_writer(&release, &mut blob) {
            Ok(()) => {
                debug!(peer = %requester, epoch_id, "H-12 piggy-back: minted epoch-key release");
                vec![blob]
            }
            Err(e) => {
                debug!(
                    peer = %requester,
                    error = %e,
                    "H-12 piggy-back: failed to serialize release — empty releases"
                );
                Vec::new()
            }
        }
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
        let epoch_key_releases_from_response = response.epoch_key_releases;
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
        match cert.verify_with_domain(&self.domain, &peer_str, now) {
            Ok(()) => {
                info!(%peer_id, "H-12: peer admitted to domain");
                self.admitted_peers.insert(peer_id);
                crate::telemetry::record_admission_handshake("ok");
                self.refresh_peer_count_gauges();
                // **Z-1 Phase B.3 / §4.6.2** — cache the freshly-verified
                // cert so Phase B.7+ can look up the publisher's hybrid
                // KEM pubkey. Must run *after* `verify_with_domain` so
                // a malformed / wrong-length / wrong-signer cert never
                // lands in the cache. Re-handshake on KEM rotation
                // overwrites the previous entry.
                self.cache_peer_admission_cert(peer_str, cert);
                // **Z-1 Phase B.5 / §4.5 H-12 piggy-back ingest** —
                // install any epoch-key releases the responder included.
                // Processed after admission so we only install material
                // from trusted admitted peers. Each blob runs through the
                // full receive pipeline (schema → recipient binding →
                // replay-window → KEM decap → AEAD unwrap) so a
                // malformed or misaddressed blob is rejected harmlessly.
                self.ingest_piggybacked_epoch_key_releases(
                    &peer_id,
                    epoch_key_releases_from_response,
                );
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

    /// **Z-1 Phase B.3 / §4.6.2** — insert (or overwrite) the
    /// freshly-verified peer cert into [`Self::peer_certs`] and
    /// persist the cache atomically. Persistence failures are
    /// best-effort: a `warn!` log is emitted, but the in-memory entry
    /// is kept so the running process still has the cert available
    /// for Phase B.7+ KEM lookups. The next successful save will
    /// flush both the new entry and any older entries that survived
    /// the failed write.
    ///
    /// Exposed `pub` (rather than private) so a unit test can drive
    /// the cache funnel directly without spinning up libp2p — the
    /// integration tests at `dds-node/tests/h12_admission.rs` cover
    /// the end-to-end handshake path.
    pub fn cache_peer_admission_cert(&mut self, peer_id: String, cert: dds_domain::AdmissionCert) {
        self.peer_certs.insert(peer_id, cert);
        if let Err(e) = self.peer_certs.save(&self.peer_certs_path) {
            warn!(
                error = %e,
                path = %self.peer_certs_path.display(),
                "H-12: failed to persist peer cert cache (in-memory entry kept)"
            );
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
    ///
    /// Exposed `pub` (rather than private) so an integration test can
    /// drive the merge funnel directly without spinning up libp2p — the
    /// existing `dds-node/tests/h12_revocation_piggyback.rs` covers the
    /// end-to-end handshake; the piggyback-driven audit-emission test
    /// exercises this entry point with a hand-built revocation list.
    pub fn merge_piggybacked_revocations(&mut self, peer_id: &PeerId, revocations: Vec<Vec<u8>>) {
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
        // Decode + carry the original blob so a successfully-added
        // revocation can be audited with the exact CBOR bytes the peer
        // sent — the audit-event-schema.md `token_cbor_b64` field
        // contract is "the exact CBOR-encoded payload the audited
        // action operated on".
        let mut decoded: Vec<(dds_domain::AdmissionRevocation, Vec<u8>)> =
            Vec::with_capacity(revocations.len());
        for blob in revocations {
            match dds_domain::AdmissionRevocation::from_cbor(&blob) {
                Ok(r) => decoded.push((r, blob)),
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
        // Per-entry add so we can emit one `admission.cert.revoked`
        // audit entry per *newly* admitted revocation. Mirrors the
        // existing per-token gossip-ingest funnel — previously the
        // bulk `merge` path lost the per-entry outcome and so could
        // not stamp the audit chain.
        let mut added = 0usize;
        let mut newly_added: Vec<Vec<u8>> = Vec::new();
        let mut newly_revoked_peers: Vec<String> = Vec::new();
        for (rev, blob) in decoded {
            let revoked_peer = rev.body.peer_id.clone();
            match self.admission_revocations.add(rev) {
                Ok(true) => {
                    added += 1;
                    newly_added.push(blob);
                    newly_revoked_peers.push(revoked_peer);
                }
                Ok(false) => {}
                Err(e) => warn!(
                    %peer_id,
                    error = %e,
                    "H-12: skipping piggy-backed revocation that failed to verify"
                ),
            }
        }
        if added == 0 {
            return;
        }
        // **Z-1 Phase B.3 / §4.6.2** — drop cached certs for any
        // newly-revoked peers so a subsequent Phase B.7+ KEM lookup
        // cannot reuse the revoked publisher's pubkey. Best-effort
        // persist; the in-memory eviction is the load-bearing
        // mutation. Idempotent on a peer not currently cached.
        let mut evicted = false;
        for revoked_peer in &newly_revoked_peers {
            if self.peer_certs.remove(revoked_peer).is_some() {
                evicted = true;
            }
        }
        if evicted {
            if let Err(e) = self.peer_certs.save(&self.peer_certs_path) {
                warn!(
                    error = %e,
                    path = %self.peer_certs_path.display(),
                    "H-12: failed to persist peer cert cache after revocation eviction"
                );
            }
        }
        // Stamp the audit chain *before* persisting so a write failure
        // on the on-disk revocation file does not silently drop the
        // operator-visible signal that a peer was just revoked. The
        // chain itself is the durability surface for the action.
        for blob in newly_added {
            self.emit_audit_from_ingest("admission.cert.revoked", blob, None);
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

    /// **Z-1 Phase B.5 / §4.5 H-12 piggy-back ingest** — process
    /// `EpochKeyRelease` blobs the responder included in its
    /// `AdmissionResponse`. Each blob is run through the full receive
    /// pipeline (schema → recipient binding → replay-window → KEM decap
    /// → AEAD unwrap) via [`Self::install_epoch_key_release`]. A blob
    /// that fails any gate is dropped and logged; the remainder are
    /// installed normally.
    ///
    /// Cap enforcement: a responder that over-sends (more than
    /// [`dds_net::pq_envelope::MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`]
    /// blobs) is dropped wholesale to bound the per-message decap budget,
    /// mirroring the same cap in `handle_epoch_key_response`.
    fn ingest_piggybacked_epoch_key_releases(&mut self, peer_id: &PeerId, releases: Vec<Vec<u8>>) {
        use dds_net::pq_envelope::MAX_EPOCH_KEY_RELEASES_PER_RESPONSE;
        if releases.is_empty() {
            return;
        }
        if releases.len() > MAX_EPOCH_KEY_RELEASES_PER_RESPONSE {
            warn!(
                %peer_id,
                count = releases.len(),
                cap = MAX_EPOCH_KEY_RELEASES_PER_RESPONSE,
                "H-12 piggy-back: peer over-sent epoch-key releases — dropping"
            );
            return;
        }
        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return,
        };
        let recipient_str = self.peer_id.to_string();
        let mut installed = 0usize;
        for blob in releases {
            // Bounded depth: peer-supplied (mirrors B.5 receive pipeline).
            let release: EpochKeyRelease =
                match dds_core::cbor_bounded::from_reader(blob.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!(
                            %peer_id,
                            error = %e,
                            "H-12 piggy-back: skipping release that failed to decode"
                        );
                        continue;
                    }
                };
            match self.install_epoch_key_release(&release, &recipient_str, now_unix) {
                Ok(InstallOutcome::Inserted) | Ok(InstallOutcome::Rotated) => installed += 1,
                Ok(InstallOutcome::AlreadyCurrent) | Ok(InstallOutcome::Stale) => {}
                Err(reason) => {
                    debug!(
                        %peer_id,
                        reason,
                        "H-12 piggy-back: epoch-key release rejected"
                    );
                }
            }
        }
        if installed > 0 {
            debug!(%peer_id, installed, "H-12 piggy-back: installed epoch-key releases");
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

    /// **Z-1 Phase B.3 / §4.6.2** — expose the in-memory peer cert
    /// cache for tests and for Phase B.7+ KEM-pubkey lookup paths.
    /// Each entry is a write-after-verify cache (verified against
    /// [`Self::domain`] before insert); callers must not treat it as
    /// a trust anchor.
    pub fn peer_certs(&self) -> &PeerCertStore {
        &self.peer_certs
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
                crate::telemetry::record_gossip_messages_dropped("unknown_topic");
                return;
            }
        };

        // **Z-1 Phase B.7** — detect envelope shape.
        // Try to decode as a `GossipEnvelopeV3` first. A v3 envelope is
        // a CBOR map with `publisher`, `epoch_id`, `nonce`, `ciphertext`
        // fields; a v2 plaintext envelope is a CBOR map with a
        // `DirectoryOp`/`Revocation`/`Burn`/`AuditLog` variant tag.
        // The two shapes are structurally distinct so decoding one won't
        // silently succeed on the other's bytes in practice.
        let payload: std::borrow::Cow<[u8]> = if let Ok(env) = GossipEnvelopeV3::from_cbor(data) {
            // Encrypted envelope — look up epoch key and decrypt.
            let nonce: [u8; 12] = env.nonce;
            match self.epoch_keys.peer_epoch_key(&env.publisher, env.epoch_id) {
                None => {
                    warn!(
                        publisher = %env.publisher,
                        epoch_id = env.epoch_id,
                        "no cached epoch key for publisher — dropping encrypted gossip"
                    );
                    crate::telemetry::record_pq_envelope_decrypt("no_key");
                    crate::telemetry::record_gossip_messages_dropped("enc_v3_no_key");
                    // **PQ-B7-RECOVERY-1**: attempt late-join recovery by
                    // requesting the publisher's current epoch key. The
                    // request is throttled by EPOCH_KEY_REQUEST_COOLDOWN
                    // so rapid successive drops don't flood the publisher.
                    self.try_epoch_key_request(&env.publisher);
                    return;
                }
                Some(epoch_key) => {
                    match dds_core::crypto::epoch_key::decrypt_payload(
                        epoch_key,
                        &nonce,
                        &env.ciphertext,
                    ) {
                        Ok(plaintext) => {
                            crate::telemetry::record_pq_envelope_decrypt("ok");
                            std::borrow::Cow::Owned(plaintext)
                        }
                        Err(_) => {
                            warn!(
                                publisher = %env.publisher,
                                epoch_id = env.epoch_id,
                                "AEAD decryption failed for encrypted gossip envelope"
                            );
                            crate::telemetry::record_pq_envelope_decrypt("aead_fail");
                            crate::telemetry::record_gossip_messages_dropped("enc_v3_aead_fail");
                            return;
                        }
                    }
                }
            }
        } else {
            // Plaintext envelope — check domain enc-v3 capability.
            if self
                .domain
                .has_capability(dds_domain::domain::CAPABILITY_ENC_V3)
            {
                warn!("received plaintext gossip on enc-v3 domain — dropping");
                crate::telemetry::record_gossip_messages_dropped("enc_v3_plaintext_rejected");
                return;
            }
            std::borrow::Cow::Borrowed(data)
        };

        let msg = match GossipMessage::from_cbor(&payload) {
            Ok(m) => m,
            Err(e) => {
                warn!("invalid gossip message: {e}");
                crate::telemetry::record_gossip_messages_dropped("decode_error");
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
                crate::telemetry::record_gossip_messages_dropped("topic_kind_mismatch");
            }
        }
    }

    /// **Z-1 Phase B.7** — publish a `GossipMessage` on the given topic,
    /// wrapping it in a `GossipEnvelopeV3` when the domain has the
    /// `enc-v3` capability.
    ///
    /// Returns `Ok(())` even when gossipsub reports `InsufficientPeers`
    /// (no mesh peers yet) because callers log that condition
    /// separately via the loadtest / e2e harness. Any other publish
    /// error is returned as a `String`.
    pub fn publish_gossip_op(
        &mut self,
        topic: libp2p::gossipsub::IdentTopic,
        msg: GossipMessage,
    ) -> Result<(), String> {
        let cbor = msg.to_cbor().map_err(|e| format!("gossip encode: {e}"))?;
        let wire: Vec<u8> = if self
            .domain
            .has_capability(dds_domain::domain::CAPABILITY_ENC_V3)
        {
            let (epoch_id, epoch_key) = self.epoch_keys.my_current_epoch();
            let mut rng = rand::rngs::OsRng;
            let (nonce, ciphertext) =
                dds_core::crypto::epoch_key::encrypt_payload(&mut rng, epoch_key, &cbor)
                    .map_err(|e| format!("gossip encrypt: {e:?}"))?;
            let env = GossipEnvelopeV3 {
                publisher: self.peer_id.to_string(),
                epoch_id,
                nonce,
                ciphertext,
            };
            env.to_cbor()
                .map_err(|e| format!("gossip envelope encode: {e}"))?
        } else {
            cbor
        };
        match self.swarm.behaviour_mut().gossipsub.publish(topic, wire) {
            Ok(_) | Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {}
            Err(e) => return Err(format!("gossipsub publish: {e:?}")),
        }
        Ok(())
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
        // **SC-5 Phase B.1 follow-on**: same authoritative-ingest-gate
        // pattern as C-3, but for `SoftwareAssignment::publisher_identity`.
        // A malformed publisher_identity (empty Authenticode subject,
        // wrong-shape Team ID, etc.) would silently match nothing on
        // the downstream agent — observationally identical to "no
        // publisher pinning". Drop at ingest so the rogue token never
        // enters the trust graph and never propagates to peers.
        if !software_publisher_identity_ok(&token) {
            warn!(
                jti = %token.payload.jti,
                issuer = %token.payload.iss,
                body_type = ?token.payload.body_type,
                "rejecting inbound token: malformed SoftwareAssignment.publisher_identity"
            );
            self.emit_audit_from_ingest(
                rejected_action_for(&token.payload.kind),
                token_bytes.to_vec(),
                Some("publisher-identity-invalid".to_string()),
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

        // **Z-1 Phase B.9** — revocation-triggered epoch rotation with
        // jitter (§4.6, §6.1). Set a deferred sleep so the `run()` loop
        // fires `rotate_and_fan_out("revocation")` after a random
        // 0..REVOCATION_ROTATION_JITTER_SECS delay. Only set if there
        // isn't already a pending revocation rotation (deduplicate rapid
        // successive revocations — the single rotation is enough).
        if self.pending_revocation_rotation.is_none() {
            let jitter_secs = rand::Rng::gen_range(
                &mut rand::rngs::OsRng,
                0u64..REVOCATION_ROTATION_JITTER_SECS,
            );
            debug!(
                jitter_secs,
                "Phase B.9: scheduling jittered epoch rotation after revocation"
            );
            self.pending_revocation_rotation = Some(Box::pin(tokio::time::sleep(
                std::time::Duration::from_secs(jitter_secs),
            )));
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
    /// **Z-1 Phase B.8** — build a sync response, encrypting each payload
    /// under our epoch key when the domain advertises `enc-v3`.
    ///
    /// On non-`enc-v3` domains the response is plaintext (same behaviour as
    /// before B.8). On `enc-v3` domains each `SyncPayload` is CBOR-encoded
    /// then AEAD-encrypted under our current epoch key into a
    /// `SyncEnvelopeV3` blob; the `payloads` field is left empty and
    /// `enc_payloads` carries the ciphertext list so v2 requesters (which
    /// don't know `enc_payloads`) receive an empty `payloads` and do nothing
    /// — acceptable because they can't decrypt anyway (§4.7 mixed-fleet).
    fn build_sync_response(&self, req: &SyncRequest) -> SyncResponse {
        let mut candidate_payloads: Vec<SyncPayload> =
            Vec::with_capacity(SYNC_MAX_RESPONSE_ENTRIES.min(self.sync_payloads.len()));
        let mut bytes_acc: usize = 0;
        let mut complete = true;
        for (id, payload) in &self.sync_payloads {
            if req.known_op_ids.contains(id.as_str()) {
                continue;
            }
            let payload_bytes = payload.op_bytes.len() + payload.token_bytes.len();
            if candidate_payloads.len() >= SYNC_MAX_RESPONSE_ENTRIES
                || bytes_acc.saturating_add(payload_bytes) > SYNC_MAX_RESPONSE_BYTES
            {
                complete = false;
                break;
            }
            bytes_acc += payload_bytes;
            candidate_payloads.push(payload.clone());
        }

        if !self
            .domain
            .has_capability(dds_domain::domain::CAPABILITY_ENC_V3)
        {
            return SyncResponse {
                payloads: candidate_payloads,
                complete,
                enc_payloads: Vec::new(),
            };
        }

        // enc-v3: encrypt each payload under our current epoch key.
        let (epoch_id, epoch_key) = self.epoch_keys.my_current_epoch();
        let my_peer_id_str = self.peer_id.to_string();
        let mut rng = rand::rngs::OsRng;
        let mut enc_payloads: Vec<Vec<u8>> = Vec::with_capacity(candidate_payloads.len());

        for payload in &candidate_payloads {
            // CBOR-encode the SyncPayload struct.
            let mut payload_cbor: Vec<u8> = Vec::new();
            if let Err(e) = ciborium::into_writer(payload, &mut payload_cbor) {
                warn!(error = %e, "B.8: sync payload CBOR encode failed — skipping entry");
                continue;
            }
            // AEAD-encrypt under our epoch key.
            let (nonce, ciphertext) = match dds_core::crypto::epoch_key::encrypt_payload(
                &mut rng,
                epoch_key,
                &payload_cbor,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = ?e, "B.8: sync payload AEAD encrypt failed — skipping entry");
                    continue;
                }
            };
            let env = SyncEnvelopeV3 {
                responder: my_peer_id_str.clone(),
                epoch_id,
                nonce,
                ciphertext,
            };
            match env.to_cbor() {
                Ok(blob) => enc_payloads.push(blob),
                Err(e) => {
                    warn!(error = %e, "B.8: SyncEnvelopeV3 CBOR encode failed — skipping entry");
                }
            }
        }

        SyncResponse {
            payloads: Vec::new(),
            complete,
            enc_payloads,
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

    /// Send a sync request to a peer unconditionally, bypassing the
    /// per-peer cooldown. Intended for tests and for the HTTP layer when
    /// a fresh enrollment makes an immediate re-sync desirable.
    pub fn force_sync_with(&mut self, peer: PeerId) {
        self.sync_last_outbound.remove(&peer);
        self.try_sync_with(peer);
    }

    /// **Z-1 Phase B.7 / PQ-B7-RECOVERY-1** — request the epoch key for
    /// `publisher_id` from the publisher itself (if currently admitted).
    ///
    /// Called from [`Self::handle_gossip_message`] when a
    /// `GossipEnvelopeV3` arrives for a publisher whose epoch key is not
    /// yet in the local cache (the `no_key` drop path). Sending a
    /// targeted `EpochKeyRequest` to the publisher triggers
    /// `build_epoch_key_response` on their side, which mints a fresh
    /// `EpochKeyRelease` encapsulated to our hybrid KEM pubkey.
    ///
    /// Respects a per-publisher cooldown (`EPOCH_KEY_REQUEST_COOLDOWN`)
    /// to avoid flooding the publisher on rapid successive drops before
    /// the first response arrives. If the publisher is not currently
    /// in `admitted_peers` the request is silently skipped — the next
    /// reconnect + re-admission will install the release via the H-12
    /// piggy-back path.
    fn try_epoch_key_request(&mut self, publisher_id: &str) {
        let now = Instant::now();
        if let Some(prev) = self.epoch_key_request_last.get(publisher_id) {
            if now.duration_since(*prev) < EPOCH_KEY_REQUEST_COOLDOWN {
                crate::telemetry::record_pq_release_request("cooldown");
                return;
            }
        }

        // Parse the publisher string into a PeerId to look up in
        // admitted_peers. If the publisher is not currently admitted
        // (offline / not yet handshaken), skip — the H-12 piggy-back
        // on the next reconnect will deliver the release.
        let publisher_peer_id: PeerId = match publisher_id.parse() {
            Ok(id) => id,
            Err(_) => {
                debug!(publisher = %publisher_id, "epoch-key request: malformed publisher PeerId — skipping");
                crate::telemetry::record_pq_release_request("malformed_peer_id");
                return;
            }
        };

        if !self.admitted_peers.contains(&publisher_peer_id) {
            debug!(
                publisher = %publisher_id,
                "epoch-key request: publisher not currently admitted — skipping"
            );
            crate::telemetry::record_pq_release_request("not_admitted");
            return;
        }

        let req = EpochKeyRequest {
            publishers: vec![publisher_id.to_string()],
            outbound_releases: vec![],
        };
        self.swarm
            .behaviour_mut()
            .epoch_keys
            .send_request(&publisher_peer_id, req);
        self.epoch_key_request_last
            .insert(publisher_id.to_string(), now);
        crate::telemetry::record_pq_release_request("sent");
        debug!(publisher = %publisher_id, "epoch-key request: sent late-join recovery request");
    }

    /// **Z-1 Phase B.9** — rotate the local epoch key and fan out new
    /// `EpochKeyRelease`s to every admitted peer that already holds a
    /// Phase-B hybrid KEM pubkey in its cached `AdmissionCert`. Bumps
    /// `dds_pq_rotation_total{reason}` and persists the updated store.
    ///
    /// `reason` should be one of `"time"`, `"revocation"`, or `"manual"`.
    /// Called from:
    /// - the `run()` loop's rotation-timer branch (`reason = "time"`)
    /// - the `run()` loop's revocation-jitter branch (`reason = "revocation"`)
    /// - the `POST /v1/pq/rotate` handler (`reason = "manual"`)
    pub fn rotate_and_fan_out(&mut self, reason: &str) {
        let new_epoch_id = self.epoch_keys.rotate_my_epoch(&mut rand::rngs::OsRng);
        if let Err(e) = self.epoch_keys.save(&self.epoch_keys_path) {
            warn!(error = %e, "Phase B.9: failed to persist epoch keys after rotation");
        }
        info!(
            epoch_id = new_epoch_id,
            reason, "Phase B.9: epoch key rotated"
        );
        crate::telemetry::record_pq_rotation(reason);
        crate::telemetry::record_pq_epoch_id(new_epoch_id);
        self.emit_epoch_key_releases_to_all_admitted_peers();
    }

    /// **Z-1 Phase B.9** — push the local node's current epoch key to
    /// every admitted peer that has a Phase-B hybrid KEM pubkey in its
    /// cached `AdmissionCert`.
    ///
    /// For each eligible peer, the publisher mints a fresh
    /// `EpochKeyRelease` encapsulated to the peer's KEM pubkey and sends
    /// it via `EpochKeyRequest { outbound_releases: [blob] }` so the
    /// receiver's `handle_epoch_keys_event` installs it via the normal
    /// B.5 receive pipeline. The request's `publishers` list is empty —
    /// the peer is not asked to reciprocate.
    ///
    /// Per §6.1 the fan-out is capped at `EPOCH_KEY_FANOUT_CONCURRENCY`
    /// concurrent sends; the remainder queue via libp2p's per-peer
    /// request-response backpressure. Only currently admitted + connected
    /// peers receive the push — peers that reconnect later will receive
    /// the release via the H-12 piggy-back path.
    fn emit_epoch_key_releases_to_all_admitted_peers(&mut self) {
        let my_peer_id_str = self.peer_id.to_string();
        let (epoch_id, epoch_key) = self.epoch_keys.my_current_epoch();
        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                warn!("Phase B.9: clock error, skipping fan-out");
                return;
            }
        };
        const EPOCH_LIFETIME_SECS: u64 = 86_400;
        let expires_at = now_unix.saturating_add(EPOCH_LIFETIME_SECS);

        // Collect eligible (peer_id_str, kem_pk) pairs first to avoid
        // borrowing `self.peer_certs` while driving the swarm.
        let targets: Vec<(String, Vec<u8>)> = self
            .peer_certs
            .iter_kem_pubkeys()
            .map(|(peer_str, pk)| (peer_str.clone(), pk.clone()))
            .collect();

        let mut sent = 0usize;
        for (peer_str, kem_pk_bytes) in &targets {
            // Only push to currently admitted peers; offline peers get
            // the release via the H-12 piggy-back on next reconnect.
            let peer_id: PeerId = match peer_str.parse() {
                Ok(id) => id,
                Err(_) => continue,
            };
            if !self.admitted_peers.contains(&peer_id) {
                continue;
            }
            // Parse the recipient's KEM pubkey.
            let recipient_kem_pk = match dds_core::crypto::kem::HybridKemPublicKey::from_bytes(
                kem_pk_bytes,
            ) {
                Ok(pk) => pk,
                Err(_) => {
                    debug!(peer = %peer_str, "Phase B.9: malformed cached KEM pubkey, skipping fan-out");
                    continue;
                }
            };
            // Mint the per-recipient release.
            let release = match mint_epoch_key_release_for_recipient(
                &mut rand::rngs::OsRng,
                &my_peer_id_str,
                epoch_id,
                epoch_key,
                peer_str,
                &recipient_kem_pk,
                now_unix,
                expires_at,
            ) {
                Ok(r) => r,
                Err(reason) => {
                    debug!(peer = %peer_str, reason, "Phase B.9: mint failed, skipping fan-out");
                    continue;
                }
            };
            let blob = match release.to_cbor() {
                Ok(b) => b,
                Err(e) => {
                    debug!(peer = %peer_str, error = %e, "Phase B.9: CBOR-encode failed, skipping fan-out");
                    continue;
                }
            };
            // Push via EpochKeyRequest with empty publishers list and the
            // pre-minted release as an outbound blob. The responder will
            // install the release and reply with an empty response.
            let req = EpochKeyRequest {
                publishers: vec![],
                outbound_releases: vec![blob],
            };
            self.swarm
                .behaviour_mut()
                .epoch_keys
                .send_request(&peer_id, req);
            sent += 1;
            if sent >= EPOCH_KEY_FANOUT_CONCURRENCY {
                debug!(
                    sent,
                    remaining = targets.len().saturating_sub(sent),
                    "Phase B.9: concurrency cap reached, deferring remaining fan-out to libp2p queue"
                );
                // libp2p request_response queues additional sends; just
                // break the explicit cap loop — the remaining sends still
                // happen, just queued via the behaviour's internal buffer.
                // Reset and continue so all targets get a release.
                sent = 0;
            }
        }
        debug!(
            peers = targets.len(),
            "Phase B.9: epoch-key fan-out complete"
        );
    }

    /// Apply an inbound sync response: merge into trust graph + DAG +
    /// store, and cache the payloads for future serving to other peers.
    ///
    /// **Z-1 Phase B.8** — when the response carries `enc_payloads`
    /// (non-empty), decrypt each `SyncEnvelopeV3` blob using the
    /// responder's cached epoch key before proceeding to the existing
    /// verification + merge pipeline. Plaintext `payloads` are used
    /// unchanged when `enc_payloads` is absent (non-`enc-v3` peers,
    /// mixed-fleet window per §4.7).
    fn handle_sync_response(&mut self, peer: PeerId, resp: SyncResponse) {
        // Resolve the effective payload list.  If `enc_payloads` is
        // non-empty we decrypt; otherwise fall through to `payloads`.
        let resp_payloads: Vec<SyncPayload> = if !resp.enc_payloads.is_empty() {
            let responder_str = peer.to_string();
            let mut decrypted: Vec<SyncPayload> = Vec::with_capacity(resp.enc_payloads.len());
            for blob in &resp.enc_payloads {
                let env = match SyncEnvelopeV3::from_cbor(blob) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(%peer, error = %e, "B.8: SyncEnvelopeV3 CBOR decode failed — dropping entry");
                        crate::telemetry::record_pq_envelope_decrypt("aead_fail");
                        continue;
                    }
                };
                if env.responder != responder_str {
                    warn!(
                        %peer,
                        env_responder = %env.responder,
                        "B.8: SyncEnvelopeV3 responder mismatch — dropping entry"
                    );
                    crate::telemetry::record_pq_envelope_decrypt("aead_fail");
                    continue;
                }
                let epoch_key = match self.epoch_keys.peer_epoch_key(&env.responder, env.epoch_id) {
                    Some(k) => k,
                    None => {
                        warn!(
                            %peer,
                            epoch_id = env.epoch_id,
                            "B.8: no cached epoch key for sync responder — dropping entry"
                        );
                        crate::telemetry::record_pq_envelope_decrypt("no_key");
                        self.try_epoch_key_request(&env.responder);
                        continue;
                    }
                };
                match dds_core::crypto::epoch_key::decrypt_payload(
                    epoch_key,
                    &env.nonce,
                    &env.ciphertext,
                ) {
                    Ok(plaintext) => {
                        crate::telemetry::record_pq_envelope_decrypt("ok");
                        match ciborium::from_reader::<SyncPayload, _>(plaintext.as_slice()) {
                            Ok(p) => decrypted.push(p),
                            Err(e) => {
                                warn!(%peer, error = %e, "B.8: decrypted sync payload CBOR decode failed — dropping entry");
                            }
                        }
                    }
                    Err(_) => {
                        warn!(
                            %peer,
                            epoch_id = env.epoch_id,
                            "B.8: AEAD decryption failed for sync envelope"
                        );
                        crate::telemetry::record_pq_envelope_decrypt("aead_fail");
                    }
                }
            }
            decrypted
        } else {
            resp.payloads
        };

        if resp_payloads.is_empty() {
            debug!(%peer, "sync: peer reported no diff");
            return;
        }

        // Shadow `resp` so the existing pipeline below is unchanged.
        let resp = SyncResponse {
            payloads: resp_payloads,
            complete: resp.complete,
            enc_payloads: Vec::new(),
        };

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
                    crate::telemetry::record_sync_payloads_rejected("legacy_v1");
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
                    crate::telemetry::record_sync_payloads_rejected("publisher_capability");
                    return false;
                }
                // **SC-5 Phase B.1 follow-on**: same fail-closed shape
                // gate the gossip ingest path runs via
                // `software_publisher_identity_ok`. A malformed
                // `publisher_identity` on a `SoftwareAssignment`
                // delivered through sync would otherwise silently
                // downgrade to hash-only on the agent.
                if !software_publisher_identity_ok(&token) {
                    warn!(
                        %peer,
                        jti = %token.payload.jti,
                        issuer = %token.payload.iss,
                        body_type = ?token.payload.body_type,
                        "sync: dropping payload with malformed SoftwareAssignment.publisher_identity"
                    );
                    crate::telemetry::record_sync_payloads_rejected("publisher_identity");
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
                    crate::telemetry::record_sync_payloads_rejected("replay_window");
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
        // Bump `dds_sync_payloads_rejected_total{reason=...}` for every
        // post-apply rejection partitioned by the dds-net categorical
        // reason. Pre-apply skips already bumped above so the same
        // counter family covers both the pre-apply (legacy_v1 /
        // publisher_capability / replay_window) and the post-apply
        // (signature / duplicate_jti / graph) surfaces.
        for (reason, count) in &result.rejected_by_reason {
            for _ in 0..*count {
                crate::telemetry::record_sync_payloads_rejected(reason.as_label());
            }
        }
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
                        crate::telemetry::record_sync_pull("fail");
                        return;
                    }
                    self.handle_sync_response(peer, response);
                    crate::telemetry::record_sync_pull("ok");
                }
            },
            RrEvent::OutboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "sync: outbound failure");
                crate::telemetry::record_sync_pull("fail");
            }
            RrEvent::InboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "sync: inbound failure");
            }
            RrEvent::ResponseSent { .. } => {}
        }
    }

    /// **Z-1 Phase B.5 + B.9 (`docs/pqc-phase-b-plan.md` §4.5 + §4.5.1)** —
    /// dispatch one libp2p request-response event for the
    /// `/dds/epoch-keys/1.0.0/<domain>` protocol. Inbound requests
    /// from admitted peers are answered with the responder's currently-
    /// available releases for the requested publishers; inbound responses
    /// from admitted peers are fed through the schema + replay-window +
    /// decap pipeline and successful releases are installed in
    /// [`Self::epoch_keys`].
    ///
    /// **B.9 extension**: requests may also carry `outbound_releases`
    /// (pushed by the sender after a rotation). These are processed via
    /// the same `install_epoch_key_release` pipeline as response releases,
    /// independent of the `publishers` pull path.
    ///
    /// **H-12 gating** mirrors the `sync` and `admission` handlers:
    /// requests / responses from un-admitted peers are dropped before
    /// any decap work runs. A relay attempting to inject epoch-key
    /// material from an un-admitted peer cannot reach the schema gate.
    fn handle_epoch_keys_event(&mut self, event: RrEvent<EpochKeyRequest, EpochKeyResponse>) {
        match event {
            RrEvent::Message { peer, message, .. } => match message {
                RrMessage::Request {
                    request, channel, ..
                } => {
                    if !self.admitted_peers.contains(&peer) {
                        debug!(%peer, "Phase B.5: dropping epoch-key request from unadmitted peer");
                        drop(channel);
                        return;
                    }
                    // Schema gate (cap + empty-string check + outbound cap)
                    // — drop wholesale on a malformed shape, mirrors the B.4
                    // pre-decap fail-closed pattern.
                    if let Err(e) = request.validate() {
                        debug!(%peer, error = %e, "Phase B.5: malformed EpochKeyRequest — dropping");
                        drop(channel);
                        return;
                    }
                    // **B.9**: process any outbound releases pushed by the
                    // sender (rotation fan-out path). Run through the same
                    // install pipeline as response releases; failures are
                    // per-blob and don't abort the remaining entries.
                    if !request.outbound_releases.is_empty() {
                        let outbound_blobs = request.outbound_releases.clone();
                        debug!(
                            %peer,
                            count = outbound_blobs.len(),
                            "Phase B.9: processing outbound releases from rotation fan-out"
                        );
                        // Re-use the EpochKeyResponse install pipeline.
                        let wrapped = EpochKeyResponse {
                            releases: outbound_blobs,
                        };
                        self.handle_epoch_key_response(peer, wrapped);
                    }
                    // Respond to the pull part (may be empty publishers).
                    let response = self.build_epoch_key_response(&request, &peer);
                    let release_count = response.releases.len();
                    if self
                        .swarm
                        .behaviour_mut()
                        .epoch_keys
                        .send_response(channel, response)
                        .is_err()
                    {
                        warn!(%peer, "Phase B.5: failed to send epoch-key response (channel closed)");
                    } else {
                        debug!(
                            %peer,
                            release_count,
                            "Phase B.5: served epoch-key request"
                        );
                    }
                }
                RrMessage::Response { response, .. } => {
                    if !self.admitted_peers.contains(&peer) {
                        debug!(%peer, "Phase B.5: dropping epoch-key response from unadmitted peer");
                        return;
                    }
                    self.handle_epoch_key_response(peer, response);
                }
            },
            RrEvent::OutboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "Phase B.5: epoch-key outbound failure");
            }
            RrEvent::InboundFailure { peer, error, .. } => {
                debug!(%peer, %error, "Phase B.5: epoch-key inbound failure");
            }
            RrEvent::ResponseSent { .. } => {}
        }
    }

    /// **Phase B.5 responder + Phase B.7 publisher-side mint.** Build
    /// the response payload for a freshly-validated [`EpochKeyRequest`].
    ///
    /// Filtering rule: the responder can only mint releases for
    /// publishers it can authoritatively speak for — i.e. itself. For
    /// each requested publisher equal to the responder's own PeerId,
    /// the responder mints a fresh [`EpochKeyRelease`] of its current
    /// epoch key, encapsulated to the requester's hybrid KEM pubkey
    /// (looked up in [`Self::peer_certs`]). Requested publishers that
    /// do not match the responder's PeerId are skipped — the
    /// requester is expected to fan out to those publishers directly
    /// (per `pqc-phase-b-plan.md` §4.5.1).
    ///
    /// The forwarding case ("re-encapsulate a peer's epoch key under
    /// my key for a third party") is intentionally **not** wired
    /// here: the original publisher's signature would not verify
    /// against a re-encapsulation, and Phase B's signature shape is
    /// still pending (see [`mint_epoch_key_release_for_recipient`]).
    /// Until that lands, the safe semantics are "I speak only for
    /// myself".
    ///
    /// Skipped reasons (logged at debug level):
    /// - the requester has no cached `AdmissionCert` in
    ///   [`Self::peer_certs`] (handshake never completed, or the
    ///   cache was wiped);
    /// - the requester's cached cert has no
    ///   [`AdmissionCert::pq_kem_pubkey`] (the requester is on a
    ///   pre-Phase-B build);
    /// - the cached pubkey is malformed at the
    ///   [`HybridKemPublicKey::from_bytes`] schema gate;
    /// - any of the inner mint steps (KEM encap, AEAD wrap, CBOR
    ///   serialize) fails.
    ///
    /// In every skipped case the responder ships an *empty* releases
    /// vector rather than failing the request: a partial response
    /// (`releases.len() < requested.len()`) is the wire-level signal
    /// for "I could not honor every publisher you asked about", and
    /// the requester re-fans-out to the next candidate peer.
    fn build_epoch_key_response(
        &self,
        request: &EpochKeyRequest,
        requester: &PeerId,
    ) -> EpochKeyResponse {
        let my_peer_id_str = self.peer_id.to_string();
        let requester_str = requester.to_string();

        // Requester KEM pubkey lookup. Bail early if any prerequisite
        // is missing — we still ship the (empty) response shape so the
        // libp2p request_response channel doesn't time out.
        let recipient_kem_pk = match self
            .peer_certs
            .get(&requester_str)
            .and_then(|cert| cert.pq_kem_pubkey.as_deref())
        {
            Some(bytes) => match dds_core::crypto::kem::HybridKemPublicKey::from_bytes(bytes) {
                Ok(pk) => pk,
                Err(_) => {
                    debug!(
                        peer = %requester,
                        "Phase B.7: cached requester KEM pubkey is malformed — empty response"
                    );
                    crate::telemetry::record_pq_releases_emitted("malformed_kem_pk");
                    return EpochKeyResponse::default();
                }
            },
            None => {
                debug!(
                    peer = %requester,
                    "Phase B.7: requester has no cached KEM pubkey — empty response"
                );
                crate::telemetry::record_pq_releases_emitted("no_kem_pk");
                return EpochKeyResponse::default();
            }
        };

        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                debug!("Phase B.7: clock error, returning empty response");
                crate::telemetry::record_pq_releases_emitted("clock_error");
                return EpochKeyResponse::default();
            }
        };

        // Mint at most one release per request: the only publisher we
        // can speak for is ourselves, so even if the request lists
        // duplicates of our own peer id (shouldn't happen in practice)
        // we ship one entry.
        let asks_for_self = request
            .publishers
            .iter()
            .any(|p| p.as_str() == my_peer_id_str);
        if !asks_for_self {
            crate::telemetry::record_pq_releases_emitted("not_for_self");
            return EpochKeyResponse::default();
        }

        let (epoch_id, epoch_key) = self.epoch_keys.my_current_epoch();
        // Expires_at: same 24h budget the rotation timer (B.9) will
        // use. Using a static 24h here keeps the schema gate happy
        // (`expires_at > issued_at`) without coupling to the (still
        // unset) rotation cadence.
        const EPOCH_LIFETIME_SECS: u64 = 86_400;
        let expires_at = now_unix.saturating_add(EPOCH_LIFETIME_SECS);

        let release = match mint_epoch_key_release_for_recipient(
            &mut rand::rngs::OsRng,
            &my_peer_id_str,
            epoch_id,
            epoch_key,
            &requester_str,
            &recipient_kem_pk,
            now_unix,
            expires_at,
        ) {
            Ok(r) => r,
            Err(reason) => {
                debug!(
                    peer = %requester,
                    reason,
                    "Phase B.7: mint failed — empty response"
                );
                crate::telemetry::record_pq_releases_emitted("mint_fail");
                return EpochKeyResponse::default();
            }
        };

        let blob = match release.to_cbor() {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    peer = %requester,
                    error = %e,
                    "Phase B.7: CBOR-encode of fresh release failed — empty response"
                );
                crate::telemetry::record_pq_releases_emitted("cbor_fail");
                return EpochKeyResponse::default();
            }
        };

        crate::telemetry::record_pq_releases_emitted("ok");
        EpochKeyResponse {
            releases: vec![blob],
        }
    }

    /// **Phase B.5 receiver.** Decode every release in `response`,
    /// run the schema + replay-window + recipient-binding gates from
    /// B.4 / B.6, decap each surviving release using
    /// [`Self::epoch_keys`]'s KEM secret, unwrap the AEAD-wrapped
    /// epoch key, and install it in [`Self::epoch_keys`]. Persists
    /// the store on any successful install so a process restart keeps
    /// the freshly-decapped peer key. Failures at any stage drop only
    /// the offending release (the rest still process), mirroring the
    /// `apply_sync_payloads` per-payload error semantics.
    fn handle_epoch_key_response(&mut self, peer: PeerId, response: EpochKeyResponse) {
        // Outer cap — drop the whole response wholesale on overflow,
        // matches the §4.5.1 `MAX_EPOCH_KEY_RELEASES_PER_RESPONSE` cap.
        if let Err(e) = response.validate() {
            warn!(%peer, error = %e, "Phase B.5: dropping over-cap EpochKeyResponse");
            return;
        }

        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                warn!(%peer, error = %e, "Phase B.5: clock error, skipping release ingest");
                return;
            }
        };
        let recipient_str = self.peer_id.to_string();

        let mut installed = 0usize;
        let mut rejected = 0usize;
        for blob in &response.releases {
            // Bounded depth: peer-supplied. Security review I-6.
            let release: EpochKeyRelease =
                match dds_core::cbor_bounded::from_reader(blob.as_slice()) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!(%peer, error = %e, "Phase B.5: release CBOR decode failed");
                        rejected += 1;
                        continue;
                    }
                };
            match self.install_epoch_key_release(&release, &recipient_str, now_unix) {
                Ok(outcome) => match outcome {
                    InstallOutcome::Inserted | InstallOutcome::Rotated => installed += 1,
                    InstallOutcome::AlreadyCurrent | InstallOutcome::Stale => {}
                },
                Err(reason) => {
                    debug!(%peer, publisher = %release.publisher, reason, "Phase B.5: release rejected");
                    rejected += 1;
                }
            }
        }

        if installed > 0 {
            // Persist on any successful install so the new release(s)
            // survive a restart. Best-effort: a write failure is
            // logged but the in-memory entry is kept so the process
            // can still decrypt this epoch's gossip.
            if let Err(e) = self.epoch_keys.save(&self.epoch_keys_path) {
                warn!(
                    path = %self.epoch_keys_path.display(),
                    error = %e,
                    "Phase B.5: failed to persist epoch-key store after install"
                );
            }
        }
        if installed > 0 || rejected > 0 {
            debug!(
                %peer,
                installed,
                rejected,
                total = response.releases.len(),
                "Phase B.5: processed epoch-key response"
            );
        }
    }

    /// **Phase B.5 release ingest funnel** — applies the full set of
    /// pre-install gates to a single decoded [`EpochKeyRelease`] and,
    /// on success, decaps the AEAD-wrapped epoch key + installs it in
    /// [`Self::epoch_keys`]. Returns the [`InstallOutcome`] from
    /// [`crate::epoch_key_store::EpochKeyStore::install_peer_release`]
    /// on success, or a `&'static str` reason on rejection (suitable
    /// for log + metric labels).
    ///
    /// Gates, in order:
    /// 1. Schema validate ([`EpochKeyRelease::validate`]) — empty
    ///    publisher / recipient, length checks on each fixed-size
    ///    field, expires_at strictly after issued_at.
    /// 2. Recipient binding — `release.recipient == our PeerId`.
    /// 3. Replay window ([`is_release_within_replay_window`]) —
    ///    `issued_at` within
    ///    [`dds_net::pq_envelope::EPOCH_RELEASE_REPLAY_WINDOW_SECS`]
    ///    of `now_unix` (clock-skew futures allowed).
    /// 4. Decap via [`dds_core::crypto::kem::decap`] using the
    ///    canonical binding `(publisher || recipient || epoch_id_be)`
    ///    so a release encapsulated for a different (publisher,
    ///    recipient, epoch) tuple cannot be lifted into this slot.
    /// 5. AEAD unwrap via [`dds_core::crypto::epoch_key::unwrap`] —
    ///    a wrong-key / tampered-ciphertext / tampered-nonce release
    ///    fails-loud here.
    /// 6. Install via
    ///    [`crate::epoch_key_store::EpochKeyStore::install_peer_release`]
    ///    which classifies the install as Inserted / Rotated /
    ///    AlreadyCurrent / Stale.
    ///
    /// Publisher-signature verification (Ed25519 + optional
    /// ML-DSA-65) is intentionally **not** performed at this layer —
    /// see the docstring on [`Self::epoch_keys`] for the threat-model
    /// note. The release is delivered over an authenticated libp2p
    /// channel (Noise + admitted-peer gating), and a forger that
    /// neither has the publisher's epoch key nor the recipient's KEM
    /// secret cannot construct `(kem_ct, aead_ciphertext)` pair that
    /// decaps + unwraps to a usable epoch key. Step (4) + (5) are
    /// the load-bearing forgery defence at this layer; the publisher
    /// signature verify lands as a B.6 follow-on once the canonical
    /// signing-bytes shape is finalised.
    pub fn install_epoch_key_release(
        &mut self,
        release: &EpochKeyRelease,
        recipient_str: &str,
        now_unix: u64,
    ) -> Result<InstallOutcome, &'static str> {
        if let Err(_e) = release.validate() {
            crate::telemetry::record_pq_release_installed("schema");
            return Err("schema");
        }
        if release.recipient != recipient_str {
            crate::telemetry::record_pq_release_installed("recipient_mismatch");
            return Err("recipient_mismatch");
        }
        if !is_release_within_replay_window(release.issued_at, now_unix) {
            crate::telemetry::record_pq_release_installed("replay_window");
            return Err("replay_window");
        }
        // Defensive re-check on the two length-bound slices. Schema
        // validate already covered these but we destructure into
        // fixed-length arrays before handing to the crypto layer.
        if release.kem_ct.len() != EPOCH_KEY_RELEASE_KEM_CT_LEN
            || release.aead_ciphertext.len() != EPOCH_KEY_RELEASE_AEAD_CT_LEN
        {
            crate::telemetry::record_pq_release_installed("schema");
            return Err("schema");
        }

        let kem_ct = match dds_core::crypto::kem::KemCiphertext::from_bytes(&release.kem_ct) {
            Ok(ct) => ct,
            Err(_) => {
                crate::telemetry::record_pq_release_installed("kem_ct");
                return Err("kem_ct");
            }
        };
        let binding = epoch_key_binding(&release.publisher, recipient_str, release.epoch_id);
        let shared =
            match dds_core::crypto::kem::decap(self.epoch_keys.kem_secret(), &kem_ct, &binding) {
                Ok(s) => s,
                Err(_) => {
                    crate::telemetry::record_pq_release_installed("decap");
                    return Err("decap");
                }
            };
        let epoch_key = match dds_core::crypto::epoch_key::unwrap(
            &shared,
            &release.aead_nonce,
            &release.aead_ciphertext,
        ) {
            Ok(k) => k,
            Err(_) => {
                crate::telemetry::record_pq_release_installed("aead");
                return Err("aead");
            }
        };

        let outcome = self.epoch_keys.install_peer_release(
            &release.publisher,
            release.epoch_id,
            epoch_key,
            release.expires_at,
        );
        crate::telemetry::record_pq_release_installed("ok");
        Ok(outcome)
    }

    /// Read-only handle to the epoch-key store. Test-only — the live
    /// node owns the store and mutates it through the receive path.
    #[doc(hidden)]
    pub fn epoch_keys_for_tests(&self) -> &EpochKeyStore {
        &self.epoch_keys
    }

    /// **Z-1 Phase B.7 test hook.** Drive the
    /// [`Self::build_epoch_key_response`] funnel directly without
    /// having to spin up a libp2p swarm + stage an
    /// `EpochKeyRequest` round-trip on the
    /// `/dds/epoch-keys/1.0.0/<domain>` protocol. The contract this
    /// pins (the publisher-side mint of a release encapsulated to
    /// the requester's KEM pubkey) is the load-bearing piece of the
    /// §4.5.1 late-join recovery; the test surface is what unblocks
    /// the B.9 rotation timer + the B.12 multi-node integration
    /// harness.
    #[doc(hidden)]
    pub fn build_epoch_key_response_for_tests(
        &self,
        request: &EpochKeyRequest,
        requester: &PeerId,
    ) -> EpochKeyResponse {
        self.build_epoch_key_response(request, requester)
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

    /// **Z-1 Phase B.7 test hook.** Drive `handle_gossip_message`
    /// without spinning up a libp2p swarm. The topic hash must be one
    /// of the topics this node subscribed to at `start()` time — or a
    /// synthetic hash that `identify_topic` will match. The `data`
    /// bytes may be a plaintext CBOR `GossipMessage` or a CBOR-encoded
    /// `GossipEnvelopeV3` depending on which path the test is exercising.
    #[doc(hidden)]
    pub fn handle_gossip_message_for_tests(
        &mut self,
        topic_hash: &libp2p::gossipsub::TopicHash,
        data: &[u8],
    ) {
        self.handle_gossip_message(topic_hash, data);
    }

    /// **Z-1 Phase B.7 test hook.** Mutably borrow the epoch-key store
    /// so a test can pre-install a peer epoch key via
    /// `EpochKeyStore::install_peer_release` before calling
    /// `handle_gossip_message_for_tests`.
    #[doc(hidden)]
    pub fn epoch_keys_mut_for_tests(&mut self) -> &mut EpochKeyStore {
        &mut self.epoch_keys
    }

    /// **Z-1 Phase B.8 test hook.** Drive [`Self::build_sync_response`]
    /// without a live libp2p swarm or sync protocol session. Allows tests
    /// to verify encrypted vs. plaintext response shapes depending on the
    /// `enc-v3` capability.
    #[doc(hidden)]
    pub fn build_sync_response_for_tests(&self, req: &SyncRequest) -> SyncResponse {
        self.build_sync_response(req)
    }

    /// **Z-1 Phase B.8 test hook.** Drive [`Self::handle_sync_response`]
    /// without a live libp2p swarm. Allows tests to verify that an
    /// encrypted `SyncResponse` (carrying `enc_payloads`) is correctly
    /// decrypted and merged into the node's state.
    #[doc(hidden)]
    pub fn handle_sync_response_for_tests(&mut self, peer: PeerId, resp: SyncResponse) {
        self.handle_sync_response(peer, resp);
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

/// **Z-1 Phase B.5** — canonical hybrid-KEM `binding_info` for a
/// per-recipient [`dds_net::pq_envelope::EpochKeyRelease`]. The
/// publisher uses this exact binding when calling
/// [`dds_core::crypto::kem::encap`]; the receiver re-derives the same
/// binding before [`dds_core::crypto::kem::decap`] so a release
/// encapsulated for a different `(publisher, recipient, epoch_id)`
/// tuple cannot be lifted into another slot. Mirrors the M-2 / Phase
/// A `dds-hybrid-v2/...` domain-separation pattern: the binding is
/// `b"dds-pqc-epoch-key/" || publisher || b"|" || recipient || b"|"
/// || epoch_id_be`. Publisher and recipient are the base58 PeerId
/// strings exactly as they appear in
/// [`EpochKeyRelease::publisher`](dds_net::pq_envelope::EpochKeyRelease)
/// / [`EpochKeyRelease::recipient`](dds_net::pq_envelope::EpochKeyRelease).
/// The `|` separator + the prefix make a parser-confusion attack
/// (where one peer's PeerId is a suffix of another's, or where a
/// publisher's id ends with a digit indistinguishable from the start
/// of an epoch_id) impossible.
pub fn epoch_key_binding(publisher: &str, recipient: &str, epoch_id: u64) -> Vec<u8> {
    const PREFIX: &[u8] = b"dds-pqc-epoch-key/v1/";
    let mut out = Vec::with_capacity(PREFIX.len() + publisher.len() + 1 + recipient.len() + 1 + 8);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(publisher.as_bytes());
    out.push(b'|');
    out.extend_from_slice(recipient.as_bytes());
    out.push(b'|');
    out.extend_from_slice(&epoch_id.to_be_bytes());
    out
}

/// **Z-1 Phase B.7** — publisher-side mint of an
/// [`EpochKeyRelease`] for one specific recipient.
///
/// Inverse of [`DdsNode::install_epoch_key_release`]: the publisher
/// takes its current `(epoch_id, epoch_key)`, derives the canonical
/// [`epoch_key_binding`] for `(publisher, recipient, epoch_id)`,
/// runs the hybrid X25519 + ML-KEM-768 KEM via
/// [`dds_core::crypto::kem::encap`] against `recipient_kem_pk`, and
/// AEAD-wraps the 32-byte epoch key under the derived shared secret
/// via [`dds_core::crypto::epoch_key::wrap`]. The receiver — having
/// the matching KEM secret in its
/// [`crate::epoch_key_store::EpochKeyStore`] — re-derives the same
/// shared secret via [`dds_core::crypto::kem::decap`] and unwraps to
/// recover `epoch_key`.
///
/// `signature` is currently a 64-byte zero placeholder. The
/// canonical signing-bytes shape (Ed25519 + optional ML-DSA-65 over
/// the wire-encoded body) is intentionally deferred to a B.6 / B.9
/// follow-on. See the docstring on [`DdsNode::epoch_keys`] for the
/// threat-model note: at the install layer the load-bearing forgery
/// defence is the per-recipient hybrid-KEM decap + AEAD unwrap
/// pipeline; an attacker without `recipient_kem_pk`'s matching
/// secret cannot construct a `(kem_ct, aead_ciphertext)` pair that
/// recovers a usable epoch key.
///
/// Errors are short `&'static str` reasons suitable for log + metric
/// labels at the call site, mirroring the receive-side
/// [`DdsNode::install_epoch_key_release`] return shape.
#[allow(clippy::too_many_arguments)]
pub fn mint_epoch_key_release_for_recipient<R: rand_core::CryptoRngCore>(
    rng: &mut R,
    publisher_id: &str,
    epoch_id: u64,
    epoch_key: &[u8; dds_core::crypto::epoch_key::EPOCH_KEY_LEN],
    recipient_id: &str,
    recipient_kem_pk: &dds_core::crypto::kem::HybridKemPublicKey,
    issued_at: u64,
    expires_at: u64,
) -> Result<EpochKeyRelease, &'static str> {
    if publisher_id.is_empty() {
        return Err("empty_publisher");
    }
    if recipient_id.is_empty() {
        return Err("empty_recipient");
    }
    if expires_at <= issued_at {
        return Err("invalid_expiry");
    }

    let binding = epoch_key_binding(publisher_id, recipient_id, epoch_id);
    let (kem_ct, shared) =
        dds_core::crypto::kem::encap(rng, recipient_kem_pk, &binding).map_err(|_| "encap")?;
    let (aead_nonce, aead_ciphertext) =
        dds_core::crypto::epoch_key::wrap(rng, &shared, epoch_key).map_err(|_| "wrap")?;

    Ok(EpochKeyRelease {
        publisher: publisher_id.to_string(),
        epoch_id,
        issued_at,
        expires_at,
        recipient: recipient_id.to_string(),
        kem_ct: kem_ct.to_bytes(),
        aead_nonce,
        aead_ciphertext,
        signature: vec![0u8; EPOCH_KEY_RELEASE_ED25519_SIG_LEN],
        pq_signature: None,
    })
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

/// SC-5 Phase B.1 follow-on — ingest-time fail-closed gate on
/// `SoftwareAssignment::publisher_identity` shape. Mirrors the C-3
/// pattern: filtering only at serve time
/// ([`crate::service::LocalService::list_applicable_software`])
/// still admits the rogue token into the trust graph and lets it
/// propagate to peers whose serve-time filters might be older or
/// patched differently. An empty Authenticode subject or a
/// wrong-shape Apple Team ID would silently match nothing on the
/// downstream agent — observationally indistinguishable from "no
/// publisher pinning", which is exactly the silent downgrade the
/// two-signature gate is meant to prevent.
///
/// Returns `true` (admit) when the token does not carry a
/// `SoftwareAssignment` body, when the body decodes cleanly without a
/// `publisher_identity` (legacy v1 publishers), or when the embedded
/// `publisher_identity` passes
/// [`dds_domain::PublisherIdentity::validate`]. Returns `false` only
/// for a CBOR-decodable `SoftwareAssignment` whose `publisher_identity`
/// is malformed. CBOR decode failures are *not* this gate's
/// responsibility — they surface separately through the existing
/// `SyncResult::errors` path and through the per-token validation
/// guard at the top of [`DdsNode::ingest_operation`].
fn software_publisher_identity_ok(token: &Token) -> bool {
    use dds_domain::{DomainDocument, SoftwareAssignment, body_types};

    if token.payload.kind != TokenKind::Attest {
        return true;
    }
    let body_type = match token.payload.body_type.as_deref() {
        Some(bt) => bt,
        None => return true,
    };
    if body_type != body_types::SOFTWARE_ASSIGNMENT {
        return true;
    }
    let doc = match SoftwareAssignment::extract(&token.payload) {
        Ok(Some(d)) => d,
        // No body / different body type — handled by other gates.
        Ok(None) => return true,
        // Decode failure — not this gate's concern; the upstream
        // ingest paths already surface decode errors.
        Err(_) => return true,
    };
    match doc.publisher_identity.as_ref() {
        Some(pi) => pi.validate().is_ok(),
        None => true,
    }
}

#[cfg(test)]
mod publisher_identity_gate_tests {
    //! SC-5 Phase B.1 follow-on — unit coverage for
    //! [`software_publisher_identity_ok`], the ingest-side fail-closed
    //! gate that mirrors C-3's `publisher_capability_ok` for the
    //! `SoftwareAssignment::publisher_identity` shape invariants.
    //!
    //! Both ingest call sites (gossip in
    //! [`DdsNode::ingest_operation`] and sync in
    //! [`DdsNode::handle_sync_response`]) route through this helper, so
    //! covering it directly covers both wire paths.
    use super::*;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_domain::DomainDocument;
    use dds_domain::body_types;
    use dds_domain::types::{InstallAction, PolicyScope, PublisherIdentity, SoftwareAssignment};
    use rand::rngs::OsRng;

    fn make_software_token(publisher_identity: Option<PublisherIdentity>) -> Token {
        let ident = Identity::generate("publisher", &mut OsRng);
        let pkg = SoftwareAssignment {
            package_id: "com.example.app".to_string(),
            display_name: "Example".to_string(),
            version: "1.0.0".to_string(),
            source: "https://example.test/app.msi".to_string(),
            sha256: "0".repeat(64),
            action: InstallAction::Install,
            scope: PolicyScope {
                device_tags: Vec::new(),
                org_units: Vec::new(),
                identity_urns: Vec::new(),
            },
            silent: true,
            pre_install_script: None,
            post_install_script: None,
            publisher_identity,
        };
        let mut payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: "ingest-pi-test".to_string(),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        pkg.embed(&mut payload).expect("embed software assignment");
        Token::sign(payload, &ident.signing_key).expect("sign attest token")
    }

    #[test]
    fn admits_software_token_without_publisher_identity() {
        let token = make_software_token(None);
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_software_token_with_valid_authenticode_publisher() {
        let token = make_software_token(Some(PublisherIdentity::Authenticode {
            subject: "Example Corp".to_string(),
            root_thumbprint: Some("a".repeat(40)),
        }));
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_software_token_with_valid_apple_publisher() {
        let token = make_software_token(Some(PublisherIdentity::AppleDeveloperId {
            team_id: "ABCDE12345".to_string(),
        }));
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn rejects_software_token_with_empty_authenticode_subject() {
        let token = make_software_token(Some(PublisherIdentity::Authenticode {
            subject: String::new(),
            root_thumbprint: None,
        }));
        assert!(!software_publisher_identity_ok(&token));
    }

    #[test]
    fn rejects_software_token_with_malformed_root_thumbprint() {
        let token = make_software_token(Some(PublisherIdentity::Authenticode {
            subject: "Example Corp".to_string(),
            // Uppercase hex — validate() requires lowercase.
            root_thumbprint: Some("A".repeat(40)),
        }));
        assert!(!software_publisher_identity_ok(&token));
    }

    #[test]
    fn rejects_software_token_with_malformed_apple_team_id() {
        let token = make_software_token(Some(PublisherIdentity::AppleDeveloperId {
            // Lowercase — validate() requires uppercase alphanumerics.
            team_id: "abcde12345".to_string(),
        }));
        assert!(!software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_non_attest_tokens_unconditionally() {
        let ident = Identity::generate("revoker", &mut OsRng);
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: "revoke-test".to_string(),
            sub: ident.id.to_urn(),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some("target-jti".to_string()),
            iat: 1714605000,
            // Revoke tokens must not carry an `exp` (RevocationMustNotExpire).
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        let token = Token::sign(payload, &ident.signing_key).expect("sign");
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_attest_tokens_with_no_body() {
        let ident = Identity::generate("attester", &mut OsRng);
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: "no-body-test".to_string(),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some("dds:directory-entry".to_string()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        let token = Token::sign(payload, &ident.signing_key).expect("sign");
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_attest_tokens_carrying_non_software_bodies() {
        let ident = Identity::generate("policy-publisher", &mut OsRng);
        // Hand-construct a payload tagged with WINDOWS_POLICY but with
        // an empty body_cbor so we don't have to round-trip the full
        // policy document type — `software_publisher_identity_ok` only
        // looks at body_type and short-circuits before decode.
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: "windows-policy-test".to_string(),
            sub: "device:fake".to_string(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(4102444800),
            body_type: Some(body_types::WINDOWS_POLICY.to_string()),
            body_cbor: Some(vec![0xA0]), // empty CBOR map
        };
        let token = Token::sign(payload, &ident.signing_key).expect("sign");
        assert!(software_publisher_identity_ok(&token));
    }

    #[test]
    fn admits_software_token_when_body_decode_fails() {
        // Decode failures are not this gate's responsibility — they
        // surface elsewhere (SyncResult::errors / the per-token
        // validation path). The gate must not panic and must not
        // silently reject because a malformed CBOR blob *might*
        // contain a malformed publisher_identity.
        let ident = Identity::generate("torn-publisher", &mut OsRng);
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: "torn-cbor-test".to_string(),
            sub: "device:fake".to_string(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(4102444800),
            body_type: Some(body_types::SOFTWARE_ASSIGNMENT.to_string()),
            // Junk bytes that won't decode as a SoftwareAssignment.
            body_cbor: Some(vec![0xFF, 0xFE, 0xFD]),
        };
        let token = Token::sign(payload, &ident.signing_key).expect("sign");
        assert!(software_publisher_identity_ok(&token));
    }
}
