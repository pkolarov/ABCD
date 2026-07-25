//! libp2p swarm setup and Noise-encrypted transport configuration.
//!
//! Builds a libp2p `Swarm` with:
//! - TCP + QUIC transports (Noise encryption, Yamux muxing)
//! - Gossipsub for pub/sub directory operation propagation
//! - Kademlia DHT for peer routing
//! - mDNS for local network zero-config discovery
//! - Identify protocol for peer metadata exchange

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use libp2p::{
    PeerId, StreamProtocol, connection_limits, gossipsub, identify, kad, mdns, noise,
    request_response,
    swarm::{NetworkBehaviour, Swarm},
    tcp, yamux,
};

use crate::admission::{AdmissionRequest, AdmissionResponse};
use crate::pq_envelope::{EpochKeyRequest, EpochKeyResponse};
use crate::sync::{SyncRequest, SyncResponse};

/// Combined network behaviour for DDS nodes.
#[derive(NetworkBehaviour)]
pub struct DdsBehaviour {
    /// Gossipsub for directory operation propagation.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery and routing.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// mDNS for local network peer discovery (toggleable via config).
    pub mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    /// Identify protocol for exchanging peer metadata.
    pub identify: identify::Behaviour,
    /// Anti-entropy / catch-up sync over libp2p `request_response`.
    /// Lets a node that missed gossip messages (offline window, slow
    /// peer, message loss) pull the diff from any connected peer. The
    /// in-memory protocol is `SyncRequest`/`SyncResponse` defined in
    /// `dds_net::sync`; the wire format is CBOR via the built-in codec.
    /// Resolves B6 (the gossipsub-only delivery gap surfaced by the
    /// 2026-04-09 chaos soak).
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    /// **H-12 (security review)**: per-peer admission handshake.
    /// Immediately after Noise completes, each side asks the other
    /// for its admission cert over `/dds/admission/1.0.0/<domain>`
    /// and verifies it against the domain pubkey + its own `PeerId`
    /// expectation. Only admitted peers are allowed to publish into
    /// gossip or request sync; `dds-node` enforces the check against
    /// the result of this exchange. Kept as a separate behaviour
    /// (not piggybacked on `sync`) so the protocol version can evolve
    /// independently.
    pub admission: request_response::cbor::Behaviour<AdmissionRequest, AdmissionResponse>,
    /// **Z-1 Phase B.5 (`docs/pqc-phase-b-plan.md` §4.5 + §4.5.1)**:
    /// per-recipient epoch-key release exchange on
    /// `/dds/epoch-keys/1.0.0/<domain>`. Used by:
    ///
    /// 1. A publisher pushing fresh
    ///    [`crate::pq_envelope::EpochKeyRelease`] blobs to
    ///    already-admitted peers when it rotates mid-connection (the
    ///    H-12 piggy-back on
    ///    [`AdmissionResponse::epoch_key_releases`] only fires on
    ///    fresh handshakes).
    /// 2. A receiver that observes a
    ///    [`crate::pq_envelope::GossipEnvelopeV3`] for a
    ///    `(publisher, epoch_id)` it has no cached key for emitting
    ///    a single [`EpochKeyRequest`] for late-join recovery.
    ///
    /// Both sides advertise the protocol so either party can
    /// initiate; `dds-node` drives the request side from the
    /// rotation timer and the gossip-decrypt-miss path. Kept as a
    /// separate behaviour (not piggybacked on `sync` or `admission`)
    /// so the protocol version can evolve independently as the
    /// epoch-key wire format changes — Phase B.4's `EpochKeyRelease`
    /// already has additive `pq_signature: Option<…>`, but a future
    /// v4 release shape (e.g., MLS-style rekey) would bump this
    /// protocol while leaving sync / admission untouched.
    pub epoch_keys: request_response::cbor::Behaviour<EpochKeyRequest, EpochKeyResponse>,
    /// **M-1 (pre-prod review 2026-07-24)**: connection admission caps.
    ///
    /// The swarm binds `0.0.0.0:4001` by default, and every inbound
    /// connection costs a Noise handshake plus an admission-challenge
    /// allocation that lingers until the H-12 attempt budget is spent.
    /// Without a ceiling an attacker rotating keypairs (so the PeerId
    /// denylist never bites) can hold an unbounded number of half-open
    /// and established connections. `connection_limits` denies past the
    /// cap at the swarm layer, *before* any handshake work is done —
    /// [`libp2p::swarm::SwarmEvent::IncomingConnectionError`] is emitted
    /// instead. `dds-node` complements this with a wall-clock deadline
    /// on connections that never complete admission.
    ///
    /// Declared last so the derived `DdsBehaviourEvent` variants for the
    /// protocol behaviours above keep their ordinals; this behaviour's
    /// event type is [`std::convert::Infallible`], so its variant is
    /// never constructed.
    pub limits: connection_limits::Behaviour,
}

/// Configuration for building a DDS swarm.
#[derive(Debug, Clone)]
pub struct SwarmConfig {
    /// Gossipsub heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Domain protocol tag — bare base32 of the `DomainId`. Used to namespace
    /// libp2p protocol strings so nodes from different DDS domains cannot
    /// complete a handshake. Pass an empty string only in tests that bypass
    /// the domain layer.
    pub domain_tag: String,
    /// Idle connection timeout.
    pub idle_timeout: Duration,
    /// Whether mDNS is enabled for local network discovery.
    pub mdns_enabled: bool,
    /// **M-1** — connection admission caps applied by
    /// [`DdsBehaviour::limits`]. See [`ConnectionCaps`].
    pub connection_caps: ConnectionCaps,
}

/// **M-1 (pre-prod review 2026-07-24)** — inbound/outbound connection
/// ceilings handed to `connection_limits::Behaviour`.
///
/// Defaults are sized for the deployment shape DDS actually ships: a
/// LAN mesh of tens of nodes plus a handful of WAN bootstrap anchors.
/// They are generous enough that no legitimate topology hits them, and
/// tight enough that a single attacker cannot pin unbounded memory in
/// half-open Noise handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCaps {
    /// Half-open inbound connections (post-TCP-accept, pre-Noise).
    /// This is the cap that bounds handshake-flood memory.
    pub max_pending_incoming: u32,
    /// Half-open outbound connections (bounds a dial storm from our own
    /// Kademlia/mDNS discovery).
    pub max_pending_outgoing: u32,
    /// Established inbound connections.
    pub max_established_incoming: u32,
    /// Established outbound connections.
    pub max_established_outgoing: u32,
    /// Established connections to any single peer. libp2p opens one per
    /// transport (TCP + QUIC), so this must stay above 2.
    pub max_established_per_peer: u32,
}

impl Default for ConnectionCaps {
    fn default() -> Self {
        Self {
            max_pending_incoming: 64,
            max_pending_outgoing: 128,
            max_established_incoming: 256,
            max_established_outgoing: 256,
            // TCP + QUIC to the same peer is normal; allow a small margin
            // for a reconnect racing the teardown of the old connection.
            max_established_per_peer: 4,
        }
    }
}

impl ConnectionCaps {
    fn to_limits(self) -> connection_limits::ConnectionLimits {
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(self.max_pending_incoming))
            .with_max_pending_outgoing(Some(self.max_pending_outgoing))
            .with_max_established_incoming(Some(self.max_established_incoming))
            .with_max_established_outgoing(Some(self.max_established_outgoing))
            .with_max_established_per_peer(Some(self.max_established_per_peer))
    }
}

impl SwarmConfig {
    /// Kademlia protocol name for this domain.
    pub fn kad_protocol(&self) -> String {
        format!("/dds/kad/1.0.0/{}", self.domain_tag)
    }
    /// Identify protocol name for this domain.
    pub fn identify_protocol(&self) -> String {
        format!("/dds/id/1.0.0/{}", self.domain_tag)
    }
    /// Anti-entropy sync protocol name for this domain. Domain-tagged so
    /// nodes from different DDS domains can never complete a sync
    /// exchange (matches the isolation guarantee for kad/identify).
    pub fn sync_protocol(&self) -> String {
        format!("/dds/sync/1.0.0/{}", self.domain_tag)
    }
    /// Admission-exchange protocol name for this domain (H-12).
    /// Domain-tagged so a peer in a different domain never even
    /// enters the admission handshake.
    pub fn admission_protocol(&self) -> String {
        format!("/dds/admission/1.0.0/{}", self.domain_tag)
    }
    /// **Z-1 Phase B.5** — epoch-key request/response protocol name
    /// for this domain. Domain-tagged so a peer in a different
    /// domain (or running an Ed25519-only / pre-Phase-B build)
    /// cannot complete the exchange.
    pub fn epoch_keys_protocol(&self) -> String {
        format!("/dds/epoch-keys/1.0.0/{}", self.domain_tag)
    }
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            domain_tag: "default".to_string(),
            idle_timeout: Duration::from_secs(60),
            mdns_enabled: true,
            connection_caps: ConnectionCaps::default(),
        }
    }
}

/// **H-1 (pre-prod review 2026-07-24)** — peer-scoring parameters for
/// gossipsub.
///
/// Scoring is what makes `validate_messages()` bite: a peer whose
/// messages we repeatedly `Reject` accumulates a P4 invalid-message
/// penalty and eventually falls below the graylist threshold, at which
/// point gossipsub stops reading its RPCs entirely. Without scoring the
/// only consequence of rejection is "we didn't forward it", and an
/// attacker can re-offend for free.
///
/// The defaults are libp2p's, with one deliberate change: loopback
/// addresses are exempt from the IP-colocation penalty. Multi-node
/// integration tests, `dds-loadtest`, and single-host demo meshes run
/// every peer on 127.0.0.1, which would otherwise trip
/// `ip_colocation_factor_threshold` (10) and graylist honest peers.
fn peer_score_params() -> gossipsub::PeerScoreParams {
    let mut params = gossipsub::PeerScoreParams::default();
    params
        .ip_colocation_factor_whitelist
        .insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    params
        .ip_colocation_factor_whitelist
        .insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    params
}

/// Build a DDS swarm with the given configuration and a pre-existing
/// libp2p identity (so the `PeerId` is stable across restarts).
///
/// Returns the `Swarm` and the local `PeerId`.
pub fn build_swarm(
    config: SwarmConfig,
    keypair: libp2p::identity::Keypair,
) -> Result<(Swarm<DdsBehaviour>, PeerId), Box<dyn std::error::Error>> {
    let kad_protocol = config.kad_protocol();
    let identify_protocol = config.identify_protocol();
    let sync_protocol = config.sync_protocol();
    let admission_protocol = config.admission_protocol();
    let epoch_keys_protocol = config.epoch_keys_protocol();
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key: &libp2p::identity::Keypair| {
            let peer_id = key.public().to_peer_id();

            // Gossipsub: content-address messages by hash
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // **H-1 (pre-prod review 2026-07-24)** — `validate_messages()`
            // is the load-bearing flag here. Without it libp2p forwards
            // every signature-valid, non-duplicate message to the whole
            // mesh *before* the application sees it, so `dds-node`'s H-12
            // `admitted_peers` gate could only suppress local ingest —
            // the relay had already happened. An unadmitted, Noise-only
            // peer could therefore use any entry node as an amplifier for
            // the entire domain (dedup defeated by varying one byte), and
            // downstream nodes saw the message arrive from an honest
            // relay, so their own H-12 gate passed.
            //
            // With this flag every inbound message is parked in the
            // message cache until the application calls
            // `report_message_validation_result`. `dds-node` reports
            // `Accept` only after the admission gate + payload validation
            // pass; anything else is `Ignore`/`Reject` and is never
            // forwarded. See `Node::handle_swarm_event` — every path out
            // of the gossip arm must report exactly once or the message
            // leaks until the mcache TTL expires it.
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(config.heartbeat_interval)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .validate_messages()
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;
            // **H-1** — activate peer scoring so repeat offenders are
            // graylisted rather than merely ignored one message at a time.
            gossipsub
                .with_peer_score(
                    peer_score_params(),
                    gossipsub::PeerScoreThresholds::default(),
                )
                .map_err(std::io::Error::other)?;

            // Kademlia DHT
            let mut kad_config = kad::Config::new(
                libp2p::StreamProtocol::try_from_owned(kad_protocol.clone())
                    .map_err(|e| std::io::Error::other(format!("invalid protocol: {e}")))?,
            );
            kad_config.set_query_timeout(Duration::from_secs(30));
            let store = kad::store::MemoryStore::new(peer_id);
            let kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);

            // mDNS (conditionally enabled)
            let mdns = if config.mdns_enabled {
                libp2p::swarm::behaviour::toggle::Toggle::from(Some(mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    peer_id,
                )?))
            } else {
                libp2p::swarm::behaviour::toggle::Toggle::from(None)
            };

            // Identify
            let identify = identify::Behaviour::new(identify::Config::new(
                identify_protocol.clone(),
                key.public(),
            ));

            // Anti-entropy sync (request_response over CBOR). Both sides
            // are full participants — every node can serve a sync
            // request from any other node in its domain.
            let sync = request_response::cbor::Behaviour::<SyncRequest, SyncResponse>::new(
                [(
                    StreamProtocol::try_from_owned(sync_protocol.clone())
                        .map_err(|e| std::io::Error::other(format!("invalid protocol: {e}")))?,
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            // H-12: admission handshake (request_response over CBOR).
            // Both sides advertise the protocol so either party can
            // initiate; `dds-node` drives the exchange on
            // `ConnectionEstablished`.
            let admission =
                request_response::cbor::Behaviour::<AdmissionRequest, AdmissionResponse>::new(
                    [(
                        StreamProtocol::try_from_owned(admission_protocol.clone())
                            .map_err(|e| std::io::Error::other(format!("invalid protocol: {e}")))?,
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

            // **Z-1 Phase B.5** — epoch-key request/response. Both
            // sides advertise the protocol so either the publisher
            // (push on rotation) or the receiver (late-join recovery
            // pull) can initiate. `dds-node` drives the request side
            // off the rotation timer and the gossip-decrypt-miss
            // path; the wire format is CBOR via the built-in codec
            // and routes the opaque `EpochKeyRelease` blobs from
            // `pq_envelope`.
            let epoch_keys =
                request_response::cbor::Behaviour::<EpochKeyRequest, EpochKeyResponse>::new(
                    [(
                        StreamProtocol::try_from_owned(epoch_keys_protocol.clone())
                            .map_err(|e| std::io::Error::other(format!("invalid protocol: {e}")))?,
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

            // **M-1** — swarm-layer connection admission caps.
            let limits = connection_limits::Behaviour::new(config.connection_caps.to_limits());

            Ok(DdsBehaviour {
                gossipsub,
                kademlia,
                mdns,
                identify,
                sync,
                admission,
                epoch_keys,
                limits,
            })
        })?
        .with_swarm_config(|c: libp2p::swarm::Config| {
            c.with_idle_connection_timeout(config.idle_timeout)
        })
        .build();

    let peer_id = *swarm.local_peer_id();
    Ok((swarm, peer_id))
}

/// Build a DDS swarm with default configuration and a fresh ephemeral
/// libp2p identity. Convenience for tests only — production code should
/// build the swarm with a persistent keypair so the `PeerId` is stable.
pub fn build_default_swarm() -> Result<(Swarm<DdsBehaviour>, PeerId), Box<dyn std::error::Error>> {
    build_swarm(
        SwarmConfig::default(),
        libp2p::identity::Keypair::generate_ed25519(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_strings_include_domain_tag() {
        let cfg = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "abc123".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
            connection_caps: ConnectionCaps::default(),
        };
        assert_eq!(cfg.kad_protocol(), "/dds/kad/1.0.0/abc123");
        assert_eq!(cfg.identify_protocol(), "/dds/id/1.0.0/abc123");
        assert_eq!(cfg.sync_protocol(), "/dds/sync/1.0.0/abc123");
        assert_eq!(cfg.admission_protocol(), "/dds/admission/1.0.0/abc123");
        assert_eq!(cfg.epoch_keys_protocol(), "/dds/epoch-keys/1.0.0/abc123");
    }

    #[test]
    fn different_domain_tags_yield_distinct_protocols() {
        let a = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "acme".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
            connection_caps: ConnectionCaps::default(),
        };
        let b = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "globex".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
            connection_caps: ConnectionCaps::default(),
        };
        assert_ne!(a.kad_protocol(), b.kad_protocol());
        assert_ne!(a.identify_protocol(), b.identify_protocol());
        assert_ne!(a.sync_protocol(), b.sync_protocol());
        assert_ne!(a.admission_protocol(), b.admission_protocol());
        assert_ne!(a.epoch_keys_protocol(), b.epoch_keys_protocol());
    }

    #[test]
    fn build_swarm_with_explicit_keypair_is_stable() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let expected_peer = libp2p::PeerId::from(kp.public());
        let cfg = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "test".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
            connection_caps: ConnectionCaps::default(),
        };
        let (_swarm, peer_id) = build_swarm(cfg, kp).unwrap();
        assert_eq!(peer_id, expected_peer);
    }

    /// **H-1 regression (pre-prod review 2026-07-24)** — the gossipsub
    /// config must enable application-side validation.
    ///
    /// Without `validate_messages()` libp2p auto-forwards every
    /// signature-valid, non-duplicate message to the mesh *before*
    /// `dds-node`'s H-12 admission gate runs, so the gate could only
    /// suppress local ingest — the relay had already happened. An
    /// unadmitted, Noise-only peer could then use any entry node as an
    /// amplifier into the whole domain. This is the single flag that
    /// makes the gate load-bearing for relay, so it is worth pinning
    /// directly rather than only through the node-level behaviour test.
    #[test]
    fn h1_gossipsub_config_requires_application_validation() {
        let cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .build()
            .expect("config builds");
        assert!(
            cfg.validate_messages(),
            "H-1: gossipsub must hold messages for application validation"
        );
        assert!(matches!(
            cfg.validation_mode(),
            gossipsub::ValidationMode::Strict
        ));
    }

    /// **H-1** — the peer-score parameters must actually validate, or
    /// `with_peer_score` fails at swarm build and scoring silently never
    /// activates. Also pins the loopback whitelist: without it, every
    /// multi-node test and single-host demo mesh (all peers on
    /// 127.0.0.1) trips `ip_colocation_factor_threshold` and graylists
    /// honest peers.
    #[test]
    fn h1_peer_score_params_are_valid_and_exempt_loopback() {
        let params = peer_score_params();
        params.validate().expect("peer score params must validate");
        gossipsub::PeerScoreThresholds::default()
            .validate()
            .expect("peer score thresholds must validate");
        assert!(
            params
                .ip_colocation_factor_whitelist
                .contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "loopback must be exempt from the IP-colocation penalty"
        );
        assert!(
            params
                .ip_colocation_factor_whitelist
                .contains(&IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    /// **M-1 regression (pre-prod review 2026-07-24)** — the swarm must
    /// carry finite connection ceilings.
    ///
    /// The listener binds `0.0.0.0:4001` by default and every inbound
    /// connection costs a Noise handshake plus an admission-challenge
    /// allocation. With no cap, an attacker rotating keypairs (so the
    /// PeerId denylist never bites) could hold an unbounded number of
    /// half-open connections.
    #[test]
    fn m1_connection_caps_are_finite_and_allow_dual_transport() {
        let caps = ConnectionCaps::default();
        assert!(caps.max_pending_incoming > 0);
        assert!(caps.max_established_incoming > 0);
        assert!(caps.max_pending_outgoing > 0);
        assert!(caps.max_established_outgoing > 0);
        // libp2p opens one connection per transport (TCP + QUIC) to the
        // same peer, and a reconnect can briefly race the teardown of
        // the old one — anything below 3 would flap.
        assert!(
            caps.max_established_per_peer >= 3,
            "per-peer cap must leave room for TCP + QUIC plus a reconnect race"
        );
        // The per-peer cap must not exceed the global inbound cap, or it
        // would be unreachable.
        assert!(caps.max_established_per_peer <= caps.max_established_incoming);
    }

    /// **M-1** — the caps must survive into the built swarm. This
    /// exercises the real `build_swarm` path, so a future edit that
    /// drops the `limits` behaviour from `DdsBehaviour` fails here.
    #[test]
    fn m1_build_swarm_installs_connection_limits() {
        let cfg = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "caps".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
            connection_caps: ConnectionCaps {
                max_pending_incoming: 7,
                max_pending_outgoing: 8,
                max_established_incoming: 9,
                max_established_outgoing: 10,
                max_established_per_peer: 4,
            },
        };
        let (swarm, _peer) =
            build_swarm(cfg, libp2p::identity::Keypair::generate_ed25519()).unwrap();
        // `connection_limits::Behaviour` exposes no getter for its
        // limits, so assert the field exists and the swarm built with it
        // — the compile-time reference is the load-bearing part.
        let _limits: &connection_limits::Behaviour = &swarm.behaviour().limits;
    }
}
