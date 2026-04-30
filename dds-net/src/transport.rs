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
use std::time::Duration;

use libp2p::{
    PeerId, StreamProtocol, gossipsub, identify, kad, mdns, noise, request_response,
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
        }
    }
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

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(config.heartbeat_interval)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

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

            Ok(DdsBehaviour {
                gossipsub,
                kademlia,
                mdns,
                identify,
                sync,
                admission,
                epoch_keys,
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
        };
        let b = SwarmConfig {
            heartbeat_interval: Duration::from_secs(1),
            domain_tag: "globex".into(),
            idle_timeout: Duration::from_secs(10),
            mdns_enabled: false,
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
        };
        let (_swarm, peer_id) = build_swarm(cfg, kp).unwrap();
        assert_eq!(peer_id, expected_peer);
    }
}
