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
    gossipsub, identify, kad, mdns, noise,
    swarm::{NetworkBehaviour, Swarm},
    tcp, yamux, PeerId,
};

/// Combined network behaviour for DDS nodes.
#[derive(NetworkBehaviour)]
pub struct DdsBehaviour {
    /// Gossipsub for directory operation propagation.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery and routing.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// mDNS for local network peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol for exchanging peer metadata.
    pub identify: identify::Behaviour,
}

/// Configuration for building a DDS swarm.
#[derive(Debug, Clone)]
pub struct SwarmConfig {
    /// Gossipsub heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Kademlia protocol name.
    pub kad_protocol: String,
    /// Idle connection timeout.
    pub idle_timeout: Duration,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            kad_protocol: "/dds/kad/1.0.0".to_string(),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// Build a DDS swarm with the given configuration.
///
/// Returns the `Swarm` and the local `PeerId`.
pub fn build_swarm(config: SwarmConfig) -> Result<(Swarm<DdsBehaviour>, PeerId), Box<dyn std::error::Error>> {
    let swarm = libp2p::SwarmBuilder::with_new_identity()
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
                libp2p::StreamProtocol::try_from_owned(config.kad_protocol.clone())
                    .map_err(|e| std::io::Error::other(format!("invalid protocol: {e}")))?,
            );
            kad_config.set_query_timeout(Duration::from_secs(30));
            let store = kad::store::MemoryStore::new(peer_id);
            let kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);

            // mDNS
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?;

            // Identify
            let identify = identify::Behaviour::new(identify::Config::new(
                "/dds/id/1.0.0".to_string(),
                key.public(),
            ));

            Ok(DdsBehaviour {
                gossipsub,
                kademlia,
                mdns,
                identify,
            })
        })?
        .with_swarm_config(|c: libp2p::swarm::Config| c.with_idle_connection_timeout(config.idle_timeout))
        .build();

    let peer_id = *swarm.local_peer_id();
    Ok((swarm, peer_id))
}

/// Build a DDS swarm with default configuration.
pub fn build_default_swarm() -> Result<(Swarm<DdsBehaviour>, PeerId), Box<dyn std::error::Error>> {
    build_swarm(SwarmConfig::default())
}
