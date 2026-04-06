//! # dds-net
//!
//! P2P networking layer for the Decentralized Directory Service.
//!
//! Built on libp2p, provides:
//! - Gossipsub topic management for directory operation propagation
//! - Kademlia DHT + mDNS peer discovery
//! - Delta-sync protocol for efficient state convergence
//! - Noise-encrypted transport (TCP + QUIC)

pub mod discovery;
pub mod gossip;
pub mod sync;
pub mod transport;
