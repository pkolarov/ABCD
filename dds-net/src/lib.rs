//! # dds-net
//!
//! P2P networking layer for the Decentralized Directory Service.
//!
//! Built on libp2p, provides:
//! - [`transport`] — Swarm construction with combined DdsBehaviour
//! - [`gossip`] — Gossipsub topic management for directory operations
//! - [`discovery`] — Kademlia DHT + mDNS peer discovery
//! - [`sync`] — Delta-sync protocol for efficient state convergence

pub mod admission;
pub mod discovery;
pub mod gossip;
pub mod pq_envelope;
pub mod sync;
pub mod transport;
