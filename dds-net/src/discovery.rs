//! Peer discovery via Kademlia DHT and mDNS.
//!
//! Handles two discovery mechanisms:
//! - **mDNS** — Zero-config local network discovery (LAN)
//! - **Kademlia DHT** — Internet-scale peer routing via bootstrap nodes

use libp2p::{Multiaddr, PeerId, Swarm};

use crate::transport::DdsBehaviour;

/// Add a bootstrap peer to the Kademlia DHT.
pub fn add_bootstrap_peer(swarm: &mut Swarm<DdsBehaviour>, peer_id: PeerId, addr: Multiaddr) {
    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
}

/// Add multiple bootstrap peers.
pub fn add_bootstrap_peers(swarm: &mut Swarm<DdsBehaviour>, peers: &[(PeerId, Multiaddr)]) {
    for (peer_id, addr) in peers {
        add_bootstrap_peer(swarm, *peer_id, addr.clone());
    }
}

/// Trigger a Kademlia bootstrap to discover peers.
pub fn bootstrap_kademlia(swarm: &mut Swarm<DdsBehaviour>) -> Result<libp2p::kad::QueryId, String> {
    swarm
        .behaviour_mut()
        .kademlia
        .bootstrap()
        .map_err(|e| format!("Kademlia bootstrap failed: {e}"))
}

/// Add a peer discovered via mDNS to gossipsub.
pub fn add_mdns_peer(swarm: &mut Swarm<DdsBehaviour>, peer_id: PeerId) {
    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
    tracing::info!(%peer_id, "mDNS: added peer to gossipsub");
}

/// Remove a peer that expired from mDNS.
pub fn remove_mdns_peer(swarm: &mut Swarm<DdsBehaviour>, peer_id: PeerId) {
    swarm
        .behaviour_mut()
        .gossipsub
        .remove_explicit_peer(&peer_id);
    tracing::info!(%peer_id, "mDNS: removed peer from gossipsub");
}

/// Parse a multiaddr string containing an embedded peer ID.
///
/// Expected format: `/ip4/10.0.1.1/tcp/4001/p2p/<peer-id>`
pub fn parse_peer_multiaddr(addr_str: &str) -> Result<(PeerId, Multiaddr), String> {
    let addr: Multiaddr = addr_str
        .parse()
        .map_err(|e| format!("invalid multiaddr: {e}"))?;

    // Extract peer ID from the /p2p/ component
    let peer_id = addr
        .iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .ok_or_else(|| "multiaddr missing /p2p/ component".to_string())?;

    Ok((peer_id, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_peer_multiaddr_tcp() {
        let addr =
            "/ip4/10.0.1.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let (peer_id, multiaddr) = parse_peer_multiaddr(addr).unwrap();
        assert_eq!(
            peer_id.to_string(),
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        );
        assert!(multiaddr.to_string().contains("/tcp/4001"));
    }

    #[test]
    fn test_parse_peer_multiaddr_invalid() {
        let result = parse_peer_multiaddr("not-a-multiaddr");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_peer_multiaddr_no_peer_id() {
        let result = parse_peer_multiaddr("/ip4/10.0.1.1/tcp/4001");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing /p2p/"));
    }
}
