//! Gossipsub topic management for directory operation propagation.
//!
//! Topics follow the structure:
//! - `/dds/v1/dom/<dom-tag>/org/<org-hash>/ops` — All operations for an org
//! - `/dds/v1/dom/<dom-tag>/org/<org-hash>/revocations` — Revocations
//! - `/dds/v1/dom/<dom-tag>/org/<org-hash>/burns` — Identity burns
//!
//! The `dom-tag` is the bare base32 encoding of the `DomainId` and provides
//! a second layer of cross-domain isolation on top of the libp2p protocol
//! string namespacing in [`crate::transport`].

use libp2p::gossipsub;
use serde::{Deserialize, Serialize};

/// DDS gossipsub topic types. Each variant carries `(domain_tag, org_hash)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DdsTopic {
    /// General directory operations for an (domain, org) pair.
    Operations(String, String),
    /// Revocation-only channel (high priority).
    Revocations(String, String),
    /// Burn-only channel (highest priority).
    Burns(String, String),
}

impl DdsTopic {
    /// Create the topic set for a given domain tag and org root hash.
    pub fn for_domain_org(domain_tag: &str, org_hash: &str) -> DdsTopicSet {
        let d = domain_tag.to_string();
        let o = org_hash.to_string();
        DdsTopicSet {
            operations: DdsTopic::Operations(d.clone(), o.clone()),
            revocations: DdsTopic::Revocations(d.clone(), o.clone()),
            burns: DdsTopic::Burns(d, o),
        }
    }

    /// Get the gossipsub topic string.
    pub fn topic_string(&self) -> String {
        match self {
            DdsTopic::Operations(d, o) => format!("/dds/v1/dom/{d}/org/{o}/ops"),
            DdsTopic::Revocations(d, o) => format!("/dds/v1/dom/{d}/org/{o}/revocations"),
            DdsTopic::Burns(d, o) => format!("/dds/v1/dom/{d}/org/{o}/burns"),
        }
    }

    /// Convert to a gossipsub IdentTopic.
    pub fn to_ident_topic(&self) -> gossipsub::IdentTopic {
        gossipsub::IdentTopic::new(self.topic_string())
    }
}

/// A complete set of topics for one organization.
#[derive(Debug, Clone)]
pub struct DdsTopicSet {
    pub operations: DdsTopic,
    pub revocations: DdsTopic,
    pub burns: DdsTopic,
}

impl DdsTopicSet {
    /// Subscribe to all topics in this set on the given gossipsub behaviour.
    pub fn subscribe_all(
        &self,
        gossipsub: &mut gossipsub::Behaviour,
    ) -> Result<(), gossipsub::SubscriptionError> {
        gossipsub.subscribe(&self.operations.to_ident_topic())?;
        gossipsub.subscribe(&self.revocations.to_ident_topic())?;
        gossipsub.subscribe(&self.burns.to_ident_topic())?;
        Ok(())
    }

    /// Get all topic hashes for matching incoming messages.
    pub fn topic_hashes(&self) -> Vec<gossipsub::TopicHash> {
        vec![
            self.operations.to_ident_topic().hash(),
            self.revocations.to_ident_topic().hash(),
            self.burns.to_ident_topic().hash(),
        ]
    }

    /// Determine which DdsTopic a message belongs to based on its topic hash.
    pub fn identify_topic(&self, hash: &gossipsub::TopicHash) -> Option<&DdsTopic> {
        if *hash == self.operations.to_ident_topic().hash() {
            Some(&self.operations)
        } else if *hash == self.revocations.to_ident_topic().hash() {
            Some(&self.revocations)
        } else if *hash == self.burns.to_ident_topic().hash() {
            Some(&self.burns)
        } else {
            None
        }
    }
}

/// Message types sent over gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// A new directory operation (CRDT op + backing token).
    DirectoryOp {
        /// CBOR-encoded Operation.
        op_bytes: Vec<u8>,
        /// CBOR-encoded signed Token backing this operation.
        token_bytes: Vec<u8>,
    },
    /// A revocation announcement.
    Revocation {
        /// CBOR-encoded revocation Token.
        token_bytes: Vec<u8>,
    },
    /// An identity burn announcement.
    Burn {
        /// CBOR-encoded burn Token.
        token_bytes: Vec<u8>,
    },
}

impl GossipMessage {
    /// Serialize to CBOR bytes for gossip transmission.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DOMAIN: &str = "domtag";
    const TEST_ORG: &str = "abc123hash";

    #[test]
    fn test_topic_strings() {
        let topics = DdsTopic::for_domain_org(TEST_DOMAIN, TEST_ORG);
        assert_eq!(
            topics.operations.topic_string(),
            "/dds/v1/dom/domtag/org/abc123hash/ops"
        );
        assert_eq!(
            topics.revocations.topic_string(),
            "/dds/v1/dom/domtag/org/abc123hash/revocations"
        );
        assert_eq!(
            topics.burns.topic_string(),
            "/dds/v1/dom/domtag/org/abc123hash/burns"
        );
    }

    #[test]
    fn test_topics_isolated_per_domain() {
        let a = DdsTopic::for_domain_org("acme", TEST_ORG);
        let b = DdsTopic::for_domain_org("globex", TEST_ORG);
        assert_ne!(
            a.operations.to_ident_topic().hash(),
            b.operations.to_ident_topic().hash()
        );
    }

    #[test]
    fn test_identify_topic() {
        let topics = DdsTopic::for_domain_org(TEST_DOMAIN, TEST_ORG);
        let ops_hash = topics.operations.to_ident_topic().hash();
        let rev_hash = topics.revocations.to_ident_topic().hash();
        let burn_hash = topics.burns.to_ident_topic().hash();

        assert!(matches!(
            topics.identify_topic(&ops_hash),
            Some(DdsTopic::Operations(..))
        ));
        assert!(matches!(
            topics.identify_topic(&rev_hash),
            Some(DdsTopic::Revocations(..))
        ));
        assert!(matches!(
            topics.identify_topic(&burn_hash),
            Some(DdsTopic::Burns(..))
        ));

        let unknown = gossipsub::IdentTopic::new("unknown").hash();
        assert!(topics.identify_topic(&unknown).is_none());
    }

    #[test]
    fn test_topic_hashes_count() {
        let topics = DdsTopic::for_domain_org(TEST_DOMAIN, TEST_ORG);
        assert_eq!(topics.topic_hashes().len(), 3);
    }

    #[test]
    fn test_gossip_message_cbor_roundtrip_op() {
        let msg = GossipMessage::DirectoryOp {
            op_bytes: vec![1, 2, 3],
            token_bytes: vec![4, 5, 6],
        };
        let encoded = msg.to_cbor().unwrap();
        let decoded = GossipMessage::from_cbor(&encoded).unwrap();
        assert!(matches!(decoded, GossipMessage::DirectoryOp { .. }));
    }

    #[test]
    fn test_gossip_message_cbor_roundtrip_revocation() {
        let msg = GossipMessage::Revocation {
            token_bytes: vec![10, 20, 30],
        };
        let encoded = msg.to_cbor().unwrap();
        let decoded = GossipMessage::from_cbor(&encoded).unwrap();
        assert!(matches!(decoded, GossipMessage::Revocation { .. }));
    }

    #[test]
    fn test_gossip_message_cbor_roundtrip_burn() {
        let msg = GossipMessage::Burn {
            token_bytes: vec![99],
        };
        let encoded = msg.to_cbor().unwrap();
        let decoded = GossipMessage::from_cbor(&encoded).unwrap();
        assert!(matches!(decoded, GossipMessage::Burn { .. }));
    }

    #[test]
    fn test_gossip_message_from_invalid_cbor() {
        let result = GossipMessage::from_cbor(&[0xff, 0xfe]);
        assert!(result.is_err());
    }
}
