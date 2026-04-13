//! Cryptographic audit log entries for mutations.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKeyBundle, SignatureBundle};

/// An append-only cryptographic audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Action being performed (e.g., "attest", "vouch", "revoke", "burn").
    pub action: String,
    /// The CBOR-encoded Token that caused this mutation.
    pub token_bytes: Vec<u8>,
    /// Identity URN of the node that gossiped this entry.
    pub node_urn: String,
    /// Public key bundle of the node that gossiped this entry.
    pub node_public_key: PublicKeyBundle,
    /// Signature of this entry by the node.
    pub node_signature: SignatureBundle,
    /// Unix timestamp (seconds since epoch) when this entry was created.
    /// Older entries without this field deserialize as 0.
    #[serde(default)]
    pub timestamp: u64,
}
