//! Air-gapped sync dump format.
//!
//! A single CBOR file that packages a node's tokens, CRDT operations,
//! and revocation/burn sets so two nodes that can never see each other
//! on the network can stay in sync via USB-stick / courier transfer.
//!
//! The format is intentionally simple:
//!
//! ```text
//! DdsDump {
//!   version: u8 = 1,
//!   domain_id: String,          // "dds-dom:<base32>" — must match on import
//!   exported_at: u64,           // unix seconds
//!   tokens: Vec<Vec<u8>>,       // CBOR-encoded Token (payload+signature)
//!   operations: Vec<Vec<u8>>,   // CBOR-encoded Operation
//!   revoked: Vec<String>,       // revoked JTIs
//!   burned:  Vec<String>,       // burned identity URNs
//! }
//! ```
//!
//! All imports are *idempotent*: `put_token`, `put_operation`, `revoke`
//! and `burn` are safe to re-apply. Re-importing the same dump twice
//! changes nothing.

use serde::{Deserialize, Serialize};

/// Current on-disk dump format version.
pub const DUMP_VERSION: u8 = 1;

/// Top-level .ddsdump payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct DdsDump {
    pub version: u8,
    pub domain_id: String,
    pub exported_at: u64,
    pub tokens: Vec<Vec<u8>>,
    pub operations: Vec<Vec<u8>>,
    pub revoked: Vec<String>,
    pub burned: Vec<String>,
}

impl DdsDump {
    /// Serialize the dump to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    /// Deserialize a dump from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
    }
}
