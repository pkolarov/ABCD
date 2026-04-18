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
//!   version: u8 = 2,
//!   domain_id: String,          // "dds-dom:<base32>" — must match on import
//!   exported_at: u64,           // unix seconds
//!   tokens: Vec<Vec<u8>>,       // CBOR-encoded Token (payload+signature)
//!   operations: Vec<Vec<u8>>,   // CBOR-encoded Operation
//!   revoked: Vec<String>,       // revoked JTIs
//!   burned:  Vec<String>,       // burned identity URNs
//!   signature: Vec<u8>,         // v2+: Ed25519(domain_key) over signing_bytes
//! }
//! ```
//!
//! **M-16 (security review)**: v2 dumps carry a mandatory Ed25519
//! signature by the domain signing key over a canonical digest of
//! the dump contents. The importer verifies the signature against
//! the local domain pubkey (or the one in the dump if bootstrapping)
//! before applying anything. Legacy v1 dumps still read with a
//! warning because they pre-date this check.
//!
//! All imports are *idempotent*: `put_token`, `put_operation`, `revoke`
//! and `burn` are safe to re-apply. Re-importing the same dump twice
//! changes nothing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current on-disk dump format version. v1 had no signature; v2 adds
/// a required Ed25519 signature over `signing_bytes`.
pub const DUMP_VERSION: u8 = 2;
/// Oldest version we still read (with a warning).
pub const DUMP_MIN_READ_VERSION: u8 = 1;

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
    /// Ed25519 signature by the domain signing key over
    /// [`DdsDump::signing_bytes`]. Empty for legacy v1 dumps.
    #[serde(default, with = "serde_bytes")]
    pub signature: Vec<u8>,
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

    /// Canonical bytes covered by the dump's signature. Order is
    /// fixed: version, domain_id, exported_at, each tokens entry in
    /// order, each operations entry in order, each revoked JTI in
    /// order, each burned URN in order. Uses SHA-256 to keep the
    /// signed payload small and stable across CBOR encoder drift.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"dds-dump-v2|");
        h.update([self.version]);
        h.update(b"|");
        h.update(self.domain_id.as_bytes());
        h.update(b"|");
        h.update(self.exported_at.to_be_bytes());
        h.update(b"|");
        h.update((self.tokens.len() as u64).to_be_bytes());
        for t in &self.tokens {
            h.update((t.len() as u64).to_be_bytes());
            h.update(t);
        }
        h.update((self.operations.len() as u64).to_be_bytes());
        for o in &self.operations {
            h.update((o.len() as u64).to_be_bytes());
            h.update(o);
        }
        h.update((self.revoked.len() as u64).to_be_bytes());
        for jti in &self.revoked {
            h.update((jti.len() as u64).to_be_bytes());
            h.update(jti.as_bytes());
        }
        h.update((self.burned.len() as u64).to_be_bytes());
        for urn in &self.burned {
            h.update((urn.len() as u64).to_be_bytes());
            h.update(urn.as_bytes());
        }
        h.finalize().to_vec()
    }
}
