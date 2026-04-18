//! Cryptographic audit log entries for mutations.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKeyBundle, SchemeId, SignatureBundle, verify};
use crate::identity::VouchsafeId;

/// An append-only cryptographic audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Action being performed (e.g., "attest", "vouch", "revoke", "burn").
    pub action: String,
    /// The CBOR-encoded Token that caused this mutation.
    #[serde(with = "serde_bytes")]
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
    /// **L-12 (security review)**: SHA-256 of the previous entry's
    /// [`AuditLogEntry::chain_hash`], or empty bytes for the first
    /// entry in the log ("genesis"). The hash chain makes the log
    /// tamper-evident: removing or editing any entry breaks the
    /// chain at every later entry. `prev_hash` is covered by
    /// `node_signature` via [`AuditLogEntry::signing_bytes`], so it
    /// cannot be rewritten without a fresh signature from the
    /// (correctly-bound) node key.
    #[serde(default, with = "serde_bytes")]
    pub prev_hash: Vec<u8>,
}

/// The fields of an `AuditLogEntry` that are covered by the
/// `node_signature`. Mirrors `AuditLogEntry` in field order; we
/// CBOR-encode this struct (which excludes `node_signature`) to produce
/// the bytes that are signed and verified. Borrows so it can be built
/// from an existing entry without cloning, but only used as Serialize.
#[derive(Debug, Serialize)]
struct AuditLogSignedFields<'a> {
    action: &'a str,
    #[serde(with = "serde_bytes")]
    token_bytes: &'a [u8],
    node_urn: &'a str,
    node_public_key: &'a PublicKeyBundle,
    timestamp: u64,
    /// L-12: include the chain predecessor in the signed bytes so
    /// rewriting history requires forging every subsequent signature.
    #[serde(with = "serde_bytes")]
    prev_hash: &'a [u8],
}

/// Errors from constructing or verifying an `AuditLogEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    Serialization,
    UrnKeyBindingMismatch,
    InvalidSignature,
}

impl core::fmt::Display for AuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuditError::Serialization => write!(f, "audit entry serialization failed"),
            AuditError::UrnKeyBindingMismatch => {
                write!(f, "node_urn does not bind to node_public_key")
            }
            AuditError::InvalidSignature => write!(f, "audit entry signature invalid"),
        }
    }
}

impl AuditLogEntry {
    /// CBOR-encode the fields covered by `node_signature` (everything
    /// except the signature itself). Used by both `sign` and `verify`
    /// so the byte sequence is always identical.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let signed = AuditLogSignedFields {
            action: &self.action,
            token_bytes: &self.token_bytes,
            node_urn: &self.node_urn,
            node_public_key: &self.node_public_key,
            timestamp: self.timestamp,
            prev_hash: &self.prev_hash,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&signed, &mut buf).map_err(|_| AuditError::Serialization)?;
        Ok(buf)
    }

    /// **L-12 (security review)**: the hash that the *next* entry in
    /// the log should carry as `prev_hash`. Computed over the full
    /// signed bytes plus the signature so any tamper to the entry
    /// (including the signature field itself) rotates the chain
    /// head and breaks all following entries.
    pub fn chain_hash(&self) -> Result<Vec<u8>, AuditError> {
        use sha2::{Digest, Sha256};
        let bytes = self.signing_bytes()?;
        let mut h = Sha256::new();
        h.update(b"dds-audit-chain-v1|");
        h.update(&bytes);
        h.update(b"|");
        h.update(&self.node_signature.bytes);
        Ok(h.finalize().to_vec())
    }

    /// Construct and sign an entry with an Ed25519 signing key derived
    /// from the node identity.
    #[cfg(feature = "std")]
    pub fn sign_ed25519(
        action: impl Into<String>,
        token_bytes: Vec<u8>,
        node_urn: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
        timestamp: u64,
    ) -> Result<Self, AuditError> {
        Self::sign_ed25519_chained(
            action,
            token_bytes,
            node_urn,
            signing_key,
            timestamp,
            Vec::new(),
        )
    }

    /// Construct and sign an entry, stamping `prev_hash` from the
    /// previous log entry's [`AuditLogEntry::chain_hash`]. Pass an
    /// empty `prev_hash` for the genesis entry. **L-12**.
    #[cfg(feature = "std")]
    pub fn sign_ed25519_chained(
        action: impl Into<String>,
        token_bytes: Vec<u8>,
        node_urn: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
        timestamp: u64,
        prev_hash: Vec<u8>,
    ) -> Result<Self, AuditError> {
        use ed25519_dalek::Signer;

        let node_public_key = PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        let mut entry = Self {
            action: action.into(),
            token_bytes,
            node_urn: node_urn.into(),
            node_public_key,
            // Placeholder — rewritten below once signing_bytes is built.
            node_signature: SignatureBundle {
                scheme: SchemeId::Ed25519,
                bytes: Vec::new(),
            },
            timestamp,
            prev_hash,
        };
        let bytes = entry.signing_bytes()?;
        let sig = signing_key.sign(&bytes);
        entry.node_signature = SignatureBundle {
            scheme: SchemeId::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        };
        Ok(entry)
    }

    /// Verify that:
    ///  1. `node_urn` cryptographically derives from `node_public_key`
    ///     (same URN-from-pubkey check used by `Token::verify_issuer_binding`)
    ///  2. `node_signature` is a valid signature over `signing_bytes()`
    ///     under `node_public_key`.
    pub fn verify(&self) -> Result<(), AuditError> {
        let id =
            VouchsafeId::from_urn(&self.node_urn).map_err(|_| AuditError::UrnKeyBindingMismatch)?;
        if !id.verify_binding_bundle(&self.node_public_key) {
            return Err(AuditError::UrnKeyBindingMismatch);
        }
        let bytes = self.signing_bytes()?;
        verify(&self.node_public_key, &bytes, &self.node_signature)
            .map_err(|_| AuditError::InvalidSignature)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand::rngs::OsRng;

    #[test]
    fn audit_entry_sign_verify_roundtrip() {
        let id = Identity::generate("audit-test", &mut OsRng);
        let entry = AuditLogEntry::sign_ed25519(
            "attest",
            alloc::vec![0xA0],
            id.id.to_urn(),
            &id.signing_key,
            1234,
        )
        .unwrap();
        assert!(entry.verify().is_ok());
    }

    #[test]
    fn audit_entry_rejects_tampered_signature() {
        let id = Identity::generate("audit-test", &mut OsRng);
        let mut entry = AuditLogEntry::sign_ed25519(
            "attest",
            alloc::vec![0xA0],
            id.id.to_urn(),
            &id.signing_key,
            1234,
        )
        .unwrap();
        // Flip a byte in the signature.
        entry.node_signature.bytes[0] ^= 0xFF;
        assert_eq!(entry.verify(), Err(AuditError::InvalidSignature));
    }

    #[test]
    fn audit_entry_rejects_tampered_action() {
        let id = Identity::generate("audit-test", &mut OsRng);
        let mut entry = AuditLogEntry::sign_ed25519(
            "attest",
            alloc::vec![0xA0],
            id.id.to_urn(),
            &id.signing_key,
            1234,
        )
        .unwrap();
        entry.action = "burn".into();
        assert_eq!(entry.verify(), Err(AuditError::InvalidSignature));
    }

    /// L-12: chaining together three entries and verifying each
    /// `prev_hash` matches the previous entry's `chain_hash`.
    #[test]
    fn audit_entry_chain_hash_links_next_entry() {
        let id = Identity::generate("audit", &mut OsRng);
        let e1 = AuditLogEntry::sign_ed25519_chained(
            "attest",
            alloc::vec![0xA1],
            id.id.to_urn(),
            &id.signing_key,
            1,
            Vec::new(),
        )
        .unwrap();
        let h1 = e1.chain_hash().unwrap();
        let e2 = AuditLogEntry::sign_ed25519_chained(
            "vouch",
            alloc::vec![0xA2],
            id.id.to_urn(),
            &id.signing_key,
            2,
            h1.clone(),
        )
        .unwrap();
        assert_eq!(e2.prev_hash, h1);
        assert!(e1.verify().is_ok());
        assert!(e2.verify().is_ok());
    }

    /// L-12: flipping a bit in entry 1 changes its `chain_hash`, so
    /// entry 2's `prev_hash` no longer matches — chain break is
    /// detectable by a verifier walking the log.
    #[test]
    fn audit_entry_chain_break_detectable() {
        let id = Identity::generate("audit", &mut OsRng);
        let mut e1 = AuditLogEntry::sign_ed25519(
            "attest",
            alloc::vec![0xA1],
            id.id.to_urn(),
            &id.signing_key,
            1,
        )
        .unwrap();
        let h1_before = e1.chain_hash().unwrap();
        // Tamper with entry 1 — this also invalidates its signature.
        e1.action = "burn".into();
        assert!(e1.verify().is_err());
        let h1_after = e1.chain_hash().unwrap();
        assert_ne!(h1_before, h1_after);
    }

    #[test]
    fn audit_entry_rejects_mismatched_urn() {
        let id1 = Identity::generate("a", &mut OsRng);
        let id2 = Identity::generate("b", &mut OsRng);
        let mut entry = AuditLogEntry::sign_ed25519(
            "attest",
            alloc::vec![0xA0],
            id1.id.to_urn(),
            &id1.signing_key,
            1234,
        )
        .unwrap();
        // Substitute another identity's URN — pubkey no longer binds to URN.
        entry.node_urn = id2.id.to_urn();
        assert_eq!(entry.verify(), Err(AuditError::UrnKeyBindingMismatch));
    }
}
