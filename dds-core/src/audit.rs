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
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&signed, &mut buf).map_err(|_| AuditError::Serialization)?;
        Ok(buf)
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
