//! Vouchsafe identity generation and key handling.
//!
//! Provides self-verifying identity URNs of the form:
//! `urn:vouchsafe:<label>.<base32-sha256-of-public-key>`

use alloc::string::String;
use alloc::format;
use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The URN prefix for all Vouchsafe identities.
const URN_PREFIX: &str = "urn:vouchsafe:";

/// A Vouchsafe identity consisting of a human-readable label and
/// a cryptographic hash of the Ed25519 public key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VouchsafeId {
    /// Human-readable label (e.g., "alice", "fileserver-01")
    label: String,
    /// Lowercase Base32 (no padding) of SHA-256(public_key_bytes)
    hash: String,
}

impl fmt::Debug for VouchsafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VouchsafeId({})", self.to_urn())
    }
}

impl fmt::Display for VouchsafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_urn())
    }
}

impl VouchsafeId {
    /// Derive a VouchsafeId from a label and an Ed25519 public key.
    pub fn from_verifying_key(label: &str, key: &VerifyingKey) -> Self {
        let hash = compute_key_hash(key);
        Self {
            label: String::from(label),
            hash,
        }
    }

    /// Parse a VouchsafeId from a URN string.
    ///
    /// Expected format: `urn:vouchsafe:<label>.<hash>`
    pub fn from_urn(urn: &str) -> Result<Self, IdentityError> {
        let rest = urn
            .strip_prefix(URN_PREFIX)
            .ok_or(IdentityError::InvalidUrn)?;

        let (label, hash) = rest
            .rsplit_once('.')
            .ok_or(IdentityError::InvalidUrn)?;

        if label.is_empty() || hash.is_empty() {
            return Err(IdentityError::InvalidUrn);
        }

        Ok(Self {
            label: String::from(label),
            hash: String::from(hash),
        })
    }

    /// Verify that this identity is cryptographically bound to the given public key.
    pub fn verify_binding(&self, key: &VerifyingKey) -> bool {
        let expected_hash = compute_key_hash(key);
        self.hash == expected_hash
    }

    /// Return the full URN string.
    pub fn to_urn(&self) -> String {
        format!("{}{}.{}", URN_PREFIX, self.label, self.hash)
    }

    /// Return the label portion.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the hash portion.
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// Compute the lowercase base32 (no padding) of SHA-256(public_key_bytes).
fn compute_key_hash(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &digest)
}

/// An Ed25519 keypair bundled with its derived VouchsafeId.
pub struct Identity {
    pub id: VouchsafeId,
    pub signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity with the given label.
    pub fn generate<R: rand_core::CryptoRngCore>(label: &str, rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        let verifying_key = signing_key.verifying_key();
        let id = VouchsafeId::from_verifying_key(label, &verifying_key);
        Self { id, signing_key }
    }

    /// Reconstruct an identity from an existing signing key and label.
    pub fn from_signing_key(label: &str, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let id = VouchsafeId::from_verifying_key(label, &verifying_key);
        Self { id, signing_key }
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Errors that can occur during identity operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The URN string is malformed.
    InvalidUrn,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::InvalidUrn => write!(f, "invalid Vouchsafe URN format"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_identity() {
        let ident = Identity::generate("alice", &mut OsRng);
        assert_eq!(ident.id.label(), "alice");
        assert!(!ident.id.hash().is_empty());
    }

    #[test]
    fn test_urn_roundtrip() {
        let ident = Identity::generate("bob", &mut OsRng);
        let urn = ident.id.to_urn();
        assert!(urn.starts_with("urn:vouchsafe:bob."));
        let parsed = VouchsafeId::from_urn(&urn).unwrap();
        assert_eq!(parsed, ident.id);
    }

    #[test]
    fn test_verify_binding_correct_key() {
        let ident = Identity::generate("alice", &mut OsRng);
        assert!(ident.id.verify_binding(&ident.verifying_key()));
    }

    #[test]
    fn test_verify_binding_wrong_key() {
        let ident1 = Identity::generate("alice", &mut OsRng);
        let ident2 = Identity::generate("bob", &mut OsRng);
        assert!(!ident1.id.verify_binding(&ident2.verifying_key()));
    }

    #[test]
    fn test_deterministic_id() {
        let ident = Identity::generate("alice", &mut OsRng);
        let id2 = VouchsafeId::from_verifying_key("alice", &ident.verifying_key());
        assert_eq!(ident.id, id2);
    }

    #[test]
    fn test_different_labels_different_urns() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let id1 = VouchsafeId::from_verifying_key("alice", &vk);
        let id2 = VouchsafeId::from_verifying_key("bob", &vk);
        // Same hash but different label → different URN
        assert_eq!(id1.hash(), id2.hash());
        assert_ne!(id1.to_urn(), id2.to_urn());
    }

    #[test]
    fn test_from_urn_invalid_no_prefix() {
        assert_eq!(
            VouchsafeId::from_urn("invalid:alice.hash"),
            Err(IdentityError::InvalidUrn)
        );
    }

    #[test]
    fn test_from_urn_invalid_no_dot() {
        assert_eq!(
            VouchsafeId::from_urn("urn:vouchsafe:alicehash"),
            Err(IdentityError::InvalidUrn)
        );
    }

    #[test]
    fn test_from_urn_invalid_empty_label() {
        assert_eq!(
            VouchsafeId::from_urn("urn:vouchsafe:.hash"),
            Err(IdentityError::InvalidUrn)
        );
    }

    #[test]
    fn test_from_urn_invalid_empty_hash() {
        assert_eq!(
            VouchsafeId::from_urn("urn:vouchsafe:alice."),
            Err(IdentityError::InvalidUrn)
        );
    }

    #[test]
    fn test_display_and_debug() {
        let ident = Identity::generate("test", &mut OsRng);
        let display = format!("{}", ident.id);
        let debug = format!("{:?}", ident.id);
        assert!(display.starts_with("urn:vouchsafe:test."));
        assert!(debug.starts_with("VouchsafeId(urn:vouchsafe:test."));
    }

    #[test]
    fn test_from_signing_key() {
        let key = SigningKey::generate(&mut OsRng);
        let ident = Identity::from_signing_key("svc", key.clone());
        assert_eq!(ident.id.label(), "svc");
        assert!(ident.id.verify_binding(&key.verifying_key()));
    }
}
