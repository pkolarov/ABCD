//! Vouchsafe identity generation and key handling.
//!
//! Provides self-verifying identity URNs of the form:
//! `urn:vouchsafe:<label>.<base32-sha256-of-public-key>`
//!
//! The hash is computed over `PublicKeyBundle.bytes`, which works for both
//! classical Ed25519 (32B) and hybrid Ed25519+ML-DSA-65 (1,984B) keys.

use alloc::format;
use alloc::string::String;
use core::fmt;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::crypto::{PublicKeyBundle, SchemeId, SignatureBundle};

/// The URN prefix for all Vouchsafe identities.
const URN_PREFIX: &str = "urn:vouchsafe:";

/// A Vouchsafe identity consisting of a human-readable label and
/// a cryptographic hash of the public key bundle.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VouchsafeId {
    /// Human-readable label (e.g., "alice", "fileserver-01")
    label: String,
    /// Lowercase Base32 (no padding) of SHA-256(public_key_bundle_bytes)
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
    /// Derive a VouchsafeId from a label and a public key bundle.
    ///
    /// Works for any scheme (Ed25519, hybrid, future PQ-only).
    pub fn from_public_key(label: &str, pk: &PublicKeyBundle) -> Self {
        let hash = compute_bundle_hash(pk);
        Self {
            label: String::from(label),
            hash,
        }
    }

    /// Derive a VouchsafeId from a label and raw Ed25519 verifying key.
    /// Convenience for FIDO2 / classical-only contexts.
    pub fn from_verifying_key(label: &str, key: &ed25519_dalek::VerifyingKey) -> Self {
        let pk = PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: key.to_bytes().to_vec(),
        };
        Self::from_public_key(label, &pk)
    }

    /// Parse a VouchsafeId from a URN string.
    ///
    /// Expected format: `urn:vouchsafe:<label>.<hash>`
    pub fn from_urn(urn: &str) -> Result<Self, IdentityError> {
        let rest = urn
            .strip_prefix(URN_PREFIX)
            .ok_or(IdentityError::InvalidUrn)?;

        let (label, hash) = rest.rsplit_once('.').ok_or(IdentityError::InvalidUrn)?;

        if label.is_empty() || hash.is_empty() {
            return Err(IdentityError::InvalidUrn);
        }

        Ok(Self {
            label: String::from(label),
            hash: String::from(hash),
        })
    }

    /// Verify that this identity is cryptographically bound to the given public key bundle.
    pub fn verify_binding_bundle(&self, pk: &PublicKeyBundle) -> bool {
        let expected_hash = compute_bundle_hash(pk);
        self.hash == expected_hash
    }

    /// Verify binding against a raw Ed25519 verifying key (backward compat).
    pub fn verify_binding(&self, key: &ed25519_dalek::VerifyingKey) -> bool {
        let pk = PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: key.to_bytes().to_vec(),
        };
        self.verify_binding_bundle(&pk)
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

/// Compute the lowercase base32 (no padding) of SHA-256(public_key_bundle_bytes).
fn compute_bundle_hash(pk: &PublicKeyBundle) -> String {
    let digest = Sha256::digest(&pk.bytes);
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &digest)
}

/// A keypair bundled with its derived VouchsafeId.
///
/// Stores the Ed25519 signing key (always present — the classical component)
/// and the public key bundle (which may be classical-only or hybrid).
pub struct Identity {
    pub id: VouchsafeId,
    /// The Ed25519 signing key (classical component, always present).
    pub signing_key: SigningKey,
    /// The full public key bundle (scheme-aware).
    pub public_key: PublicKeyBundle,
}

impl Identity {
    /// Generate a new classical (Ed25519) identity.
    pub fn generate<R: rand_core::CryptoRngCore>(label: &str, rng: &mut R) -> Self {
        let classical = crate::crypto::Ed25519Only::generate(rng);
        let public_key = classical.public_key_bundle();
        let id = VouchsafeId::from_public_key(label, &public_key);
        // L-1 (security review): move the signing key out of the
        // wrapper rather than clone it, so there's only one copy on
        // the heap.
        Self {
            id,
            signing_key: classical.into_signing_key(),
            public_key,
        }
    }

    /// Generate a new hybrid (Ed25519 + ML-DSA-65) identity.
    #[cfg(feature = "pq")]
    pub fn generate_hybrid<R: rand_core::CryptoRngCore>(
        label: &str,
        rng: &mut R,
    ) -> HybridIdentity {
        let hybrid = crate::crypto::HybridEdMldsa::generate(rng);
        let public_key = hybrid.public_key_bundle();
        let id = VouchsafeId::from_public_key(label, &public_key);
        HybridIdentity {
            id,
            hybrid_key: hybrid,
            public_key,
        }
    }

    /// Reconstruct from an existing signing key and label (classical).
    pub fn from_signing_key(label: &str, signing_key: SigningKey) -> Self {
        let public_key = PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        let id = VouchsafeId::from_public_key(label, &public_key);
        Self {
            id,
            signing_key,
            public_key,
        }
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message with the classical Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        let classical = crate::crypto::Ed25519Only::from_bytes(&self.signing_key.to_bytes());
        classical.sign(message)
    }
}

/// A hybrid identity with both classical and post-quantum keys.
#[cfg(feature = "pq")]
pub struct HybridIdentity {
    pub id: VouchsafeId,
    /// The hybrid signing key (Ed25519 + ML-DSA-65).
    pub hybrid_key: crate::crypto::HybridEdMldsa,
    /// The full public key bundle.
    pub public_key: PublicKeyBundle,
}

#[cfg(feature = "pq")]
impl HybridIdentity {
    /// Sign a message with both Ed25519 and ML-DSA-65.
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        self.hybrid_key.sign(message)
    }

    /// Get the Ed25519 signing key (for backward compat).
    pub fn ed25519_signing_key(&self) -> &SigningKey {
        self.hybrid_key.ed25519_signing_key()
    }

    /// Get the Ed25519 verifying key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.hybrid_key.ed25519_signing_key().verifying_key()
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
        assert_eq!(ident.public_key.scheme, SchemeId::Ed25519);
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
        assert!(ident.id.verify_binding_bundle(&ident.public_key));
    }

    #[test]
    fn test_verify_binding_wrong_key() {
        let ident1 = Identity::generate("alice", &mut OsRng);
        let ident2 = Identity::generate("bob", &mut OsRng);
        assert!(!ident1.id.verify_binding(&ident2.verifying_key()));
        assert!(!ident1.id.verify_binding_bundle(&ident2.public_key));
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

    #[test]
    fn test_sign_with_identity() {
        let ident = Identity::generate("alice", &mut OsRng);
        let sig = ident.sign(b"hello");
        assert_eq!(sig.scheme, SchemeId::Ed25519);
        assert!(crate::crypto::verify(&ident.public_key, b"hello", &sig).is_ok());
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_hybrid_identity() {
        let hybrid = Identity::generate_hybrid("quantum-alice", &mut OsRng);
        assert_eq!(hybrid.public_key.scheme, SchemeId::HybridEdMldsa65);
        assert_eq!(hybrid.id.label(), "quantum-alice");

        let sig = hybrid.sign(b"post-quantum message");
        assert_eq!(sig.scheme, SchemeId::HybridEdMldsa65);
        assert!(crate::crypto::verify(&hybrid.public_key, b"post-quantum message", &sig).is_ok());

        // Verify binding
        assert!(hybrid.id.verify_binding_bundle(&hybrid.public_key));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_hybrid_and_classical_different_ids() {
        let classical = Identity::generate("alice", &mut OsRng);
        let hybrid = Identity::generate_hybrid("alice", &mut OsRng);
        // Different schemes produce different hashes even with same label
        assert_ne!(classical.id, hybrid.id);
    }
}
