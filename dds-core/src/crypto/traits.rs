//! Cryptographic signing scheme traits.

use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Identifies which signing scheme produced a key or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemeId {
    /// Classical Ed25519 only.
    Ed25519,
    /// ECDSA P-256 only (for FIDO2 hardware compatibility).
    EcdsaP256,
    /// Hybrid Ed25519 + ML-DSA-65 (FIPS 204).
    HybridEdMldsa65,
    /// Triple-Hybrid Ed25519 + ECDSA-P256 + ML-DSA-65.
    TripleHybridEdEcdsaMldsa65,
}

impl fmt::Display for SchemeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemeId::Ed25519 => write!(f, "Ed25519"),
            SchemeId::EcdsaP256 => write!(f, "ECDSA-P256"),
            SchemeId::HybridEdMldsa65 => write!(f, "Ed25519+ML-DSA-65"),
            SchemeId::TripleHybridEdEcdsaMldsa65 => write!(f, "Ed25519+ECDSA-P256+ML-DSA-65"),
        }
    }
}

/// A serialized public key with its scheme identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    pub scheme: SchemeId,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// A serialized signature with its scheme identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    pub scheme: SchemeId,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// Errors from cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature verification failed.
    InvalidSignature,
    /// Public key is malformed.
    InvalidPublicKey,
    /// Scheme mismatch between key and signature.
    SchemeMismatch,
    /// The PQ feature is not enabled.
    PqNotAvailable,
    /// Key generation failure.
    KeyGenError(alloc::string::String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::InvalidPublicKey => write!(f, "invalid public key"),
            CryptoError::SchemeMismatch => write!(f, "scheme mismatch between key and signature"),
            CryptoError::PqNotAvailable => write!(f, "post-quantum feature not enabled"),
            CryptoError::KeyGenError(e) => write!(f, "key generation error: {e}"),
        }
    }
}

/// Verify a signature against a public key bundle and message — v2
/// semantics (post-M-2). Hybrid / triple-hybrid schemes expect the
/// component signatures to have been produced with the scheme-
/// specific domain prefixes.
///
/// For single-scheme signatures (Ed25519, ECDSA) there is no v1/v2
/// distinction — the function is identical to [`verify_v1`].
pub fn verify(
    public_key: &PublicKeyBundle,
    message: &[u8],
    signature: &SignatureBundle,
) -> Result<(), CryptoError> {
    if public_key.scheme != signature.scheme {
        return Err(CryptoError::SchemeMismatch);
    }
    match public_key.scheme {
        SchemeId::Ed25519 => {
            super::classical::verify_ed25519(&public_key.bytes, message, &signature.bytes)
        }
        SchemeId::EcdsaP256 => {
            super::ecdsa::verify_ecdsa_p256(&public_key.bytes, message, &signature.bytes)
        }
        #[cfg(feature = "pq")]
        SchemeId::HybridEdMldsa65 => {
            super::hybrid::verify_hybrid_v2(&public_key.bytes, message, &signature.bytes)
        }
        #[cfg(not(feature = "pq"))]
        SchemeId::HybridEdMldsa65 => Err(CryptoError::PqNotAvailable),
        #[cfg(feature = "pq")]
        SchemeId::TripleHybridEdEcdsaMldsa65 => super::triple_hybrid::verify_triple_hybrid_v2(
            &public_key.bytes,
            message,
            &signature.bytes,
        ),
        #[cfg(not(feature = "pq"))]
        SchemeId::TripleHybridEdEcdsaMldsa65 => Err(CryptoError::PqNotAvailable),
    }
}

/// **M-2 legacy path** — verify a signature produced before M-2
/// landed. Hybrid / triple-hybrid components were signed over the
/// raw message (no scheme-specific domain prefixes). Required to
/// verify persisted v=1 hybrid tokens on disk and, when the operator
/// has opted in via `allow_legacy_v1_tokens`, v=1 hybrid tokens
/// arriving from legacy peers during the cutover window.
///
/// Classical schemes (Ed25519, ECDSA) delegate to the same backend
/// as [`verify`] because they have no v1/v2 distinction.
pub fn verify_v1(
    public_key: &PublicKeyBundle,
    message: &[u8],
    signature: &SignatureBundle,
) -> Result<(), CryptoError> {
    if public_key.scheme != signature.scheme {
        return Err(CryptoError::SchemeMismatch);
    }
    match public_key.scheme {
        SchemeId::Ed25519 => {
            super::classical::verify_ed25519(&public_key.bytes, message, &signature.bytes)
        }
        SchemeId::EcdsaP256 => {
            super::ecdsa::verify_ecdsa_p256(&public_key.bytes, message, &signature.bytes)
        }
        #[cfg(feature = "pq")]
        SchemeId::HybridEdMldsa65 => {
            super::hybrid::verify_hybrid_v1(&public_key.bytes, message, &signature.bytes)
        }
        #[cfg(not(feature = "pq"))]
        SchemeId::HybridEdMldsa65 => Err(CryptoError::PqNotAvailable),
        #[cfg(feature = "pq")]
        SchemeId::TripleHybridEdEcdsaMldsa65 => super::triple_hybrid::verify_triple_hybrid_v1(
            &public_key.bytes,
            message,
            &signature.bytes,
        ),
        #[cfg(not(feature = "pq"))]
        SchemeId::TripleHybridEdEcdsaMldsa65 => Err(CryptoError::PqNotAvailable),
    }
}
