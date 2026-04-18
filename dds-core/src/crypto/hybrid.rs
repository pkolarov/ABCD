//! Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signing scheme.
//!
//! Both classical and post-quantum signatures are produced and
//! both must verify for a signature to be accepted. This provides:
//! - Immediate quantum resistance via ML-DSA-65
//! - Backward auditability via Ed25519
//! - Defence-in-depth: compromise of either scheme alone is insufficient
//!
//! Key/signature sizes:
//! - Public key: 32 (Ed25519) + 1,952 (ML-DSA-65) = 1,984 bytes
//! - Signature: 64 (Ed25519) + 3,309 (ML-DSA-65) = 3,373 bytes
//!
//! **M-2 (security review)** — `sign_v2` / `verify_hybrid_v2`
//! domain-separate the two component signatures with scheme-specific
//! null-terminated prefixes so neither component signature can be
//! cleanly lifted out of the hybrid and presented as a standalone
//! signature over the same message. v1 variants (no prefixes) are
//! kept so tests can pin pre-v2 bytes; new signers use v2.

use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey};

use super::traits::*;

/// Sizes for the hybrid key/signature format.
const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_SIG_LEN: usize = 3309;

/// **M-2** — scheme-specific domain prefix for the Ed25519
/// component of a v2 hybrid signature. Null-terminated so a longer
/// tag cannot be confused with a shorter one.
pub(crate) const ED_PREFIX_V2: &[u8] = b"dds-hybrid-v2/ed25519\x00";
/// **M-2** — scheme-specific domain prefix for the ML-DSA-65
/// component of a v2 hybrid signature.
pub(crate) const PQ_PREFIX_V2: &[u8] = b"dds-hybrid-v2/mldsa65\x00";

fn prefixed(prefix: &'static [u8], msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + msg.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(msg);
    out
}

/// Hybrid signing key: Ed25519 + ML-DSA-65.
pub struct HybridEdMldsa {
    ed_key: EdSigningKey,
    pq_sk: mldsa65::SecretKey,
    pq_pk: mldsa65::PublicKey,
}

impl HybridEdMldsa {
    /// Generate a new hybrid keypair.
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        let ed_key = EdSigningKey::generate(rng);
        let (pq_pk, pq_sk) = mldsa65::keypair();
        Self {
            ed_key,
            pq_sk,
            pq_pk,
        }
    }

    /// Get the composite public key bundle (Ed25519 ∥ ML-DSA-65).
    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        let mut bytes = Vec::with_capacity(ED25519_PK_LEN + MLDSA65_PK_LEN);
        bytes.extend_from_slice(&self.ed_key.verifying_key().to_bytes());
        bytes.extend_from_slice(self.pq_pk.as_bytes());
        PublicKeyBundle {
            scheme: SchemeId::HybridEdMldsa65,
            bytes,
        }
    }

    /// Sign a message with both schemes **without** domain
    /// separation. Pre-M-2 behaviour; kept so tests can pin legacy
    /// bytes.
    #[doc(hidden)]
    pub fn sign_v1(&self, message: &[u8]) -> SignatureBundle {
        let ed_sig = self.ed_key.sign(message);
        let pq_sig = mldsa65::detached_sign(message, &self.pq_sk);

        let mut bytes = Vec::with_capacity(ED25519_SIG_LEN + MLDSA65_SIG_LEN);
        bytes.extend_from_slice(&ed_sig.to_bytes());
        bytes.extend_from_slice(pq_sig.as_bytes());
        SignatureBundle {
            scheme: SchemeId::HybridEdMldsa65,
            bytes,
        }
    }

    /// Sign a message at v2 — each component signs its own
    /// scheme-prefixed message (M-2).
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        self.sign_v2(message)
    }

    /// Explicit v2 signer; `sign` is an alias for readability.
    pub fn sign_v2(&self, message: &[u8]) -> SignatureBundle {
        let ed_msg = prefixed(ED_PREFIX_V2, message);
        let pq_msg = prefixed(PQ_PREFIX_V2, message);
        let ed_sig = self.ed_key.sign(&ed_msg);
        let pq_sig = mldsa65::detached_sign(&pq_msg, &self.pq_sk);

        let mut bytes = Vec::with_capacity(ED25519_SIG_LEN + MLDSA65_SIG_LEN);
        bytes.extend_from_slice(&ed_sig.to_bytes());
        bytes.extend_from_slice(pq_sig.as_bytes());
        SignatureBundle {
            scheme: SchemeId::HybridEdMldsa65,
            bytes,
        }
    }

    /// Get the raw Ed25519 signing key (for backward compatibility).
    pub fn ed25519_signing_key(&self) -> &EdSigningKey {
        &self.ed_key
    }
}

/// Verify a hybrid signature at v2: each component is verified
/// against its scheme-prefixed message (M-2).
pub fn verify_hybrid(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    verify_hybrid_v2(public_key_bytes, message, signature_bytes)
}

/// Explicit v2 verifier (alias of [`verify_hybrid`]).
pub fn verify_hybrid_v2(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    if public_key_bytes.len() != ED25519_PK_LEN + MLDSA65_PK_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (ed_pk_bytes, pq_pk_bytes) = public_key_bytes.split_at(ED25519_PK_LEN);

    if signature_bytes.len() != ED25519_SIG_LEN + MLDSA65_SIG_LEN {
        return Err(CryptoError::InvalidSignature);
    }
    let (ed_sig_bytes, pq_sig_bytes) = signature_bytes.split_at(ED25519_SIG_LEN);

    let ed_msg = prefixed(ED_PREFIX_V2, message);
    let pq_msg = prefixed(PQ_PREFIX_V2, message);
    super::classical::verify_ed25519(ed_pk_bytes, &ed_msg, ed_sig_bytes)?;
    let pq_pk =
        mldsa65::PublicKey::from_bytes(pq_pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let pq_sig = mldsa65::DetachedSignature::from_bytes(pq_sig_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    mldsa65::verify_detached_signature(&pq_sig, &pq_msg, &pq_pk)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

/// Pre-M-2 hybrid verifier — kept so tests can pin legacy bytes.
#[doc(hidden)]
pub fn verify_hybrid_v1(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    if public_key_bytes.len() != ED25519_PK_LEN + MLDSA65_PK_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (ed_pk_bytes, pq_pk_bytes) = public_key_bytes.split_at(ED25519_PK_LEN);
    if signature_bytes.len() != ED25519_SIG_LEN + MLDSA65_SIG_LEN {
        return Err(CryptoError::InvalidSignature);
    }
    let (ed_sig_bytes, pq_sig_bytes) = signature_bytes.split_at(ED25519_SIG_LEN);
    super::classical::verify_ed25519(ed_pk_bytes, message, ed_sig_bytes)?;
    let pq_pk =
        mldsa65::PublicKey::from_bytes(pq_pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let pq_sig = mldsa65::DetachedSignature::from_bytes(pq_sig_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    mldsa65::verify_detached_signature(&pq_sig, message, &pq_pk)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_hybrid_generate_sign_verify() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let msg = b"quantum-safe hello";
        let sig = key.sign(msg);
        let pk = key.public_key_bundle();

        assert_eq!(pk.scheme, SchemeId::HybridEdMldsa65);
        assert_eq!(pk.bytes.len(), ED25519_PK_LEN + MLDSA65_PK_LEN);
        assert_eq!(sig.scheme, SchemeId::HybridEdMldsa65);
        assert_eq!(sig.bytes.len(), ED25519_SIG_LEN + MLDSA65_SIG_LEN);

        assert!(super::super::traits::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_wrong_message_fails() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let sig = key.sign(b"correct");
        let pk = key.public_key_bundle();
        assert!(super::super::traits::verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_hybrid_wrong_key_fails() {
        let key1 = HybridEdMldsa::generate(&mut OsRng);
        let key2 = HybridEdMldsa::generate(&mut OsRng);
        let sig = key1.sign(b"msg");
        let pk2 = key2.public_key_bundle();
        assert!(super::super::traits::verify(&pk2, b"msg", &sig).is_err());
    }

    #[test]
    fn test_hybrid_truncated_signature_fails() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let mut sig = key.sign(b"msg");
        sig.bytes.truncate(ED25519_SIG_LEN);
        let pk = key.public_key_bundle();
        assert_eq!(
            super::super::traits::verify(&pk, b"msg", &sig),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn test_hybrid_truncated_pubkey_fails() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let sig = key.sign(b"msg");
        let mut pk = key.public_key_bundle();
        pk.bytes.truncate(ED25519_PK_LEN);
        assert_eq!(
            super::super::traits::verify(&pk, b"msg", &sig),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn test_hybrid_key_sizes() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let pk = key.public_key_bundle();
        let sig = key.sign(b"test");
        assert_eq!(pk.bytes.len(), 1984); // 32 + 1952
        assert_eq!(sig.bytes.len(), 3373); // 64 + 3309
    }

    /// **M-2 (security review)**: the Ed25519 component of a v2
    /// hybrid signature is NOT a valid standalone signature over
    /// the original message — each component signs its own
    /// scheme-prefixed message, so the component cannot be lifted
    /// out of the hybrid and presented as a classical Ed25519
    /// signature. This regression-tests that M-2's domain
    /// separation is actually in effect.
    #[test]
    fn v2_hybrid_component_is_not_standalone_valid() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let msg = b"standalone-check";
        let sig = key.sign(msg);
        let pk = key.public_key_bundle();

        let ed_pk = &pk.bytes[..ED25519_PK_LEN];
        let ed_sig = &sig.bytes[..ED25519_SIG_LEN];
        // Direct verify against the original message must FAIL.
        assert!(super::super::classical::verify_ed25519(ed_pk, msg, ed_sig).is_err());
        // But verify against the domain-separated input must succeed.
        let ed_msg = prefixed(ED_PREFIX_V2, msg);
        assert!(super::super::classical::verify_ed25519(ed_pk, &ed_msg, ed_sig).is_ok());
    }

    /// Legacy v1 sign/verify round-trip still works — needed for
    /// tests that pin pre-M-2 byte-exact test vectors.
    #[test]
    fn v1_legacy_sign_verify_roundtrip() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let msg = b"legacy-path";
        let sig = key.sign_v1(msg);
        let pk = key.public_key_bundle();
        assert!(verify_hybrid_v1(&pk.bytes, msg, &sig.bytes).is_ok());
    }

    /// v1 and v2 signatures are NOT interchangeable: a v1 signature
    /// must fail under v2 verify (and vice versa).
    #[test]
    fn v1_and_v2_hybrid_signatures_are_not_interchangeable() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let msg = b"cross-version";
        let pk = key.public_key_bundle();
        let v1_sig = key.sign_v1(msg);
        let v2_sig = key.sign(msg);
        assert!(verify_hybrid_v2(&pk.bytes, msg, &v1_sig.bytes).is_err());
        assert!(verify_hybrid_v1(&pk.bytes, msg, &v2_sig.bytes).is_err());
    }
}
