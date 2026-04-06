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

    /// Sign a message with both schemes (Ed25519 ∥ ML-DSA-65).
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
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

    /// Get the raw Ed25519 signing key (for backward compatibility).
    pub fn ed25519_signing_key(&self) -> &EdSigningKey {
        &self.ed_key
    }
}

/// Verify a hybrid signature: both Ed25519 AND ML-DSA-65 must pass.
pub fn verify_hybrid(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    // Split composite public key
    if public_key_bytes.len() != ED25519_PK_LEN + MLDSA65_PK_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (ed_pk_bytes, pq_pk_bytes) = public_key_bytes.split_at(ED25519_PK_LEN);

    // Split composite signature
    if signature_bytes.len() != ED25519_SIG_LEN + MLDSA65_SIG_LEN {
        return Err(CryptoError::InvalidSignature);
    }
    let (ed_sig_bytes, pq_sig_bytes) = signature_bytes.split_at(ED25519_SIG_LEN);

    // Verify Ed25519
    super::classical::verify_ed25519(ed_pk_bytes, message, ed_sig_bytes)?;

    // Verify ML-DSA-65
    let pq_pk = mldsa65::PublicKey::from_bytes(pq_pk_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
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
        assert_eq!(pk.bytes.len(), 1984);  // 32 + 1952
        assert_eq!(sig.bytes.len(), 3373); // 64 + 3309
    }

    #[test]
    fn test_hybrid_ed25519_standalone_verifiable() {
        let key = HybridEdMldsa::generate(&mut OsRng);
        let msg = b"standalone-check";
        let sig = key.sign(msg);
        let pk = key.public_key_bundle();

        let ed_pk = &pk.bytes[..ED25519_PK_LEN];
        let ed_sig = &sig.bytes[..ED25519_SIG_LEN];
        assert!(super::super::classical::verify_ed25519(ed_pk, msg, ed_sig).is_ok());
    }
}
