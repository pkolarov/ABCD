//! Triple-Hybrid Ed25519 + ECDSA-P256 + ML-DSA-65 signing scheme.
//!
//! **M-2 (security review)** — `sign_v2` / `verify_triple_hybrid_v2`
//! domain-separate the three component signatures with
//! scheme-specific null-terminated prefixes. See [`super::hybrid`]
//! for the two-scheme variant.

use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey};

use super::traits::*;

const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const P256_PK_LEN: usize = 65; // uncompressed SEC1
const P256_SIG_LEN: usize = 64;
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_SIG_LEN: usize = 3309;

/// **M-2** — scheme-specific domain prefixes for the triple-hybrid
/// components. Null-terminated; never appear on the wire.
pub(crate) const ED_PREFIX_V2: &[u8] = b"dds-triple-v2/ed25519\x00";
pub(crate) const P256_PREFIX_V2: &[u8] = b"dds-triple-v2/p256\x00";
pub(crate) const PQ_PREFIX_V2: &[u8] = b"dds-triple-v2/mldsa65\x00";

fn prefixed(prefix: &'static [u8], msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + msg.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(msg);
    out
}

pub struct TripleHybridEdEcdsaMldsa65 {
    ed_key: EdSigningKey,
    p256_key: P256SigningKey,
    pq_sk: mldsa65::SecretKey,
    pq_pk: mldsa65::PublicKey,
}

impl TripleHybridEdEcdsaMldsa65 {
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        let ed_key = EdSigningKey::generate(rng);
        let p256_key = P256SigningKey::random(rng);
        let (pq_pk, pq_sk) = mldsa65::keypair();
        Self {
            ed_key,
            p256_key,
            pq_sk,
            pq_pk,
        }
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        let mut bytes = Vec::with_capacity(ED25519_PK_LEN + P256_PK_LEN + MLDSA65_PK_LEN);
        bytes.extend_from_slice(&self.ed_key.verifying_key().to_bytes());
        bytes.extend_from_slice(
            self.p256_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        bytes.extend_from_slice(self.pq_pk.as_bytes());
        PublicKeyBundle {
            scheme: SchemeId::TripleHybridEdEcdsaMldsa65,
            bytes,
        }
    }

    /// Sign at v2 (domain-separated per component; M-2).
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        self.sign_v2(message)
    }

    /// Explicit v2 signer.
    pub fn sign_v2(&self, message: &[u8]) -> SignatureBundle {
        let ed_msg = prefixed(ED_PREFIX_V2, message);
        let p256_msg = prefixed(P256_PREFIX_V2, message);
        let pq_msg = prefixed(PQ_PREFIX_V2, message);
        let ed_sig = self.ed_key.sign(&ed_msg);
        let p256_sig: P256Signature = self.p256_key.sign(&p256_msg);
        let pq_sig = mldsa65::detached_sign(&pq_msg, &self.pq_sk);

        let mut bytes = Vec::with_capacity(ED25519_SIG_LEN + P256_SIG_LEN + MLDSA65_SIG_LEN);
        bytes.extend_from_slice(&ed_sig.to_bytes());
        bytes.extend_from_slice(&p256_sig.to_bytes());
        bytes.extend_from_slice(pq_sig.as_bytes());
        SignatureBundle {
            scheme: SchemeId::TripleHybridEdEcdsaMldsa65,
            bytes,
        }
    }

    /// Pre-M-2 signer; kept for pinning legacy test vectors.
    #[doc(hidden)]
    pub fn sign_v1(&self, message: &[u8]) -> SignatureBundle {
        let ed_sig = self.ed_key.sign(message);
        let p256_sig: P256Signature = self.p256_key.sign(message);
        let pq_sig = mldsa65::detached_sign(message, &self.pq_sk);

        let mut bytes = Vec::with_capacity(ED25519_SIG_LEN + P256_SIG_LEN + MLDSA65_SIG_LEN);
        bytes.extend_from_slice(&ed_sig.to_bytes());
        bytes.extend_from_slice(&p256_sig.to_bytes());
        bytes.extend_from_slice(pq_sig.as_bytes());
        SignatureBundle {
            scheme: SchemeId::TripleHybridEdEcdsaMldsa65,
            bytes,
        }
    }
}

/// v2 verifier (M-2 domain-separated).
pub fn verify_triple_hybrid(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    verify_triple_hybrid_v2(public_key_bytes, message, signature_bytes)
}

/// Explicit v2 verifier.
pub fn verify_triple_hybrid_v2(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let pk_expected_len = ED25519_PK_LEN + P256_PK_LEN + MLDSA65_PK_LEN;
    if public_key_bytes.len() != pk_expected_len {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (ed_pk_bytes, rest_pk) = public_key_bytes.split_at(ED25519_PK_LEN);
    let (p256_pk_bytes, pq_pk_bytes) = rest_pk.split_at(P256_PK_LEN);

    let sig_expected_len = ED25519_SIG_LEN + P256_SIG_LEN + MLDSA65_SIG_LEN;
    if signature_bytes.len() != sig_expected_len {
        return Err(CryptoError::InvalidSignature);
    }
    let (ed_sig_bytes, rest_sig) = signature_bytes.split_at(ED25519_SIG_LEN);
    let (p256_sig_bytes, pq_sig_bytes) = rest_sig.split_at(P256_SIG_LEN);

    let ed_msg = prefixed(ED_PREFIX_V2, message);
    let p256_msg = prefixed(P256_PREFIX_V2, message);
    let pq_msg = prefixed(PQ_PREFIX_V2, message);

    super::classical::verify_ed25519(ed_pk_bytes, &ed_msg, ed_sig_bytes)?;
    super::ecdsa::verify_ecdsa_p256(p256_pk_bytes, &p256_msg, p256_sig_bytes)?;

    let pq_pk =
        mldsa65::PublicKey::from_bytes(pq_pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let pq_sig = mldsa65::DetachedSignature::from_bytes(pq_sig_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    mldsa65::verify_detached_signature(&pq_sig, &pq_msg, &pq_pk)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}

/// Pre-M-2 verifier; kept for pinning legacy test vectors.
#[doc(hidden)]
pub fn verify_triple_hybrid_v1(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let pk_expected_len = ED25519_PK_LEN + P256_PK_LEN + MLDSA65_PK_LEN;
    if public_key_bytes.len() != pk_expected_len {
        return Err(CryptoError::InvalidPublicKey);
    }
    let (ed_pk_bytes, rest_pk) = public_key_bytes.split_at(ED25519_PK_LEN);
    let (p256_pk_bytes, pq_pk_bytes) = rest_pk.split_at(P256_PK_LEN);
    let sig_expected_len = ED25519_SIG_LEN + P256_SIG_LEN + MLDSA65_SIG_LEN;
    if signature_bytes.len() != sig_expected_len {
        return Err(CryptoError::InvalidSignature);
    }
    let (ed_sig_bytes, rest_sig) = signature_bytes.split_at(ED25519_SIG_LEN);
    let (p256_sig_bytes, pq_sig_bytes) = rest_sig.split_at(P256_SIG_LEN);
    super::classical::verify_ed25519(ed_pk_bytes, message, ed_sig_bytes)?;
    super::ecdsa::verify_ecdsa_p256(p256_pk_bytes, message, p256_sig_bytes)?;
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
    fn triple_hybrid_v2_sign_verify_roundtrip() {
        let key = TripleHybridEdEcdsaMldsa65::generate(&mut OsRng);
        let pk = key.public_key_bundle();
        let sig = key.sign(b"triple-msg");
        assert!(verify_triple_hybrid(&pk.bytes, b"triple-msg", &sig.bytes).is_ok());
    }

    /// M-2: v1 and v2 triple-hybrid signatures are not cross-valid.
    #[test]
    fn triple_hybrid_v1_v2_are_not_interchangeable() {
        let key = TripleHybridEdEcdsaMldsa65::generate(&mut OsRng);
        let pk = key.public_key_bundle();
        let msg = b"triple-cross";
        let v1 = key.sign_v1(msg);
        let v2 = key.sign(msg);
        assert!(verify_triple_hybrid_v2(&pk.bytes, msg, &v1.bytes).is_err());
        assert!(verify_triple_hybrid_v1(&pk.bytes, msg, &v2.bytes).is_err());
    }

    /// M-2: each component of a v2 triple-hybrid signature signs
    /// a scheme-prefixed message, so a component cannot be lifted
    /// and verified standalone against the original message.
    #[test]
    fn triple_hybrid_v2_component_not_standalone_valid() {
        let key = TripleHybridEdEcdsaMldsa65::generate(&mut OsRng);
        let pk = key.public_key_bundle();
        let msg = b"standalone-triple";
        let sig = key.sign(msg);
        use crate::crypto::{classical, ecdsa};
        // Ed25519 component
        let ed_pk = &pk.bytes[..ED25519_PK_LEN];
        let ed_sig = &sig.bytes[..ED25519_SIG_LEN];
        assert!(classical::verify_ed25519(ed_pk, msg, ed_sig).is_err());
        // P-256 component
        let p256_pk = &pk.bytes[ED25519_PK_LEN..ED25519_PK_LEN + P256_PK_LEN];
        let p256_sig = &sig.bytes[ED25519_SIG_LEN..ED25519_SIG_LEN + P256_SIG_LEN];
        assert!(ecdsa::verify_ecdsa_p256(p256_pk, msg, p256_sig).is_err());
    }
}
