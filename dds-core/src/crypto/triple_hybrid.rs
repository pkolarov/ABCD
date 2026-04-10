//! Triple-Hybrid Ed25519 + ECDSA-P256 + ML-DSA-65 signing scheme.

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
        bytes.extend_from_slice(self.p256_key.verifying_key().to_encoded_point(false).as_bytes());
        bytes.extend_from_slice(self.pq_pk.as_bytes());
        PublicKeyBundle {
            scheme: SchemeId::TripleHybridEdEcdsaMldsa65,
            bytes,
        }
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
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

pub fn verify_triple_hybrid(
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

    let pq_pk = mldsa65::PublicKey::from_bytes(pq_pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let pq_sig = mldsa65::DetachedSignature::from_bytes(pq_sig_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;
    mldsa65::verify_detached_signature(&pq_sig, message, &pq_pk)
        .map_err(|_| CryptoError::InvalidSignature)?;

    Ok(())
}
