//! Classical Ed25519 signing scheme.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::traits::*;

/// Classical Ed25519 signing key.
pub struct Ed25519Only {
    signing_key: SigningKey,
}

impl Ed25519Only {
    /// Generate a new Ed25519 keypair.
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            signing_key: SigningKey::generate(rng),
        }
    }

    /// Reconstruct from raw secret key bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Get the public key bundle.
    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: self.signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        let sig = self.signing_key.sign(message);
        SignatureBundle {
            scheme: SchemeId::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        }
    }

    /// Get the raw Ed25519 signing key (for backward compatibility).
    pub fn ed25519_signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the raw Ed25519 verifying key.
    pub fn ed25519_verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Verify an Ed25519 signature (standalone function for trait dispatch).
pub fn verify_ed25519(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let pk_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;

    let vk = VerifyingKey::from_bytes(&pk_array).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(&sig_array);
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_sign_verify() {
        let key = Ed25519Only::generate(&mut OsRng);
        let msg = b"hello world";
        let sig = key.sign(msg);
        let pk = key.public_key_bundle();

        assert_eq!(pk.scheme, SchemeId::Ed25519);
        assert_eq!(pk.bytes.len(), 32);
        assert_eq!(sig.scheme, SchemeId::Ed25519);
        assert_eq!(sig.bytes.len(), 64);

        assert!(verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let key = Ed25519Only::generate(&mut OsRng);
        let sig = key.sign(b"correct");
        let pk = key.public_key_bundle();
        assert!(verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Ed25519Only::generate(&mut OsRng);
        let key2 = Ed25519Only::generate(&mut OsRng);
        let sig = key1.sign(b"msg");
        let pk2 = key2.public_key_bundle();
        assert!(verify(&pk2, b"msg", &sig).is_err());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let key = Ed25519Only::generate(&mut OsRng);
        let bytes = key.ed25519_signing_key().to_bytes();
        let restored = Ed25519Only::from_bytes(&bytes);
        assert_eq!(
            key.public_key_bundle().bytes,
            restored.public_key_bundle().bytes
        );
    }

    #[test]
    fn test_scheme_mismatch() {
        let key = Ed25519Only::generate(&mut OsRng);
        let mut sig = key.sign(b"msg");
        sig.scheme = SchemeId::HybridEdMldsa65; // mismatch
        let pk = key.public_key_bundle();
        assert_eq!(verify(&pk, b"msg", &sig), Err(CryptoError::SchemeMismatch));
    }
}
