//! ECDSA P-256 signing scheme.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::traits::*;

/// ECDSA P-256 signing key.
pub struct EcdsaP256Only {
    signing_key: SigningKey,
}

impl EcdsaP256Only {
    /// Generate a new ECDSA P-256 keypair.
    pub fn generate<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            signing_key: SigningKey::random(rng),
        }
    }

    /// Reconstruct from raw secret key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let signing_key =
            SigningKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { signing_key })
    }

    /// Get the public key bundle.
    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        let verifying_key = self.signing_key.verifying_key();
        // Use compressed SEC1 encoding (33 bytes) or uncompressed (65 bytes).
        // We'll use uncompressed to be safe, or just let to_sec1_bytes default.
        // to_sec1_bytes() on VerifyingKey returns compressed if the key was compressed,
        // but default is uncompressed usually. Let's use uncompressed explicit:
        let bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        PublicKeyBundle {
            scheme: SchemeId::EcdsaP256,
            bytes,
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        let sig: Signature = self.signing_key.sign(message);
        SignatureBundle {
            scheme: SchemeId::EcdsaP256,
            bytes: sig.to_bytes().to_vec(),
        }
    }
}

/// Verify an ECDSA P-256 signature (standalone function for trait dispatch).
pub fn verify_ecdsa_p256(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_slice(signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_sign_verify() {
        let key = EcdsaP256Only::generate(&mut OsRng);
        let msg = b"hello world";
        let sig = key.sign(msg);
        let pk = key.public_key_bundle();

        assert_eq!(pk.scheme, SchemeId::EcdsaP256);
        assert_eq!(sig.scheme, SchemeId::EcdsaP256);

        assert!(verify(&pk, msg, &sig).is_ok());
    }
}
