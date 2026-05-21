//! Admission [`KeyProvider`] backends for `dds-node`.
//!
//! Phase A1 ships the `SoftwareKeyfile` backend only.
//! TPM 2.0 (Phase A3) and Apple Secure Enclave (Phase A4) follow.
//!
//! See `docs/hardware-bound-admission-plan.md` §7 for the per-backend spec.

use std::path::Path;

use dds_core::key_provider::{AdmissionPublicKey, KeyProvider, ProviderKind, SignError};
use sha2::{Digest, Sha256};

/// Software Ed25519 admission key stored on disk — dev/CI fallback.
///
/// Wraps [`crate::p2p_identity`]'s load/create path for a separate
/// `admission_key.bin` file. The on-disk format is identical to
/// `p2p_key.bin` (CBOR, v=1 plain or v=3 ChaCha20-Poly1305 + Argon2id
/// using the same `DDS_NODE_PASSPHRASE`). Logs a WARN on every
/// construction — hardware backends are preferred for production.
///
/// See `docs/hardware-bound-admission-plan.md` §7.1.
pub struct SoftwareKeyfile {
    signing_key: ed25519_dalek::SigningKey,
    handle: String,
}

impl SoftwareKeyfile {
    /// Load or create an Ed25519 admission key at `path`.
    ///
    /// Creates `admission_key.bin` when absent; reuses it when present.
    /// Always logs a startup WARN — hardware backend is preferred for
    /// production nodes.
    pub fn load_or_create(path: &Path) -> Result<Self, crate::p2p_identity::P2pIdentityError> {
        let kp = crate::p2p_identity::load_or_create(path)?;

        let signing_key = kp
            .try_into_ed25519()
            .ok()
            .and_then(|ed| {
                let binding = ed.secret();
                let secret_slice = binding.as_ref();
                let bytes: &[u8; 32] = secret_slice.try_into().ok()?;
                Some(ed25519_dalek::SigningKey::from_bytes(bytes))
            })
            .ok_or_else(|| {
                crate::p2p_identity::P2pIdentityError::Libp2p(
                    "admission key is not Ed25519".to_string(),
                )
            })?;

        // Stable handle: SHA-256 of the path string (not a secret).
        let handle = hex::encode(Sha256::digest(path.display().to_string().as_bytes()));

        tracing::warn!(
            path = %path.display(),
            "admission key is software-resident; hardware backend (TPM 2.0 or \
             Apple Secure Enclave) is recommended for production — see \
             docs/hardware-bound-admission-plan.md §7"
        );

        Ok(Self {
            signing_key,
            handle,
        })
    }
}

impl KeyProvider for SoftwareKeyfile {
    fn provider_kind(&self) -> ProviderKind {
        ProviderKind::SoftwareKeyfile
    }

    fn public_key(&self) -> AdmissionPublicKey {
        AdmissionPublicKey::Ed25519(self.signing_key.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    fn identity_handle(&self) -> String {
        self.handle.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_store::{PASSPHRASE_ENV, PASSPHRASE_ENV_LOCK};
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    #[test]
    fn software_keyfile_stable_across_loads() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admission_key.bin");

        let kp1 = SoftwareKeyfile::load_or_create(&path).unwrap();
        let pubkey1 = match kp1.public_key() {
            AdmissionPublicKey::Ed25519(b) => b,
            _ => panic!("expected Ed25519"),
        };

        let kp2 = SoftwareKeyfile::load_or_create(&path).unwrap();
        let pubkey2 = match kp2.public_key() {
            AdmissionPublicKey::Ed25519(b) => b,
            _ => panic!("expected Ed25519"),
        };

        assert_eq!(
            pubkey1, pubkey2,
            "admission key must be stable across loads"
        );
    }

    #[test]
    fn software_keyfile_sign_verify() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admission_key.bin");
        let kp = SoftwareKeyfile::load_or_create(&path).unwrap();

        let msg = b"h12-challenge-nonce-12345678901234";
        let sig_bytes = kp.sign(msg).unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature is 64 bytes");

        let pubkey_bytes = match kp.public_key() {
            AdmissionPublicKey::Ed25519(b) => b,
            _ => panic!("expected Ed25519"),
        };
        let arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        verifying_key.verify(msg, &sig).unwrap();
    }

    #[test]
    fn provider_kind_is_software() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admission_key.bin");
        let kp = SoftwareKeyfile::load_or_create(&path).unwrap();
        assert_eq!(kp.provider_kind(), ProviderKind::SoftwareKeyfile);
    }

    #[test]
    fn identity_handle_is_deterministic() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admission_key.bin");
        let kp1 = SoftwareKeyfile::load_or_create(&path).unwrap();
        let kp2 = SoftwareKeyfile::load_or_create(&path).unwrap();
        assert_eq!(kp1.identity_handle(), kp2.identity_handle());
        // Handle is a 64-char hex string (SHA-256).
        assert_eq!(kp1.identity_handle().len(), 64);
    }
}
