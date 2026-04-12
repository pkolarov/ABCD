//! Persistent, encrypted-at-rest node identity.
//!
//! The node Ed25519 signing key is stored on disk encrypted with
//! ChaCha20-Poly1305 using a key derived from a passphrase via Argon2id.
//! The passphrase is read from the `DDS_NODE_PASSPHRASE` environment
//! variable. If the env var is unset, the key is stored unencrypted with
//! a clearly-labelled "plain" version byte (suitable for development on a
//! trusted host but logged as a warning).
//!
//! File format (CBOR map):
//! ```text
//! {
//!   "v":     u8,            // 1 = plain, 2 = argon2id+chacha20poly1305
//!   "label": text,
//!   "salt":  bytes(16)?,    // (v=2 only)
//!   "nonce": bytes(12)?,    // (v=2 only)
//!   "key":   bytes,         // 32 raw bytes (v=1) or ciphertext (v=2)
//! }
//! ```
//!
//! Versioning is explicit so future migrations (e.g. PQ wrap, OS keyring)
//! can land without breaking existing on-disk material.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value as CborValue;
use dds_core::identity::Identity;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// Environment variable name for the optional disk-encryption passphrase.
pub const PASSPHRASE_ENV: &str = "DDS_NODE_PASSPHRASE";

#[cfg(test)]
pub(crate) static PASSPHRASE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;

/// Errors loading or saving the persistent identity.
#[derive(Debug)]
pub enum IdentityStoreError {
    Io(String),
    Cbor(String),
    Format(String),
    Crypto(String),
}

impl std::fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityStoreError::Io(e) => write!(f, "io: {e}"),
            IdentityStoreError::Cbor(e) => write!(f, "cbor: {e}"),
            IdentityStoreError::Format(e) => write!(f, "format: {e}"),
            IdentityStoreError::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for IdentityStoreError {}

/// Load an identity from `path`, or generate and persist one if missing.
pub fn load_or_create(path: &Path, label: &str) -> Result<Identity, IdentityStoreError> {
    if path.exists() {
        load(path)
    } else {
        let ident = Identity::generate(label, &mut OsRng);
        save(path, &ident)?;
        Ok(ident)
    }
}

/// Save an identity to disk, encrypting if `DDS_NODE_PASSPHRASE` is set.
pub fn save(path: &Path, ident: &Identity) -> Result<(), IdentityStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    }
    let mut key_bytes = ident.signing_key.to_bytes();
    let label = ident.id.label().to_string();

    let map = match std::env::var(PASSPHRASE_ENV) {
        Ok(pass) if !pass.is_empty() => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let mut key = derive_key(pass.as_bytes(), &salt)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), key_bytes.as_ref())
                .map_err(|e| IdentityStoreError::Crypto(e.to_string()))?;
            key.zeroize();
            key_bytes.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED.into()),
                ),
                (CborValue::Text("label".into()), CborValue::Text(label)),
                (
                    CborValue::Text("salt".into()),
                    CborValue::Bytes(salt.to_vec()),
                ),
                (
                    CborValue::Text("nonce".into()),
                    CborValue::Bytes(nonce_bytes.to_vec()),
                ),
                (CborValue::Text("key".into()), CborValue::Bytes(ct)),
            ]
        }
        _ => {
            tracing::warn!(
                "{PASSPHRASE_ENV} not set; node identity will be stored unencrypted at {}",
                path.display()
            );
            let v = vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_PLAIN.into()),
                ),
                (CborValue::Text("label".into()), CborValue::Text(label)),
                (
                    CborValue::Text("key".into()),
                    CborValue::Bytes(key_bytes.to_vec()),
                ),
            ];
            key_bytes.zeroize();
            v
        }
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| IdentityStoreError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    Ok(())
}

/// Load an identity from disk.
pub fn load(path: &Path) -> Result<Identity, IdentityStoreError> {
    let bytes = std::fs::read(path).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| IdentityStoreError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| IdentityStoreError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut label: Option<String> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut key_field: Option<Vec<u8>> = None;
    for (k, v) in map.iter() {
        if let Some(name) = k.as_text() {
            match name {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "label" => label = v.as_text().map(|s| s.to_string()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }
    let label = label.ok_or_else(|| IdentityStoreError::Format("missing label".into()))?;
    let key_field = key_field.ok_or_else(|| IdentityStoreError::Format("missing key".into()))?;

    let mut raw = match version {
        Some(v) if v == VERSION_PLAIN as i64 => {
            if key_field.len() != 32 {
                return Err(IdentityStoreError::Format("plain key wrong length".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&key_field);
            k
        }
        Some(v) if v == VERSION_ENCRYPTED as i64 => {
            let pass = std::env::var(PASSPHRASE_ENV).map_err(|_| {
                IdentityStoreError::Crypto(format!(
                    "identity is encrypted but {PASSPHRASE_ENV} is not set"
                ))
            })?;
            let salt = salt.ok_or_else(|| IdentityStoreError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| IdentityStoreError::Format("missing nonce".into()))?;
            let mut key = derive_key(pass.as_bytes(), &salt)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let mut pt = cipher
                .decrypt(Nonce::from_slice(&nonce), key_field.as_ref())
                .map_err(|e| IdentityStoreError::Crypto(format!("decrypt: {e}")))?;
            key.zeroize();
            if pt.len() != 32 {
                pt.zeroize();
                return Err(IdentityStoreError::Format(
                    "decrypted key wrong length".into(),
                ));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&pt);
            pt.zeroize();
            k
        }
        other => {
            return Err(IdentityStoreError::Format(format!(
                "unknown version {other:?}"
            )));
        }
    };

    let signing_key = SigningKey::from_bytes(&raw);
    raw.zeroize();
    Ok(Identity::from_signing_key(&label, signing_key))
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], IdentityStoreError> {
    // Modest Argon2id params: 19 MiB, 2 iterations, 1 lane.
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| IdentityStoreError::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| IdentityStoreError::Crypto(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_plain_roundtrip() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");
        let ident = load_or_create(&path, "node-a").unwrap();
        let urn = ident.id.to_urn();
        let again = load(&path).unwrap();
        assert_eq!(again.id.to_urn(), urn);
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple") };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");
        let ident = load_or_create(&path, "node-b").unwrap();
        let urn = ident.id.to_urn();
        let again = load(&path).unwrap();
        assert_eq!(again.id.to_urn(), urn);

        // Wrong passphrase fails.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "wrong passphrase") };
        let res = load(&path);
        assert!(res.is_err());

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        // Now plain-mode load of an encrypted file must error too.
        let res = load(&path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_or_create_persists_across_calls() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");
        let a = load_or_create(&path, "node").unwrap();
        let b = load_or_create(&path, "node").unwrap();
        assert_eq!(a.id.to_urn(), b.id.to_urn());
    }
}
