//! Persistent libp2p identity for the node.
//!
//! The libp2p `Keypair` is loaded from disk if present, otherwise generated
//! and persisted. The on-disk format is the libp2p protobuf encoding,
//! optionally wrapped with ChaCha20-Poly1305 + Argon2id when the
//! `DDS_NODE_PASSPHRASE` environment variable is set (same passphrase as
//! the dds-core identity store, since they typically belong to the same
//! operator). Without this file, the node's `PeerId` would change on every
//! restart, which would invalidate its admission certificate.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value as CborValue;
use libp2p::identity::Keypair;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::identity_store::PASSPHRASE_ENV;

const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;

#[derive(Debug)]
pub enum P2pIdentityError {
    Io(String),
    Cbor(String),
    Format(String),
    Crypto(String),
    Libp2p(String),
}

impl std::fmt::Display for P2pIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pIdentityError::Io(e) => write!(f, "io: {e}"),
            P2pIdentityError::Cbor(e) => write!(f, "cbor: {e}"),
            P2pIdentityError::Format(e) => write!(f, "format: {e}"),
            P2pIdentityError::Crypto(e) => write!(f, "crypto: {e}"),
            P2pIdentityError::Libp2p(e) => write!(f, "libp2p: {e}"),
        }
    }
}

impl std::error::Error for P2pIdentityError {}

/// Load the libp2p keypair from `path`, generating and persisting one if
/// the file does not yet exist.
pub fn load_or_create(path: &Path) -> Result<Keypair, P2pIdentityError> {
    if path.exists() {
        load(path)
    } else {
        let kp = Keypair::generate_ed25519();
        save(path, &kp)?;
        Ok(kp)
    }
}

pub fn save(path: &Path, kp: &Keypair) -> Result<(), P2pIdentityError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| P2pIdentityError::Io(e.to_string()))?;
    }
    let mut proto = kp
        .to_protobuf_encoding()
        .map_err(|e| P2pIdentityError::Libp2p(e.to_string()))?;

    let map = match std::env::var(PASSPHRASE_ENV) {
        Ok(pass) if !pass.is_empty() => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let mut key = derive_key(pass.as_bytes(), &salt)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), proto.as_slice())
                .map_err(|e| P2pIdentityError::Crypto(e.to_string()))?;
            key.zeroize();
            proto.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED.into()),
                ),
                (
                    CborValue::Text("salt".into()),
                    CborValue::Bytes(salt.to_vec()),
                ),
                (
                    CborValue::Text("nonce".into()),
                    CborValue::Bytes(nonce.to_vec()),
                ),
                (CborValue::Text("key".into()), CborValue::Bytes(ct)),
            ]
        }
        _ => {
            tracing::warn!(
                "{PASSPHRASE_ENV} not set; libp2p keypair will be stored unencrypted at {}",
                path.display()
            );
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_PLAIN.into()),
                ),
                (CborValue::Text("key".into()), CborValue::Bytes(proto)),
            ]
        }
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| P2pIdentityError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| P2pIdentityError::Io(e.to_string()))?;
    set_owner_only_permissions(path);
    Ok(())
}

/// Best-effort: restrict file to owner-only read/write (0o600 on Unix).
fn set_owner_only_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

pub fn load(path: &Path) -> Result<Keypair, P2pIdentityError> {
    let bytes = std::fs::read(path).map_err(|e| P2pIdentityError::Io(e.to_string()))?;
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| P2pIdentityError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| P2pIdentityError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut key_field: Option<Vec<u8>> = None;
    for (k, v) in map.iter() {
        if let Some(name) = k.as_text() {
            match name {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }
    let key_field = key_field.ok_or_else(|| P2pIdentityError::Format("missing key".into()))?;

    let mut proto = match version {
        Some(v) if v == VERSION_PLAIN as i64 => key_field,
        Some(v) if v == VERSION_ENCRYPTED as i64 => {
            let pass = std::env::var(PASSPHRASE_ENV).map_err(|_| {
                P2pIdentityError::Crypto(format!(
                    "p2p key is encrypted but {PASSPHRASE_ENV} is not set"
                ))
            })?;
            let salt = salt.ok_or_else(|| P2pIdentityError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| P2pIdentityError::Format("missing nonce".into()))?;
            let mut key = derive_key(pass.as_bytes(), &salt)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let pt = cipher
                .decrypt(Nonce::from_slice(&nonce), key_field.as_ref())
                .map_err(|e| P2pIdentityError::Crypto(format!("decrypt: {e}")))?;
            key.zeroize();
            pt
        }
        other => {
            return Err(P2pIdentityError::Format(format!(
                "unknown version {other:?}"
            )));
        }
    };

    let result = Keypair::from_protobuf_encoding(&proto)
        .map_err(|e| P2pIdentityError::Libp2p(e.to_string()));
    proto.zeroize();
    result
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], P2pIdentityError> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| P2pIdentityError::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| P2pIdentityError::Crypto(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_store::PASSPHRASE_ENV_LOCK;
    use libp2p::PeerId;
    use tempfile::TempDir;

    #[test]
    fn plain_roundtrip_stable_peer_id() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p2p_key.bin");
        let kp1 = load_or_create(&path).unwrap();
        let id1 = PeerId::from(kp1.public());
        let kp2 = load_or_create(&path).unwrap();
        let id2 = PeerId::from(kp2.public());
        assert_eq!(id1, id2);
    }

    #[test]
    fn encrypted_roundtrip() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(PASSPHRASE_ENV, "passphrase-x") };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p2p_key.bin");
        let kp1 = load_or_create(&path).unwrap();
        let id1 = PeerId::from(kp1.public());
        let kp2 = load(&path).unwrap();
        let id2 = PeerId::from(kp2.public());
        assert_eq!(id1, id2);

        unsafe { std::env::set_var(PASSPHRASE_ENV, "wrong") };
        assert!(load(&path).is_err());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    }
}
