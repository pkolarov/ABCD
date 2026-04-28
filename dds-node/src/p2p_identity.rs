//! Persistent libp2p identity for the node.
//!
//! The libp2p `Keypair` is loaded from disk if present, otherwise generated
//! and persisted. The on-disk format is the libp2p protobuf encoding,
//! optionally wrapped with ChaCha20-Poly1305 + Argon2id when the
//! `DDS_NODE_PASSPHRASE` environment variable is set (same passphrase as
//! the dds-core identity store, since they typically belong to the same
//! operator). Without this file, the node's `PeerId` would change on every
//! restart, which would invalidate its admission certificate.
//!
//! File format (CBOR map):
//! ```text
//! {
//!   "v":      u8,          // 1=plain, 2=argon2id(legacy), 3=argon2id+params-in-blob
//!   "salt":   bytes(16)?,  // v>=2
//!   "nonce":  bytes(12)?,  // v>=2
//!   "m_cost": u32?,        // v=3 (Argon2id memory, KiB)
//!   "t_cost": u32?,        // v=3 (Argon2id iterations)
//!   "p_cost": u32?,        // v=3 (Argon2id lanes)
//!   "key":    bytes,       // libp2p protobuf (v=1) or ciphertext (v>=2)
//! }
//! ```
//!
//! **A-5 (security review, 2026-04-24)**: this module mirrors the
//! hardening applied to [`crate::identity_store`]:
//! - L-2 — `O_NOFOLLOW` on Unix reads so a sibling-symlink attacker
//!   cannot redirect the load.
//! - L-3 — atomic write via `tempfile::NamedTempFile::persist` so a
//!   crash mid-write cannot leave a torn key blob, and permissions are
//!   set on the tempfile before the rename so the final file is never
//!   observably world-readable.
//! - L-4 — parent directory tightened to `0o700` on Unix at create.
//! - M-10 — v=3 Argon2id parameters at OWASP tier 2
//!   (m=64 MiB, t=3, p=4) embedded in the blob, with lazy rewrap of
//!   pre-existing v=2 blobs on next successful load.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value as CborValue;
use libp2p::identity::Keypair;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::identity_store::{PASSPHRASE_ENV, REQUIRE_ENCRYPTED_KEYS_ENV, require_encrypted_keys};

const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;
/// **M-10**: v=3 carries Argon2id parameters in the blob and uses
/// OWASP second-tier defaults (m=64 MiB, t=3, p=4).
const VERSION_ENCRYPTED_V3: u8 = 3;

/// Legacy v=2 Argon2id parameters, retained for backward-compatible
/// decryption of pre-A-5 blobs during the lazy-rewrap window.
const V2_M_COST_KIB: u32 = 19 * 1024;
const V2_T_COST: u32 = 2;
const V2_P_COST: u32 = 1;

/// **M-10** — v=3 Argon2id parameters. OWASP's second tier for
/// interactive unlock. Chosen to match `identity_store` exactly so the
/// two stores have a single observable security level.
const V3_M_COST_KIB: u32 = 64 * 1024;
const V3_T_COST: u32 = 3;
const V3_P_COST: u32 = 4;

/// Argon2id parameters read from / written to the v=3 blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    const V2: Self = Self {
        m_cost_kib: V2_M_COST_KIB,
        t_cost: V2_T_COST,
        p_cost: V2_P_COST,
    };
    const V3: Self = Self {
        m_cost_kib: V3_M_COST_KIB,
        t_cost: V3_T_COST,
        p_cost: V3_P_COST,
    };
}

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
        // L-4: tighten parent directory perms (matches identity_store).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut proto = kp
        .to_protobuf_encoding()
        .map_err(|e| P2pIdentityError::Libp2p(e.to_string()))?;

    // H-9 hygiene: passphrase wrapped in `Zeroizing` so it's wiped on
    // drop even on the early-error paths below.
    let passphrase = std::env::var(PASSPHRASE_ENV).map(Zeroizing::new);
    let will_be_plaintext = !matches!(&passphrase, Ok(p) if !p.is_empty());
    if will_be_plaintext && require_encrypted_keys() {
        proto.zeroize();
        return Err(P2pIdentityError::Crypto(format!(
            "refusing to write plaintext libp2p identity at {} — \
             {REQUIRE_ENCRYPTED_KEYS_ENV} is set but {PASSPHRASE_ENV} is empty. \
             Set {PASSPHRASE_ENV} to a non-empty value, or unset \
             {REQUIRE_ENCRYPTED_KEYS_ENV} on dev hosts.",
            path.display()
        )));
    }
    let map = match passphrase {
        Ok(pass) if !pass.is_empty() => {
            // M-10: emit v=3 with parameters embedded in the blob.
            let params = KdfParams::V3;
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let mut key = derive_key(pass.as_bytes(), &salt, params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), proto.as_slice())
                .map_err(|e| P2pIdentityError::Crypto(e.to_string()))?;
            key.zeroize();
            proto.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED_V3.into()),
                ),
                (
                    CborValue::Text("salt".into()),
                    CborValue::Bytes(salt.to_vec()),
                ),
                (
                    CborValue::Text("nonce".into()),
                    CborValue::Bytes(nonce_bytes.to_vec()),
                ),
                (
                    CborValue::Text("m_cost".into()),
                    CborValue::Integer(params.m_cost_kib.into()),
                ),
                (
                    CborValue::Text("t_cost".into()),
                    CborValue::Integer(params.t_cost.into()),
                ),
                (
                    CborValue::Text("p_cost".into()),
                    CborValue::Integer(params.p_cost.into()),
                ),
                (CborValue::Text("key".into()), CborValue::Bytes(ct)),
            ]
        }
        _ => {
            tracing::warn!(
                "{PASSPHRASE_ENV} not set; libp2p keypair will be stored unencrypted at {}",
                path.display()
            );
            let v = vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_PLAIN.into()),
                ),
                (
                    CborValue::Text("key".into()),
                    CborValue::Bytes(proto.clone()),
                ),
            ];
            proto.zeroize();
            v
        }
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| P2pIdentityError::Cbor(e.to_string()))?;

    // L-3: atomic write — tempfile + rename. Permissions are set on
    // the tempfile path BEFORE the rename so the final file is never
    // observably world-readable.
    let parent = path
        .parent()
        .ok_or_else(|| P2pIdentityError::Io("p2p key path has no parent".into()))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| P2pIdentityError::Io(format!("tempfile: {e}")))?;
    std::fs::write(tmp.path(), &buf)
        .map_err(|e| P2pIdentityError::Io(format!("tempfile write: {e}")))?;
    set_owner_only_permissions(tmp.path());
    tmp.persist(path)
        .map_err(|e| P2pIdentityError::Io(format!("rename: {e}")))?;
    set_owner_only_permissions(path);
    Ok(())
}

/// Best-effort: restrict file to owner-only read/write (0o600 on Unix).
fn set_owner_only_permissions(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(_path, perms);
    }
}

/// L-2: read without following symlinks on Unix. On Windows we fall
/// back to `std::fs::read` because NTFS semantics differ and parent
/// ACLs are the standard hardening mechanism.
fn read_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        std::fs::read(path)
    }
}

pub fn load(path: &Path) -> Result<Keypair, P2pIdentityError> {
    let bytes = read_no_follow(path).map_err(|e| P2pIdentityError::Io(e.to_string()))?;
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| P2pIdentityError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| P2pIdentityError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut key_field: Option<Vec<u8>> = None;
    let mut m_cost: Option<u32> = None;
    let mut t_cost: Option<u32> = None;
    let mut p_cost: Option<u32> = None;
    for (k, v) in map.iter() {
        if let Some(name) = k.as_text() {
            match name {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                "m_cost" => m_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                "t_cost" => t_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                "p_cost" => p_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                _ => {}
            }
        }
    }
    let key_field = key_field.ok_or_else(|| P2pIdentityError::Format("missing key".into()))?;

    let mut rewrap_v2_to_v3 = false;
    let mut proto = match version {
        Some(v) if v == VERSION_PLAIN as i64 => key_field,
        Some(v) if v == VERSION_ENCRYPTED as i64 || v == VERSION_ENCRYPTED_V3 as i64 => {
            // H-9 hygiene: passphrase wiped on drop.
            let pass = Zeroizing::new(std::env::var(PASSPHRASE_ENV).map_err(|_| {
                P2pIdentityError::Crypto(format!(
                    "p2p key is encrypted but {PASSPHRASE_ENV} is not set"
                ))
            })?);
            let salt = salt.ok_or_else(|| P2pIdentityError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| P2pIdentityError::Format("missing nonce".into()))?;
            let params = if v == VERSION_ENCRYPTED as i64 {
                rewrap_v2_to_v3 = true;
                KdfParams::V2
            } else {
                let m =
                    m_cost.ok_or_else(|| P2pIdentityError::Format("v=3 missing m_cost".into()))?;
                let t =
                    t_cost.ok_or_else(|| P2pIdentityError::Format("v=3 missing t_cost".into()))?;
                let p =
                    p_cost.ok_or_else(|| P2pIdentityError::Format("v=3 missing p_cost".into()))?;
                KdfParams {
                    m_cost_kib: m,
                    t_cost: t,
                    p_cost: p,
                }
            };
            let mut key = derive_key(pass.as_bytes(), &salt, params)?;
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

    let kp = Keypair::from_protobuf_encoding(&proto)
        .map_err(|e| P2pIdentityError::Libp2p(e.to_string()))?;
    proto.zeroize();

    // M-10: lazy rewrap. If the on-disk blob was v=2 and we successfully
    // decrypted, re-save under v=3 (tier-2 Argon2 + embedded params).
    // Identity (PeerId) is preserved; only the on-disk KDF parameters
    // change. Failures are logged and swallowed — the caller has the
    // keypair and a future save will migrate.
    if rewrap_v2_to_v3 {
        match save(path, &kp) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    "M-10: p2p keypair rewrapped v=2 -> v=3 Argon2id (m=64MiB, t=3, p=4)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "M-10: v=2 decrypt succeeded but lazy rewrap failed; \
                     keypair will be used but remains on v=2 on disk"
                );
            }
        }
    }

    Ok(kp)
}

fn derive_key(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<[u8; 32], P2pIdentityError> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
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

    /// **A-5 / M-10**: new saves use the v=3 schema with Argon2id
    /// parameters embedded in the blob.
    #[test]
    fn save_writes_v3_with_embedded_params() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(PASSPHRASE_ENV, "unit-test-a5") };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p2p_key.bin");
        let _ = load_or_create(&path).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let map = value.as_map().unwrap();
        let mut v: Option<i64> = None;
        let mut m: Option<u32> = None;
        let mut t: Option<u32> = None;
        let mut p: Option<u32> = None;
        for (k, val) in map {
            match k.as_text().unwrap_or("") {
                "v" => v = val.as_integer().and_then(|i| i64::try_from(i).ok()),
                "m_cost" => m = val.as_integer().and_then(|i| u32::try_from(i).ok()),
                "t_cost" => t = val.as_integer().and_then(|i| u32::try_from(i).ok()),
                "p_cost" => p = val.as_integer().and_then(|i| u32::try_from(i).ok()),
                _ => {}
            }
        }
        assert_eq!(v, Some(VERSION_ENCRYPTED_V3 as i64));
        assert_eq!(m, Some(V3_M_COST_KIB));
        assert_eq!(t, Some(V3_T_COST));
        assert_eq!(p, Some(V3_P_COST));
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    }

    /// **A-5 / M-10**: a blob written under legacy v=2 params is
    /// transparently rewrapped to v=3 on the next successful load.
    /// PeerId is preserved.
    #[test]
    fn lazy_rewrap_v2_to_v3_preserves_peer_id() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let pass = "unit-test-a5-rewrap";
        unsafe { std::env::set_var(PASSPHRASE_ENV, pass) };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p2p_key.bin");

        // Hand-craft a v=2 blob for a freshly-generated keypair.
        let kp = Keypair::generate_ed25519();
        let original_peer_id = PeerId::from(kp.public());
        let mut proto = kp.to_protobuf_encoding().unwrap();
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut k = derive_key(pass.as_bytes(), &salt, KdfParams::V2).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), proto.as_slice())
            .unwrap();
        k.zeroize();
        proto.zeroize();
        let map = vec![
            (
                CborValue::Text("v".into()),
                CborValue::Integer((VERSION_ENCRYPTED as i64).into()),
            ),
            (
                CborValue::Text("salt".into()),
                CborValue::Bytes(salt.to_vec()),
            ),
            (
                CborValue::Text("nonce".into()),
                CborValue::Bytes(nonce_bytes.to_vec()),
            ),
            (CborValue::Text("key".into()), CborValue::Bytes(ct)),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        // Load — must succeed AND trigger lazy rewrap.
        let loaded = load(&path).unwrap();
        assert_eq!(PeerId::from(loaded.public()), original_peer_id);

        // On-disk version is now v=3.
        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let map = value.as_map().unwrap();
        let v = map
            .iter()
            .find_map(|(k, val)| (k.as_text()? == "v").then(|| val.as_integer()))
            .flatten()
            .and_then(|i| i64::try_from(i).ok());
        assert_eq!(v, Some(VERSION_ENCRYPTED_V3 as i64));

        // A fresh load still returns the same PeerId.
        let again = load(&path).unwrap();
        assert_eq!(PeerId::from(again.public()), original_peer_id);

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    }

    /// **security-gaps.md remaining work #4** — when
    /// `DDS_REQUIRE_ENCRYPTED_KEYS` is set and `DDS_NODE_PASSPHRASE`
    /// is empty, `save` must refuse to write a plaintext libp2p key
    /// blob. The same call succeeds when a passphrase is set.
    #[test]
    fn save_refuses_plaintext_when_required_env_set() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        unsafe { std::env::set_var(REQUIRE_ENCRYPTED_KEYS_ENV, "1") };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p2p_key.bin");
        let kp = Keypair::generate_ed25519();
        let err = save(&path, &kp).expect_err("save must refuse plaintext");
        match err {
            P2pIdentityError::Crypto(msg) => {
                assert!(
                    msg.contains("refusing to write plaintext libp2p identity")
                        && msg.contains(REQUIRE_ENCRYPTED_KEYS_ENV),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Crypto error, got {other:?}"),
        }
        assert!(!path.exists(), "file must not be created on refusal");

        // With a passphrase set the save proceeds normally.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "p2p-require-test") };
        save(&path, &kp).expect("encrypted save must proceed under require-encrypted");
        assert!(path.exists());

        unsafe { std::env::remove_var(REQUIRE_ENCRYPTED_KEYS_ENV) };
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    }

    /// **A-5 / L-2**: a symlink at the key path must be refused on
    /// Unix loads.
    #[cfg(unix)]
    #[test]
    fn load_refuses_symlink_unix() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real_p2p.bin");
        let link = dir.path().join("p2p_key.bin");

        // Write a valid plain blob at `real`.
        let kp = Keypair::generate_ed25519();
        save(&real, &kp).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = load(&link).expect_err("symlinked load must be refused");
        match err {
            P2pIdentityError::Io(_) => {}
            other => panic!("expected Io error from O_NOFOLLOW, got {other:?}"),
        }
    }
}
