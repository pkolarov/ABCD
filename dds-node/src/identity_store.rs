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
//!   "v":      u8,          // 1=plain, 2=argon2id(legacy), 3=argon2id+params-in-blob
//!   "label":  text,
//!   "salt":   bytes(16)?,  // v>=2
//!   "nonce":  bytes(12)?,  // v>=2
//!   "m_cost": u32?,        // v=3 (Argon2id memory, KiB)
//!   "t_cost": u32?,        // v=3 (Argon2id iterations)
//!   "p_cost": u32?,        // v=3 (Argon2id lanes)
//!   "key":    bytes,       // 32 raw bytes (v=1) or ciphertext (v>=2)
//! }
//! ```
//!
//! Versioning is explicit so future migrations (e.g. PQ wrap, OS keyring)
//! can land without breaking existing on-disk material. **M-10 (security
//! review)**: v=3 stores Argon2id parameters inside the blob (rather than
//! hardcoding them) so a future parameter bump does not need yet another
//! schema version. Loads of v=2 blobs transparently re-encrypt as v=3
//! (lazy rewrap) so the migration is invisible to operators.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value as CborValue;
use dds_core::identity::Identity;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

/// Environment variable name for the optional disk-encryption passphrase.
pub const PASSPHRASE_ENV: &str = "DDS_NODE_PASSPHRASE";

/// **M-14 (security review)**: escape hatch for explicit,
/// operator-acknowledged plaintext downgrade (dev/testing only).
/// Set to a non-empty value to allow `save()` to write an
/// unencrypted blob even when an encrypted marker exists.
pub const ALLOW_PLAINTEXT_DOWNGRADE_ENV: &str = "DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE";

#[cfg(test)]
pub(crate) static PASSPHRASE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;
/// **M-10 (security review)**: v=3 carries Argon2id parameters in the
/// blob and uses OWASP second-tier defaults (m=64 MiB, t=3, p=4).
const VERSION_ENCRYPTED_V3: u8 = 3;

/// Legacy v=2 Argon2id parameters, retained for backward-compatible
/// decryption of existing blobs during the lazy-rewrap window.
const V2_M_COST_KIB: u32 = 19 * 1024;
const V2_T_COST: u32 = 2;
const V2_P_COST: u32 = 1;

/// **M-10** — v=3 Argon2id parameters. OWASP's second tier for
/// interactive unlock; target unlock time ~200–500 ms on modern
/// hardware. Parameters live in the blob so a future bump is just
/// another value here + a migration step (no new `v`).
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

/// **M-14 (security review)**: path of the sticky "this node was
/// once encrypted" marker file. When present, `save()` refuses to
/// write a plaintext blob so an attacker with filesystem write
/// cannot force a silent downgrade by clearing the passphrase env
/// var. The marker is intentionally a side file (same name + suffix)
/// rather than a field inside the key blob: we must be able to
/// detect the invariant without first parsing (and thus trusting) an
/// arbitrary file an attacker may have swapped in.
fn encrypted_marker_path(key_path: &Path) -> std::path::PathBuf {
    let mut p = key_path.as_os_str().to_os_string();
    p.push(".encrypted-marker");
    std::path::PathBuf::from(p)
}

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
        // L-4 (security review): tighten parent directory perms.
        // `create_dir_all` uses the process umask (typically 0o755)
        // and leaves key files in a world-readable parent.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut key_bytes = ident.signing_key.to_bytes();
    let label = ident.id.label().to_string();

    // M-14 (security review): compute whether the caller is about to
    // produce a plaintext blob, and refuse if a previous save wrote
    // an encrypted blob. The attacker's scenario is: unset the
    // passphrase env var (or remove/corrupt the passphrase source)
    // and wait for the next save — without this gate, the key on
    // disk would silently roll back to plaintext.
    let passphrase = std::env::var(PASSPHRASE_ENV).map(Zeroizing::new);
    let will_be_plaintext =
        !matches!(&passphrase, Ok(p) if !p.is_empty());
    if will_be_plaintext && encrypted_marker_path(path).exists() {
        let allow_downgrade = std::env::var(ALLOW_PLAINTEXT_DOWNGRADE_ENV)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !allow_downgrade {
            return Err(IdentityStoreError::Crypto(format!(
                "refusing to overwrite encrypted identity at {} with plaintext \
                 ({PASSPHRASE_ENV} is empty but an encrypted-marker is present). \
                 If this is intentional (e.g., rotating to a new passphrase), \
                 set {ALLOW_PLAINTEXT_DOWNGRADE_ENV}=1 to override.",
                path.display()
            )));
        }
        tracing::warn!(
            "plaintext downgrade of encrypted identity at {} permitted by \
             {ALLOW_PLAINTEXT_DOWNGRADE_ENV}",
            path.display()
        );
    }

    // H-9 (security review): wrap the passphrase in `Zeroizing` so it
    // is wiped on drop even on the early-error paths that follow.
    let map = match passphrase {
        Ok(pass) if !pass.is_empty() => {
            // M-10: write v=3 with parameters embedded in the blob so
            // future parameter bumps do not need yet another schema
            // version. Loads of legacy v=2 blobs are rewrapped to v=3
            // transparently (see `load`).
            let params = KdfParams::V3;
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let mut key = derive_key(pass.as_bytes(), &salt, params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), key_bytes.as_ref())
                .map_err(|e| IdentityStoreError::Crypto(e.to_string()))?;
            key.zeroize();
            key_bytes.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED_V3.into()),
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
    // L-3 (security review): atomic write — tempfile + rename so a
    // crash mid-write can't leave a torn key blob on disk. Set perms
    // before the rename so the final file is never world-readable.
    let parent = path
        .parent()
        .ok_or_else(|| IdentityStoreError::Io("identity path has no parent".into()))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| IdentityStoreError::Io(format!("tempfile: {e}")))?;
    std::fs::write(tmp.path(), &buf)
        .map_err(|e| IdentityStoreError::Io(format!("tempfile write: {e}")))?;
    set_owner_only_permissions(tmp.path());
    tmp.persist(path)
        .map_err(|e| IdentityStoreError::Io(format!("rename: {e}")))?;
    set_owner_only_permissions(path);

    // M-14: drop the sticky marker once we've written an encrypted
    // blob. We intentionally only create the marker on success, and
    // never remove it once present (downgrade is then always explicit).
    if !will_be_plaintext {
        let marker = encrypted_marker_path(path);
        if !marker.exists() {
            let _ = std::fs::write(&marker, []);
            set_owner_only_permissions(&marker);
        }
    }
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

/// Read a file without following symlinks (L-2). On Unix uses
/// `O_NOFOLLOW`; on Windows we just call `std::fs::read` because NTFS
/// semantics differ and parent-directory ACLs are the standard
/// hardening mechanism.
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

/// Load an identity from disk.
pub fn load(path: &Path) -> Result<Identity, IdentityStoreError> {
    // L-2 (security review): refuse to follow symlinks on Unix so a
    // local attacker who controls a sibling path can't redirect the
    // read to an attacker-chosen blob. Windows: rely on parent ACL.
    let bytes = read_no_follow(path).map_err(|e| IdentityStoreError::Io(e.to_string()))?;
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
    let mut m_cost: Option<u32> = None;
    let mut t_cost: Option<u32> = None;
    let mut p_cost: Option<u32> = None;
    for (k, v) in map.iter() {
        if let Some(name) = k.as_text() {
            match name {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "label" => label = v.as_text().map(|s| s.to_string()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                "m_cost" => {
                    m_cost = v.as_integer().and_then(|i| u32::try_from(i).ok());
                }
                "t_cost" => {
                    t_cost = v.as_integer().and_then(|i| u32::try_from(i).ok());
                }
                "p_cost" => {
                    p_cost = v.as_integer().and_then(|i| u32::try_from(i).ok());
                }
                _ => {}
            }
        }
    }
    let label = label.ok_or_else(|| IdentityStoreError::Format("missing label".into()))?;
    let key_field = key_field.ok_or_else(|| IdentityStoreError::Format("missing key".into()))?;

    let mut rewrap_v2_to_v3 = false;
    let mut raw = match version {
        Some(v) if v == VERSION_PLAIN as i64 => {
            if key_field.len() != 32 {
                return Err(IdentityStoreError::Format("plain key wrong length".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&key_field);
            k
        }
        Some(v) if v == VERSION_ENCRYPTED as i64 || v == VERSION_ENCRYPTED_V3 as i64 => {
            // H-9: passphrase wiped on drop.
            let pass = Zeroizing::new(std::env::var(PASSPHRASE_ENV).map_err(|_| {
                IdentityStoreError::Crypto(format!(
                    "identity is encrypted but {PASSPHRASE_ENV} is not set"
                ))
            })?);
            let salt = salt.ok_or_else(|| IdentityStoreError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| IdentityStoreError::Format("missing nonce".into()))?;
            // v=2 uses legacy params; v=3 uses the params baked into
            // the blob. If v=3 lacks any of m/t/p, reject as malformed
            // rather than silently falling back.
            let params = if v == VERSION_ENCRYPTED as i64 {
                rewrap_v2_to_v3 = true;
                KdfParams::V2
            } else {
                let m = m_cost.ok_or_else(|| {
                    IdentityStoreError::Format("v=3 missing m_cost".into())
                })?;
                let t = t_cost.ok_or_else(|| {
                    IdentityStoreError::Format("v=3 missing t_cost".into())
                })?;
                let p = p_cost.ok_or_else(|| {
                    IdentityStoreError::Format("v=3 missing p_cost".into())
                })?;
                KdfParams {
                    m_cost_kib: m,
                    t_cost: t,
                    p_cost: p,
                }
            };
            let mut key = derive_key(pass.as_bytes(), &salt, params)?;
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
    let ident = Identity::from_signing_key(&label, signing_key);

    // **M-10**: lazy rewrap. When the blob on disk is v=2 and the
    // passphrase is available, re-encrypt as v=3 with the new
    // Argon2id parameters. On failure log and return the identity
    // anyway — we've successfully decrypted, so the caller should
    // proceed; a subsequent save on a writable volume will migrate
    // on its own.
    if rewrap_v2_to_v3 {
        match save(path, &ident) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    "M-10: identity rewrapped v=2 -> v=3 Argon2id (m=64MiB, t=3, p=4)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "M-10: v=2 decrypt succeeded but lazy rewrap failed; \
                     identity will be used but remains on v=2 on disk"
                );
            }
        }
    }

    Ok(ident)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    p: KdfParams,
) -> Result<[u8; 32], IdentityStoreError> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
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

    /// **M-10 (security review)**: new saves use the v=3 schema
    /// with Argon2id parameters embedded in the blob.
    #[test]
    fn test_m10_save_writes_v3_with_embedded_params() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(PASSPHRASE_ENV, "unit-test-m10") };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");
        let _ = load_or_create(&path, "node-m10").unwrap();

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

    /// **M-10**: a blob saved under v=2 legacy params is
    /// transparently rewrapped to v=3 on the next successful load.
    /// The identity is preserved; only the on-disk KDF parameters
    /// change.
    #[test]
    fn test_m10_lazy_rewrap_v2_to_v3() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let pass = "unit-test-m10-rewrap";
        unsafe { std::env::set_var(PASSPHRASE_ENV, pass) };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");

        // Hand-craft a v=2 blob for a freshly-generated identity.
        let ident = Identity::generate("legacy", &mut OsRng);
        let urn = ident.id.to_urn();
        let mut key_bytes = ident.signing_key.to_bytes();
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut k = derive_key(pass.as_bytes(), &salt, KdfParams::V2).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), key_bytes.as_ref())
            .unwrap();
        k.zeroize();
        key_bytes.zeroize();
        let map = vec![
            (
                CborValue::Text("v".into()),
                CborValue::Integer((VERSION_ENCRYPTED as i64).into()),
            ),
            (
                CborValue::Text("label".into()),
                CborValue::Text("legacy".into()),
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
        // M-14's marker must exist so `save` doesn't refuse (encrypted
        // save will also create it, but simulate the pre-existing
        // state to be safe).
        std::fs::write(encrypted_marker_path(&path), []).unwrap();

        // Load — must succeed AND trigger lazy rewrap.
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id.to_urn(), urn);

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

        // And a fresh load still returns the same identity.
        let again = load(&path).unwrap();
        assert_eq!(again.id.to_urn(), urn);

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
    }

    /// **M-14 (security review)**: once the identity has been saved
    /// encrypted, a subsequent save with `DDS_NODE_PASSPHRASE` unset
    /// must fail — the sticky marker prevents a silent downgrade
    /// that a local attacker could force by clearing the env var.
    #[test]
    fn test_m14_refuses_plaintext_downgrade() {
        let _g = PASSPHRASE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple") };
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("node_key.bin");
        let ident = load_or_create(&path, "node-m14").unwrap();
        assert!(encrypted_marker_path(&path).exists());

        // Now clear the passphrase and try to overwrite with plaintext.
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let err = save(&path, &ident).expect_err("save must refuse downgrade");
        match err {
            IdentityStoreError::Crypto(msg) => {
                assert!(
                    msg.contains("refusing to overwrite encrypted identity"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Crypto error, got {other:?}"),
        }

        // Explicit override allows downgrade (dev/testing).
        unsafe {
            std::env::set_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV, "1");
        }
        save(&path, &ident).expect("explicit override must succeed");
        unsafe {
            std::env::remove_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV);
        }
    }
}
