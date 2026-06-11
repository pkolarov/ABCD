//! Persistence for the [`DomainKey`] secret and the public [`Domain`] info,
//! plus load/save helpers for [`AdmissionCert`].
//!
//! - The **public** domain (name + id + pubkey) is stored as TOML in
//!   `domain.toml`. Safe to share with sibling nodes.
//! - The **secret** domain key is stored as CBOR in `domain_key.bin`,
//!   plain or encrypted with `DDS_DOMAIN_PASSPHRASE` (mirrors
//!   [`crate::identity_store`]). Held only by the admin who created the
//!   domain (in Stage 2 this moves to a FIDO2 authenticator).
//! - Admission certs are CBOR (no encryption — they are public bearer
//!   tokens authorising one node to participate in the domain).

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value as CborValue;
use dds_domain::domain::{from_hex, to_hex};
use dds_domain::{AdmissionCert, Domain, DomainId, DomainKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const DOMAIN_PASSPHRASE_ENV: &str = "DDS_DOMAIN_PASSPHRASE";

// AUDIT-2026-06-11 #26: the domain root key is the most sensitive key
// (embedded in provision bundles), so its KDF must be at least as strong
// as the per-node keys hardened under M-10. We raise the Argon2id params
// to OWASP tier 2 (m=64 MiB, t=3, p=4) to match `identity_store` /
// `p2p_identity`. Backward compatibility: existing on-disk blobs were
// written with the legacy params (m=19 MiB, t=2, p=1) and did NOT store
// the params in the blob, so we cannot bump them blindly. Approach
// (mirrors M-10's v=2->v=3 migration): the encrypted passphrase blobs
// (v=2 / v=5) now carry `m_cost` / `t_cost` / `p_cost` fields. On load,
// params are read from the blob when present and fall back to the legacy
// V2 constants when absent (the pre-#26 on-disk shape) so existing
// `domain_key.bin` files still DECRYPT. On save we always write the
// strong V3 params + the fields, so the next save lazily upgrades the
// blob. No keyfile version bump was needed: CBOR maps are open, and the
// legacy reader tolerated unknown keys, so adding the param fields to
// v=2 / v=5 is forward- and backward-compatible.
const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;
/// Version 3: domain key encrypted with FIDO2 hmac-secret output.
/// The CBOR map stores `credential_id` (bytes) and `hmac_salt` (bytes)
/// alongside the encrypted key. No passphrase needed — touch the
/// FIDO2 key to decrypt.
const VERSION_FIDO2: u8 = 3;
/// **Z-1 Phase A** — Version 4: plain hybrid (Ed25519 + ML-DSA-65)
/// domain key. Map fields:
///   `v: 4`, `name: <text>`, `ed: <32B>`, `pq_sk: <4032B>`,
///   `pq_pk: <1952B>`.
/// The Ed25519 secret stays a top-level `ed` field for symmetry with
/// the v5 encrypted variant — `key` was retained for v1/v2/v3 only so
/// a quick `xxd` of the file shows the v4 schema is hybrid.
const VERSION_PLAIN_HYBRID: u8 = 4;
/// **Z-1 Phase A** — Version 5: passphrase-encrypted hybrid domain
/// key. Map fields:
///   `v: 5`, `name: <text>`, `salt: <16B argon2 salt>`,
///   `nonce: <12B chacha20-poly1305 nonce>`,
///   `blob: <ciphertext over CBOR-encoded HybridKeyMaterial>`.
/// One nonce + one ciphertext over the whole `{ed, pq_sk, pq_pk}`
/// CBOR struct rather than three independent fields — simpler than
/// managing three nonces and avoids the nonce-reuse foot-gun if a
/// future maintainer copy-pastes the encrypt path.
const VERSION_ENCRYPTED_HYBRID: u8 = 5;

// AUDIT-2026-06-11 #26: legacy Argon2id params, retained only for
// backward-compatible decryption of pre-#26 blobs that did not embed
// their KDF params. New blobs always use `KdfParams::V3`.
const V2_M_COST_KIB: u32 = 19 * 1024;
const V2_T_COST: u32 = 2;
const V2_P_COST: u32 = 1;

// AUDIT-2026-06-11 #26: strong Argon2id params (OWASP tier 2), matching
// `identity_store` / `p2p_identity` M-10. The domain root key is the
// most sensitive key in the system, so it must not be weaker than the
// per-node keys.
const V3_M_COST_KIB: u32 = 64 * 1024;
const V3_T_COST: u32 = 3;
const V3_P_COST: u32 = 4;

/// AUDIT-2026-06-11 #26: Argon2id parameters read from / written to the
/// encrypted domain-key blob. Carried in the blob so a future bump is
/// just another value here plus a lazy rewrap (no new keyfile version),
/// mirroring `identity_store::KdfParams`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// Legacy params for pre-#26 blobs that lack embedded param fields.
    const V2: Self = Self {
        m_cost_kib: V2_M_COST_KIB,
        t_cost: V2_T_COST,
        p_cost: V2_P_COST,
    };
    /// Strong params written by all new saves.
    const V3: Self = Self {
        m_cost_kib: V3_M_COST_KIB,
        t_cost: V3_T_COST,
        p_cost: V3_P_COST,
    };
}

/// **security-gaps.md remaining work / AUDIT-2026-06-11 #27**: path of
/// the sticky "this domain key was once encrypted" marker file. Mirrors
/// [`crate::identity_store`]'s M-14 marker so an attacker who clears
/// `DDS_DOMAIN_PASSPHRASE` cannot force a silent downgrade of an
/// encrypted `domain_key.bin` to plaintext. Kept as a side file (not a
/// blob field) so the invariant is checkable without first parsing an
/// attacker-swappable file.
fn encrypted_marker_path(key_path: &Path) -> std::path::PathBuf {
    let mut p = key_path.as_os_str().to_os_string();
    p.push(".encrypted-marker");
    std::path::PathBuf::from(p)
}

/// **Z-1 Phase A** — inner CBOR struct that is the plaintext payload
/// of a v5 encrypted blob (and the conceptual shape of v4 plain
/// fields). Used only inside `save_domain_key` / `load_domain_key_*`.
#[derive(Serialize, Deserialize)]
struct HybridKeyMaterial {
    /// Ed25519 secret key (32 bytes).
    #[serde(with = "serde_bytes")]
    ed: Vec<u8>,
    /// ML-DSA-65 secret key (4,032 bytes).
    #[serde(with = "serde_bytes")]
    pq_sk: Vec<u8>,
    /// ML-DSA-65 public key (1,952 bytes). Carried alongside the
    /// secret so `DomainPqKey::from_secret_bytes` can run its
    /// secret/public self-test at load time without re-deriving the
    /// public key (which would require an extra round-trip through
    /// pqcrypto-mldsa internals we don't expose).
    #[serde(with = "serde_bytes")]
    pq_pk: Vec<u8>,
}

#[derive(Debug)]
pub enum DomainStoreError {
    Io(String),
    Cbor(String),
    Toml(String),
    Format(String),
    Crypto(String),
    Domain(String),
}

impl std::fmt::Display for DomainStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainStoreError::Io(e) => write!(f, "io: {e}"),
            DomainStoreError::Cbor(e) => write!(f, "cbor: {e}"),
            DomainStoreError::Toml(e) => write!(f, "toml: {e}"),
            DomainStoreError::Format(e) => write!(f, "format: {e}"),
            DomainStoreError::Crypto(e) => write!(f, "crypto: {e}"),
            DomainStoreError::Domain(e) => write!(f, "domain: {e}"),
        }
    }
}

impl std::error::Error for DomainStoreError {}

/// On-disk TOML representation of the public [`Domain`].
///
/// **Z-1 Phase A** — the optional `pq_pubkey` field carries the
/// hex-encoded ML-DSA-65 public key (1,952 bytes ⇒ 3,904 hex chars)
/// when the domain has been rotated to v2-hybrid. Absent on v1
/// domains; legacy `domain.toml` files without the field
/// deserialize cleanly under `#[serde(default)]`.
///
/// **Z-1 Phase B.3** — the optional `capabilities` field carries
/// admin-controlled capability tags (e.g. `["enc-v3"]`). Empty vec
/// is the v1 / v2 default; an absent field also deserializes to an
/// empty vec.
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainFile {
    pub name: String,
    /// `dds-dom:<base32>` form of the domain id.
    pub id: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub pubkey: String,
    /// **Z-1 Phase A** — hex-encoded ML-DSA-65 public key for v2
    /// hybrid domains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_pubkey: Option<String>,
    /// **Z-1 Phase B.3** — admin-controlled capability tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl DomainFile {
    pub fn from_domain(domain: &Domain) -> Self {
        Self {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: to_hex(&domain.pubkey),
            pq_pubkey: domain.pq_pubkey.as_deref().map(to_hex),
            capabilities: domain.capabilities.clone(),
        }
    }

    pub fn into_domain(self) -> Result<Domain, DomainStoreError> {
        let id = DomainId::parse(&self.id).map_err(|e| DomainStoreError::Domain(e.to_string()))?;
        let pk_vec = from_hex(&self.pubkey).map_err(|e| DomainStoreError::Domain(e.to_string()))?;
        if pk_vec.len() != 32 {
            return Err(DomainStoreError::Format(format!(
                "pubkey: expected 32 bytes, got {}",
                pk_vec.len()
            )));
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pk_vec);
        let pq_pubkey = match self.pq_pubkey {
            Some(hex) if !hex.is_empty() => {
                Some(from_hex(&hex).map_err(|e| DomainStoreError::Domain(e.to_string()))?)
            }
            _ => None,
        };
        let domain = Domain {
            name: self.name,
            id,
            pubkey,
            pq_pubkey,
            capabilities: self.capabilities,
        };
        domain
            .verify_self_consistent()
            .map_err(|e| DomainStoreError::Domain(e.to_string()))?;
        Ok(domain)
    }
}

pub fn save_domain_file(path: &Path, domain: &Domain) -> Result<(), DomainStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    }
    tighten_parent_dir_perms(path);
    let f = DomainFile::from_domain(domain);
    let s = toml::to_string_pretty(&f).map_err(|e| DomainStoreError::Toml(e.to_string()))?;
    atomic_write_owner_only(path, s.as_bytes())?;
    Ok(())
}

pub fn load_domain_file(path: &Path) -> Result<Domain, DomainStoreError> {
    let s = std::fs::read_to_string(path).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    let f: DomainFile = toml::from_str(&s).map_err(|e| DomainStoreError::Toml(e.to_string()))?;
    f.into_domain()
}

pub fn save_domain_key(path: &Path, key: &DomainKey) -> Result<(), DomainStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    }
    tighten_parent_dir_perms(path);
    let secret = key.signing_key.to_bytes();
    let name = key.name.clone();
    let passphrase = match std::env::var(DOMAIN_PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    };

    // **security-gaps.md remaining work #4** — operator opt-in to
    // refuse a plaintext domain key. When `DDS_REQUIRE_ENCRYPTED_KEYS`
    // is set, fail-closed before writing v=1 / v=4 plain blobs. The
    // FIDO2 path goes through `save_domain_key_fido2` and is already
    // encrypted, so it is unaffected.
    if passphrase.is_none() && crate::identity_store::require_encrypted_keys() {
        return Err(DomainStoreError::Crypto(format!(
            "refusing to write plaintext domain key at {} — \
             {} is set but {DOMAIN_PASSPHRASE_ENV} is empty. \
             Set {DOMAIN_PASSPHRASE_ENV} to a non-empty value, use \
             `--fido2`, or unset {} on dev hosts.",
            path.display(),
            crate::identity_store::REQUIRE_ENCRYPTED_KEYS_ENV,
            crate::identity_store::REQUIRE_ENCRYPTED_KEYS_ENV,
        )));
    }

    // AUDIT-2026-06-11 #27: sticky plaintext-downgrade guard, mirroring
    // identity_store's M-14 marker (which only covered node_key.bin).
    // If a previous save wrote an encrypted domain key (the marker is
    // present) and this save would write plaintext (passphrase cleared),
    // refuse so an attacker with filesystem write cannot force a silent
    // downgrade by clearing DDS_DOMAIN_PASSPHRASE. Override is the same
    // operator-acknowledged DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE env var.
    let will_be_plaintext = passphrase.is_none();
    if will_be_plaintext && encrypted_marker_path(path).exists() {
        let allow_downgrade = std::env::var(crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !allow_downgrade {
            return Err(DomainStoreError::Crypto(format!(
                "refusing to overwrite encrypted domain key at {} with plaintext \
                 ({DOMAIN_PASSPHRASE_ENV} is empty but an encrypted-marker is present). \
                 If this is intentional (e.g., rotating to a new passphrase), set {}=1 \
                 to override.",
                path.display(),
                crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV,
            )));
        }
        tracing::warn!(
            "plaintext downgrade of encrypted domain key at {} permitted by {}",
            path.display(),
            crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV,
        );
    }

    // **Z-1 Phase A** — branch on hybrid vs Ed25519-only and on
    // whether a passphrase is set, picking one of v1 / v2 / v4 / v5.
    // (v3 = FIDO2 stays Ed25519-only via `save_domain_key_fido2`.)
    let map = match (key.is_hybrid(), passphrase) {
        (false, None) => {
            tracing::warn!(
                "{DOMAIN_PASSPHRASE_ENV} not set; domain key will be stored unencrypted at {}",
                path.display()
            );
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_PLAIN.into()),
                ),
                (CborValue::Text("name".into()), CborValue::Text(name)),
                (
                    CborValue::Text("key".into()),
                    CborValue::Bytes(secret.to_vec()),
                ),
            ]
        }
        (false, Some(pass)) => {
            // AUDIT-2026-06-11 #26: derive with the strong V3 params and
            // embed them in the blob so this and future bumps migrate
            // lazily without a keyfile version change.
            let params = KdfParams::V3;
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let mut k = derive_key(pass.as_bytes(), &salt, params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), secret.as_ref())
                .map_err(|e| DomainStoreError::Crypto(e.to_string()))?;
            k.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED.into()),
                ),
                (CborValue::Text("name".into()), CborValue::Text(name)),
                (
                    CborValue::Text("salt".into()),
                    CborValue::Bytes(salt.to_vec()),
                ),
                (
                    CborValue::Text("nonce".into()),
                    CborValue::Bytes(nonce.to_vec()),
                ),
                // AUDIT-2026-06-11 #26: embed Argon2id params.
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
        (true, None) => {
            tracing::warn!(
                "{DOMAIN_PASSPHRASE_ENV} not set; hybrid domain key will be stored \
                 unencrypted at {} (v4 plain hybrid)",
                path.display()
            );
            let pq = key.pq.as_ref().expect("hybrid branch implies pq is Some");
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_PLAIN_HYBRID.into()),
                ),
                (CborValue::Text("name".into()), CborValue::Text(name)),
                (
                    CborValue::Text("ed".into()),
                    CborValue::Bytes(secret.to_vec()),
                ),
                (
                    CborValue::Text("pq_sk".into()),
                    CborValue::Bytes(pq.secret_key_bytes()),
                ),
                (
                    CborValue::Text("pq_pk".into()),
                    CborValue::Bytes(pq.public_key_bytes()),
                ),
            ]
        }
        (true, Some(pass)) => {
            let pq = key.pq.as_ref().expect("hybrid branch implies pq is Some");
            // CBOR-encode the inner material, then encrypt the whole
            // blob under one key + one nonce so we never have to manage
            // multiple nonces with the same passphrase-derived key.
            let inner = HybridKeyMaterial {
                ed: secret.to_vec(),
                pq_sk: pq.secret_key_bytes(),
                pq_pk: pq.public_key_bytes(),
            };
            let mut inner_bytes = Vec::new();
            ciborium::into_writer(&inner, &mut inner_bytes)
                .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
            // AUDIT-2026-06-11 #26: strong V3 params, embedded in the blob.
            let params = KdfParams::V3;
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let mut k = derive_key(pass.as_bytes(), &salt, params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), inner_bytes.as_ref())
                .map_err(|e| DomainStoreError::Crypto(e.to_string()))?;
            k.zeroize();
            inner_bytes.zeroize();
            vec![
                (
                    CborValue::Text("v".into()),
                    CborValue::Integer(VERSION_ENCRYPTED_HYBRID.into()),
                ),
                (CborValue::Text("name".into()), CborValue::Text(name)),
                (
                    CborValue::Text("salt".into()),
                    CborValue::Bytes(salt.to_vec()),
                ),
                (
                    CborValue::Text("nonce".into()),
                    CborValue::Bytes(nonce.to_vec()),
                ),
                // AUDIT-2026-06-11 #26: embed Argon2id params.
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
                (CborValue::Text("blob".into()), CborValue::Bytes(ct)),
            ]
        }
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    atomic_write_owner_only(path, &buf)?;

    // AUDIT-2026-06-11 #27: drop the sticky marker once an encrypted blob
    // has been written. Created only on success and never removed, so a
    // later plaintext downgrade is always explicit (see the guard above).
    if !will_be_plaintext {
        let marker = encrypted_marker_path(path);
        if !marker.exists() {
            let _ = std::fs::write(&marker, []);
            set_owner_only_permissions(&marker);
        }
    }
    Ok(())
}

/// Best-effort: restrict file to owner-only access.
///
/// Delegates to [`crate::file_acl::restrict_to_owner`] — `chmod 0o600`
/// on Unix, protected DACL on Windows. See `file_acl.rs` for the SDDL
/// detail.
fn set_owner_only_permissions(path: &Path) {
    crate::file_acl::restrict_to_owner(path);
}

/// L-4 (security review): tighten the parent directory of a written
/// key/cert file to `0o700` on Unix.
///
/// `create_dir_all` honours the process umask (typically `0o022`),
/// which leaves the data directory at `0o755` and a co-tenant readable.
/// Mirrors the same idiom in [`crate::identity_store::save`] and
/// [`crate::p2p_identity::save`]. Best-effort: ignore failures so a
/// pre-existing directory whose mode we cannot change does not break
/// the save (the per-file `0o600` and the data-dir DACL on Windows
/// are the authoritative perimeters). On Windows the parent perimeter
/// is the protected DACL applied by the MSI custom action
/// `CA_RestrictDataDirAcl` and the per-file DACL via
/// [`crate::file_acl::restrict_to_owner`], so this helper is a no-op.
fn tighten_parent_dir_perms(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// L-3 (security review): atomic write — `tempfile::NamedTempFile` in
/// the same parent directory + `persist` (POSIX `rename`) so a crash
/// mid-write can't leave a torn key/cert blob on disk. Owner-only
/// permissions are applied to the tempfile *before* the rename so the
/// final file is never observably world-readable. Mirrors the same
/// idiom landed in [`crate::identity_store::save`] and
/// [`crate::p2p_identity::save`]; closes the L-3 follow-on for the
/// four `domain_store` save paths (`save_domain_file`,
/// `save_domain_key`, `save_admission_cert`,
/// `save_domain_key_fido2`) which previously used a non-atomic
/// `std::fs::write`.
fn atomic_write_owner_only(path: &Path, buf: &[u8]) -> Result<(), DomainStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| DomainStoreError::Io("path has no parent".into()))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| DomainStoreError::Io(format!("tempfile: {e}")))?;
    std::fs::write(tmp.path(), buf)
        .map_err(|e| DomainStoreError::Io(format!("tempfile write: {e}")))?;
    set_owner_only_permissions(tmp.path());
    tmp.persist(path)
        .map_err(|e| DomainStoreError::Io(format!("rename: {e}")))?;
    set_owner_only_permissions(path);
    Ok(())
}

pub fn load_domain_key(path: &Path) -> Result<DomainKey, DomainStoreError> {
    let bytes = std::fs::read(path).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    load_domain_key_from_bytes(&bytes)
}

/// Load a domain key from raw CBOR bytes (already in memory).
/// Used by the provisioning flow to decrypt a domain key embedded
/// in a provision bundle without writing it to disk first.
pub fn load_domain_key_from_bytes(bytes: &[u8]) -> Result<DomainKey, DomainStoreError> {
    let value: CborValue =
        ciborium::from_reader(bytes).map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| DomainStoreError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut name: Option<String> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut key_field: Option<Vec<u8>> = None;
    // **Z-1 Phase A** — v4 plain hybrid + v5 encrypted hybrid fields.
    let mut ed_field: Option<Vec<u8>> = None;
    let mut pq_sk_field: Option<Vec<u8>> = None;
    let mut pq_pk_field: Option<Vec<u8>> = None;
    let mut blob_field: Option<Vec<u8>> = None;
    // AUDIT-2026-06-11 #26: optional embedded Argon2id params (absent on
    // pre-#26 blobs, in which case we fall back to the legacy V2 params).
    let mut m_cost: Option<u32> = None;
    let mut t_cost: Option<u32> = None;
    let mut p_cost: Option<u32> = None;
    for (k, v) in map.iter() {
        if let Some(n) = k.as_text() {
            match n {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "name" => name = v.as_text().map(|s| s.to_string()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                "ed" => ed_field = v.as_bytes().cloned(),
                "pq_sk" => pq_sk_field = v.as_bytes().cloned(),
                "pq_pk" => pq_pk_field = v.as_bytes().cloned(),
                "blob" => blob_field = v.as_bytes().cloned(),
                "m_cost" => m_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                "t_cost" => t_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                "p_cost" => p_cost = v.as_integer().and_then(|i| u32::try_from(i).ok()),
                _ => {}
            }
        }
    }
    let name = name.ok_or_else(|| DomainStoreError::Format("missing name".into()))?;

    // AUDIT-2026-06-11 #26: resolve the KDF params for the encrypted
    // paths. If the blob carries all three fields, use them; otherwise
    // (pre-#26 blob) fall back to the legacy V2 params so existing
    // `domain_key.bin` files still decrypt.
    let kdf_params = match (m_cost, t_cost, p_cost) {
        (Some(m), Some(t), Some(p)) => KdfParams {
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
        },
        _ => KdfParams::V2,
    };

    // **Z-1 Phase A** — short-circuit for hybrid (v4 / v5) so we can
    // return a `from_secret_bytes_hybrid` DomainKey before falling
    // through to the v1 / v2 / v3 Ed25519-only path.
    match version {
        Some(v) if v == VERSION_PLAIN_HYBRID as i64 => {
            let ed = ed_field.ok_or_else(|| DomainStoreError::Format("missing ed".into()))?;
            let pq_sk =
                pq_sk_field.ok_or_else(|| DomainStoreError::Format("missing pq_sk".into()))?;
            let pq_pk =
                pq_pk_field.ok_or_else(|| DomainStoreError::Format("missing pq_pk".into()))?;
            if ed.len() != 32 {
                return Err(DomainStoreError::Format(format!(
                    "v4 ed: expected 32 bytes, got {}",
                    ed.len()
                )));
            }
            let mut ed_arr = [0u8; 32];
            ed_arr.copy_from_slice(&ed);
            return DomainKey::from_secret_bytes_hybrid(&name, ed_arr, &pq_sk, &pq_pk)
                .map_err(|e| DomainStoreError::Crypto(e.to_string()));
        }
        Some(v) if v == VERSION_ENCRYPTED_HYBRID as i64 => {
            let pass = std::env::var(DOMAIN_PASSPHRASE_ENV).map_err(|_| {
                DomainStoreError::Crypto(format!(
                    "hybrid domain key encrypted but {DOMAIN_PASSPHRASE_ENV} not set"
                ))
            })?;
            let salt = salt.ok_or_else(|| DomainStoreError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| DomainStoreError::Format("missing nonce".into()))?;
            let blob = blob_field.ok_or_else(|| DomainStoreError::Format("missing blob".into()))?;
            let mut k = derive_key(pass.as_bytes(), &salt, kdf_params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
            let mut pt = cipher
                .decrypt(Nonce::from_slice(&nonce), blob.as_ref())
                .map_err(|e| DomainStoreError::Crypto(format!("decrypt: {e}")))?;
            k.zeroize();
            let inner: HybridKeyMaterial = ciborium::from_reader(&pt[..])
                .map_err(|e| DomainStoreError::Cbor(format!("inner: {e}")))?;
            pt.zeroize();
            if inner.ed.len() != 32 {
                return Err(DomainStoreError::Format(format!(
                    "v5 ed: expected 32 bytes, got {}",
                    inner.ed.len()
                )));
            }
            let mut ed_arr = [0u8; 32];
            ed_arr.copy_from_slice(&inner.ed);
            return DomainKey::from_secret_bytes_hybrid(&name, ed_arr, &inner.pq_sk, &inner.pq_pk)
                .map_err(|e| DomainStoreError::Crypto(e.to_string()));
        }
        _ => {}
    }

    let key_field = key_field.ok_or_else(|| DomainStoreError::Format("missing key".into()))?;

    let raw = match version {
        Some(v) if v == VERSION_PLAIN as i64 => {
            if key_field.len() != 32 {
                return Err(DomainStoreError::Format("plain key wrong length".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&key_field);
            k
        }
        Some(v) if v == VERSION_ENCRYPTED as i64 => {
            let pass = std::env::var(DOMAIN_PASSPHRASE_ENV).map_err(|_| {
                DomainStoreError::Crypto(format!(
                    "domain key encrypted but {DOMAIN_PASSPHRASE_ENV} not set"
                ))
            })?;
            let salt = salt.ok_or_else(|| DomainStoreError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| DomainStoreError::Format("missing nonce".into()))?;
            let mut k = derive_key(pass.as_bytes(), &salt, kdf_params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
            let pt = cipher
                .decrypt(Nonce::from_slice(&nonce), key_field.as_ref())
                .map_err(|e| DomainStoreError::Crypto(format!("decrypt: {e}")))?;
            k.zeroize();
            if pt.len() != 32 {
                return Err(DomainStoreError::Format(
                    "decrypted key wrong length".into(),
                ));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&pt);
            k
        }
        #[cfg(feature = "fido2")]
        Some(v) if v == VERSION_FIDO2 as i64 => {
            let cred_id = map
                .iter()
                .find_map(|(k, v)| {
                    if k.as_text() == Some("credential_id") {
                        v.as_bytes().cloned()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| DomainStoreError::Format("missing credential_id".into()))?;
            let hmac_salt = map
                .iter()
                .find_map(|(k, v)| {
                    if k.as_text() == Some("hmac_salt") {
                        v.as_bytes().cloned()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| DomainStoreError::Format("missing hmac_salt".into()))?;
            let salt = salt.ok_or_else(|| DomainStoreError::Format("missing salt".into()))?;
            let nonce = nonce.ok_or_else(|| DomainStoreError::Format("missing nonce".into()))?;

            tracing::info!("Domain key is FIDO2-protected — touch your key to unlock");
            let hmac_key = fido2_hmac_secret(&cred_id, &hmac_salt)?;
            // AUDIT-2026-06-11 #26: the FIDO2 hmac-secret output is already
            // a 32-byte high-entropy key, so Argon2 params are not a
            // weakness here; we keep this path on V2-equivalent params via
            // the `kdf_params` fallback (v3 FIDO2 blobs do not embed
            // params) to avoid breaking existing FIDO2-protected blobs.
            let mut k = derive_key(&hmac_key, &salt, kdf_params)?;
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
            let pt = cipher
                .decrypt(Nonce::from_slice(&nonce), key_field.as_ref())
                .map_err(|e| DomainStoreError::Crypto(format!("decrypt: {e}")))?;
            k.zeroize();
            if pt.len() != 32 {
                return Err(DomainStoreError::Format(
                    "decrypted key wrong length".into(),
                ));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&pt);
            k
        }
        #[cfg(not(feature = "fido2"))]
        Some(v) if v == VERSION_FIDO2 as i64 => {
            return Err(DomainStoreError::Crypto(
                "domain key is FIDO2-protected but dds-node was built without --features fido2"
                    .into(),
            ));
        }
        other => {
            return Err(DomainStoreError::Format(format!(
                "unknown version {other:?}"
            )));
        }
    };
    Ok(DomainKey::from_secret_bytes(&name, raw))
}

pub fn save_admission_cert(path: &Path, cert: &AdmissionCert) -> Result<(), DomainStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    }
    tighten_parent_dir_perms(path);
    let bytes = cert
        .to_cbor()
        .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    atomic_write_owner_only(path, &bytes)?;
    Ok(())
}

pub fn load_admission_cert(path: &Path) -> Result<AdmissionCert, DomainStoreError> {
    let bytes = std::fs::read(path).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    AdmissionCert::from_cbor(&bytes).map_err(|e| DomainStoreError::Cbor(e.to_string()))
}

/// Save the domain key encrypted with FIDO2 hmac-secret (version 3).
///
/// Creates a FIDO2 credential on the hardware key, uses the hmac-secret
/// extension output to derive an encryption key, and stores the encrypted
/// Ed25519 domain key alongside the credential_id and hmac_salt.
///
/// No passphrase needed — touch the FIDO2 key to create/decrypt.
#[cfg(feature = "fido2")]
pub fn save_domain_key_fido2(path: &Path, key: &DomainKey) -> Result<Vec<u8>, DomainStoreError> {
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, fidokey::MakeCredentialArgsBuilder, verifier};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    }
    tighten_parent_dir_perms(path);

    tracing::info!("Creating FIDO2 credential to protect domain key...");
    tracing::info!(">>> TOUCH YOUR FIDO2 KEY <<<");

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| DomainStoreError::Crypto(format!("FIDO2 device: {e}")))?;

    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new("dds-domain-key", &challenge).build();
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| DomainStoreError::Crypto(format!("makeCredential: {e}")))?;

    let verify_result = verifier::verify_attestation("dds-domain-key", &challenge, &attestation);
    if !verify_result.is_success {
        return Err(DomainStoreError::Crypto(
            "FIDO2 attestation verification failed".into(),
        ));
    }
    let credential_id = verify_result.credential_id;

    // Generate a random salt for hmac-secret
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    // Get hmac-secret output: do a getAssertion with the just-created credential
    tracing::info!("Deriving encryption key via hmac-secret...");
    tracing::info!(">>> TOUCH YOUR FIDO2 KEY AGAIN <<<");
    let hmac_output = fido2_hmac_secret(&credential_id, &hmac_salt)?;

    // Encrypt the domain key with hmac-secret-derived key
    let secret = key.signing_key.to_bytes();
    let name = key.name.clone();

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // AUDIT-2026-06-11 #26: hmac-secret output is already high-entropy;
    // keep V2 params (no embedded param fields) so the load-path
    // fallback decrypts both pre- and post-#26 FIDO2 blobs identically.
    let mut k = derive_key(&hmac_output, &salt, KdfParams::V2)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_ref())
        .map_err(|e| DomainStoreError::Crypto(e.to_string()))?;
    k.zeroize();

    let map = vec![
        (
            CborValue::Text("v".into()),
            CborValue::Integer(VERSION_FIDO2.into()),
        ),
        (CborValue::Text("name".into()), CborValue::Text(name)),
        (
            CborValue::Text("credential_id".into()),
            CborValue::Bytes(credential_id.clone()),
        ),
        (
            CborValue::Text("hmac_salt".into()),
            CborValue::Bytes(hmac_salt.to_vec()),
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
    ];
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    atomic_write_owner_only(path, &buf)?;

    // AUDIT-2026-06-11 #27: a FIDO2-protected domain key is encrypted, so
    // drop the sticky marker to block any later silent plaintext downgrade.
    let marker = encrypted_marker_path(path);
    if !marker.exists() {
        let _ = std::fs::write(&marker, []);
        set_owner_only_permissions(&marker);
    }

    tracing::info!(
        "Domain key saved (FIDO2-protected, credential_id={} bytes)",
        credential_id.len()
    );
    Ok(credential_id)
}

/// Perform a FIDO2 getAssertion with hmac-secret extension to derive a
/// deterministic 32-byte key from the authenticator.
#[cfg(feature = "fido2")]
fn fido2_hmac_secret(credential_id: &[u8], hmac_salt: &[u8]) -> Result<Vec<u8>, DomainStoreError> {
    use ctap_hid_fido2::{
        Cfg, FidoKeyHidFactory,
        fidokey::{GetAssertionArgsBuilder, get_assertion::Extension},
        verifier,
    };

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| DomainStoreError::Crypto(format!("FIDO2 device: {e}")))?;

    // Convert salt to fixed [u8; 32]
    let mut salt_arr = [0u8; 32];
    let copy_len = hmac_salt.len().min(32);
    salt_arr[..copy_len].copy_from_slice(&hmac_salt[..copy_len]);

    let challenge = verifier::create_challenge();
    let args = GetAssertionArgsBuilder::new("dds-domain-key", &challenge)
        .credential_id(credential_id)
        .extensions(&[Extension::HmacSecret(Some(salt_arr))])
        .build();

    tracing::info!(">>> TOUCH YOUR FIDO2 KEY TO UNLOCK DOMAIN KEY <<<");

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| DomainStoreError::Crypto(format!("getAssertion: {e}")))?;

    if assertions.is_empty() {
        return Err(DomainStoreError::Crypto("no assertion returned".into()));
    }

    // Extract hmac-secret output from extensions
    for ext in &assertions[0].extensions {
        if let Extension::HmacSecret(Some(output)) = ext {
            return Ok(output.to_vec());
        }
    }

    Err(DomainStoreError::Crypto(
        "authenticator did not return hmac-secret output".into(),
    ))
}

fn derive_key(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<[u8; 32], DomainStoreError> {
    // AUDIT-2026-06-11 #26: params are now supplied by the caller (read
    // from the blob on load, `KdfParams::V3` on save) rather than
    // hardcoded to the weak legacy values.
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| DomainStoreError::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| DomainStoreError::Crypto(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    use crate::TEST_ENV_LOCK as ENV_LOCK;

    #[test]
    fn domain_file_roundtrip() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain.toml");
        save_domain_file(&path, &domain).unwrap();
        let loaded = load_domain_file(&path).unwrap();
        assert_eq!(loaded, domain);
    }

    #[test]
    fn domain_file_rejects_inconsistent_pubkey() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain.toml");
        // Hand-write a file where the id doesn't match the pubkey.
        std::fs::write(
            &path,
            r#"name = "fake"
id = "dds-dom:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
pubkey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#,
        )
        .unwrap();
        assert!(load_domain_file(&path).is_err());
    }

    #[test]
    fn domain_key_plain_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        let loaded = load_domain_key(&path).unwrap();
        assert_eq!(loaded.name, key.name);
        assert_eq!(loaded.pubkey(), key.pubkey());
    }

    #[test]
    fn domain_key_encrypted_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "domain-pass") };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        let loaded = load_domain_key(&path).unwrap();
        assert_eq!(loaded.pubkey(), key.pubkey());

        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "wrong") };
        assert!(load_domain_key(&path).is_err());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
    }

    #[test]
    fn admission_cert_file_roundtrip() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let cert = key.issue_admission("peerX".into(), 0, Some(9999));
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("admission.cbor");
        save_admission_cert(&path, &cert).unwrap();
        let loaded = load_admission_cert(&path).unwrap();
        let d = key.domain();
        loaded.verify(&d.pubkey, &d.id, "peerX", 100).unwrap();
    }

    /// L-4 (security review): the parent directory of a written
    /// `domain_key.bin` is tightened to `0o700` so the secret is not
    /// reachable through a co-tenant-readable directory entry. Mirrors
    /// the existing idiom in [`crate::identity_store::save`] and
    /// [`crate::p2p_identity::save`]; closes the "sibling" gap that
    /// L-4's "+ siblings" qualifier left open in `domain_store.rs`.
    #[test]
    #[cfg(unix)]
    fn save_domain_key_tightens_parent_dir_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        // Pre-loosen the directory so the assertion below proves the
        // save call is what tightened it (not the umask at create).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "save_domain_key must tighten parent dir to 0o700 (got {mode:o})"
        );
    }

    /// L-3 follow-on: every `domain_store` save path goes through the
    /// shared `atomic_write_owner_only` helper (`tempfile::NamedTempFile`
    /// in the same parent directory + `persist`). The test pins three
    /// invariants per save call: (1) the target file ends up with mode
    /// `0o600`; (2) no `tmpfile` leftovers remain in the parent
    /// directory after success — `NamedTempFile::persist` renames the
    /// tempfile so only the target should be present; (3) the helper
    /// is overwrite-safe — saving a second time over an existing file
    /// succeeds with no orphan tempfile and the new bytes are present.
    /// Mirrors the L-3 regression coverage already in
    /// [`crate::identity_store`] and [`crate::p2p_identity`].
    #[test]
    #[cfg(unix)]
    fn save_paths_are_atomic_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let dir = TempDir::new().unwrap();

        // Closure: assert exactly one entry under `dir`, named `expected`,
        // and that its mode is `0o600`. The "exactly one entry" check
        // catches a stray `.tmp*` left over by a future regression that
        // reverts to non-atomic write semantics.
        let assert_only_target = |expected: &Path, label: &str| {
            let entries: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "{label}: expected only the target file in parent dir, got {entries:?}"
            );
            assert_eq!(
                entries[0].to_string_lossy(),
                expected.file_name().unwrap().to_string_lossy(),
                "{label}: unexpected entry {entries:?}"
            );
            let mode = std::fs::metadata(expected).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{label}: target file mode {mode:o} != 0o600");
        };

        // 1. save_domain_file: no temp leftover, mode 0o600, overwrite-safe.
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        let domain_path = dir.path().join("domain.toml");
        save_domain_file(&domain_path, &domain).unwrap();
        assert_only_target(&domain_path, "save_domain_file first call");
        save_domain_file(&domain_path, &domain).unwrap();
        assert_only_target(&domain_path, "save_domain_file second call (overwrite)");
        std::fs::remove_file(&domain_path).unwrap();

        // 2. save_domain_key (plain v=1): same invariants.
        let key_path = dir.path().join("domain_key.bin");
        save_domain_key(&key_path, &key).unwrap();
        assert_only_target(&key_path, "save_domain_key first call");
        save_domain_key(&key_path, &key).unwrap();
        assert_only_target(&key_path, "save_domain_key second call (overwrite)");
        std::fs::remove_file(&key_path).unwrap();

        // 3. save_admission_cert: cert files are public bearer tokens but
        // the atomicity guarantee still applies — a torn cert would block
        // node startup just as effectively as a torn key.
        let cert_path = dir.path().join("admission.cbor");
        let cert = key.issue_admission("peerL3".into(), 0, None);
        save_admission_cert(&cert_path, &cert).unwrap();
        assert_only_target(&cert_path, "save_admission_cert first call");
        save_admission_cert(&cert_path, &cert).unwrap();
        assert_only_target(&cert_path, "save_admission_cert second call (overwrite)");
    }

    // -----------------------------------------------------------------
    // Z-1 Phase A — v4 (plain hybrid) + v5 (encrypted hybrid) on-disk
    // -----------------------------------------------------------------

    /// A hybrid `DomainKey` round-trips through the v4 plain on-disk
    /// format with both the Ed25519 and ML-DSA-65 halves intact: the
    /// reloaded key still produces a hybrid admission cert that
    /// verifies under the original `Domain`.
    #[test]
    fn domain_key_plain_hybrid_v4_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let original_domain = key.domain();
        assert!(original_domain.is_hybrid());
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        // Sanity: the on-disk header is v=4.
        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let v = value
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                (k.as_text() == Some("v"))
                    .then(|| v.as_integer().and_then(|i| i64::try_from(i).ok()))
            })
            .flatten()
            .unwrap();
        assert_eq!(v, VERSION_PLAIN_HYBRID as i64);

        let loaded = load_domain_key(&path).unwrap();
        assert!(loaded.is_hybrid());
        assert_eq!(loaded.pubkey(), key.pubkey());
        assert_eq!(loaded.pq_pubkey_bytes(), key.pq_pubkey_bytes());
        // End-to-end: a hybrid cert from the reloaded key verifies
        // under the original domain (catches a torn pq secret/public
        // pair that would silently switch to a different keypair).
        let cert = loaded.issue_admission("peerX".into(), 0, None);
        cert.verify_with_domain(&original_domain, "peerX", 0)
            .unwrap();
    }

    /// A hybrid `DomainKey` round-trips through the v5 encrypted
    /// on-disk format. Wrong passphrase rejects.
    #[test]
    fn domain_key_encrypted_hybrid_v5_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "hybrid-pass") };
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let original_domain = key.domain();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let v = value
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                (k.as_text() == Some("v"))
                    .then(|| v.as_integer().and_then(|i| i64::try_from(i).ok()))
            })
            .flatten()
            .unwrap();
        assert_eq!(v, VERSION_ENCRYPTED_HYBRID as i64);

        let loaded = load_domain_key(&path).unwrap();
        assert!(loaded.is_hybrid());
        assert_eq!(loaded.pubkey(), key.pubkey());
        assert_eq!(loaded.pq_pubkey_bytes(), key.pq_pubkey_bytes());
        let cert = loaded.issue_admission("peerY".into(), 0, None);
        cert.verify_with_domain(&original_domain, "peerY", 0)
            .unwrap();

        // Wrong passphrase → load fails (Crypto error from the
        // ChaCha20-Poly1305 AEAD tag mismatch).
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "wrong") };
        assert!(load_domain_key(&path).is_err());

        // Missing passphrase → load fails with the Crypto missing-env
        // message (mirrors the v2 behaviour for non-hybrid keys).
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let err = match load_domain_key(&path) {
            Ok(_) => panic!("missing pass must fail to load encrypted hybrid v5"),
            Err(e) => e,
        };
        assert!(err.to_string().contains(DOMAIN_PASSPHRASE_ENV));
    }

    /// **Backward compat.** A v1 plain (Ed25519-only) on-disk key
    /// still loads after the v4/v5 schema additions. Belt-and-suspenders
    /// regression test for the `match version` short-circuit ordering.
    #[test]
    fn domain_key_plain_v1_still_loads_after_hybrid_additions() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let v = value
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                (k.as_text() == Some("v"))
                    .then(|| v.as_integer().and_then(|i| i64::try_from(i).ok()))
            })
            .flatten()
            .unwrap();
        assert_eq!(v, VERSION_PLAIN as i64);
        let loaded = load_domain_key(&path).unwrap();
        assert!(!loaded.is_hybrid());
        assert_eq!(loaded.pubkey(), key.pubkey());
    }

    /// **security-gaps.md remaining work #4** — when
    /// `DDS_REQUIRE_ENCRYPTED_KEYS` is set and `DDS_DOMAIN_PASSPHRASE`
    /// is empty, both the Ed25519-only (v=1) and hybrid (v=4 plain
    /// hybrid) save paths must refuse to write a plaintext domain
    /// key. With a passphrase set, the same call succeeds and writes
    /// v=2 / v=5 respectively.
    #[test]
    fn domain_key_save_refuses_plaintext_when_required_env_set() {
        use crate::identity_store::REQUIRE_ENCRYPTED_KEYS_ENV;
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        unsafe { std::env::set_var(REQUIRE_ENCRYPTED_KEYS_ENV, "1") };

        let dir = TempDir::new().unwrap();

        // (1) Ed25519-only path → would write v=1 plain; must refuse.
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let path = dir.path().join("domain_key.bin");
        let err = save_domain_key(&path, &key).expect_err("v=1 save must refuse plaintext");
        match err {
            DomainStoreError::Crypto(msg) => {
                assert!(
                    msg.contains("refusing to write plaintext domain key")
                        && msg.contains(REQUIRE_ENCRYPTED_KEYS_ENV)
                        && msg.contains(DOMAIN_PASSPHRASE_ENV),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Crypto error, got {other:?}"),
        }
        assert!(!path.exists(), "v=1 path must not be created on refusal");

        // (2) Hybrid path → would write v=4 plain hybrid; must refuse.
        let hybrid = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let path_h = dir.path().join("domain_key_hybrid.bin");
        let err = save_domain_key(&path_h, &hybrid).expect_err("v=4 save must refuse plaintext");
        match err {
            DomainStoreError::Crypto(msg) => {
                assert!(
                    msg.contains("refusing to write plaintext domain key")
                        && msg.contains(REQUIRE_ENCRYPTED_KEYS_ENV),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Crypto error, got {other:?}"),
        }
        assert!(
            !path_h.exists(),
            "v=4 hybrid path must not be created on refusal"
        );

        // (3) With a passphrase set, both saves proceed (v=2 + v=5).
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "domain-require-test") };
        save_domain_key(&path, &key).expect("v=2 encrypted save must proceed");
        save_domain_key(&path_h, &hybrid).expect("v=5 encrypted save must proceed");
        let v_ed = std::fs::read(&path).unwrap();
        let v_h = std::fs::read(&path_h).unwrap();
        let read_v = |b: &[u8]| -> i64 {
            let val: CborValue = ciborium::from_reader(b).unwrap();
            val.as_map()
                .unwrap()
                .iter()
                .find_map(|(k, v)| {
                    (k.as_text() == Some("v"))
                        .then(|| v.as_integer().and_then(|i| i64::try_from(i).ok()))
                })
                .flatten()
                .unwrap()
        };
        assert_eq!(read_v(&v_ed), VERSION_ENCRYPTED as i64);
        assert_eq!(read_v(&v_h), VERSION_ENCRYPTED_HYBRID as i64);

        unsafe { std::env::remove_var(REQUIRE_ENCRYPTED_KEYS_ENV) };
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
    }

    /// **AUDIT-2026-06-11 #26**: a new encrypted domain-key save embeds
    /// the strong V3 Argon2id params (m=64 MiB, t=3, p=4) in the blob.
    #[test]
    fn save_domain_key_embeds_v3_params() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "audit26-params") };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");
        save_domain_key(&path, &key).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let val: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let map = val.as_map().unwrap();
        let get_u32 = |name: &str| -> Option<u32> {
            map.iter().find_map(|(k, v)| {
                (k.as_text() == Some(name))
                    .then(|| v.as_integer().and_then(|i| u32::try_from(i).ok()))
                    .flatten()
            })
        };
        assert_eq!(get_u32("m_cost"), Some(V3_M_COST_KIB));
        assert_eq!(get_u32("t_cost"), Some(V3_T_COST));
        assert_eq!(get_u32("p_cost"), Some(V3_P_COST));

        // And it still round-trips.
        let loaded = load_domain_key(&path).unwrap();
        assert_eq!(loaded.pubkey(), key.pubkey());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
    }

    /// **AUDIT-2026-06-11 #26 backward-compat**: a legacy v=2 blob written
    /// with the old params and WITHOUT embedded param fields must still
    /// decrypt (params fall back to `KdfParams::V2`).
    #[test]
    fn legacy_v2_domain_key_without_params_still_decrypts() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let pass = "audit26-legacy";
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, pass) };
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let secret = key.signing_key.to_bytes();

        // Hand-craft a pre-#26 v=2 blob: legacy params, no m/t/p fields.
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut k = derive_key(pass.as_bytes(), &salt, KdfParams::V2).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), secret.as_ref())
            .unwrap();
        k.zeroize();
        let map = vec![
            (
                CborValue::Text("v".into()),
                CborValue::Integer((VERSION_ENCRYPTED as i64).into()),
            ),
            (
                CborValue::Text("name".into()),
                CborValue::Text("acme.com".into()),
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
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();

        let loaded = load_domain_key_from_bytes(&buf).expect("legacy v=2 blob must decrypt");
        assert_eq!(loaded.pubkey(), key.pubkey());
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
    }

    /// **AUDIT-2026-06-11 #27**: once an encrypted domain key has been
    /// written (marker present), a subsequent plaintext save (passphrase
    /// cleared) is refused — unless the explicit override is set.
    #[test]
    fn save_domain_key_refuses_plaintext_downgrade() {
        use crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV;
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV) };
        unsafe { std::env::set_var(DOMAIN_PASSPHRASE_ENV, "audit27-pass") };

        let key = DomainKey::generate("acme.com", &mut OsRng);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("domain_key.bin");

        // (1) Encrypted save drops the sticky marker.
        save_domain_key(&path, &key).unwrap();
        assert!(encrypted_marker_path(&path).exists(), "marker must be set");

        // (2) Clearing the passphrase and saving again must be refused.
        unsafe { std::env::remove_var(DOMAIN_PASSPHRASE_ENV) };
        let err = save_domain_key(&path, &key).expect_err("plaintext downgrade must be refused");
        match err {
            DomainStoreError::Crypto(msg) => {
                assert!(
                    msg.contains("refusing to overwrite encrypted domain key"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Crypto error, got {other:?}"),
        }

        // (3) With the override set, the downgrade proceeds.
        unsafe { std::env::set_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV, "1") };
        save_domain_key(&path, &key).expect("override must permit downgrade");
        unsafe { std::env::remove_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV) };
    }
}
