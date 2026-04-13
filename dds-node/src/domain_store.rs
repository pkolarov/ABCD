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
const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;
/// Version 3: domain key encrypted with FIDO2 hmac-secret output.
/// The CBOR map stores `credential_id` (bytes) and `hmac_salt` (bytes)
/// alongside the encrypted key. No passphrase needed — touch the
/// FIDO2 key to decrypt.
const VERSION_FIDO2: u8 = 3;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainFile {
    pub name: String,
    /// `dds-dom:<base32>` form of the domain id.
    pub id: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub pubkey: String,
}

impl DomainFile {
    pub fn from_domain(domain: &Domain) -> Self {
        Self {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: to_hex(&domain.pubkey),
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
        let domain = Domain {
            name: self.name,
            id,
            pubkey,
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
    let f = DomainFile::from_domain(domain);
    let s = toml::to_string_pretty(&f).map_err(|e| DomainStoreError::Toml(e.to_string()))?;
    std::fs::write(path, s).map_err(|e| DomainStoreError::Io(e.to_string()))?;
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
    let secret = key.signing_key.to_bytes();
    let name = key.name.clone();

    let map = match std::env::var(DOMAIN_PASSPHRASE_ENV) {
        Ok(pass) if !pass.is_empty() => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let mut k = derive_key(pass.as_bytes(), &salt)?;
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
                (CborValue::Text("key".into()), CborValue::Bytes(ct)),
            ]
        }
        _ => {
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
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| DomainStoreError::Io(e.to_string()))?;
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
    for (k, v) in map.iter() {
        if let Some(n) = k.as_text() {
            match n {
                "v" => version = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "name" => name = v.as_text().map(|s| s.to_string()),
                "salt" => salt = v.as_bytes().cloned(),
                "nonce" => nonce = v.as_bytes().cloned(),
                "key" => key_field = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }
    let name = name.ok_or_else(|| DomainStoreError::Format("missing name".into()))?;
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
            let mut k = derive_key(pass.as_bytes(), &salt)?;
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
            let mut k = derive_key(&hmac_key, &salt)?;
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
    let bytes = cert
        .to_cbor()
        .map_err(|e| DomainStoreError::Cbor(e.to_string()))?;
    std::fs::write(path, &bytes).map_err(|e| DomainStoreError::Io(e.to_string()))?;
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

    let mut k = derive_key(&hmac_output, &salt)?;
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
    std::fs::write(path, &buf).map_err(|e| DomainStoreError::Io(e.to_string()))?;
    set_owner_only_permissions(path);

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

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], DomainStoreError> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
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
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
}
