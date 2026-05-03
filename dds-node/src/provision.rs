//! Single-file node provisioning — `.dds` bundle format.
//!
//! A provision bundle is a CBOR file containing all domain info + the
//! encrypted domain key. An admin creates it once, puts it on a USB
//! stick, and any new machine can self-provision with one command:
//!
//! ```text
//! dds-node provision /mnt/usb/acme.dds
//! # touch FIDO2 key → node is admitted, configured, enrolled, started
//! ```
//!
//! The domain key inside the bundle is FIDO2-encrypted (v3) and can
//! only be decrypted by the admin's physical hardware key. It is
//! decrypted in memory, used to sign an admission cert, then zeroed.
//! It never touches disk on the new machine.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborValue;
use dds_domain::Domain;
use dds_domain::DomainKey;
use dds_domain::domain::{DomainId, from_hex, to_hex};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{domain_store, identity_store, p2p_identity};

/// Current wire version. v3 bundles carry a mandatory Ed25519
/// signature over the canonical signing bytes, verified on load
/// against the embedded `domain_pubkey`. v4 (**SC-1 / Z-1 Phase A
/// follow-up**) extends the signed payload with the optional
/// `domain_pq_pubkey` (hex-encoded ML-DSA-65 public key) so a v2-hybrid
/// domain survives the bundle round-trip; the writer picks v3 vs. v4
/// based on whether `domain_pq_pubkey` is populated, so a v1 fleet
/// keeps emitting byte-identical v3 bundles.
const BUNDLE_VERSION: u64 = 4;
/// Minimum supported bundle version for read. v1 had no integrity
/// metadata; v2 carried a SHA-256 fingerprint but no signature; we
/// still read both but emit a warning because neither prevents a
/// bundle-signing-key swap on its own.
const MIN_READ_VERSION: u64 = 1;

// ---- Error type ----

#[derive(Debug)]
pub enum ProvisionError {
    Io(String),
    Cbor(String),
    Format(String),
    DomainStore(domain_store::DomainStoreError),
    AlreadyProvisioned,
    NodeStart(String),
    Enrollment(String),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::Io(e) => write!(f, "io: {e}"),
            ProvisionError::Cbor(e) => write!(f, "cbor: {e}"),
            ProvisionError::Format(e) => write!(f, "format: {e}"),
            ProvisionError::DomainStore(e) => write!(f, "domain: {e}"),
            ProvisionError::AlreadyProvisioned => {
                write!(f, "node already provisioned (admission.cbor exists)")
            }
            ProvisionError::NodeStart(e) => write!(f, "node start: {e}"),
            ProvisionError::Enrollment(e) => write!(f, "enrollment: {e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<domain_store::DomainStoreError> for ProvisionError {
    fn from(e: domain_store::DomainStoreError) -> Self {
        ProvisionError::DomainStore(e)
    }
}

// ---- Bundle ----

/// A provision bundle containing everything needed to join a domain.
#[derive(Debug, Clone)]
pub struct ProvisionBundle {
    pub domain_name: String,
    pub domain_id: String,
    pub domain_pubkey: String,
    /// **SC-1 / Z-1 Phase A** — hex-encoded ML-DSA-65 public key
    /// (1,952 bytes ⇒ 3,904 hex chars) when the issuing domain is
    /// v2-hybrid. `None` for legacy v1 (Ed25519-only) domains.
    /// When `Some`, the bundle is written / verified as v4 and is
    /// stamped into both the provisioned node's `domain.toml`
    /// (`pq_pubkey = "..."`) and `dds.toml` (`[domain].pq_pubkey =
    /// "..."`) so the new node starts as a v2-hybrid verifier and
    /// will reject any Ed25519-only admission cert / revocation.
    pub domain_pq_pubkey: Option<String>,
    pub domain_key_blob: Vec<u8>,
    pub org_hash: String,
    pub listen_port: u16,
    pub api_port: u16,
    pub mdns_enabled: bool,
    /// SHA-256 fingerprint of the integrity-bound metadata fields
    /// (domain_id + domain_pubkey + org_hash + ports + domain_key_blob,
    /// plus `domain_pq_pubkey` for v4). Populated on load for v2+
    /// bundles. Operators MUST confirm this fingerprint OUT-OF-BAND
    /// before importing; the in-bundle signature (v3+) catches the
    /// common tamper case where the metadata is altered without
    /// re-deriving a new domain key.
    pub fingerprint: String,
}

/// Pick the on-disk wire version for a bundle. v4 is used when (and
/// only when) the bundle carries `domain_pq_pubkey` (v2-hybrid
/// domain); v3 stays the default for legacy Ed25519-only domains so
/// existing fleets keep emitting byte-identical bundles.
fn wire_version(bundle: &ProvisionBundle) -> u64 {
    if bundle.domain_pq_pubkey.is_some() {
        4
    } else {
        3
    }
}

/// Canonical bytes covered by the bundle's signature and fingerprint.
/// Order is fixed; any field added in a future version must go AFTER
/// the existing fields. The version-distinct prefix
/// (`dds-bundle-v3|` vs. `dds-bundle-v4|`) prevents cross-version
/// signature replay — a v3 signature does not validate a v4 message
/// and vice versa. v4 appends the optional `domain_pq_pubkey` hex
/// (length-prefixed so an empty string and an absent field can never
/// collide). Includes `domain_key_blob` so a MITM swapping the
/// encrypted key for one they control invalidates the signature.
fn signing_bytes(bundle: &ProvisionBundle) -> Vec<u8> {
    let version = wire_version(bundle);
    let mut h = Sha256::new();
    match version {
        4 => h.update(b"dds-bundle-v4|"),
        _ => h.update(b"dds-bundle-v3|"),
    }
    h.update(bundle.domain_id.as_bytes());
    h.update(b"|");
    h.update(bundle.domain_pubkey.as_bytes());
    h.update(b"|");
    h.update(bundle.org_hash.as_bytes());
    h.update(b"|");
    h.update(bundle.listen_port.to_be_bytes());
    h.update(b"|");
    h.update(bundle.api_port.to_be_bytes());
    h.update(b"|");
    h.update([u8::from(bundle.mdns_enabled)]);
    h.update(b"|");
    h.update((bundle.domain_key_blob.len() as u64).to_be_bytes());
    h.update(&bundle.domain_key_blob);
    if version >= 4 {
        h.update(b"|");
        let pq_hex = bundle.domain_pq_pubkey.as_deref().unwrap_or("");
        h.update((pq_hex.len() as u64).to_be_bytes());
        h.update(pq_hex.as_bytes());
    }
    h.finalize().to_vec()
}

/// Save a v3 provision bundle to a `.dds` file, signed by `signer`
/// (the domain Ed25519 signing key).
///
/// **H-10 (security review)**: the bundle body is hashed via
/// `signing_bytes` and signed with the domain key. The verifying
/// pubkey embedded in `bundle.domain_pubkey` is what `load_bundle`
/// will verify against. Combined with the fingerprint printed on
/// both create and load paths, this defends against two distinct
/// attacks:
///
///   - Metadata tamper *without* key swap: signature verification
///     fails (because the same key signs a different message hash).
///   - Full swap including pubkey and signing key: signature verifies
///     against the attacker's key; the fingerprint changes; the
///     operator MUST detect the mismatch out-of-band via the
///     fingerprint that was printed at bundle-creation time.
pub fn save_bundle(
    path: &Path,
    bundle: &ProvisionBundle,
    signer: &DomainKey,
) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProvisionError::Io(e.to_string()))?;
    }
    // Sanity-check: the signer's pubkey must match the embedded
    // domain_pubkey, otherwise `load_bundle` would reject the bundle.
    let signer_pubkey_hex = to_hex(&signer.pubkey());
    if signer_pubkey_hex != bundle.domain_pubkey {
        return Err(ProvisionError::Format(format!(
            "signer pubkey ({signer_pubkey_hex}) does not match \
             bundle.domain_pubkey ({}) — refusing to write a bundle \
             that would fail verification on load",
            bundle.domain_pubkey
        )));
    }
    // **SC-1** — refuse to silently downgrade a v2-hybrid signer:
    // if the signing key carries an ML-DSA-65 half, the bundle MUST
    // carry the matching `domain_pq_pubkey`, and conversely a bundle
    // claiming a hybrid pubkey MUST be backed by a hybrid signer
    // whose ML-DSA-65 public key matches. (dds-domain is always built
    // with the `pq` feature in this workspace, so no cfg gate.)
    {
        let signer_pq_hex = signer.pq_pubkey_bytes().as_deref().map(to_hex);
        match (&signer_pq_hex, &bundle.domain_pq_pubkey) {
            (Some(_), None) => {
                return Err(ProvisionError::Format(
                    "signer is v2-hybrid (carries ML-DSA-65) but bundle.domain_pq_pubkey \
                     is None — refusing to write a v3 bundle that would silently downgrade \
                     the verifier side of single-file provisioning to Ed25519-only"
                        .into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ProvisionError::Format(
                    "bundle claims domain_pq_pubkey but signer is Ed25519-only — refusing \
                     to write a v4 bundle whose hybrid pubkey cannot be authenticated by \
                     the included signer"
                        .into(),
                ));
            }
            (Some(s), Some(b)) if s != b => {
                return Err(ProvisionError::Format(format!(
                    "signer pq_pubkey ({} chars) does not match bundle.domain_pq_pubkey \
                     ({} chars) — refusing to write an inconsistent hybrid bundle",
                    s.len(),
                    b.len()
                )));
            }
            _ => {}
        }
    }
    let fingerprint = compute_fingerprint(bundle);
    let msg = signing_bytes(bundle);
    let signature = signer.signing_key.sign(&msg).to_bytes().to_vec();
    let version = wire_version(bundle);

    let mut map = vec![
        (
            CborValue::Text("version".into()),
            CborValue::Integer(version.into()),
        ),
        (
            CborValue::Text("domain_name".into()),
            CborValue::Text(bundle.domain_name.clone()),
        ),
        (
            CborValue::Text("domain_id".into()),
            CborValue::Text(bundle.domain_id.clone()),
        ),
        (
            CborValue::Text("domain_pubkey".into()),
            CborValue::Text(bundle.domain_pubkey.clone()),
        ),
        (
            CborValue::Text("domain_key".into()),
            CborValue::Bytes(bundle.domain_key_blob.clone()),
        ),
        (
            CborValue::Text("org_hash".into()),
            CborValue::Text(bundle.org_hash.clone()),
        ),
        (
            CborValue::Text("listen_port".into()),
            CborValue::Integer(u64::from(bundle.listen_port).into()),
        ),
        (
            CborValue::Text("api_port".into()),
            CborValue::Integer(u64::from(bundle.api_port).into()),
        ),
        (
            CborValue::Text("mdns_enabled".into()),
            CborValue::Bool(bundle.mdns_enabled),
        ),
        (
            CborValue::Text("fingerprint".into()),
            CborValue::Text(fingerprint),
        ),
        (
            CborValue::Text("signature".into()),
            CborValue::Bytes(signature),
        ),
    ];
    // **SC-1** — v4 carries the hybrid domain PQ pubkey so the verifier
    // side of single-file provisioning is no longer silently downgraded
    // from v2-hybrid to v1.
    if let Some(pq_hex) = &bundle.domain_pq_pubkey {
        map.push((
            CborValue::Text("domain_pq_pubkey".into()),
            CborValue::Text(pq_hex.clone()),
        ));
    }
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| ProvisionError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| ProvisionError::Io(e.to_string()))?;
    // L-5 follow-on (security review): the provision bundle carries the
    // passphrase- or FIDO2-wrapped `domain_key_blob`, the domain pubkey,
    // org_hash, and an integrity signature — all sensitive provisioning
    // material, even though the key blob itself is encrypted. Restrict
    // the file to owner-only on Unix so a co-tenant can't read it and
    // attempt offline unwrap. Mirrors the same idiom applied to
    // `dds-cli export` and `dds-cli audit export --out`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// SHA-256 fingerprint over the same canonical signing bytes used
/// for the bundle signature. Operators confirm this value
/// out-of-band — it covers `domain_id`, `domain_pubkey`, `org_hash`,
/// ports, `mdns_enabled`, and `domain_key_blob` so that any
/// attacker-controlled substitution changes the fingerprint too.
fn compute_fingerprint(bundle: &ProvisionBundle) -> String {
    let digest = signing_bytes(bundle);
    let mut s = String::with_capacity(64);
    for b in &digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Load a provision bundle from a `.dds` file.
pub fn load_bundle(path: &Path) -> Result<ProvisionBundle, ProvisionError> {
    let bytes = std::fs::read(path).map_err(|e| ProvisionError::Io(e.to_string()))?;
    // Bounded depth: provision bundles originate from a separate
    // admin machine and travel as a file the operator drops in.
    // Security review I-6.
    let value: CborValue = dds_core::cbor_bounded::from_reader(&bytes[..])
        .map_err(|e| ProvisionError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ProvisionError::Format("not a CBOR map".into()))?;

    let get_text = |key: &str| -> Result<String, ProvisionError> {
        map.iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_text().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| ProvisionError::Format(format!("missing field: {key}")))
    };
    let get_u64 = |key: &str, default: u64| -> u64 {
        map.iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_integer().and_then(|i| u64::try_from(i).ok())
                } else {
                    None
                }
            })
            .unwrap_or(default)
    };
    let get_bool = |key: &str, default: bool| -> bool {
        map.iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_bool()
                } else {
                    None
                }
            })
            .unwrap_or(default)
    };
    let get_bytes = |key: &str| -> Result<Vec<u8>, ProvisionError> {
        map.iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some(key) {
                    v.as_bytes().cloned()
                } else {
                    None
                }
            })
            .ok_or_else(|| ProvisionError::Format(format!("missing field: {key}")))
    };

    let version = get_u64("version", 0);
    if !(MIN_READ_VERSION..=BUNDLE_VERSION).contains(&version) {
        return Err(ProvisionError::Format(format!(
            "unsupported bundle version {version} (supported {MIN_READ_VERSION}..={BUNDLE_VERSION})"
        )));
    }
    let stored_fingerprint: Option<String> = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("fingerprint") {
            v.as_text().map(|s| s.to_string())
        } else {
            None
        }
    });
    let stored_signature: Option<Vec<u8>> = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("signature") {
            v.as_bytes().cloned()
        } else {
            None
        }
    });

    // **SC-1** — v4 carries `domain_pq_pubkey`; older versions never
    // do, so a forged v3 bundle that bolts the field on still hashes
    // under the v3 prefix (which excludes pq_pubkey) and the field is
    // discarded on load. We additionally require that v1..v3 bundles
    // never carry the field (defense in depth against a downgrade
    // attempt that includes the field but uses the v3 prefix).
    let stored_pq_pubkey: Option<String> = map.iter().find_map(|(k, v)| {
        if k.as_text() == Some("domain_pq_pubkey") {
            v.as_text().map(|s| s.to_string())
        } else {
            None
        }
    });
    if version < 4 && stored_pq_pubkey.is_some() {
        return Err(ProvisionError::Format(format!(
            "v{version} bundle carries `domain_pq_pubkey` — only v4+ may include \
             a hybrid PQ key, refuse to import to prevent silent downgrade"
        )));
    }

    let bundle = ProvisionBundle {
        domain_name: get_text("domain_name")?,
        domain_id: get_text("domain_id")?,
        domain_pubkey: get_text("domain_pubkey")?,
        domain_pq_pubkey: if version >= 4 { stored_pq_pubkey } else { None },
        domain_key_blob: get_bytes("domain_key")?,
        org_hash: get_text("org_hash")?,
        listen_port: get_u64("listen_port", 4001) as u16,
        api_port: get_u64("api_port", 5551) as u16,
        mdns_enabled: get_bool("mdns_enabled", true),
        fingerprint: String::new(),
    };
    let computed_fingerprint = compute_fingerprint(&bundle);

    match version {
        4 | 3 => {
            // **H-10 (security review)**: v3 / v4 MUST carry a
            // signature and MUST carry the fingerprint. Both are
            // verified here; the caller then prints the fingerprint
            // for operator OOB confirmation. **SC-1**: v4 also folds
            // the optional `domain_pq_pubkey` into both the signed
            // bytes and the fingerprint via the bumped `dds-bundle-v4|`
            // prefix in [`signing_bytes`].
            let sig_bytes = stored_signature.ok_or_else(|| {
                ProvisionError::Format(format!(
                    "v{version} bundle missing signature field — refuse to import"
                ))
            })?;
            let stored = stored_fingerprint.ok_or_else(|| {
                ProvisionError::Format(format!(
                    "v{version} bundle missing fingerprint field — refuse to import"
                ))
            })?;
            if stored != computed_fingerprint {
                return Err(ProvisionError::Format(format!(
                    "bundle fingerprint mismatch: file claims {stored}, computed \
                     {computed_fingerprint}; the bundle has been tampered with"
                )));
            }
            // Verify the Ed25519 signature against the embedded pubkey.
            // This catches metadata tampering that re-computes the
            // fingerprint but does not have the domain signing key.
            let pk_bytes = from_hex(&bundle.domain_pubkey).map_err(|e| {
                ProvisionError::Format(format!("bundle domain_pubkey is not hex: {e}"))
            })?;
            if pk_bytes.len() != 32 {
                return Err(ProvisionError::Format(
                    "bundle domain_pubkey is not 32 bytes".into(),
                ));
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                ProvisionError::Format(format!("bundle domain_pubkey invalid: {e}"))
            })?;
            if sig_bytes.len() != 64 {
                return Err(ProvisionError::Format(
                    "bundle signature is not 64 bytes".into(),
                ));
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);
            let sig = Signature::from_bytes(&sig_arr);
            let msg = signing_bytes(&bundle);
            vk.verify(&msg, &sig).map_err(|_| {
                ProvisionError::Format(
                    "bundle signature does not verify against embedded domain_pubkey \
                     — the bundle has been tampered with or the pubkey was substituted"
                        .into(),
                )
            })?;
            Ok(ProvisionBundle {
                fingerprint: computed_fingerprint,
                ..bundle
            })
        }
        2 => {
            // v2 legacy: fingerprint but no signature.
            let stored = stored_fingerprint.ok_or_else(|| {
                ProvisionError::Format(
                    "v2 bundle is missing the fingerprint field — refuse to import".into(),
                )
            })?;
            if stored != computed_fingerprint {
                return Err(ProvisionError::Format(format!(
                    "bundle fingerprint mismatch: file claims {stored}, computed \
                     {computed_fingerprint}; the bundle has been tampered with"
                )));
            }
            tracing::warn!(
                "loading legacy v2 provision bundle (unsigned, fingerprint only); \
                 re-create with the current toolchain to get an Ed25519-signed v3 bundle"
            );
            Ok(ProvisionBundle {
                fingerprint: computed_fingerprint,
                ..bundle
            })
        }
        _ => {
            // v1: no integrity metadata at all.
            tracing::warn!(
                "loading legacy v1 provision bundle (no integrity metadata); \
                 confirm the displayed fingerprint out-of-band before trusting"
            );
            Ok(ProvisionBundle {
                fingerprint: computed_fingerprint,
                ..bundle
            })
        }
    }
}

// ---- Bundle creation ----

/// Create a provision bundle from the domain directory (after init-domain).
///
/// Unwraps the domain key from `<domain_dir>/domain_key.bin` (this
/// triggers the FIDO2 touch / passphrase prompt) so it can sign the
/// bundle body per H-10. If the operator cannot unwrap the key here,
/// the fallback is out of scope — they cannot create a v3 bundle
/// without access to the signing key.
pub fn create_bundle(
    domain_dir: &Path,
    org_hash: &str,
    out_path: &Path,
) -> Result<(), ProvisionError> {
    let domain_toml = domain_dir.join("domain.toml");
    let domain_key_bin = domain_dir.join("domain_key.bin");

    let domain = domain_store::load_domain_file(&domain_toml)?;
    let key_blob = std::fs::read(&domain_key_bin).map_err(|e| ProvisionError::Io(e.to_string()))?;
    // Unwrap the signing key (may prompt for passphrase / FIDO2 touch).
    let signer = domain_store::load_domain_key_from_bytes(&key_blob)?;

    // **SC-1** — preserve the hybrid pubkey through the bundle so the
    // verifier side of single-file provisioning is no longer silently
    // downgraded from v2-hybrid to v1.
    let domain_pq_pubkey = domain.pq_pubkey.as_deref().map(to_hex);
    let bundle = ProvisionBundle {
        domain_name: domain.name,
        domain_id: domain.id.to_string(),
        domain_pubkey: to_hex(&domain.pubkey),
        domain_pq_pubkey,
        domain_key_blob: key_blob,
        org_hash: org_hash.to_string(),
        listen_port: 4001,
        api_port: 5551,
        mdns_enabled: true,
        fingerprint: String::new(),
    };

    save_bundle(out_path, &bundle, &signer)?;
    // Zeroize the unwrapped signing key.
    let mut secret = signer.signing_key.to_bytes();
    secret.zeroize();
    drop(signer);

    // H-10 (security review): print the fingerprint so the operator
    // can confirm it out-of-band on the importing side.
    let fp = compute_fingerprint(&bundle);
    println!("Bundle integrity fingerprint: {fp}");
    println!("  Confirm this fingerprint on the importing host BEFORE provisioning.");
    Ok(())
}

// ---- Provisioning orchestrator ----

/// Result of a successful provisioning.
#[derive(Debug)]
pub struct ProvisionSummary {
    pub domain_name: String,
    pub domain_id: String,
    pub peer_id: String,
    pub device_urn: Option<String>,
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Default data directory for the current platform.
fn default_data_dir() -> PathBuf {
    match std::env::consts::OS {
        "macos" => PathBuf::from("/Library/Application Support/DDS/node-data"),
        "windows" => {
            let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
            PathBuf::from(pd).join("DDS").join("node-data")
        }
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".dds")
        }
    }
}

/// Default config directory (parent of data dir).
fn default_config_dir() -> PathBuf {
    match std::env::consts::OS {
        "macos" => PathBuf::from("/Library/Application Support/DDS"),
        "windows" => {
            let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
            PathBuf::from(pd).join("DDS")
        }
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".dds")
        }
    }
}

/// Provision this node from a bundle file.
///
/// This is the core "one command, one touch" flow:
/// 1. Load bundle
/// 2. Decrypt domain key (FIDO2 touch)
/// 3. Generate node identity + sign admission cert
/// 4. Write config files
/// 5. Optionally start the node and enroll the device
pub fn run_provision(
    bundle_path: &Path,
    data_dir: Option<&Path>,
    start_node: bool,
) -> Result<ProvisionSummary, ProvisionError> {
    // 1. Load bundle
    println!("[1/6] Loading provision bundle...");
    let bundle = load_bundle(bundle_path)?;
    println!("  Domain: {} ({})", bundle.domain_name, bundle.domain_id);
    // H-10 (security review): show the operator the integrity
    // fingerprint that was printed at bundle-creation time. They
    // MUST confirm it matches out-of-band before the provision
    // proceeds — the in-bundle signature alone cannot defend
    // against a full key-swap attack.
    println!("  Bundle fingerprint: {}", bundle.fingerprint);
    println!(
        "  >>> Confirm this fingerprint matches the one printed at \
         `dds-node create-provision-bundle` time BEFORE proceeding <<<"
    );

    // 2. Determine directories
    let data_dir = data_dir.map(PathBuf::from).unwrap_or_else(default_data_dir);
    let config_dir = data_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(default_config_dir);

    std::fs::create_dir_all(&data_dir).map_err(|e| ProvisionError::Io(e.to_string()))?;
    std::fs::create_dir_all(&config_dir).map_err(|e| ProvisionError::Io(e.to_string()))?;

    // Check for existing provisioning
    let admission_path = data_dir.join("admission.cbor");
    if admission_path.exists() {
        return Err(ProvisionError::AlreadyProvisioned);
    }

    // 3. Decrypt domain key (triggers FIDO2 touch for v3)
    println!("[2/6] Decrypting domain key...");
    println!("  >>> TOUCH YOUR FIDO2 KEY <<<");
    let domain_key = domain_store::load_domain_key_from_bytes(&bundle.domain_key_blob)?;
    println!("  Domain key decrypted.");

    // Verify domain key matches bundle
    let expected_id = DomainId::parse(&bundle.domain_id)
        .map_err(|e| ProvisionError::Format(format!("bad domain_id: {e}")))?;
    if domain_key.id() != expected_id {
        return Err(ProvisionError::Format(
            "domain key does not match bundle domain_id".into(),
        ));
    }

    // 4. Generate p2p identity + sign admission cert
    println!("[3/6] Generating node identity...");
    let p2p_path = data_dir.join("p2p_key.bin");
    let kp = p2p_identity::load_or_create(&p2p_path)
        .map_err(|e| ProvisionError::Io(format!("p2p key: {e}")))?;
    let peer_id = libp2p::PeerId::from(kp.public());
    println!("  Peer ID: {peer_id}");

    // PQ-DEFAULT-2: generate (or reload) the hybrid KEM keypair so the
    // admission cert carries pq_kem_pubkey on first connect — enc-v3
    // coverage is no longer 0% out of the box on hybrid domains.
    let epoch_keys_path = data_dir.join("epoch_keys.cbor");
    let needs_save = !epoch_keys_path.exists();
    let epoch_keys = {
        let mut rng = rand::thread_rng();
        crate::epoch_key_store::EpochKeyStore::load_or_create(&epoch_keys_path, &mut rng)
            .map_err(|e| ProvisionError::Io(format!("epoch_keys: {e}")))?
    };
    if needs_save {
        epoch_keys
            .save(&epoch_keys_path)
            .map_err(|e| ProvisionError::Io(format!("epoch_keys save: {e}")))?;
    }
    let kem_pubkey_bytes: Option<Vec<u8>> = if bundle.domain_pq_pubkey.is_some() {
        Some(epoch_keys.kem_public().to_bytes())
    } else {
        None
    };
    println!(
        "  KEM pubkey: {}",
        if kem_pubkey_bytes.is_some() {
            "set"
        } else {
            "not set (legacy domain)"
        }
    );

    let now = now_epoch();
    let ttl = 365 * 86400; // 1 year — re-provision or re-admit to renew
    let cert = domain_key.issue_admission_with_kem(
        peer_id.to_string(),
        now,
        Some(now + ttl),
        kem_pubkey_bytes,
    );

    // Zeroize domain key — never touches disk on this machine
    let mut secret = domain_key.signing_key.to_bytes();
    secret.zeroize();
    drop(domain_key);

    // 5. Write files
    println!("[4/6] Writing configuration...");

    // admission.cbor
    domain_store::save_admission_cert(&admission_path, &cert)?;

    // domain.toml
    let pk_bytes = from_hex(&bundle.domain_pubkey)
        .map_err(|e| ProvisionError::Format(format!("bad pubkey hex: {e}")))?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pk_bytes);
    // **SC-1** — propagate the hybrid PQ pubkey from the bundle so the
    // provisioned node starts as a v2-hybrid verifier (and therefore
    // rejects any Ed25519-only admission cert / revocation that targets
    // this domain).
    let pq_pubkey_bytes = match bundle.domain_pq_pubkey.as_deref() {
        Some(hex) if !hex.is_empty() => Some(
            from_hex(hex).map_err(|e| ProvisionError::Format(format!("bad pq_pubkey hex: {e}")))?,
        ),
        _ => None,
    };
    let domain = Domain {
        name: bundle.domain_name.clone(),
        id: expected_id,
        pubkey,
        pq_pubkey: pq_pubkey_bytes,
        // **Z-1 Phase B.3** — provisioning bundles do not yet ship
        // capabilities (no `enc-v3` flip at first install). Operators
        // populate `[domain].capabilities` post-provision once the v3
        // gate is ready to flip; the field defaults empty here.
        capabilities: Vec::new(),
    };
    // `verify_self_consistent` (called inside `save_domain_file ->
    // DomainFile::into_domain` round-trips below) catches a wrong
    // ML-DSA-65 length; do an early check too so we fail before
    // touching disk.
    domain
        .verify_self_consistent()
        .map_err(|e| ProvisionError::Format(format!("provisioned domain inconsistent: {e}")))?;
    domain_store::save_domain_file(&data_dir.join("domain.toml"), &domain)?;

    // node_key.bin — keep the Identity around so we can derive the
    // node Ed25519 pubkey for SC-3 (Policy Agent install-time pubkey
    // pinning). This is the same pubkey served by `/v1/node/info`,
    // computed locally without an HTTP round-trip.
    let node_ident = identity_store::load_or_create(&data_dir.join("node_key.bin"), "dds-node")
        .map_err(|e| ProvisionError::Io(format!("node key: {e}")))?;
    let node_pubkey_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(node_ident.signing_key.verifying_key().to_bytes())
    };
    drop(node_ident);

    // dds.toml — **SC-1**: when the bundle carries a hybrid pubkey,
    // stamp `pq_pubkey` into `[domain]` so `cmd_run` loads a v2-hybrid
    // verifier. Plain Ed25519 deployments emit a byte-identical config
    // to the pre-SC-1 layout.
    //
    // **SC-2**: on Unix the local API now defaults to a UDS instead of
    // anonymous loopback TCP. The Rust node's UDS listener extracts
    // peer credentials (`getpeereid` / `SO_PEERCRED`) on every accepted
    // connection so admin endpoints are gated on the caller's UID.
    // Pair the UDS with `[network.api_auth] trust_loopback_tcp_admin =
    // false` (refuse anonymous TCP fallbacks) and `strict_device_binding
    // = true` (M-8 step-2 — refuse Anonymous callers on device-scoped
    // reads). On Windows the same role is filled by the named-pipe
    // listener configured by the MSI; until single-file provisioning
    // grows pipe-first defaults too, the Windows branch keeps the
    // pre-SC-2 loopback TCP layout.
    let config_path = config_dir.join("dds.toml");
    #[cfg(unix)]
    let (api_addr_for_config, api_auth_block) = (
        format!("unix:{}", config_dir.join("dds.sock").display()),
        "\n[network.api_auth]\n\
         trust_loopback_tcp_admin = false\n\
         strict_device_binding = true\n"
            .to_string(),
    );
    #[cfg(not(unix))]
    let (api_addr_for_config, api_auth_block) =
        (format!("127.0.0.1:{}", bundle.api_port), String::new());
    let pq_pubkey_line = match bundle.domain_pq_pubkey.as_deref() {
        Some(hex) if !hex.is_empty() => format!("pq_pubkey = \"{hex}\"\n"),
        _ => String::new(),
    };
    // **Windows path escaping** — `data_dir` and `admission_path`
    // can be Windows-style (`C:\Users\...`) and TOML basic strings
    // (double-quoted) interpret backslashes as escape sequences, so
    // `\Users` looks like a malformed `\U` Unicode escape and the
    // re-load via `NodeConfig::from_str` panics. TOML *literal*
    // strings (single-quoted) take the bytes verbatim. Path values
    // never contain a single quote on either Windows or Unix, so
    // single-quote framing is safe across platforms.
    let config_content = format!(
        r#"# DDS Node Configuration — provisioned from bundle
data_dir = '{data_dir}'
org_hash = "{org_hash}"
trusted_roots = []

[network]
listen_addr = "/ip4/0.0.0.0/tcp/{listen_port}"
bootstrap_peers = []
mdns_enabled = {mdns}
heartbeat_secs = 5
idle_timeout_secs = 60
api_addr = "{api_addr}"

[domain]
name = "{domain_name}"
id = "{domain_id}"
pubkey = "{domain_pubkey}"
{pq_pubkey_line}admission_path = '{admission}'
audit_log_enabled = false
{api_auth_block}"#,
        data_dir = data_dir.display(),
        org_hash = bundle.org_hash,
        listen_port = bundle.listen_port,
        mdns = bundle.mdns_enabled,
        api_addr = api_addr_for_config,
        api_auth_block = api_auth_block,
        domain_name = bundle.domain_name,
        domain_id = bundle.domain_id,
        domain_pubkey = bundle.domain_pubkey,
        pq_pubkey_line = pq_pubkey_line,
        admission = admission_path.display(),
    );
    std::fs::write(&config_path, &config_content).map_err(|e| ProvisionError::Io(e.to_string()))?;
    println!("  Config: {}", config_path.display());

    // Verify no domain_key.bin leaked to data_dir
    assert!(
        !data_dir.join("domain_key.bin").exists(),
        "BUG: domain_key.bin should never be written to data_dir during provisioning"
    );

    let mut summary = ProvisionSummary {
        domain_name: bundle.domain_name.clone(),
        domain_id: bundle.domain_id.clone(),
        peer_id: peer_id.to_string(),
        device_urn: None,
        data_dir: data_dir.clone(),
        config_path: config_path.clone(),
    };

    // **SC-3** — stamp the node Ed25519 pubkey into the Policy Agent's
    // `appsettings.json` before we start the agent (start_platform_node
    // boots both `dds-node` and the policy-agent service). The agent's
    // `Program.cs` fails closed on an empty `PinnedNodePubkeyB64`, so
    // without this stamp the agent crash-loops until an operator
    // edits the file by hand. `DeviceUrn` is stamped later, after
    // enrollment returns the URN.
    match stamp_agent_appsettings(&config_dir, None, Some(&node_pubkey_b64)) {
        Ok(true) => {
            println!("  Pinned node pubkey into Policy Agent appsettings.json");
        }
        Ok(false) => {
            // Agent appsettings.json not present — single-file
            // provisioning on a host without the .NET Policy Agent
            // installed (developer / loadtest deploys). Leave a hint
            // so operators know how to wire it later.
            println!(
                "  No Policy Agent appsettings.json found; \
                 set PinnedNodePubkeyB64 manually if you install the agent later"
            );
        }
        Err(e) => {
            // Stamp is best-effort: a malformed appsettings.json must
            // not abort provisioning, the operator can fix it
            // separately.
            println!("  Warning: could not pin node pubkey: {e}");
        }
    }

    // 6. Start node and enroll (if requested)
    if start_node {
        println!("[5/6] Starting node...");
        start_platform_node(&config_path)?;

        // Wait for health. SC-2: on Unix the API binds a UDS, so we
        // route both the readiness check and the enrollment POST
        // through `curl --unix-socket`. On Windows the loopback TCP
        // fallback still applies.
        let api_addr: ApiAddr = api_addr_for_config.as_str().into();
        print!("  Waiting for node...");
        let mut ready = false;
        for _ in 0..30 {
            if api_addr.status_check() {
                println!(" ready!");
                ready = true;
                break;
            }
            print!(".");
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if !ready {
            println!(" timeout (node may still be starting)");
        }

        // Enroll device
        if ready {
            println!("[6/6] Enrolling this device...");
            match enroll_this_device(&api_addr, &bundle.org_hash) {
                Ok(urn) => {
                    println!("  Device URN: {urn}");
                    // **SC-3** — stamp the freshly-issued device URN into
                    // the agent's appsettings.json so the next agent
                    // start (LaunchDaemon KeepAlive on macOS, SCM auto-
                    // start on Windows) finds both pinning fields
                    // populated. The agent self-restarts on launchd
                    // KeepAlive, so we also kickstart explicitly to
                    // avoid waiting out the back-off window.
                    match stamp_agent_appsettings(&config_dir, Some(&urn), None) {
                        Ok(true) => {
                            println!("  Stamped DeviceUrn into Policy Agent appsettings.json");
                            kickstart_policy_agent();
                        }
                        Ok(false) => {
                            println!(
                                "  No Policy Agent appsettings.json found to stamp DeviceUrn; \
                                 set DdsPolicyAgent.DeviceUrn manually after installing the agent"
                            );
                        }
                        Err(e) => {
                            println!("  Warning: could not stamp DeviceUrn: {e}");
                        }
                    }
                    summary.device_urn = Some(urn);
                }
                Err(e) => {
                    println!("  Enrollment failed (can retry later): {e}");
                }
            }
        }
    } else {
        println!("[5/6] Skipping node start (--no-start)");
        println!("[6/6] Skipping device enrollment");
    }

    Ok(summary)
}

/// **SC-3** — best-effort restart of the Policy Agent service after
/// `appsettings.json` was rewritten with a fresh `DeviceUrn`. Failure
/// is silent because the macOS LaunchDaemon already has
/// `KeepAlive=true` and the Windows service will be restarted by SCM
/// after the next boot anyway; this just shortens the window between
/// stamp-time and first-successful-poll.
fn kickstart_policy_agent() {
    match std::env::consts::OS {
        "macos" => {
            let _ = std::process::Command::new("launchctl")
                .args(["kickstart", "-k", "system/com.dds.policyagent"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        "windows" => {
            let _ = std::process::Command::new("sc")
                .args(["stop", "DdsPolicyAgent"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = std::process::Command::new("sc")
                .args(["start", "DdsPolicyAgent"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        _ => {}
    }
}

fn start_platform_node(config_path: &Path) -> Result<(), ProvisionError> {
    match std::env::consts::OS {
        "macos" => {
            // Enable and bootstrap the LaunchDaemon for dds-node
            let _ = std::process::Command::new("launchctl")
                .args(["enable", "system/com.dds.node"])
                .status();
            let status = std::process::Command::new("launchctl")
                .args([
                    "bootstrap",
                    "system",
                    "/Library/LaunchDaemons/com.dds.node.plist",
                ])
                .status()
                .map_err(|e| ProvisionError::NodeStart(e.to_string()))?;
            if !status.success() {
                // May already be bootstrapped; try kickstart
                let _ = std::process::Command::new("launchctl")
                    .args(["kickstart", "-k", "system/com.dds.node"])
                    .status();
            }

            // Also start the policy agent (mirrors Windows MSI which auto-starts
            // both DdsNode and DdsPolicyAgent services)
            let palist_path = "/Library/LaunchDaemons/com.dds.policyagent.plist";
            if std::path::Path::new(palist_path).exists() {
                let _ = std::process::Command::new("launchctl")
                    .args(["enable", "system/com.dds.policyagent"])
                    .status();
                let pa_status = std::process::Command::new("launchctl")
                    .args(["bootstrap", "system", palist_path])
                    .status();
                if pa_status.map(|s| !s.success()).unwrap_or(true) {
                    let _ = std::process::Command::new("launchctl")
                        .args(["kickstart", "-k", "system/com.dds.policyagent"])
                        .status();
                }
            }
            Ok(())
        }
        "windows" => {
            let status = std::process::Command::new("sc")
                .args(["start", "DdsNode"])
                .status()
                .map_err(|e| ProvisionError::NodeStart(e.to_string()))?;
            if !status.success() {
                // Service might not be installed yet; try direct start
                let _ = std::process::Command::new("dds-node")
                    .args(["run", &config_path.to_string_lossy()])
                    .spawn()
                    .map_err(|e| ProvisionError::NodeStart(e.to_string()))?;
            }
            // Also start the policy agent if installed
            let _ = std::process::Command::new("sc")
                .args(["start", "DdsPolicyAgent"])
                .status();
            Ok(())
        }
        _ => {
            // Start in background
            let _child = std::process::Command::new("dds-node")
                .args(["run", &config_path.to_string_lossy()])
                .spawn()
                .map_err(|e| ProvisionError::NodeStart(e.to_string()))?;
            Ok(())
        }
    }
}

/// Local-API address the readiness check and enrollment POST need to
/// reach. SC-2 introduced `unix:` defaults on Unix, so the `curl`
/// invocation has to switch to `--unix-socket`.
enum ApiAddr {
    /// `unix:/path/to/sock` — pass `/path/to/sock` to `curl --unix-socket`,
    /// then any HTTP URL works as the request target (we use
    /// `http://localhost/...`).
    Unix(String),
    /// Plain `host:port` — passed through as `http://host:port/...`.
    Tcp(String),
}

impl From<&str> for ApiAddr {
    fn from(addr: &str) -> Self {
        if let Some(path) = addr.strip_prefix("unix:") {
            ApiAddr::Unix(path.to_string())
        } else {
            ApiAddr::Tcp(addr.to_string())
        }
    }
}

impl ApiAddr {
    fn curl_args<'a>(&'a self, target_path: &'a str) -> (Option<&'a str>, String) {
        match self {
            ApiAddr::Unix(sock) => (
                Some(sock.as_str()),
                format!("http://localhost{target_path}"),
            ),
            ApiAddr::Tcp(hp) => (None, format!("http://{hp}{target_path}")),
        }
    }

    fn status_check(&self) -> bool {
        let (sock, url) = self.curl_args("/v1/status");
        let mut cmd = std::process::Command::new("curl");
        cmd.arg("-sf");
        if let Some(s) = sock {
            cmd.args(["--unix-socket", s]);
        }
        cmd.arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn enroll_this_device(api_addr: &ApiAddr, org_hash: &str) -> Result<String, ProvisionError> {
    let hostname = gethostname();
    let os_name = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    };
    let device_id = format!("DDS-{}-{}", os_name.to_uppercase(), hostname.to_uppercase());

    let body = format!(
        r#"{{"label":"{}","device_id":"{}","hostname":"{}","os":"{}","os_version":"{}","tpm_ek_hash":null,"org_unit":"{}","tags":["auto-provisioned"]}}"#,
        hostname,
        device_id,
        hostname,
        os_name,
        std::env::consts::ARCH,
        org_hash
    );

    let (sock, url) = api_addr.curl_args("/v1/enroll/device");
    let mut cmd = std::process::Command::new("curl");
    cmd.arg("-sf");
    if let Some(s) = sock {
        cmd.args(["--unix-socket", s]);
    }
    let output = cmd
        .args([
            "-X",
            "POST",
            &url,
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
        ])
        .output()
        .map_err(|e| ProvisionError::Enrollment(e.to_string()))?;

    if !output.status.success() {
        return Err(ProvisionError::Enrollment(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let resp = String::from_utf8_lossy(&output.stdout);
    // Extract "urn" field from JSON response
    if let Some(start) = resp.find("\"urn\":\"") {
        let rest = &resp[start + 7..];
        if let Some(end) = rest.find('"') {
            return Ok(rest[..end].to_string());
        }
    }
    Err(ProvisionError::Enrollment(format!(
        "could not parse device URN from response: {resp}"
    )))
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// **SC-3** — locate the Policy Agent's `appsettings.json` so
/// `run_provision` can stamp install-time pinning fields
/// (`PinnedNodePubkeyB64`, `DeviceUrn`) before the agent first reads
/// its config. Without these the agent fails closed at startup
/// (`Program.cs` validates both at host build time), so an
/// unprovisioned packaged install never enforces policy or software
/// assignments.
///
/// On macOS the install layout copies `appsettings.json` into the
/// shared config dir (`/Library/Application Support/DDS/`) which is
/// the parent of the node `data_dir`, so probing `<config_dir>/
/// appsettings.json` finds it. On Windows the MSI puts it under
/// `%ProgramFiles%\DDS\config\` which is *not* the same as the
/// node's `%ProgramData%\DDS\` — we probe the standard MSI path as a
/// fallback.
fn agent_appsettings_path(config_dir: &Path) -> Option<PathBuf> {
    let primary = config_dir.join("appsettings.json");
    if primary.exists() {
        return Some(primary);
    }
    if cfg!(windows) {
        if let Ok(pf) = std::env::var("ProgramFiles") {
            let p = PathBuf::from(pf)
                .join("DDS")
                .join("config")
                .join("appsettings.json");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// **SC-3** — stamp Policy Agent install-time pinning into
/// `appsettings.json`. Updates the `DdsPolicyAgent` section in place,
/// preserving every other key (logging settings, RequirePackageSignature
/// on macOS, etc). Either field may be `None` to leave it untouched —
/// the caller stamps the node pubkey before starting the node and
/// stamps the device URN after enrollment, so the field is updated as
/// each value becomes available.
///
/// Returns `Ok(true)` when the file existed and was rewritten,
/// `Ok(false)` when no agent config was found (legitimate on hosts
/// without the agent installed). Errors propagate as `ProvisionError`.
pub fn stamp_agent_appsettings(
    config_dir: &Path,
    device_urn: Option<&str>,
    node_pubkey_b64: Option<&str>,
) -> Result<bool, ProvisionError> {
    let path = match agent_appsettings_path(config_dir) {
        Some(p) => p,
        None => return Ok(false),
    };

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| ProvisionError::Io(format!("read {}: {e}", path.display())))?;
    // Tolerate a UTF-8 BOM at the start of appsettings.json. PowerShell
    // 5.1's `Set-Content -Encoding UTF8` writes a BOM by default, and
    // operator scripts (Bootstrap-DdsDomain.ps1, GUI tools) commonly
    // re-stamp this file from PS — without this strip, the next
    // CA_StampAgentPubkey on MSI re-install fails with
    //   parse appsettings.json: expected value at line 1 column 1
    let raw = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);
    let mut root: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| ProvisionError::Format(format!("parse {}: {e}", path.display())))?;

    let agent = root
        .as_object_mut()
        .ok_or_else(|| ProvisionError::Format(format!("{} is not a JSON object", path.display())))?
        .entry("DdsPolicyAgent".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            ProvisionError::Format(format!(
                "{}: DdsPolicyAgent is not a JSON object",
                path.display()
            ))
        })?;

    if let Some(urn) = device_urn {
        agent.insert("DeviceUrn".into(), serde_json::Value::String(urn.into()));
    }
    if let Some(pk) = node_pubkey_b64 {
        agent.insert(
            "PinnedNodePubkeyB64".into(),
            serde_json::Value::String(pk.into()),
        );
    }

    let mut out = serde_json::to_string_pretty(&root)
        .map_err(|e| ProvisionError::Format(format!("serialize {}: {e}", path.display())))?;
    out.push('\n');
    std::fs::write(&path, &out)
        .map_err(|e| ProvisionError::Io(format!("write {}: {e}", path.display())))?;
    Ok(true)
}

/// **SC-3-W** — derive the node Ed25519 pubkey from `<data_dir>/node_key.bin`
/// (creating the identity if it does not yet exist) and stamp it into the
/// Policy Agent's `appsettings.json`. Used by the Windows MSI custom action
/// `CA_StampAgentPubkey` so a fresh MSI install ships the pinning field
/// populated *before* the Policy Agent first starts; the agent fails closed
/// on an empty `PinnedNodePubkeyB64`, so without this stamp the SCM auto-
/// start would crash-loop until an operator either runs single-file
/// `dds-node provision` or hand-edits the JSON.
///
/// `config_dir` points at the directory holding `appsettings.json` (the
/// Windows MSI passes `[INSTALLFOLDER]config`). [`stamp_agent_appsettings`]
/// falls back to `%ProgramFiles%\DDS\config\appsettings.json` on Windows
/// when the primary probe does not find the file. Returns `true` when the
/// file existed and was rewritten, `false` when no agent config could be
/// located (legitimate on hosts without the .NET agent installed — the MSI
/// custom action treats this as success so dev/loadtest installs proceed
/// cleanly). `DeviceUrn` is intentionally **not** stamped here: it is only
/// known after enrollment with a domain, which is not part of the MSI
/// install path.
pub fn stamp_pubkey(data_dir: &Path, config_dir: &Path) -> Result<bool, ProvisionError> {
    use base64::Engine as _;

    std::fs::create_dir_all(data_dir)
        .map_err(|e| ProvisionError::Io(format!("create data_dir {}: {e}", data_dir.display())))?;

    let key_path = data_dir.join("node_key.bin");
    let ident = identity_store::load_or_create(&key_path, "dds-node")
        .map_err(|e| ProvisionError::Io(format!("node key: {e}")))?;
    let node_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(ident.signing_key.verifying_key().to_bytes());
    drop(ident);

    stamp_agent_appsettings(config_dir, None, Some(&node_pubkey_b64))
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use dds_domain::DomainKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    use crate::TEST_ENV_LOCK as ENV_LOCK;

    #[test]
    fn bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.dds");
        let key = DomainKey::generate("test.local", &mut OsRng);
        let domain = key.domain();

        let bundle = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: None,
            domain_key_blob: vec![1, 2, 3, 4],
            org_hash: "test-org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };

        save_bundle(&path, &bundle, &key).unwrap();
        let loaded = load_bundle(&path).unwrap();
        assert!(
            !loaded.fingerprint.is_empty(),
            "fingerprint populated on load"
        );
        assert_eq!(loaded.fingerprint, compute_fingerprint(&bundle));

        assert_eq!(loaded.domain_name, domain.name);
        assert_eq!(loaded.domain_id, domain.id.to_string());
        assert_eq!(loaded.domain_key_blob, vec![1, 2, 3, 4]);
        assert_eq!(loaded.org_hash, "test-org");
        assert_eq!(loaded.listen_port, 4001);
        assert_eq!(loaded.api_port, 5551);
        assert!(loaded.mdns_enabled);
        assert!(loaded.domain_pq_pubkey.is_none());
        // Ed25519-only domain ⇒ writer picks v3 (byte-identical to
        // the pre-SC-1 layout). Verify the on-disk version field.
        let raw = std::fs::read(&path).unwrap();
        let cbor: CborValue = ciborium::from_reader(&raw[..]).unwrap();
        let v = cbor
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("version") {
                    v.as_integer().and_then(|i| u64::try_from(i).ok())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(v, 3, "ed25519-only bundle stays at v3");
    }

    /// L-5 follow-on regression: the provision bundle file carries the
    /// passphrase-/FIDO2-wrapped domain key blob and other sensitive
    /// provisioning metadata; mirror the `dds export` / `dds-cli audit
    /// export --out` idiom and pin owner-only on Unix.
    #[cfg(unix)]
    #[test]
    fn save_bundle_writes_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("owner-only.dds");
        let key = DomainKey::generate("test.local", &mut OsRng);
        let domain = key.domain();
        let bundle = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: None,
            domain_key_blob: vec![1, 2, 3, 4],
            org_hash: "test-org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        save_bundle(&path, &bundle, &key).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bundle file must be owner-only (0o600)");
    }

    /// H-10 regression: a bundle whose signature doesn't match the
    /// embedded pubkey must be rejected.
    #[test]
    fn bundle_rejects_tampered_signature() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tampered.dds");
        let key = DomainKey::generate("test.local", &mut OsRng);
        let domain = key.domain();

        let bundle = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: None,
            domain_key_blob: vec![1, 2, 3, 4],
            org_hash: "test-org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        save_bundle(&path, &bundle, &key).unwrap();

        // Flip a byte in the signature.
        let bytes = std::fs::read(&path).unwrap();
        let value: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
        let mut map = value.into_map().unwrap();
        for (k, v) in map.iter_mut() {
            if k.as_text() == Some("signature") {
                if let CborValue::Bytes(b) = v {
                    b[0] ^= 0xFF;
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let err = load_bundle(&path).unwrap_err();
        assert!(
            err.to_string().contains("signature does not verify"),
            "expected signature verification error, got: {err}"
        );
    }

    /// H-10 regression: if the attacker substitutes a whole new key
    /// (both pubkey and signature re-derived with it) the signature
    /// verifies, but the fingerprint changes — operator OOB check
    /// is the last line of defense. We verify the fingerprint
    /// genuinely differs between the two signers.
    #[test]
    fn bundle_fingerprint_diverges_under_key_swap() {
        let dir = TempDir::new().unwrap();
        let legit = DomainKey::generate("legit", &mut OsRng);
        let attacker = DomainKey::generate("attacker", &mut OsRng);

        let b1 = ProvisionBundle {
            domain_name: "x".into(),
            domain_id: legit.id().to_string(),
            domain_pubkey: to_hex(&legit.pubkey()),
            domain_pq_pubkey: None,
            domain_key_blob: vec![1, 2, 3],
            org_hash: "org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        let b2 = ProvisionBundle {
            domain_pubkey: to_hex(&attacker.pubkey()),
            domain_id: attacker.id().to_string(),
            ..b1.clone()
        };
        // Each bundle signs cleanly with ITS key but the fingerprints
        // differ — operator OOB would catch the swap.
        let p1 = dir.path().join("legit.dds");
        let p2 = dir.path().join("attacker.dds");
        save_bundle(&p1, &b1, &legit).unwrap();
        save_bundle(&p2, &b2, &attacker).unwrap();
        let l1 = load_bundle(&p1).unwrap();
        let l2 = load_bundle(&p2).unwrap();
        assert_ne!(l1.fingerprint, l2.fingerprint);
    }

    #[test]
    fn bundle_rejects_unknown_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.dds");

        let map = vec![(
            CborValue::Text("version".into()),
            CborValue::Integer(99i64.into()),
        )];
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let err = load_bundle(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported bundle version"));
    }

    /// H-10 regression: if a v2 bundle has a fingerprint that does not
    /// match the other metadata, loading must fail.
    #[test]
    fn bundle_rejects_tampered_fingerprint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tampered.dds");

        // Build a legitimate bundle, then corrupt the stored fingerprint.
        let map = vec![
            (
                CborValue::Text("version".into()),
                CborValue::Integer(2i64.into()),
            ),
            (
                CborValue::Text("domain_name".into()),
                CborValue::Text("test.local".into()),
            ),
            (
                CborValue::Text("domain_id".into()),
                CborValue::Text("dds-dom:aaaa".into()),
            ),
            (
                CborValue::Text("domain_pubkey".into()),
                CborValue::Text("ff".repeat(32)),
            ),
            (
                CborValue::Text("domain_key".into()),
                CborValue::Bytes(vec![1, 2, 3]),
            ),
            (
                CborValue::Text("org_hash".into()),
                CborValue::Text("org".into()),
            ),
            (
                CborValue::Text("listen_port".into()),
                CborValue::Integer(4001u64.into()),
            ),
            (
                CborValue::Text("api_port".into()),
                CborValue::Integer(5551u64.into()),
            ),
            (
                CborValue::Text("mdns_enabled".into()),
                CborValue::Bool(true),
            ),
            (
                CborValue::Text("fingerprint".into()),
                // Deliberately wrong.
                CborValue::Text("00".repeat(32)),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let err = load_bundle(&path).unwrap_err();
        assert!(
            err.to_string().contains("fingerprint mismatch"),
            "expected fingerprint mismatch error, got: {err}"
        );
    }

    #[test]
    fn provision_with_plain_domain_key() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        // Create a domain key (plain, no passphrase).
        // Use set_var to "" rather than remove_var to avoid racing
        // other tests that check this env var.
        unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
        // Sibling test in p2p_identity::tests holds a different lock
        // (`PASSPHRASE_ENV_LOCK`) and may have set this env var without
        // unsetting it before our `ENV_LOCK` was acquired. Clear it so
        // the plaintext save we exercise here is not gated.
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        let key = DomainKey::generate("provision-test", &mut OsRng);
        let domain = key.domain();
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        // Create bundle
        let bundle_path = dir.path().join("test.dds");
        create_bundle(&domain_dir, "test-org", &bundle_path).unwrap();
        assert!(bundle_path.exists());

        // Provision (no start, no enrollment)
        let data_dir = dir.path().join("node-data");
        let result = run_provision(&bundle_path, Some(&data_dir), false).unwrap();

        assert_eq!(result.domain_name, "provision-test");
        assert!(!result.peer_id.is_empty());
        assert!(data_dir.join("admission.cbor").exists());
        assert!(data_dir.join("domain.toml").exists());
        assert!(data_dir.join("p2p_key.bin").exists());
        assert!(data_dir.join("node_key.bin").exists());
        assert!(!data_dir.join("domain_key.bin").exists()); // never written

        // Config written
        let config = std::fs::read_to_string(&result.config_path).unwrap();
        assert!(config.contains("provision-test"));
        assert!(config.contains("test-org"));
    }

    /// **SC-2** — single-file provisioning emits UDS-first defaults
    /// on Unix: `api_addr` points at a `unix:` socket inside the
    /// config dir and `[network.api_auth]` flips
    /// `trust_loopback_tcp_admin = false` + `strict_device_binding =
    /// true`. On Windows the legacy loopback TCP layout still applies
    /// (the named-pipe MSI handles the equivalent role there) and the
    /// `[network.api_auth]` block must NOT appear.
    ///
    /// The domain key is saved under an explicit passphrase so the
    /// test stays green even when `DDS_REQUIRE_ENCRYPTED_KEYS` happens
    /// to be set by a sibling test running concurrently under the
    /// `PASSPHRASE_ENV_LOCK` (a separate mutex from the `ENV_LOCK`
    /// we hold here — see `identity_store::PASSPHRASE_ENV_LOCK` and
    /// `crate::TEST_ENV_LOCK`).
    #[test]
    fn provision_writes_uds_first_api_defaults() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "sc2-test-pass") };
        let key = DomainKey::generate("sc2-test", &mut OsRng);
        let domain = key.domain();
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        let bundle_path = dir.path().join("test.dds");
        create_bundle(&domain_dir, "sc2-org", &bundle_path).unwrap();

        let data_dir = dir.path().join("node-data");
        let result = run_provision(&bundle_path, Some(&data_dir), false).unwrap();

        let cfg = std::fs::read_to_string(&result.config_path).unwrap();

        // SC-2 also re-loads the emitted dds.toml through the real
        // parser so a typo in the [network.api_auth] block would fail
        // the test rather than silently regress.
        let parsed = crate::config::NodeConfig::from_str(&cfg).unwrap();

        #[cfg(unix)]
        {
            let expected_sock = data_dir
                .parent()
                .expect("config_dir = data_dir.parent()")
                .join("dds.sock");
            assert_eq!(
                parsed.network.api_addr,
                format!("unix:{}", expected_sock.display()),
                "Unix provisioning must default to unix: socket api_addr; got: {}",
                parsed.network.api_addr
            );
            assert!(
                !parsed.network.api_auth.trust_loopback_tcp_admin,
                "Unix provisioning must disable trust_loopback_tcp_admin"
            );
            assert!(
                parsed.network.api_auth.strict_device_binding,
                "Unix provisioning must enable strict_device_binding"
            );
            assert!(
                cfg.contains("[network.api_auth]"),
                "Unix provisioning must emit [network.api_auth] block; got:\n{cfg}"
            );
        }
        #[cfg(not(unix))]
        {
            assert!(
                parsed.network.api_addr.starts_with("127.0.0.1:"),
                "Windows provisioning keeps loopback TCP api_addr; got: {}",
                parsed.network.api_addr
            );
            assert!(
                parsed.network.api_auth.trust_loopback_tcp_admin,
                "Windows provisioning keeps trust_loopback_tcp_admin = true \
                 until single-file provisioning grows pipe-first defaults"
            );
            assert!(
                !cfg.contains("[network.api_auth]"),
                "Windows provisioning must not emit [network.api_auth] block; got:\n{cfg}"
            );
        }

        unsafe { std::env::remove_var("DDS_DOMAIN_PASSPHRASE") };
    }

    #[test]
    fn provision_refuses_double() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::remove_var("DDS_DOMAIN_PASSPHRASE") };
        // See provision_with_plain_domain_key: a sibling p2p_identity
        // test under `PASSPHRASE_ENV_LOCK` may have left this set.
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        let key = DomainKey::generate("double-test", &mut OsRng);
        let domain = key.domain();
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        let bundle_path = dir.path().join("test.dds");
        create_bundle(&domain_dir, "org", &bundle_path).unwrap();

        let data_dir = dir.path().join("node-data");
        run_provision(&bundle_path, Some(&data_dir), false).unwrap();

        // Second provision should fail
        let err = run_provision(&bundle_path, Some(&data_dir), false).unwrap_err();
        assert!(matches!(err, ProvisionError::AlreadyProvisioned));
    }

    // ---- SC-1 (Z-1 Phase A follow-up) — hybrid bundle round-trip ----
    //
    // The four tests below cover the gap STATUS.md lists as SC-1:
    // single-file provisioning silently downgraded a v2-hybrid domain
    // to a v1 verifier because `ProvisionBundle` did not carry
    // `domain_pq_pubkey`. The fix bumps the bundle wire to v4 and
    // pipes the hybrid pubkey through `create_bundle` →
    // `run_provision` so the provisioned `domain.toml` and `dds.toml`
    // both keep the ML-DSA-65 component.

    /// **SC-1**: a v2-hybrid bundle round-trips its `domain_pq_pubkey`,
    /// the on-disk version is v4, and tampering with the embedded PQ
    /// pubkey is caught by the v4 signature.
    #[test]

    fn hybrid_bundle_roundtrip_preserves_pq_pubkey() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hybrid.dds");
        let key = DomainKey::generate_hybrid("hybrid.local", &mut OsRng);
        let domain = key.domain();
        let pq_hex = to_hex(domain.pq_pubkey.as_ref().expect("hybrid domain"));

        let bundle = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: Some(pq_hex.clone()),
            domain_key_blob: vec![1, 2, 3, 4],
            org_hash: "hybrid-org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };

        save_bundle(&path, &bundle, &key).unwrap();

        // On-disk version is v4 (writer picks v4 when pq_pubkey is set).
        let raw = std::fs::read(&path).unwrap();
        let cbor: CborValue = ciborium::from_reader(&raw[..]).unwrap();
        let v = cbor
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                if k.as_text() == Some("version") {
                    v.as_integer().and_then(|i| u64::try_from(i).ok())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(v, 4, "hybrid bundle uses v4 wire");

        let loaded = load_bundle(&path).unwrap();
        assert_eq!(loaded.domain_pq_pubkey.as_deref(), Some(pq_hex.as_str()));

        // Tamper with the stored pq_pubkey but keep the original
        // signature; v4 includes pq in the signed bytes so verify
        // must fail (this is exactly the silent-downgrade defence).
        let mut map = cbor.into_map().unwrap();
        for (k, v) in map.iter_mut() {
            if k.as_text() == Some("domain_pq_pubkey") {
                if let CborValue::Text(s) = v {
                    // Flip the first hex digit ('a'..'f' rotate by 1
                    // stays in-set so the field still parses as hex).
                    let mut bytes = s.as_bytes().to_vec();
                    bytes[0] = match bytes[0] {
                        b'0'..=b'8' => bytes[0] + 1,
                        b'9' => b'0',
                        b'a'..=b'e' => bytes[0] + 1,
                        b'f' => b'a',
                        _ => bytes[0] ^ 0x01,
                    };
                    *s = String::from_utf8(bytes).unwrap();
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        let err = load_bundle(&path).unwrap_err();
        assert!(
            err.to_string().contains("signature does not verify")
                || err.to_string().contains("fingerprint mismatch"),
            "expected v4 to detect pq_pubkey tamper, got: {err}"
        );
    }

    /// **SC-1**: an attacker tries the silent downgrade by forging a
    /// v3 bundle that bolts a `domain_pq_pubkey` field onto the CBOR
    /// map. The v3 prefix in `signing_bytes` excludes pq, so
    /// signature verification would still pass — load_bundle must
    /// instead refuse the bundle outright.
    #[test]
    fn bundle_rejects_v3_with_pq_pubkey_field() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("smuggled.dds");
        let key = DomainKey::generate("v3-smuggle", &mut OsRng);
        let domain = key.domain();

        // Build a legitimate v3 bundle, then bolt on `domain_pq_pubkey`.
        let bundle = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: None,
            domain_key_blob: vec![9, 8, 7],
            org_hash: "org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        save_bundle(&path, &bundle, &key).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let cbor: CborValue = ciborium::from_reader(&raw[..]).unwrap();
        let mut map = cbor.into_map().unwrap();
        map.push((
            CborValue::Text("domain_pq_pubkey".into()),
            CborValue::Text("ab".repeat(1952)),
        ));
        let mut buf = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let err = load_bundle(&path).unwrap_err();
        assert!(
            err.to_string().contains("only v4+ may include"),
            "expected silent-downgrade rejection, got: {err}"
        );
    }

    /// **SC-1**: `save_bundle` refuses to write a bundle whose
    /// signer/bundle pq state disagree (signer is hybrid but bundle
    /// claims no pq, or vice versa). This is the producer-side gate
    /// that would have prevented the original SC-1 gap from being
    /// reachable through the toolchain.
    #[test]

    fn save_bundle_refuses_signer_bundle_pq_mismatch() {
        let dir = TempDir::new().unwrap();
        let hybrid = DomainKey::generate_hybrid("hybrid.local", &mut OsRng);
        let domain = hybrid.domain();

        // Hybrid signer but bundle drops the pq_pubkey ⇒ refused.
        let bad = ProvisionBundle {
            domain_name: domain.name.clone(),
            domain_id: domain.id.to_string(),
            domain_pubkey: to_hex(&domain.pubkey),
            domain_pq_pubkey: None,
            domain_key_blob: vec![1],
            org_hash: "org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        let err = save_bundle(&dir.path().join("a.dds"), &bad, &hybrid).unwrap_err();
        assert!(
            err.to_string().contains("v2-hybrid"),
            "expected hybrid-signer / no-pq bundle to be refused, got: {err}"
        );

        // Conversely: Ed25519-only signer but bundle asserts a pq_pubkey.
        let plain = DomainKey::generate("plain.local", &mut OsRng);
        let plain_dom = plain.domain();
        let bogus_pq = "ab".repeat(1952);
        let bad2 = ProvisionBundle {
            domain_name: plain_dom.name.clone(),
            domain_id: plain_dom.id.to_string(),
            domain_pubkey: to_hex(&plain_dom.pubkey),
            domain_pq_pubkey: Some(bogus_pq),
            domain_key_blob: vec![1],
            org_hash: "org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
            fingerprint: String::new(),
        };
        let err2 = save_bundle(&dir.path().join("b.dds"), &bad2, &plain).unwrap_err();
        assert!(
            err2.to_string().contains("Ed25519-only"),
            "expected ed25519-signer / pq-bundle to be refused, got: {err2}"
        );
    }

    /// **SC-1 end-to-end**: provisioning a v2-hybrid bundle stamps
    /// `pq_pubkey` into both `domain.toml` and `dds.toml`, so the
    /// provisioned node starts as a v2-hybrid verifier instead of
    /// the v1 verifier the original gap produced. This is the
    /// "downgrade rejection" regression: it pins the verifier-side
    /// state that admission certs / revocations are gated on.
    #[test]

    fn provision_with_hybrid_domain_key_keeps_pq_pubkey() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
        // See provision_with_plain_domain_key: a sibling p2p_identity
        // test under `PASSPHRASE_ENV_LOCK` may have left this set.
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        let key = DomainKey::generate_hybrid("provision-hybrid", &mut OsRng);
        let domain = key.domain();
        let expected_pq_hex = to_hex(domain.pq_pubkey.as_ref().expect("hybrid"));
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        let bundle_path = dir.path().join("hybrid.dds");
        create_bundle(&domain_dir, "hybrid-org", &bundle_path).unwrap();

        // The created bundle must be v4 and carry the same pq_pubkey.
        let loaded = load_bundle(&bundle_path).unwrap();
        assert_eq!(
            loaded.domain_pq_pubkey.as_deref(),
            Some(expected_pq_hex.as_str())
        );

        let data_dir = dir.path().join("node-data");
        let result = run_provision(&bundle_path, Some(&data_dir), false).unwrap();
        assert_eq!(result.domain_name, "provision-hybrid");

        // domain.toml on the provisioned node carries the pq pubkey.
        let provisioned_domain =
            domain_store::load_domain_file(&data_dir.join("domain.toml")).unwrap();
        assert!(
            provisioned_domain.is_hybrid(),
            "provisioned domain.toml lost pq_pubkey — silent downgrade"
        );
        assert_eq!(
            provisioned_domain
                .pq_pubkey
                .as_deref()
                .map(to_hex)
                .as_deref(),
            Some(expected_pq_hex.as_str())
        );

        // dds.toml on the provisioned node carries `[domain].pq_pubkey`,
        // so `cmd_run` will boot a v2-hybrid verifier.
        let cfg = std::fs::read_to_string(&result.config_path).unwrap();
        assert!(
            cfg.contains(&format!("pq_pubkey = \"{expected_pq_hex}\"")),
            "provisioned dds.toml missing [domain].pq_pubkey line:\n{cfg}"
        );

        // Sanity: an Ed25519-only admission cert (i.e., one whose
        // `pq_signature` is None) must fail under the verifier the
        // provisioned node would build (v2-hybrid). Issue a real
        // hybrid cert so the Ed25519 part still verifies, then strip
        // the PQ component to isolate the v2 gate. This pins the
        // "downgrade rejection" guarantee called out in SC-1.
        let mut hybrid_cert = key.issue_admission(result.peer_id.clone(), 0, None);
        assert!(
            hybrid_cert.pq_signature.is_some(),
            "hybrid issuer should populate pq_signature"
        );
        hybrid_cert.pq_signature = None;
        let err = hybrid_cert
            .verify_with_domain(&provisioned_domain, &result.peer_id, 1)
            .unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("pq_signature") || err_str.contains("hybrid"),
            "expected v2-hybrid verifier to reject v1-only cert, got: {err_str}"
        );
    }

    /// **SC-3** — `stamp_agent_appsettings` must be a no-op (returning
    /// `false`) on a host without an agent appsettings file. This is
    /// the dev / loadtest case, where `run_provision` should still
    /// proceed even though there is no Policy Agent to pin.
    #[test]
    fn stamp_agent_appsettings_missing_returns_false() {
        let dir = TempDir::new().unwrap();
        let written =
            stamp_agent_appsettings(dir.path(), Some("urn:vouchsafe:abc"), Some("pk")).unwrap();
        assert!(!written, "no appsettings.json present ⇒ Ok(false)");
    }

    /// **SC-3** — happy-path: stamping both fields rewrites them and
    /// preserves every other key in both the agent section and the
    /// rest of the file (Logging block, RequirePackageSignature, etc).
    #[test]
    fn stamp_agent_appsettings_writes_both_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("appsettings.json");
        std::fs::write(
            &path,
            r#"{
  "Logging": { "LogLevel": { "Default": "Information" } },
  "DdsPolicyAgent": {
    "DeviceUrn": "",
    "NodeBaseUrl": "unix:/var/run/dds.sock",
    "PollIntervalSeconds": 60,
    "RequirePackageSignature": true
  }
}"#,
        )
        .unwrap();

        let written = stamp_agent_appsettings(
            dir.path(),
            Some("urn:vouchsafe:device-xyz"),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        )
        .unwrap();
        assert!(written, "appsettings.json was rewritten");

        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let agent = v.get("DdsPolicyAgent").unwrap();
        assert_eq!(
            agent.get("DeviceUrn").and_then(|x| x.as_str()),
            Some("urn:vouchsafe:device-xyz")
        );
        assert_eq!(
            agent.get("PinnedNodePubkeyB64").and_then(|x| x.as_str()),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
        // Unrelated keys preserved.
        assert_eq!(
            agent.get("PollIntervalSeconds").and_then(|x| x.as_i64()),
            Some(60)
        );
        assert_eq!(
            agent.get("NodeBaseUrl").and_then(|x| x.as_str()),
            Some("unix:/var/run/dds.sock")
        );
        assert_eq!(
            agent
                .get("RequirePackageSignature")
                .and_then(|x| x.as_bool()),
            Some(true)
        );
        // Top-level Logging block preserved.
        assert!(v.get("Logging").is_some());
    }

    /// **SC-3** — partial stamp: passing `None` for one field must not
    /// clobber a previously-stamped value. Pubkey is set first (before
    /// the node starts), then enrollment populates DeviceUrn — the
    /// pubkey must still be there afterwards.
    #[test]
    fn stamp_agent_appsettings_partial_preserves_other_field() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("appsettings.json");
        std::fs::write(
            &path,
            r#"{ "DdsPolicyAgent": { "DeviceUrn": "", "PinnedNodePubkeyB64": "" } }"#,
        )
        .unwrap();

        // Phase 1: stamp pubkey only (pre-start of node).
        stamp_agent_appsettings(dir.path(), None, Some("PUBKEY-PHASE-1")).unwrap();
        // Phase 2: stamp DeviceUrn only (post-enrollment).
        stamp_agent_appsettings(dir.path(), Some("urn:vouchsafe:dev"), None).unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let agent = v.get("DdsPolicyAgent").unwrap();
        assert_eq!(
            agent.get("DeviceUrn").and_then(|x| x.as_str()),
            Some("urn:vouchsafe:dev")
        );
        assert_eq!(
            agent.get("PinnedNodePubkeyB64").and_then(|x| x.as_str()),
            Some("PUBKEY-PHASE-1"),
            "pubkey from phase 1 must survive the phase-2 partial stamp"
        );
    }

    /// **SC-3** — agent section absent: a fresh appsettings.json that
    /// only has unrelated top-level keys (e.g. a loadtest harness)
    /// should grow a new `DdsPolicyAgent` block rather than fail.
    #[test]
    fn stamp_agent_appsettings_creates_section_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("appsettings.json");
        std::fs::write(&path, r#"{ "Logging": {} }"#).unwrap();
        let written = stamp_agent_appsettings(dir.path(), Some("urn:x"), Some("pk")).unwrap();
        assert!(written);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let agent = v.get("DdsPolicyAgent").unwrap().as_object().unwrap();
        assert_eq!(agent.get("DeviceUrn").unwrap().as_str(), Some("urn:x"));
        assert_eq!(
            agent.get("PinnedNodePubkeyB64").unwrap().as_str(),
            Some("pk")
        );
    }

    /// **SC-3** — malformed JSON returns `ProvisionError::Format` so
    /// the caller can degrade gracefully (we log a warning and
    /// continue). It must not panic and must not silently overwrite.
    #[test]
    fn stamp_agent_appsettings_rejects_malformed_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("appsettings.json");
        std::fs::write(&path, "not json {").unwrap();
        let err = stamp_agent_appsettings(dir.path(), Some("u"), Some("p")).unwrap_err();
        let s = err.to_string();
        assert!(s.starts_with("format:"), "expected Format error, got: {s}");
        // Confirm we did NOT rewrite the file.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json {");
    }

    /// **SC-3-W** — `stamp_pubkey` is the Windows-MSI install-time entry
    /// point. It must (a) create `node_key.bin` if missing so a fresh
    /// install gets a stable identity, (b) derive the same base64 pubkey
    /// that `/v1/node/info` would later return, and (c) write it into
    /// the agent's `appsettings.json` without touching unrelated keys.
    #[test]
    fn stamp_pubkey_creates_node_key_and_writes_appsettings() {
        use base64::Engine as _;

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Make sure the fail-closed gate from security-gaps #4 is off
        // for this test — load_or_create on a missing file would
        // otherwise refuse to write a plain v1 identity.
        // SAFETY: TEST_ENV_LOCK serializes env mutation across the test
        // binary, so this `remove_var` cannot race with another test.
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        unsafe { std::env::remove_var("DDS_NODE_PASSPHRASE") };

        let data_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();

        // Pre-seed a populated agent appsettings.json — `Logging` and
        // `NodeBaseUrl` must survive untouched, the empty pubkey gets
        // overwritten with the real one.
        let appsettings_path = config_dir.path().join("appsettings.json");
        std::fs::write(
            &appsettings_path,
            r#"{
  "Logging": { "LogLevel": { "Default": "Information" } },
  "DdsPolicyAgent": {
    "DeviceUrn": "",
    "PinnedNodePubkeyB64": "",
    "NodeBaseUrl": "pipe:dds-api",
    "PollIntervalSeconds": 60,
    "StateDir": "C:\\ProgramData\\DDS"
  }
}"#,
        )
        .unwrap();

        // Pre-condition: no node_key.bin yet.
        assert!(!data_dir.path().join("node_key.bin").exists());

        let written = stamp_pubkey(data_dir.path(), config_dir.path()).unwrap();
        assert!(written, "stamp_pubkey returned false despite present file");

        // Post-condition: node_key.bin was created.
        assert!(
            data_dir.path().join("node_key.bin").exists(),
            "node_key.bin must be created on first stamp"
        );

        // Pubkey on disk matches what `/v1/node/info` would return.
        let ident = identity_store::load(&data_dir.path().join("node_key.bin")).unwrap();
        let expected = base64::engine::general_purpose::STANDARD
            .encode(ident.signing_key.verifying_key().to_bytes());

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&appsettings_path).unwrap()).unwrap();
        let agent = v.get("DdsPolicyAgent").unwrap();
        assert_eq!(
            agent.get("PinnedNodePubkeyB64").and_then(|x| x.as_str()),
            Some(expected.as_str()),
            "stamped pubkey must match the freshly-loaded identity"
        );

        // DeviceUrn is left as an empty string by stamp_pubkey — only
        // post-enrollment populates it.
        assert_eq!(
            agent.get("DeviceUrn").and_then(|x| x.as_str()),
            Some(""),
            "stamp_pubkey must not touch DeviceUrn"
        );

        // Unrelated keys preserved.
        assert!(v.get("Logging").is_some());
        assert_eq!(
            agent.get("NodeBaseUrl").and_then(|x| x.as_str()),
            Some("pipe:dds-api")
        );
        assert_eq!(
            agent.get("PollIntervalSeconds").and_then(|x| x.as_u64()),
            Some(60)
        );
    }

    /// **SC-3-W** — second invocation must not rotate the identity:
    /// the MSI repair / upgrade path may re-run the custom action and
    /// the stamped pubkey must remain stable so the Policy Agent does
    /// not lose envelope-verification trust. Mirrors the
    /// `--keep-existing` semantics of `gen-hmac-secret`.
    #[test]
    fn stamp_pubkey_is_idempotent_across_repeats() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        unsafe { std::env::remove_var("DDS_NODE_PASSPHRASE") };

        let data_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();
        std::fs::write(
            config_dir.path().join("appsettings.json"),
            r#"{ "DdsPolicyAgent": { "DeviceUrn": "", "PinnedNodePubkeyB64": "" } }"#,
        )
        .unwrap();

        stamp_pubkey(data_dir.path(), config_dir.path()).unwrap();
        let first = std::fs::read_to_string(config_dir.path().join("appsettings.json")).unwrap();

        stamp_pubkey(data_dir.path(), config_dir.path()).unwrap();
        let second = std::fs::read_to_string(config_dir.path().join("appsettings.json")).unwrap();

        assert_eq!(
            first, second,
            "second stamp_pubkey call rotated the identity (MSI repair would break the agent)"
        );
    }

    /// **SC-3-W** — when no `appsettings.json` is present (dev /
    /// loadtest hosts that install only the Rust node, not the .NET
    /// Policy Agent), `stamp_pubkey` must still seed `node_key.bin`
    /// (so a later `dds-node run` finds a stable identity) and report
    /// `false` so the MSI custom action exits cleanly without
    /// failing the install.
    #[test]
    fn stamp_pubkey_returns_false_when_appsettings_absent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };
        unsafe { std::env::remove_var("DDS_NODE_PASSPHRASE") };
        // Also clear ProgramFiles so the Windows fallback path inside
        // `agent_appsettings_path` cannot find an unrelated install.
        unsafe { std::env::remove_var("ProgramFiles") };

        let data_dir = TempDir::new().unwrap();
        let config_dir = TempDir::new().unwrap();

        let written = stamp_pubkey(data_dir.path(), config_dir.path()).unwrap();
        assert!(!written, "expected false when no appsettings.json present");
        assert!(
            data_dir.path().join("node_key.bin").exists(),
            "node_key.bin must still be seeded so dds-node run finds it"
        );
    }

    /// **PQ-DEFAULT-2** — provisioning a hybrid domain must:
    /// 1. write `epoch_keys.cbor` to `data_dir`, and
    /// 2. embed the hybrid KEM pubkey in the issued admission cert.
    ///
    /// Before this fix, `run_provision` always called `issue_admission`
    /// (KEM pubkey = None), which meant `v3 coverage` stayed at 0% even
    /// when the domain was enc-v3 capable.
    #[test]
    fn provision_hybrid_domain_embeds_kem_pubkey_in_admission_cert() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };

        let key = DomainKey::generate_hybrid("pqd2-hybrid", &mut OsRng);
        let domain = key.domain();
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        let bundle_path = dir.path().join("pqd2.dds");
        create_bundle(&domain_dir, "pqd2-org", &bundle_path).unwrap();

        let data_dir = dir.path().join("node-data");
        let result = run_provision(&bundle_path, Some(&data_dir), false).unwrap();

        // epoch_keys.cbor must be written by run_provision.
        assert!(
            data_dir.join("epoch_keys.cbor").exists(),
            "epoch_keys.cbor must be created by provision (PQ-DEFAULT-2)"
        );

        // The admission cert must carry the hybrid KEM pubkey.
        let cert = domain_store::load_admission_cert(&data_dir.join("admission.cbor")).unwrap();
        assert!(
            cert.pq_kem_pubkey.is_some(),
            "admission cert must embed pq_kem_pubkey on hybrid domain (PQ-DEFAULT-2); peer_id={}",
            result.peer_id
        );
        assert_eq!(
            cert.pq_kem_pubkey.as_ref().unwrap().len(),
            dds_domain::HYBRID_KEM_PUBKEY_LEN,
            "pq_kem_pubkey length mismatch"
        );
    }

    /// **PQ-DEFAULT-2** — provisioning a legacy (Ed25519-only) domain
    /// must NOT embed a KEM pubkey in the admission cert (the cert would
    /// never be used with enc-v3 anyway, and embedding would be a waste
    /// of bytes).
    #[test]
    fn provision_legacy_domain_does_not_embed_kem_pubkey() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
        unsafe { std::env::remove_var("DDS_REQUIRE_ENCRYPTED_KEYS") };

        let key = DomainKey::generate("pqd2-legacy", &mut OsRng);
        let domain = key.domain();
        domain_store::save_domain_file(&domain_dir.join("domain.toml"), &domain).unwrap();
        domain_store::save_domain_key(&domain_dir.join("domain_key.bin"), &key).unwrap();

        let bundle_path = dir.path().join("pqd2-legacy.dds");
        create_bundle(&domain_dir, "pqd2-legacy-org", &bundle_path).unwrap();

        let data_dir = dir.path().join("node-data");
        run_provision(&bundle_path, Some(&data_dir), false).unwrap();

        let cert = domain_store::load_admission_cert(&data_dir.join("admission.cbor")).unwrap();
        assert!(
            cert.pq_kem_pubkey.is_none(),
            "legacy domain admission cert must not carry pq_kem_pubkey"
        );
    }
}
