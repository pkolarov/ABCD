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

/// Current wire version: v3 bundles carry a mandatory Ed25519
/// signature over the canonical signing bytes, verified on load
/// against the embedded `domain_pubkey`.
const BUNDLE_VERSION: u64 = 3;
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
    pub domain_key_blob: Vec<u8>,
    pub org_hash: String,
    pub listen_port: u16,
    pub api_port: u16,
    pub mdns_enabled: bool,
    /// SHA-256 fingerprint of the integrity-bound metadata fields
    /// (domain_id + domain_pubkey + org_hash + ports + domain_key_blob).
    /// Populated on load for v2+ bundles. Operators MUST confirm this
    /// fingerprint OUT-OF-BAND before importing; the in-bundle
    /// signature (v3+) catches the common tamper case where the
    /// metadata is altered without re-deriving a new domain key.
    pub fingerprint: String,
}

/// Canonical bytes covered by the bundle's signature and fingerprint.
/// Order is fixed; any field added in a future version must go AFTER
/// the existing fields so v3 consumers continue to verify against the
/// same prefix. Includes `domain_key_blob` so a MITM swapping the
/// encrypted key for one they control invalidates the signature.
fn signing_bytes(bundle: &ProvisionBundle) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"dds-bundle-v3|");
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
    let fingerprint = compute_fingerprint(bundle);
    let msg = signing_bytes(bundle);
    let signature = signer.signing_key.sign(&msg).to_bytes().to_vec();

    let map = vec![
        (
            CborValue::Text("version".into()),
            CborValue::Integer(BUNDLE_VERSION.into()),
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
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| ProvisionError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| ProvisionError::Io(e.to_string()))?;
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
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| ProvisionError::Cbor(e.to_string()))?;
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

    let bundle = ProvisionBundle {
        domain_name: get_text("domain_name")?,
        domain_id: get_text("domain_id")?,
        domain_pubkey: get_text("domain_pubkey")?,
        domain_key_blob: get_bytes("domain_key")?,
        org_hash: get_text("org_hash")?,
        listen_port: get_u64("listen_port", 4001) as u16,
        api_port: get_u64("api_port", 5551) as u16,
        mdns_enabled: get_bool("mdns_enabled", true),
        fingerprint: String::new(),
    };
    let computed_fingerprint = compute_fingerprint(&bundle);

    match version {
        3 => {
            // **H-10 (security review)**: v3 MUST carry a signature and
            // MUST carry the fingerprint. Both are verified here; the
            // caller then prints the fingerprint for operator OOB
            // confirmation.
            let sig_bytes = stored_signature.ok_or_else(|| {
                ProvisionError::Format(
                    "v3 bundle missing signature field — refuse to import".into(),
                )
            })?;
            let stored = stored_fingerprint.ok_or_else(|| {
                ProvisionError::Format(
                    "v3 bundle missing fingerprint field — refuse to import".into(),
                )
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

    let bundle = ProvisionBundle {
        domain_name: domain.name,
        domain_id: domain.id.to_string(),
        domain_pubkey: to_hex(&domain.pubkey),
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

    let now = now_epoch();
    let ttl = 365 * 86400; // 1 year — re-provision or re-admit to renew
    let cert = domain_key.issue_admission(peer_id.to_string(), now, Some(now + ttl));

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
    let domain = Domain {
        name: bundle.domain_name.clone(),
        id: expected_id,
        pubkey,
    };
    domain_store::save_domain_file(&data_dir.join("domain.toml"), &domain)?;

    // node_key.bin
    let _node_ident = identity_store::load_or_create(&data_dir.join("node_key.bin"), "dds-node")
        .map_err(|e| ProvisionError::Io(format!("node key: {e}")))?;

    // dds.toml
    let config_path = config_dir.join("dds.toml");
    let config_content = format!(
        r#"# DDS Node Configuration — provisioned from bundle
data_dir = "{data_dir}"
org_hash = "{org_hash}"
trusted_roots = []

[network]
listen_addr = "/ip4/0.0.0.0/tcp/{listen_port}"
bootstrap_peers = []
mdns_enabled = {mdns}
heartbeat_secs = 5
idle_timeout_secs = 60
api_addr = "127.0.0.1:{api_port}"

[domain]
name = "{domain_name}"
id = "{domain_id}"
pubkey = "{domain_pubkey}"
admission_path = "{admission}"
audit_log_enabled = false
"#,
        data_dir = data_dir.display(),
        org_hash = bundle.org_hash,
        listen_port = bundle.listen_port,
        mdns = bundle.mdns_enabled,
        api_port = bundle.api_port,
        domain_name = bundle.domain_name,
        domain_id = bundle.domain_id,
        domain_pubkey = bundle.domain_pubkey,
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

    // 6. Start node and enroll (if requested)
    if start_node {
        println!("[5/6] Starting node...");
        start_platform_node(&config_path)?;

        // Wait for health
        let api_url = format!("http://127.0.0.1:{}", bundle.api_port);
        print!("  Waiting for node...");
        let mut ready = false;
        for _ in 0..30 {
            if reqwest_blocking_status_check(&api_url) {
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
            match enroll_this_device(&api_url, &bundle.org_hash) {
                Ok(urn) => {
                    println!("  Device URN: {urn}");
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

fn reqwest_blocking_status_check(api_url: &str) -> bool {
    std::process::Command::new("curl")
        .args(["-sf", &format!("{api_url}/v1/status")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn enroll_this_device(api_url: &str, org_hash: &str) -> Result<String, ProvisionError> {
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

    let output = std::process::Command::new("curl")
        .args([
            "-sf",
            "-X",
            "POST",
            &format!("{api_url}/v1/enroll/device"),
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

    #[test]
    fn provision_refuses_double() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let domain_dir = dir.path().join("domain");
        std::fs::create_dir_all(&domain_dir).unwrap();

        unsafe { std::env::remove_var("DDS_DOMAIN_PASSPHRASE") };
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
}
