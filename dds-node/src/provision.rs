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
use dds_domain::domain::{DomainId, from_hex, to_hex};
use zeroize::Zeroize;

use crate::{domain_store, identity_store, p2p_identity};

const BUNDLE_VERSION: u64 = 1;

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
#[derive(Debug)]
pub struct ProvisionBundle {
    pub domain_name: String,
    pub domain_id: String,
    pub domain_pubkey: String,
    pub domain_key_blob: Vec<u8>,
    pub org_hash: String,
    pub listen_port: u16,
    pub api_port: u16,
    pub mdns_enabled: bool,
}

/// Save a provision bundle to a `.dds` file.
pub fn save_bundle(path: &Path, bundle: &ProvisionBundle) -> Result<(), ProvisionError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProvisionError::Io(e.to_string()))?;
    }
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
    ];
    let mut buf = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut buf)
        .map_err(|e| ProvisionError::Cbor(e.to_string()))?;
    std::fs::write(path, &buf).map_err(|e| ProvisionError::Io(e.to_string()))?;
    Ok(())
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
    if version != BUNDLE_VERSION {
        return Err(ProvisionError::Format(format!(
            "unsupported bundle version {version} (expected {BUNDLE_VERSION})"
        )));
    }

    Ok(ProvisionBundle {
        domain_name: get_text("domain_name")?,
        domain_id: get_text("domain_id")?,
        domain_pubkey: get_text("domain_pubkey")?,
        domain_key_blob: get_bytes("domain_key")?,
        org_hash: get_text("org_hash")?,
        listen_port: get_u64("listen_port", 4001) as u16,
        api_port: get_u64("api_port", 5551) as u16,
        mdns_enabled: get_bool("mdns_enabled", true),
    })
}

// ---- Bundle creation ----

/// Create a provision bundle from the domain directory (after init-domain).
pub fn create_bundle(
    domain_dir: &Path,
    org_hash: &str,
    out_path: &Path,
) -> Result<(), ProvisionError> {
    let domain_toml = domain_dir.join("domain.toml");
    let domain_key_bin = domain_dir.join("domain_key.bin");

    let domain = domain_store::load_domain_file(&domain_toml)?;
    let key_blob = std::fs::read(&domain_key_bin).map_err(|e| ProvisionError::Io(e.to_string()))?;

    let bundle = ProvisionBundle {
        domain_name: domain.name,
        domain_id: domain.id.to_string(),
        domain_pubkey: to_hex(&domain.pubkey),
        domain_key_blob: key_blob,
        org_hash: org_hash.to_string(),
        listen_port: 4001,
        api_port: 5551,
        mdns_enabled: true,
    };

    save_bundle(out_path, &bundle)?;
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
            // Enable and bootstrap the LaunchDaemon
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
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Shared with domain_store tests to prevent env var races
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.dds");

        let bundle = ProvisionBundle {
            domain_name: "test.local".into(),
            domain_id: "dds-dom:aaaa".into(),
            domain_pubkey: "ff".repeat(32),
            domain_key_blob: vec![1, 2, 3, 4],
            org_hash: "test-org".into(),
            listen_port: 4001,
            api_port: 5551,
            mdns_enabled: true,
        };

        save_bundle(&path, &bundle).unwrap();
        let loaded = load_bundle(&path).unwrap();

        assert_eq!(loaded.domain_name, "test.local");
        assert_eq!(loaded.domain_id, "dds-dom:aaaa");
        assert_eq!(loaded.domain_key_blob, vec![1, 2, 3, 4]);
        assert_eq!(loaded.org_hash, "test-org");
        assert_eq!(loaded.listen_port, 4001);
        assert_eq!(loaded.api_port, 5551);
        assert!(loaded.mdns_enabled);
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
