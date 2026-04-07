//! Node configuration: storage paths, network settings, bootstrap peers.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Storage directory for redb database and keys.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Organization root hash this node serves.
    pub org_hash: String,

    /// Domain this node belongs to. Required — a node without a domain
    /// has no place on the network and cannot be admitted to one.
    pub domain: DomainConfig,

    /// Trusted root identity URNs.
    #[serde(default)]
    pub trusted_roots: Vec<String>,

    /// Optional explicit path to the persistent node identity file.
    /// Defaults to `<data_dir>/node_key.bin`. The file is encrypted with
    /// `DDS_NODE_PASSPHRASE` if that environment variable is set.
    #[serde(default)]
    pub identity_path: Option<PathBuf>,

    /// Interval in seconds between scans for expired tokens. The expiry
    /// sweeper drops expired attestations/vouches from the trust graph
    /// and revokes them in the store. Default: 60 seconds.
    #[serde(default = "default_expiry_scan_interval")]
    pub expiry_scan_interval_secs: u64,
}

fn default_expiry_scan_interval() -> u64 {
    60
}

/// Domain identity for this node. The `name` is a display label; the `id`
/// (a `dds-dom:` URN) is the cryptographic source of truth, and `pubkey` is
/// the Ed25519 verifying key whose hash equals `id`.
///
/// At startup the node loads the admission certificate from
/// `admission_path` (default `<data_dir>/admission.cbor`) and verifies that
/// it was signed by `pubkey` and applies to this node's libp2p `PeerId`.
/// If verification fails the node refuses to start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Human-readable domain name (e.g. "acme.com"). Display only.
    pub name: String,
    /// `dds-dom:<base32>` form of the domain id.
    pub id: String,
    /// Hex-encoded 32-byte Ed25519 public key for the domain.
    pub pubkey: String,
    /// Path to the admission certificate. Defaults to
    /// `<data_dir>/admission.cbor`.
    #[serde(default)]
    pub admission_path: Option<PathBuf>,
    /// Opt-in flag to enable the append-only cryptographic audit log.
    /// If false (default), nodes discard historical operations once they are applied to the directory CRDTs.
    #[serde(default = "default_false")]
    pub audit_log_enabled: bool,
}

/// Network settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// TCP listen address.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Bootstrap peer multiaddrs (with embedded peer IDs).
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Enable mDNS for local network discovery.
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Gossipsub heartbeat interval in seconds.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,

    /// Idle connection timeout in seconds.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Local API listen address.
    #[serde(default = "default_api_addr")]
    pub api_addr: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            bootstrap_peers: Vec::new(),
            mdns_enabled: true,
            heartbeat_secs: default_heartbeat(),
            idle_timeout_secs: default_idle_timeout(),
            api_addr: default_api_addr(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    dirs_next().unwrap_or_else(|| PathBuf::from(".dds"))
}

fn dirs_next() -> Option<PathBuf> {
    home::home_dir().map(|h| h.join(".dds"))
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/tcp/4001".to_string()
}

fn default_api_addr() -> String {
    "127.0.0.1:5551".to_string()
}
fn default_false() -> bool {
    false
}


fn default_true() -> bool {
    true
}

fn default_heartbeat() -> u64 {
    5
}

fn default_idle_timeout() -> u64 {
    60
}

impl NodeConfig {
    /// Load config from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load config from a TOML string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Path to the redb database file.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("directory.redb")
    }

    /// Path to the node identity key file.
    pub fn identity_key_path(&self) -> PathBuf {
        self.identity_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("node_key.bin"))
    }

    /// Path to the persistent libp2p keypair file.
    pub fn p2p_key_path(&self) -> PathBuf {
        self.data_dir.join("p2p_key.bin")
    }

    /// Path to the admission certificate file.
    pub fn admission_path(&self) -> PathBuf {
        self.domain
            .admission_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("admission.cbor"))
    }
}

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config I/O error: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_TOML: &str = r#"
[domain]
name = "test.local"
id = "dds-dom:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
pubkey = "0000000000000000000000000000000000000000000000000000000000000000"
"#;

    #[test]
    fn test_parse_minimal_config() {
        let toml = format!(r#"org_hash = "abc123"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(config.org_hash, "abc123");
        assert!(config.network.mdns_enabled);
        assert_eq!(config.domain.name, "test.local");
    }

    #[test]
    fn test_missing_domain_section_fails() {
        let result = NodeConfig::from_str(r#"org_hash = "abc123""#);
        assert!(result.is_err(), "config without [domain] must fail");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = format!(
            r#"
            org_hash = "abc123"
            data_dir = "/tmp/dds-test"
            trusted_roots = ["urn:vouchsafe:root.hash1"]
            {DOMAIN_TOML}
            [network]
            listen_addr = "/ip4/10.0.1.1/tcp/9000"
            bootstrap_peers = ["/ip4/10.0.1.2/tcp/4001/p2p/12D3KooWTest"]
            mdns_enabled = false
            heartbeat_secs = 10
            idle_timeout_secs = 120
            api_addr = "127.0.0.1:6661"
        "#
        );
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(config.data_dir, PathBuf::from("/tmp/dds-test"));
        assert_eq!(config.trusted_roots.len(), 1);
        assert_eq!(config.network.listen_addr, "/ip4/10.0.1.1/tcp/9000");
        assert!(!config.network.mdns_enabled);
        assert_eq!(config.network.heartbeat_secs, 10);
    }

    #[test]
    fn test_db_path() {
        let toml = format!(
            r#"
            org_hash = "test"
            data_dir = "/data/dds"
            {DOMAIN_TOML}
        "#
        );
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(config.db_path(), PathBuf::from("/data/dds/directory.redb"));
        assert_eq!(
            config.admission_path(),
            PathBuf::from("/data/dds/admission.cbor")
        );
    }

    #[test]
    fn test_invalid_toml() {
        let result = NodeConfig::from_str("not valid toml {{{");
        assert!(result.is_err());
    }
}
