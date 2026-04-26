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

    /// URN of the domain's bootstrap admin — the principal that
    /// completed `admin_setup`. H-8 in the security review: the
    /// bootstrap admin may vouch for any purpose, while non-bootstrap
    /// admins must hold a `dds:admin-vouch:<purpose>` capability vouch
    /// signed by the bootstrap admin. Persisted so that the constraint
    /// survives node restart; rehydrated by `LocalService::new`.
    #[serde(default)]
    pub bootstrap_admin_urn: Option<String>,

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

    /// Maximum vouch chain depth for trust validation. Bounds the
    /// delegation depth: root → admin → sub-admin → user = depth 3.
    /// Prevents unbounded delegation and limits trust graph traversal.
    /// Default: 5 (from `dds_core::trust::DEFAULT_MAX_CHAIN_DEPTH`).
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: usize,

    /// Maximum number of audit log entries to retain. When exceeded,
    /// oldest entries are pruned on the next sweep. 0 = unlimited.
    #[serde(default)]
    pub audit_log_max_entries: usize,

    /// Maximum age (in days) for audit log entries. Entries older than
    /// this are pruned on the next sweep. 0 = no age limit.
    #[serde(default)]
    pub audit_log_retention_days: u64,

    /// **M-7 (security review)**: when true, only honor a device's
    /// self-attested `tags` / `org_unit` for policy/software scoping
    /// if there is also a vouch from a trusted root with purpose
    /// `dds:device-scope` over the device URN. Default `false` to
    /// preserve behavior on existing deployments — operators can
    /// turn it on once they've vouched all enrolled devices.
    #[serde(default)]
    pub enforce_device_scope_vouch: bool,

    /// **A-1 step-1 (security review)**: opt into accepting FIDO2
    /// enrollment attestations with `fmt = "none"`. Default `false`
    /// — packed self-attestation (or full with `x5c`, after A-1
    /// step-2 lands) is required. Flip to `true` only on
    /// dev/test deployments where a real authenticator is not
    /// available and the operator explicitly accepts that any
    /// local process can mint credentials. Each enrollment that
    /// uses the unattested path is logged at WARN.
    #[serde(default)]
    pub allow_unattested_credentials: bool,

    /// FIDO2 AAGUID allow-list (Phase 1 of
    /// [`docs/fido2-attestation-allowlist.md`](../../docs/fido2-attestation-allowlist.md)).
    /// Each entry is a canonical UUID string
    /// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or a 32-character
    /// hex string identifying an authenticator model the operator
    /// has approved. When the list is non-empty, enrollment rejects
    /// any FIDO2 credential whose AAGUID is not present. Default is
    /// empty, which preserves existing behavior (any AAGUID,
    /// including all-zero, is accepted).
    #[serde(default)]
    pub fido2_allowed_aaguids: Vec<String>,

    /// FIDO2 attestation trust roots, keyed by AAGUID (Phase 2 of
    /// `docs/fido2-attestation-allowlist.md`). When an entry exists for
    /// the credential's AAGUID, enrollment requires `attStmt.x5c` and
    /// validates the chain against the listed PEM file (any number of
    /// concatenated certs in the file are treated as alternative trust
    /// anchors). The leaf cert's `id-fido-gen-ce-aaguid` extension
    /// (OID `1.3.6.1.4.1.45724.1.1.4`) must equal the AAGUID in
    /// authData. Without an entry, the credential's AAGUID is only
    /// gated by `fido2_allowed_aaguids` (if any) and self-attested
    /// `packed` is still accepted. Empty by default.
    #[serde(default)]
    pub fido2_attestation_roots: Vec<Fido2AttestationRoot>,
}

/// A single AAGUID → trust-root binding for Phase 2 of
/// `docs/fido2-attestation-allowlist.md`. Lives at the
/// `[[domain.fido2_attestation_roots]]` array-of-tables in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2AttestationRoot {
    /// Canonical UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or
    /// 32-char bare-hex AAGUID. Case-insensitive.
    pub aaguid: String,
    /// Filesystem path to a PEM file containing one or more X.509
    /// certificates (any cert in the file is a valid trust anchor —
    /// useful for vendors that rotate roots). The file is read at
    /// startup; subsequent file changes require a node restart.
    pub ca_pem_path: PathBuf,
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

    /// **H-7 (security review)** — transport-auth policy for the local
    /// API. Governs which callers may reach admin-gated endpoints. See
    /// [`ApiAuthConfig`].
    #[serde(default)]
    pub api_auth: ApiAuthConfig,

    /// **M-1 / M-2 downgrade guard (security review)** — when `false`
    /// (the default), inbound tokens in the legacy v=1 envelope
    /// (pre-canonical-CBOR, pre-domain-separated hybrid) are dropped
    /// at the gossip/sync ingest layer. Persisted v1 tokens already
    /// in the local store still verify and serve normally — this flag
    /// controls only fresh ingest from peers. Operators set it to
    /// `true` during a domain-wide v1→v2 cutover if legacy publishers
    /// are still live, then flip back to `false`.
    #[serde(default = "default_false")]
    pub allow_legacy_v1_tokens: bool,

    /// observability-plan.md Phase C — Prometheus `/metrics` listen
    /// address. When `Some` the node spawns a second axum server
    /// alongside the API listener and answers `GET /metrics` with
    /// the standard Prometheus text exposition. `None` (the default)
    /// keeps the endpoint disabled so existing deployments do not
    /// open a second port without the operator opting in. Recommended
    /// value for an in-cluster Prometheus is `127.0.0.1:9495` plus a
    /// scrape-side TLS sidecar; off-host scrape requires the
    /// operator to supply their own ACL / mTLS posture.
    #[serde(default)]
    pub metrics_addr: Option<String>,
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
            api_auth: ApiAuthConfig::default(),
            allow_legacy_v1_tokens: false,
            metrics_addr: None,
        }
    }
}

/// **H-7 (security review)** — transport-authentication policy for
/// the local HTTP API.
///
/// The local API currently binds loopback TCP and has no per-caller
/// identity. G1-S2/S3 of the transport-authn remediation move the
/// listener to a UDS (Unix) or named pipe (Windows) and populate a
/// `CallerIdentity` extension from peer credentials (`SO_PEERCRED` /
/// `GetNamedPipeClientProcessId`). The admin-gate middleware then
/// admits only callers whose `uid` is in `unix_admin_uids` (or `0`)
/// or whose `sid` is in `windows_admin_sids`.
///
/// `trust_loopback_tcp_admin` is the migration escape hatch. While
/// it's `true` (current default), callers whose identity is
/// `Anonymous` — i.e. loopback TCP — are still admitted to admin
/// endpoints so existing deployments keep working. G1-S5 flips this
/// to `false`; G1-S6 removes the TCP listener entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAuthConfig {
    /// When `true`, callers whose `CallerIdentity` is `Anonymous`
    /// (loopback TCP with no peer creds) are admitted to admin
    /// endpoints. Default `true` for backward compatibility during
    /// the transport migration.
    #[serde(default = "default_true")]
    pub trust_loopback_tcp_admin: bool,

    /// Additional UIDs permitted on admin endpoints over UDS. `0`
    /// (root) and the service UID (the effective UID of the dds-node
    /// process) are always admitted. Extras listed here let an
    /// operator whitelist specific admin accounts.
    #[serde(default)]
    pub unix_admin_uids: Vec<u32>,

    /// Primary **user** SIDs permitted on admin endpoints over the
    /// Windows named pipe. Only `LocalSystem` (`S-1-5-18`) is
    /// admitted by default — that covers the dds-node service
    /// account and the C++ Auth Bridge / C# Policy Agent when they
    /// run as `LocalSystem` (which they do today per the MSI).
    ///
    /// **Caveat**: this is a primary-SID allowlist, not a group
    /// allowlist. `BUILTIN\Administrators` (`S-1-5-32-544`) is a
    /// group SID that never appears as a caller's primary SID, so
    /// listing it here has no effect. To admit elevated admin
    /// operators running the CLI, enumerate their per-user SIDs
    /// (`S-1-5-21-…`). Once the pipe listener (G1-S3) surfaces
    /// `TokenGroups`, a separate `windows_admin_groups` field will
    /// let operators admit by group membership.
    #[serde(default)]
    pub windows_admin_sids: Vec<String>,

    /// **H-6 (security review)** — path to the per-install HMAC
    /// secret used to authenticate the node's HTTP response bodies.
    /// When set, every response carries an `X-DDS-Body-MAC` header
    /// whose value is
    /// `base64(HMAC-SHA256(key, method || \0 || path || \0 || body))`.
    /// Windows Auth Bridge clients verify the MAC on the
    /// `/v1/session/challenge` response to block the challenge-
    /// substitution attack from H-6. The file must be at least 16
    /// bytes; the MSI / packaging layer generates 32 random bytes
    /// at install time. `None` = feature disabled (signer is a
    /// no-op — existing clients that ignore the header are not
    /// affected).
    #[serde(default)]
    pub node_hmac_secret_path: Option<PathBuf>,

    /// **M-8 step-2 (security review)** — when `true`, `Anonymous`
    /// callers (loopback TCP with no peer credentials) are refused
    /// on device-scoped read endpoints (`/v1/windows/*`,
    /// `/v1/macos/*`). M-8 step-1 wired a TOFU device-binding store
    /// that gates `Uds` / `Pipe` callers; step-2's remaining work
    /// is to drop the `Anonymous` bypass once operators have cut
    /// over to UDS / named-pipe transport (see `api_addr = unix:/…`
    /// or `pipe:…`). Defaults to `false` so existing TCP deployments
    /// keep working during the H-7 transport cutover; flip to
    /// `true` after the cutover and simultaneously drop
    /// `trust_loopback_tcp_admin`.
    #[serde(default)]
    pub strict_device_binding: bool,
}

impl Default for ApiAuthConfig {
    fn default() -> Self {
        Self {
            trust_loopback_tcp_admin: true,
            unix_admin_uids: Vec::new(),
            windows_admin_sids: Vec::new(),
            node_hmac_secret_path: None,
            strict_device_binding: false,
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

fn default_max_delegation_depth() -> usize {
    dds_core::trust::DEFAULT_MAX_CHAIN_DEPTH
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

    /// Path to the admission revocation list file (CBOR-encoded
    /// `RevocationListV1`). Defaults to `<data_dir>/admission_revocations.cbor`.
    /// The list is loaded once at startup; revocations dropped here
    /// take effect on the next node restart and from then on apply to
    /// every peer admission handshake.
    pub fn admission_revocations_path(&self) -> PathBuf {
        self.data_dir.join("admission_revocations.cbor")
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

    /// H-8 regression: `bootstrap_admin_urn` must round-trip through
    /// config serialization so the bootstrap admin's "vouch-anything"
    /// privilege survives restart.
    #[test]
    fn test_bootstrap_admin_urn_roundtrip() {
        let toml = format!(
            r#"
            org_hash = "abc"
            bootstrap_admin_urn = "urn:vouchsafe:bootstrap.hash"
            {DOMAIN_TOML}
        "#
        );
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(
            config.bootstrap_admin_urn.as_deref(),
            Some("urn:vouchsafe:bootstrap.hash")
        );
    }

    /// Defaults: no bootstrap admin recorded means a fresh node that
    /// has not yet completed `admin_setup`.
    #[test]
    fn test_bootstrap_admin_urn_default_none() {
        let toml = format!(r#"org_hash = "abc"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(config.bootstrap_admin_urn, None);
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

    #[test]
    fn test_delegation_depth_defaults_to_5() {
        let toml = format!(r#"org_hash = "abc123"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(
            config.domain.max_delegation_depth,
            dds_core::trust::DEFAULT_MAX_CHAIN_DEPTH
        );
    }

    #[test]
    fn test_delegation_depth_configurable() {
        let toml = r#"
            org_hash = "abc123"
            [domain]
            name = "test.local"
            id = "dds-dom:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            pubkey = "0000000000000000000000000000000000000000000000000000000000000000"
            max_delegation_depth = 3
        "#;
        let config = NodeConfig::from_str(toml).unwrap();
        assert_eq!(config.domain.max_delegation_depth, 3);
    }

    #[test]
    fn test_audit_retention_defaults() {
        let toml = format!(r#"org_hash = "abc123"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert_eq!(config.domain.audit_log_max_entries, 0);
        assert_eq!(config.domain.audit_log_retention_days, 0);
    }

    /// H-7: the default `ApiAuthConfig` preserves existing TCP
    /// deployments (trust loopback) while the transport migration
    /// is in flight.
    #[test]
    fn test_api_auth_defaults() {
        let toml = format!(r#"org_hash = "abc123"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert!(config.network.api_auth.trust_loopback_tcp_admin);
        assert!(config.network.api_auth.unix_admin_uids.is_empty());
        assert!(config.network.api_auth.windows_admin_sids.is_empty());
    }

    /// **M-1 / M-2 downgrade guard (security review)** — legacy v1
    /// ingest is refused by default. Flag round-trips through TOML.
    #[test]
    fn test_allow_legacy_v1_tokens_defaults_false() {
        let toml = format!(r#"org_hash = "abc123"{DOMAIN_TOML}"#);
        let config = NodeConfig::from_str(&toml).unwrap();
        assert!(!config.network.allow_legacy_v1_tokens);
    }

    #[test]
    fn test_allow_legacy_v1_tokens_roundtrip() {
        let toml = format!(
            r#"
            org_hash = "abc123"
            {DOMAIN_TOML}
            [network]
            allow_legacy_v1_tokens = true
        "#
        );
        let config = NodeConfig::from_str(&toml).unwrap();
        assert!(config.network.allow_legacy_v1_tokens);
    }

    #[test]
    fn test_api_auth_strict_roundtrip() {
        let toml = format!(
            r#"
            org_hash = "abc123"
            {DOMAIN_TOML}
            [network]
            [network.api_auth]
            trust_loopback_tcp_admin = false
            unix_admin_uids = [1000, 1001]
            windows_admin_sids = ["S-1-5-21-1-2-3-1000"]
        "#
        );
        let config = NodeConfig::from_str(&toml).unwrap();
        assert!(!config.network.api_auth.trust_loopback_tcp_admin);
        assert_eq!(config.network.api_auth.unix_admin_uids, vec![1000, 1001]);
        assert_eq!(
            config.network.api_auth.windows_admin_sids,
            vec!["S-1-5-21-1-2-3-1000".to_string()]
        );
    }

    #[test]
    fn test_audit_retention_configurable() {
        let toml = r#"
            org_hash = "abc123"
            [domain]
            name = "test.local"
            id = "dds-dom:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            pubkey = "0000000000000000000000000000000000000000000000000000000000000000"
            audit_log_enabled = true
            audit_log_max_entries = 10000
            audit_log_retention_days = 90
        "#;
        let config = NodeConfig::from_str(toml).unwrap();
        assert!(config.domain.audit_log_enabled);
        assert_eq!(config.domain.audit_log_max_entries, 10000);
        assert_eq!(config.domain.audit_log_retention_days, 90);
    }
}
