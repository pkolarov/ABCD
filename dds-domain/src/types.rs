//! Typed domain documents — each serializes to CBOR for `TokenPayload::body_cbor`.

use crate::{body_types, DomainDocument};
use serde::{Deserialize, Serialize};

// ============================================================
// 1. UserAuthAttestation — FIDO2/passkey enrollment
// ============================================================

/// Wraps a FIDO2/WebAuthn attestation for user enrollment.
/// The actual FIDO2 attestation object is stored as raw bytes
/// (the signed token envelope provides the DDS-layer signature).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserAuthAttestation {
    /// FIDO2 credential ID (base64url).
    pub credential_id: String,
    /// FIDO2 attestation object (raw bytes from navigator.credentials.create).
    #[serde(with = "serde_bytes")]
    pub attestation_object: Vec<u8>,
    /// Client data JSON hash (SHA-256).
    #[serde(with = "serde_bytes")]
    pub client_data_hash: Vec<u8>,
    /// Relying party ID (e.g. "login.example.com").
    pub rp_id: String,
    /// User display name.
    pub user_display_name: String,
    /// Authenticator type: "platform" | "cross-platform".
    pub authenticator_type: String,
}

impl DomainDocument for UserAuthAttestation {
    const BODY_TYPE: &'static str = body_types::USER_AUTH_ATTESTATION;
}

// ============================================================
// 2. DeviceJoinDocument — device enrollment
// ============================================================

/// Device enrollment request — binds a device identity to the directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceJoinDocument {
    /// Device hardware identifier (e.g. TPM EK hash, serial number).
    pub device_id: String,
    /// Device hostname.
    pub hostname: String,
    /// Operating system (e.g. "Windows 11 24H2", "macOS 15.4").
    pub os: String,
    /// OS version string.
    pub os_version: String,
    /// Device TPM attestation key hash (if available).
    pub tpm_ek_hash: Option<String>,
    /// Organizational unit for this device.
    pub org_unit: Option<String>,
    /// Device tags for policy targeting.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl DomainDocument for DeviceJoinDocument {
    const BODY_TYPE: &'static str = body_types::DEVICE_JOIN;
}

// ============================================================
// 3. WindowsPolicyDocument — GPO-equivalent
// ============================================================

/// A policy document distributed to managed devices (GPO replacement).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WindowsPolicyDocument {
    /// Policy identifier (e.g. "security/password-policy").
    pub policy_id: String,
    /// Policy display name.
    pub display_name: String,
    /// Policy version (monotonically increasing).
    pub version: u64,
    /// Target scope: device tags, org units, or identity URNs.
    pub scope: PolicyScope,
    /// Policy settings as key-value pairs (typed).
    pub settings: Vec<PolicySetting>,
    /// Enforcement mode.
    pub enforcement: Enforcement,
}

/// Who this policy targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyScope {
    /// Apply to devices with these tags.
    #[serde(default)]
    pub device_tags: Vec<String>,
    /// Apply to devices in these org units.
    #[serde(default)]
    pub org_units: Vec<String>,
    /// Apply to specific identity URNs.
    #[serde(default)]
    pub identity_urns: Vec<String>,
}

/// A single policy setting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicySetting {
    /// Setting key (e.g. "password.min_length").
    pub key: String,
    /// Setting value (JSON-compatible).
    pub value: SettingValue,
}

/// Typed policy setting value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SettingValue {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<String>),
}

/// Policy enforcement mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Enforcement {
    /// Log violations but don't enforce.
    Audit,
    /// Enforce the policy.
    Enforce,
    /// Disabled (policy exists but is not applied).
    Disabled,
}

impl DomainDocument for WindowsPolicyDocument {
    const BODY_TYPE: &'static str = body_types::WINDOWS_POLICY;
}


// ============================================================
// 4. SoftwareAssignment — app/package deployment manifest
// ============================================================

/// A software package assignment for managed devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SoftwareAssignment {
    /// Package identifier (e.g. "com.example.editor").
    pub package_id: String,
    /// Package display name.
    pub display_name: String,
    /// Package version.
    pub version: String,
    /// Download URL or content hash.
    pub source: String,
    /// SHA-256 hash of the package binary.
    pub sha256: String,
    /// Install action.
    pub action: InstallAction,
    /// Target scope (same as policy).
    pub scope: PolicyScope,
    /// Whether to install silently.
    pub silent: bool,
    /// Pre/post install scripts (optional).
    pub pre_install_script: Option<String>,
    pub post_install_script: Option<String>,
}

/// Software install action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstallAction {
    Install,
    Uninstall,
    Update,
}

impl DomainDocument for SoftwareAssignment {
    const BODY_TYPE: &'static str = body_types::SOFTWARE_ASSIGNMENT;
}

// ============================================================
// 5. ServicePrincipalDocument — machine/service identity
// ============================================================

/// A service principal (machine identity) registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServicePrincipalDocument {
    /// Service principal name (e.g. "HTTP/api.example.com").
    pub spn: String,
    /// Service display name.
    pub display_name: String,
    /// Service type (e.g. "web-server", "database", "api-gateway").
    pub service_type: String,
    /// Allowed authentication methods.
    #[serde(default)]
    pub auth_methods: Vec<String>,
    /// Service endpoint URLs.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Maximum session duration in seconds.
    pub max_session_secs: Option<u64>,
    /// Tags for policy targeting.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl DomainDocument for ServicePrincipalDocument {
    const BODY_TYPE: &'static str = body_types::SERVICE_PRINCIPAL;
}

// ============================================================
// 6. SessionDocument — short-lived auth session
// ============================================================

/// A short-lived session token for < 1ms local validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionDocument {
    /// Session identifier.
    pub session_id: String,
    /// Subject identity URN.
    pub subject_urn: String,
    /// Device identity URN (if device-bound).
    pub device_urn: Option<String>,
    /// Granted purposes/roles.
    #[serde(default)]
    pub granted_purposes: Vec<String>,
    /// Authorized resources (empty = all per policy).
    #[serde(default)]
    pub authorized_resources: Vec<String>,
    /// Session start time (Unix seconds).
    pub session_start: u64,
    /// Session duration in seconds (typically 300-3600).
    pub duration_secs: u64,
    /// Whether MFA was verified.
    pub mfa_verified: bool,
    /// TLS channel binding hash (optional).
    pub tls_binding: Option<String>,
}

impl DomainDocument for SessionDocument {
    const BODY_TYPE: &'static str = body_types::SESSION;
}