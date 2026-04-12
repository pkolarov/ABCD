//! Typed domain documents — each serializes to CBOR for `TokenPayload::body_cbor`.

use crate::{DomainDocument, body_types};
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
    /// Free-form policy settings as key-value pairs. Forward-compatible
    /// escape hatch — appliers fall back to this for any directive not
    /// covered by the typed `windows` bundle below.
    pub settings: Vec<PolicySetting>,
    /// Enforcement mode.
    pub enforcement: Enforcement,
    /// Strongly-typed Windows-specific directives. The Windows policy
    /// applier reads this for known directives (registry, accounts,
    /// password policy, services); unknown settings still flow through
    /// `settings`. Backward-compatible: pre-existing tokens without
    /// this field deserialize as `None` thanks to `serde(default)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsSettings>,
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

// ----------------------------------------------------------------
// Strongly-typed Windows directives (for `WindowsPolicyDocument::windows`).
//
// These are the inputs the Windows policy applier (`DdsPolicyAgent`)
// consumes. They live in dds-domain rather than the agent so that:
//   1. The wire shape is locked at the directory layer — admin tools
//      (`dds-cli`, future web UI) and the agent share one definition.
//   2. Non-Windows nodes can still gossip and store the documents
//      without pulling in any Win32 dependency.
// The applier itself is .NET; it consumes these via the `dds-node`
// HTTP API as JSON, so every variant must serialize cleanly to both
// CBOR (for the trust graph) and JSON (for the API). All variants
// here are flat enums or plain structs — no untagged or transparent
// representations.
// ----------------------------------------------------------------

/// Strongly-typed Windows policy directives. Lives alongside the
/// free-form `WindowsPolicyDocument::settings` list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct WindowsSettings {
    /// Registry directives, applied in document order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry: Vec<RegistryDirective>,
    /// Local Windows account directives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_accounts: Vec<AccountDirective>,
    /// Local password policy. `None` = leave existing policy unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<PasswordPolicy>,
    /// Windows service directives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceDirective>,
}

/// Registry hive (mirrors Win32 `HKEY_*` predefined handles).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryHive {
    /// `HKEY_LOCAL_MACHINE`.
    LocalMachine,
    /// `HKEY_CURRENT_USER` — note: a `LocalSystem` applier writes its
    /// own profile here, not the interactive user's. Use sparingly.
    CurrentUser,
    /// `HKEY_USERS`.
    Users,
    /// `HKEY_CLASSES_ROOT`.
    ClassesRoot,
}

/// Registry value type (subset of Win32 `REG_*`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RegistryValue {
    /// `REG_SZ`.
    String(String),
    /// `REG_EXPAND_SZ`.
    ExpandString(String),
    /// `REG_DWORD` (32-bit unsigned).
    Dword(u32),
    /// `REG_QWORD` (64-bit unsigned).
    Qword(u64),
    /// `REG_MULTI_SZ`.
    MultiString(Vec<String>),
    /// `REG_BINARY`.
    Binary(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// What to do with a registry entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryAction {
    /// Create or overwrite the named value.
    Set,
    /// Remove the value. If `name` is `None`, remove the entire key
    /// (and the agent should refuse if the key has subkeys, to avoid
    /// accidental wide-blast deletes).
    Delete,
}

/// One registry directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryDirective {
    pub hive: RegistryHive,
    /// Subkey path under `hive`, e.g.
    /// `SOFTWARE\Policies\Microsoft\Windows\System`. No leading
    /// backslash, no hive prefix.
    pub key: String,
    /// Value name. `None` means the `(Default)` value of the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Value to set. Required for `Action::Set`, ignored for `Delete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<RegistryValue>,
    pub action: RegistryAction,
}

/// What to do with a local Windows account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountAction {
    /// Create the account if it does not exist (idempotent).
    Create,
    /// Delete the account if it exists.
    Delete,
    /// Disable the account but keep its profile.
    Disable,
    /// Re-enable a previously disabled account.
    Enable,
}

/// Local Windows account directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountDirective {
    /// SAM account name (e.g. `"alice"`). Length and character rules
    /// are enforced by the applier, not the document.
    pub username: String,
    pub action: AccountAction,
    /// Display name shown in `lusrmgr.msc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Description / comment shown in `lusrmgr.msc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Local groups the account should be a member of. The applier
    /// is responsible for adding-without-removing existing memberships
    /// the directive does not name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// If `Some(true)`, set `PASSWORD_NEVER_EXPIRES`. `None` = leave
    /// existing flag unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_never_expires: Option<bool>,
}

/// Local password policy directive. All fields optional — `None` =
/// leave that knob untouched. Empty `PasswordPolicy{}` is a no-op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PasswordPolicy {
    /// Minimum password length, characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum password age, days. `0` = passwords never expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<u32>,
    /// Minimum password age, days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_age_days: Option<u32>,
    /// Number of remembered previous passwords (history).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_size: Option<u32>,
    /// Require Windows complexity rules (upper + lower + digit + symbol).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complexity_required: Option<bool>,
    /// Failed-attempt threshold before lockout. `0` = lockout disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_threshold: Option<u32>,
    /// Lockout duration, minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_duration_minutes: Option<u32>,
}

/// Service start type (mirrors `SC_START_TYPE`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceStartType {
    /// `SERVICE_BOOT_START`.
    Boot,
    /// `SERVICE_SYSTEM_START`.
    System,
    /// `SERVICE_AUTO_START`.
    Automatic,
    /// `SERVICE_DEMAND_START`.
    Manual,
    /// `SERVICE_DISABLED`.
    Disabled,
}

/// What to do with a Windows service.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceAction {
    /// Configure the service (start type / display name) but don't
    /// touch its current run state.
    Configure,
    /// Configure + ensure the service is running.
    Start,
    /// Configure + ensure the service is stopped.
    Stop,
}

/// Windows service directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceDirective {
    /// Service short name (e.g. `"wuauserv"`).
    pub name: String,
    /// Optional display name to set on the service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Start type to set. `None` = leave existing start type unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_type: Option<ServiceStartType>,
    pub action: ServiceAction,
}

impl DomainDocument for WindowsPolicyDocument {
    const BODY_TYPE: &'static str = body_types::WINDOWS_POLICY;
}

// ============================================================
// 4. MacOsPolicyDocument — macOS managed-device policy
// ============================================================

/// A policy document distributed to managed macOS devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MacOsPolicyDocument {
    /// Policy identifier (e.g. "security/screensaver").
    pub policy_id: String,
    /// Policy display name.
    pub display_name: String,
    /// Policy version (monotonically increasing).
    pub version: u64,
    /// Target scope: device tags, org units, or identity URNs.
    pub scope: PolicyScope,
    /// Free-form policy settings as key-value pairs. Forward-compatible
    /// escape hatch for directives not yet represented in `macos`.
    pub settings: Vec<PolicySetting>,
    /// Enforcement mode.
    pub enforcement: Enforcement,
    /// Strongly-typed macOS-specific directives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<MacOsSettings>,
}

/// Strongly-typed macOS policy directives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MacOsSettings {
    /// Managed preference writes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<PreferenceDirective>,
    /// Local account directives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_accounts: Vec<MacAccountDirective>,
    /// launchd job directives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub launchd: Vec<LaunchdDirective>,
    /// Configuration profile directives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<ProfileDirective>,
}

/// Where a preference should be applied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PreferenceScope {
    /// System-wide managed preference.
    System,
    /// New-user template preference.
    UserTemplate,
}

/// What to do with a managed preference.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PreferenceAction {
    /// Create or overwrite the key.
    Set,
    /// Remove the key.
    Delete,
}

/// One macOS managed preference directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreferenceDirective {
    /// Preference domain, e.g. `com.apple.screensaver`.
    pub domain: String,
    /// Preference key inside the domain.
    pub key: String,
    /// Arbitrary JSON-compatible value. Required for `Set`, ignored for `Delete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// Target preference scope.
    pub scope: PreferenceScope,
    /// Set or delete.
    pub action: PreferenceAction,
}

/// What to do with a local macOS account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MacAccountAction {
    Create,
    Delete,
    Disable,
    Enable,
    Modify,
}

/// Local macOS account directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MacAccountDirective {
    pub username: String,
    pub action: MacAccountAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
}

/// What to do with a launchd job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LaunchdAction {
    Load,
    Unload,
    Kickstart,
    Configure,
}

/// One launchd directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LaunchdDirective {
    /// launchd label (e.g. `com.dds.policyagent`).
    pub label: String,
    /// Path to the plist defining the job.
    pub plist_path: String,
    /// Desired enablement state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    pub action: LaunchdAction,
}

/// What to do with a configuration profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileAction {
    Install,
    Remove,
}

/// One configuration profile directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileDirective {
    /// Payload identifier, e.g. `com.example.screensaver`.
    pub identifier: String,
    /// Human-readable profile name.
    pub display_name: String,
    /// SHA-256 of the raw `.mobileconfig` payload.
    pub payload_sha256: String,
    /// Base64-encoded `.mobileconfig` bytes.
    pub mobileconfig_b64: String,
    pub action: ProfileAction,
}

impl DomainDocument for MacOsPolicyDocument {
    const BODY_TYPE: &'static str = body_types::MACOS_POLICY;
}

// ============================================================
// 5. SoftwareAssignment — app/package deployment manifest
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
// 6. ServicePrincipalDocument — machine/service identity
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
// 7. SessionDocument — short-lived auth session
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainDocument;
    use dds_core::token::TokenPayload;
    use serde_json::json;

    fn empty_payload() -> TokenPayload {
        TokenPayload {
            iss: "urn:vouchsafe:test.abc".into(),
            iss_key: dds_core::crypto::PublicKeyBundle {
                scheme: dds_core::crypto::SchemeId::Ed25519,
                bytes: vec![0u8; 32],
            },
            jti: "test-jti".into(),
            sub: "urn:vouchsafe:test.abc".into(),
            kind: dds_core::token::TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1,
            exp: Some(2),
            body_type: None,
            body_cbor: None,
        }
    }

    #[test]
    fn macos_policy_embed_extract_round_trip() {
        let doc = MacOsPolicyDocument {
            policy_id: "security/screensaver".into(),
            display_name: "Screensaver".into(),
            version: 7,
            scope: PolicyScope {
                device_tags: vec!["mac-laptop".into()],
                org_units: vec!["engineering".into()],
                identity_urns: vec![],
            },
            settings: vec![],
            enforcement: Enforcement::Audit,
            macos: Some(MacOsSettings {
                preferences: vec![PreferenceDirective {
                    domain: "com.apple.screensaver".into(),
                    key: "idleTime".into(),
                    value: Some(json!(600)),
                    scope: PreferenceScope::System,
                    action: PreferenceAction::Set,
                }],
                launchd: vec![LaunchdDirective {
                    label: "com.dds.policyagent".into(),
                    plist_path: "/Library/LaunchDaemons/com.dds.policyagent.plist".into(),
                    enabled: Some(true),
                    action: LaunchdAction::Configure,
                }],
                ..Default::default()
            }),
        };

        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();

        let extracted = MacOsPolicyDocument::extract(&payload).unwrap().unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn macos_policy_extract_returns_none_for_other_body_type() {
        let doc = WindowsPolicyDocument {
            policy_id: "win".into(),
            display_name: "Windows".into(),
            version: 1,
            scope: PolicyScope {
                device_tags: vec![],
                org_units: vec![],
                identity_urns: vec![],
            },
            settings: vec![],
            enforcement: Enforcement::Enforce,
            windows: None,
        };
        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();
        assert!(MacOsPolicyDocument::extract(&payload).unwrap().is_none());
    }
}
