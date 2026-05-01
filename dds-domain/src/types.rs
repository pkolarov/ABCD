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
    /// Optional DDS subject URN authorized to claim this local account
    /// on matching Windows endpoints. When absent, the directive is
    /// still valid for the policy agent but cannot drive the native
    /// pre-logon claim flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_subject_urn: Option<String>,
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
// 5. LinuxPolicyDocument — Linux managed-device policy
// ============================================================

/// A policy document distributed to managed Linux devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinuxPolicyDocument {
    /// Policy identifier (e.g. "security/sudoers").
    pub policy_id: String,
    /// Policy display name.
    pub display_name: String,
    /// Policy version (monotonically increasing).
    pub version: u64,
    /// Target scope: device tags, org units, or identity URNs.
    pub scope: PolicyScope,
    /// Free-form policy settings as key-value pairs. Forward-compatible
    /// escape hatch for directives not yet represented in `linux`.
    pub settings: Vec<PolicySetting>,
    /// Enforcement mode.
    pub enforcement: Enforcement,
    /// Strongly-typed Linux-specific directives. L-1 keeps this empty;
    /// L-2 adds users/groups, sudoers, systemd, files, and package
    /// directives behind this field without changing the document wrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxSettings>,
}

/// Strongly-typed Linux policy directives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LinuxSettings {}

impl DomainDocument for LinuxPolicyDocument {
    const BODY_TYPE: &'static str = body_types::LINUX_POLICY;
}

// ============================================================
// 6. MacAccountBindingDocument — subject/device/account binding
// ============================================================

/// How macOS login and account lifecycle are owned on a device.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MacJoinState {
    /// No external directory or IdP owns the login window.
    Standalone,
    /// Active Directory, Open Directory, LDAP, or similar owns sign-in.
    DirectoryBound,
    /// An IdP + MDM Platform SSO flow owns sign-in and local account creation.
    PlatformSsoManaged,
    /// DDS couldn't determine ownership safely.
    Unknown,
}

/// Which authority owns the macOS account bound to a DDS subject.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MacAccountAuthority {
    /// DDS creates and mutates the local account lifecycle.
    DdsLocal,
    /// The local account exists, but DDS does not own its lifecycle.
    LocalOnly,
    /// An external directory owns who may authenticate as the account.
    ExternalDirectory,
    /// Platform SSO / IdP owns sign-in and account synchronization.
    PlatformSso,
}

/// Binds a DDS subject on a specific device to the macOS local account
/// that hosts their home folder and login session.
///
/// This is intentionally separate from `MacOsPolicyDocument`: policy says
/// what the host should enforce, while this document records who a login
/// identity maps to on a given Mac and who owns that account lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MacAccountBindingDocument {
    /// Stable binding identifier.
    pub binding_id: String,
    /// DDS subject identity URN.
    pub subject_urn: String,
    /// DDS device identity URN.
    pub device_urn: String,
    /// The macOS short name (`/Users/<short_name>`).
    pub local_short_name: String,
    /// Human-readable account name shown in the login window or System Settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_display_name: Option<String>,
    /// Host join state at the time the binding was recorded.
    pub join_state: MacJoinState,
    /// Which authority owns the account lifecycle.
    pub authority: MacAccountAuthority,
    /// Local administrative groups/roles this binding expects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admin_groups: Vec<String>,
    /// Optional link to an enterprise SSO identity record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_link_id: Option<String>,
    /// Unix seconds when the binding was established.
    pub created_at: u64,
}

impl DomainDocument for MacAccountBindingDocument {
    const BODY_TYPE: &'static str = body_types::MACOS_ACCOUNT_BINDING;
}

// ============================================================
// 6. SsoIdentityLinkDocument — enterprise identity mapping
// ============================================================

/// Links an enterprise IdP identity to a DDS subject URN.
///
/// This is not an authorization grant. Group membership and privileges
/// still come from DDS vouches and policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SsoIdentityLinkDocument {
    /// Stable link identifier.
    pub link_id: String,
    /// DDS subject identity URN.
    pub subject_urn: String,
    /// Provider kind, e.g. `entra`, `okta`, `ad`, `openidc`.
    pub provider: String,
    /// Provider-specific immutable subject/object identifier.
    pub provider_subject: String,
    /// Optional issuer / tenant / realm identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Human sign-in name, e.g. UPN or email-like principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_name: Option<String>,
    /// Optional contact email published by the IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name copied from the IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Unix seconds when the mapping was established.
    pub created_at: u64,
}

impl DomainDocument for SsoIdentityLinkDocument {
    const BODY_TYPE: &'static str = body_types::SSO_IDENTITY_LINK;
}

// ============================================================
// 7. SoftwareAssignment — app/package deployment manifest
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
    /// Required OS-vendor-rooted signer identity on the package blob, in
    /// addition to the SHA-256 hash. When set, the agent must verify the
    /// platform signature on the downloaded artifact and refuse the
    /// install if either the OS-vendor signature is invalid or the
    /// signer subject does not match this value. `None` preserves v1
    /// hash-only behaviour for legacy publishers; new publishers should
    /// always supply this field. Closes the schema half of Z-7
    /// ([docs/supply-chain-plan.md](../../docs/supply-chain-plan.md)
    /// Phase B.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_identity: Option<PublisherIdentity>,
}

/// Software install action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InstallAction {
    Install,
    Uninstall,
    Update,
}

/// Required signer identity that an agent must observe on the
/// downloaded package blob, in addition to the SHA-256 check. This is
/// the schema-level surface of the supply-chain Phase B "two-signature
/// gate" (DDS document signature + OS-vendor signature on the blob).
/// The variant tells the agent which native verifier to use; the inner
/// fields tell it what signer to insist on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PublisherIdentity {
    /// Windows Authenticode. The Windows agent must call
    /// `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` on the
    /// staged file and compare the certificate subject string against
    /// `subject` (case-sensitive exact match against
    /// `CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE)`).
    /// `root_thumbprint`, when set, additionally pins the chain root —
    /// the agent walks the chain and refuses the install if no
    /// certificate in the chain has the given SHA-1 thumbprint
    /// (40 lowercase hex chars).
    Authenticode {
        /// Authenticode signer subject as reported by
        /// `CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE)`.
        subject: String,
        /// Optional SHA-1 thumbprint (40 lowercase hex chars) of a
        /// certificate that must appear in the trust chain.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_thumbprint: Option<String>,
    },
    /// macOS Developer ID. The macOS agent must call
    /// `pkgutil --check-signature` (or `codesign --verify` for app
    /// bundles) and compare the parsed Team ID against `team_id`
    /// (case-sensitive exact match — Apple Team IDs are 10
    /// uppercase alphanumerics).
    AppleDeveloperId {
        /// Apple Developer Team ID (10 alphanumerics, e.g.
        /// "ABCDE12345").
        team_id: String,
    },
}

/// Validation outcome for a [`PublisherIdentity`] value, surfaced as a
/// distinct error type so the trust-graph admission path can reject
/// malformed publisher metadata at ingest time without needing to
/// thread `Result<_, String>` through the document layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherIdentityError {
    /// Authenticode `subject` was empty.
    EmptyAuthenticodeSubject,
    /// Authenticode `root_thumbprint` was not a 40-char lowercase hex
    /// string.
    InvalidRootThumbprint,
    /// `team_id` was not exactly 10 uppercase alphanumerics.
    InvalidAppleTeamId,
}

impl core::fmt::Display for PublisherIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyAuthenticodeSubject => f.write_str("authenticode subject is empty"),
            Self::InvalidRootThumbprint => {
                f.write_str("authenticode root_thumbprint must be 40 lowercase hex chars")
            }
            Self::InvalidAppleTeamId => {
                f.write_str("apple team_id must be 10 uppercase alphanumerics")
            }
        }
    }
}

impl std::error::Error for PublisherIdentityError {}

impl PublisherIdentity {
    /// Validate the field-level invariants documented on each variant.
    /// Empty / wrong-shape values would silently match nothing on the
    /// agent and be observationally indistinguishable from "no
    /// publisher pinning" — fail closed at the schema layer instead.
    pub fn validate(&self) -> Result<(), PublisherIdentityError> {
        match self {
            Self::Authenticode {
                subject,
                root_thumbprint,
            } => {
                if subject.trim().is_empty() {
                    return Err(PublisherIdentityError::EmptyAuthenticodeSubject);
                }
                if let Some(tp) = root_thumbprint {
                    let ok = tp.len() == 40
                        && tp
                            .chars()
                            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
                    if !ok {
                        return Err(PublisherIdentityError::InvalidRootThumbprint);
                    }
                }
                Ok(())
            }
            Self::AppleDeveloperId { team_id } => {
                let ok = team_id.len() == 10
                    && team_id
                        .chars()
                        .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase());
                if !ok {
                    return Err(PublisherIdentityError::InvalidAppleTeamId);
                }
                Ok(())
            }
        }
    }
}

impl DomainDocument for SoftwareAssignment {
    const BODY_TYPE: &'static str = body_types::SOFTWARE_ASSIGNMENT;
}

// ============================================================
// 8. ServicePrincipalDocument — machine/service identity
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
// 9. SessionDocument — short-lived auth session
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

    #[test]
    fn macos_account_binding_embed_extract_round_trip() {
        let doc = MacAccountBindingDocument {
            binding_id: "bind-mac-alice".into(),
            subject_urn: "urn:vouchsafe:alice.abc".into(),
            device_urn: "urn:vouchsafe:macbook.def".into(),
            local_short_name: "alice".into(),
            local_display_name: Some("Alice Example".into()),
            join_state: MacJoinState::PlatformSsoManaged,
            authority: MacAccountAuthority::PlatformSso,
            admin_groups: vec!["admin".into()],
            sso_link_id: Some("sso-alice".into()),
            created_at: 1_712_956_800,
        };

        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();

        let extracted = MacAccountBindingDocument::extract(&payload)
            .unwrap()
            .unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn macos_account_binding_extract_returns_none_for_other_body_type() {
        let doc = SessionDocument {
            session_id: "sess-1".into(),
            subject_urn: "urn:vouchsafe:alice.abc".into(),
            device_urn: Some("urn:vouchsafe:macbook.def".into()),
            granted_purposes: vec![],
            authorized_resources: vec![],
            session_start: 1,
            duration_secs: 300,
            mfa_verified: true,
            tls_binding: None,
        };
        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();
        assert!(
            MacAccountBindingDocument::extract(&payload)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sso_identity_link_embed_extract_round_trip() {
        let doc = SsoIdentityLinkDocument {
            link_id: "sso-alice".into(),
            subject_urn: "urn:vouchsafe:alice.abc".into(),
            provider: "entra".into(),
            provider_subject: "00000000-1111-2222-3333-444444444444".into(),
            issuer: Some("contoso.onmicrosoft.com".into()),
            principal_name: Some("alice@contoso.com".into()),
            email: Some("alice@contoso.com".into()),
            display_name: Some("Alice Example".into()),
            created_at: 1_712_956_800,
        };

        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();

        let extracted = SsoIdentityLinkDocument::extract(&payload).unwrap().unwrap();
        assert_eq!(extracted, doc);
    }

    #[test]
    fn sso_identity_link_extract_returns_none_for_other_body_type() {
        let doc = DeviceJoinDocument {
            device_id: "mac-001".into(),
            hostname: "mbp-001".into(),
            os: "macOS".into(),
            os_version: "15.4".into(),
            tpm_ek_hash: None,
            org_unit: Some("engineering".into()),
            tags: vec!["mac".into()],
        };
        let mut payload = empty_payload();
        doc.embed(&mut payload).unwrap();
        assert!(
            SsoIdentityLinkDocument::extract(&payload)
                .unwrap()
                .is_none()
        );
    }
}
