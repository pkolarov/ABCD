// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.MacOS.Config;

/// <summary>
/// Configuration for the macOS DDS policy agent.
/// </summary>
public sealed class AgentConfig
{
    public const string SectionName = "DdsPolicyAgent";

    /// <summary>
    /// This device's DDS identity URN. Required.
    /// </summary>
    public string DeviceUrn { get; set; } = string.Empty;

    /// <summary>
    /// Base URL for the local dds-node HTTP API.
    /// </summary>
    public string NodeBaseUrl { get; set; } = "http://127.0.0.1:5551";

    /// <summary>
    /// Poll interval in seconds.
    /// </summary>
    public int PollIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Persistent state directory for applied-state.json and future
    /// staging artifacts.
    /// </summary>
    public string StateDir { get; set; } = OperatingSystem.IsMacOS()
        ? "/Library/Application Support/DDS"
        : "./dds-agent-state";

    /// <summary>
    /// Root directory for managed system preference plists.
    /// </summary>
    public string ManagedPreferencesDir { get; set; } = OperatingSystem.IsMacOS()
        ? "/Library/Managed Preferences"
        : "./dds-agent-managed-preferences";

    /// <summary>
    /// Alternate root for user-template managed preference plists.
    /// When empty, a subdirectory under <see cref="ManagedPreferencesDir"/>
    /// is used.
    /// </summary>
    public string UserTemplatePreferencesDir { get; set; } = string.Empty;

    /// <summary>
    /// Directory that stores managed launch daemons.
    /// </summary>
    public string LaunchDaemonPlistDir { get; set; } = OperatingSystem.IsMacOS()
        ? "/Library/LaunchDaemons"
        : "./dds-agent-launchd/LaunchDaemons";

    /// <summary>
    /// Directory that stores managed launch agents.
    /// </summary>
    public string LaunchAgentPlistDir { get; set; } = OperatingSystem.IsMacOS()
        ? "/Library/LaunchAgents"
        : "./dds-agent-launchd/LaunchAgents";

    /// <summary>
    /// launchd domain target used by bootstrap/bootout/kickstart. The
    /// default is the system domain because the agent itself runs as a
    /// LaunchDaemon.
    /// </summary>
    public string LaunchdDomain { get; set; } = "system";

    /// <summary>
    /// Directory used to persist launchd label to plist-path bindings.
    /// </summary>
    public string LaunchdStateFile { get; set; } = string.Empty;

    /// <summary>
    /// Working directory used to stage downloaded or verified `.pkg`
    /// files before invoking `/usr/sbin/installer`.
    /// </summary>
    public string PackageCacheDir { get; set; } = string.Empty;

    /// <summary>
    /// Directory used to persist profile payload hashes for idempotency.
    /// </summary>
    public string ProfileStateDir { get; set; } = string.Empty;

    /// <summary>
    /// Volume or domain target passed to `/usr/sbin/installer`.
    /// </summary>
    public string PackageInstallTarget { get; set; } = "/";

    /// <summary>
    /// Require `pkgutil --check-signature` to succeed before install.
    /// Disable only for local unsigned test packages.
    /// </summary>
    public bool RequirePackageSignature { get; set; } = true;

    /// <summary>
    /// Inline pre/post install scripts remain disabled by default. They
    /// can be enabled later if the policy model grows a safer execution
    /// contract.
    /// </summary>
    public bool AllowInlinePackageScripts { get; set; }

    /// <summary>
    /// <b>H-3 (security review)</b>: base64-standard-with-padding
    /// encoding of the 32-byte Ed25519 public key of the dds-node
    /// this agent is bound to. Every signed policy / software
    /// envelope must verify under this pubkey before any enforcer
    /// runs. Pin at install time via the provisioning bundle.
    /// Required in production — empty string means the agent will
    /// fail closed.
    /// </summary>
    public string PinnedNodePubkeyB64 { get; set; } = string.Empty;

    /// <summary>
    /// Maximum tolerated clock skew between the node and the agent
    /// when validating the envelope's <c>issued_at</c> timestamp.
    /// Default: 300 seconds.
    /// </summary>
    public int EnvelopeMaxClockSkewSeconds { get; set; } = 300;

    public string ResolveStateDir()
        => string.IsNullOrWhiteSpace(StateDir)
            ? (OperatingSystem.IsMacOS()
                ? "/Library/Application Support/DDS"
                : "./dds-agent-state")
            : StateDir;

    public string ResolveManagedPreferencesDir()
        => string.IsNullOrWhiteSpace(ManagedPreferencesDir)
            ? Path.Combine(ResolveStateDir(), "ManagedPreferences")
            : ManagedPreferencesDir;

    public string ResolveUserTemplatePreferencesDir()
        => string.IsNullOrWhiteSpace(UserTemplatePreferencesDir)
            ? Path.Combine(ResolveManagedPreferencesDir(), "UserTemplate")
            : UserTemplatePreferencesDir;

    public string ResolveLaunchDaemonPlistDir()
        => string.IsNullOrWhiteSpace(LaunchDaemonPlistDir)
            ? Path.Combine(ResolveStateDir(), "LaunchDaemons")
            : LaunchDaemonPlistDir;

    public string ResolveLaunchAgentPlistDir()
        => string.IsNullOrWhiteSpace(LaunchAgentPlistDir)
            ? Path.Combine(ResolveStateDir(), "LaunchAgents")
            : LaunchAgentPlistDir;

    public string ResolveLaunchdStateFile()
        => string.IsNullOrWhiteSpace(LaunchdStateFile)
            ? Path.Combine(ResolveStateDir(), "launchd-state.json")
            : LaunchdStateFile;

    public string ResolvePackageCacheDir()
        => string.IsNullOrWhiteSpace(PackageCacheDir)
            ? Path.Combine(ResolveStateDir(), "packages")
            : PackageCacheDir;

    public string ResolveProfileStateDir()
        => string.IsNullOrWhiteSpace(ProfileStateDir)
            ? Path.Combine(ResolveStateDir(), "profiles")
            : ProfileStateDir;
}
