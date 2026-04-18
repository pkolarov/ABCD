// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Config;

/// <summary>
/// Configuration for the DDS Policy Agent. Bound from
/// appsettings.json section "DdsPolicyAgent" or environment
/// variables prefixed with DDS_AGENT_.
/// </summary>
public sealed class AgentConfig
{
    public const string SectionName = "DdsPolicyAgent";

    /// <summary>
    /// This device's identity URN (from its DeviceJoinDocument).
    /// Required — the agent cannot determine scope without it.
    /// </summary>
    public string DeviceUrn { get; set; } = string.Empty;

    /// <summary>
    /// Base URL for the local dds-node HTTP API.
    /// Default: http://127.0.0.1:5551
    /// </summary>
    public string NodeBaseUrl { get; set; } = "http://127.0.0.1:5551";

    /// <summary>
    /// How often (seconds) the agent polls dds-node for new
    /// policies and software assignments. Default: 60.
    /// </summary>
    public int PollIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Directory for persistent agent state (applied-state.json).
    /// Default: %ProgramData%\DDS on Windows, ./dds-agent-state elsewhere.
    /// </summary>
    public string StateDir { get; set; } = OperatingSystem.IsWindows()
        ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DDS")
        : "./dds-agent-state";

    /// <summary>
    /// <b>H-2 (security review)</b>: base64-standard-with-padding
    /// encoding of the 32-byte Ed25519 public key of the dds-node
    /// that this agent is bound to. Every signed policy / software
    /// envelope must verify under this pubkey before any enforcer
    /// runs. Pin at MSI install time by reading the pubkey from a
    /// provisioning bundle (or <c>dds-node status --node-pubkey</c>).
    ///
    /// Required in production. A null/empty value causes the agent
    /// to fail closed — it will log an error and not apply any
    /// policy.
    /// </summary>
    public string PinnedNodePubkeyB64 { get; set; } = string.Empty;

    /// <summary>
    /// Maximum tolerated clock skew between the node and the agent
    /// when validating the envelope's <c>issued_at</c> timestamp.
    /// Default: 300 seconds.
    /// </summary>
    public int EnvelopeMaxClockSkewSeconds { get; set; } = 300;
}
