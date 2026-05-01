// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Linux.Config;

public sealed class AgentConfig
{
    public const string SectionName = "DdsPolicyAgent";

    public string DeviceUrn { get; set; } = string.Empty;
    public string NodeBaseUrl { get; set; } = "unix:/run/dds/api.sock";
    public int PollIntervalSeconds { get; set; } = 60;
    public string StateDir { get; set; } = OperatingSystem.IsLinux()
        ? "/var/lib/dds/policy-agent"
        : "./dds-linux-agent-state";
    public string PinnedNodePubkeyB64 { get; set; } = string.Empty;
    public int EnvelopeMaxClockSkewSeconds { get; set; } = 300;
    public bool AuditOnly { get; set; } = true;

    public string ResolveStateDir()
        => string.IsNullOrWhiteSpace(StateDir)
            ? (OperatingSystem.IsLinux()
                ? "/var/lib/dds/policy-agent"
                : "./dds-linux-agent-state")
            : StateDir;
}
