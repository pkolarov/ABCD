// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;

namespace DDS.PolicyAgent.MacOS.Enforcers;

public enum EnforcementMode
{
    Audit,
    Enforce,
}

public sealed record EnforcementOutcome(
    EnforcementStatus Status,
    string? Error = null,
    IReadOnlyList<string>? Changes = null);

public enum EnforcementStatus
{
    Ok,
    Failed,
    Skipped,
}

public interface IEnforcer
{
    string Name { get; }

    Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,
        CancellationToken ct = default);
}
