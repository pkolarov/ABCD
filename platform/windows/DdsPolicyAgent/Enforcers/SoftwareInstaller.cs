// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Phase C: log-only stub. Logs what it would install/uninstall.
/// Phase F replaces the body with real msiexec / Add-AppxPackage /
/// EXE invocation, SHA-256 verification, and uninstall-string
/// lookup.
/// </summary>
public sealed class SoftwareInstaller : IEnforcer
{
    private readonly ILogger<SoftwareInstaller> _log;
    public string Name => "Software";

    public SoftwareInstaller(ILogger<SoftwareInstaller> log) => _log = log;

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        var pkgId = directive.TryGetProperty("package_id", out var id)
            ? id.GetString() : "unknown";
        var version = directive.TryGetProperty("version", out var v)
            ? v.GetString() : "?";
        var action = directive.TryGetProperty("action", out var a)
            ? a.GetString() : "Install";

        var desc = $"{action} {pkgId} v{version}";
        _log.LogInformation("[DRY-RUN] Software: {Action}", desc);

        return Task.FromResult(new EnforcementOutcome(
            EnforcementStatus.Skipped, null, new[] { desc }));
    }
}
