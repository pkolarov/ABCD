// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Phase C: log-only stub. Logs each registry directive it would
/// apply but does not touch the registry. Phase D replaces the body
/// with real <c>Microsoft.Win32.Registry</c> calls.
/// </summary>
public sealed class RegistryEnforcer : IEnforcer
{
    private readonly ILogger<RegistryEnforcer> _log;
    public string Name => "Registry";

    public RegistryEnforcer(ILogger<RegistryEnforcer> log) => _log = log;

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        var changes = new List<string>();
        if (directive.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in directive.EnumerateArray())
            {
                var hive = item.GetProperty("hive").GetString();
                var key = item.GetProperty("key").GetString();
                var name = item.TryGetProperty("name", out var n) ? n.GetString() : "(Default)";
                var action = item.GetProperty("action").GetString();
                var desc = $"{action} {hive}\\{key}\\{name}";
                changes.Add(desc);
                _log.LogInformation("[DRY-RUN] Registry: {Action}", desc);
            }
        }
        return Task.FromResult(new EnforcementOutcome(
            EnforcementStatus.Skipped, null, changes));
    }
}
