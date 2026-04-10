// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Phase C: log-only stub. Logs each password-policy knob it would
/// change. Phase E replaces the body with secedit / NetUserModalsSet.
/// </summary>
public sealed class PasswordPolicyEnforcer : IEnforcer
{
    private readonly ILogger<PasswordPolicyEnforcer> _log;
    public string Name => "PasswordPolicy";

    public PasswordPolicyEnforcer(ILogger<PasswordPolicyEnforcer> log) => _log = log;

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        var changes = new List<string>();
        if (directive.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in directive.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Null)
                    continue; // None — leave untouched
                var desc = $"set {prop.Name} = {prop.Value}";
                changes.Add(desc);
                _log.LogInformation("[DRY-RUN] PasswordPolicy: {Setting}", desc);
            }
        }
        return Task.FromResult(new EnforcementOutcome(
            EnforcementStatus.Skipped, null, changes));
    }
}
