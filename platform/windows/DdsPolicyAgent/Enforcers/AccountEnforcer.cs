// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Phase C: log-only stub. Logs each local-account directive it
/// would apply. Phase E replaces the body with real netapi32 /
/// DirectoryServices.AccountManagement calls. Refuses operations on
/// domain-joined machines (v1 scope decision).
/// </summary>
public sealed class AccountEnforcer : IEnforcer
{
    private readonly ILogger<AccountEnforcer> _log;
    public string Name => "Account";

    public AccountEnforcer(ILogger<AccountEnforcer> log) => _log = log;

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        var changes = new List<string>();
        if (directive.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in directive.EnumerateArray())
            {
                var user = item.GetProperty("username").GetString();
                var action = item.GetProperty("action").GetString();
                var desc = $"{action} local account '{user}'";
                changes.Add(desc);
                _log.LogInformation("[DRY-RUN] Account: {Action}", desc);
            }
        }
        return Task.FromResult(new EnforcementOutcome(
            EnforcementStatus.Skipped, null, changes));
    }
}
