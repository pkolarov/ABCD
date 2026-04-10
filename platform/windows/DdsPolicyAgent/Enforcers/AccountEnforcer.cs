// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforces <c>WindowsSettings.local_accounts</c> directives by
/// dispatching through <see cref="IAccountOperations"/>.
///
/// <b>v1 scope decision:</b> refuses all operations on domain-joined
/// machines. The AD-replacement story is Phase 4.
/// </summary>
public sealed class AccountEnforcer : IEnforcer
{
    private readonly IAccountOperations _ops;
    private readonly ILogger<AccountEnforcer> _log;
    public string Name => "Account";

    public AccountEnforcer(IAccountOperations ops, ILogger<AccountEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Array)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

        // Domain-join guard (v1 scope decision)
        if (_ops.IsDomainJoined())
        {
            _log.LogWarning("Account enforcer refused: machine is domain-joined (v1 out of scope)");
            return Task.FromResult(new EnforcementOutcome(
                EnforcementStatus.Skipped,
                "domain-joined machines are out of scope for v1"));
        }

        var changes = new List<string>();
        string? firstError = null;
        var overallStatus = EnforcementStatus.Ok;

        foreach (var item in directive.EnumerateArray())
        {
            try
            {
                var result = ApplyOne(item, mode);
                changes.Add(result);
            }
            catch (Exception ex)
            {
                var desc = DescribeDirective(item);
                _log.LogError(ex, "Account enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var username = item.GetProperty("username").GetString()!;
        var action = item.GetProperty("action").GetString()!;

        var desc = $"{action} '{username}'";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Account: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Create":
                return ApplyCreate(item, username);
            case "Delete":
                return ApplyDelete(username);
            case "Disable":
                return ApplyDisable(username);
            case "Enable":
                return ApplyEnable(username);
            default:
                throw new InvalidOperationException($"Unknown account action: {action}");
        }
    }

    private string ApplyCreate(JsonElement item, string username)
    {
        var fullName = item.TryGetProperty("full_name", out var fn)
            && fn.ValueKind != JsonValueKind.Null
            ? fn.GetString() : null;
        var description = item.TryGetProperty("description", out var d)
            && d.ValueKind != JsonValueKind.Null
            ? d.GetString() : null;

        if (_ops.UserExists(username))
        {
            _log.LogDebug("Account: '{User}' already exists — ensuring groups/flags", username);
        }
        else
        {
            _ops.CreateUser(username, fullName, description);
            _log.LogInformation("Account: created '{User}'", username);
        }

        // Ensure group memberships (additive — never removes existing)
        if (item.TryGetProperty("groups", out var groups)
            && groups.ValueKind == JsonValueKind.Array)
        {
            foreach (var g in groups.EnumerateArray())
            {
                var groupName = g.GetString();
                if (groupName is not null)
                    _ops.AddToGroup(username, groupName);
            }
        }

        // PASSWORD_NEVER_EXPIRES flag
        if (item.TryGetProperty("password_never_expires", out var pne)
            && pne.ValueKind != JsonValueKind.Null)
        {
            _ops.SetPasswordNeverExpires(username, pne.GetBoolean());
        }

        return $"Create '{username}'";
    }

    private string ApplyDelete(string username)
    {
        if (!_ops.UserExists(username))
        {
            _log.LogDebug("Account: '{User}' does not exist — nothing to delete", username);
            return $"[NO-OP] Delete '{username}' (not found)";
        }
        _ops.DeleteUser(username);
        _log.LogInformation("Account: deleted '{User}'", username);
        return $"Delete '{username}'";
    }

    private string ApplyDisable(string username)
    {
        if (!_ops.UserExists(username))
            return $"[NO-OP] Disable '{username}' (not found)";
        if (!_ops.IsEnabled(username))
            return $"[NO-OP] Disable '{username}' (already disabled)";
        _ops.DisableUser(username);
        _log.LogInformation("Account: disabled '{User}'", username);
        return $"Disable '{username}'";
    }

    private string ApplyEnable(string username)
    {
        if (!_ops.UserExists(username))
            return $"[NO-OP] Enable '{username}' (not found)";
        if (_ops.IsEnabled(username))
            return $"[NO-OP] Enable '{username}' (already enabled)";
        _ops.EnableUser(username);
        _log.LogInformation("Account: enabled '{User}'", username);
        return $"Enable '{username}'";
    }

    private static string DescribeDirective(JsonElement item)
    {
        var user = item.TryGetProperty("username", out var u) ? u.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} '{user}'";
    }
}
