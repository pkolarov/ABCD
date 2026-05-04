// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforces <c>WindowsSettings.services</c> directives by
/// dispatching through <see cref="IServiceOperations"/>. In
/// production the DI container injects
/// <see cref="WindowsServiceOperations"/> (real SCM); in tests it
/// injects <see cref="InMemoryServiceOperations"/>.
///
/// <para>
/// <b>Security:</b> service names are validated against
/// <see cref="SafeServiceNamePattern"/> before any SCM call.
/// Names outside the pattern are rejected with
/// <see cref="EnforcementStatus.Failed"/> to prevent a compromised
/// dds-node from injecting arbitrary service paths.
/// </para>
/// </summary>
public sealed class ServiceEnforcer : IEnforcer
{
    private readonly IServiceOperations _ops;
    private readonly ILogger<ServiceEnforcer> _log;
    public string Name => "Service";

    /// <summary>
    /// Allowable characters in a Windows service short name.
    /// Mirrors the SCM constraint: letters, digits, underscores, and
    /// hyphens only. Leading/trailing whitespace is also rejected.
    /// </summary>
    public static readonly Regex SafeServiceNamePattern =
        new(@"^[A-Za-z0-9_\-]{1,256}$", RegexOptions.Compiled);

    public ServiceEnforcer(IServiceOperations ops, ILogger<ServiceEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Array)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

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
                _log.LogError(ex, "Service enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var name = item.GetProperty("name").GetString()!;
        var action = item.GetProperty("action").GetString()!;

        if (!SafeServiceNamePattern.IsMatch(name))
            throw new InvalidOperationException(
                $"Refused: service name '{name}' contains invalid characters");

        var startType = item.TryGetProperty("start_type", out var st)
            && st.ValueKind != JsonValueKind.Null
            ? st.GetString() : null;

        var desc = startType is not null
            ? $"{action} '{name}' (start_type={startType})"
            : $"{action} '{name}'";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Service: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Configure":
                return ApplyConfigure(name, startType, desc);

            case "Start":
                ApplyConfigure(name, startType, desc);
                if (_ops.ServiceExists(name) && _ops.GetRunState(name) != "Running")
                {
                    _ops.StartService(name);
                    _log.LogInformation("Service: started '{Name}'", name);
                    return $"Start '{name}'";
                }
                return $"[NO-OP] Start '{name}' (already running or not found)";

            case "Stop":
                ApplyConfigure(name, startType, desc);
                if (_ops.ServiceExists(name) && _ops.GetRunState(name) != "Stopped")
                {
                    _ops.StopService(name);
                    _log.LogInformation("Service: stopped '{Name}'", name);
                    return $"Stop '{name}'";
                }
                return $"[NO-OP] Stop '{name}' (already stopped or not found)";

            default:
                throw new InvalidOperationException($"Unknown service action: {action}");
        }
    }

    private string ApplyConfigure(string name, string? startType, string desc)
    {
        if (!_ops.ServiceExists(name))
        {
            _log.LogWarning("Service: '{Name}' not found — skipping", name);
            return $"[NO-OP] {desc} (service not found)";
        }

        if (startType is not null)
        {
            var current = _ops.GetStartType(name);
            if (current != startType)
            {
                _ops.SetStartType(name, startType);
                _log.LogInformation("Service: set start type for '{Name}' to {Type}", name, startType);
                return $"Configure '{name}' start_type={startType}";
            }
            return $"[NO-OP] Configure '{name}' (start_type already {startType})";
        }

        return $"[NO-OP] Configure '{name}' (nothing to change)";
    }

    /// <summary>
    /// Extract the managed-item key for a directive. Returns the
    /// service name for all action types, so the Worker can track
    /// DDS-managed services across poll cycles.
    /// </summary>
    public static string? ExtractManagedKey(JsonElement item) =>
        item.TryGetProperty("name", out var n) ? n.GetString() : null;

    /// <summary>
    /// Log stale services that are no longer in the policy.
    /// Service configuration is not automatically reverted because
    /// DDS does not record the pre-apply baseline; reverting blindly
    /// could disrupt existing services. Operators are notified via
    /// the audit log and should review manually.
    /// </summary>
    public List<string> ReconcileStaleServices(
        IReadOnlySet<string> staleServiceNames, EnforcementMode mode)
    {
        var changes = new List<string>();
        foreach (var name in staleServiceNames)
        {
            _log.LogWarning(
                "Service reconcile: service '{Name}' is no longer in policy — " +
                "DDS will not auto-revert service configuration; review manually",
                name);
            changes.Add($"[MANUAL] Reconcile-Review {name} (service configuration not auto-reverted)");
        }
        return changes;
    }

    private static string DescribeDirective(JsonElement item)
    {
        var name = item.TryGetProperty("name", out var n) ? n.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} '{name}'";
    }
}
