// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforces <c>WindowsSettings.password_policy</c> directives by
/// dispatching through <see cref="IPasswordPolicyOperations"/>.
///
/// All fields in the directive are optional — <c>null</c> means
/// "leave the current value unchanged". An empty object is a no-op.
/// The enforcer reads the current state first and only writes knobs
/// that differ from the desired value (idempotent).
/// </summary>
public sealed class PasswordPolicyEnforcer : IEnforcer
{
    private readonly IPasswordPolicyOperations _ops;
    private readonly ILogger<PasswordPolicyEnforcer> _log;
    public string Name => "PasswordPolicy";

    public PasswordPolicyEnforcer(IPasswordPolicyOperations ops, ILogger<PasswordPolicyEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Object)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

        var current = _ops.GetCurrent();
        var changes = new List<string>();
        string? firstError = null;
        var overallStatus = EnforcementStatus.Ok;

        ApplyKnob(directive, "min_length", current.MinLength,
            v => _ops.SetMinLength(v), mode, changes, ref firstError, ref overallStatus);

        ApplyKnob(directive, "max_age_days", current.MaxAgeDays,
            v => _ops.SetMaxAgeDays(v), mode, changes, ref firstError, ref overallStatus);

        ApplyKnob(directive, "min_age_days", current.MinAgeDays,
            v => _ops.SetMinAgeDays(v), mode, changes, ref firstError, ref overallStatus);

        ApplyKnob(directive, "history_size", current.HistorySize,
            v => _ops.SetHistorySize(v), mode, changes, ref firstError, ref overallStatus);

        ApplyBoolKnob(directive, "complexity_required", current.ComplexityRequired,
            v => _ops.SetComplexityRequired(v), mode, changes, ref firstError, ref overallStatus);

        ApplyKnob(directive, "lockout_threshold", current.LockoutThreshold,
            v => _ops.SetLockoutThreshold(v), mode, changes, ref firstError, ref overallStatus);

        ApplyKnob(directive, "lockout_duration_minutes", current.LockoutDurationMinutes,
            v => _ops.SetLockoutDurationMinutes(v), mode, changes, ref firstError, ref overallStatus);

        if (changes.Count == 0)
        {
            _log.LogDebug("PasswordPolicy: all knobs at desired state — no changes");
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Ok, null, changes));
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private void ApplyKnob(
        JsonElement directive, string name, uint? currentValue,
        Action<uint> setter, EnforcementMode mode,
        List<string> changes, ref string? firstError, ref EnforcementStatus status)
    {
        if (!directive.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null)
            return;

        var desired = prop.GetUInt32();
        if (currentValue.HasValue && currentValue.Value == desired)
        {
            _log.LogDebug("PasswordPolicy: {Name} already {Value}", name, desired);
            return;
        }

        if (mode == EnforcementMode.Audit)
        {
            changes.Add($"[AUDIT] {name}: {currentValue} -> {desired}");
            _log.LogInformation("[AUDIT] PasswordPolicy: would set {Name} = {Value}", name, desired);
            return;
        }

        try
        {
            setter(desired);
            changes.Add($"{name}: {currentValue} -> {desired}");
            _log.LogInformation("PasswordPolicy: set {Name} = {Value}", name, desired);
        }
        catch (Exception ex)
        {
            changes.Add($"FAILED: {name} — {ex.Message}");
            firstError ??= ex.Message;
            status = EnforcementStatus.Failed;
            _log.LogError(ex, "PasswordPolicy: failed to set {Name}", name);
        }
    }

    private void ApplyBoolKnob(
        JsonElement directive, string name, bool? currentValue,
        Action<bool> setter, EnforcementMode mode,
        List<string> changes, ref string? firstError, ref EnforcementStatus status)
    {
        if (!directive.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null)
            return;

        var desired = prop.GetBoolean();
        if (currentValue.HasValue && currentValue.Value == desired)
        {
            _log.LogDebug("PasswordPolicy: {Name} already {Value}", name, desired);
            return;
        }

        if (mode == EnforcementMode.Audit)
        {
            changes.Add($"[AUDIT] {name}: {currentValue} -> {desired}");
            _log.LogInformation("[AUDIT] PasswordPolicy: would set {Name} = {Value}", name, desired);
            return;
        }

        try
        {
            setter(desired);
            changes.Add($"{name}: {currentValue} -> {desired}");
            _log.LogInformation("PasswordPolicy: set {Name} = {Value}", name, desired);
        }
        catch (Exception ex)
        {
            changes.Add($"FAILED: {name} — {ex.Message}");
            firstError ??= ex.Message;
            status = EnforcementStatus.Failed;
            _log.LogError(ex, "PasswordPolicy: failed to set {Name}", name);
        }
    }
}
