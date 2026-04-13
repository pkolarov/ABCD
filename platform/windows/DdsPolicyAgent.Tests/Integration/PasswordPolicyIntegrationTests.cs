// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests.Integration;

/// <summary>
/// Integration tests for <see cref="WindowsPasswordPolicyOperations"/>
/// and <see cref="PasswordPolicyEnforcer"/> against the real local
/// security policy.
///
/// All tests require elevation. The original policy state is captured
/// in the constructor and restored in <see cref="Dispose"/>.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")]
public sealed class PasswordPolicyIntegrationTests : IDisposable
{
    private readonly WindowsPasswordPolicyOperations _ops = new();
    private PasswordPolicyState? _originalState;

    private void CaptureOriginalState()
    {
        _originalState ??= _ops.GetCurrent();
    }

    // ----------------------------------------------------------------
    // GetCurrent
    // ----------------------------------------------------------------

    [SkippableFact]
    public void GetCurrent_Returns_NonNull_Values()
    {
        SkipIfNotAdmin();
        var state = _ops.GetCurrent();

        Assert.NotNull(state);
        Assert.NotNull(state.MinLength);
        Assert.NotNull(state.MaxAgeDays);
        Assert.NotNull(state.MinAgeDays);
        Assert.NotNull(state.HistorySize);
        // Complexity may be null if secedit fails, but on a normal box it should be readable
        Assert.NotNull(state.LockoutThreshold);
        Assert.NotNull(state.LockoutDurationMinutes);
    }

    // ----------------------------------------------------------------
    // Individual knobs
    // ----------------------------------------------------------------

    [SkippableFact]
    public void SetMinLength_Changes_Policy()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        // Pick a safe value different from the likely default (0)
        var target = _originalState!.MinLength == 8u ? 10u : 8u;
        _ops.SetMinLength(target);

        var updated = _ops.GetCurrent();
        Assert.Equal(target, updated.MinLength);
    }

    [SkippableFact]
    public void SetMaxAgeDays_Changes_Policy()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        var target = _originalState!.MaxAgeDays == 60u ? 90u : 60u;
        _ops.SetMaxAgeDays(target);

        var updated = _ops.GetCurrent();
        Assert.Equal(target, updated.MaxAgeDays);
    }

    [SkippableFact]
    public void SetHistorySize_Changes_Policy()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        var target = _originalState!.HistorySize == 5u ? 10u : 5u;
        _ops.SetHistorySize(target);

        var updated = _ops.GetCurrent();
        Assert.Equal(target, updated.HistorySize);
    }

    [SkippableFact]
    public void SetLockoutThreshold_Changes_Policy()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        var target = _originalState!.LockoutThreshold == 5u ? 10u : 5u;
        _ops.SetLockoutThreshold(target);

        var updated = _ops.GetCurrent();
        Assert.Equal(target, updated.LockoutThreshold);
    }

    // ----------------------------------------------------------------
    // Full enforcer pipeline
    // ----------------------------------------------------------------

    [SkippableFact]
    public async Task Full_Enforcer_Applies_Multiple_Knobs()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        var enforcer = new PasswordPolicyEnforcer(_ops, NullLogger<PasswordPolicyEnforcer>.Instance);

        // Set all knobs to known values
        var json = """{"min_length":10,"max_age_days":60,"history_size":12,"lockout_threshold":8}""";
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, result.Status);

        var state = _ops.GetCurrent();
        Assert.Equal(10u, state.MinLength);
        Assert.Equal(60u, state.MaxAgeDays);
        Assert.Equal(12u, state.HistorySize);
        Assert.Equal(8u, state.LockoutThreshold);
    }

    [SkippableFact]
    public async Task Full_Enforcer_Idempotent_On_Second_Apply()
    {
        SkipIfNotAdmin();
        CaptureOriginalState();

        var enforcer = new PasswordPolicyEnforcer(_ops, NullLogger<PasswordPolicyEnforcer>.Instance);
        var json = """{"min_length":6}""";
        var directive = JsonDocument.Parse(json).RootElement;

        var r1 = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r1.Status);

        // Second apply — already at desired state
        var r2 = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r2.Status);
        Assert.Empty(r2.Changes!); // no-op
    }

    // ----------------------------------------------------------------
    // Cleanup — restore original policy
    // ----------------------------------------------------------------

    public void Dispose()
    {
        if (_originalState is null) return;

        try
        {
            if (_originalState.MinLength.HasValue)
                _ops.SetMinLength(_originalState.MinLength.Value);
            if (_originalState.MaxAgeDays.HasValue)
                _ops.SetMaxAgeDays(_originalState.MaxAgeDays.Value);
            if (_originalState.MinAgeDays.HasValue)
                _ops.SetMinAgeDays(_originalState.MinAgeDays.Value);
            if (_originalState.HistorySize.HasValue)
                _ops.SetHistorySize(_originalState.HistorySize.Value);
            if (_originalState.LockoutThreshold.HasValue)
                _ops.SetLockoutThreshold(_originalState.LockoutThreshold.Value);
            if (_originalState.LockoutDurationMinutes.HasValue)
                _ops.SetLockoutDurationMinutes(_originalState.LockoutDurationMinutes.Value);
            if (_originalState.ComplexityRequired.HasValue)
                _ops.SetComplexityRequired(_originalState.ComplexityRequired.Value);
        }
        catch { /* best-effort restore */ }
    }

    private static void SkipIfNotAdmin()
    {
        var reason = IntegrationTestHelpers.SkipIfNotWindows();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
        reason = IntegrationTestHelpers.SkipIfNotAdmin();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
    }
}
