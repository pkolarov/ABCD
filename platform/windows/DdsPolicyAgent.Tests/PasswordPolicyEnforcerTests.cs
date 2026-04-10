// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

public class PasswordPolicyEnforcerTests
{
    private readonly InMemoryPasswordPolicyOperations _ops = new();
    private readonly PasswordPolicyEnforcer _enforcer;

    public PasswordPolicyEnforcerTests()
    {
        _enforcer = new PasswordPolicyEnforcer(_ops, NullLogger<PasswordPolicyEnforcer>.Instance);
    }

    [Fact]
    public async Task Sets_min_length()
    {
        var dir = Parse("""{"min_length":14}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal((uint)14, _ops.GetCurrent().MinLength);
        Assert.Single(r.Changes!);
    }

    [Fact]
    public async Task Sets_multiple_knobs_at_once()
    {
        var dir = Parse("""
        {"min_length":12,"max_age_days":90,"history_size":24,"complexity_required":true,
         "lockout_threshold":5,"lockout_duration_minutes":30}
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        var state = _ops.GetCurrent();
        Assert.Equal((uint)12, state.MinLength);
        Assert.Equal((uint)90, state.MaxAgeDays);
        Assert.Equal((uint)24, state.HistorySize);
        Assert.True(state.ComplexityRequired);
        Assert.Equal((uint)5, state.LockoutThreshold);
        Assert.Equal((uint)30, state.LockoutDurationMinutes);
        Assert.Equal(6, r.Changes!.Count);
    }

    [Fact]
    public async Task Null_fields_are_skipped()
    {
        var dir = Parse("""{"min_length":14,"max_age_days":null,"lockout_threshold":null}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal((uint)14, _ops.GetCurrent().MinLength);
        // max_age_days stays at default (42 in the test double)
        Assert.Equal((uint)42, _ops.GetCurrent().MaxAgeDays);
        Assert.Single(r.Changes!);
    }

    [Fact]
    public async Task Idempotent_when_already_at_desired_state()
    {
        _ops.SetMinLength(14);
        var dir = Parse("""{"min_length":14}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Empty(r.Changes!); // no-op — already at 14
    }

    [Fact]
    public async Task Overwrites_when_different()
    {
        _ops.SetMinLength(8);
        var dir = Parse("""{"min_length":14}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Single(r.Changes!);
        Assert.Contains("8 -> 14", r.Changes[0]);
        Assert.Equal((uint)14, _ops.GetCurrent().MinLength);
    }

    [Fact]
    public async Task Audit_mode_does_not_write()
    {
        var dir = Parse("""{"min_length":20,"complexity_required":true}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal(2, r.Changes!.Count);
        Assert.All(r.Changes!, c => Assert.Contains("AUDIT", c));
        // Nothing actually changed
        Assert.Equal((uint)0, _ops.GetCurrent().MinLength);
        Assert.False(_ops.GetCurrent().ComplexityRequired);
    }

    [Fact]
    public async Task Empty_object_is_noop()
    {
        var dir = Parse("""{}""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Empty(r.Changes!);
    }

    [Fact]
    public async Task Boolean_knob_complexity_required()
    {
        var dir = Parse("""{"complexity_required":false}""");
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.False(_ops.GetCurrent().ComplexityRequired);

        var dir2 = Parse("""{"complexity_required":true}""");
        await _enforcer.ApplyAsync(dir2, EnforcementMode.Enforce);
        Assert.True(_ops.GetCurrent().ComplexityRequired);
    }

    [Fact]
    public async Task Min_age_days_and_lockout()
    {
        var dir = Parse("""{"min_age_days":1,"lockout_duration_minutes":15}""");
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal((uint)1, _ops.GetCurrent().MinAgeDays);
        Assert.Equal((uint)15, _ops.GetCurrent().LockoutDurationMinutes);
    }

    private static JsonElement Parse(string json)
        => JsonDocument.Parse(json).RootElement;
}
