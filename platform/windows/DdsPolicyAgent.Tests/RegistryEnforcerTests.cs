// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

public class RegistryEnforcerTests
{
    private readonly InMemoryRegistryOperations _ops = new();
    private readonly RegistryEnforcer _enforcer;

    public RegistryEnforcerTests()
    {
        _enforcer = new RegistryEnforcer(_ops, NullLogger<RegistryEnforcer>.Instance);
    }

    // --- Set action ---

    [Fact]
    public async Task Set_dword_creates_value()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Test","name":"MaxRetries","value":{"Dword":3},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal((uint)3, _ops.Peek("LocalMachine", @"SOFTWARE\Policies\Test", "MaxRetries"));
    }

    [Fact]
    public async Task Set_string_creates_value()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\App","name":"License","value":{"String":"ABC-123"},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal("ABC-123", _ops.Peek("LocalMachine", @"SOFTWARE\Policies\App", "License"));
    }

    [Fact]
    public async Task Set_qword_creates_value()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Q","name":"BigNum","value":{"Qword":9999999999},"action":"Set"}]
        """);
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal((ulong)9999999999, _ops.Peek("LocalMachine", @"SOFTWARE\Policies\Q", "BigNum"));
    }

    [Fact]
    public async Task Set_multistring_creates_value()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\M","name":"Items","value":{"MultiString":["a","b","c"]},"action":"Set"}]
        """);
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        var val = _ops.Peek("LocalMachine", @"SOFTWARE\Policies\M", "Items") as string[];
        Assert.NotNull(val);
        Assert.Equal(["a", "b", "c"], val);
    }

    [Fact]
    public async Task Set_is_idempotent_when_value_unchanged()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Idem","name":"Flag","value":{"Dword":1},"action":"Set"}]
        """);
        var r1 = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r1.Status);
        Assert.Contains("Set", r1.Changes![0]);

        // Second apply — value already at desired state
        var r2 = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r2.Status);
        Assert.Contains("NO-OP", r2.Changes![0]);
    }

    [Fact]
    public async Task Set_overwrites_when_value_differs()
    {
        _ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Up", "V", (uint)1, RegValueKind.Dword);
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Up","name":"V","value":{"Dword":2},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal((uint)2, _ops.Peek("LocalMachine", @"SOFTWARE\Policies\Up", "V"));
    }

    // --- Delete action ---

    [Fact]
    public async Task Delete_value_removes_it()
    {
        _ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Del", "Gone", "x", RegValueKind.String);
        Assert.NotNull(_ops.Peek("LocalMachine", @"SOFTWARE\Policies\Del", "Gone"));

        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Del","name":"Gone","action":"Delete"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Null(_ops.Peek("LocalMachine", @"SOFTWARE\Policies\Del", "Gone"));
    }

    [Fact]
    public async Task Delete_key_removes_key()
    {
        _ops.SetValue("LocalMachine", @"SOFTWARE\Policies\RemoveMe", "X", "v", RegValueKind.String);
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\RemoveMe","action":"Delete"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Null(_ops.Peek("LocalMachine", @"SOFTWARE\Policies\RemoveMe", "X"));
    }

    // --- Audit mode ---

    [Fact]
    public async Task Audit_mode_does_not_write()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Audit","name":"V","value":{"Dword":1},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("AUDIT", r.Changes![0]);
        Assert.Null(_ops.Peek("LocalMachine", @"SOFTWARE\Policies\Audit", "V"));
    }

    // --- Security: allowlist ---

    [Fact]
    public async Task Refuses_write_outside_allowlist()
    {
        var dir = Parse("""
        [{"hive":"LocalMachine","key":"SOFTWARE\\Evil\\Path","name":"Backdoor","value":{"Dword":1},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        Assert.Contains("outside the allowed", r.Error);
    }

    [Fact]
    public async Task Refuses_write_to_non_HKLM_hive()
    {
        var dir = Parse("""
        [{"hive":"CurrentUser","key":"SOFTWARE\\Policies\\Test","name":"V","value":{"Dword":1},"action":"Set"}]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
    }

    [Theory]
    [InlineData(@"SOFTWARE\Policies\Microsoft\Windows\System", true)]
    [InlineData(@"SOFTWARE\DDS\Agent", true)]
    [InlineData(@"SYSTEM\CurrentControlSet\Services\MyService", true)]
    [InlineData(@"SOFTWARE\Evil\Path", false)]
    [InlineData(@"SYSTEM\Setup", false)]
    [InlineData(@"SAM\Domains", false)]
    public void IsAllowed_checks_prefix(string key, bool expected)
    {
        Assert.Equal(expected, RegistryEnforcer.IsAllowed("LocalMachine", key));
    }

    // --- Value parsing ---

    [Fact]
    public void ParseValue_handles_all_variants()
    {
        var item = JsonDocument.Parse("""
            {"value":{"ExpandString":"%SystemRoot%\\System32"}}
        """).RootElement;
        var (val, kind) = RegistryEnforcer.ParseValue(item);
        Assert.Equal(RegValueKind.ExpandString, kind);
        Assert.Equal(@"%SystemRoot%\System32", val);
    }

    [Fact]
    public void ParseValue_rejects_missing_value()
    {
        var item = JsonDocument.Parse("""{"action":"Set"}""").RootElement;
        Assert.Throws<InvalidOperationException>(() => RegistryEnforcer.ParseValue(item));
    }

    // --- Multiple directives ---

    [Fact]
    public async Task Multiple_directives_applied_in_order()
    {
        var dir = Parse("""
        [
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Multi","name":"A","value":{"Dword":1},"action":"Set"},
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Multi","name":"B","value":{"String":"hello"},"action":"Set"},
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Multi","name":"A","action":"Delete"}
        ]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal(3, r.Changes!.Count);
        // A was set then deleted, B remains
        Assert.Null(_ops.Peek("LocalMachine", @"SOFTWARE\Policies\Multi", "A"));
        Assert.Equal("hello", _ops.Peek("LocalMachine", @"SOFTWARE\Policies\Multi", "B"));
    }

    [Fact]
    public async Task One_bad_directive_does_not_stop_others()
    {
        var dir = Parse("""
        [
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\OK","name":"V","value":{"Dword":1},"action":"Set"},
            {"hive":"LocalMachine","key":"SOFTWARE\\Evil\\Bad","name":"X","value":{"Dword":1},"action":"Set"},
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\OK2","name":"V","value":{"Dword":2},"action":"Set"}
        ]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        // Overall status is Failed because one directive failed
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        Assert.Equal(3, r.Changes!.Count);
        // But the valid ones were still applied
        Assert.Equal((uint)1, _ops.Peek("LocalMachine", @"SOFTWARE\Policies\OK", "V"));
        Assert.Equal((uint)2, _ops.Peek("LocalMachine", @"SOFTWARE\Policies\OK2", "V"));
    }

    private static JsonElement Parse(string json)
        => JsonDocument.Parse(json).RootElement;
}
