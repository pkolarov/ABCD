// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

public class ServiceEnforcerTests
{
    private readonly InMemoryServiceOperations _ops = new();
    private readonly ServiceEnforcer _enforcer;

    public ServiceEnforcerTests()
    {
        _enforcer = new ServiceEnforcer(_ops, NullLogger<ServiceEnforcer>.Instance);
    }

    private static JsonElement Parse(string json) =>
        JsonDocument.Parse(json).RootElement;

    // --- Configure action ---

    [Fact]
    public async Task Configure_sets_start_type()
    {
        _ops.Seed("wuauserv", startType: "Automatic");
        var dir = Parse("""[{"name":"wuauserv","start_type":"Disabled","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal("Disabled", _ops.Peek("wuauserv")!.StartType);
    }

    [Fact]
    public async Task Configure_is_noop_when_start_type_unchanged()
    {
        _ops.Seed("wuauserv", startType: "Manual");
        var dir = Parse("""[{"name":"wuauserv","start_type":"Manual","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    [Fact]
    public async Task Configure_is_noop_when_service_not_found()
    {
        var dir = Parse("""[{"name":"nosuchsvc","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
        Assert.Contains("not found", r.Changes![0]);
    }

    [Fact]
    public async Task Configure_with_no_start_type_is_noop()
    {
        _ops.Seed("spooler");
        var dir = Parse("""[{"name":"spooler","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    // --- Start action ---

    [Fact]
    public async Task Start_starts_stopped_service()
    {
        _ops.Seed("spooler", startType: "Automatic", runState: "Stopped");
        var dir = Parse("""[{"name":"spooler","action":"Start"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal("Running", _ops.Peek("spooler")!.RunState);
    }

    [Fact]
    public async Task Start_is_noop_when_already_running()
    {
        _ops.Seed("spooler", runState: "Running");
        var dir = Parse("""[{"name":"spooler","action":"Start"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    [Fact]
    public async Task Start_also_sets_start_type()
    {
        _ops.Seed("spooler", startType: "Manual", runState: "Stopped");
        var dir = Parse("""[{"name":"spooler","start_type":"Automatic","action":"Start"}]""");
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal("Automatic", _ops.Peek("spooler")!.StartType);
        Assert.Equal("Running", _ops.Peek("spooler")!.RunState);
    }

    [Fact]
    public async Task Start_is_noop_for_nonexistent_service()
    {
        var dir = Parse("""[{"name":"nosuchsvc","action":"Start"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    // --- Stop action ---

    [Fact]
    public async Task Stop_stops_running_service()
    {
        _ops.Seed("bits", runState: "Running");
        var dir = Parse("""[{"name":"bits","action":"Stop"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal("Stopped", _ops.Peek("bits")!.RunState);
    }

    [Fact]
    public async Task Stop_is_noop_when_already_stopped()
    {
        _ops.Seed("bits", runState: "Stopped");
        var dir = Parse("""[{"name":"bits","action":"Stop"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    [Fact]
    public async Task Stop_also_sets_start_type_to_disabled()
    {
        _ops.Seed("bits", startType: "Automatic", runState: "Running");
        var dir = Parse("""[{"name":"bits","start_type":"Disabled","action":"Stop"}]""");
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal("Disabled", _ops.Peek("bits")!.StartType);
        Assert.Equal("Stopped", _ops.Peek("bits")!.RunState);
    }

    // --- Audit mode ---

    [Fact]
    public async Task Audit_mode_does_not_change_state()
    {
        _ops.Seed("spooler", startType: "Automatic", runState: "Running");
        var dir = Parse("""[{"name":"spooler","start_type":"Disabled","action":"Stop"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("[AUDIT]", r.Changes![0]);
        // State must be unchanged
        Assert.Equal("Automatic", _ops.Peek("spooler")!.StartType);
        Assert.Equal("Running", _ops.Peek("spooler")!.RunState);
    }

    // --- Security: service name validation ---

    [Fact]
    public async Task Rejects_service_name_with_path_traversal()
    {
        var dir = Parse("""[{"name":"..\\evil","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        Assert.Contains("FAILED", r.Changes![0]);
    }

    [Fact]
    public async Task Rejects_service_name_with_spaces()
    {
        var dir = Parse("""[{"name":"evil service","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
    }

    [Fact]
    public async Task Rejects_empty_service_name()
    {
        var dir = Parse("""[{"name":"","action":"Configure"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
    }

    [Fact]
    public void SafeServiceNamePattern_allows_valid_names()
    {
        Assert.Matches(ServiceEnforcer.SafeServiceNamePattern, "wuauserv");
        Assert.Matches(ServiceEnforcer.SafeServiceNamePattern, "DdsPolicyAgent");
        Assert.Matches(ServiceEnforcer.SafeServiceNamePattern, "my-service_1");
    }

    // --- Multiple directives ---

    [Fact]
    public async Task Multiple_directives_are_all_applied()
    {
        _ops.Seed("svcA", startType: "Automatic", runState: "Stopped");
        _ops.Seed("svcB", startType: "Manual", runState: "Running");
        var dir = Parse("""
        [
            {"name":"svcA","action":"Start"},
            {"name":"svcB","action":"Stop"}
        ]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal(2, r.Changes!.Count);
        Assert.Equal("Running", _ops.Peek("svcA")!.RunState);
        Assert.Equal("Stopped", _ops.Peek("svcB")!.RunState);
    }

    [Fact]
    public async Task Partial_failure_returns_failed_status()
    {
        _ops.Seed("goodsvc", runState: "Stopped");
        // "badsvc" has invalid name (space)
        var dir = Parse("""
        [
            {"name":"goodsvc","action":"Start"},
            {"name":"bad svc","action":"Configure"}
        ]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        // goodsvc should still have been processed
        Assert.Equal("Running", _ops.Peek("goodsvc")!.RunState);
    }

    // --- ExtractManagedKey ---

    [Fact]
    public void ExtractManagedKey_returns_service_name()
    {
        var item = JsonDocument.Parse("""{"name":"spooler","action":"Start"}""").RootElement;
        Assert.Equal("spooler", ServiceEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void ExtractManagedKey_returns_null_for_missing_name()
    {
        var item = JsonDocument.Parse("""{"action":"Start"}""").RootElement;
        Assert.Null(ServiceEnforcer.ExtractManagedKey(item));
    }
}
