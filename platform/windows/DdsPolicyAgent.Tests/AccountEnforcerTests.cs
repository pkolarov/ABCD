// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

public class AccountEnforcerTests
{
    private readonly InMemoryAccountOperations _ops = new();
    private readonly AccountEnforcer _enforcer;

    public AccountEnforcerTests()
    {
        _enforcer = new AccountEnforcer(_ops, NullLogger<AccountEnforcer>.Instance);
    }

    // --- Create ---

    [Fact]
    public async Task Create_new_user()
    {
        var dir = Parse("""[{"username":"alice","action":"Create","full_name":"Alice A","description":"Test user"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.True(_ops.UserExists("alice"));
        Assert.Equal("Alice A", _ops.Peek("alice")!.FullName);
        Assert.Equal("Test user", _ops.Peek("alice")!.Description);
    }

    [Fact]
    public async Task Create_with_groups()
    {
        var dir = Parse("""
        [{"username":"bob","action":"Create","groups":["Administrators","Remote Desktop Users"]}]
        """);
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        var groups = _ops.GetGroups("bob");
        Assert.Contains("Administrators", groups);
        Assert.Contains("Remote Desktop Users", groups);
    }

    [Fact]
    public async Task Create_with_password_never_expires()
    {
        var dir = Parse("""[{"username":"svc","action":"Create","password_never_expires":true}]""");
        await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.True(_ops.Peek("svc")!.PasswordNeverExpires);
    }

    [Fact]
    public async Task Create_is_idempotent_for_existing_user()
    {
        _ops.CreateUser("alice", null, null);
        var dir = Parse("""[{"username":"alice","action":"Create","groups":["Users"]}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        // Should add group without error
        Assert.Contains("Users", _ops.GetGroups("alice"));
    }

    // --- Delete ---

    [Fact]
    public async Task Delete_existing_user()
    {
        _ops.CreateUser("temp", null, null);
        var dir = Parse("""[{"username":"temp","action":"Delete"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.False(_ops.UserExists("temp"));
    }

    [Fact]
    public async Task Delete_nonexistent_is_noop()
    {
        var dir = Parse("""[{"username":"ghost","action":"Delete"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    // --- Disable / Enable ---

    [Fact]
    public async Task Disable_then_enable()
    {
        _ops.CreateUser("target", null, null);
        Assert.True(_ops.IsEnabled("target"));

        var disable = Parse("""[{"username":"target","action":"Disable"}]""");
        await _enforcer.ApplyAsync(disable, EnforcementMode.Enforce);
        Assert.False(_ops.IsEnabled("target"));

        var enable = Parse("""[{"username":"target","action":"Enable"}]""");
        await _enforcer.ApplyAsync(enable, EnforcementMode.Enforce);
        Assert.True(_ops.IsEnabled("target"));
    }

    [Fact]
    public async Task Disable_already_disabled_is_noop()
    {
        _ops.CreateUser("dis", null, null);
        _ops.DisableUser("dis");
        var dir = Parse("""[{"username":"dis","action":"Disable"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    [Fact]
    public async Task Enable_already_enabled_is_noop()
    {
        _ops.CreateUser("en", null, null);
        var dir = Parse("""[{"username":"en","action":"Enable"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Contains("NO-OP", r.Changes![0]);
    }

    // --- Audit mode ---

    [Fact]
    public async Task Audit_mode_does_not_create()
    {
        var dir = Parse("""[{"username":"phantom","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Contains("AUDIT", r.Changes![0]);
        Assert.False(_ops.UserExists("phantom"));
    }

    // --- Domain-join guard ---

    [Fact]
    public async Task Refuses_on_domain_joined_machine()
    {
        _ops.SimulateDomainJoined = true;
        var dir = Parse("""[{"username":"alice","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, r.Status);
        Assert.Contains("domain-joined", r.Error);
        Assert.False(_ops.UserExists("alice"));
    }

    // --- Multiple directives ---

    [Fact]
    public async Task Multiple_directives_in_order()
    {
        var dir = Parse("""
        [
            {"username":"a","action":"Create"},
            {"username":"b","action":"Create"},
            {"username":"a","action":"Disable"}
        ]
        """);
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.Equal(3, r.Changes!.Count);
        Assert.True(_ops.UserExists("a"));
        Assert.False(_ops.IsEnabled("a"));
        Assert.True(_ops.UserExists("b"));
    }

    private static JsonElement Parse(string json)
        => JsonDocument.Parse(json).RootElement;
}
