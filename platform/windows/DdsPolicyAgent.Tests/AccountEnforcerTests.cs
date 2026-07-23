// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.HostState;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

public class AccountEnforcerTests
{
    private readonly InMemoryAccountOperations _ops = new();
    private readonly InMemoryJoinStateProbe _joinState = new(JoinState.Workgroup);
    private readonly AccountEnforcer _enforcer;

    public AccountEnforcerTests()
    {
        _enforcer = new AccountEnforcer(_ops, _joinState, NullLogger<AccountEnforcer>.Instance);
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
        _joinState.Current = JoinState.AdJoined;
        var dir = Parse("""[{"username":"alice","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, r.Status);
        Assert.Contains("domain-joined", r.Error);
        Assert.False(_ops.UserExists("alice"));
    }

    [Fact]
    public async Task Refuses_on_hybrid_joined_machine()
    {
        _joinState.Current = JoinState.HybridJoined;
        var dir = Parse("""[{"username":"alice","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, r.Status);
        Assert.False(_ops.UserExists("alice"));
    }

    [Fact]
    public async Task Allows_on_workgroup_machine()
    {
        _joinState.Current = JoinState.Workgroup;
        var dir = Parse("""[{"username":"wg","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.True(_ops.UserExists("wg"));
    }

    [Fact]
    public async Task Refuses_on_unknown_join_state_without_claiming_domain_joined()
    {
        // Fail-closed on Unknown is intentional, but the recorded reason
        // must say the state was undetermined — a workgroup machine with
        // a failing probe was previously reported as "domain-joined",
        // which sent operators chasing a nonexistent AD join.
        _joinState.Current = JoinState.Unknown;
        var dir = Parse("""[{"username":"alice","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, r.Status);
        Assert.Contains("could not be determined", r.Error);
        Assert.DoesNotContain("domain-joined", r.Error);
        Assert.False(_ops.UserExists("alice"));
    }

    [Fact]
    public async Task Allows_on_entra_only_joined_machine()
    {
        // EntraOnlyJoined is not AD — account mutation stays in scope,
        // matching the pre-change RefuseOnHostState() set (AdJoined,
        // HybridJoined, Unknown).
        _joinState.Current = JoinState.EntraOnlyJoined;
        var dir = Parse("""[{"username":"eo","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r.Status);
        Assert.True(_ops.UserExists("eo"));
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

    // --- Username validation ---

    [Theory]
    [InlineData("alice")]
    [InlineData("svc-account")]
    [InlineData("node_1")]
    [InlineData("a")]
    [InlineData("ABCDEFGHIJ1234567890")]  // exactly 20 chars
    public void IsValidUsername_accepts_valid_names(string name)
    {
        Assert.True(AccountEnforcer.IsValidUsername(name));
    }

    [Theory]
    [InlineData("")]                          // empty
    [InlineData("ABCDEFGHIJ12345678901")]     // 21 chars
    [InlineData("alice/bob")]                 // slash (SAM forbidden)
    [InlineData("alice\\bob")]                // backslash (SAM forbidden)
    [InlineData("alice[0]")]                  // brackets (SAM forbidden)
    [InlineData("alice:1")]                   // colon (SAM forbidden)
    [InlineData("alice;1")]                   // semicolon (SAM forbidden)
    [InlineData("alice|pipe")]                // pipe (SAM forbidden)
    [InlineData("a=b")]                       // equals (SAM forbidden)
    [InlineData("a,b")]                       // comma (SAM forbidden)
    [InlineData("a+b")]                       // plus (SAM forbidden)
    [InlineData("a*b")]                       // asterisk (SAM forbidden)
    [InlineData("a?b")]                       // question mark (SAM forbidden)
    [InlineData("a<b")]                       // less-than (SAM forbidden)
    [InlineData("a>b")]                       // greater-than (SAM forbidden)
    [InlineData("alice@domain")]              // at-sign (SAM forbidden)
    [InlineData("ends.")]                     // trailing dot
    [InlineData("ends ")]                     // space (not in allowlist)
    [InlineData("alice bob")]                 // space in middle (not in allowlist)
    [InlineData("alice!")]                    // exclamation (not in allowlist)
    [InlineData("alice#1")]                   // hash (not in allowlist)
    [InlineData("alice\tname")]               // tab — control character
    public void IsValidUsername_rejects_invalid_names(string name)
    {
        Assert.False(AccountEnforcer.IsValidUsername(name));
    }

    [Fact]
    public async Task Invalid_username_returns_failed_status()
    {
        var dir = Parse("""[{"username":"alice/admin","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        Assert.Contains("FAILED", r.Changes![0]);
        Assert.False(_ops.UserExists("alice/admin"));
    }

    [Fact]
    public async Task Username_too_long_returns_failed_status()
    {
        var dir = Parse("""[{"username":"ABCDEFGHIJ12345678901","action":"Create"}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
    }

    // --- Group name validation ---

    [Theory]
    [InlineData("Administrators")]
    [InlineData("Remote Desktop Users")]
    [InlineData("my-group_1")]
    public void IsValidGroupName_accepts_valid_names(string name)
    {
        Assert.True(AccountEnforcer.IsValidGroupName(name));
    }

    [Theory]
    [InlineData("")]                   // empty
    [InlineData("group/evil")]         // slash
    [InlineData("group:name")]         // colon
    [InlineData("group|pipe")]         // pipe
    [InlineData("ends.")]              // trailing dot
    [InlineData("ends ")]              // trailing space
    [InlineData("group\tname")]        // tab — control character
    [InlineData("group\nname")]        // newline — control character
    public void IsValidGroupName_rejects_invalid_names(string name)
    {
        Assert.False(AccountEnforcer.IsValidGroupName(name));
    }

    [Fact]
    public async Task Invalid_group_name_in_Create_returns_failed_status()
    {
        var dir = Parse("""[{"username":"alice","action":"Create","groups":["bad/group"]}]""");
        var r = await _enforcer.ApplyAsync(dir, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, r.Status);
        Assert.Contains("FAILED", r.Changes![0]);
        // alice was created before group validation ran; group was NOT added
        Assert.True(_ops.UserExists("alice"));
        Assert.DoesNotContain("bad/group", _ops.GetGroups("alice"));
    }

    // --- ReconcileStaleGroups ---

    [Fact]
    public void ReconcileStaleGroups_removes_valid_stale_group()
    {
        _ops.CreateUser("alice", null, null);
        _ops.AddToGroup("alice", "Administrators");

        var changes = _enforcer.ReconcileStaleGroups(
            new HashSet<string>(["alice:Administrators"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-RemoveFromGroup", changes[0]);
        Assert.DoesNotContain("Administrators", _ops.GetGroups("alice"));
    }

    [Fact]
    public void ReconcileStaleGroups_audit_mode_does_not_remove()
    {
        _ops.CreateUser("alice", null, null);
        _ops.AddToGroup("alice", "Administrators");

        var changes = _enforcer.ReconcileStaleGroups(
            new HashSet<string>(["alice:Administrators"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.Contains("Administrators", _ops.GetGroups("alice"));
    }

    [Fact]
    public void ReconcileStaleGroups_skips_invalid_group_name()
    {
        _ops.CreateUser("alice", null, null);
        _ops.AddToGroup("alice", "bad/group");

        var changes = _enforcer.ReconcileStaleGroups(
            new HashSet<string>(["alice:bad/group"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Empty(changes);
        Assert.Contains("bad/group", _ops.GetGroups("alice")); // NOT removed — invalid key was skipped
    }

    [Fact]
    public void ReconcileStaleAccounts_skips_invalid_username()
    {
        // A stale key with an invalid username (e.g. containing a slash) must
        // be skipped without calling into Win32 — symmetric with the group-name
        // validation added for ReconcileStaleGroups.
        var changes = _enforcer.ReconcileStaleAccounts(
            new HashSet<string>(["bad/user"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Empty(changes);
    }

    [Fact]
    public void ReconcileStaleGroups_skips_invalid_username_in_key()
    {
        // A stale group key whose username part is invalid must be skipped
        // before any Win32 group-removal call — symmetric with the group-name
        // check added in the 75th pass.
        _ops.CreateUser("alice", null, null);
        _ops.AddToGroup("alice", "Administrators");

        var changes = _enforcer.ReconcileStaleGroups(
            new HashSet<string>(["bad/user:Administrators"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Empty(changes);
        Assert.Contains("Administrators", _ops.GetGroups("alice")); // untouched
    }

    private static JsonElement Parse(string json)
        => JsonDocument.Parse(json).RootElement;
}
