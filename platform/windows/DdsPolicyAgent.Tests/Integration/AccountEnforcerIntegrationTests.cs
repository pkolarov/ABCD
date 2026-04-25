// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.HostState;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests.Integration;

/// <summary>
/// Integration tests for <see cref="WindowsAccountOperations"/> and
/// <see cref="AccountEnforcer"/> against real local SAM accounts.
///
/// All tests require elevation (admin). Test users are named
/// <c>dds-e2e-{hex}</c> and cleaned up in <see cref="Dispose"/>.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")]
public sealed class AccountEnforcerIntegrationTests : IDisposable
{
    private readonly WindowsAccountOperations _ops = new();
    private readonly InMemoryJoinStateProbe _probe = new(JoinState.Workgroup);
    private readonly string _suffix = Guid.NewGuid().ToString("N")[..8];
    private readonly List<string> _createdUsers = new();

    private string TestUser(string tag = "main") => $"dds-e2e-{_suffix[..4]}{tag[..1]}";

    // ----------------------------------------------------------------
    // WindowsJoinStateProbe — smoke
    // ----------------------------------------------------------------

    [SkippableFact]
    public void WindowsJoinStateProbe_Detect_Returns_Workgroup_On_Dev_Box()
    {
        SkipIfNotAdmin();
        // The dev / CI host is not domain-joined. We don't strictly
        // assert Workgroup (HybridJoined is theoretically possible if
        // the box is workplace-registered) — the contract under test
        // is that the probe completes without throwing and returns one
        // of the five well-known states. The build runner is expected
        // to be Workgroup; CI assertion is in the workgroup smoke.
        var probe = new WindowsJoinStateProbe();
        var state = probe.Detect();
        Assert.Contains(state, new[]
        {
            JoinState.Workgroup,
            JoinState.AdJoined,
            JoinState.HybridJoined,
            JoinState.EntraOnlyJoined,
            JoinState.Unknown,
        });
    }

    // ----------------------------------------------------------------
    // CreateUser / UserExists / DeleteUser
    // ----------------------------------------------------------------

    [SkippableFact]
    public void CreateUser_Creates_Local_Account()
    {
        SkipIfNotAdmin();
        var user = TestUser();
        _ops.CreateUser(user, "DDS E2E Test", "Integration test account");
        _createdUsers.Add(user);

        Assert.True(_ops.UserExists(user));
    }

    [SkippableFact]
    public void UserExists_Returns_False_For_Missing()
    {
        SkipIfNotAdmin();
        Assert.False(_ops.UserExists($"dds-nosuch-{_suffix}"));
    }

    [SkippableFact]
    public void DeleteUser_Removes_Account()
    {
        SkipIfNotAdmin();
        var user = TestUser("del");
        _ops.CreateUser(user, null, null);
        Assert.True(_ops.UserExists(user));

        _ops.DeleteUser(user);
        Assert.False(_ops.UserExists(user));
        // No need to add to _createdUsers since we just deleted it
    }

    // ----------------------------------------------------------------
    // Disable / Enable / IsEnabled
    // ----------------------------------------------------------------

    [SkippableFact]
    public void Disable_Then_Enable_Roundtrips()
    {
        SkipIfNotAdmin();
        var user = TestUser("dis");
        _ops.CreateUser(user, null, null);
        _createdUsers.Add(user);

        Assert.True(_ops.IsEnabled(user));

        _ops.DisableUser(user);
        Assert.False(_ops.IsEnabled(user));

        _ops.EnableUser(user);
        Assert.True(_ops.IsEnabled(user));
    }

    // ----------------------------------------------------------------
    // Groups
    // ----------------------------------------------------------------

    [SkippableFact]
    public void AddToGroup_And_GetGroups()
    {
        SkipIfNotAdmin();
        var user = TestUser("grp");
        _ops.CreateUser(user, null, null);
        _createdUsers.Add(user);

        _ops.AddToGroup(user, "Users");
        var groups = _ops.GetGroups(user);
        Assert.Contains("Users", groups);
    }

    [SkippableFact]
    public void AddToGroup_Idempotent()
    {
        SkipIfNotAdmin();
        var user = TestUser("dup");
        _ops.CreateUser(user, null, null);
        _createdUsers.Add(user);

        _ops.AddToGroup(user, "Users");
        // Second add should not throw (ERROR_MEMBER_IN_ALIAS is silenced)
        _ops.AddToGroup(user, "Users");
        Assert.Contains("Users", _ops.GetGroups(user));
    }

    // ----------------------------------------------------------------
    // PasswordNeverExpires
    // ----------------------------------------------------------------

    [SkippableFact]
    public void SetPasswordNeverExpires_Roundtrips()
    {
        SkipIfNotAdmin();
        var user = TestUser("pne");
        _ops.CreateUser(user, null, null);
        _createdUsers.Add(user);

        _ops.SetPasswordNeverExpires(user, true);
        // Verify by reading back — IsEnabled doesn't cover this, so we
        // rely on no exception + a second toggle
        _ops.SetPasswordNeverExpires(user, false);
        // If we get here, both directions work
    }

    // ----------------------------------------------------------------
    // Full enforcer pipeline
    // ----------------------------------------------------------------

    [SkippableFact]
    public async Task Full_Enforcer_Create_With_Groups()
    {
        SkipIfNotAdmin();
        var user = TestUser("enf");
        _createdUsers.Add(user);

        var enforcer = new AccountEnforcer(_ops, _probe, NullLogger<AccountEnforcer>.Instance);
        var json = $$"""
        [{"username":"{{user}}","action":"Create","full_name":"E2E Bot","groups":["Users"],"password_never_expires":true}]
        """;
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, result.Status);
        Assert.True(_ops.UserExists(user));
        Assert.Contains("Users", _ops.GetGroups(user));
    }

    [SkippableFact]
    public async Task Full_Enforcer_Disable_Then_Delete()
    {
        SkipIfNotAdmin();
        var user = TestUser("dld");
        _ops.CreateUser(user, null, null);
        _createdUsers.Add(user);

        var enforcer = new AccountEnforcer(_ops, _probe, NullLogger<AccountEnforcer>.Instance);

        // Disable
        var disableJson = $$"""[{"username":"{{user}}","action":"Disable"}]""";
        var r1 = await enforcer.ApplyAsync(
            JsonDocument.Parse(disableJson).RootElement, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r1.Status);
        Assert.False(_ops.IsEnabled(user));

        // Delete
        var deleteJson = $$"""[{"username":"{{user}}","action":"Delete"}]""";
        var r2 = await enforcer.ApplyAsync(
            JsonDocument.Parse(deleteJson).RootElement, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r2.Status);
        Assert.False(_ops.UserExists(user));
        _createdUsers.Remove(user); // already deleted
    }

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------

    public void Dispose()
    {
        foreach (var user in _createdUsers)
        {
            try { _ops.DeleteUser(user); } catch { /* best-effort */ }
        }
    }

    private static void SkipIfNotAdmin()
    {
        var reason = IntegrationTestHelpers.SkipIfNotWindows();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
        reason = IntegrationTestHelpers.SkipIfNotAdmin();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
    }
}
