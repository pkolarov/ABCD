// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// Phase C enforcers are log-only stubs. These tests verify the
/// contract: they always return <see cref="EnforcementStatus.Skipped"/>
/// and produce a non-empty change list.
/// </summary>
public class EnforcerStubTests
{
    [Fact]
    public async Task RegistryEnforcer_audit_mode_returns_ok_with_changes()
    {
        var ops = new InMemoryRegistryOperations();
        var e = new RegistryEnforcer(ops, NullLogger<RegistryEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
            {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Test","name":"Enabled","value":{"Dword":1},"action":"Set"}
        ]
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("AUDIT", outcome.Changes[0]);
        // Audit mode must NOT write to the registry
        Assert.Equal(0, ops.Count);
    }

    [Fact]
    public async Task AccountEnforcer_creates_user_in_enforce_mode()
    {
        var ops = new InMemoryAccountOperations();
        var e = new AccountEnforcer(ops, NullLogger<AccountEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
            {"username":"alice","action":"Create"}
        ]
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("alice", outcome.Changes[0]);
        Assert.True(ops.UserExists("alice"));
    }

    [Fact]
    public async Task PasswordPolicyEnforcer_sets_knobs_in_enforce_mode()
    {
        var ops = new InMemoryPasswordPolicyOperations();
        var e = new PasswordPolicyEnforcer(ops, NullLogger<PasswordPolicyEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        {"min_length":14,"complexity_required":true,"lockout_threshold":null}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(outcome.Changes);
        // lockout_threshold is null => skipped, so 2 changes
        Assert.Equal(2, outcome.Changes.Count);
        var state = ops.GetCurrent();
        Assert.Equal((uint)14, state.MinLength);
        Assert.True(state.ComplexityRequired);
    }

    [Fact]
    public async Task SoftwareInstaller_install_requires_source_url()
    {
        var ops = new InMemorySoftwareOperations();
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.Contains("source_url", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_audit_mode_does_not_install()
    {
        var ops = new InMemorySoftwareOperations();
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install",
         "source_url":"https://example.com/editor.msi","sha256":"abc123"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Audit);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.Contains("AUDIT", outcome.Changes![0]);
        Assert.False(ops.IsInstalled("com.example.editor"));
    }

    [Fact]
    public async Task SoftwareInstaller_install_via_in_memory_ops()
    {
        var ops = new InMemorySoftwareOperations();
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install",
         "installer_type":"msi","source_url":"https://example.com/editor.msi",
         "sha256":"abc123"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.Single(outcome.Changes!);
        Assert.Contains("editor", outcome.Changes[0]);
    }

    [Fact]
    public async Task SoftwareInstaller_uninstall_not_installed_is_noop()
    {
        var ops = new InMemorySoftwareOperations();
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Uninstall"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.Contains("NO-OP", outcome.Changes![0]);
    }

    [Fact]
    public async Task SoftwareInstaller_rejects_bad_sha256()
    {
        var ops = new InMemorySoftwareOperations { SimulateHashMismatch = true };
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install",
         "installer_type":"msi","source_url":"https://example.com/editor.msi",
         "sha256":"abc123"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.Contains("SHA-256", outcome.Error);
    }

    // ----------------------------------------------------------------
    // Reconciliation tests
    // ----------------------------------------------------------------

    [Fact]
    public void RegistryEnforcer_ExtractManagedKey_extracts_hive_key_name()
    {
        var item = JsonDocument.Parse("""
        {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Test","name":"Enabled","value":{"Dword":1},"action":"Set"}
        """).RootElement;

        var key = RegistryEnforcer.ExtractManagedKey(item);
        Assert.Equal(@"LocalMachine\SOFTWARE\Policies\Test\Enabled", key);
    }

    [Fact]
    public void RegistryEnforcer_ExtractManagedKey_key_only_when_no_name()
    {
        var item = JsonDocument.Parse("""
        {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\Test","action":"Delete"}
        """).RootElement;

        var key = RegistryEnforcer.ExtractManagedKey(item);
        Assert.Equal(@"LocalMachine\SOFTWARE\Policies\Test", key);
    }

    [Fact]
    public void RegistryEnforcer_reconcile_deletes_stale_value()
    {
        var ops = new InMemoryRegistryOperations();
        ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Test", "OldValue", (uint)42, RegValueKind.Dword);
        var e = new RegistryEnforcer(ops, NullLogger<RegistryEnforcer>.Instance);

        var stale = new HashSet<string> { @"LocalMachine\SOFTWARE\Policies\Test\OldValue" };
        var changes = e.ReconcileStaleItems(stale, EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Delete", changes[0]);
        Assert.Null(ops.Peek("LocalMachine", @"SOFTWARE\Policies\Test", "OldValue"));
    }

    [Fact]
    public void RegistryEnforcer_reconcile_audit_mode_does_not_delete()
    {
        var ops = new InMemoryRegistryOperations();
        ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Test", "OldValue", (uint)42, RegValueKind.Dword);
        var e = new RegistryEnforcer(ops, NullLogger<RegistryEnforcer>.Instance);

        var stale = new HashSet<string> { @"LocalMachine\SOFTWARE\Policies\Test\OldValue" };
        var changes = e.ReconcileStaleItems(stale, EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("AUDIT", changes[0]);
        Assert.NotNull(ops.Peek("LocalMachine", @"SOFTWARE\Policies\Test", "OldValue"));
    }

    [Fact]
    public void RegistryEnforcer_reconcile_skips_outside_allowlist()
    {
        var ops = new InMemoryRegistryOperations();
        var e = new RegistryEnforcer(ops, NullLogger<RegistryEnforcer>.Instance);

        var stale = new HashSet<string> { @"LocalMachine\SYSTEM\BadPath\Value1" };
        var changes = e.ReconcileStaleItems(stale, EnforcementMode.Enforce);

        Assert.Empty(changes);
    }

    [Fact]
    public void AccountEnforcer_ExtractManagedKey_returns_username_for_create()
    {
        var item = JsonDocument.Parse("""{"username":"alice","action":"Create"}""").RootElement;
        Assert.Equal("alice", AccountEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void AccountEnforcer_ExtractManagedKey_returns_null_for_delete()
    {
        var item = JsonDocument.Parse("""{"username":"alice","action":"Delete"}""").RootElement;
        Assert.Null(AccountEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void AccountEnforcer_ExtractManagedGroups_returns_user_group_pairs()
    {
        var item = JsonDocument.Parse("""
        {"username":"bob","action":"Create","groups":["Administrators","Users"]}
        """).RootElement;

        var groups = AccountEnforcer.ExtractManagedGroups(item).ToList();
        Assert.Equal(2, groups.Count);
        Assert.Contains("bob:Administrators", groups);
        Assert.Contains("bob:Users", groups);
    }

    [Fact]
    public void AccountEnforcer_reconcile_disables_stale_user()
    {
        var ops = new InMemoryAccountOperations();
        ops.CreateUser("stale-user", null, null);
        var e = new AccountEnforcer(ops, NullLogger<AccountEnforcer>.Instance);

        var stale = new HashSet<string> { "stale-user" };
        var changes = e.ReconcileStaleAccounts(stale, EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Disable", changes[0]);
        Assert.False(ops.IsEnabled("stale-user"));
    }

    [Fact]
    public void AccountEnforcer_reconcile_audit_does_not_disable()
    {
        var ops = new InMemoryAccountOperations();
        ops.CreateUser("stale-user", null, null);
        var e = new AccountEnforcer(ops, NullLogger<AccountEnforcer>.Instance);

        var stale = new HashSet<string> { "stale-user" };
        var changes = e.ReconcileStaleAccounts(stale, EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("AUDIT", changes[0]);
        Assert.True(ops.IsEnabled("stale-user"));
    }

    [Fact]
    public void AccountEnforcer_reconcile_removes_stale_group()
    {
        var ops = new InMemoryAccountOperations();
        ops.CreateUser("bob", null, null);
        ops.AddToGroup("bob", "Administrators");
        ops.AddToGroup("bob", "Users");
        var e = new AccountEnforcer(ops, NullLogger<AccountEnforcer>.Instance);

        var stale = new HashSet<string> { "bob:Administrators" };
        var changes = e.ReconcileStaleGroups(stale, EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("RemoveFromGroup", changes[0]);
        var groups = ops.GetGroups("bob");
        Assert.DoesNotContain("Administrators", groups);
        Assert.Contains("Users", groups);
    }

    [Fact]
    public void SoftwareInstaller_ExtractManagedKey_returns_packageId_for_install()
    {
        var item = JsonDocument.Parse("""
        {"package_id":"com.example.editor","action":"Install"}
        """).RootElement;
        Assert.Equal("com.example.editor", SoftwareInstaller.ExtractManagedKey(item));
    }

    [Fact]
    public void SoftwareInstaller_ExtractManagedKey_returns_null_for_uninstall()
    {
        var item = JsonDocument.Parse("""
        {"package_id":"com.example.editor","action":"Uninstall"}
        """).RootElement;
        Assert.Null(SoftwareInstaller.ExtractManagedKey(item));
    }

    [Fact]
    public void SoftwareInstaller_reconcile_uninstalls_stale_package()
    {
        var ops = new InMemorySoftwareOperations();
        ops.SeedInstalled("com.example.old");
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);

        var stale = new HashSet<string> { "com.example.old" };
        var changes = e.ReconcileStalePackages(stale, EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Uninstall", changes[0]);
        Assert.False(ops.IsInstalled("com.example.old"));
    }

    [Fact]
    public void SoftwareInstaller_reconcile_audit_does_not_uninstall()
    {
        var ops = new InMemorySoftwareOperations();
        ops.SeedInstalled("com.example.old");
        var e = new SoftwareInstaller(ops, NullLogger<SoftwareInstaller>.Instance);

        var stale = new HashSet<string> { "com.example.old" };
        var changes = e.ReconcileStalePackages(stale, EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("AUDIT", changes[0]);
        Assert.True(ops.IsInstalled("com.example.old"));
    }

    [Fact]
    public void RegistryEnforcer_ParseManagedKey_roundtrips()
    {
        var parsed = RegistryEnforcer.ParseManagedKey(@"LocalMachine\SOFTWARE\Policies\Test\Enabled");
        Assert.NotNull(parsed);
        Assert.Equal("LocalMachine", parsed.Value.Hive);
        Assert.Equal(@"SOFTWARE\Policies\Test", parsed.Value.Key);
        Assert.Equal("Enabled", parsed.Value.ValueName);
    }

    [Fact]
    public void InMemoryRegistryOps_GetValueNames_returns_stored_names()
    {
        var ops = new InMemoryRegistryOperations();
        ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Test", "A", (uint)1, RegValueKind.Dword);
        ops.SetValue("LocalMachine", @"SOFTWARE\Policies\Test", "B", (uint)2, RegValueKind.Dword);

        var names = ops.GetValueNames("LocalMachine", @"SOFTWARE\Policies\Test");
        Assert.Equal(2, names.Count);
        Assert.Contains("A", names);
        Assert.Contains("B", names);
    }

    [Fact]
    public void InMemoryAccountOps_RemoveFromGroup_removes_membership()
    {
        var ops = new InMemoryAccountOperations();
        ops.CreateUser("alice", null, null);
        ops.AddToGroup("alice", "Users");
        ops.AddToGroup("alice", "Administrators");

        ops.RemoveFromGroup("alice", "Administrators");

        var groups = ops.GetGroups("alice");
        Assert.Single(groups);
        Assert.Contains("Users", groups);
    }
}
