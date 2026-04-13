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
}
