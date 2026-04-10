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
    public async Task RegistryEnforcer_returns_skipped_with_changes()
    {
        var e = new RegistryEnforcer(NullLogger<RegistryEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
            {"hive":"LocalMachine","key":"SOFTWARE\\Test","name":"Enabled","value":{"Dword":1},"action":"Set"}
        ]
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("Set", outcome.Changes[0]);
    }

    [Fact]
    public async Task AccountEnforcer_returns_skipped_with_changes()
    {
        var e = new AccountEnforcer(NullLogger<AccountEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
            {"username":"alice","action":"Create"}
        ]
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("alice", outcome.Changes[0]);
    }

    [Fact]
    public async Task PasswordPolicyEnforcer_returns_skipped_with_changes()
    {
        var e = new PasswordPolicyEnforcer(NullLogger<PasswordPolicyEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        {"min_length":14,"complexity_required":true,"lockout_threshold":null}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, outcome.Status);
        Assert.NotNull(outcome.Changes);
        // lockout_threshold is null => skipped, so 2 changes
        Assert.Equal(2, outcome.Changes.Count);
    }

    [Fact]
    public async Task SoftwareInstaller_returns_skipped_with_changes()
    {
        var e = new SoftwareInstaller(NullLogger<SoftwareInstaller>.Instance);
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install"}
        """).RootElement;

        var outcome = await e.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Skipped, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("editor", outcome.Changes[0]);
    }
}
