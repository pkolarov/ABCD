// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Tests;

public class EnforcerTests
{
    [Fact]
    public async Task PreferenceEnforcer_enforce_mode_writes_and_noops_when_unchanged()
    {
        var ops = new InMemoryMacPreferenceOperations();
        var enforcer = new PreferenceEnforcer(ops, NullLogger<PreferenceEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
          {"domain":"com.apple.screensaver","key":"idleTime","value":600,"scope":"System","action":"Set"}
        ]
        """).RootElement;

        var first = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        var second = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, first.Status);
        Assert.Equal("600", ops.GetValueJson("com.apple.screensaver", "idleTime", PreferenceScope.System));
        Assert.Equal(EnforcementStatus.Ok, second.Status);
        Assert.Contains("[NO-OP]", second.Changes![0]);
    }

    [Fact]
    public async Task MacAccountEnforcer_creates_and_modifies_local_user()
    {
        var ops = new InMemoryMacAccountOperations();
        var enforcer = new MacAccountEnforcer(ops, NullLogger<MacAccountEnforcer>.Instance);

        var create = JsonDocument.Parse("""
        [
          {"username":"alice","action":"Create","full_name":"Alice Example","shell":"/bin/zsh","admin":true}
        ]
        """).RootElement;
        var modify = JsonDocument.Parse("""
        [
          {"username":"alice","action":"Modify","hidden":true}
        ]
        """).RootElement;

        var createOutcome = await enforcer.ApplyAsync(create, EnforcementMode.Enforce);
        var modifyOutcome = await enforcer.ApplyAsync(modify, EnforcementMode.Enforce);
        var account = ops.Peek("alice");

        Assert.Equal(EnforcementStatus.Ok, createOutcome.Status);
        Assert.Equal(EnforcementStatus.Ok, modifyOutcome.Status);
        Assert.NotNull(account);
        Assert.True(account!.Admin);
        Assert.True(account.Hidden);
        Assert.Equal("/bin/zsh", account.Shell);
    }

    [Fact]
    public async Task LaunchdEnforcer_configures_and_loads_job()
    {
        var ops = new InMemoryLaunchdOperations();
        var enforcer = new LaunchdEnforcer(ops, NullLogger<LaunchdEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
          {"label":"com.dds.policyagent","plist_path":"/Library/LaunchDaemons/com.dds.policyagent.plist","enabled":true,"action":"Configure"},
          {"label":"com.dds.policyagent","action":"Load"}
        ]
        """).RootElement;

        var outcome = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        var job = ops.Peek("com.dds.policyagent");

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(job);
        Assert.True(job!.Loaded);
        Assert.True(job.Enabled);
    }

    [Fact]
    public async Task ProfileEnforcer_installs_and_noops_for_same_payload()
    {
        var ops = new InMemoryProfileOperations();
        var enforcer = new ProfileEnforcer(ops, NullLogger<ProfileEnforcer>.Instance);
        var directive = JsonDocument.Parse("""
        [
          {
            "identifier":"com.dds.test",
            "display_name":"DDS Test Profile",
            "payload_sha256":"sha256:test",
            "mobileconfig_b64":"SGVsbG8=",
            "action":"Install"
          }
        ]
        """).RootElement;

        var first = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        var second = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, first.Status);
        Assert.Equal(EnforcementStatus.Ok, second.Status);
        Assert.Contains("[NO-OP]", second.Changes![0]);
    }

    [Fact]
    public async Task SoftwareInstaller_audit_mode_reports_intent()
    {
        var enforcer = new SoftwareInstaller(
            NullLogger<SoftwareInstaller>.Instance,
            new RecordingCommandRunner((_, _, _) => new CommandResult(0, string.Empty, string.Empty)),
            Options.Create(new AgentConfig()),
            new StaticHttpClientFactory(new HttpClient()));
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.editor","version":"1.0","action":"Install","source":"/tmp/editor.pkg","sha256":"sha256:deadbeef"}
        """).RootElement;

        var outcome = await enforcer.ApplyAsync(directive, EnforcementMode.Audit);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
        Assert.Contains("[AUDIT]", outcome.Changes[0]);
    }
}
