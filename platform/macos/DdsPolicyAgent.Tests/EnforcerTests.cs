// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Tests;

// Joined to the same non-parallel collection as BackendOperationTests:
// the A-6 tests below mutate `DDS_POLICYAGENT_ASSUME_ROOT` and would
// otherwise race with that class's ctor/Dispose.
[Collection("PolicyAgentEnvSerial")]
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

    // --- A-6: bounded software downloads -------------------------------------

    /// <summary>
    /// Helper: build a `SoftwareInstaller` whose HTTP client serves a
    /// synthetic body of <paramref name="bodyLen"/> bytes (Content-Length
    /// optional). Sets <c>MaxPackageBytes</c> to <paramref name="cap"/>.
    /// `pkgutil --pkg-info` is stubbed to return non-zero so the
    /// "already installed" short-circuit doesn't fire.
    /// </summary>
    private static (SoftwareInstaller installer, JsonElement directive) MakeA6Installer(
        long bodyLen, bool emitContentLength, long cap, string packageId, string version)
    {
        var http = new HttpClient(new FakeBytesHandler(bodyLen, emitContentLength));
        var cfg = new AgentConfig
        {
            RequirePackageSignature = false,
            MaxPackageBytes = cap,
            PackageCacheDir = Path.Combine(Path.GetTempPath(),
                $"dds-a6-{Guid.NewGuid():N}"),
        };
        var runner = new RecordingCommandRunner(
            (file, _, _) => file == "/usr/sbin/pkgutil"
                ? new CommandResult(1, string.Empty, string.Empty)
                : new CommandResult(0, string.Empty, string.Empty));
        var installer = new SoftwareInstaller(
            NullLogger<SoftwareInstaller>.Instance,
            runner,
            Options.Create(cfg),
            new StaticHttpClientFactory(http));
        var directive = JsonDocument.Parse($$"""
        {
            "package_id": "{{packageId}}",
            "version": "{{version}}",
            "action": "Install",
            "source": "https://example.invalid/pkg.pkg",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }
        """).RootElement;
        return (installer, directive);
    }

    /// <summary>
    /// Save/restore wrapper around `DDS_POLICYAGENT_ASSUME_ROOT` so
    /// that A-6 tests don't trample on parallel test classes (e.g.
    /// `BackendOperationTests`) that also depend on this env var.
    /// </summary>
    private readonly struct AssumeRootScope : IDisposable
    {
        private readonly string? _prev;
        public AssumeRootScope(string? prev) { _prev = prev; }
        public static AssumeRootScope Enter()
        {
            var prev = Environment.GetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT");
            Environment.SetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT", "1");
            return new AssumeRootScope(prev);
        }
        public void Dispose()
            => Environment.SetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT", _prev);
    }

    /// <summary>
    /// A-6: when `Content-Length` declares a body larger than the cap,
    /// the download is refused before any bytes are written.
    /// </summary>
    [Fact]
    public async Task SoftwareInstaller_a6_refuses_download_when_content_length_exceeds_cap()
    {
        using var _ = AssumeRootScope.Enter();
        var (installer, directive) = MakeA6Installer(
            bodyLen: 4 * 1024,
            emitContentLength: true,
            cap: 1024,
            packageId: "com.example.a6.declared",
            version: "1.0");
        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("Content-Length", outcome.Error);
        Assert.Contains("exceeds cap", outcome.Error);
    }

    /// <summary>
    /// A-6: when no `Content-Length` is sent and the body actually
    /// exceeds the cap, the streaming loop aborts mid-flight and the
    /// partial file is deleted.
    /// </summary>
    [Fact]
    public async Task SoftwareInstaller_a6_refuses_download_when_stream_exceeds_cap()
    {
        using var _ = AssumeRootScope.Enter();
        var (installer, directive) = MakeA6Installer(
            bodyLen: 4 * 1024,
            emitContentLength: false,
            cap: 1024,
            packageId: "com.example.a6.streamed",
            version: "1.0");
        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("exceeded cap", outcome.Error);
    }

    /// <summary>
    /// A-6: when the body fits under the cap, the download succeeds.
    /// (The hash check then fails because we feed 0xAA bytes against
    /// the all-zero placeholder sha — which is the expected next
    /// failure mode and confirms the download path completed.)
    /// </summary>
    [Fact]
    public async Task SoftwareInstaller_a6_under_cap_proceeds_to_hash_check()
    {
        using var _ = AssumeRootScope.Enter();
        var (installer, directive) = MakeA6Installer(
            bodyLen: 256,
            emitContentLength: true,
            cap: 4096,
            packageId: "com.example.a6.under",
            version: "1.0");
        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);
        // Download completes; hash mismatch is the next gate.
        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("hash mismatch", outcome.Error);
    }

    // --- Reconciliation: ExtractManagedKey ---

    [Fact]
    public void PreferenceEnforcer_ExtractManagedKey_returns_key_for_Set()
    {
        var item = JsonDocument.Parse("""
        {"domain":"com.apple.screensaver","key":"idleTime","value":600,"scope":"System","action":"Set"}
        """).RootElement;
        Assert.Equal("System:com.apple.screensaver:idleTime", PreferenceEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void PreferenceEnforcer_ExtractManagedKey_returns_null_for_Delete()
    {
        var item = JsonDocument.Parse("""
        {"domain":"com.apple.screensaver","key":"idleTime","action":"Delete"}
        """).RootElement;
        Assert.Null(PreferenceEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void LaunchdEnforcer_ExtractManagedKey_returns_label_for_Configure()
    {
        var item = JsonDocument.Parse("""
        {"label":"com.dds.agent","plist_path":"/Library/LaunchDaemons/com.dds.agent.plist","action":"Configure"}
        """).RootElement;
        Assert.Equal("com.dds.agent", LaunchdEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void LaunchdEnforcer_ExtractManagedKey_returns_null_for_Load()
    {
        var item = JsonDocument.Parse("""
        {"label":"com.dds.agent","action":"Load"}
        """).RootElement;
        Assert.Null(LaunchdEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void MacAccountEnforcer_ExtractManagedKey_returns_username_for_Create()
    {
        var item = JsonDocument.Parse("""
        {"username":"alice","action":"Create","full_name":"Alice"}
        """).RootElement;
        Assert.Equal("alice", MacAccountEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void MacAccountEnforcer_ExtractManagedKey_returns_null_for_Delete()
    {
        var item = JsonDocument.Parse("""
        {"username":"alice","action":"Delete"}
        """).RootElement;
        Assert.Null(MacAccountEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void MacAccountEnforcer_ExtractManagedGroups_returns_username_colon_group_pairs()
    {
        var item = JsonDocument.Parse("""
        {"username":"alice","action":"Create","groups":["staff","wheel"]}
        """).RootElement;
        var groups = MacAccountEnforcer.ExtractManagedGroups(item).ToList();
        Assert.Equal(2, groups.Count);
        Assert.Contains("alice:staff", groups);
        Assert.Contains("alice:wheel", groups);
    }

    [Fact]
    public void ProfileEnforcer_ExtractManagedKey_returns_identifier_for_Install()
    {
        var item = JsonDocument.Parse("""
        {"identifier":"com.dds.wifi","action":"Install","display_name":"WiFi","payload_sha256":"sha256:aaa","mobileconfig_b64":"SGVsbG8="}
        """).RootElement;
        Assert.Equal("com.dds.wifi", ProfileEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void ProfileEnforcer_ExtractManagedKey_returns_null_for_Remove()
    {
        var item = JsonDocument.Parse("""
        {"identifier":"com.dds.wifi","action":"Remove"}
        """).RootElement;
        Assert.Null(ProfileEnforcer.ExtractManagedKey(item));
    }

    [Fact]
    public void SoftwareInstaller_ExtractManagedKey_returns_package_id_for_Install()
    {
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.app","version":"1.0","action":"Install","source":"/tmp/app.pkg","sha256":"sha256:aaa"}
        """).RootElement;
        Assert.Equal("com.example.app", SoftwareInstaller.ExtractManagedKey(directive));
    }

    [Fact]
    public void SoftwareInstaller_ExtractManagedKey_returns_null_for_Uninstall()
    {
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.app","action":"Uninstall"}
        """).RootElement;
        Assert.Null(SoftwareInstaller.ExtractManagedKey(directive));
    }

    // --- Reconciliation: Reconcile* methods ---

    [Fact]
    public void PreferenceEnforcer_ReconcileStaleItems_enforce_mode_deletes_values()
    {
        var ops = new InMemoryMacPreferenceOperations();
        ops.SetValueJson("com.apple.screensaver", "idleTime", PreferenceScope.System, "600");
        var enforcer = new PreferenceEnforcer(ops, NullLogger<PreferenceEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleItems(
            new HashSet<string>(["System:com.apple.screensaver:idleTime"]),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Delete", changes[0]);
        Assert.Null(ops.GetValueJson("com.apple.screensaver", "idleTime", PreferenceScope.System));
    }

    [Fact]
    public void PreferenceEnforcer_ReconcileStaleItems_audit_mode_does_not_delete()
    {
        var ops = new InMemoryMacPreferenceOperations();
        ops.SetValueJson("com.apple.screensaver", "idleTime", PreferenceScope.System, "600");
        var enforcer = new PreferenceEnforcer(ops, NullLogger<PreferenceEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleItems(
            new HashSet<string>(["System:com.apple.screensaver:idleTime"]),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.Equal("600", ops.GetValueJson("com.apple.screensaver", "idleTime", PreferenceScope.System));
    }

    [Fact]
    public void LaunchdEnforcer_ReconcileStaleItems_enforce_mode_unloads_jobs()
    {
        var ops = new InMemoryLaunchdOperations();
        ops.Load("com.dds.old");
        var enforcer = new LaunchdEnforcer(ops, NullLogger<LaunchdEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleItems(
            new HashSet<string>(["com.dds.old"]),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Unload", changes[0]);
        Assert.False(ops.Peek("com.dds.old")!.Loaded);
    }

    [Fact]
    public void LaunchdEnforcer_ReconcileStaleItems_audit_mode_does_not_unload()
    {
        var ops = new InMemoryLaunchdOperations();
        ops.Load("com.dds.old");
        var enforcer = new LaunchdEnforcer(ops, NullLogger<LaunchdEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleItems(
            new HashSet<string>(["com.dds.old"]),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.True(ops.Peek("com.dds.old")!.Loaded);
    }

    [Fact]
    public void MacAccountEnforcer_ReconcileStaleAccounts_enforce_mode_disables_users()
    {
        var ops = new InMemoryMacAccountOperations();
        ops.CreateUser("alice", null, null, false, false);
        var enforcer = new MacAccountEnforcer(ops, NullLogger<MacAccountEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleAccounts(
            new HashSet<string>(["alice"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Disable", changes[0]);
        Assert.False(ops.IsEnabled("alice"));
    }

    [Fact]
    public void MacAccountEnforcer_ReconcileStaleAccounts_audit_mode_does_not_disable()
    {
        var ops = new InMemoryMacAccountOperations();
        ops.CreateUser("alice", null, null, false, false);
        var enforcer = new MacAccountEnforcer(ops, NullLogger<MacAccountEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleAccounts(
            new HashSet<string>(["alice"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.True(ops.IsEnabled("alice"));
    }

    [Fact]
    public void MacAccountEnforcer_ReconcileStaleGroups_enforce_mode_removes_memberships()
    {
        var ops = new InMemoryMacAccountOperations();
        ops.CreateUser("alice", null, null, false, false);
        ops.Peek("alice")!.Groups.Add("staff");
        var enforcer = new MacAccountEnforcer(ops, NullLogger<MacAccountEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleGroups(
            new HashSet<string>(["alice:staff"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-RemoveGroup", changes[0]);
        Assert.False(ops.IsInGroup("alice", "staff"));
    }

    [Fact]
    public void MacAccountEnforcer_ReconcileStaleGroups_audit_mode_does_not_remove()
    {
        var ops = new InMemoryMacAccountOperations();
        ops.CreateUser("alice", null, null, false, false);
        ops.Peek("alice")!.Groups.Add("staff");
        var enforcer = new MacAccountEnforcer(ops, NullLogger<MacAccountEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleGroups(
            new HashSet<string>(["alice:staff"], StringComparer.OrdinalIgnoreCase),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.True(ops.IsInGroup("alice", "staff"));
    }

    [Fact]
    public void ProfileEnforcer_ReconcileStaleProfiles_enforce_mode_removes_profiles()
    {
        var ops = new InMemoryProfileOperations();
        ops.Install("com.dds.wifi", "WiFi", "sha256:aaa", [0x01]);
        var enforcer = new ProfileEnforcer(ops, NullLogger<ProfileEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleProfiles(
            new HashSet<string>(["com.dds.wifi"]),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("Reconcile-Remove", changes[0]);
        Assert.False(ops.IsInstalled("com.dds.wifi", "sha256:aaa"));
    }

    [Fact]
    public void ProfileEnforcer_ReconcileStaleProfiles_audit_mode_does_not_remove()
    {
        var ops = new InMemoryProfileOperations();
        ops.Install("com.dds.wifi", "WiFi", "sha256:aaa", [0x01]);
        var enforcer = new ProfileEnforcer(ops, NullLogger<ProfileEnforcer>.Instance);

        var changes = enforcer.ReconcileStaleProfiles(
            new HashSet<string>(["com.dds.wifi"]),
            EnforcementMode.Audit);

        Assert.Single(changes);
        Assert.Contains("[AUDIT]", changes[0]);
        Assert.True(ops.IsInstalled("com.dds.wifi", "sha256:aaa"));
    }

    [Fact]
    public void SoftwareInstaller_ReconcileStalePackages_always_logs_manual_action()
    {
        var installer = new SoftwareInstaller(
            NullLogger<SoftwareInstaller>.Instance,
            new RecordingCommandRunner((_, _, _) => new CommandResult(0, string.Empty, string.Empty)),
            Options.Create(new AgentConfig()),
            new StaticHttpClientFactory(new HttpClient()));

        var changes = installer.ReconcileStalePackages(
            new HashSet<string>(["com.example.app"]),
            EnforcementMode.Enforce);

        Assert.Single(changes);
        Assert.Contains("[MANUAL]", changes[0]);
        Assert.Contains("com.example.app", changes[0]);
    }
}
