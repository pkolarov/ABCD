// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Linux.Client;
using DDS.PolicyAgent.Linux.Config;
using DDS.PolicyAgent.Linux.Runtime;
using DDS.PolicyAgent.Linux.State;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.Linux.Tests;

// ---- test doubles ----

sealed class TestDdsNodeClient : IDdsNodeClient
{
    public List<ApplicableLinuxPolicy> NextPolicies { get; set; } = [];
    public List<AppliedReport> ReceivedReports { get; } = [];
    public bool GetPoliciesWasCalled { get; private set; }

    public Task<List<ApplicableLinuxPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        GetPoliciesWasCalled = true;
        return Task.FromResult(NextPolicies);
    }

    public Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default)
    {
        ReceivedReports.Add(report);
        return Task.CompletedTask;
    }
}

sealed class TestAppliedStateStore : IAppliedStateStore
{
    private readonly Dictionary<string, (string Version, string Hash, string Status)> _entries = new();

    public AppliedState Load() => new();

    public bool HasChanged(string targetId, string contentHash)
        => !_entries.TryGetValue(targetId, out var e) || e.Hash != contentHash;

    public void RecordApplied(string targetId, string version, string contentHash, string status)
        => _entries[targetId] = (version, contentHash, status);

    public void RecordManagedUsername(string username) { }
    public void RecordManagedPath(string path) { }
    public void RecordManagedPackage(string packageName) { }
    public void RecordManagedSudoersFilename(string filename) { }
    public void RecordManagedSystemdDropin(string dropinKey) { }
    public void RemoveManagedUsername(string username) { }
    public void RemoveManagedPath(string path) { }
    public void RemoveManagedPackage(string packageName) { }
    public void RemoveManagedSudoersFilename(string filename) { }
    public void RemoveManagedSystemdDropin(string dropinKey) { }
    public void SetManagedGroups(IEnumerable<string> groups) { }
}

/// State store whose Load() returns a pre-populated managed set and records
/// every add/remove call so tests can assert on resource lifecycle.
sealed class TrackingAppliedStateStore : IAppliedStateStore
{
    private readonly AppliedState _state;

    public List<string> AddedUsernames         { get; } = [];
    public List<string> RemovedUsernames       { get; } = [];
    public List<string> AddedPaths             { get; } = [];
    public List<string> RemovedPaths           { get; } = [];
    public List<string> AddedPackages          { get; } = [];
    public List<string> RemovedPackages        { get; } = [];
    public List<string> AddedSudoersFilenames   { get; } = [];
    public List<string> RemovedSudoersFilenames { get; } = [];
    public List<string> AddedSystemdDropinKeys  { get; } = [];
    public List<string> RemovedSystemdDropinKeys{ get; } = [];

    public TrackingAppliedStateStore(AppliedState initialState)
        => _state = initialState;

    public AppliedState Load() => _state;
    public bool HasChanged(string _, string __) => true;
    public void RecordApplied(string _, string __, string ___, string ____) { }

    public List<IEnumerable<string>> SetGroupsCalls { get; } = [];

    public void RecordManagedUsername(string u)        => AddedUsernames.Add(u);
    public void RecordManagedPath(string p)            => AddedPaths.Add(p);
    public void RecordManagedPackage(string n)         => AddedPackages.Add(n);
    public void RecordManagedSudoersFilename(string f) => AddedSudoersFilenames.Add(f);
    public void RecordManagedSystemdDropin(string k)   => AddedSystemdDropinKeys.Add(k);

    public void RemoveManagedUsername(string u)        => RemovedUsernames.Add(u);
    public void RemoveManagedPath(string p)            => RemovedPaths.Add(p);
    public void RemoveManagedPackage(string n)         => RemovedPackages.Add(n);
    public void RemoveManagedSudoersFilename(string f) => RemovedSudoersFilenames.Add(f);
    public void RemoveManagedSystemdDropin(string k)   => RemovedSystemdDropinKeys.Add(k);
    public void SetManagedGroups(IEnumerable<string> groups) => SetGroupsCalls.Add(groups.ToList());
}

// ---- helpers ----

file static class WorkerFactory
{
    public static Worker Create(
        AgentConfig config,
        IDdsNodeClient? client = null,
        IAppliedStateStore? store = null,
        ICommandRunner? runner = null,
        string? sshdDropinPath = null,
        string? sysctlDropinPath = null,
        string? sudoersDir = null,
        string? systemdDropinBase = null)
    {
        client ??= new TestDdsNodeClient();
        store  ??= new TestAppliedStateStore();
        runner ??= new NullCommandRunner();
        return new Worker(
            client,
            store,
            Options.Create(config),
            runner,
            NullLogger<Worker>.Instance,
            sshdDropinPath,
            sysctlDropinPath,
            sudoersDir,
            systemdDropinBase);
    }

    public static ApplicableLinuxPolicy MakePolicy(string policyId, string documentJson)
    {
        var doc = JsonDocument.Parse(documentJson);
        return new ApplicableLinuxPolicy
        {
            Jti = policyId,
            Issuer = "urn:dds:issuer:test",
            Iat = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Document = doc.RootElement,
        };
    }
}

// ---- ContentHash tests ----

public sealed class ContentHashTests
{
    [Fact]
    public void ContentHash_is_deterministic()
    {
        var doc = JsonDocument.Parse("""{"policy_id":"p1","version":1}""");
        var h1 = Worker.ContentHash(doc.RootElement);
        var h2 = Worker.ContentHash(doc.RootElement);
        Assert.Equal(h1, h2);
        Assert.StartsWith("sha256:", h1);
    }

    [Fact]
    public void ContentHash_differs_for_different_documents()
    {
        var d1 = JsonDocument.Parse("""{"policy_id":"p1"}""");
        var d2 = JsonDocument.Parse("""{"policy_id":"p2"}""");
        Assert.NotEqual(
            Worker.ContentHash(d1.RootElement),
            Worker.ContentHash(d2.RootElement));
    }
}

// ---- tests ----

public sealed class WorkerTests
{
    [Fact]
    public async Task FailsClosedWithoutDeviceUrn()
    {
        var client = new TestDdsNodeClient();
        var worker = WorkerFactory.Create(
            new AgentConfig { DeviceUrn = "", PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]) },
            client);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await worker.StartAsync(cts.Token);
        await worker.StopAsync(CancellationToken.None);

        Assert.False(client.GetPoliciesWasCalled);
    }

    [Fact]
    public async Task FailsClosedWithoutPinnedNodeKey()
    {
        var client = new TestDdsNodeClient();
        var worker = WorkerFactory.Create(
            new AgentConfig { DeviceUrn = "urn:dds:device:test", PinnedNodePubkeyB64 = "" },
            client);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await worker.StartAsync(cts.Token);
        await worker.StopAsync(CancellationToken.None);

        Assert.False(client.GetPoliciesWasCalled);
    }

    [Fact]
    public async Task ReportsSkippedForNonLinuxPolicyBundle()
    {
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-no-linux",
                    """{"policy_id":"policy-no-linux","version":1}"""),
            ],
        };

        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Single(client.ReceivedReports);
        Assert.Equal("skipped", client.ReceivedReports[0].Status);
        Assert.Equal(AppliedKind.Policy, client.ReceivedReports[0].Kind);
    }

    [Fact]
    public async Task ReportsOkForEmptyLinuxPolicyBundle()
    {
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-with-linux",
                    """{"policy_id":"policy-with-linux","version":1,"linux":{}}"""),
            ],
        };

        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Single(client.ReceivedReports);
        Assert.Equal("ok", client.ReceivedReports[0].Status);
    }

    [Fact]
    public async Task ProcessCommandRunnerRunsCommand()
    {
        var runner = new ProcessCommandRunner();
        var result = await runner.RunAsync("echo", "hello");
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("hello", result.Stdout);
    }

    [Fact]
    public void NullCommandRunnerRecordsInvocations()
    {
        var runner = new NullCommandRunner();
        runner.RunAsync("useradd", "-m alice");
        Assert.Single(runner.Invocations);
        Assert.Equal("useradd", runner.Invocations[0].FileName);
        Assert.Equal("-m alice", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task DeleteUser_RemovesFromManagedSet()
    {
        // Pre-populate the managed set with "alice" so the delete guard passes.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedUsernames.Add("alice");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-delete-user",
                    """{"policy_id":"policy-delete-user","version":1,"linux":{"local_users":[{"username":"alice","action":"Delete"}]}}"""),
            ],
        };
        // AuditOnly: false so the enforcer runs the command path (NullCommandRunner captures it).
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client,
            store);

        await worker.PollOnceAsync(CancellationToken.None);

        // The delete directive must trigger RemoveManagedUsername, not RecordManagedUsername.
        Assert.Contains("alice", store.RemovedUsernames);
        Assert.DoesNotContain("alice", store.AddedUsernames);
    }

    [Fact]
    public async Task DeleteFile_RemovesFromManagedSet()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPaths.Add("/etc/dds/managed.conf");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-delete-file",
                    """{"policy_id":"policy-delete-file","version":1,"linux":{"files":[{"path":"/etc/dds/managed.conf","action":"Delete"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client,
            store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("/etc/dds/managed.conf", store.RemovedPaths);
        Assert.DoesNotContain("/etc/dds/managed.conf", store.AddedPaths);
    }

    // =========================================================
    // Reconciliation tests
    // =========================================================

    [Fact]
    public async Task Reconciliation_StaleUser_IsDisabledAndRemovedFromManagedSet()
    {
        // "alice" was managed in a previous cycle but is absent from current policies.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedUsernames.Add("alice");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("alice", store.RemovedUsernames);
        Assert.Contains(runner.Invocations,
            i => i.FileName == "passwd" && i.Arguments.Contains("alice"));
    }

    [Fact]
    public async Task Reconciliation_StaleUser_AuditOnly_NoRunnerCall()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedUsernames.Add("bob");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // Audit mode: no commands, but state must still be updated so the
        // stale item is not re-reported on every cycle.
        Assert.Contains("bob", store.RemovedUsernames);
        Assert.Empty(runner.Invocations);

        // Reconciliation report must carry the [AUDIT] prefix so operators
        // can distinguish dry-run entries from actual changes.
        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] user:disable:bob", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StaleFile_IsDeletedAndRemovedFromManagedSet()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPaths.Add("/etc/dds/stale.conf");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("/etc/dds/stale.conf", store.RemovedPaths);
    }

    [Fact]
    public async Task Reconciliation_StalePackage_IsRemovedAndRemovedFromManagedSet()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPackages.Add("ntp");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("ntp", store.RemovedPackages);
        // Package removal invokes the package manager — any call with "ntp" qualifies.
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("ntp"));
    }

    [Fact]
    public async Task Reconciliation_StaleFile_AuditOnly_ReturnsAuditPrefixedEntry()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPaths.Add("/etc/dds/stale.conf");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // State is updated so the item is not re-reported every cycle.
        Assert.Contains("/etc/dds/stale.conf", store.RemovedPaths);
        // Reconciliation report must carry the [AUDIT] prefix.
        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] file:delete:/etc/dds/stale.conf", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StalePackage_AuditOnly_ReturnsAuditPrefixedEntry()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPackages.Add("ntp");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // State is updated so the item is not re-reported every cycle.
        Assert.Contains("ntp", store.RemovedPackages);
        // Audit mode: package manager must NOT be invoked.
        Assert.Empty(runner.Invocations);
        // Reconciliation report must carry the [AUDIT] prefix.
        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] pkg:remove:ntp", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StillDesiredUser_IsNotDisabled()
    {
        // "alice" is managed AND still present in the current policy → not stale.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedUsernames.Add("alice");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-still-has-alice",
                    """{"policy_id":"policy-still-has-alice","version":1,"linux":{"local_users":[{"username":"alice","action":"Create"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.DoesNotContain("alice", store.RemovedUsernames);
        Assert.DoesNotContain(runner.Invocations,
            i => i.FileName == "passwd" && i.Arguments.Contains("alice"));
    }

    [Fact]
    public async Task Reconciliation_ReconciliationReport_SentWhenChangesExist()
    {
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPackages.Add("curl");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        var reconcileReport = client.ReceivedReports.FirstOrDefault(
            r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconcileReport);
        Assert.Equal("ok", reconcileReport.Status);
        Assert.Equal("reconciliation", reconcileReport.Kind);
        Assert.Contains(reconcileReport.Directives, d => d.Contains("curl"));
    }

    [Fact]
    public async Task Reconciliation_NoStaleItems_NoReportSent()
    {
        // Empty managed sets → nothing stale → no reconciliation report.
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");
    }

    [Fact]
    public async Task Reconciliation_SysctlKeyStillDesired_NoReconciliationReport()
    {
        // A policy that declares a sysctl key keeps that key as desired →
        // no reconciliation action should be taken for it.
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-sysctl",
                    """{"policy_id":"policy-sysctl","version":1,"linux":{"sysctl":[{"key":"vm.swappiness","value":"10","action":"Set"}]}}"""),
            ],
        };

        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        // No reconciliation report expected since the key is still desired.
        Assert.DoesNotContain(client.ReceivedReports,
            r => r.TargetId == "_reconciliation");
    }

    [Fact]
    public async Task Reconciliation_StaleSysctlKey_EnforceMode_DeletesKeyFromDropin()
    {
        // A sysctl key is present in the managed drop-in but absent from all current
        // policies → ReconcileStaleKeysAsync removes the key and rewrites the file in
        // enforce mode, emitting "sysctl:delete:{key}" (no [AUDIT] prefix).
        var tmp = Path.Combine(Path.GetTempPath(), "dds-sysctl-wkr-enf-" + Guid.NewGuid() + ".conf");
        try
        {
            await File.WriteAllTextAsync(tmp, "# Managed by DDS\nvm.swappiness = 10\n");

            var client = new TestDdsNodeClient();   // no policies → desiredSysctlKeys is empty

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = false,
                },
                client,
                sysctlDropinPath: tmp);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("sysctl:delete:vm.swappiness", report.Directives);
            Assert.DoesNotContain("[AUDIT]", string.Concat(report.Directives));
            // Enforce mode: the key must have been removed from the drop-in file.
            var content = await File.ReadAllTextAsync(tmp);
            Assert.DoesNotContain("vm.swappiness", content);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    [Fact]
    public async Task Reconciliation_StaleSysctlKey_AuditOnly_EmitsAuditPrefixedDeleteDirective()
    {
        // A sysctl key is present in the managed drop-in but absent from all current
        // policies → ReconcileStaleKeysAsync returns "[AUDIT] sysctl:delete:{key}" in
        // audit mode without rewriting the file.
        // Pre-seed a real temp drop-in with the key so SysctlEnforcer.LoadDropin finds it.
        var tmp = Path.Combine(Path.GetTempPath(), "dds-sysctl-wkr-" + Guid.NewGuid() + ".conf");
        try
        {
            await File.WriteAllTextAsync(tmp, "# Managed by DDS\nvm.swappiness = 10\n");

            var client = new TestDdsNodeClient();   // no policies → desiredSysctlKeys is empty

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = true,
                },
                client,
                sysctlDropinPath: tmp);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("[AUDIT] sysctl:delete:vm.swappiness", report.Directives);
            // Audit mode: drop-in must not be modified or deleted.
            Assert.True(File.Exists(tmp));
            Assert.Contains("vm.swappiness = 10", await File.ReadAllTextAsync(tmp));
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    [Fact]
    public async Task Reconciliation_SshPolicyAbsentFromAllPolicies_SshdReconciliationAttempted()
    {
        // No applicable policy has an ssh field → sshdEnforcer.ApplyAsync(null) is called.
        // In CI the drop-in does not exist, so it is a no-op and no report is emitted.
        // This test verifies the code path is reached without throwing.
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-no-ssh",
                    """{"policy_id":"policy-no-ssh","version":1,"linux":{"local_users":[]}}"""),
            ],
        };

        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client);

        // Must not throw — the reconciliation null-ssh path runs and is a no-op
        // since /etc/ssh/sshd_config.d/60-dds.conf does not exist in CI.
        await worker.PollOnceAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Reconciliation_AllInvalidSshFields_TreatedSameAsAbsentSshField()
    {
        // A policy with an ssh object whose every field is invalid (no recognized valid
        // directive) must be treated the same as an absent ssh field for reconciliation
        // purposes. hasSshPolicy must be false so the reconciliation pass runs
        // sshdEnforcer.ApplyAsync(null) and can clean up any stale dropin.
        // In CI the dropin does not exist, so it is a no-op and no reconciliation
        // report is emitted. This test verifies the code path is reached without throwing.
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-all-invalid-ssh",
                    """{"policy_id":"policy-all-invalid-ssh","version":1,"linux":{"ssh":{"permit_root_login":"typo-value"}}}"""),
            ],
        };

        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client);

        // Must not throw, and no reconciliation report since dropin does not exist in CI.
        await worker.PollOnceAsync(CancellationToken.None);

        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");
    }

    [Fact]
    public async Task Reconciliation_SshPolicyAbsent_EnforceMode_DeletesDropinFile()
    {
        // No applicable policy has an ssh field and the sshd drop-in exists on disk →
        // the reconciliation pass calls sshdEnforcer.ApplyAsync(null) which deletes the
        // file in enforce mode, emitting "sshd:remove" (no [AUDIT] prefix).
        // Use empty NextPolicies so only the reconciliation phase runs; a policy with a
        // linux section but no ssh field would cause the apply phase to call ApplyAsync(null)
        // first, deleting the file before the reconciliation pass acts on it.
        var tmp = Path.Combine(Path.GetTempPath(), "dds-sshd-wkr-enf-" + Guid.NewGuid() + ".conf");
        try
        {
            await File.WriteAllTextAsync(tmp, "# Managed by DDS\nPasswordAuthentication no\n");

            var client = new TestDdsNodeClient();   // no policies → hasSshPolicy stays false

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = false,
                },
                client,
                sshdDropinPath: tmp);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("sshd:remove", report.Directives);
            Assert.DoesNotContain("[AUDIT]", string.Concat(report.Directives));
            // Enforce mode: the drop-in must have been deleted.
            Assert.False(File.Exists(tmp));
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    [Fact]
    public async Task Reconciliation_SshPolicyAbsent_AuditOnly_EmitsAuditPrefixedRemoveDirective()
    {
        // No policy has an ssh field and the sshd drop-in exists on disk → the
        // reconciliation pass calls sshdEnforcer.ApplyAsync(null) which returns
        // "[AUDIT] sshd:remove" in audit mode without deleting the file.
        // This test pre-seeds the drop-in via a temp file so the File.Exists
        // check in SshdEnforcer passes, proving the directive reaches the report.
        var tmp = Path.Combine(Path.GetTempPath(), "dds-sshd-wkr-" + Guid.NewGuid() + ".conf");
        try
        {
            await File.WriteAllTextAsync(tmp, "# Managed by DDS\nPasswordAuthentication no\n");

            var client = new TestDdsNodeClient
            {
                NextPolicies =
                [
                    WorkerFactory.MakePolicy(
                        "policy-no-ssh",
                        """{"policy_id":"policy-no-ssh","version":1,"linux":{"local_users":[]}}"""),
                ],
            };

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = true,
                },
                client,
                sshdDropinPath: tmp);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("[AUDIT] sshd:remove", report.Directives);
            // Audit mode: drop-in must not be deleted.
            Assert.True(File.Exists(tmp));
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    [Fact]
    public async Task Reconciliation_StaleSudoersDropin_IsDeletedAndRemovedFromManagedSet()
    {
        // "dds-ops" was a managed sudoers drop-in in a previous cycle but is absent
        // from all current policies → the reconciliation pass should delete it.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSudoersFilenames.Add("dds-ops");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("dds-ops", store.RemovedSudoersFilenames);
        Assert.DoesNotContain("dds-ops", store.AddedSudoersFilenames);
    }

    [Fact]
    public async Task Reconciliation_StaleSudoersDropin_EnforceMode_DeletesDropinFile()
    {
        // A sudoers drop-in is present on disk but absent from all current policies →
        // ReconcileStaleSudoersAsync deletes the file in enforce mode, emitting
        // "sudoers:delete:{filename}" (no [AUDIT] prefix).
        var tmpDir = Path.Combine(Path.GetTempPath(), "dds-sudoers-wkr-enf-" + Guid.NewGuid());
        Directory.CreateDirectory(tmpDir);
        var dropinPath = Path.Combine(tmpDir, "dds-ops");
        try
        {
            await File.WriteAllTextAsync(dropinPath, "alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n");

            var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
            initialState.ManagedSudoersFilenames.Add("dds-ops");
            var store  = new TrackingAppliedStateStore(initialState);
            var client = new TestDdsNodeClient();   // no policies → staleSudoers = {"dds-ops"}

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = false,
                },
                client,
                store,
                sudoersDir: tmpDir);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("sudoers:delete:dds-ops", report.Directives);
            Assert.DoesNotContain("[AUDIT]", string.Concat(report.Directives));
            // Enforce mode: the drop-in file must have been deleted.
            Assert.False(File.Exists(dropinPath));
        }
        finally
        {
            if (Directory.Exists(tmpDir)) Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public async Task Reconciliation_StillDesiredSudoersDropin_IsNotDeleted()
    {
        // "dds-ops" is managed AND still present in the current policy → not stale.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSudoersFilenames.Add("dds-ops");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-still-has-sudoers",
                    """{"policy_id":"policy-still-has-sudoers","version":1,"linux":{"sudoers":[{"filename":"dds-ops","content":"alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.DoesNotContain("dds-ops", store.RemovedSudoersFilenames);
    }

    [Fact]
    public async Task SudoersSet_RecordsManagedFilename()
    {
        // Applying a sudoers directive with non-empty content should record the filename.
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-sudoers-set",
                    """{"policy_id":"policy-sudoers-set","version":1,"linux":{"sudoers":[{"filename":"dds-ops","content":"alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("dds-ops", store.AddedSudoersFilenames);
    }

    [Fact]
    public async Task Reconciliation_StaleSystemdDropin_IsDeletedAndRemovedFromManagedSet()
    {
        // "sshd.service/hardening" was a managed systemd drop-in in a previous cycle but
        // is absent from all current policies → reconciliation should delete it.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSystemdDropins.Add("sshd.service/hardening");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("sshd.service/hardening", store.RemovedSystemdDropinKeys);
        Assert.DoesNotContain("sshd.service/hardening", store.AddedSystemdDropinKeys);
    }

    [Fact]
    public async Task Reconciliation_StillDesiredSystemdDropin_IsNotDeleted()
    {
        // "sshd.service/hardening" is managed AND still present in the current policy → not stale.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSystemdDropins.Add("sshd.service/hardening");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-still-has-dropin",
                    """{"policy_id":"policy-still-has-dropin","version":1,"linux":{"systemd":[{"unit":"sshd.service","action":"ConfigureDropin","dropin_name":"hardening","dropin_content":"[Service]\nLimitNOFILE=65535"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.DoesNotContain("sshd.service/hardening", store.RemovedSystemdDropinKeys);
    }

    [Fact]
    public async Task Reconciliation_StaleSystemdDropin_EnforceMode_DeletesDropinFile()
    {
        // A systemd drop-in is present on disk but absent from all current policies →
        // ReconcileStaleDropinsAsync deletes the file in enforce mode, emitting
        // "systemd:removedropin:{key}" (no [AUDIT] prefix).
        var tmpBase = Path.Combine(Path.GetTempPath(), "dds-systemd-wkr-enf-" + Guid.NewGuid());
        var dropinDir  = Path.Combine(tmpBase, "sshd.service.d");
        var dropinPath = Path.Combine(dropinDir, "hardening.conf");
        Directory.CreateDirectory(dropinDir);
        try
        {
            await File.WriteAllTextAsync(dropinPath, "[Service]\nLimitNOFILE=65535\n");

            var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
            initialState.ManagedSystemdDropins.Add("sshd.service/hardening");
            var store  = new TrackingAppliedStateStore(initialState);
            var client = new TestDdsNodeClient();   // no policies → staleSystemdDropins = {"sshd.service/hardening"}

            var worker = WorkerFactory.Create(
                new AgentConfig
                {
                    DeviceUrn           = "urn:dds:device:test",
                    PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                    AuditOnly           = false,
                },
                client,
                store,
                systemdDropinBase: tmpBase);

            await worker.PollOnceAsync(CancellationToken.None);

            var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "_reconciliation");
            Assert.NotNull(report);
            Assert.Contains("systemd:removedropin:sshd.service/hardening", report.Directives);
            Assert.DoesNotContain("[AUDIT]", string.Concat(report.Directives));
            // Enforce mode: the drop-in file must have been deleted.
            Assert.False(File.Exists(dropinPath));
        }
        finally
        {
            if (Directory.Exists(tmpBase)) Directory.Delete(tmpBase, recursive: true);
        }
    }

    [Fact]
    public async Task SystemdConfigureDropin_RecordsManagedDropin()
    {
        // Applying a ConfigureDropin directive should record the "unit/stem" key.
        var store  = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-dropin-set",
                    """{"policy_id":"policy-dropin-set","version":1,"linux":{"systemd":[{"unit":"sshd.service","action":"ConfigureDropin","dropin_name":"hardening","dropin_content":"[Service]\nLimitNOFILE=65535"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("sshd.service/hardening", store.AddedSystemdDropinKeys);
    }

    [Fact]
    public async Task GroupMembership_ReconcileRemovesStaleKey()
    {
        // Pre-state: "alice:sudo" was previously managed. Current policy has no groups.
        // Expected: gpasswd -d alice sudo is called; SetManagedGroups called with empty set.
        var staleState = new DDS.PolicyAgent.Linux.State.AppliedState();
        staleState.ManagedGroups.Add("alice:sudo");

        var store  = new TrackingAppliedStateStore(staleState);
        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-no-groups",
                    """{"policy_id":"policy-no-groups","version":1,"linux":{"local_users":[{"username":"alice","action":"Create","shell":"/bin/bash"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains(runner.Invocations,
            i => i.FileName == "gpasswd" && i.Arguments.Contains("alice") && i.Arguments.Contains("sudo"));
        Assert.Single(store.SetGroupsCalls);
        Assert.Empty(store.SetGroupsCalls[0]);
    }

    [Fact]
    public async Task GroupMembership_DesiredGroupPersisted()
    {
        // Policy declares alice in group sudo — SetManagedGroups should be called with "alice:sudo".
        var store  = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-with-group",
                    """{"policy_id":"policy-with-group","version":1,"linux":{"local_users":[{"username":"alice","action":"Create","shell":"/bin/bash","groups":["sudo"]}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Single(store.SetGroupsCalls);
        Assert.Contains("alice:sudo", store.SetGroupsCalls[0]);
    }

    [Fact]
    public async Task GroupMembership_DeleteDirective_DoesNotKeepGroupDesired()
    {
        // A Delete user directive must NOT add the user's groups to desiredGroups.
        // If it did, the stale-group reconciliation pass would skip removing the
        // membership ("alice:sudo" would appear desired even though alice is being
        // deleted). This is a regression test for the ExtractDesiredItems bug fix.
        var staleState = new DDS.PolicyAgent.Linux.State.AppliedState();
        staleState.ManagedGroups.Add("alice:sudo");

        var store  = new TrackingAppliedStateStore(staleState);
        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                // Policy now says Delete alice (but mistakenly still lists groups).
                WorkerFactory.MakePolicy(
                    "policy-delete-user",
                    """{"policy_id":"policy-delete-user","version":1,"linux":{"local_users":[{"username":"alice","action":"Delete","groups":["sudo"]}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // SetManagedGroups must be called with an empty set: the Delete directive
        // must not contribute "alice:sudo" to the desired set.
        Assert.Single(store.SetGroupsCalls);
        Assert.Empty(store.SetGroupsCalls[0]);

        // The stale group reconciliation must have attempted gpasswd -d alice sudo.
        Assert.Contains(runner.Invocations,
            i => i.FileName == "gpasswd" && i.Arguments.Contains("alice") && i.Arguments.Contains("sudo"));
    }

    [Fact]
    public async Task CreateUser_RecordsManagedUsername()
    {
        // A Create directive that succeeds should register the username in the managed set.
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-create-user",
                    """{"policy_id":"policy-create-user","version":1,"linux":{"local_users":[{"username":"bob","action":"Create","shell":"/bin/bash"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("bob", store.AddedUsernames);
    }

    [Fact]
    public async Task SetFile_RecordsManagedPath()
    {
        // A Set file directive that succeeds should register the path in the managed set.
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var contentB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("# managed by dds"));
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-set-file",
                    "{\"policy_id\":\"policy-set-file\",\"version\":1,\"linux\":{\"files\":[{\"path\":\"/etc/dds/test.conf\",\"action\":\"Set\",\"content_b64\":\"" + contentB64 + "\"}]}}"),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("/etc/dds/test.conf", store.AddedPaths);
    }

    [Fact]
    public async Task EnsureDir_RecordsManagedPath()
    {
        // An EnsureDir file directive should register the path in the managed set.
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-ensuredir",
                    """{"policy_id":"policy-ensuredir","version":1,"linux":{"files":[{"path":"/etc/dds/conf.d","action":"EnsureDir"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("/etc/dds/conf.d", store.AddedPaths);
    }

    [Fact]
    public async Task InstallPackage_RecordsManagedPackage()
    {
        // An Install package directive that succeeds should register the package in the managed set.
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-install-pkg",
                    """{"policy_id":"policy-install-pkg","version":1,"linux":{"packages":[{"name":"curl","action":"Install"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("curl", store.AddedPackages);
    }

    [Fact]
    public async Task RemovePackage_RemovesFromManagedSet()
    {
        // Pre-populate the managed set with "curl" so the PackageEnforcer Remove guard passes.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedPackages.Add("curl");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-remove-pkg",
                    """{"policy_id":"policy-remove-pkg","version":1,"linux":{"packages":[{"name":"curl","action":"Remove"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // The remove directive must trigger RemoveManagedPackage, not RecordManagedPackage.
        Assert.Contains("curl", store.RemovedPackages);
        Assert.DoesNotContain("curl", store.AddedPackages);
    }

    [Fact]
    public async Task DeleteSudoers_RemovesFromManagedSet()
    {
        // Pre-populate the managed set with "dds-ops" to reflect a realistic prior cycle.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSudoersFilenames.Add("dds-ops");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                // Empty content signals deletion in SudoersEnforcer.
                WorkerFactory.MakePolicy(
                    "policy-delete-sudoers",
                    """{"policy_id":"policy-delete-sudoers","version":1,"linux":{"sudoers":[{"filename":"dds-ops","content":""}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // The delete directive must trigger RemoveManagedSudoersFilename, not RecordManagedSudoersFilename.
        Assert.Contains("dds-ops", store.RemovedSudoersFilenames);
        Assert.DoesNotContain("dds-ops", store.AddedSudoersFilenames);
    }

    [Fact]
    public async Task RemoveDropin_RemovesFromManagedSet()
    {
        // Pre-populate the managed set with the dropin key to reflect a realistic prior cycle.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSystemdDropins.Add("sshd.service/dds-limits");
        var store = new TrackingAppliedStateStore(initialState);

        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-remove-dropin",
                    """{"policy_id":"policy-remove-dropin","version":1,"linux":{"systemd":[{"unit":"sshd.service","action":"RemoveDropin","dropin_name":"dds-limits"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // The RemoveDropin directive must trigger RemoveManagedSystemdDropin, not RecordManagedSystemdDropin.
        Assert.Contains("sshd.service/dds-limits", store.RemovedSystemdDropinKeys);
        Assert.DoesNotContain("sshd.service/dds-limits", store.AddedSystemdDropinKeys);
    }

    // =========================================================
    // Apply-phase [AUDIT] prefix tests (113th pass)
    //
    // The 112th pass fixed missing [AUDIT] prefixes in six enforcer
    // ApplyAsync paths. These tests verify the prefix survives the
    // full Worker → enforcer → report pipeline (not just the
    // enforcer unit in isolation).
    // =========================================================

    [Fact]
    public async Task Apply_CreateUser_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-create-user",
                    """{"policy_id":"policy-audit-create-user","version":1,"linux":{"local_users":[{"username":"alice","action":"Create","shell":"/bin/bash"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // Managed state must be updated so future Remove directives pass the guard.
        Assert.Contains("alice", store.AddedUsernames);

        // The policy report directive must carry [AUDIT] so operators can
        // distinguish dry-run entries from actual mutations.
        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-create-user");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] user:create:alice", report.Directives);
    }

    [Fact]
    public async Task Apply_InstallPackage_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-install-pkg",
                    """{"policy_id":"policy-audit-install-pkg","version":1,"linux":{"packages":[{"name":"ntp","action":"Install"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("ntp", store.AddedPackages);

        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-install-pkg");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] pkg:install:ntp", report.Directives);
    }

    [Fact]
    public async Task Apply_SetFile_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var contentB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("# managed by dds"));
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-set-file",
                    "{\"policy_id\":\"policy-audit-set-file\",\"version\":1,\"linux\":{\"files\":[{\"path\":\"/etc/dds/audit.conf\",\"action\":\"Set\",\"content_b64\":\"" + contentB64 + "\"}]}}"),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        Assert.Contains("/etc/dds/audit.conf", store.AddedPaths);

        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-set-file");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] file:set:/etc/dds/audit.conf", report.Directives);
    }

    [Fact]
    public async Task Apply_SetSudoers_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-sudoers",
                    """{"policy_id":"policy-audit-sudoers","version":1,"linux":{"sudoers":[{"filename":"dds-ops","content":"alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // Managed state must be updated so stale-sudoers reconciliation detects the drop-in.
        Assert.Contains("dds-ops", store.AddedSudoersFilenames);

        // The policy report directive must carry [AUDIT] so operators can
        // distinguish dry-run entries from actual mutations.
        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-sudoers");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] sudoers:set:dds-ops", report.Directives);
    }

    [Fact]
    public async Task Apply_SetSysctl_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-sysctl",
                    """{"policy_id":"policy-audit-sysctl","version":1,"linux":{"sysctl":[{"key":"vm.swappiness","value":"10","action":"Set"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-sysctl");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] sysctl:set:vm.swappiness", report.Directives);
    }

    [Fact]
    public async Task Apply_ConfigureSystemdDropin_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var store = new TrackingAppliedStateStore(new DDS.PolicyAgent.Linux.State.AppliedState());
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-systemd",
                    """{"policy_id":"policy-audit-systemd","version":1,"linux":{"systemd":[{"unit":"sshd.service","action":"ConfigureDropin","dropin_name":"hardening","dropin_content":"[Service]\nLimitNOFILE=65535"}]}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store);

        await worker.PollOnceAsync(CancellationToken.None);

        // Managed state must be updated so stale-dropin reconciliation detects the drop-in.
        Assert.Contains("sshd.service/hardening", store.AddedSystemdDropinKeys);

        // The policy report directive must carry [AUDIT].
        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-systemd");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] systemd:configuredropin:sshd.service/hardening", report.Directives);
    }

    [Fact]
    public async Task Apply_SshdPolicy_AuditOnly_ReportDirectiveHasAuditPrefix()
    {
        var client = new TestDdsNodeClient
        {
            NextPolicies =
            [
                WorkerFactory.MakePolicy(
                    "policy-audit-sshd",
                    """{"policy_id":"policy-audit-sshd","version":1,"linux":{"ssh":{"password_authentication":false}}}"""),
            ],
        };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client);

        await worker.PollOnceAsync(CancellationToken.None);

        var report = client.ReceivedReports.SingleOrDefault(r => r.TargetId == "policy-audit-sshd");
        Assert.NotNull(report);
        Assert.Contains("[AUDIT] sshd:set:PasswordAuthentication=False", report.Directives);
    }

    [Fact]
    public async Task Reconciliation_StaleSudoersDropin_AuditOnly_EmitsAuditPrefixedDeleteDirective()
    {
        // "dds-ops" was managed in a prior cycle but is absent from all current policies.
        // In audit mode the drop-in must NOT be deleted, but the reconciliation report
        // must carry the [AUDIT] prefix so operators can distinguish dry-run from real action.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSudoersFilenames.Add("dds-ops");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // State tracking must still remove the filename so the item is not re-reported every cycle.
        Assert.Contains("dds-ops", store.RemovedSudoersFilenames);
        // No filesystem calls — visudo/delete must not be invoked.
        Assert.Empty(runner.Invocations);

        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] sudoers:delete:dds-ops", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StaleSystemdDropin_AuditOnly_EmitsAuditPrefixedRemoveDropinDirective()
    {
        // "sshd.service/hardening" was managed in a prior cycle but is absent from all current
        // policies. In audit mode the drop-in file must NOT be removed, but the reconciliation
        // report must carry the [AUDIT] prefix.
        var initialState = new DDS.PolicyAgent.Linux.State.AppliedState();
        initialState.ManagedSystemdDropins.Add("sshd.service/hardening");
        var store = new TrackingAppliedStateStore(initialState);

        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // State tracking must still remove the key so the item is not re-reported every cycle.
        Assert.Contains("sshd.service/hardening", store.RemovedSystemdDropinKeys);
        // daemon-reload and file-delete must not be invoked.
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "systemctl");

        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] systemd:removedropin:sshd.service/hardening", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StaleGroupMembership_AuditOnly_EmitsAuditPrefixedLeaveGroupDirective()
    {
        // "alice:sudo" was managed in a prior cycle but is absent from all current policies.
        // In audit mode gpasswd must NOT be called, but the reconciliation report must carry
        // the [AUDIT] prefix so operators can distinguish dry-run from real action.
        var staleState = new DDS.PolicyAgent.Linux.State.AppliedState();
        staleState.ManagedGroups.Add("alice:sudo");

        var store  = new TrackingAppliedStateStore(staleState);
        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = true,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // gpasswd must not be invoked in audit mode.
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "gpasswd");
        // SetManagedGroups is always called with the empty desired set.
        Assert.Single(store.SetGroupsCalls);
        Assert.Empty(store.SetGroupsCalls[0]);

        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("[AUDIT] user:leave-group:alice:sudo", reconciliation.Directives);
    }

    [Fact]
    public async Task Reconciliation_StaleGroupMembership_EnforceMode_EmitsLeaveGroupDirective()
    {
        // "alice:sudo" was managed in a prior cycle but is absent from all current policies.
        // In enforce mode gpasswd must be called and the reconciliation report must carry
        // user:leave-group:alice:sudo without the [AUDIT] prefix.
        var staleState = new DDS.PolicyAgent.Linux.State.AppliedState();
        staleState.ManagedGroups.Add("alice:sudo");

        var store  = new TrackingAppliedStateStore(staleState);
        var runner = new NullCommandRunner();
        var client = new TestDdsNodeClient { NextPolicies = [] };
        var worker = WorkerFactory.Create(
            new AgentConfig
            {
                DeviceUrn = "urn:dds:device:test",
                PinnedNodePubkeyB64 = Convert.ToBase64String(new byte[32]),
                AuditOnly = false,
            },
            client, store, runner);

        await worker.PollOnceAsync(CancellationToken.None);

        // gpasswd must be invoked in enforce mode.
        Assert.Contains(runner.Invocations,
            i => i.FileName == "gpasswd" && i.Arguments.Contains("alice") && i.Arguments.Contains("sudo"));
        // SetManagedGroups is called with the empty desired set.
        Assert.Single(store.SetGroupsCalls);
        Assert.Empty(store.SetGroupsCalls[0]);

        var reconciliation = client.ReceivedReports
            .SingleOrDefault(r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconciliation);
        Assert.Contains("user:leave-group:alice:sudo", reconciliation.Directives);
        Assert.DoesNotContain("[AUDIT]", string.Join(",", reconciliation.Directives));
    }
}
