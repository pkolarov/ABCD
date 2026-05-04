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
    public void RemoveManagedUsername(string username) { }
    public void RemoveManagedPath(string path) { }
    public void RemoveManagedPackage(string packageName) { }
}

/// State store whose Load() returns a pre-populated managed set and records
/// every add/remove call so tests can assert on resource lifecycle.
sealed class TrackingAppliedStateStore : IAppliedStateStore
{
    private readonly AppliedState _state;

    public List<string> AddedUsernames   { get; } = [];
    public List<string> RemovedUsernames { get; } = [];
    public List<string> AddedPaths       { get; } = [];
    public List<string> RemovedPaths     { get; } = [];
    public List<string> AddedPackages    { get; } = [];
    public List<string> RemovedPackages  { get; } = [];

    public TrackingAppliedStateStore(AppliedState initialState)
        => _state = initialState;

    public AppliedState Load() => _state;
    public bool HasChanged(string _, string __) => true;
    public void RecordApplied(string _, string __, string ___, string ____) { }

    public void RecordManagedUsername(string u) => AddedUsernames.Add(u);
    public void RecordManagedPath(string p)     => AddedPaths.Add(p);
    public void RecordManagedPackage(string n)  => AddedPackages.Add(n);

    public void RemoveManagedUsername(string u) => RemovedUsernames.Add(u);
    public void RemoveManagedPath(string p)     => RemovedPaths.Add(p);
    public void RemoveManagedPackage(string n)  => RemovedPackages.Add(n);
}

// ---- helpers ----

file static class WorkerFactory
{
    public static Worker Create(
        AgentConfig config,
        IDdsNodeClient? client = null,
        IAppliedStateStore? store = null,
        ICommandRunner? runner = null)
    {
        client ??= new TestDdsNodeClient();
        store  ??= new TestAppliedStateStore();
        runner ??= new NullCommandRunner();
        return new Worker(
            client,
            store,
            Options.Create(config),
            runner,
            NullLogger<Worker>.Instance);
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
}
