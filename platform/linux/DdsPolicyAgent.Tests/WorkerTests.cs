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
}
