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
}
