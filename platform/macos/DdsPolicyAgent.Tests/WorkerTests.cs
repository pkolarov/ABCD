// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.MacOS.Client;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.Runtime;
using DDS.PolicyAgent.MacOS.State;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace DDS.PolicyAgent.MacOS.Tests;

public class WorkerTests
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

    [Fact]
    public async Task Worker_stops_immediately_when_DeviceUrn_is_empty()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var stateStore = Substitute.For<IAppliedStateStore>();
        var config = Options.Create(new AgentConfig { DeviceUrn = "" });

        var worker = new Worker(
            client, stateStore, config,
            NullLogger<Worker>.Instance,
            new PreferenceEnforcer(new InMemoryMacPreferenceOperations(), NullLogger<PreferenceEnforcer>.Instance),
            new MacAccountEnforcer(new InMemoryMacAccountOperations(), NullLogger<MacAccountEnforcer>.Instance),
            new LaunchdEnforcer(new InMemoryLaunchdOperations(), NullLogger<LaunchdEnforcer>.Instance),
            new ProfileEnforcer(new InMemoryProfileOperations(), NullLogger<ProfileEnforcer>.Instance),
            new SoftwareInstaller(
                NullLogger<SoftwareInstaller>.Instance,
                Substitute.For<ICommandRunner>(),
                Options.Create(new AgentConfig()),
                new StaticHttpClientFactory(new HttpClient())));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await worker.StartAsync(cts.Token);
        await client.DidNotReceive().GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await worker.StopAsync(default);
    }

    // ─── Reconciliation tests ─────────────────────────────────────────────────
    // These tests drive Worker.PollAndApplyAsync (exposed as internal) directly
    // rather than through ExecuteAsync so they can check reconciliation outcomes
    // without setting up a full hosted-service lifecycle.

    private static Worker MakeWorker(
        TestMacDdsNodeClient client,
        TrackingAppliedStateStore store,
        InMemoryLaunchdOperations? launchdOps = null,
        InMemoryMacAccountOperations? accountOps = null,
        InMemoryMacPreferenceOperations? prefOps = null)
    {
        launchdOps ??= new InMemoryLaunchdOperations();
        accountOps ??= new InMemoryMacAccountOperations();
        prefOps ??= new InMemoryMacPreferenceOperations();

        var config = Options.Create(new AgentConfig { DeviceUrn = "urn:dds:device:test" });
        return new Worker(
            client, store, config,
            NullLogger<Worker>.Instance,
            new PreferenceEnforcer(prefOps, NullLogger<PreferenceEnforcer>.Instance),
            new MacAccountEnforcer(accountOps, NullLogger<MacAccountEnforcer>.Instance),
            new LaunchdEnforcer(launchdOps, NullLogger<LaunchdEnforcer>.Instance),
            new ProfileEnforcer(new InMemoryProfileOperations(), NullLogger<ProfileEnforcer>.Instance),
            new SoftwareInstaller(
                NullLogger<SoftwareInstaller>.Instance,
                Substitute.For<ICommandRunner>(),
                Options.Create(new AgentConfig()),
                new StaticHttpClientFactory(new HttpClient())));
    }

    [Fact]
    public async Task Reconciliation_StaleLaunchdJob_IsUnloaded()
    {
        // "com.dds.old-job" was managed in the previous cycle but is absent
        // from all current policies → reconciliation must unload it.
        var launchdOps = new InMemoryLaunchdOperations();
        launchdOps.Load("com.dds.old-job");

        var store = new TrackingAppliedStateStore(new()
        {
            ["launchd"] = ["com.dds.old-job"],
        });
        var client = new TestMacDdsNodeClient(); // no policies, no software

        var worker = MakeWorker(client, store, launchdOps: launchdOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // The job must have been unloaded by the enforcer (Loaded → false).
        Assert.False(launchdOps.Peek("com.dds.old-job")?.Loaded ?? false);

        // The managed set for launchd must now be empty.
        Assert.True(store.SetCalls.ContainsKey("launchd"));
        Assert.Empty(store.SetCalls["launchd"]);
    }

    [Fact]
    public async Task Reconciliation_StaleAccount_IsDisabled()
    {
        // "dds-kiosk" was managed in the previous cycle but is absent
        // from all current policies → reconciliation must disable it.
        var accountOps = new InMemoryMacAccountOperations();
        accountOps.CreateUser("dds-kiosk", null, null, false, false);

        var store = new TrackingAppliedStateStore(new()
        {
            ["accounts"] = ["dds-kiosk"],
        });
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // The account must be disabled (not deleted) — IsEnabled flips to false.
        Assert.False(accountOps.IsEnabled("dds-kiosk"));

        // The managed-accounts set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("accounts"));
        Assert.Empty(store.SetCalls["accounts"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredLaunchdJob_IsNotUnloaded()
    {
        // "com.dds.active-job" is both managed AND still present in the
        // current policy — it must survive reconciliation.
        var launchdOps = new InMemoryLaunchdOperations();
        launchdOps.Load("com.dds.active-job");

        var store = new TrackingAppliedStateStore(new()
        {
            ["launchd"] = ["com.dds.active-job"],
        });

        // Policy document contains the same job → desired set is non-empty.
        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"launchd":[{"label":"com.dds.active-job","action":"Configure","plist_path":"/Library/LaunchDaemons/com.dds.active-job.plist"}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy
                {
                    Jti = "jti-1",
                    Document = policyDoc.RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store, launchdOps: launchdOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Still loaded — reconciliation must not have touched it.
        Assert.True(launchdOps.Peek("com.dds.active-job")?.Loaded ?? false);

        // The managed set must still contain the job.
        Assert.True(store.SetCalls.ContainsKey("launchd"));
        Assert.Contains("com.dds.active-job", store.SetCalls["launchd"]);
    }

    [Fact]
    public async Task Reconciliation_ReconciliationReport_SentWhenChangesExist()
    {
        // When stale items are cleaned up the Worker must POST a
        // "_reconciliation" report back to dds-node.
        var launchdOps = new InMemoryLaunchdOperations();
        launchdOps.Load("com.dds.stale");

        var store = new TrackingAppliedStateStore(new()
        {
            ["launchd"] = ["com.dds.stale"],
        });
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store, launchdOps: launchdOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        var reconcileReport = client.ReceivedReports.FirstOrDefault(
            r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconcileReport);
        Assert.Equal("ok", reconcileReport.Status);
        Assert.Contains(reconcileReport.Directives, d => d.Contains("com.dds.stale"));
    }
}
