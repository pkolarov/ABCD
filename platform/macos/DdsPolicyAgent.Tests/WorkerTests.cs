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

    [Fact]
    public async Task Worker_stops_immediately_when_PinnedNodePubkeyB64_is_empty()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var stateStore = Substitute.For<IAppliedStateStore>();
        var config = Options.Create(new AgentConfig
        {
            DeviceUrn = "urn:dds:device:test",
            PinnedNodePubkeyB64 = "",
        });

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
        InMemoryMacPreferenceOperations? prefOps = null,
        InMemoryProfileOperations? profileOps = null)
    {
        launchdOps ??= new InMemoryLaunchdOperations();
        accountOps ??= new InMemoryMacAccountOperations();
        prefOps ??= new InMemoryMacPreferenceOperations();
        profileOps ??= new InMemoryProfileOperations();

        var config = Options.Create(new AgentConfig { DeviceUrn = "urn:dds:device:test" });
        return new Worker(
            client, store, config,
            NullLogger<Worker>.Instance,
            new PreferenceEnforcer(prefOps, NullLogger<PreferenceEnforcer>.Instance),
            new MacAccountEnforcer(accountOps, NullLogger<MacAccountEnforcer>.Instance),
            new LaunchdEnforcer(launchdOps, NullLogger<LaunchdEnforcer>.Instance),
            new ProfileEnforcer(profileOps, NullLogger<ProfileEnforcer>.Instance),
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

    [Fact]
    public async Task Reconciliation_NoStaleItems_NoReportSent()
    {
        // Empty managed sets → nothing stale → no reconciliation report.
        var store = new TrackingAppliedStateStore();
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(CancellationToken.None);

        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");
    }

    [Fact]
    public async Task Reconciliation_StalePreference_IsRemovedAndSetUpdated()
    {
        // "System:com.apple.dock:autohide" was managed in the previous cycle but is
        // absent from all current policies → reconciliation must delete the value.
        var prefOps = new InMemoryMacPreferenceOperations();
        prefOps.SetValueJson("com.apple.dock", "autohide", PreferenceScope.System, "true");

        var store = new TrackingAppliedStateStore(new()
        {
            ["preferences"] = ["System:com.apple.dock:autohide"],
        });
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store, prefOps: prefOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // The preference value must have been deleted by the enforcer.
        Assert.Null(prefOps.GetValueJson("com.apple.dock", "autohide", PreferenceScope.System));

        // The managed-preferences set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("preferences"));
        Assert.Empty(store.SetCalls["preferences"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredAccount_IsNotDisabled()
    {
        // "dds-kiosk" is both managed AND still present in the current
        // policy — it must survive reconciliation with IsEnabled == true.
        var accountOps = new InMemoryMacAccountOperations();
        accountOps.CreateUser("dds-kiosk", null, null, false, false);

        var store = new TrackingAppliedStateStore(new()
        {
            ["accounts"] = ["dds-kiosk"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"local_accounts":[{"action":"Create","username":"dds-kiosk"}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy { Jti = "jti-1", Document = policyDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Account must still be enabled — reconciliation must not have touched it.
        Assert.True(accountOps.IsEnabled("dds-kiosk"));

        // The managed set must still contain the account.
        Assert.True(store.SetCalls.ContainsKey("accounts"));
        Assert.Contains("dds-kiosk", store.SetCalls["accounts"]);
    }

    [Fact]
    public async Task Reconciliation_StaleProfile_IsRemovedAndSetUpdated()
    {
        // "com.dds.old-profile" was managed in the previous cycle but is absent
        // from all current policies → reconciliation must remove it.
        var profileOps = new InMemoryProfileOperations();
        profileOps.Install("com.dds.old-profile", "Old Profile", "sha256abc", [0x00]);

        var store = new TrackingAppliedStateStore(new()
        {
            ["profiles"] = ["com.dds.old-profile"],
        });
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store, profileOps: profileOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Profile must have been removed by the enforcer.
        Assert.False(profileOps.IsInstalled("com.dds.old-profile", "sha256abc"));

        // The managed-profiles set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("profiles"));
        Assert.Empty(store.SetCalls["profiles"]);
    }

    [Fact]
    public async Task Reconciliation_StaleSoftware_ReportsManualUninstall()
    {
        // "com.example.app" was managed in the previous cycle but is absent from
        // current software assignments → reconciliation logs a MANUAL uninstall
        // entry (generic pkg removal is not supported on macOS).
        var store = new TrackingAppliedStateStore(new()
        {
            ["software_managed"] = ["com.example.app"],
        });
        var client = new TestMacDdsNodeClient(); // no software directives

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Reconciliation report must contain a MANUAL entry for the stale package.
        var reconcileReport = client.ReceivedReports.FirstOrDefault(
            r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconcileReport);
        Assert.Contains(reconcileReport.Directives,
            d => d.Contains("MANUAL") && d.Contains("com.example.app"));

        // The managed-software set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("software_managed"));
        Assert.Empty(store.SetCalls["software_managed"]);
    }

    [Fact]
    public async Task Reconciliation_StaleGroupMembership_IsRemovedAndSetUpdated()
    {
        // "alice:sudo" was managed in the previous cycle but is absent from
        // all current policies → reconciliation must remove alice from sudo.
        var accountOps = new InMemoryMacAccountOperations();
        accountOps.CreateUser("alice", null, null, false, false);
        accountOps.AddToGroup("alice", "sudo");

        var store = new TrackingAppliedStateStore(new()
        {
            ["account_groups"] = ["alice:sudo"],
        });
        var client = new TestMacDdsNodeClient();

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // alice must have been removed from sudo by the enforcer.
        Assert.False(accountOps.IsInGroup("alice", "sudo"));

        // The managed-groups set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("account_groups"));
        Assert.Empty(store.SetCalls["account_groups"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredGroupMembership_IsKept()
    {
        // "alice:sudo" is both managed AND still declared in the current policy
        // — reconciliation must NOT remove alice from sudo.
        var accountOps = new InMemoryMacAccountOperations();
        accountOps.CreateUser("alice", null, null, false, false);
        accountOps.AddToGroup("alice", "sudo");

        var store = new TrackingAppliedStateStore(new()
        {
            ["account_groups"] = ["alice:sudo"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"local_accounts":[{"action":"Create","username":"alice","groups":["sudo"]}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy { Jti = "jti-1", Document = policyDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // alice must still be in sudo — reconciliation must not have touched it.
        Assert.True(accountOps.IsInGroup("alice", "sudo"));

        // The managed-groups set must still contain the membership.
        Assert.True(store.SetCalls.ContainsKey("account_groups"));
        Assert.Contains("alice:sudo", store.SetCalls["account_groups"]);
    }

    [Fact]
    public async Task GroupMembership_DeleteDirective_DoesNotKeepGroupDesired()
    {
        // A Delete account directive must NOT add the account's groups to desiredGroups.
        // If it did, stale-group reconciliation would skip removing "alice:sudo" even
        // though alice is being deleted. Regression test for the ExtractDesiredItems fix.
        var accountOps = new InMemoryMacAccountOperations();
        accountOps.CreateUser("alice", null, null, false, false);
        accountOps.AddToGroup("alice", "sudo");

        var store = new TrackingAppliedStateStore(new()
        {
            ["account_groups"] = ["alice:sudo"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"local_accounts":[{"action":"Delete","username":"alice","groups":["sudo"]}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy { Jti = "jti-1", Document = policyDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Stale-group reconciliation must have removed alice from sudo.
        Assert.False(accountOps.IsInGroup("alice", "sudo"));

        // The managed-groups set must now be empty.
        Assert.True(store.SetCalls.ContainsKey("account_groups"));
        Assert.Empty(store.SetCalls["account_groups"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredPreference_IsKept()
    {
        // "System:com.apple.dock:autohide" is both managed AND still declared
        // in the current policy — reconciliation must NOT delete the value.
        var prefOps = new InMemoryMacPreferenceOperations();
        prefOps.SetValueJson("com.apple.dock", "autohide", PreferenceScope.System, "true");

        var store = new TrackingAppliedStateStore(new()
        {
            ["preferences"] = ["System:com.apple.dock:autohide"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"preferences":[{"domain":"com.apple.dock","key":"autohide","value":true,"scope":"System","action":"Set"}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy { Jti = "jti-1", Document = policyDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store, prefOps: prefOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // The preference value must still be present.
        Assert.NotNull(prefOps.GetValueJson("com.apple.dock", "autohide", PreferenceScope.System));

        // The managed-preferences set must still contain the key.
        Assert.True(store.SetCalls.ContainsKey("preferences"));
        Assert.Contains("System:com.apple.dock:autohide", store.SetCalls["preferences"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredProfile_IsKept()
    {
        // "com.dds.active-profile" is both managed AND still declared in the
        // current policy — reconciliation must NOT remove the profile.
        var profileOps = new InMemoryProfileOperations();
        profileOps.Install("com.dds.active-profile", "Active Profile", "sha256abc", [0x01]);

        var store = new TrackingAppliedStateStore(new()
        {
            ["profiles"] = ["com.dds.active-profile"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"macos":{"profiles":[{"action":"Install","identifier":"com.dds.active-profile","display_name":"Active Profile","payload_sha256":"sha256abc","payload_b64":"AQ=="}]}}""");

        var client = new TestMacDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableMacOsPolicy { Jti = "jti-1", Document = policyDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store, profileOps: profileOps);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // Profile must still be installed — reconciliation must not have touched it.
        Assert.True(profileOps.IsInstalled("com.dds.active-profile", "sha256abc"));

        // The managed-profiles set must still contain the profile.
        Assert.True(store.SetCalls.ContainsKey("profiles"));
        Assert.Contains("com.dds.active-profile", store.SetCalls["profiles"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredSoftware_IsKept()
    {
        // "com.example.app" is both managed AND still present in current
        // software assignments — reconciliation must NOT emit a MANUAL uninstall.
        var store = new TrackingAppliedStateStore(new()
        {
            ["software_managed"] = ["com.example.app"],
        });

        var softwareDoc = JsonDocument.Parse(
            """{"package_id":"com.example.app","action":"Install","version":"1.0","source":"https://example.com/app.pkg","sha256":"abc"}""");

        var client = new TestMacDdsNodeClient
        {
            NextSoftware =
            [
                new ApplicableSoftware { Jti = "jti-sw-1", Document = softwareDoc.RootElement },
            ],
        };

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(CancellationToken.None);

        // No reconciliation report must be sent.
        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");

        // The managed-software set must still contain the package.
        Assert.True(store.SetCalls.ContainsKey("software_managed"));
        Assert.Contains("com.example.app", store.SetCalls["software_managed"]);
    }
}
