// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.HostState;
using DDS.PolicyAgent.State;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace DDS.PolicyAgent.Tests;

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

        var worker = BuildWorker(client, stateStore, new InMemoryJoinStateProbe(), config);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await worker.StartAsync(cts.Token);
        // Should have returned immediately without calling the client.
        await client.DidNotReceive().GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await worker.StopAsync(default);
    }

    // --- AD-04: EffectiveMode wrapper -----------------------------------

    [Theory]
    [InlineData(JoinState.Workgroup, EnforcementMode.Enforce, EnforcementMode.Enforce)]
    [InlineData(JoinState.Workgroup, EnforcementMode.Audit, EnforcementMode.Audit)]
    [InlineData(JoinState.AdJoined, EnforcementMode.Enforce, EnforcementMode.Audit)]
    [InlineData(JoinState.AdJoined, EnforcementMode.Audit, EnforcementMode.Audit)]
    [InlineData(JoinState.HybridJoined, EnforcementMode.Enforce, EnforcementMode.Audit)]
    [InlineData(JoinState.Unknown, EnforcementMode.Enforce, EnforcementMode.Audit)]
    public void EffectiveMode_forces_audit_on_ad_hybrid_unknown(
        JoinState host, EnforcementMode requested, EnforcementMode expected)
    {
        Assert.Equal(expected, Worker.EffectiveMode(requested, host));
    }

    [Fact]
    public void EffectiveModeReason_distinguishes_ad_coexistence_from_unknown_probe()
    {
        Assert.Equal(AppliedReason.AuditDueToAdCoexistence, Worker.EffectiveModeReason(JoinState.AdJoined));
        Assert.Equal(AppliedReason.AuditDueToAdCoexistence, Worker.EffectiveModeReason(JoinState.HybridJoined));
        Assert.Equal(AppliedReason.AuditDueToUnknownHostState, Worker.EffectiveModeReason(JoinState.Unknown));
        Assert.Null(Worker.EffectiveModeReason(JoinState.Workgroup));
        Assert.Null(Worker.EffectiveModeReason(JoinState.EntraOnlyJoined));
    }

    // --- AD-06: Entra-only short-circuit --------------------------------

    [Fact]
    public async Task Entra_only_host_emits_unsupported_heartbeat_and_skips_polling()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var stateStore = Substitute.For<IAppliedStateStore>();
        var probe = new InMemoryJoinStateProbe(JoinState.EntraOnlyJoined);
        var config = Options.Create(new AgentConfig
        {
            DeviceUrn = "dds:device:entra-host",
            PollIntervalSeconds = 60,
        });

        var worker = BuildWorker(client, stateStore, probe, config);

        using var cts = new CancellationTokenSource();
        var task = worker.StartAsync(cts.Token);
        await Task.Delay(150);
        cts.Cancel();
        await task;
        await worker.StopAsync(default);

        // No directive polling should have happened.
        await client.DidNotReceive().GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await client.DidNotReceive().GetSoftwareAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        // Exactly one heartbeat report with the canonical reason should
        // have fired in the cycle that ran before cancellation.
        await client.Received(1).ReportAppliedAsync(
            Arg.Is<AppliedReport>(r => r.TargetId == "_host_state"
                                       && r.Status == "unsupported"
                                       && r.Reason == AppliedReason.UnsupportedEntra),
            Arg.Any<CancellationToken>());
    }

    // --- AD-04 / AD-05: AD-joined host runs audit-only ------------------

    [Fact]
    public async Task AdJoined_host_dispatches_in_audit_mode_and_reports_reason()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var stateStore = Substitute.For<IAppliedStateStore>();
        var probe = new InMemoryJoinStateProbe(JoinState.AdJoined);
        var config = Options.Create(new AgentConfig
        {
            DeviceUrn = "dds:device:ad-host",
            PollIntervalSeconds = 60,
        });

        client.GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new List<ApplicableWindowsPolicy>
            {
                BuildPolicy("p:reg:1", version: "1",
                    """{"policy_id":"p:reg:1","version":1,"enforcement":"Enforce","windows":{"registry":[{"action":"Set","hive":"HKLM","subkey":"Software\\X","value_name":"Y","kind":"DWORD","value":1}]}}"""),
            });
        client.GetSoftwareAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new List<ApplicableSoftware>());
        stateStore.HasChanged(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        stateStore.GetManagedItems(Arg.Any<string>())
            .Returns(_ => (IReadOnlySet<string>)new HashSet<string>());

        var ops = new InMemoryRegistryOperations();
        var worker = BuildWorker(
            client, stateStore, probe, config,
            registryEnforcer: new RegistryEnforcer(ops, NullLogger<RegistryEnforcer>.Instance));

        using var cts = new CancellationTokenSource();
        var task = worker.StartAsync(cts.Token);
        await Task.Delay(150);
        cts.Cancel();
        await task;
        await worker.StopAsync(default);

        // The registry operation must NOT have been written through.
        // InMemoryRegistryOperations exposes Count = number of stored values.
        Assert.Equal(0, ops.Count);
        // The reported status must carry the AD-coexistence reason.
        await client.Received().ReportAppliedAsync(
            Arg.Is<AppliedReport>(r => r.TargetId == "p:reg:1"
                                       && r.Reason == AppliedReason.AuditDueToAdCoexistence),
            Arg.Any<CancellationToken>());
    }

    // --- AD-04: stale-item reconciliation freezes under audit -----------

    [Fact]
    public async Task AdJoined_host_freezes_stale_items_instead_of_unwinding()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var probe = new InMemoryJoinStateProbe(JoinState.AdJoined);
        var stateDir = Path.Combine(Path.GetTempPath(), $"dds-test-{Guid.NewGuid():N}");
        try
        {
            var stateStore = new AppliedStateStore(stateDir);
            // Pre-seed a stale item from a prior workgroup-mode cycle.
            stateStore.RecordManagedItems(
                "registry",
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "HKLM\\Software\\Stale" },
                JoinState.Workgroup, auditMode: false, reason: null);

            var config = Options.Create(new AgentConfig
            {
                DeviceUrn = "dds:device:ad-host",
                PollIntervalSeconds = 60,
            });
            client.GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableWindowsPolicy>());
            client.GetSoftwareAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableSoftware>());

            var worker = BuildWorker(client, stateStore, probe, config);

            using var cts = new CancellationTokenSource();
            var task = worker.StartAsync(cts.Token);
            await Task.Delay(150);
            cts.Cancel();
            await task;
            await worker.StopAsync(default);

            // Stale item must still be present in inventory.
            var managed = stateStore.GetManagedItems("registry");
            Assert.Contains("HKLM\\Software\\Stale", managed);

            // And it must be marked audit_frozen with the AD reason.
            var state = stateStore.Load();
            var record = state.ManagedItems["registry"]["HKLM\\Software\\Stale"];
            Assert.True(record.AuditFrozen);
            Assert.Equal(nameof(JoinState.AdJoined), record.HostStateAtApply);
            Assert.NotNull(record.LastReason);
            Assert.Contains(AppliedReason.AuditDueToAdCoexistence, record.LastReason);
            Assert.Contains(AppliedReason.WouldCleanStale, record.LastReason);
        }
        finally
        {
            try { Directory.Delete(stateDir, recursive: true); } catch { /* best effort */ }
        }
    }

    // --- service reconciliation tracking --------------------------------

    [Fact]
    public async Task Service_directives_are_tracked_in_managed_items()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var probe = new InMemoryJoinStateProbe(JoinState.Workgroup);
        var stateDir = Path.Combine(Path.GetTempPath(), $"dds-test-{Guid.NewGuid():N}");
        try
        {
            var stateStore = new AppliedStateStore(stateDir);
            var config = Options.Create(new AgentConfig
            {
                DeviceUrn = "dds:device:svc-host",
                PollIntervalSeconds = 60,
            });
            client.GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableWindowsPolicy>
                {
                    BuildPolicy("p:svc:1", version: "1",
                        """{"policy_id":"p:svc:1","version":1,"enforcement":"Enforce","windows":{"services":[{"name":"MySvc","action":"Configure","start_type":"Automatic"}]}}"""),
                });
            client.GetSoftwareAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableSoftware>());

            var ops = new InMemoryServiceOperations();
            ops.Seed("MySvc", startType: "Manual", runState: "Stopped");
            var worker = BuildWorker(
                client, stateStore, probe, config,
                serviceEnforcer: new ServiceEnforcer(ops, NullLogger<ServiceEnforcer>.Instance));

            using var cts = new CancellationTokenSource();
            var task = worker.StartAsync(cts.Token);
            await Task.Delay(150);
            cts.Cancel();
            await task;
            await worker.StopAsync(default);

            var managed = stateStore.GetManagedItems("services");
            Assert.Contains("MySvc", managed);
        }
        finally
        {
            try { Directory.Delete(stateDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task Stale_service_is_noted_in_reconciliation_report()
    {
        var client = Substitute.For<IDdsNodeClient>();
        var probe = new InMemoryJoinStateProbe(JoinState.Workgroup);
        var stateDir = Path.Combine(Path.GetTempPath(), $"dds-test-{Guid.NewGuid():N}");
        try
        {
            var stateStore = new AppliedStateStore(stateDir);
            stateStore.RecordManagedItems(
                "services",
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "StaleSvc" },
                JoinState.Workgroup, auditMode: false, reason: null);

            var config = Options.Create(new AgentConfig
            {
                DeviceUrn = "dds:device:svc-host",
                PollIntervalSeconds = 60,
            });
            client.GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableWindowsPolicy>());
            client.GetSoftwareAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new List<ApplicableSoftware>());

            var worker = BuildWorker(client, stateStore, probe, config);

            using var cts = new CancellationTokenSource();
            var task = worker.StartAsync(cts.Token);
            await Task.Delay(150);
            cts.Cancel();
            await task;
            await worker.StopAsync(default);

            // After reconciliation the stale service must NOT be in the current desired set.
            var managed = stateStore.GetManagedItems("services");
            Assert.DoesNotContain("StaleSvc", managed);

            // A reconciliation report containing [MANUAL] must have been submitted.
            await client.Received().ReportAppliedAsync(
                Arg.Is<AppliedReport>(r =>
                    r.TargetId == "_reconciliation" &&
                    r.Directives != null &&
                    r.Directives.Any(d => d.Contains("[MANUAL]") && d.Contains("StaleSvc"))),
                Arg.Any<CancellationToken>());
        }
        finally
        {
            try { Directory.Delete(stateDir, recursive: true); } catch { /* best effort */ }
        }
    }

    // ─── Reconciliation tests (Worker-level) ─────────────────────────────────
    // These tests drive Worker.PollAndApplyAsync directly on a workgroup host
    // with an empty policy list so the reconciliation pass runs in isolation.

    private static Worker MakeWorker(
        TestWindowsDdsNodeClient client,
        TrackingAppliedStateStore store,
        InMemoryRegistryOperations? registryOps = null,
        InMemoryAccountOperations? accountOps = null,
        InMemorySoftwareOperations? softwareOps = null,
        InMemoryServiceOperations? serviceOps = null)
    {
        var config = Options.Create(new AgentConfig { DeviceUrn = "urn:dds:device:test" });
        return new Worker(
            client, store, new InMemoryJoinStateProbe(JoinState.Workgroup), config,
            NullLogger<Worker>.Instance,
            new RegistryEnforcer(registryOps ?? new InMemoryRegistryOperations(), NullLogger<RegistryEnforcer>.Instance),
            new AccountEnforcer(accountOps ?? new InMemoryAccountOperations(), new InMemoryJoinStateProbe(), NullLogger<AccountEnforcer>.Instance),
            new PasswordPolicyEnforcer(new InMemoryPasswordPolicyOperations(), NullLogger<PasswordPolicyEnforcer>.Instance),
            new SoftwareInstaller(softwareOps ?? new InMemorySoftwareOperations(), NullLogger<SoftwareInstaller>.Instance),
            new ServiceEnforcer(serviceOps ?? new InMemoryServiceOperations(), NullLogger<ServiceEnforcer>.Instance));
    }

    [Fact]
    public async Task Reconciliation_StaleRegistryEntry_IsDeleted()
    {
        // A registry value was managed in the prior cycle but no current
        // policy claims it → reconciliation must delete it.
        var registryOps = new InMemoryRegistryOperations();
        registryOps.SetValue("LocalMachine", @"SOFTWARE\Policies\DDS", "OldSetting", (uint)1, RegValueKind.Dword);

        var store = new TrackingAppliedStateStore(new()
        {
            ["registry"] = [@"LocalMachine\SOFTWARE\Policies\DDS\OldSetting"],
        });
        var client = new TestWindowsDdsNodeClient(); // no policies

        var worker = MakeWorker(client, store, registryOps: registryOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Value must have been deleted by the enforcer.
        Assert.Null(registryOps.Peek("LocalMachine", @"SOFTWARE\Policies\DDS", "OldSetting"));

        // The managed-registry set must now be empty.
        Assert.True(store.RecordCalls.ContainsKey("registry"));
        Assert.Empty(store.RecordCalls["registry"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredRegistryEntry_IsKept()
    {
        // A registry value is both managed AND present in the current policy
        // → reconciliation must not touch it.
        var registryOps = new InMemoryRegistryOperations();
        registryOps.SetValue("LocalMachine", @"SOFTWARE\Policies\DDS", "Setting", (uint)1, RegValueKind.Dword);

        var store = new TrackingAppliedStateStore(new()
        {
            ["registry"] = [@"LocalMachine\SOFTWARE\Policies\DDS\Setting"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"enforcement":"Enforce","windows":{"registry":[{"action":"Set","hive":"LocalMachine","key":"SOFTWARE\\Policies\\DDS","name":"Setting","value":{"Dword":1}}]}}""");
        var client = new TestWindowsDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableWindowsPolicy
                {
                    Jti = "jti-1",
                    Issuer = "dds:test",
                    Iat = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Document = policyDoc.RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store, registryOps: registryOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Value must still be present — reconciliation must not have deleted it.
        Assert.NotNull(registryOps.Peek("LocalMachine", @"SOFTWARE\Policies\DDS", "Setting"));

        // The managed set must still contain the entry.
        Assert.True(store.RecordCalls.ContainsKey("registry"));
        Assert.Contains(@"LocalMachine\SOFTWARE\Policies\DDS\Setting",
            store.RecordCalls["registry"], StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reconciliation_StaleAccount_IsDisabled()
    {
        // "dds-ops" was managed in the prior cycle but no current policy
        // claims it → reconciliation must disable the account.
        var accountOps = new InMemoryAccountOperations();
        accountOps.CreateUser("dds-ops", null, null);

        var store = new TrackingAppliedStateStore(new()
        {
            ["accounts"] = ["dds-ops"],
        });
        var client = new TestWindowsDdsNodeClient();

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Account must be disabled (not deleted).
        Assert.False(accountOps.IsEnabled("dds-ops"));

        // The managed-accounts set must now be empty.
        Assert.True(store.RecordCalls.ContainsKey("accounts"));
        Assert.Empty(store.RecordCalls["accounts"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredAccount_IsNotDisabled()
    {
        // "dds-ops" is both managed AND present in the current policy
        // → reconciliation must not disable it.
        var accountOps = new InMemoryAccountOperations();
        accountOps.CreateUser("dds-ops", null, null);

        var store = new TrackingAppliedStateStore(new()
        {
            ["accounts"] = ["dds-ops"],
        });

        var policyDoc = JsonDocument.Parse(
            """{"policy_id":"p1","version":1,"enforcement":"Enforce","windows":{"local_accounts":[{"action":"Create","username":"dds-ops"}]}}""");
        var client = new TestWindowsDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableWindowsPolicy
                {
                    Jti = "jti-1",
                    Issuer = "dds:test",
                    Iat = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Document = policyDoc.RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Account must still be enabled.
        Assert.True(accountOps.IsEnabled("dds-ops"));

        // The managed set must still contain the account.
        Assert.True(store.RecordCalls.ContainsKey("accounts"));
        Assert.Contains("dds-ops", store.RecordCalls["accounts"], StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reconciliation_StaleGroupMembership_IsRemoved()
    {
        // "alice:Administrators" was managed in the prior cycle but no
        // current policy claims it → reconciliation must remove alice from Administrators.
        var accountOps = new InMemoryAccountOperations();
        accountOps.CreateUser("alice", null, null);
        accountOps.AddToGroup("alice", "Administrators");
        accountOps.AddToGroup("alice", "Users");

        var store = new TrackingAppliedStateStore(new()
        {
            ["account_groups"] = ["alice:Administrators"],
        });
        var client = new TestWindowsDdsNodeClient();

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // alice must have been removed from Administrators.
        Assert.DoesNotContain("Administrators", accountOps.GetGroups("alice"));
        // alice must still be in Users (unmanaged membership is not touched).
        Assert.Contains("Users", accountOps.GetGroups("alice"));

        // The managed-groups set must now be empty.
        Assert.True(store.RecordCalls.ContainsKey("account_groups"));
        Assert.Empty(store.RecordCalls["account_groups"]);
    }

    [Fact]
    public async Task Reconciliation_StaleSoftware_IsUninstalled()
    {
        // "com.example.editor" was managed in the prior cycle but no
        // current software assignment claims it → reconciliation must uninstall it.
        var softwareOps = new InMemorySoftwareOperations();
        softwareOps.SeedInstalled("com.example.editor");

        var store = new TrackingAppliedStateStore(new()
        {
            ["software_managed"] = ["com.example.editor"],
        });
        var client = new TestWindowsDdsNodeClient();

        var worker = MakeWorker(client, store, softwareOps: softwareOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Package must have been uninstalled.
        Assert.False(softwareOps.IsInstalled("com.example.editor"));

        // The managed-software set must now be empty.
        Assert.True(store.RecordCalls.ContainsKey("software_managed"));
        Assert.Empty(store.RecordCalls["software_managed"]);
    }

    [Fact]
    public async Task Reconciliation_StaleService_IsNotedInReport()
    {
        // "LegacySvc" was managed in the prior cycle but no current policy
        // declares it → reconciliation must emit a [MANUAL] directive for it
        // (services are not auto-reverted) and update the managed-services set.
        var store = new TrackingAppliedStateStore(new()
        {
            ["services"] = ["LegacySvc"],
        });
        var client = new TestWindowsDdsNodeClient();

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // A reconciliation report must have been submitted.
        var reconcileReport = client.ReceivedReports.FirstOrDefault(
            r => r.TargetId == "_reconciliation");
        Assert.NotNull(reconcileReport);
        Assert.Equal("ok", reconcileReport.Status);
        Assert.Contains(reconcileReport.Directives,
            d => d.Contains("[MANUAL]") && d.Contains("LegacySvc"));

        // The managed-services set must now be empty.
        Assert.True(store.RecordCalls.ContainsKey("services"));
        Assert.Empty(store.RecordCalls["services"]);
    }

    [Fact]
    public async Task Reconciliation_NoStaleItems_NoReportSent()
    {
        // Empty managed sets → nothing stale → no _reconciliation report.
        var store = new TrackingAppliedStateStore();
        var client = new TestWindowsDdsNodeClient();

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");
    }

    [Fact]
    public async Task Reconciliation_DesiredGroupMembership_IsKept()
    {
        // "alice:Administrators" is both managed AND still declared in the current
        // policy — reconciliation must NOT remove alice from Administrators.
        var accountOps = new InMemoryAccountOperations();
        accountOps.CreateUser("alice", null, null);
        accountOps.AddToGroup("alice", "Administrators");

        var store = new TrackingAppliedStateStore(new()
        {
            ["account_groups"] = ["alice:Administrators"],
        });

        var client = new TestWindowsDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableWindowsPolicy
                {
                    Jti = "jti-1",
                    Document = JsonDocument.Parse(
                        """{"policy_id":"p1","version":1,"windows":{"local_accounts":[{"action":"Create","username":"alice","groups":["Administrators"]}]}}""").RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store, accountOps: accountOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // alice must still be in Administrators — reconciliation must not have touched it.
        Assert.Contains("Administrators", accountOps.GetGroups("alice"));

        // The managed-groups set must still contain the membership.
        Assert.True(store.RecordCalls.ContainsKey("account_groups"));
        Assert.Contains("alice:Administrators", store.RecordCalls["account_groups"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredSoftware_IsKept()
    {
        // "com.example.editor" is both managed AND still present in current
        // software assignments — reconciliation must NOT uninstall it.
        var softwareOps = new InMemorySoftwareOperations();
        softwareOps.SeedInstalled("com.example.editor");

        var store = new TrackingAppliedStateStore(new()
        {
            ["software_managed"] = ["com.example.editor"],
        });

        var client = new TestWindowsDdsNodeClient
        {
            NextSoftware =
            [
                new ApplicableSoftware
                {
                    Jti = "jti-sw-1",
                    Document = JsonDocument.Parse(
                        """{"package_id":"com.example.editor","action":"Install","version":"1.0","source_url":"https://example.com/editor.msi","sha256":"abc","installer_type":"msi"}""").RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store, softwareOps: softwareOps);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // Package must still be marked installed — reconciliation must not have uninstalled it.
        Assert.True(softwareOps.IsInstalled("com.example.editor"));

        // The managed-software set must still contain the package.
        Assert.True(store.RecordCalls.ContainsKey("software_managed"));
        Assert.Contains("com.example.editor", store.RecordCalls["software_managed"]);
    }

    [Fact]
    public async Task Reconciliation_DesiredService_IsKept()
    {
        // "MySvc" is both managed AND still declared in the current policy —
        // reconciliation must NOT emit a [MANUAL] directive for it.
        var store = new TrackingAppliedStateStore(new()
        {
            ["services"] = ["MySvc"],
        });

        var client = new TestWindowsDdsNodeClient
        {
            NextPolicies =
            [
                new ApplicableWindowsPolicy
                {
                    Jti = "jti-1",
                    Document = JsonDocument.Parse(
                        """{"policy_id":"p1","version":1,"windows":{"services":[{"name":"MySvc","action":"Configure","binary_path":"C:\\MySvc\\mysvc.exe","display_name":"My Service","start_type":"Automatic"}]}}""").RootElement,
                },
            ],
        };

        var worker = MakeWorker(client, store);
        await worker.PollAndApplyAsync(JoinState.Workgroup, CancellationToken.None);

        // No reconciliation report must be sent.
        Assert.DoesNotContain(client.ReceivedReports, r => r.TargetId == "_reconciliation");

        // The managed-services set must still contain the service.
        Assert.True(store.RecordCalls.ContainsKey("services"));
        Assert.Contains("MySvc", store.RecordCalls["services"]);
    }

    // --- helpers --------------------------------------------------------

    private static Worker BuildWorker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IJoinStateProbe probe,
        IOptions<AgentConfig> config,
        RegistryEnforcer? registryEnforcer = null,
        AccountEnforcer? accountEnforcer = null,
        PasswordPolicyEnforcer? passwordPolicyEnforcer = null,
        SoftwareInstaller? softwareInstaller = null,
        ServiceEnforcer? serviceEnforcer = null)
    {
        return new Worker(
            client,
            stateStore,
            probe,
            config,
            NullLogger<Worker>.Instance,
            registryEnforcer ?? new RegistryEnforcer(
                new InMemoryRegistryOperations(), NullLogger<RegistryEnforcer>.Instance),
            accountEnforcer ?? new AccountEnforcer(
                new InMemoryAccountOperations(), new InMemoryJoinStateProbe(),
                NullLogger<AccountEnforcer>.Instance),
            passwordPolicyEnforcer ?? new PasswordPolicyEnforcer(
                new InMemoryPasswordPolicyOperations(),
                NullLogger<PasswordPolicyEnforcer>.Instance),
            softwareInstaller ?? new SoftwareInstaller(
                new InMemorySoftwareOperations(),
                NullLogger<SoftwareInstaller>.Instance),
            serviceEnforcer ?? new ServiceEnforcer(
                new InMemoryServiceOperations(),
                NullLogger<ServiceEnforcer>.Instance));
    }

    private static ApplicableWindowsPolicy BuildPolicy(string id, string version, string docJson)
    {
        return new ApplicableWindowsPolicy
        {
            Jti = id,
            Issuer = "dds:test",
            Iat = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Document = JsonDocument.Parse(docJson).RootElement,
        };
    }
}
