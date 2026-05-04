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
