// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
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

        var worker = new Worker(
            client, stateStore, config,
            NullLogger<Worker>.Instance,
            new RegistryEnforcer(new InMemoryRegistryOperations(), NullLogger<RegistryEnforcer>.Instance),
            new AccountEnforcer(new InMemoryAccountOperations(), NullLogger<AccountEnforcer>.Instance),
            new PasswordPolicyEnforcer(new InMemoryPasswordPolicyOperations(), NullLogger<PasswordPolicyEnforcer>.Instance),
            new SoftwareInstaller(new InMemorySoftwareOperations(), NullLogger<SoftwareInstaller>.Instance));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await worker.StartAsync(cts.Token);
        // Should have returned immediately without calling the client.
        await client.DidNotReceive().GetPoliciesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await worker.StopAsync(default);
    }
}
