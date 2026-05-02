// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.Linux;
using DDS.PolicyAgent.Linux.Client;
using DDS.PolicyAgent.Linux.Config;
using DDS.PolicyAgent.Linux.Runtime;
using DDS.PolicyAgent.Linux.State;
using Microsoft.Extensions.Configuration;

var builder = Host.CreateApplicationBuilder(args);

var configPath = Environment.GetEnvironmentVariable("DDS_POLICY_AGENT_CONFIG");
if (string.IsNullOrWhiteSpace(configPath) && OperatingSystem.IsLinux())
    configPath = "/etc/dds/policy-agent.json";
if (!string.IsNullOrWhiteSpace(configPath))
    builder.Configuration.AddJsonFile(configPath, optional: true, reloadOnChange: true);

builder.Services.Configure<AgentConfig>(
    builder.Configuration.GetSection(AgentConfig.SectionName));

builder.Services.AddSingleton<IAppliedStateStore>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    return new AppliedStateStore(cfg.ResolveStateDir());
});

builder.Services.AddSingleton<EnvelopeVerifier>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    if (string.IsNullOrWhiteSpace(cfg.PinnedNodePubkeyB64))
    {
        throw new InvalidOperationException(
            "DdsPolicyAgent:PinnedNodePubkeyB64 is not configured");
    }
    byte[] pubkey;
    try { pubkey = Convert.FromBase64String(cfg.PinnedNodePubkeyB64); }
    catch (FormatException e)
    {
        throw new InvalidOperationException(
            "DdsPolicyAgent:PinnedNodePubkeyB64 is not valid base64", e);
    }
    if (pubkey.Length != 32)
        throw new InvalidOperationException(
            "DdsPolicyAgent:PinnedNodePubkeyB64 must decode to 32 bytes");
    if (string.IsNullOrWhiteSpace(cfg.DeviceUrn))
        throw new InvalidOperationException(
            "DdsPolicyAgent:DeviceUrn is required for envelope verification");
    return new EnvelopeVerifier(
        pubkey, cfg.DeviceUrn,
        TimeSpan.FromSeconds(cfg.EnvelopeMaxClockSkewSeconds));
});

builder.Services.AddHttpClient<IDdsNodeClient, DdsNodeClient>((sp, http) =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    http.BaseAddress = DdsNodeHttpFactory.ResolveBaseAddress(cfg.NodeBaseUrl);
    http.Timeout = TimeSpan.FromSeconds(10);
})
.ConfigurePrimaryHttpMessageHandler(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    return DdsNodeHttpFactory.BuildHandler(cfg.NodeBaseUrl);
});

builder.Services.AddSingleton<ICommandRunner, ProcessCommandRunner>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
