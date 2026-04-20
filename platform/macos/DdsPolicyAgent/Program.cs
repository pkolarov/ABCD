// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.MacOS;
using DDS.PolicyAgent.MacOS.Client;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.Runtime;
using DDS.PolicyAgent.MacOS.State;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<AgentConfig>(
    builder.Configuration.GetSection(AgentConfig.SectionName));

builder.Services.AddSingleton<IAppliedStateStore>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    return new AppliedStateStore(cfg.StateDir);
});

// **H-3 (security review)**: build the envelope verifier from the
// pinned node pubkey. Fail fast at startup if the pubkey is missing
// or malformed — a root agent must not run with an unauthenticated
// localhost channel.
builder.Services.AddSingleton<EnvelopeVerifier>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    if (string.IsNullOrWhiteSpace(cfg.PinnedNodePubkeyB64))
    {
        throw new InvalidOperationException(
            "DdsPolicyAgent:PinnedNodePubkeyB64 is not configured. "
            + "Pin the dds-node public key at install time (see H-3 in the security review).");
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

// **H-7 step-2b (security review)**: primary handler routes `unix:`
// URLs through a `SocketsHttpHandler` with a `ConnectCallback` that
// opens the named Unix domain socket, so the Rust node's UDS listener
// sees a concrete peer-cred-authenticated caller. TCP URLs keep the
// default handler. See `DdsNodeHttpFactory` for the dispatch rules.
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
builder.Services.AddHttpClient();

builder.Services.AddSingleton<ICommandRunner, ProcessCommandRunner>();
builder.Services.AddSingleton<IMacPreferenceOperations, HostMacPreferenceOperations>();
builder.Services.AddSingleton<IMacAccountOperations, HostMacAccountOperations>();
builder.Services.AddSingleton<ILaunchdOperations, HostLaunchdOperations>();
builder.Services.AddSingleton<IProfileOperations, HostProfileOperations>();

builder.Services.AddSingleton<PreferenceEnforcer>();
builder.Services.AddSingleton<MacAccountEnforcer>();
builder.Services.AddSingleton<LaunchdEnforcer>();
builder.Services.AddSingleton<ProfileEnforcer>();
builder.Services.AddSingleton<SoftwareInstaller>();

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
