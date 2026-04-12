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

builder.Services.AddHttpClient<IDdsNodeClient, DdsNodeClient>((sp, http) =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    http.BaseAddress = new Uri(cfg.NodeBaseUrl.TrimEnd('/') + "/");
    http.Timeout = TimeSpan.FromSeconds(10);
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
