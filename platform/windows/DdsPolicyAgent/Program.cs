// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.State;

var builder = Host.CreateApplicationBuilder(args);

// Bind configuration
builder.Services.Configure<AgentConfig>(
    builder.Configuration.GetSection(AgentConfig.SectionName));

// Register the applied-state store (singleton — one file on disk).
builder.Services.AddSingleton<IAppliedStateStore>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    return new AppliedStateStore(cfg.StateDir);
});

// Register the HTTP client for dds-node.
builder.Services.AddHttpClient<IDdsNodeClient, DdsNodeClient>((sp, http) =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    http.BaseAddress = new Uri(cfg.NodeBaseUrl.TrimEnd('/') + "/");
    http.Timeout = TimeSpan.FromSeconds(10);
});

// Registry operations: real Win32 on Windows, no-op elsewhere.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IRegistryOperations, WindowsRegistryOperations>();
}
else
{
    // Non-Windows: inject a stub that logs. Useful for dev/testing
    // on macOS/Linux where Microsoft.Win32.Registry isn't available.
    builder.Services.AddSingleton<IRegistryOperations, InMemoryRegistryOperations>();
}

// Account operations: real Win32 on Windows, in-memory elsewhere.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IAccountOperations, WindowsAccountOperations>();
    builder.Services.AddSingleton<IPasswordPolicyOperations, WindowsPasswordPolicyOperations>();
}
else
{
    builder.Services.AddSingleton<IAccountOperations, InMemoryAccountOperations>();
    builder.Services.AddSingleton<IPasswordPolicyOperations, InMemoryPasswordPolicyOperations>();
}

// Register enforcers.
builder.Services.AddSingleton<RegistryEnforcer>();
builder.Services.AddSingleton<AccountEnforcer>();
builder.Services.AddSingleton<PasswordPolicyEnforcer>();
builder.Services.AddSingleton<SoftwareInstaller>();

// Register the background worker.
builder.Services.AddHostedService<Worker>();

// On Windows, run as a Windows Service when started by SCM.
// On other platforms this is a no-op (graceful fallback to console).
if (OperatingSystem.IsWindows())
{
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = "DdsPolicyAgent";
    });
}

var host = builder.Build();
host.Run();
