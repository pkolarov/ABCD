// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.HostState;
using DDS.PolicyAgent.State;
using Microsoft.Extensions.Logging;

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

// **H-2 (security review)**: build the envelope verifier from the
// pinned node pubkey. Fail fast at startup if the pubkey is missing
// or malformed — a SYSTEM agent must not run with an unauthenticated
// localhost channel.
builder.Services.AddSingleton<EnvelopeVerifier>(sp =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>().Value;
    if (string.IsNullOrWhiteSpace(cfg.PinnedNodePubkeyB64))
    {
        throw new InvalidOperationException(
            "DdsPolicyAgent:PinnedNodePubkeyB64 is not configured. "
            + "Pin the dds-node public key at install time (see H-2 in the security review).");
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

// Register the HTTP client for dds-node.
// **H-7 step-2b (security review)**: primary handler routes `pipe:` URLs
// through a `SocketsHttpHandler` with a `ConnectCallback` that opens a
// `NamedPipeClientStream`, so the Rust node's pipe listener sees a
// concrete caller SID via `GetNamedPipeClientProcessId`. `unix:` is
// also supported for cross-platform dev builds. TCP URLs keep the
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

// Host JoinState probe: real probe on Windows, in-memory Workgroup
// elsewhere so the host build links cleanly on macOS/Linux dev boxes.
// Phase 1 wires the seam; the periodic-refresh timer + worker-side
// EffectiveMode override land in AD-04 (Phase 2).
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IJoinStateProbe>(sp =>
        new WindowsJoinStateProbe(
            sp.GetRequiredService<ILoggerFactory>().CreateLogger<WindowsJoinStateProbe>()));
}
else
{
    builder.Services.AddSingleton<IJoinStateProbe>(_ =>
        new InMemoryJoinStateProbe(JoinState.Workgroup));
}

// Software operations: real Win32 on Windows, in-memory elsewhere.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<ISoftwareOperations>(sp =>
    {
        var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient("software");
        // A-6 (security review): cap each package download so a hostile
        // or MITM'd publisher URL cannot fill the disk before the
        // SHA-256 mismatch is caught.
        var cfg = sp
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentConfig>>()
            .Value;
        return new WindowsSoftwareOperations(http, cfg.MaxPackageBytes);
    });
}
else
{
    builder.Services.AddSingleton<ISoftwareOperations, InMemorySoftwareOperations>();
}

// Service operations: real SCM on Windows, in-memory elsewhere.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IServiceOperations, WindowsServiceOperations>();
}
else
{
    builder.Services.AddSingleton<IServiceOperations, InMemoryServiceOperations>();
}

// SC-5 Phase B.2: Authenticode verifier for the staged installer
// signature gate. Real WinVerifyTrust on Windows; the stub on other
// platforms fails any directive that requires a signature so dev/test
// builds on macOS/Linux cannot accidentally short-circuit the gate.
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IAuthenticodeVerifier, WinTrustAuthenticodeVerifier>();
}
else
{
    builder.Services.AddSingleton<IAuthenticodeVerifier, StubAuthenticodeVerifier>();
}

// Register enforcers.
builder.Services.AddSingleton<RegistryEnforcer>();
builder.Services.AddSingleton<AccountEnforcer>();
builder.Services.AddSingleton<PasswordPolicyEnforcer>();
builder.Services.AddSingleton<SoftwareInstaller>();
builder.Services.AddSingleton<ServiceEnforcer>();

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
