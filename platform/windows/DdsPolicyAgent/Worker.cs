// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent;

/// <summary>
/// Background worker that polls dds-node once a minute for
/// <c>WindowsPolicyDocument</c> and <c>SoftwareAssignment</c>
/// documents scoped to this device, then dispatches them through
/// the registered enforcers.
///
/// Phase C ships all enforcers as log-only stubs — the worker loop
/// is fully wired but no Win32 side-effects happen.
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly AgentConfig _config;
    private readonly ILogger<Worker> _log;
    private readonly IEnforcer _registryEnforcer;
    private readonly IEnforcer _accountEnforcer;
    private readonly IEnforcer _passwordPolicyEnforcer;
    private readonly IEnforcer _softwareInstaller;

    // Accept concrete enforcer types so the DI container resolves them
    // directly. The IEnforcer fields allow the dispatch loop to call
    // them uniformly.
    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IOptions<AgentConfig> config,
        ILogger<Worker> log,
        RegistryEnforcer registryEnforcer,
        AccountEnforcer accountEnforcer,
        PasswordPolicyEnforcer passwordPolicyEnforcer,
        SoftwareInstaller softwareInstaller)
    {
        _client = client;
        _stateStore = stateStore;
        _config = config.Value;
        _log = log;
        _registryEnforcer = registryEnforcer;
        _accountEnforcer = accountEnforcer;
        _passwordPolicyEnforcer = passwordPolicyEnforcer;
        _softwareInstaller = softwareInstaller;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_config.DeviceUrn))
        {
            _log.LogError("DeviceUrn is not configured — cannot start policy agent");
            return;
        }

        _log.LogInformation(
            "DDS Policy Agent started. device={DeviceUrn} poll={Interval}s node={NodeUrl}",
            _config.DeviceUrn, _config.PollIntervalSeconds, _config.NodeBaseUrl);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollAndApplyAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Poll cycle failed — will retry next interval");
            }

            await Task.Delay(
                TimeSpan.FromSeconds(_config.PollIntervalSeconds),
                stoppingToken).ConfigureAwait(false);
        }

        _log.LogInformation("DDS Policy Agent stopping");
    }

    private async Task PollAndApplyAsync(CancellationToken ct)
    {
        // --- policies ---
        var policies = await _client
            .GetPoliciesAsync(_config.DeviceUrn, ct)
            .ConfigureAwait(false);
        _log.LogDebug("Received {Count} applicable policies", policies.Count);

        foreach (var p in policies)
        {
            var hash = ContentHash(p.Document);
            var policyId = p.Document.TryGetProperty("policy_id", out var id)
                ? id.GetString() ?? p.Jti
                : p.Jti;
            var version = p.Document.TryGetProperty("version", out var v)
                ? v.ToString()
                : "0";

            if (!_stateStore.HasChanged(policyId, hash))
            {
                _log.LogDebug("Policy {Id} v{V} unchanged — skip", policyId, version);
                continue;
            }

            var enforcement = p.Document.TryGetProperty("enforcement", out var e)
                ? ParseMode(e.GetString())
                : EnforcementMode.Enforce;

            var directives = new List<string>();

            // Typed bundle
            if (p.Document.TryGetProperty("windows", out var win)
                && win.ValueKind == JsonValueKind.Object)
            {
                directives.AddRange(
                    await DispatchWindowsBundle(win, enforcement, ct).ConfigureAwait(false));
            }

            // Report back
            await ReportAsync(policyId, version, directives, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, "ok", isSoftware: false);
        }

        // --- software ---
        var software = await _client
            .GetSoftwareAsync(_config.DeviceUrn, ct)
            .ConfigureAwait(false);
        _log.LogDebug("Received {Count} applicable software assignments", software.Count);

        foreach (var s in software)
        {
            var hash = ContentHash(s.Document);
            var pkgId = s.Document.TryGetProperty("package_id", out var id)
                ? id.GetString() ?? s.Jti
                : s.Jti;
            var version = s.Document.TryGetProperty("version", out var v)
                ? v.GetString() ?? "0"
                : "0";

            if (!_stateStore.HasChanged(pkgId, hash))
            {
                _log.LogDebug("Software {Id} v{V} unchanged — skip", pkgId, version);
                continue;
            }

            var outcome = await _softwareInstaller
                .ApplyAsync(s.Document, EnforcementMode.Enforce, ct)
                .ConfigureAwait(false);

            var directives = outcome.Changes?.ToList() ?? [];
            await ReportAsync(pkgId, version, directives, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(pkgId, version, hash, "ok", isSoftware: true);
        }
    }

    private async Task<List<string>> DispatchWindowsBundle(
        JsonElement win, EnforcementMode mode, CancellationToken ct)
    {
        var directives = new List<string>();

        if (win.TryGetProperty("registry", out var reg)
            && reg.ValueKind == JsonValueKind.Array)
        {
            var r = await _registryEnforcer.ApplyAsync(reg, mode, ct).ConfigureAwait(false);
            if (r.Changes is not null) directives.AddRange(r.Changes);
        }

        if (win.TryGetProperty("local_accounts", out var acct)
            && acct.ValueKind == JsonValueKind.Array)
        {
            var r = await _accountEnforcer.ApplyAsync(acct, mode, ct).ConfigureAwait(false);
            if (r.Changes is not null) directives.AddRange(r.Changes);
        }

        if (win.TryGetProperty("password_policy", out var pp)
            && pp.ValueKind == JsonValueKind.Object)
        {
            var r = await _passwordPolicyEnforcer.ApplyAsync(pp, mode, ct).ConfigureAwait(false);
            if (r.Changes is not null) directives.AddRange(r.Changes);
        }

        if (win.TryGetProperty("services", out var svc)
            && svc.ValueKind == JsonValueKind.Array)
        {
            // Services use the same RegistryEnforcer stub for now;
            // Phase D will split this to a ServiceEnforcer.
            _log.LogInformation("[DRY-RUN] Services: {Count} directives", svc.GetArrayLength());
            foreach (var item in svc.EnumerateArray())
            {
                var name = item.TryGetProperty("name", out var n) ? n.GetString() : "?";
                directives.Add($"service: {name}");
            }
        }

        return directives;
    }

    private async Task ReportAsync(
        string targetId, string version, List<string> directives, CancellationToken ct)
    {
        try
        {
            await _client.ReportAppliedAsync(new AppliedReport
            {
                DeviceUrn = _config.DeviceUrn,
                TargetId = targetId,
                Version = version,
                Status = "ok",
                Directives = directives,
                AppliedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to report applied status for {Target}", targetId);
        }
    }

    private static EnforcementMode ParseMode(string? s) => s switch
    {
        "Audit" => EnforcementMode.Audit,
        "Enforce" => EnforcementMode.Enforce,
        _ => EnforcementMode.Enforce,
    };

    public static string ContentHash(JsonElement doc)
    {
        var raw = doc.GetRawText();
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }
}
