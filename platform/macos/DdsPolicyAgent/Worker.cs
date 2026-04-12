// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.MacOS.Client;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS;

/// <summary>
/// Background worker that polls <c>dds-node</c> for macOS policy and
/// software assignments scoped to this device, dispatches them through
/// the local enforcers, and reports the applied outcome back to the
/// node.
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly AgentConfig _config;
    private readonly ILogger<Worker> _log;
    private readonly IEnforcer _preferenceEnforcer;
    private readonly IEnforcer _accountEnforcer;
    private readonly IEnforcer _launchdEnforcer;
    private readonly IEnforcer _profileEnforcer;
    private readonly IEnforcer _softwareInstaller;

    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IOptions<AgentConfig> config,
        ILogger<Worker> log,
        PreferenceEnforcer preferenceEnforcer,
        MacAccountEnforcer accountEnforcer,
        LaunchdEnforcer launchdEnforcer,
        ProfileEnforcer profileEnforcer,
        SoftwareInstaller softwareInstaller)
    {
        _client = client;
        _stateStore = stateStore;
        _config = config.Value;
        _log = log;
        _preferenceEnforcer = preferenceEnforcer;
        _accountEnforcer = accountEnforcer;
        _launchdEnforcer = launchdEnforcer;
        _profileEnforcer = profileEnforcer;
        _softwareInstaller = softwareInstaller;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_config.DeviceUrn))
        {
            _log.LogError("DeviceUrn is not configured — cannot start macOS policy agent");
            return;
        }

        _log.LogInformation(
            "DDS macOS Policy Agent started. device={DeviceUrn} poll={Interval}s node={NodeUrl}",
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

        _log.LogInformation("DDS macOS Policy Agent stopping");
    }

    private async Task PollAndApplyAsync(CancellationToken ct)
    {
        var policies = await _client
            .GetPoliciesAsync(_config.DeviceUrn, ct)
            .ConfigureAwait(false);
        _log.LogDebug("Received {Count} applicable macOS policies", policies.Count);

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

            var apply = await DispatchMacOsBundle(p.Document, enforcement, ct).ConfigureAwait(false);
            await ReportAsync(policyId, version, apply, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, apply.Status, isSoftware: false);
        }

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
            var apply = ApplyBundleResult.FromOutcome(outcome);

            await ReportAsync(pkgId, version, apply, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(pkgId, version, hash, apply.Status, isSoftware: true);
        }
    }

    private async Task<ApplyBundleResult> DispatchMacOsBundle(
        JsonElement doc, EnforcementMode mode, CancellationToken ct)
    {
        if (!doc.TryGetProperty("macos", out var mac)
            || mac.ValueKind != JsonValueKind.Object)
        {
            return new ApplyBundleResult(
                "skipped",
                ["[NO-OP] document has no macos bundle"],
                null);
        }

        var outcomes = new List<EnforcementOutcome>();

        if (mac.TryGetProperty("preferences", out var prefs)
            && prefs.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _preferenceEnforcer.ApplyAsync(prefs, mode, ct).ConfigureAwait(false));
        }

        if (mac.TryGetProperty("local_accounts", out var accounts)
            && accounts.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _accountEnforcer.ApplyAsync(accounts, mode, ct).ConfigureAwait(false));
        }

        if (mac.TryGetProperty("launchd", out var launchd)
            && launchd.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _launchdEnforcer.ApplyAsync(launchd, mode, ct).ConfigureAwait(false));
        }

        if (mac.TryGetProperty("profiles", out var profiles)
            && profiles.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _profileEnforcer.ApplyAsync(profiles, mode, ct).ConfigureAwait(false));
        }

        return ApplyBundleResult.Aggregate(outcomes);
    }

    private async Task ReportAsync(
        string targetId,
        string version,
        ApplyBundleResult apply,
        CancellationToken ct)
    {
        try
        {
            await _client.ReportAppliedAsync(new AppliedReport
            {
                DeviceUrn = _config.DeviceUrn,
                TargetId = targetId,
                Version = version,
                Status = apply.Status,
                Directives = apply.Directives,
                Error = apply.Error,
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

internal sealed record ApplyBundleResult(
    string Status,
    List<string> Directives,
    string? Error)
{
    public static ApplyBundleResult FromOutcome(EnforcementOutcome outcome)
    {
        var status = outcome.Status switch
        {
            EnforcementStatus.Ok => "ok",
            EnforcementStatus.Failed => "failed",
            _ => "skipped",
        };

        return new ApplyBundleResult(
            status,
            outcome.Changes?.ToList() ?? [],
            outcome.Error);
    }

    public static ApplyBundleResult Aggregate(IEnumerable<EnforcementOutcome> outcomes)
    {
        var materialized = outcomes.ToList();
        if (materialized.Count == 0)
            return new ApplyBundleResult("skipped", [], null);

        var directives = materialized
            .Where(o => o.Changes is not null)
            .SelectMany(o => o.Changes!)
            .ToList();

        var firstError = materialized
            .Select(o => o.Error)
            .FirstOrDefault(e => !string.IsNullOrWhiteSpace(e));

        var status = "ok";
        if (materialized.Any(o => o.Status == EnforcementStatus.Failed))
            status = "failed";
        else if (materialized.All(o => o.Status == EnforcementStatus.Skipped))
            status = "skipped";

        return new ApplyBundleResult(status, directives, firstError);
    }
}
