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
    private readonly PreferenceEnforcer _preferenceEnforcer;
    private readonly MacAccountEnforcer _accountEnforcer;
    private readonly LaunchdEnforcer _launchdEnforcer;
    private readonly ProfileEnforcer _profileEnforcer;
    private readonly SoftwareInstaller _softwareInstaller;

    // Accept concrete enforcer types so the DI container resolves them
    // directly and we can call reconciliation methods.
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
        // Collect desired managed items across all policies for reconciliation.
        var desiredPreferences = new HashSet<string>(StringComparer.Ordinal);
        var desiredAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredLaunchd = new HashSet<string>(StringComparer.Ordinal);
        var desiredProfiles = new HashSet<string>(StringComparer.Ordinal);
        var desiredSoftware = new HashSet<string>(StringComparer.Ordinal);
        var globalMode = EnforcementMode.Enforce;

        // --- policies ---
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

            var enforcement = p.Document.TryGetProperty("enforcement", out var e)
                ? ParseMode(e.GetString())
                : EnforcementMode.Enforce;
            if (enforcement == EnforcementMode.Audit)
                globalMode = EnforcementMode.Audit;

            // Always extract desired items for reconciliation, even if unchanged.
            if (p.Document.TryGetProperty("macos", out var mac)
                && mac.ValueKind == JsonValueKind.Object)
            {
                ExtractDesiredItems(mac, desiredPreferences, desiredAccounts, desiredGroups,
                    desiredLaunchd, desiredProfiles);
            }

            if (!_stateStore.HasChanged(policyId, hash))
            {
                _log.LogDebug("Policy {Id} v{V} unchanged — skip", policyId, version);
                continue;
            }

            var apply = await DispatchMacOsBundle(p.Document, enforcement, ct).ConfigureAwait(false);
            await ReportAsync(policyId, version, apply, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, apply.Status, isSoftware: false);
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

            // Track desired software for reconciliation.
            var managedKey = SoftwareInstaller.ExtractManagedKey(s.Document);
            if (managedKey is not null)
                desiredSoftware.Add(managedKey);

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

        // --- reconciliation pass ---
        await ReconcileAsync(
            desiredPreferences, desiredAccounts, desiredGroups,
            desiredLaunchd, desiredProfiles, desiredSoftware,
            globalMode, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Extract desired managed-item keys from a macOS policy bundle
    /// for reconciliation tracking.
    /// </summary>
    private static void ExtractDesiredItems(
        JsonElement mac,
        HashSet<string> preferences,
        HashSet<string> accounts,
        HashSet<string> groups,
        HashSet<string> launchd,
        HashSet<string> profiles)
    {
        if (mac.TryGetProperty("preferences", out var prefs) && prefs.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in prefs.EnumerateArray())
            {
                var key = PreferenceEnforcer.ExtractManagedKey(item);
                if (key is not null) preferences.Add(key);
            }
        }

        if (mac.TryGetProperty("local_accounts", out var acct) && acct.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in acct.EnumerateArray())
            {
                var key = MacAccountEnforcer.ExtractManagedKey(item);
                if (key is not null) accounts.Add(key);

                foreach (var g in MacAccountEnforcer.ExtractManagedGroups(item))
                    groups.Add(g);
            }
        }

        if (mac.TryGetProperty("launchd", out var jobs) && jobs.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in jobs.EnumerateArray())
            {
                var key = LaunchdEnforcer.ExtractManagedKey(item);
                if (key is not null) launchd.Add(key);
            }
        }

        if (mac.TryGetProperty("profiles", out var prof) && prof.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in prof.EnumerateArray())
            {
                var key = ProfileEnforcer.ExtractManagedKey(item);
                if (key is not null) profiles.Add(key);
            }
        }
    }

    /// <summary>
    /// Compare the current desired state with previously managed items.
    /// Remove stale items that are no longer in the policy.
    /// </summary>
    private async Task ReconcileAsync(
        HashSet<string> desiredPreferences,
        HashSet<string> desiredAccounts,
        HashSet<string> desiredGroups,
        HashSet<string> desiredLaunchd,
        HashSet<string> desiredProfiles,
        HashSet<string> desiredSoftware,
        EnforcementMode mode,
        CancellationToken ct)
    {
        var reconcileChanges = new List<string>();

        // Preferences reconciliation
        var prevPreferences = _stateStore.GetManagedItems("preferences");
        var stalePreferences = new HashSet<string>(prevPreferences, StringComparer.Ordinal);
        stalePreferences.ExceptWith(desiredPreferences);
        if (stalePreferences.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale preference values to clean up", stalePreferences.Count);
            reconcileChanges.AddRange(_preferenceEnforcer.ReconcileStaleItems(stalePreferences, mode));
        }
        _stateStore.SetManagedItems("preferences", desiredPreferences);

        // Account reconciliation
        var prevAccounts = _stateStore.GetManagedItems("accounts");
        var staleAccounts = new HashSet<string>(prevAccounts, StringComparer.OrdinalIgnoreCase);
        staleAccounts.ExceptWith(desiredAccounts);
        if (staleAccounts.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale accounts to disable", staleAccounts.Count);
            reconcileChanges.AddRange(_accountEnforcer.ReconcileStaleAccounts(staleAccounts, mode));
        }
        _stateStore.SetManagedItems("accounts", desiredAccounts);

        // Group membership reconciliation
        var prevGroups = _stateStore.GetManagedItems("account_groups");
        var staleGroups = new HashSet<string>(prevGroups, StringComparer.OrdinalIgnoreCase);
        staleGroups.ExceptWith(desiredGroups);
        if (staleGroups.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale group memberships to remove", staleGroups.Count);
            reconcileChanges.AddRange(_accountEnforcer.ReconcileStaleGroups(staleGroups, mode));
        }
        _stateStore.SetManagedItems("account_groups", desiredGroups);

        // Launchd reconciliation
        var prevLaunchd = _stateStore.GetManagedItems("launchd");
        var staleLaunchd = new HashSet<string>(prevLaunchd, StringComparer.Ordinal);
        staleLaunchd.ExceptWith(desiredLaunchd);
        if (staleLaunchd.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale launchd jobs to unload", staleLaunchd.Count);
            reconcileChanges.AddRange(_launchdEnforcer.ReconcileStaleItems(staleLaunchd, mode));
        }
        _stateStore.SetManagedItems("launchd", desiredLaunchd);

        // Profile reconciliation
        var prevProfiles = _stateStore.GetManagedItems("profiles");
        var staleProfiles = new HashSet<string>(prevProfiles, StringComparer.Ordinal);
        staleProfiles.ExceptWith(desiredProfiles);
        if (staleProfiles.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale profiles to remove", staleProfiles.Count);
            reconcileChanges.AddRange(_profileEnforcer.ReconcileStaleProfiles(staleProfiles, mode));
        }
        _stateStore.SetManagedItems("profiles", desiredProfiles);

        // Software reconciliation
        var prevSoftware = _stateStore.GetManagedItems("software_managed");
        var staleSoftware = new HashSet<string>(prevSoftware, StringComparer.Ordinal);
        staleSoftware.ExceptWith(desiredSoftware);
        if (staleSoftware.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale software packages (manual uninstall required)", staleSoftware.Count);
            reconcileChanges.AddRange(_softwareInstaller.ReconcileStalePackages(staleSoftware, mode));
        }
        _stateStore.SetManagedItems("software_managed", desiredSoftware);

        if (reconcileChanges.Count > 0)
        {
            _log.LogInformation("Reconciliation complete: {Count} actions taken", reconcileChanges.Count);
            await ReportAsync("_reconciliation", "1",
                new ApplyBundleResult("ok", reconcileChanges, null), ct).ConfigureAwait(false);
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
