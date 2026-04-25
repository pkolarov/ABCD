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
    private readonly RegistryEnforcer _registryEnforcer;
    private readonly AccountEnforcer _accountEnforcer;
    private readonly PasswordPolicyEnforcer _passwordPolicyEnforcer;
    private readonly SoftwareInstaller _softwareInstaller;

    // Accept concrete enforcer types so the DI container resolves them
    // directly and we can call reconciliation methods.
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
        // Collect desired managed items across all policies for reconciliation
        var desiredRegistryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredSoftware = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var globalMode = EnforcementMode.Enforce;

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

            var enforcement = p.Document.TryGetProperty("enforcement", out var e)
                ? ParseMode(e.GetString())
                : EnforcementMode.Enforce;
            if (enforcement == EnforcementMode.Audit)
                globalMode = EnforcementMode.Audit;

            // Always extract desired items for reconciliation, even if unchanged
            if (p.Document.TryGetProperty("windows", out var win)
                && win.ValueKind == JsonValueKind.Object)
            {
                ExtractDesiredItems(win, desiredRegistryKeys, desiredAccounts, desiredGroups);
            }

            if (!_stateStore.HasChanged(policyId, hash))
            {
                _log.LogDebug("Policy {Id} v{V} unchanged — skip", policyId, version);
                continue;
            }

            ApplyBundleResult apply;
            if (p.Document.TryGetProperty("windows", out var winApply)
                && winApply.ValueKind == JsonValueKind.Object)
            {
                apply = await DispatchWindowsBundle(winApply, enforcement, ct).ConfigureAwait(false);
            }
            else
            {
                apply = new ApplyBundleResult("skipped", [], null);
            }

            // B-3: report and record the actual outcome status, not a
            // hardcoded "ok". A failed enforcement must remain re-eligible
            // on the next poll so transient failures don't latch.
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

            // Track desired software for reconciliation
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

            // B-3: capture the real status from the installer so a
            // failed install is reported and isn't suppressed by
            // HasChanged on the next poll.
            var apply = ApplyBundleResult.FromOutcome(outcome);
            await ReportAsync(pkgId, version, apply, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(pkgId, version, hash, apply.Status, isSoftware: true);
        }

        // --- reconciliation pass ---
        await ReconcileAsync(
            desiredRegistryKeys, desiredAccounts, desiredGroups,
            desiredSoftware, globalMode, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Extract desired managed-item keys from a Windows policy bundle
    /// for reconciliation tracking.
    /// </summary>
    private static void ExtractDesiredItems(
        JsonElement win,
        HashSet<string> registryKeys,
        HashSet<string> accounts,
        HashSet<string> groups)
    {
        if (win.TryGetProperty("registry", out var reg) && reg.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in reg.EnumerateArray())
            {
                var action = item.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action == "Set")
                {
                    var key = RegistryEnforcer.ExtractManagedKey(item);
                    if (key is not null) registryKeys.Add(key);
                }
            }
        }

        if (win.TryGetProperty("local_accounts", out var acct) && acct.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in acct.EnumerateArray())
            {
                var key = AccountEnforcer.ExtractManagedKey(item);
                if (key is not null) accounts.Add(key);

                foreach (var g in AccountEnforcer.ExtractManagedGroups(item))
                    groups.Add(g);
            }
        }
    }

    /// <summary>
    /// Compare the current desired state with previously managed items.
    /// Remove stale items that are no longer in the policy.
    /// </summary>
    private async Task ReconcileAsync(
        HashSet<string> desiredRegistry,
        HashSet<string> desiredAccounts,
        HashSet<string> desiredGroups,
        HashSet<string> desiredSoftware,
        EnforcementMode mode,
        CancellationToken ct)
    {
        var reconcileChanges = new List<string>();

        // Registry reconciliation
        var prevRegistry = _stateStore.GetManagedItems("registry");
        var staleRegistry = new HashSet<string>(prevRegistry, StringComparer.OrdinalIgnoreCase);
        staleRegistry.ExceptWith(desiredRegistry);
        if (staleRegistry.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale registry entries to clean up", staleRegistry.Count);
            var changes = _registryEnforcer.ReconcileStaleItems(staleRegistry, mode);
            reconcileChanges.AddRange(changes);
        }
        _stateStore.SetManagedItems("registry", desiredRegistry);

        // Account reconciliation
        var prevAccounts = _stateStore.GetManagedItems("accounts");
        var staleAccounts = new HashSet<string>(prevAccounts, StringComparer.OrdinalIgnoreCase);
        staleAccounts.ExceptWith(desiredAccounts);
        if (staleAccounts.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale accounts to disable", staleAccounts.Count);
            var changes = _accountEnforcer.ReconcileStaleAccounts(staleAccounts, mode);
            reconcileChanges.AddRange(changes);
        }
        _stateStore.SetManagedItems("accounts", desiredAccounts);

        // Group membership reconciliation
        var prevGroups = _stateStore.GetManagedItems("account_groups");
        var staleGroups = new HashSet<string>(prevGroups, StringComparer.OrdinalIgnoreCase);
        staleGroups.ExceptWith(desiredGroups);
        if (staleGroups.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale group memberships to remove", staleGroups.Count);
            var changes = _accountEnforcer.ReconcileStaleGroups(staleGroups, mode);
            reconcileChanges.AddRange(changes);
        }
        _stateStore.SetManagedItems("account_groups", desiredGroups);

        // Software reconciliation
        var prevSoftware = _stateStore.GetManagedItems("software_managed");
        var staleSoftware = new HashSet<string>(prevSoftware, StringComparer.OrdinalIgnoreCase);
        staleSoftware.ExceptWith(desiredSoftware);
        if (staleSoftware.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale software packages to uninstall", staleSoftware.Count);
            var changes = _softwareInstaller.ReconcileStalePackages(staleSoftware, mode);
            reconcileChanges.AddRange(changes);
        }
        _stateStore.SetManagedItems("software_managed", desiredSoftware);

        if (reconcileChanges.Count > 0)
        {
            _log.LogInformation("Reconciliation complete: {Count} actions taken", reconcileChanges.Count);
            await ReportAsync(
                "_reconciliation", "1",
                new ApplyBundleResult("ok", reconcileChanges, null),
                ct).ConfigureAwait(false);
        }
    }

    private async Task<ApplyBundleResult> DispatchWindowsBundle(
        JsonElement win, EnforcementMode mode, CancellationToken ct)
    {
        var outcomes = new List<EnforcementOutcome>();

        if (win.TryGetProperty("registry", out var reg)
            && reg.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _registryEnforcer.ApplyAsync(reg, mode, ct).ConfigureAwait(false));
        }

        if (win.TryGetProperty("local_accounts", out var acct)
            && acct.ValueKind == JsonValueKind.Array)
        {
            outcomes.Add(await _accountEnforcer.ApplyAsync(acct, mode, ct).ConfigureAwait(false));
        }

        if (win.TryGetProperty("password_policy", out var pp)
            && pp.ValueKind == JsonValueKind.Object)
        {
            outcomes.Add(await _passwordPolicyEnforcer.ApplyAsync(pp, mode, ct).ConfigureAwait(false));
        }

        if (win.TryGetProperty("services", out var svc)
            && svc.ValueKind == JsonValueKind.Array)
        {
            // Services use the same RegistryEnforcer stub for now;
            // Phase D will split this to a ServiceEnforcer.
            _log.LogInformation("[DRY-RUN] Services: {Count} directives", svc.GetArrayLength());
            var serviceChanges = new List<string>();
            foreach (var item in svc.EnumerateArray())
            {
                var name = item.TryGetProperty("name", out var n) ? n.GetString() : "?";
                serviceChanges.Add($"service: {name}");
            }
            outcomes.Add(new EnforcementOutcome(EnforcementStatus.Ok, null, serviceChanges));
        }

        return ApplyBundleResult.Aggregate(outcomes);
    }

    private async Task ReportAsync(
        string targetId, string version, ApplyBundleResult apply, CancellationToken ct)
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
