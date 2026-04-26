// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using DDS.PolicyAgent.HostState;
using DDS.PolicyAgent.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent;

/// <summary>
/// Background worker that polls dds-node once a minute for
/// <c>WindowsPolicyDocument</c> and <c>SoftwareAssignment</c>
/// documents scoped to this device, then dispatches them through
/// the registered enforcers.
///
/// <para>
/// <b>AD-04 / AD-05 / AD-06 (AD coexistence Phase 2):</b> the
/// worker reads <see cref="IJoinStateProbe"/> at the top of each
/// poll cycle and routes every <see cref="EnforcementMode"/>
/// argument through <see cref="EffectiveMode"/>. On
/// <see cref="JoinState.AdJoined"/>, <see cref="JoinState.HybridJoined"/>,
/// or <see cref="JoinState.Unknown"/> the effective mode is forced
/// to <see cref="EnforcementMode.Audit"/> so DDS never mutates host
/// state on a directory-managed machine. On
/// <see cref="JoinState.EntraOnlyJoined"/> the worker short-circuits
/// to a heartbeat-only loop reporting <c>unsupported_entra</c>.
/// </para>
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly IJoinStateProbe _joinState;
    private readonly AgentConfig _config;
    private readonly ILogger<Worker> _log;
    private readonly RegistryEnforcer _registryEnforcer;
    private readonly AccountEnforcer _accountEnforcer;
    private readonly PasswordPolicyEnforcer _passwordPolicyEnforcer;
    private readonly SoftwareInstaller _softwareInstaller;

    /// <summary>
    /// JoinState observed at the previous poll cycle. Used to detect
    /// transitions and force a one-time audit re-pass for unchanged
    /// documents — otherwise a workgroup → AD transition would
    /// silently skip the audit pass that proves DDS stopped
    /// enforcing.
    /// </summary>
    private JoinState? _previousJoinState;

    // Accept concrete enforcer types so the DI container resolves them
    // directly and we can call reconciliation methods.
    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IJoinStateProbe joinState,
        IOptions<AgentConfig> config,
        ILogger<Worker> log,
        RegistryEnforcer registryEnforcer,
        AccountEnforcer accountEnforcer,
        PasswordPolicyEnforcer passwordPolicyEnforcer,
        SoftwareInstaller softwareInstaller)
    {
        _client = client;
        _stateStore = stateStore;
        _joinState = joinState;
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
                // AD-04/AD-06: re-probe join state every cycle so
                // workgroup → AD or workgroup → Entra transitions take
                // effect on the next poll, not at the next service
                // restart. The probe is cheap (cached in
                // WindowsJoinStateProbe) so this is essentially free.
                _joinState.Refresh();
                var hostState = _joinState.Detect();

                if (hostState == JoinState.EntraOnlyJoined)
                {
                    await EmitEntraHeartbeatAsync(stoppingToken).ConfigureAwait(false);
                }
                else
                {
                    await PollAndApplyAsync(hostState, stoppingToken).ConfigureAwait(false);
                }
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

    /// <summary>
    /// AD-04 effective-mode wrapper. Force <see cref="EnforcementMode.Audit"/>
    /// on AD/Hybrid/Unknown hosts so no enforcer ever writes through to
    /// directory-managed state. <see cref="JoinState.EntraOnlyJoined"/>
    /// never reaches this helper because <see cref="ExecuteAsync"/>
    /// short-circuits before <see cref="PollAndApplyAsync"/> runs.
    /// </summary>
    internal static EnforcementMode EffectiveMode(EnforcementMode requested, JoinState host)
        => host switch
        {
            JoinState.AdJoined or JoinState.HybridJoined or JoinState.Unknown
                => EnforcementMode.Audit,
            _ => requested,
        };

    /// <summary>
    /// AD-04/AD-07 reason that explains why the effective mode differs
    /// from the requested mode. Returns null when no override applied.
    /// </summary>
    internal static string? EffectiveModeReason(JoinState host)
        => host switch
        {
            JoinState.AdJoined or JoinState.HybridJoined => AppliedReason.AuditDueToAdCoexistence,
            JoinState.Unknown => AppliedReason.AuditDueToUnknownHostState,
            _ => null,
        };

    private async Task EmitEntraHeartbeatAsync(CancellationToken ct)
    {
        // AD-06: one heartbeat report per cycle, no enforcer dispatch,
        // no reconciliation. Operators see clear evidence that the
        // agent is alive and refusing on Entra-only hosts.
        var apply = new ApplyBundleResult("unsupported", [], null);
        _previousJoinState = JoinState.EntraOnlyJoined;
        await ReportAsync(
            "_host_state", "1", apply, AppliedReason.UnsupportedEntra, ct)
            .ConfigureAwait(false);
        _log.LogInformation(
            "Host is Entra-only joined — DDS policy enforcement is unsupported. Skipping poll.");
    }

    private async Task PollAndApplyAsync(JoinState hostState, CancellationToken ct)
    {
        var auditMode = EffectiveMode(EnforcementMode.Enforce, hostState) == EnforcementMode.Audit;
        var modeReason = EffectiveModeReason(hostState);
        var transitionDetected = _previousJoinState is not null
                                 && _previousJoinState.Value != hostState;
        if (transitionDetected)
        {
            _log.LogInformation(
                "JoinState transition detected: {Previous} -> {Current}",
                _previousJoinState!.Value, hostState);
        }

        // Collect desired managed items across all policies for reconciliation
        var desiredRegistryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var desiredSoftware = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

            var requestedEnforcement = p.Document.TryGetProperty("enforcement", out var e)
                ? ParseMode(e.GetString())
                : EnforcementMode.Enforce;
            var effective = EffectiveMode(requestedEnforcement, hostState);

            // Always extract desired items for reconciliation, even if unchanged
            if (p.Document.TryGetProperty("windows", out var win)
                && win.ValueKind == JsonValueKind.Object)
            {
                ExtractDesiredItems(win, desiredRegistryKeys, desiredAccounts, desiredGroups);
            }

            // AD-04: a transition since the last apply must force a one-shot
            // re-evaluation even when the content hash is unchanged, so the
            // audit log proves DDS reacted to the host-state change.
            var contentChanged = _stateStore.HasChanged(policyId, hash);
            var hostStateChanged = HostStateChangedSinceApply(policyId, isSoftware: false, hostState);
            if (!contentChanged && !hostStateChanged)
            {
                _log.LogDebug("Policy {Id} v{V} unchanged — skip", policyId, version);
                continue;
            }

            ApplyBundleResult apply;
            if (p.Document.TryGetProperty("windows", out var winApply)
                && winApply.ValueKind == JsonValueKind.Object)
            {
                apply = await DispatchWindowsBundle(winApply, effective, ct).ConfigureAwait(false);
            }
            else
            {
                apply = new ApplyBundleResult("skipped", [], null);
            }

            var reason = ResolveReason(modeReason, transitionDetected, hostStateChanged && !contentChanged);
            // B-3: report and record the actual outcome status, not a
            // hardcoded "ok". A failed enforcement must remain re-eligible
            // on the next poll so transient failures don't latch.
            await ReportAsync(policyId, version, apply, reason, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(
                policyId, version, hash, apply.Status, isSoftware: false, hostState);
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

            var contentChanged = _stateStore.HasChanged(pkgId, hash);
            var hostStateChanged = HostStateChangedSinceApply(pkgId, isSoftware: true, hostState);
            if (!contentChanged && !hostStateChanged)
            {
                _log.LogDebug("Software {Id} v{V} unchanged — skip", pkgId, version);
                continue;
            }

            // AD-05: software dispatch was previously hardcoded to
            // EnforcementMode.Enforce — wrap it through EffectiveMode so
            // AD/Hybrid/Unknown hosts also short-circuit to audit.
            var effectiveSoftware = EffectiveMode(EnforcementMode.Enforce, hostState);
            var outcome = await _softwareInstaller
                .ApplyAsync(s.Document, effectiveSoftware, ct)
                .ConfigureAwait(false);

            // B-3: capture the real status from the installer so a
            // failed install is reported and isn't suppressed by
            // HasChanged on the next poll.
            var apply = ApplyBundleResult.FromOutcome(outcome);
            var reason = ResolveReason(modeReason, transitionDetected, hostStateChanged && !contentChanged);
            await ReportAsync(pkgId, version, apply, reason, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(
                pkgId, version, hash, apply.Status, isSoftware: true, hostState);
        }

        // --- reconciliation pass ---
        await ReconcileAsync(
            desiredRegistryKeys, desiredAccounts, desiredGroups,
            desiredSoftware, hostState, auditMode, modeReason, ct).ConfigureAwait(false);

        _previousJoinState = hostState;
    }

    private bool HostStateChangedSinceApply(string targetId, bool isSoftware, JoinState current)
    {
        var prior = _stateStore.GetHostStateAtApply(targetId, isSoftware);
        // Never-applied or pre-AD-04 entry without a stamped host state:
        // HasChanged already covers the "never seen" case so we don't
        // need to force a second pass for that.
        if (prior is null) return false;
        return prior.Value != current;
    }

    private static string? ResolveReason(
        string? modeReason, bool transitionDetected, bool hostStateOnlyChange)
    {
        if (transitionDetected || hostStateOnlyChange)
        {
            return AppliedReason.Combine(
                modeReason ?? AppliedReason.HostStateTransitionDetected,
                AppliedReason.HostStateTransitionDetected);
        }
        return modeReason;
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
    /// In <paramref name="auditMode"/> the inventory is updated but
    /// stale items are kept and marked frozen rather than removed —
    /// AD/Hybrid/Unknown hosts may now own those keys/accounts/MSIs and
    /// silent unwind could damage the host.
    /// </summary>
    private async Task ReconcileAsync(
        HashSet<string> desiredRegistry,
        HashSet<string> desiredAccounts,
        HashSet<string> desiredGroups,
        HashSet<string> desiredSoftware,
        JoinState hostState,
        bool auditMode,
        string? modeReason,
        CancellationToken ct)
    {
        var reconcileChanges = new List<string>();
        var effectiveMode = auditMode ? EnforcementMode.Audit : EnforcementMode.Enforce;

        // Registry reconciliation
        var prevRegistry = _stateStore.GetManagedItems("registry");
        var staleRegistry = new HashSet<string>(prevRegistry, StringComparer.OrdinalIgnoreCase);
        staleRegistry.ExceptWith(desiredRegistry);
        if (staleRegistry.Count > 0 && !auditMode)
        {
            // AD-05: only invoke the destructive reconciler in workgroup
            // mode. Audit mode logs the would-be cleanup via the record
            // store's audit_frozen marker and skips the write.
            _log.LogInformation("Reconciliation: {Count} stale registry entries to clean up", staleRegistry.Count);
            var changes = _registryEnforcer.ReconcileStaleItems(staleRegistry, effectiveMode);
            reconcileChanges.AddRange(changes);
        }
        else if (staleRegistry.Count > 0)
        {
            _log.LogInformation(
                "Reconciliation (audit-frozen): {Count} stale registry entries left in place ({Reason})",
                staleRegistry.Count, modeReason);
        }
        _stateStore.RecordManagedItems("registry", desiredRegistry, hostState, auditMode, modeReason);

        // Account reconciliation
        var prevAccounts = _stateStore.GetManagedItems("accounts");
        var staleAccounts = new HashSet<string>(prevAccounts, StringComparer.OrdinalIgnoreCase);
        staleAccounts.ExceptWith(desiredAccounts);
        if (staleAccounts.Count > 0 && !auditMode)
        {
            _log.LogInformation("Reconciliation: {Count} stale accounts to disable", staleAccounts.Count);
            var changes = _accountEnforcer.ReconcileStaleAccounts(staleAccounts, effectiveMode);
            reconcileChanges.AddRange(changes);
        }
        else if (staleAccounts.Count > 0)
        {
            _log.LogInformation(
                "Reconciliation (audit-frozen): {Count} stale accounts left in place ({Reason})",
                staleAccounts.Count, modeReason);
        }
        _stateStore.RecordManagedItems("accounts", desiredAccounts, hostState, auditMode, modeReason);

        // Group membership reconciliation
        var prevGroups = _stateStore.GetManagedItems("account_groups");
        var staleGroups = new HashSet<string>(prevGroups, StringComparer.OrdinalIgnoreCase);
        staleGroups.ExceptWith(desiredGroups);
        if (staleGroups.Count > 0 && !auditMode)
        {
            _log.LogInformation("Reconciliation: {Count} stale group memberships to remove", staleGroups.Count);
            var changes = _accountEnforcer.ReconcileStaleGroups(staleGroups, effectiveMode);
            reconcileChanges.AddRange(changes);
        }
        else if (staleGroups.Count > 0)
        {
            _log.LogInformation(
                "Reconciliation (audit-frozen): {Count} stale group memberships left in place ({Reason})",
                staleGroups.Count, modeReason);
        }
        _stateStore.RecordManagedItems("account_groups", desiredGroups, hostState, auditMode, modeReason);

        // Software reconciliation
        var prevSoftware = _stateStore.GetManagedItems("software_managed");
        var staleSoftware = new HashSet<string>(prevSoftware, StringComparer.OrdinalIgnoreCase);
        staleSoftware.ExceptWith(desiredSoftware);
        if (staleSoftware.Count > 0 && !auditMode)
        {
            _log.LogInformation("Reconciliation: {Count} stale software packages to uninstall", staleSoftware.Count);
            var changes = _softwareInstaller.ReconcileStalePackages(staleSoftware, effectiveMode);
            reconcileChanges.AddRange(changes);
        }
        else if (staleSoftware.Count > 0)
        {
            _log.LogInformation(
                "Reconciliation (audit-frozen): {Count} stale software packages left in place ({Reason})",
                staleSoftware.Count, modeReason);
        }
        _stateStore.RecordManagedItems("software_managed", desiredSoftware, hostState, auditMode, modeReason);

        if (reconcileChanges.Count > 0)
        {
            _log.LogInformation("Reconciliation complete: {Count} actions taken", reconcileChanges.Count);
            await ReportAsync(
                "_reconciliation", "1",
                new ApplyBundleResult("ok", reconcileChanges, null),
                modeReason, ct).ConfigureAwait(false);
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
        string targetId, string version, ApplyBundleResult apply,
        string? reason, CancellationToken ct)
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
                Reason = reason,
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
