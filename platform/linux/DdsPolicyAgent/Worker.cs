// SPDX-License-Identifier: MIT OR Apache-2.0
// This worker runs only on Linux; suppress CA1416 for Linux-only enforcer calls.
#pragma warning disable CA1416

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Client;
using DDS.PolicyAgent.Linux.Config;
using DDS.PolicyAgent.Linux.Enforcers;
using DDS.PolicyAgent.Linux.Runtime;
using DDS.PolicyAgent.Linux.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.Linux;

public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly AgentConfig _config;
    private readonly ICommandRunner _runner;
    private readonly ILogger<Worker> _log;

    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IOptions<AgentConfig> config,
        ICommandRunner runner,
        ILogger<Worker> log)
    {
        _client = client;
        _stateStore = stateStore;
        _config = config.Value;
        _runner = runner;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_config.DeviceUrn))
        {
            _log.LogError("DeviceUrn is not configured; cannot start Linux policy agent");
            return;
        }

        if (string.IsNullOrWhiteSpace(_config.PinnedNodePubkeyB64))
        {
            _log.LogError("PinnedNodePubkeyB64 is not configured; cannot start Linux policy agent");
            return;
        }

        _log.LogInformation(
            "DDS Linux Policy Agent started. device={DeviceUrn} poll={Interval}s node={NodeUrl} audit={Audit}",
            _config.DeviceUrn, _config.PollIntervalSeconds, _config.NodeBaseUrl, _config.AuditOnly);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Poll cycle failed; will retry next interval");
            }

            await Task.Delay(
                TimeSpan.FromSeconds(_config.PollIntervalSeconds),
                stoppingToken).ConfigureAwait(false);
        }
    }

    internal async Task PollOnceAsync(CancellationToken ct)
    {
        var policies = await _client
            .GetPoliciesAsync(_config.DeviceUrn, ct)
            .ConfigureAwait(false);
        _log.LogDebug("Received {Count} applicable Linux policies", policies.Count);

        // Build managed sets from current applied state for safe-delete guards.
        var state = _stateStore.Load();
        var managedUsernames = new HashSet<string>(
            state.ManagedUsernames, StringComparer.Ordinal);
        var managedPaths = new HashSet<string>(
            state.ManagedPaths, StringComparer.Ordinal);
        var managedPackages = new HashSet<string>(
            state.ManagedPackages, StringComparer.Ordinal);

        // Desired sets: populated from ALL current policies (including unchanged ones)
        // so the reconciliation pass at the end can detect items no longer in any policy.
        var desiredUsernames          = new HashSet<string>(StringComparer.Ordinal);
        var desiredPaths              = new HashSet<string>(StringComparer.Ordinal);
        var desiredPackages           = new HashSet<string>(StringComparer.Ordinal);
        var desiredSysctlKeys         = new HashSet<string>(StringComparer.Ordinal);
        var desiredSudoersFilenames   = new HashSet<string>(StringComparer.Ordinal);
        var desiredSystemdDropinKeys  = new HashSet<string>(StringComparer.Ordinal);
        var hasSshPolicy              = false;

        var userEnforcer    = new UserEnforcer   (_runner, _config.AuditOnly, _log);
        var sudoersEnforcer = new SudoersEnforcer(_runner, _config.AuditOnly, _log);
        var fileEnforcer    = new FileEnforcer   (_runner, _config.AuditOnly, _log);
        var systemdEnforcer = new SystemdEnforcer(_runner, _config.AuditOnly, _log);
        var pkgEnforcer     = new PackageEnforcer(_runner, _config.AuditOnly, _log);
        var sysctlEnforcer  = new SysctlEnforcer (_runner, _config.AuditOnly, _log);
        var sshdEnforcer    = new SshdEnforcer   (_runner, _config.AuditOnly, _log);

        foreach (var p in policies)
        {
            var hash = ContentHash(p.Document);
            var policyId = p.Document.TryGetProperty("policy_id", out var id)
                ? id.GetString() ?? p.Jti
                : p.Jti;
            var version = p.Document.TryGetProperty("version", out var v)
                ? v.ToString()
                : "0";

            var hasLinuxObject = p.Document.TryGetProperty("linux", out var linux)
                && linux.ValueKind == JsonValueKind.Object;

            // Always collect desired items for reconciliation, even on unchanged policies.
            if (hasLinuxObject)
            {
                ExtractDesiredItems(linux, desiredUsernames, desiredPaths, desiredPackages,
                                    desiredSysctlKeys, desiredSudoersFilenames,
                                    desiredSystemdDropinKeys);
                if (linux.TryGetProperty("ssh", out var sshProp)
                    && sshProp.ValueKind == JsonValueKind.Object)
                    hasSshPolicy = true;
            }

            if (!_stateStore.HasChanged(policyId, hash))
            {
                _log.LogDebug("Policy {Id} v{Version} unchanged; skip", policyId, version);
                continue;
            }

            if (!hasLinuxObject)
            {
                var skipReport = new AppliedReport
                {
                    DeviceUrn  = _config.DeviceUrn,
                    TargetId   = policyId,
                    Version    = version,
                    Status     = "skipped",
                    Kind       = AppliedKind.Policy,
                    Directives = [],
                    AppliedAt  = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                };
                await _client.ReportAppliedAsync(skipReport, ct).ConfigureAwait(false);
                _stateStore.RecordApplied(policyId, version, hash, "skipped");
                continue;
            }

            var allDirectives = new List<string>();
            string? errorMsg  = null;

            try
            {
                allDirectives.AddRange(await ApplyLinuxSectionAsync(
                    linux, policyId, version,
                    userEnforcer, sudoersEnforcer, fileEnforcer, systemdEnforcer, pkgEnforcer,
                    sysctlEnforcer, sshdEnforcer,
                    managedUsernames, managedPaths, managedPackages,
                    ct).ConfigureAwait(false));
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
                _log.LogError(ex, "Policy {Id} enforcer threw; recording error", policyId);
            }

            if (errorMsg is null)
                RecordManagedResources(allDirectives);

            var status = errorMsg is null ? "ok" : "error";
            var report = new AppliedReport
            {
                DeviceUrn  = _config.DeviceUrn,
                TargetId   = policyId,
                Version    = version,
                Status     = status,
                Kind       = AppliedKind.Policy,
                Directives = allDirectives,
                Error      = errorMsg,
                AppliedAt  = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await _client.ReportAppliedAsync(report, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, status);
        }

        // Reconciliation pass: disable stale users, delete stale files, remove stale packages,
        // remove stale sysctl keys, remove stale sudoers drop-ins, remove stale systemd drop-ins,
        // and remove the sshd drop-in if no policy declares ssh.
        await ReconcileLinuxAsync(
            desiredUsernames, desiredPaths, desiredPackages, desiredSysctlKeys,
            desiredSudoersFilenames, desiredSystemdDropinKeys, hasSshPolicy,
            userEnforcer, fileEnforcer, pkgEnforcer, sysctlEnforcer, sudoersEnforcer,
            systemdEnforcer, sshdEnforcer,
            ct).ConfigureAwait(false);
    }

    /// Extracts the set of DDS-managed resource keys declared in a linux policy section.
    /// Used to build the desired-state sets for reconciliation.
    private static void ExtractDesiredItems(
        JsonElement linux,
        HashSet<string> usernames,
        HashSet<string> paths,
        HashSet<string> packages,
        HashSet<string> sysctlKeys,
        HashSet<string> sudoersFilenames,
        HashSet<string> systemdDropinKeys)
    {
        if (linux.TryGetProperty("local_users", out var users) && users.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in users.EnumerateArray())
            {
                var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action == "Create" || action == "Modify" || action == "Enable" || action == "Disable")
                {
                    var username = d.TryGetProperty("username", out var u) ? u.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(username))
                        usernames.Add(username);
                }
            }
        }

        if (linux.TryGetProperty("files", out var files) && files.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in files.EnumerateArray())
            {
                var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action == "Set" || action == "EnsureDir")
                {
                    var path = d.TryGetProperty("path", out var p) ? p.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(path))
                        paths.Add(path);
                }
            }
        }

        if (linux.TryGetProperty("packages", out var pkgs) && pkgs.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in pkgs.EnumerateArray())
            {
                var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action == "Install")
                {
                    var name = d.TryGetProperty("name", out var n) ? n.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(name))
                        packages.Add(name);
                }
            }
        }

        if (linux.TryGetProperty("sysctl", out var sysctl) && sysctl.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in sysctl.EnumerateArray())
            {
                var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action == "Set")
                {
                    var key = d.TryGetProperty("key", out var k) ? k.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(key))
                        sysctlKeys.Add(key);
                }
            }
        }

        if (linux.TryGetProperty("sudoers", out var sudoers) && sudoers.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in sudoers.EnumerateArray())
            {
                // A directive with non-empty content declares ownership of that drop-in filename.
                var filename = d.TryGetProperty("filename", out var fn) ? fn.GetString() : null;
                var content  = d.TryGetProperty("content",  out var co) ? co.GetString() : null;
                if (!string.IsNullOrWhiteSpace(filename) && !string.IsNullOrEmpty(content)
                    && SudoersEnforcer.IsSafeFilename(filename))
                    sudoersFilenames.Add(filename);
            }
        }

        if (linux.TryGetProperty("systemd", out var systemd) && systemd.ValueKind == JsonValueKind.Array)
        {
            foreach (var d in systemd.EnumerateArray())
            {
                var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;
                if (action != "ConfigureDropin") continue;
                var unit = d.TryGetProperty("unit",        out var u)  ? u.GetString()  : null;
                var stem = d.TryGetProperty("dropin_name", out var sn) ? sn.GetString() : null;
                if (!string.IsNullOrWhiteSpace(unit) && !string.IsNullOrWhiteSpace(stem)
                    && SystemdEnforcer.IsSafeUnitName(unit) && SystemdEnforcer.IsSafeDropinStem(stem))
                    systemdDropinKeys.Add($"{unit}/{stem}");
            }
        }
    }

    /// Detects and handles items that were previously managed by DDS but are absent from
    /// the current policy set. Stale users are disabled (not deleted) to preserve home
    /// directories; stale files are deleted; stale packages are removed; stale sysctl
    /// keys are removed from the managed drop-in; stale sudoers drop-ins are deleted;
    /// stale systemd drop-in files are deleted; and the sshd drop-in is removed when
    /// no current policy declares an ssh field.
    private async Task ReconcileLinuxAsync(
        HashSet<string> desiredUsernames,
        HashSet<string> desiredPaths,
        HashSet<string> desiredPackages,
        HashSet<string> desiredSysctlKeys,
        HashSet<string> desiredSudoersFilenames,
        HashSet<string> desiredSystemdDropinKeys,
        bool hasSshPolicy,
        UserEnforcer userEnforcer,
        FileEnforcer fileEnforcer,
        PackageEnforcer pkgEnforcer,
        SysctlEnforcer sysctlEnforcer,
        SudoersEnforcer sudoersEnforcer,
        SystemdEnforcer systemdEnforcer,
        SshdEnforcer sshdEnforcer,
        CancellationToken ct)
    {
        var currentState = _stateStore.Load();
        var allChanges = new List<string>();

        var staleUsers = new HashSet<string>(currentState.ManagedUsernames, StringComparer.Ordinal);
        staleUsers.ExceptWith(desiredUsernames);
        if (staleUsers.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale user(s) to disable", staleUsers.Count);
            var changes = await userEnforcer
                .ReconcileStaleUsersAsync(staleUsers, ct)
                .ConfigureAwait(false);
            allChanges.AddRange(changes);
            foreach (var u in staleUsers) _stateStore.RemoveManagedUsername(u);
        }

        var stalePaths = new HashSet<string>(currentState.ManagedPaths, StringComparer.Ordinal);
        stalePaths.ExceptWith(desiredPaths);
        if (stalePaths.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale file(s) to delete", stalePaths.Count);
            var changes = fileEnforcer.ReconcileStaleFiles(stalePaths);
            allChanges.AddRange(changes);
            foreach (var p in stalePaths) _stateStore.RemoveManagedPath(p);
        }

        var stalePackages = new HashSet<string>(currentState.ManagedPackages, StringComparer.Ordinal);
        stalePackages.ExceptWith(desiredPackages);
        if (stalePackages.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale package(s) to remove", stalePackages.Count);
            var changes = await pkgEnforcer
                .ReconcileStalePackagesAsync(stalePackages, ct)
                .ConfigureAwait(false);
            allChanges.AddRange(changes);
            foreach (var n in stalePackages) _stateStore.RemoveManagedPackage(n);
        }

        // Sysctl: remove keys no longer declared in any current policy.
        var sysctlChanges = await sysctlEnforcer
            .ReconcileStaleKeysAsync(desiredSysctlKeys, ct)
            .ConfigureAwait(false);
        allChanges.AddRange(sysctlChanges);

        // Sudoers: delete drop-in files no longer declared in any current policy.
        var staleSudoers = new HashSet<string>(
            currentState.ManagedSudoersFilenames, StringComparer.Ordinal);
        staleSudoers.ExceptWith(desiredSudoersFilenames);
        if (staleSudoers.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale sudoers drop-in(s) to delete",
                staleSudoers.Count);
            var changes = await sudoersEnforcer
                .ReconcileStaleSudoersAsync(staleSudoers, ct)
                .ConfigureAwait(false);
            allChanges.AddRange(changes);
            foreach (var f in staleSudoers) _stateStore.RemoveManagedSudoersFilename(f);
        }

        // Systemd drop-ins: delete drop-in files no longer declared in any current policy.
        var staleSystemdDropins = new HashSet<string>(
            currentState.ManagedSystemdDropins, StringComparer.Ordinal);
        staleSystemdDropins.ExceptWith(desiredSystemdDropinKeys);
        if (staleSystemdDropins.Count > 0)
        {
            _log.LogInformation("Reconciliation: {Count} stale systemd drop-in(s) to delete",
                staleSystemdDropins.Count);
            var changes = await systemdEnforcer
                .ReconcileStaleDropinsAsync(staleSystemdDropins, ct)
                .ConfigureAwait(false);
            allChanges.AddRange(changes);
            foreach (var k in staleSystemdDropins) _stateStore.RemoveManagedSystemdDropin(k);
        }

        // Sshd: remove the drop-in when no current policy declares an ssh field.
        if (!hasSshPolicy)
        {
            var sshdChanges = await sshdEnforcer.ApplyAsync(null, ct).ConfigureAwait(false);
            allChanges.AddRange(sshdChanges);
        }

        if (allChanges.Count > 0)
        {
            _log.LogInformation("Reconciliation complete: {Count} action(s)", allChanges.Count);
            var report = new AppliedReport
            {
                DeviceUrn  = _config.DeviceUrn,
                TargetId   = "_reconciliation",
                Version    = "1",
                Status     = "ok",
                Kind       = AppliedKind.Reconciliation,
                Directives = allChanges,
                AppliedAt  = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await _client.ReportAppliedAsync(report, ct).ConfigureAwait(false);
        }
    }

    private static async Task<List<string>> ApplyLinuxSectionAsync(
        JsonElement linux,
        string policyId,
        string version,
        UserEnforcer userEnforcer,
        SudoersEnforcer sudoersEnforcer,
        FileEnforcer fileEnforcer,
        SystemdEnforcer systemdEnforcer,
        PackageEnforcer pkgEnforcer,
        SysctlEnforcer sysctlEnforcer,
        SshdEnforcer sshdEnforcer,
        IReadOnlySet<string> managedUsernames,
        IReadOnlySet<string> managedPaths,
        IReadOnlySet<string> managedPackages,
        CancellationToken ct)
    {
        var all = new List<string>();

        all.AddRange(await userEnforcer.ApplyAsync(
            GetArray(linux, "local_users"), managedUsernames, ct).ConfigureAwait(false));

        all.AddRange(await sudoersEnforcer.ApplyAsync(
            GetArray(linux, "sudoers"), ct).ConfigureAwait(false));

        all.AddRange(await fileEnforcer.ApplyAsync(
            GetArray(linux, "files"), managedPaths, ct).ConfigureAwait(false));

        all.AddRange(await systemdEnforcer.ApplyAsync(
            GetArray(linux, "systemd"), ct).ConfigureAwait(false));

        all.AddRange(await pkgEnforcer.ApplyAsync(
            GetArray(linux, "packages"), managedPackages, ct).ConfigureAwait(false));

        all.AddRange(await sysctlEnforcer.ApplyAsync(
            GetArray(linux, "sysctl"), ct).ConfigureAwait(false));

        JsonElement? sshPolicy = linux.TryGetProperty("ssh", out var ssh)
            && ssh.ValueKind == JsonValueKind.Object ? ssh : null;
        all.AddRange(await sshdEnforcer.ApplyAsync(sshPolicy, ct).ConfigureAwait(false));

        return all;
    }

    private static IReadOnlyList<JsonElement> GetArray(JsonElement parent, string property)
    {
        if (parent.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.Array)
            return el.EnumerateArray().ToList();
        return [];
    }

    // Parse directive tags emitted by enforcers (e.g. "user:create:alice") and
    // register the affected resource in the applied state store so that future
    // Delete / Remove operations pass the DDS-managed safety check.
    private void RecordManagedResources(IEnumerable<string> directives)
    {
        foreach (var tag in directives)
        {
            var parts = tag.Split(':', 3);
            if (parts.Length != 3) continue;
            var (category, action, id) = (parts[0], parts[1], parts[2]);

            switch (category)
            {
                case "user" when action == "create":
                    _stateStore.RecordManagedUsername(id);
                    break;
                case "user" when action == "delete":
                    _stateStore.RemoveManagedUsername(id);
                    break;
                case "file" when action == "set" || action == "ensuredir":
                    _stateStore.RecordManagedPath(id);
                    break;
                case "file" when action == "delete":
                    _stateStore.RemoveManagedPath(id);
                    break;
                case "pkg" when action == "install":
                    _stateStore.RecordManagedPackage(id);
                    break;
                case "pkg" when action == "remove":
                    _stateStore.RemoveManagedPackage(id);
                    break;
                case "sudoers" when action == "set":
                    _stateStore.RecordManagedSudoersFilename(id);
                    break;
                case "sudoers" when action == "delete":
                    _stateStore.RemoveManagedSudoersFilename(id);
                    break;
                case "systemd" when action == "configuredropin":
                    _stateStore.RecordManagedSystemdDropin(id);
                    break;
                case "systemd" when action == "removedropin":
                    _stateStore.RemoveManagedSystemdDropin(id);
                    break;
            }
        }
    }

    private static string ContentHash(JsonElement element)
    {
        var json = JsonSerializer.Serialize(element);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

}
